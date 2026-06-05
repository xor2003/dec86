from __future__ import annotations

import atexit
import contextlib
import contextvars
import functools
import inspect
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar


TRACE_ENABLE_ENV = "INERTIA_OTEL_SPANS"
TRACE_FILE_ENV = "INERTIA_OTEL_SPAN_FILE"
TRACE_TOP_N_ENV = "INERTIA_OTEL_TOP_N"
TRACE_MIN_MS_ENV = "INERTIA_OTEL_MIN_MS"
TRACE_FULL_JSONL_ENV = "INERTIA_OTEL_FULL_JSONL"
TRACE_STDERR_ENV = "INERTIA_OTEL_STDERR"
TRACE_FORMAT_ENV = "INERTIA_OTEL_SPAN_FORMAT"
TRACE_TEXT_MAX_SPANS_ENV = "INERTIA_OTEL_TEXT_MAX_SPANS"
TRACE_OTLP_ENABLE_ENV = "INERTIA_OTEL_EXPORT_OTLP"
TRACE_SERVICE_NAME_ENV = "INERTIA_OTEL_SERVICE_NAME"
TRACE_FORCE_FLUSH_MS_ENV = "INERTIA_OTEL_FORCE_FLUSH_MS"

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}
_MAX_ATTR_TEXT = 96


class TraceOutputFormat(Enum):
    TEXT = "text"
    SLOW = "slow"
    JSON = "json"
    JSONL = "jsonl"


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUTHY:
        return True
    if normalized in _FALSY:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _compact_attr(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, Path):
        value = str(value)
    elif not isinstance(value, str):
        value = str(value)
    if len(value) > _MAX_ATTR_TEXT:
        return value[: _MAX_ATTR_TEXT - 1] + "~"
    return value


def _compact_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _compact_attr(value) for key, value in attrs.items() if value is not None}


@dataclass
class _SpanRecord:
    span_id: int
    parent_id: int | None
    name: str
    start_ns: int
    attrs: dict[str, Any] = field(default_factory=dict)
    end_ns: int | None = None
    status: str = "ok"

    @property
    def duration_ms(self) -> float:
        end_ns = self.end_ns if self.end_ns is not None else time.perf_counter_ns()
        return max(0.0, (end_ns - self.start_ns) / 1_000_000.0)


@dataclass
class _TelemetryState:
    enabled: bool = False
    configured: bool = False
    emitted: bool = False
    top_n: int = 16
    min_ms: float = 1.0
    file_path: Path | None = None
    stderr_summary: bool = True
    full_jsonl: bool = False
    output_format: TraceOutputFormat = TraceOutputFormat.TEXT
    text_max_spans: int = 200
    records: list[_SpanRecord] = field(default_factory=list)
    next_id: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)
    otel_tracer: Any = None
    otel_provider: Any = None
    otel_export_status: str | None = None
    otel_shutdown: bool = False


_STATE = _TelemetryState()
_CURRENT_SPAN_ID: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "inertia_current_span_id",
    default=None,
)
_F = TypeVar("_F", bound=Callable[..., Any])
_AUTO_ATTR_NAMES = {
    "addr",
    "address",
    "base_addr",
    "binary",
    "binary_path",
    "candidate_addr",
    "c_target",
    "entry_point",
    "force_blob",
    "function_label",
    "image_end",
    "low_memory",
    "low_memory_path",
    "pat_backend",
    "region_span",
    "signature_catalog",
    "status",
    "timeout",
    "window",
}


def configure_telemetry_from_env(
    *,
    enabled: bool | None = None,
    file_path: Path | str | None = None,
    top_n: int | None = None,
    min_ms: float | None = None,
) -> bool:
    requested = _env_bool(TRACE_ENABLE_ENV) if enabled is None else bool(enabled)
    if not requested:
        return False

    with _STATE.lock:
        _STATE.enabled = True
        _STATE.top_n = max(1, int(top_n if top_n is not None else _env_int(TRACE_TOP_N_ENV, _STATE.top_n)))
        _STATE.min_ms = max(0.0, float(min_ms if min_ms is not None else _env_float(TRACE_MIN_MS_ENV, _STATE.min_ms)))
        raw_file_path = file_path if file_path is not None else os.environ.get(TRACE_FILE_ENV)
        _STATE.file_path = Path(raw_file_path) if raw_file_path else None
        _STATE.stderr_summary = _env_bool(TRACE_STDERR_ENV, True)
        _STATE.full_jsonl = _env_bool(TRACE_FULL_JSONL_ENV, False)
        _STATE.output_format = _resolve_output_format(_STATE.file_path, _STATE.full_jsonl)
        _STATE.text_max_spans = max(1, _env_int(TRACE_TEXT_MAX_SPANS_ENV, _STATE.text_max_spans))
        if not _STATE.configured:
            _STATE.otel_tracer = _optional_otel_tracer()
            atexit.register(emit_compact_summary)
            _STATE.configured = True
    return True


def telemetry_enabled() -> bool:
    return _STATE.enabled


def caller_span_name(stacklevel: int = 1) -> str:
    try:
        frame = inspect.currentframe()
        for _ in range(max(1, int(stacklevel))):
            if frame is None:
                break
            frame = frame.f_back
        if frame is None:
            return "unknown"
        module_name = frame.f_globals.get("__name__", "")
        function_name = frame.f_code.co_name
        if module_name:
            return f"{module_name}.{function_name}"
        return function_name
    except Exception:
        return "unknown"


def _optional_otel_tracer() -> Any:
    try:
        from opentelemetry import trace
    except Exception:
        return None
    if _otlp_export_requested():
        provider, status = _configure_otlp_exporter()
        _STATE.otel_provider = provider
        _STATE.otel_export_status = status
    else:
        _STATE.otel_export_status = "disabled"
    try:
        return trace.get_tracer("inertia_decompiler")
    except Exception:
        return None


def _otlp_export_requested() -> bool:
    explicit = os.environ.get(TRACE_OTLP_ENABLE_ENV)
    if explicit is not None:
        return _env_bool(TRACE_OTLP_ENABLE_ENV, False)
    return any(
        os.environ.get(name)
        for name in (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        )
    )


def _resolve_output_format(file_path: Path | None, full_jsonl: bool) -> TraceOutputFormat:
    explicit = os.environ.get(TRACE_FORMAT_ENV)
    if explicit is not None:
        normalized = explicit.strip().lower()
        if normalized in {"text", "agent", "agent_text", "txt"}:
            return TraceOutputFormat.TEXT
        if normalized in {"slow", "top", "top_text", "agent_slow"}:
            return TraceOutputFormat.SLOW
        if normalized in {"jsonl", "full_jsonl"}:
            return TraceOutputFormat.JSONL
        if normalized in {"json", "compact_json"}:
            return TraceOutputFormat.JSON
    if full_jsonl:
        return TraceOutputFormat.JSONL
    return TraceOutputFormat.TEXT


def _configure_otlp_exporter() -> tuple[Any | None, str]:
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception as ex:
        return None, f"unavailable:{type(ex).__name__}"

    try:
        resource = Resource.create(
            {
                "service.name": os.environ.get(TRACE_SERVICE_NAME_ENV, "inertia-decompiler"),
                "service.namespace": "inertia",
            }
        )
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        return provider, "configured"
    except Exception as ex:
        return None, f"configure_failed:{type(ex).__name__}"


def _auto_span_attrs(target: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    attrs: dict[str, Any] = {}
    try:
        signature = inspect.signature(target)
        bound = signature.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        values = dict(bound.arguments)
    except Exception:
        values = {f"arg{index}": value for index, value in enumerate(args[:4])}
        values.update(kwargs)

    for name, value in values.items():
        _collect_auto_attr(attrs, name, value)

    return attrs


def _collect_auto_attr(attrs: dict[str, Any], name: str, value: Any) -> None:
    if value is None:
        return
    if name in _AUTO_ATTR_NAMES:
        attrs[name] = _format_auto_value(name, value)
        return
    if name in {"path", "file_path"}:
        if isinstance(value, Path):
            attrs.setdefault("binary", value.name)
            attrs["path"] = value.name
        elif isinstance(value, str) and value:
            attrs.setdefault("binary", Path(value).name)
            attrs["path"] = Path(value).name
        return
    if name in {"function", "function_obj", "decompile_function"}:
        _collect_function_attrs(attrs, value)
        return
    if name in {"project", "candidate_project", "decompile_project", "project_obj"}:
        _collect_project_attrs(attrs, value)
        return
    if name in {"item", "task"}:
        item_function = getattr(value, "function", None)
        if item_function is not None:
            _collect_function_attrs(attrs, item_function)
        item_index = getattr(value, "index", None)
        if isinstance(item_index, int):
            attrs.setdefault("index", item_index)
        return


def _collect_function_attrs(attrs: dict[str, Any], function: Any) -> None:
    addr = getattr(function, "addr", None)
    if isinstance(addr, int):
        attrs.setdefault("addr", hex(addr))
    name = getattr(function, "name", None)
    if isinstance(name, str) and name:
        attrs.setdefault("name", name)
    block_addrs = getattr(function, "block_addrs_set", None)
    if block_addrs:
        try:
            attrs.setdefault("blocks", len(block_addrs))
        except Exception:
            pass


def _collect_project_attrs(attrs: dict[str, Any], project: Any) -> None:
    filename = getattr(project, "filename", None)
    if isinstance(filename, str) and filename:
        attrs.setdefault("binary", Path(filename).name)
    entry = getattr(project, "entry", None)
    if isinstance(entry, int):
        attrs.setdefault("entry", hex(entry))
    arch = getattr(project, "arch", None)
    arch_name = getattr(arch, "name", None)
    if isinstance(arch_name, str) and arch_name:
        attrs.setdefault("arch", arch_name)


def _format_auto_value(name: str, value: Any) -> Any:
    if isinstance(value, Path):
        return value.name
    if isinstance(value, int) and ("addr" in name or name in {"entry_point", "image_end"}):
        return hex(value)
    if isinstance(value, int) and abs(value) > 4096:
        return hex(value)
    return value


@contextlib.contextmanager
def span(span_name: str, **attrs: Any) -> Iterator[None]:
    if not _STATE.enabled:
        yield
        return

    parent_id = _CURRENT_SPAN_ID.get()
    with _STATE.lock:
        span_id = _STATE.next_id
        _STATE.next_id += 1
        record = _SpanRecord(
            span_id=span_id,
            parent_id=parent_id,
            name=str(span_name),
            start_ns=time.perf_counter_ns(),
            attrs=_compact_attrs(attrs),
        )
        _STATE.records.append(record)

    token = _CURRENT_SPAN_ID.set(span_id)
    otel_cm = _otel_span_context(span_name, record.attrs)
    try:
        with otel_cm:
            yield
    except BaseException as ex:
        record.status = "error"
        record.attrs.setdefault("exception", type(ex).__name__)
        raise
    finally:
        record.end_ns = time.perf_counter_ns()
        _CURRENT_SPAN_ID.reset(token)


def annotate_current_span(**attrs: Any) -> None:
    if not _STATE.enabled:
        return
    span_id = _CURRENT_SPAN_ID.get()
    if span_id is None:
        return
    compact = _compact_attrs(attrs)
    with _STATE.lock:
        for record in reversed(_STATE.records):
            if record.span_id == span_id:
                record.attrs.update(compact)
                return


def span_here(**attrs: Any) -> contextlib.AbstractContextManager[None]:
    if not _STATE.enabled:
        return contextlib.nullcontext()
    return span(caller_span_name(stacklevel=2), **attrs)


def trace_function(
    func: _F | None = None,
    *,
    name: str | None = None,
    attrs: dict[str, Any] | None = None,
    attr_factory: Callable[..., dict[str, Any] | None] | None = None,
) -> _F | Callable[[_F], _F]:
    def _decorate(target: _F) -> _F:
        span_name = name or f"{target.__module__}.{target.__name__}"

        @functools.wraps(target)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            if not _STATE.enabled:
                return target(*args, **kwargs)
            span_attrs = _auto_span_attrs(target, args, kwargs)
            span_attrs.update(attrs or {})
            if attr_factory is not None:
                try:
                    dynamic_attrs = attr_factory(*args, **kwargs)
                except Exception as ex:
                    dynamic_attrs = {"attr_factory_error": type(ex).__name__}
                if isinstance(dynamic_attrs, dict):
                    span_attrs.update(dynamic_attrs)
            with span(span_name, **span_attrs):
                return target(*args, **kwargs)

        return _wrapped  # type: ignore[return-value]

    if func is None:
        return _decorate
    return _decorate(func)


@contextlib.contextmanager
def _otel_span_context(span_name: str, attrs: dict[str, Any]) -> Iterator[None]:
    tracer = _STATE.otel_tracer
    if tracer is None:
        yield
        return
    try:
        span_context = tracer.start_as_current_span(span_name)
    except Exception:
        yield
        return
    with span_context as otel_span:
        for key, value in attrs.items():
            try:
                otel_span.set_attribute(key, value)
            except Exception:
                continue
        yield


def build_compact_summary() -> dict[str, Any]:
    with _STATE.lock:
        records = list(_STATE.records)
    finished = [record for record in records if record.end_ns is not None]
    if not finished:
        summary: dict[str, Any] = {
            "span_count": 0,
            "total_ms": 0.0,
            "top": [],
            "agg": [],
            "errors": [],
        }
        if _STATE.otel_export_status is not None:
            summary["otel_export"] = _STATE.otel_export_status
        return summary

    first_start = min(record.start_ns for record in finished)
    last_end = max(record.end_ns or record.start_ns for record in finished)
    total_ms = max(0.0, (last_end - first_start) / 1_000_000.0)
    visible = [record for record in finished if record.duration_ms >= _STATE.min_ms]
    top = sorted(visible, key=lambda record: record.duration_ms, reverse=True)[: _STATE.top_n]

    aggregate: dict[str, dict[str, float | int]] = {}
    for record in finished:
        entry = aggregate.setdefault(record.name, {"count": 0, "cum_ms": 0.0, "max_ms": 0.0})
        entry["count"] = int(entry["count"]) + 1
        entry["cum_ms"] = float(entry["cum_ms"]) + record.duration_ms
        entry["max_ms"] = max(float(entry["max_ms"]), record.duration_ms)
    agg_rows = sorted(
        (
            [name, int(data["count"]), round(float(data["cum_ms"]), 1), round(float(data["max_ms"]), 1)]
            for name, data in aggregate.items()
        ),
        key=lambda row: (row[2], row[3]),
        reverse=True,
    )[: _STATE.top_n]

    summary = {
        "span_count": len(finished),
        "total_ms": round(total_ms, 1),
        "top": [
            [
                record.name,
                round(record.duration_ms, 1),
                _summary_attrs(record.attrs),
            ]
            for record in top
        ],
        "agg": agg_rows,
        "errors": [
            [record.name, round(record.duration_ms, 1), _summary_attrs(record.attrs)]
            for record in finished
            if record.status == "error"
        ][: _STATE.top_n],
    }
    if _STATE.otel_export_status is not None:
        summary["otel_export"] = _STATE.otel_export_status
    return summary


def build_agent_trace_text() -> str:
    with _STATE.lock:
        records = list(_STATE.records)
    finished = [record for record in records if record.end_ns is not None]
    summary = build_compact_summary()
    otel_status = summary.get("otel_export", "-")
    if otel_status == "disabled":
        otel_status = "off"
    errors = summary.get("errors", [])
    lines = [
        (
            f"summary total_ms={summary.get('total_ms', 0.0)} "
            f"spans={len(finished)} otel={otel_status} errors={len(errors)}"
        ),
        "schema: id|parent|ms|name|attrs",
    ]
    ordered = sorted(finished, key=lambda record: record.span_id)
    limit = max(1, int(_STATE.text_max_spans))
    shown = ordered[:limit]
    if len(ordered) > len(shown):
        lines[0] += f" shown={len(shown)}"
    name_ids = _agent_trace_name_dictionary(shown)
    if name_ids:
        lines.append("names:")
        for name, name_id in sorted(name_ids.items(), key=lambda item: item[1]):
            lines.append(f"{name_id}={name}")
        lines[1] = "schema: id|parent|ms|n|attrs"
    lines.extend(_format_agent_trace_record(record, name_ids=name_ids) for record in shown)
    return "\n".join(lines) + "\n"


def build_agent_slow_trace_text() -> str:
    with _STATE.lock:
        records = list(_STATE.records)
    finished = [record for record in records if record.end_ns is not None]
    summary = build_compact_summary()
    otel_status = summary.get("otel_export", "-")
    if otel_status == "disabled":
        otel_status = "off"
    errors = summary.get("errors", [])
    lines = [
        (
            f"trace total={summary.get('total_ms', 0.0)}ms "
            f"spans={len(finished)} otel={otel_status} errors={len(errors)}"
        )
    ]
    visible = [record for record in finished if record.duration_ms >= _STATE.min_ms]
    top = sorted(visible, key=lambda record: record.duration_ms, reverse=True)[: max(1, int(_STATE.top_n))]
    for record in top:
        attrs = _format_agent_attrs(record.attrs)
        status = "" if record.status == "ok" else f" status={record.status}"
        suffix = f" {attrs}" if attrs else ""
        lines.append(f"{round(record.duration_ms, 3)} {record.name}{suffix}{status}")
    return "\n".join(lines) + "\n"


def _agent_trace_name_dictionary(records: list[_SpanRecord]) -> dict[str, int] | None:
    if len(records) < 16:
        return None
    names: dict[str, int] = {}
    for record in records:
        if record.name not in names:
            names[record.name] = len(names)
    if len(names) >= len(records):
        return None
    raw_name_chars = sum(len(record.name) for record in records)
    dict_name_chars = sum(len(str(name_id)) + 1 + len(name) for name, name_id in names.items())
    row_name_chars = sum(len(str(names[record.name])) for record in records)
    if dict_name_chars + row_name_chars + len("names:\n") + 32 >= raw_name_chars:
        return None
    return names


def _format_agent_trace_record(record: _SpanRecord, *, name_ids: dict[str, int] | None = None) -> str:
    parent = "-" if record.parent_id is None else str(record.parent_id)
    attrs = _format_agent_attrs(record.attrs)
    name = str(name_ids[record.name]) if name_ids is not None else record.name
    return f"{record.span_id}|{parent}|{round(record.duration_ms, 3)}|{name}|{attrs}"


def _format_agent_attrs(attrs: dict[str, Any]) -> str:
    if not attrs:
        return ""
    preferred = (
        "binary",
        "addr",
        "name",
        "function",
        "function_label",
        "status",
        "stage",
        "blocks",
        "bytes",
        "c_target",
        "backend",
        "functions",
        "cache",
        "timeout",
        "window",
        "entry",
        "entry_point",
        "base_addr",
        "arch",
        "low_memory_path",
        "exception",
    )
    aliases = {
        "function_label": "label",
        "c_target": "target",
        "entry_point": "entry",
        "base_addr": "base",
        "low_memory_path": "lowmem",
    }
    seen: set[str] = set()
    parts: list[str] = []
    for key in preferred:
        if key in attrs:
            parts.append(f"{aliases.get(key, key)}={_format_agent_attr_value(attrs[key])}")
            seen.add(key)
    for key in sorted(str(key) for key in attrs):
        if key in seen:
            continue
        parts.append(f"{aliases.get(key, key)}={_format_agent_attr_value(attrs[key])}")
    return " ".join(parts)


def _format_agent_attr_value(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        return "-"
    text = str(value)
    if not text:
        return "-"
    if any(ch.isspace() for ch in text):
        text = "_".join(text.split())
    return text.replace("|", "/")


def _summary_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    preferred = (
        "binary",
        "addr",
        "name",
        "function",
        "status",
        "stage",
        "blocks",
        "bytes",
        "backend",
        "functions",
        "cache",
        "exception",
    )
    out: dict[str, Any] = {}
    for key in preferred:
        value = attrs.get(key)
        if value is not None:
            out[key] = value
    return out


def emit_compact_summary() -> None:
    if not _STATE.enabled or _STATE.emitted:
        return
    _STATE.emitted = True
    summary = build_compact_summary()
    if summary["span_count"] == 0:
        return

    if _STATE.output_format == TraceOutputFormat.TEXT:
        encoded = build_agent_trace_text().rstrip("\n")
    elif _STATE.output_format == TraceOutputFormat.SLOW:
        encoded = build_agent_slow_trace_text().rstrip("\n")
    else:
        encoded = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    if _STATE.stderr_summary:
        if _STATE.output_format == TraceOutputFormat.SLOW:
            stderr_encoded = build_agent_slow_trace_text().rstrip("\n")
        else:
            # Stderr is an agent-facing surface. Keep it compact text even
            # when the file output is JSON/JSONL for external parsers.
            stderr_encoded = build_agent_trace_text().rstrip("\n")
        print(f"[otel-trace] {stderr_encoded}", file=sys.stderr)
        sys.stderr.flush()
    if _STATE.file_path is not None:
        _STATE.file_path.parent.mkdir(parents=True, exist_ok=True)
        if _STATE.output_format == TraceOutputFormat.JSONL:
            _write_full_jsonl(_STATE.file_path)
        elif _STATE.output_format == TraceOutputFormat.TEXT:
            _STATE.file_path.write_text(build_agent_trace_text(), encoding="utf-8")
        elif _STATE.output_format == TraceOutputFormat.SLOW:
            _STATE.file_path.write_text(build_agent_slow_trace_text(), encoding="utf-8")
        else:
            _STATE.file_path.write_text(encoded + "\n", encoding="utf-8")
    _flush_and_shutdown_otel()


def _flush_and_shutdown_otel() -> None:
    provider = _STATE.otel_provider
    if provider is None or _STATE.otel_shutdown:
        return
    _STATE.otel_shutdown = True
    timeout_ms = max(1, _env_int(TRACE_FORCE_FLUSH_MS_ENV, 3000))
    try:
        force_flush = getattr(provider, "force_flush", None)
        if callable(force_flush):
            force_flush(timeout_millis=timeout_ms)
    except Exception as ex:
        _STATE.otel_export_status = f"flush_failed:{type(ex).__name__}"
    try:
        shutdown = getattr(provider, "shutdown", None)
        if callable(shutdown):
            shutdown()
    except Exception as ex:
        _STATE.otel_export_status = f"shutdown_failed:{type(ex).__name__}"


def _write_full_jsonl(path: Path) -> None:
    with _STATE.lock:
        records = list(_STATE.records)
    with path.open("w", encoding="utf-8") as fp:
        fp.write(json.dumps(build_compact_summary(), sort_keys=True, separators=(",", ":")) + "\n")
        for record in records:
            if record.end_ns is None:
                continue
            fp.write(
                json.dumps(
                    {
                        "id": record.span_id,
                        "parent": record.parent_id,
                        "name": record.name,
                        "duration_ms": round(record.duration_ms, 3),
                        "status": record.status,
                        "attrs": record.attrs,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )


def reset_telemetry_for_tests() -> None:
    with _STATE.lock:
        _STATE.enabled = False
        _STATE.configured = False
        _STATE.emitted = False
        _STATE.records.clear()
        _STATE.next_id = 1
        _STATE.top_n = 16
        _STATE.min_ms = 1.0
        _STATE.file_path = None
        _STATE.stderr_summary = True
        _STATE.full_jsonl = False
        _STATE.output_format = TraceOutputFormat.TEXT
        _STATE.text_max_spans = 200
        _STATE.otel_tracer = None
        _STATE.otel_provider = None
        _STATE.otel_export_status = None
        _STATE.otel_shutdown = False
    _CURRENT_SPAN_ID.set(None)
