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
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar


TRACE_ENABLE_ENV = "INERTIA_OTEL_SPANS"
TRACE_FILE_ENV = "INERTIA_OTEL_SPAN_FILE"
TRACE_TOP_N_ENV = "INERTIA_OTEL_TOP_N"
TRACE_MIN_MS_ENV = "INERTIA_OTEL_MIN_MS"
TRACE_FULL_JSONL_ENV = "INERTIA_OTEL_FULL_JSONL"
TRACE_STDERR_ENV = "INERTIA_OTEL_STDERR"

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}
_MAX_ATTR_TEXT = 96


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
    records: list[_SpanRecord] = field(default_factory=list)
    next_id: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)
    otel_tracer: Any = None


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
    try:
        return trace.get_tracer("inertia_decompiler")
    except Exception:
        return None


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
        return {
            "span_count": 0,
            "total_ms": 0.0,
            "top": [],
            "agg": [],
            "errors": [],
        }

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

    return {
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

    encoded = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    if _STATE.stderr_summary:
        print(f"[otel-compact] {encoded}", file=sys.stderr)
        sys.stderr.flush()
    if _STATE.file_path is not None:
        _STATE.file_path.parent.mkdir(parents=True, exist_ok=True)
        if _STATE.full_jsonl:
            _write_full_jsonl(_STATE.file_path)
        else:
            _STATE.file_path.write_text(encoded + "\n", encoding="utf-8")


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
        _STATE.otel_tracer = None
    _CURRENT_SPAN_ID.set(None)
