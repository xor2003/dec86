#!/usr/bin/env python3

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import importlib.util
import io
import logging
import multiprocessing as mp
import os
import sys
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path
from typing import TextIO

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAX_MEMORY_MB = 15 * 1024

sys.path.insert(0, str(REPO_ROOT / "angr_platforms"))
sys.path.insert(0, str(REPO_ROOT))

from angr_platforms.X86_16.corpus_scan import extract_cod_functions


_REAL_STDOUT = sys.stdout
_REAL_STDERR = sys.stderr
_THREAD_LOCAL = threading.local()


class _ThreadBoundTextIO(io.TextIOBase):
    def __init__(self, fallback: TextIO):
        self._fallback = fallback
        self._local = threading.local()

    @contextlib.contextmanager
    def target(self, stream: TextIO):
        previous = getattr(self._local, "stream", None)
        self._local.stream = stream
        try:
            yield
        finally:
            if previous is None:
                with contextlib.suppress(AttributeError):
                    delattr(self._local, "stream")
            else:
                self._local.stream = previous

    def _stream(self) -> TextIO:
        return getattr(self._local, "stream", self._fallback)

    def write(self, data: str) -> int:
        return self._stream().write(data)

    def flush(self) -> None:
        self._stream().flush()

    def isatty(self) -> bool:
        target = self._stream()
        return bool(getattr(target, "isatty", lambda: False)())

    @property
    def encoding(self):  # noqa: ANN201
        return getattr(self._stream(), "encoding", getattr(self._fallback, "encoding", "utf-8"))

    @property
    def errors(self):  # noqa: ANN201
        return getattr(self._stream(), "errors", getattr(self._fallback, "errors", "strict"))

    def __getattr__(self, item):  # noqa: ANN001
        return getattr(self._stream(), item)


class _ThreadAwareLoggingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:  # pragma: no cover - defensive fallback
            return
        try:
            _THREAD_STDERR.write(f"{msg}\n")
        except Exception:  # pragma: no cover - defensive fallback
            _REAL_STDERR.write(f"{msg}\n")


_THREAD_STDOUT = _ThreadBoundTextIO(_REAL_STDOUT)
_THREAD_STDERR = _ThreadBoundTextIO(_REAL_STDERR)
sys.stdout = _THREAD_STDOUT
sys.stderr = _THREAD_STDERR

_ROOT_LOGGER = logging.getLogger()
_ROOT_LOGGER.handlers.clear()
_ROOT_LOGGER.addHandler(_ThreadAwareLoggingHandler())
_ROOT_LOGGER.setLevel(logging.WARNING)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)


@dataclasses.dataclass(frozen=True)
class CodWorkItem:
    cod_path: Path
    proc_name: str | None
    proc_kind: str | None
    proc_index: int
    proc_total: int

    @property
    def label(self) -> str:
        if self.proc_name is None:
            return "<whole-file>"
        return f"{self.proc_name} ({self.proc_kind})"


@dataclasses.dataclass(frozen=True)
class CodWorkResult:
    cod_path: Path
    proc_name: str | None
    proc_kind: str | None
    proc_index: int
    proc_total: int
    stdout_path: Path
    stderr: str
    returncode: int


@dataclasses.dataclass
class CodFileWriter:
    cod_path: Path
    out_path: Path
    proc_total: int
    next_index: int = 1
    handle: TextIO | None = None
    pending_blocks: dict[int, str] = dataclasses.field(default_factory=dict)
    failed: bool = False
    received_count: int = 0
    closed: bool = False
    reported: bool = False

    def add_block(self, proc_index: int, block: str) -> None:
        if self.closed:
            return
        self.received_count += 1
        self.pending_blocks[proc_index] = block
        self._flush_ready()

    def add_failure(self, proc_index: int, message: str) -> None:
        if self.closed:
            return
        self.received_count += 1
        self.pending_blocks[proc_index] = (
            f"/* == {proc_index}/{self.proc_total} {self.cod_path.name} "
            f":: failure == */\n{message}\n"
        ).rstrip() + "\n"
        self._flush_ready()
        self.failed = True

    def _ensure_open(self) -> None:
        if self.handle is not None:
            return
        self.handle = self.out_path.open("w", encoding="utf-8")
        self.handle.write(f"/* loading: {self.cod_path} */\n")
        self.handle.write(f"/* procedures recovered: {self.proc_total} */\n")

    def _flush_ready(self) -> None:
        if self.handle is None and self.next_index not in self.pending_blocks:
            return
        while self.next_index in self.pending_blocks:
            self._ensure_open()
            assert self.handle is not None
            self.handle.write(self.pending_blocks.pop(self.next_index))
            if not self.pending_blocks or self.next_index == self.proc_total:
                self.handle.flush()
            self.next_index += 1

    def close(self) -> None:
        if self.closed:
            return
        if self.handle is not None:
            self.handle.flush()
            self.handle.close()
            self.handle = None
        self.closed = True

    def is_complete(self) -> bool:
        return self.received_count >= self.proc_total and not self.pending_blocks and self.next_index > self.proc_total


def _iter_cod_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() == ".cod":
            yield path


def _lower_process_priority() -> None:
    try:
        os.nice(10)
    except (AttributeError, OSError):
        pass


def _mem_available_mb() -> int | None:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fp:
            for line in fp:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        return None
    return None


def _choose_parallelism(task_count: int, max_memory_mb: int) -> int:
    cpu_count = os.cpu_count() or 1
    cpu_workers = max(1, cpu_count - 1)
    if task_count <= 1:
        return 1

    available_mb = _mem_available_mb()
    if available_mb is None:
        return 1

    # Keep the pool under 75% of currently free RAM.
    budget_mb = int(available_mb * 0.75)
    worker_floor_mb = min(max_memory_mb, 1024) if max_memory_mb > 0 else 1024
    worker_floor_mb = max(512, worker_floor_mb)
    if budget_mb < worker_floor_mb * 2:
        return 1

    workers_by_mem = max(1, budget_mb // worker_floor_mb)
    workers = min(cpu_workers, task_count, workers_by_mem)
    return workers if workers > 1 else 1


def _make_executor(max_workers: int) -> ProcessPoolExecutor:
    try:
        mp_context = mp.get_context("fork")
    except ValueError:
        mp_context = None
    kwargs = {
        "max_workers": max_workers,
        "initializer": _lower_process_priority,
    }
    if mp_context is not None:
        kwargs["mp_context"] = mp_context
    return ProcessPoolExecutor(**kwargs)


def _load_worker_decompile_module():
    module = getattr(_THREAD_LOCAL, "decompile_module", None)
    if module is not None:
        return module

    module_name = f"_inertia_decompile_worker_{os.getpid()}_{threading.get_ident()}"
    spec = importlib.util.spec_from_file_location(module_name, REPO_ROOT / "decompile.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load decompile.py worker module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    _THREAD_LOCAL.decompile_module = module
    return module


def _build_work_items(cod_path: Path) -> list[CodWorkItem]:
    entries = list(extract_cod_functions(cod_path))
    if not entries:
        return [CodWorkItem(cod_path=cod_path, proc_name=None, proc_kind=None, proc_index=1, proc_total=1)]

    total = len(entries)
    return [
        CodWorkItem(
            cod_path=cod_path,
            proc_name=proc_name,
            proc_kind=proc_kind,
            proc_index=index,
            proc_total=total,
        )
        for index, (proc_name, proc_kind, _code) in enumerate(entries, start=1)
    ]


def _run_work_item(item: CodWorkItem, *, timeout: int) -> CodWorkResult:
    stdout_fd, stdout_name = tempfile.mkstemp(
        prefix=f"{item.cod_path.stem}.{item.proc_index:04d}.",
        suffix=".dec.stdout",
        dir=item.cod_path.parent,
    )
    os.close(stdout_fd)
    stdout_path = Path(stdout_name)
    stderr_buf = io.StringIO()
    returncode = 0

    try:
        with stdout_path.open("w", encoding="utf-8") as stdout_file:
            with _THREAD_STDOUT.target(stdout_file), _THREAD_STDERR.target(stderr_buf):
                module = _load_worker_decompile_module()
                argv = [str(item.cod_path), "--timeout", str(timeout), "--max-memory-mb", "0"]
                if item.proc_name is not None:
                    argv.extend(["--proc", item.proc_name, "--proc-kind", item.proc_kind or "NEAR"])
                try:
                    returncode = int(module.main(argv))
                except SystemExit as ex:
                    returncode = int(ex.code or 0)
    except Exception as ex:  # pragma: no cover - defensive fallback
        returncode = 99
        stderr_buf.write(f"{type(ex).__name__}: {ex}\n")

    return CodWorkResult(
        cod_path=item.cod_path,
        proc_name=item.proc_name,
        proc_kind=item.proc_kind,
        proc_index=item.proc_index,
        proc_total=item.proc_total,
        stdout_path=stdout_path,
        stderr=stderr_buf.getvalue(),
        returncode=returncode,
    )


def _extract_proc_body(raw_output: str) -> str:
    marker = "/* == c == */"
    idx = raw_output.rfind(marker)
    if idx == -1:
        return raw_output.strip()
    return raw_output[idx + len(marker) :].lstrip("\n").rstrip()


def _render_result_block(result: CodWorkResult) -> str:
    raw_output = result.stdout_path.read_text(encoding="utf-8", errors="replace")
    if result.returncode == 0:
        body = _extract_proc_body(raw_output)
        if body:
            rendered = body
        else:
            rendered = raw_output.strip()
    else:
        rendered = raw_output.strip()

    parts = [
        f"/* == {result.proc_index}/{result.proc_total} {result.cod_path.name}",
    ]
    if result.proc_name is not None:
        parts[0] += f" :: {result.proc_name}"
        if result.proc_kind:
            parts[0] += f" [{result.proc_kind}]"
    else:
        parts[0] += " :: whole-file"
    parts[0] += " == */"
    if rendered:
        parts.append(rendered)
    if result.stderr.strip():
        parts.append(f"/* == stderr {result.cod_path.name} == */")
        parts.append(result.stderr.rstrip())
    if result.returncode != 0:
        parts.append(f"/* == exit code {result.cod_path.name} == */")
        parts.append(str(result.returncode))

    with contextlib.suppress(OSError):
        result.stdout_path.unlink()

    return "\n".join(parts).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Decompile all .COD files into sibling .dec files.")
    parser.add_argument("cod_dir", type=Path, help="Root directory containing .COD files.")
    parser.add_argument("--timeout", type=int, default=20, help="Per-procedure decompiler timeout in seconds.")
    parser.add_argument(
        "--max-memory-mb",
        type=int,
        default=DEFAULT_MAX_MEMORY_MB,
        help="Heuristic memory floor used to decide whether to parallelize. Workers themselves run without RLIMIT_AS.",
    )
    parser.add_argument(
        "--subprocess-timeout",
        type=int,
        default=900,
        help="Soft wait timeout in seconds for the thread worker pool. Results still come from one shared process.",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip files whose sibling .dec already exists.",
    )
    args = parser.parse_args()

    _lower_process_priority()
    cod_files = list(_iter_cod_files(args.cod_dir))
    print(f"found {len(cod_files)} COD files under {args.cod_dir}")

    work_items: list[CodWorkItem] = []
    items_by_file: dict[Path, list[CodWorkItem]] = {}
    for cod_path in cod_files:
        if args.skip_existing and cod_path.with_suffix(".dec").exists():
            print(f"[skip] {cod_path}")
            continue
        items = _build_work_items(cod_path)
        items_by_file[cod_path] = items
        work_items.extend(items)

    start = time.perf_counter()
    if not work_items:
        print("done in 0.0s; failures=0/0")
        return 0

    workers = _choose_parallelism(len(work_items), args.max_memory_mb)
    if workers <= 1:
        print("/* parallelism: disabled (insufficient RAM or single procedure) */")
    else:
        print(f"/* parallelism: {workers} worker processes, shared imports, n-1 CPU target */")

    file_writers: dict[Path, CodFileWriter] = {
        cod_path: CodFileWriter(
            cod_path=cod_path,
            out_path=cod_path.with_suffix(".dec"),
            proc_total=len(items),
        )
        for cod_path, items in items_by_file.items()
    }
    failures = 0

    future_map = {}
    executor = _make_executor(max(1, workers))
    try:
        for index, item in enumerate(work_items, start=1):
            print(f"[{index}/{len(work_items)}] {item.cod_path} :: {item.label}")
            future = executor.submit(_run_work_item, item, timeout=args.timeout)
            future_map[future] = item

        pending = set(future_map)
        deadline = time.monotonic() + max(1, args.subprocess_timeout)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                for future in pending:
                    item = future_map[future]
                    failures += 1
                    print(f"  timeout after {args.subprocess_timeout}s: {item.cod_path} :: {item.label}")
                    writer = file_writers[item.cod_path]
                    writer.add_failure(
                        item.proc_index,
                        f"/* timeout after {args.subprocess_timeout}s */",
                    )
                    if writer.is_complete():
                        writer.close()
                        writer.reported = True
                        print(f"  wrote {writer.out_path}")
                break

            done, pending = wait(pending, timeout=min(1.0, remaining), return_when=FIRST_COMPLETED)
            for future in done:
                item = future_map[future]
                writer = file_writers[item.cod_path]
                try:
                    result = future.result()
                except Exception as ex:  # pragma: no cover - defensive fallback
                    failures += 1
                    print(f"  worker failed: {item.cod_path} :: {item.label}: {ex}")
                    writer.add_failure(item.proc_index, f"/* worker failed: {type(ex).__name__}: {ex} */")
                    if writer.is_complete():
                        writer.close()
                        writer.reported = True
                        print(f"  wrote {writer.out_path}")
                    continue
                writer.add_block(item.proc_index, _render_result_block(result))
                if result.returncode != 0:
                    failures += 1
                print(f"  captured {item.label}")
                if writer.is_complete():
                    writer.close()
                    writer.reported = True
                    print(f"  wrote {writer.out_path}")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    for cod_path, writer in file_writers.items():
        if not writer.closed:
            writer.close()
        if writer.received_count > 0 and not writer.reported and writer.out_path.exists():
            writer.reported = True
            print(f"  wrote {writer.out_path}")

    elapsed = time.perf_counter() - start
    print(f"done in {elapsed:.1f}s; failures={failures}/{len(work_items)}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
