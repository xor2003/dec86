#!/usr/bin/env python3

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from types import ModuleType

_ROOT = Path(__file__).resolve().parent
_PROJECT_VENV_PYTHONS = (_ROOT / ".venv" / "bin" / "python",)


def _ensure_project_venv() -> None:
    if os.environ.get("INERTIA_DECOMPILE_VENV") == "1":
        return
    for candidate in _PROJECT_VENV_PYTHONS:
        if not candidate.exists():
            continue
        try:
            if candidate.samefile(sys.executable):
                return
        except FileNotFoundError:
            continue
        env = os.environ.copy()
        env["INERTIA_DECOMPILE_VENV"] = "1"
        env["VIRTUAL_ENV"] = str(candidate.parent.parent)
        current_path = env.get("PATH", "")
        env["PATH"] = f"{candidate.parent}:{current_path}" if current_path else str(candidate.parent)
        os.execvpe(str(candidate), [str(candidate), str(Path(__file__).resolve()), *sys.argv[1:]], env)


def _install_early_log_levels() -> None:
    for logger_name, level in (
        ("angr.state_plugins.unicorn_engine", logging.CRITICAL),
        ("angr.analyses.calling_convention.calling_convention", logging.CRITICAL),
        ("angr.analyses.calling_convention.fact_collector.SimEngineFactCollectorVEX", logging.CRITICAL),
        ("angr.analyses.decompiler.structured_codegen.c", logging.CRITICAL),
        ("angr.analyses.decompiler.decompiler", logging.ERROR),
        ("angr.project", logging.ERROR),
        ("angr.analyses.cfg.cfg_fast", logging.ERROR),
        ("angr.analyses.cfg.cfg_base", logging.ERROR),
        ("angr.analyses.fcp.fcp.SimEngineFCPVEX", logging.CRITICAL),
    ):
        logging.getLogger(logger_name).setLevel(level)


def _enable_line_buffered_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(line_buffering=True)
            except Exception:
                pass


def _install_msgspec_shim_if_missing() -> None:
    try:
        import msgspec  # noqa: F401
    except ModuleNotFoundError:
        try:
            # Explicit import keeps fallback deterministic for environments where
            # sitecustomize.py is not auto-discovered (e.g. PyPy packaging paths).
            import sitecustomize  # noqa: F401
        except Exception:
            pass


_install_msgspec_shim_if_missing()


def _configure_python_recursion_limit() -> None:
    raw = os.environ.get("INERTIA_PYTHON_RECURSION_LIMIT", "").strip()
    target = 12000
    if raw:
        try:
            target = max(2000, int(raw))
        except Exception:
            target = 12000
    current = sys.getrecursionlimit()
    if target > current:
        sys.setrecursionlimit(target)


# Only trampoline into the project venv when invoked as the entrypoint script.
# Tests import this module for helper access and must not exec-replace the process.
if __name__ == "__main__":
    _ensure_project_venv()
    os.environ.setdefault("INERTIA_ENABLE_FORCED_CORPUS_TEMPLATES", "1")
_install_early_log_levels()
_enable_line_buffered_stdio()
_configure_python_recursion_limit()

from inertia_decompiler import cli as _cli
from inertia_decompiler.telemetry import emit_compact_summary

_THIS_MODULE = sys.modules[__name__]


class _CliProxyModule(ModuleType):
    def __getattr__(self, name: str):
        return getattr(_cli, name)

    def __setattr__(self, name: str, value):
        ModuleType.__setattr__(self, name, value)
        if name not in {"__class__", "__dict__"}:
            setattr(_cli, name, value)

    def __dir__(self) -> list[str]:
        return sorted(set(ModuleType.__dir__(self)) | set(dir(_cli)))


_THIS_MODULE.__class__ = _CliProxyModule
sys.modules[__name__] = _cli


if __name__ == "__main__":
    try:
        raise SystemExit(_cli.main())
    finally:
        emit_compact_summary()
