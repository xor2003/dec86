"""Tests for deterministic startup of the focused decompilation batch helper."""

from __future__ import annotations

import os
import sys

import pytest

from scripts import batch_decompile_procs


class _ReexecObserved(RuntimeError):
    """Stop a mocked successful exec replacement."""


def test_batch_decompile_reexecs_before_decompiler_use(monkeypatch) -> None:
    """A random hash runtime must restart with stable hashing and the JIT enabled."""
    monkeypatch.delenv("PYTHONHASHSEED", raising=False)
    monkeypatch.delenv("PYTHON_JIT", raising=False)
    monkeypatch.setattr(sys, "argv", ["batch_decompile_procs.py", "--help"])

    def _execvpe(executable: str, argv: list[str], environment: dict[str, str]) -> None:
        assert executable == sys.executable
        assert argv[0] == sys.executable
        assert argv[-1] == "--help"
        assert environment["PYTHONHASHSEED"] == "0"
        assert environment["PYTHON_JIT"] == "1"
        raise _ReexecObserved

    monkeypatch.setattr(os, "execvpe", _execvpe)

    with pytest.raises(_ReexecObserved):
        batch_decompile_procs._ensure_deterministic_python_runtime_8616()


def test_batch_decompile_keeps_deterministic_runtime(monkeypatch) -> None:
    """An already deterministic JIT process must not replace itself."""
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setenv("PYTHON_JIT", "1")
    monkeypatch.setattr(
        os,
        "execvpe",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected re-exec")),
    )

    batch_decompile_procs._ensure_deterministic_python_runtime_8616()
