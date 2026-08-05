from __future__ import annotations

import subprocess

from inertia_decompiler import rizin_discovery


def test_rizin_json_timeout_is_optional(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=3)

    monkeypatch.setattr(rizin_discovery.subprocess, "run", timeout)

    assert rizin_discovery._run_rizin_json(binary, "iSj", timeout_sec=3) is None


def test_mz_prologue_candidates_survive_entrypoint_timeout(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes((b"\0" * 0x20) + b"\x55\x8b\xec")
    segments = [{"paddr": 0x10, "vaddr": 0, "vsize": 0x100, "perm": "-r-x"}]
    monkeypatch.setattr(rizin_discovery, "_run_rizin_json", lambda *args, **kwargs: segments)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=2)

    monkeypatch.setattr(rizin_discovery.subprocess, "run", timeout)

    candidates, detail = rizin_discovery._mz_linear_candidates_from_prologues(binary)

    assert candidates == [0x10010]
    assert detail == "mz_prologue_fallback"
