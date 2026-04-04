from __future__ import annotations

import io
from pathlib import Path

import pytest

from meta_harness.config import LlmConfig
import meta_harness.llm as llm_mod
from meta_harness.llm import (
    build_effective_prompt,
    extract_session_id,
    is_local_provider,
    run_provider_once,
    validate_output,
)


def _cfg(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    return LlmConfig.from_env()


def test_build_effective_prompt_adds_local_guardrails(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_effective_prompt("worker", "ollama", "Base prompt", cfg, "")
    assert "Local-model guardrails" in prompt
    assert "Global Remaining steps: N" in prompt


def test_validate_output_rejects_bad_local_output(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    log = tmp_path / "bad.log"
    log.write_text("As an AI, I need more context.\nGlobal Remaining steps: 3\n", encoding="utf-8")
    assert not validate_output("worker", "ollama", log, cfg)


def test_validate_output_accepts_good_local_output(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    log = tmp_path / "good.log"
    log.write_text(
        (
            "correctness: improving in a concrete and evidence-backed way\n"
            "recompilation: improving with stable actionable next steps\n"
            "Global Remaining steps: 2\n"
            "Extra details for validation with enough content to clear the local-model minimum output size guardrail.\n"
        ),
        encoding="utf-8",
    )
    assert validate_output("reviewer", "ollama", log, cfg)


def test_extract_session_id_and_provider_kind():
    assert extract_session_id("session id: abc-123\n") == "abc-123"
    assert is_local_provider("ollama")
    assert not is_local_provider("codex")


def test_run_provider_once_writes_timestamps(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("hello", encoding="utf-8")
    log = tmp_path / "run.log"

    class Proc:
        pid = 1234
        stdout = io.StringIO("provider output\n")

        def wait(self):
            return 0

    def fake_popen(*args, **kwargs):
        assert str(cfg.root_dir) in kwargs["env"].get("PYTHONPATH", "")
        return Proc()

    monkeypatch.setattr("meta_harness.llm.subprocess.Popen", fake_popen)

    rc = run_provider_once("ollama", "new", "tiny", "prompt", prompt, log, cfg)

    assert rc == 0
    text = log.read_text(encoding="utf-8")
    assert "start provider=ollama" in text
    assert "provider output" in text
    assert "end rc=0" in text
    assert "provider output" in cfg.last_log_file.read_text(encoding="utf-8")


def test_run_provider_once_applies_codex_memory_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_MEMORY_LIMIT_MB", "512")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    cfg = _cfg(monkeypatch, tmp_path)
    if llm_mod.resource is None:
        pytest.skip("resource module unavailable")

    prompt = tmp_path / "prompt.txt"
    prompt.write_text("hello", encoding="utf-8")
    log = tmp_path / "run.log"
    seen = {}

    class Proc:
        pid = 1235
        stdout = io.StringIO("")

        def wait(self):
            return 0

    def fake_popen(*args, **kwargs):
        seen["kwargs"] = kwargs
        preexec = kwargs.get("preexec_fn")
        assert preexec is not None
        preexec()
        assert str(cfg.root_dir) in kwargs["env"].get("PYTHONPATH", "")
        return Proc()

    calls = []

    def fake_setrlimit(limit_type, limits):
        calls.append((limit_type, limits))

    monkeypatch.setattr(llm_mod.resource, "setrlimit", fake_setrlimit)
    monkeypatch.setattr("meta_harness.llm.subprocess.Popen", fake_popen)

    rc = run_provider_once("codex", "new", "tiny", "prompt", prompt, log, cfg)

    assert rc == 0
    assert "preexec_fn" in seen["kwargs"]
    assert calls


def test_run_provider_once_streams_live_output_into_last_log(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("hello", encoding="utf-8")
    log = tmp_path / "run.log"
    events: list[str] = []

    class StreamingStdout:
        def __iter__(self):
            yield "first line\n"
            events.append(cfg.last_log_file.read_text(encoding="utf-8"))
            yield "second line\n"

    class Proc:
        pid = 9999
        stdout = StreamingStdout()

        def wait(self):
            return 0

    monkeypatch.setattr("meta_harness.llm.subprocess.Popen", lambda *args, **kwargs: Proc())

    rc = run_provider_once("codex", "new", "tiny", "prompt", prompt, log, cfg)

    assert rc == 0
    assert events
    assert "first line" in events[0]
    assert "second line" in cfg.last_log_file.read_text(encoding="utf-8")
