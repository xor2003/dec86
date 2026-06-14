from __future__ import annotations

import io
import sys

import pytest

import meta_harness.llm as llm_mod
from meta_harness.config import LlmConfig
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


def test_run_provider_once_does_not_wrap_agent_in_wall_clock_timeout(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("hello", encoding="utf-8")
    log = tmp_path / "run.log"
    seen: dict[str, object] = {}

    class Proc:
        pid = 1236
        stdout = io.StringIO("provider output\n")

        def wait(self):
            return 0

    def fake_popen(cmd, *args, **kwargs):
        seen["cmd"] = list(cmd)
        return Proc()

    monkeypatch.setattr("meta_harness.llm.subprocess.Popen", fake_popen)

    rc = run_provider_once("codex", "new", "tiny", "prompt", prompt, log, cfg, timeout_secs=1)

    assert rc == 0
    cmd = seen["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:2] != ["timeout", "--foreground"]
    assert cmd[0] == "codex"


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


def test_run_provider_once_supports_mock_provider(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = tmp_path / "worker.prompt.txt"
    prompt.write_text("hello", encoding="utf-8")
    log = tmp_path / "run.log"
    script = tmp_path / "mock.jsonl"
    script.write_text(
        '{"role":"worker","mode":"new","output":"Green level: focused-item-green\\nGlobal Remaining steps: 0","exit_code":0}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MOCK_PROVIDER_SCRIPT", str(script))
    monkeypatch.setenv("MOCK_PROVIDER_INDEX_FILE", str(tmp_path / "mock.idx"))

    rc = run_provider_once("mock", "new", "mock-model", "prompt", prompt, log, cfg)

    assert rc == 0
    text = log.read_text(encoding="utf-8")
    assert "start provider=mock" in text
    assert "Green level: focused-item-green" in text
    assert "Global Remaining steps: 0" in text


def test_run_and_mirror_output_restarts_silent_agent(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENT_NO_OUTPUT_RESTART_SECS", "1")
    monkeypatch.setenv("AGENT_NO_OUTPUT_MAX_RESTARTS", "1")
    flag = tmp_path / "seen.flag"
    log = tmp_path / "silent.log"
    script = (
        "from pathlib import Path; import time; "
        f"p=Path({str(flag)!r}); "
        "print('ok', flush=True) if p.exists() else (p.write_text('1'), time.sleep(2))"
    )

    rc = llm_mod._run_and_mirror_output(
        [sys.executable, "-c", script],
        log_file=log,
        config=cfg,
        header="[test] start provider=mock mode=new model=x prompt=p root=r\n",
        env=llm_mod._provider_env(cfg),
        proc_name="python",
    )

    text = log.read_text(encoding="utf-8")
    assert rc == 0
    assert "log did not grow for 1s; restarting agent executable" in text
    assert "restart=1 start provider=mock" in text
    assert "ok" in text
