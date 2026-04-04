from __future__ import annotations

import math

from meta_harness.config import (
    CORE_EVIDENCE_INPUT_FILES,
    DEFAULT_EVIDENCE_INPUT_FILES,
    F14_EVIDENCE_INPUT_FILES,
    LlmConfig,
    RuntimeConfig,
)


def test_runtime_config_reads_multiline_evidence_files(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.setenv("EVIDENCE_INPUT_FILES", "a.txt\nb.txt\n")
    cfg = RuntimeConfig.from_env([])
    assert cfg.evidence_input_files == ["a.txt", "b.txt"]


def test_runtime_config_uses_default_evidence_files(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.delenv("EVIDENCE_INPUT_FILES", raising=False)
    cfg = RuntimeConfig.from_env([])
    assert cfg.evidence_input_files == DEFAULT_EVIDENCE_INPUT_FILES
    expected_f14 = F14_EVIDENCE_INPUT_FILES[: max(1, math.ceil(len(F14_EVIDENCE_INPUT_FILES) * 0.10))]
    assert cfg.evidence_input_files == CORE_EVIDENCE_INPUT_FILES + expected_f14


def test_llm_config_provider_override(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("REVIEWER_PROVIDER", "codex")
    cfg = LlmConfig.from_env()
    assert cfg.provider_for_key("worker") == "ollama"
    assert cfg.provider_for_key("reviewer") == "codex"


def test_runtime_config_uses_default_operator_comments_file(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.operator_comments_file == tmp_path / "HARNESS_COMMENTS.md"


def test_runtime_config_uses_default_consecutive_worker_failure_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.max_consecutive_worker_failures == 3
    assert cfg.worker_stall_failure_limit == 2


def test_runtime_config_uses_default_worker_session_log_budget(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.max_worker_session_log_bytes == 512 * 1024


def test_runtime_config_uses_web_ui_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.web_ui_enabled is True
    assert cfg.web_ui_auto_open is True
    assert cfg.web_ui_host == "127.0.0.1"
    assert cfg.web_ui_port == 8765


def test_runtime_config_uses_compact_prompt_defaults_and_default_models(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.compact_prompts is True
    assert cfg.delta_resume_prompts is True
    assert cfg.planner_model == "gpt-5.4"
    assert cfg.reviewer_model == "gpt-5.4-mini"
    assert cfg.worker_stall_model == "gpt-5.4"
    assert cfg.worker_stall_escalation_threshold == 1
    assert cfg.crash_reviewer_model == "gpt-5.4"
