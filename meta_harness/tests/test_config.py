from __future__ import annotations

from meta_harness.config import DEFAULT_EVIDENCE_INPUT_FILES, LlmConfig, RuntimeConfig


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


def test_llm_config_provider_override(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("REVIEWER_PROVIDER", "codex")
    cfg = LlmConfig.from_env()
    assert cfg.provider_for_key("worker") == "ollama"
    assert cfg.provider_for_key("reviewer") == "codex"
