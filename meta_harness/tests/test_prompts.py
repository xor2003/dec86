from __future__ import annotations

from meta_harness.config import RuntimeConfig
from meta_harness.prompts import (
    build_checker_prompt,
    build_crash_reviewer_prompt,
    build_planner_prompt,
    build_reviewer_prompt,
    build_worker_prompt,
)


def _cfg(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    return RuntimeConfig.from_env([])


def test_planner_prompt_mentions_plan_and_remaining_steps(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_planner_prompt(cfg)
    assert str(cfg.plan_path) in prompt
    assert "Global Remaining steps: N" in prompt
    assert "Do not rerun the evidence sweep" in prompt


def test_worker_prompt_mentions_implementation_role(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_worker_prompt(cfg)
    assert "Continue implementing the unfinished steps" in prompt
    assert "Never use source-specific hacks" in prompt


def test_reviewer_prompt_allows_harness_improvements(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    prompt = build_reviewer_prompt(cfg)
    assert "improve the harness itself" in prompt


def test_checker_and_crash_prompts_reference_evidence(monkeypatch, tmp_path):
    cfg = _cfg(monkeypatch, tmp_path)
    checker = build_checker_prompt(cfg)
    crash = build_crash_reviewer_prompt(cfg, "/tmp/cycle", 7)
    assert str(cfg.evidence_log_file) in checker
    assert "Harness restart required" in crash
    assert "/tmp/cycle" in crash
