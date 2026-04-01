from __future__ import annotations

import json
from pathlib import Path

from meta_harness.config import LlmConfig, RuntimeConfig
from meta_harness.orchestrator import MetaHarness


def _make_cfg(monkeypatch, tmp_path: Path) -> tuple[RuntimeConfig, LlmConfig]:
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    llm_cfg = LlmConfig.from_env()
    return cfg, llm_cfg


def _write_cycle_state(cycle_dir: Path, steps: dict[str, str], cycle: int = 1) -> None:
    cycle_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "cycle": cycle,
        "started_at": "2026-04-01T00:00:00+00:00",
        "updated_at": "2026-04-01T00:00:00+00:00",
        "completed": False,
        "steps": {
            name: {"status": status, "updated_at": "2026-04-01T00:00:00+00:00", "extra": ""}
            for name, status in steps.items()
        },
    }
    (cycle_dir / "cycle.state.json").write_text(json.dumps(state), encoding="utf-8")


def test_peek_resume_step_reads_latest_cycle_state(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    latest = cfg.runs_dir / "20260401_000001_cycle001"
    _write_cycle_state(
        latest,
        {
            "full-sweep": "done",
            "checker": "done",
            "planner": "done",
            "worker": "running",
            "reviewer": "pending",
        },
    )

    harness = MetaHarness(cfg, llm_cfg)

    assert harness.peek_resume_step() == "worker"


def test_run_resume_skips_completed_steps(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    latest = cfg.runs_dir / "20260401_000001_cycle001"
    _write_cycle_state(
        latest,
        {
            "full-sweep": "done",
            "checker": "done",
            "planner": "done",
            "worker": "running",
            "reviewer": "pending",
        },
    )

    harness = MetaHarness(cfg, llm_cfg)
    calls: list[str] = []

    monkeypatch.setattr(harness, "ensure_prereqs", lambda: None)
    monkeypatch.setattr(harness, "acquire_lock", lambda: None)
    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda _tag: calls.append(f"snapshot:{_tag}"))
    monkeypatch.setattr(harness, "maybe_self_restart", lambda _reason: False)
    monkeypatch.setattr(harness, "sweep_step", lambda: calls.append("sweep"))
    monkeypatch.setattr(harness, "checker_step", lambda: calls.append("checker"))
    monkeypatch.setattr(harness, "planner_step", lambda: calls.append("planner"))
    monkeypatch.setattr(harness, "worker_cycle", lambda: calls.append("worker"))
    monkeypatch.setattr(harness, "reviewer_step", lambda: "0")

    assert harness.run(resume=True) == 0
    assert "sweep" not in calls
    assert "checker" not in calls
    assert "planner" not in calls
    assert "worker" in calls

