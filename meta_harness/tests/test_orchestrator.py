from __future__ import annotations

import json
from pathlib import Path

from meta_harness.config import LlmConfig, RuntimeConfig
from meta_harness.orchestrator import MetaHarness, RoleRunError


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


def test_sweep_step_does_not_tee_back_into_evidence_log(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    cfg.evidence_log_file.parent.mkdir(parents=True, exist_ok=True)

    for rel in cfg.evidence_input_files:
        path = cfg.root_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stub\n", encoding="utf-8")

    calls = {}

    class DummyProc:
        pid = 4321

        def wait(self):
            return 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_popen(cmd, cwd=None, env=None, stdout=None, stderr=None, **kwargs):
        calls["cmd"] = cmd
        if hasattr(stdout, "write"):
            stdout.write("sweep output\n")
            stdout.flush()
        return DummyProc()

    class RunResult:
        def __init__(self, stdout=""):
            self.stdout = stdout
            self.returncode = 0

    def fake_run(*args, **kwargs):
        return RunResult("")

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "trim_old_logs", lambda: None)
    monkeypatch.setattr("meta_harness.orchestrator.register_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.unregister_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", fake_run)
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.Popen", fake_popen)

    harness.sweep_step()

    assert calls["cmd"][-1] == cfg.sweep_cmd
    assert "tee -a" not in calls["cmd"][-1]


def test_sweep_step_allows_completed_sweep_with_failures(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    cfg.evidence_log_file.parent.mkdir(parents=True, exist_ok=True)

    for rel in cfg.evidence_input_files:
        path = cfg.root_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stub\n", encoding="utf-8")

    class DummyProc:
        pid = 4322

        def wait(self):
            return 1

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_popen(cmd, cwd=None, env=None, stdout=None, stderr=None, **kwargs):
        if hasattr(stdout, "write"):
            stdout.write("done in 1.0s; failures=1/2\n")
            stdout.flush()
        return DummyProc()

    class RunResult:
        def __init__(self):
            self.stdout = ""
            self.returncode = 0

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "trim_old_logs", lambda: None)
    monkeypatch.setattr("meta_harness.orchestrator.register_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.unregister_child_process", lambda *args, **kwargs: None)
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.run", lambda *args, **kwargs: RunResult())
    monkeypatch.setattr("meta_harness.orchestrator.subprocess.Popen", fake_popen)

    harness.sweep_step()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["full-sweep"]["status"] == "done-with-failures"


def test_finalize_run_marks_terminated_cycle_and_captures_snapshot(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()
    harness.mark_cycle_step("planner", "running")

    captured = []
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda tag: captured.append(tag))

    harness.finalize_run("terminated", 143)

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert state["steps"]["planner"]["status"] == "terminated"
    assert state["steps"]["planner"]["extra"] == "exit_code=143"
    assert captured == ["terminated"]


def test_worker_cycle_retries_after_failed_fresh_run(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    harness = MetaHarness(cfg, llm_cfg)
    harness.prepare_cycle_workspace()

    failed_log = cfg.log_dir / "failed_worker.log"
    failed_log.parent.mkdir(parents=True, exist_ok=True)
    failed_log.write_text("partial output\n", encoding="utf-8")

    success_log = cfg.log_dir / "ok_worker.log"
    success_log.write_text("correctness\nrecompilation\nGlobal Remaining steps: 0\n", encoding="utf-8")

    calls = {"count": 0}

    def fake_run_role(role, model, prompt, resume=False):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RoleRunError(role, failed_log, "worker resume failed")
        if calls["count"] == 2:
            raise RoleRunError(role, failed_log, "worker failed")
        return success_log

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)
    monkeypatch.setattr("meta_harness.orchestrator.time.sleep", lambda _secs: None)

    harness.worker_cycle()

    state = json.loads((harness.current_cycle_dir / "cycle.state.json").read_text(encoding="utf-8"))
    assert calls["count"] == 3
    assert state["steps"]["worker"]["status"] == "done"
    assert (harness.current_cycle_dir / "worker.iter01.resume-failed.log").exists()
    assert (harness.current_cycle_dir / "worker.iter01.failed.log").exists()
    assert (harness.current_cycle_dir / "worker.iter02.log").exists()
