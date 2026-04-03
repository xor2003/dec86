from __future__ import annotations

from meta_harness import cli
from meta_harness.orchestrator import RoleRunError


def test_cli_main_invokes_harness_run(monkeypatch):
    called = {}

    class DummyHarness:
        def __init__(self, cfg, llm_cfg):
            called["cfg"] = cfg
            called["llm_cfg"] = llm_cfg

        def run(self, resume=False):
            called["run"] = True
            called["resume"] = resume
            return 0

        def run_crash_review(self, exit_code):
            called["crash"] = exit_code

        def finalize_run(self, reason, exit_code):
            called["finalize"] = (reason, exit_code)

    monkeypatch.setattr(cli, "MetaHarness", DummyHarness)
    assert cli.main([]) == 0
    assert called["run"] is True
    assert called["resume"] is False
    assert "cfg" in called and "llm_cfg" in called
    assert "finalize" not in called


def test_cli_main_passes_resume_flag(monkeypatch):
    called = {}

    class DummyHarness:
        def __init__(self, cfg, llm_cfg):
            called["cfg"] = cfg
            called["llm_cfg"] = llm_cfg

        def peek_resume_step(self):
            return None

        def run(self, resume=False):
            called["resume"] = resume
            return 0

        def run_crash_review(self, exit_code):
            called["crash"] = exit_code

        def finalize_run(self, reason, exit_code):
            called["finalize"] = (reason, exit_code)

    monkeypatch.setattr(cli, "MetaHarness", DummyHarness)
    assert cli.main(["--resume"]) == 0
    assert called["resume"] is True
    assert "finalize" not in called


def test_cli_main_marks_sigterm_exit_as_terminated(monkeypatch):
    called = {}

    class DummyHarness:
        def __init__(self, cfg, llm_cfg):
            called["cfg"] = cfg
            called["llm_cfg"] = llm_cfg

        def peek_resume_step(self):
            return None

        def run(self, resume=False):
            raise SystemExit(143)

        def run_crash_review(self, exit_code):
            called["crash"] = exit_code

        def finalize_run(self, reason, exit_code):
            called["finalize"] = (reason, exit_code)

    monkeypatch.setattr(cli, "MetaHarness", DummyHarness)
    try:
        cli.main([])
    except SystemExit as exc:
        assert exc.code == 143
    else:  # pragma: no cover
        raise AssertionError("Expected SystemExit(143)")

    assert called["finalize"] == ("terminated", 143)


def test_cli_main_treats_planner_timeout_as_terminated(monkeypatch):
    called = {}

    class DummyHarness:
        def __init__(self, cfg, llm_cfg):
            called["cfg"] = cfg
            called["llm_cfg"] = llm_cfg

        def peek_resume_step(self):
            return None

        def run(self, resume=False):
            raise RoleRunError("planner", object(), "planner timed out", 124)

        def run_crash_review(self, exit_code):
            called["crash"] = exit_code

        def finalize_run(self, reason, exit_code):
            called["finalize"] = (reason, exit_code)

    monkeypatch.setattr(cli, "MetaHarness", DummyHarness)
    assert cli.main([]) == 124
    assert called["finalize"] == ("terminated", 124)
    assert "crash" not in called
