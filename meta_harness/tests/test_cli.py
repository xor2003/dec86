from __future__ import annotations

from meta_harness import cli


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

    monkeypatch.setattr(cli, "MetaHarness", DummyHarness)
    assert cli.main([]) == 0
    assert called["run"] is True
    assert called["resume"] is False
    assert "cfg" in called and "llm_cfg" in called


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

    monkeypatch.setattr(cli, "MetaHarness", DummyHarness)
    assert cli.main(["--resume"]) == 0
    assert called["resume"] is True
