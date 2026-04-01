from __future__ import annotations

from meta_harness import cli


def test_cli_main_invokes_harness_run(monkeypatch):
    called = {}

    class DummyHarness:
        def __init__(self, cfg, llm_cfg):
            called["cfg"] = cfg
            called["llm_cfg"] = llm_cfg

        def run(self):
            called["run"] = True
            return 0

        def run_crash_review(self, exit_code):
            called["crash"] = exit_code

    monkeypatch.setattr(cli, "MetaHarness", DummyHarness)
    assert cli.main([]) == 0
    assert called["run"] is True
    assert "cfg" in called and "llm_cfg" in called
