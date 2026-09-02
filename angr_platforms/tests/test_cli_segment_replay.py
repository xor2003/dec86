"""Tests for regenerated CLI segment-lowering orchestration."""

from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler import cli_decompilation


def test_runtime_segment_replay_always_replays_named_global_identities(monkeypatch) -> None:
    """A pre-existing runtime helper still needs Lowering-owned identity replay."""
    calls: list[str] = []
    project = SimpleNamespace(_inertia_c_target="portable-flat")
    codegen = SimpleNamespace(project=project)

    monkeypatch.setattr(
        cli_decompilation,
        "apply_runtime_segment_lowering_8616",
        lambda *_args, **_kwargs: calls.append("runtime") or False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "_replay_named_segmented_global_lowering_after_regen_8616",
        lambda _codegen: calls.append("named") or True,
    )

    assert cli_decompilation._replay_runtime_segment_lowering_after_regen_8616(codegen) is True
    assert calls == ["runtime", "named"]
