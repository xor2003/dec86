from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler import cli_function_discovery


def test_direct_argument_context_attaches_framed_ranges_and_entry_aliases(monkeypatch) -> None:
    source_project = SimpleNamespace()
    target_project = SimpleNamespace()
    evidence_project = SimpleNamespace()
    ranges = ((0x1000, 0x1080), (0x1100, 0x1180))

    monkeypatch.setattr(
        cli_function_discovery,
        "isolated_discovery_evidence_project_8616",
        lambda project: evidence_project,
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda project: (0x1000, 0x1100),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_binary_padding_entry_aliases_8616",
        lambda project, seed: (seed, seed + 0x10),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_pre_entry_source_function_ranges_8616",
        lambda project, seeds: ranges,
    )

    attached = cli_function_discovery.attach_direct_target_argument_evidence_context_8616(
        source_project,
        target_project,
        0x1010,
    )

    assert attached is True
    assert target_project._inertia_caller_function_ranges_8616 == ranges
    assert target_project._inertia_caller_target_aliases_8616 == (0x1000, 0x1010)


def test_direct_argument_context_refuses_unknown_target(monkeypatch) -> None:
    project = SimpleNamespace()
    monkeypatch.setattr(
        cli_function_discovery,
        "isolated_discovery_evidence_project_8616",
        lambda source: project,
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda source: (0x1000,),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_binary_padding_entry_aliases_8616",
        lambda source, seed: (seed,),
    )

    assert (
        cli_function_discovery.attach_direct_target_argument_evidence_context_8616(
            project,
            SimpleNamespace(),
            0x2000,
        )
        is False
    )
