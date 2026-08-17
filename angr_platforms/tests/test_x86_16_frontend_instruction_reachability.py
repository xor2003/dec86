from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_instruction_reachability import (
    collect_instruction_reachability_8616,
    decoded_block_instructions_8616,
)
from angr_platforms.X86_16.recovery_instruction_coverage import (
    ExactInstructionCoverageVerdict8616,
    collect_exact_instruction_coverage_8616,
)

from inertia_decompiler.project_loading import _build_project_from_bytes


def _unreachable_padding_project() -> object:
    return _build_project_from_bytes(
        bytes.fromhex("eb 03 90 90 90 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )


def test_frontend_reachability_excludes_bytes_skipped_by_direct_jump() -> None:
    evidence = collect_instruction_reachability_8616(
        _unreachable_padding_project(),
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1006,
    )

    assert evidence.complete is True
    assert evidence.reachable_instruction_addrs == (0x1000, 0x1005)
    assert evidence.unresolved_block_addrs == ()
    assert evidence.raw_fact_count == 2
    assert evidence.materialized_count == 2
    assert evidence.failure_count == 0


def test_frontend_reachability_refuses_unresolved_indirect_jump() -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("ff e0"),
        base_addr=0x1000,
        entry_point=0x1000,
    )

    evidence = collect_instruction_reachability_8616(
        project,
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1002,
    )

    assert evidence.complete is False
    assert evidence.unresolved_block_addrs == (0x1000,)
    assert evidence.failure_count == 1


def test_frontend_reachability_records_lifter_runtime_refusal(monkeypatch) -> None:
    """An unsupported seed is unresolved evidence, not an audit crash."""
    project = _unreachable_padding_project()

    def refuse_block(_addr: int, *, opt_level: int) -> object:
        raise RuntimeError("unsupported instruction")

    monkeypatch.setattr(project.factory, "block", refuse_block)

    evidence = collect_instruction_reachability_8616(
        project,
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1006,
    )

    assert evidence.complete is False
    assert evidence.unresolved_block_addrs == (0x1000,)
    assert evidence.failure_count == 1


def test_frontend_block_inventory_reuses_only_exact_decode_requests() -> None:
    calls: list[tuple[int, int | None, int]] = []
    instruction = SimpleNamespace(address=0x1000, size=1, mnemonic="nop")

    def decode_block(
        address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> object:
        calls.append((address, num_inst, opt_level))
        return SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))

    project = SimpleNamespace(factory=SimpleNamespace(block=decode_block))

    first = decoded_block_instructions_8616(project, 0x1000, num_inst=1, opt_level=0)
    second = decoded_block_instructions_8616(project, 0x1000, num_inst=1, opt_level=0)
    whole_block = decoded_block_instructions_8616(project, 0x1000, opt_level=0)

    assert first == second == whole_block == (instruction,)
    assert calls == [(0x1000, 1, 0), (0x1000, None, 0)]


def test_frontend_block_inventory_reuses_deterministic_refusals() -> None:
    calls = 0

    class DeterministicDecodeError(RuntimeError):
        pass

    def refuse_block(
        _address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> object:
        nonlocal calls
        calls += 1
        raise DeterministicDecodeError(f"missing bytes limit={num_inst} opt={opt_level}")

    project = SimpleNamespace(factory=SimpleNamespace(block=refuse_block))

    for _attempt in range(2):
        with pytest.raises(
            DeterministicDecodeError,
            match="missing bytes limit=1 opt=0",
        ):
            decoded_block_instructions_8616(project, 0x200, num_inst=1, opt_level=0)

    assert calls == 1


def test_exact_coverage_accepts_only_binary_proven_unreachable_instructions() -> None:
    project = _unreachable_padding_project()
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            project.factory.block(0x1000, opt_level=0),
            project.factory.block(0x1005, opt_level=0),
        ),
    )
    metadata = SimpleNamespace(
        cod_raw_entries=(
            {"offset": 0, "bytes": bytes.fromhex("eb 03")},
            {"offset": 2, "bytes": bytes.fromhex("90")},
            {"offset": 3, "bytes": bytes.fromhex("90")},
            {"offset": 4, "bytes": bytes.fromhex("90")},
            {"offset": 5, "bytes": bytes.fromhex("c3")},
        )
    )

    evidence = collect_exact_instruction_coverage_8616(
        project,
        function,
        metadata,  # type: ignore[arg-type]
    )

    assert evidence.verdict is ExactInstructionCoverageVerdict8616.COMPLETE
    assert evidence.complete is True
    assert evidence.proven_unreachable_instruction_addrs == (0x1002, 0x1003, 0x1004)
    assert evidence.materialized_count == 2
    assert evidence.excluded_unreachable_count == 3
    assert evidence.failure_count == 0
