"""Real-lifter regressions for complete typed IR CFG successors."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import IRBlock, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.block_ownership import (
    IRBlockOwnershipFailure8616,
    canonicalize_ir_block_ownership_8616,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401


def test_real_conditional_exit_retains_taken_and_fallthrough_successors() -> None:
    project = angr.Project(
        io.BytesIO(bytes.fromhex("83fa007402eb00c3")),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000, 0x1005, 0x1007},
        info={},
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    ssa = build_x86_16_function_ssa(artifact)

    assert not artifact.refusals
    assert artifact.blocks[0].successor_addrs == (0x1005, 0x1007)
    assert ssa.predecessor_map == {
        0x1000: (),
        0x1005: (0x1000,),
        0x1007: (0x1000, 0x1005),
    }


def test_overlapping_real_blocks_assign_call_to_exact_start_owner() -> None:
    """Require one canonical CALL when CFG recovery emits overlapping blocks."""
    project = angr.Project(
        io.BytesIO(bytes.fromhex("b80100e80000c3")),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    nodes = {address: SimpleNamespace(addr=address) for address in (0x1000, 0x1003, 0x1006)}
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set=set(nodes),
        graph=SimpleNamespace(
            edges=((nodes[0x1000], nodes[0x1003]), (nodes[0x1003], nodes[0x1006]))
        ),
        info={},
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    calls = tuple(
        (block.addr, instruction.addr)
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )

    assert calls == ((0x1003, 0x1003),)
    assert artifact.summary["block_ownership_classified_fact_count"] > 0
    assert (
        artifact.summary["block_ownership_materialized_count"]
        == artifact.summary["block_ownership_classified_fact_count"]
    )
    assert artifact.summary["block_ownership_failure_count"] == 0


def test_overlap_without_exact_owner_decode_is_refused_and_preserved() -> None:
    """Keep an overlap when the proposed owner does not decode its instruction."""
    call = IRInstr(
        "CALL",
        None,
        (IRValue(MemSpace.CONST, const=0x2000, size=2),),
        addr=0x1003,
    )
    evidence = canonicalize_ir_block_ownership_8616(
        (
            IRBlock(0x1000, (call,), successor_addrs=(0x1003,)),
            IRBlock(0x1003),
        )
    )

    assert evidence.blocks[0].instrs == (call,)
    assert evidence.stats.materialized_count == 0
    assert evidence.stats.failure_count == 1
    assert (
        evidence.refusals[0].failure
        is IRBlockOwnershipFailure8616.CANONICAL_OWNER_MISSING_INSTRUCTION
    )
