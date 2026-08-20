"""Regressions for carry proof over exact Semantics-owned call outputs."""

from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.semantics.carry_borrow_contracts import CarryBorrowFailure8616
from angr_platforms.X86_16.semantics.carry_borrow_links import analyze_carry_borrow_links_8616


def _lift_after_dx_ax_call() -> SSAFunctionArtifact:
    project = angr.Project(
        io.BytesIO(bytes.fromhex("01 d8 11 ca c3")),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    artifact = build_x86_16_ir_function_artifact(project, function)
    block = artifact.blocks[0]
    outputs = tuple(
        IRInstr(
            "CALL_OUTPUT",
            IRValue(
                MemSpace.REG,
                name=name,
                size=2,
                expr=("call_output", "dx_ax", "0xff0"),
            ),
            (IRValue(MemSpace.CONST, const=0x2000, size=4),),
            size=2,
            addr=0xFF0,
        )
        for name in ("ax", "dx")
    )
    enriched = replace(
        artifact,
        blocks=(replace(block, instrs=(*outputs, *block.instrs)),),
    )
    return build_x86_16_function_ssa(enriched)


def _low_adds(artifact: SSAFunctionArtifact) -> tuple[tuple[int, IRInstr], ...]:
    return tuple(
        (index, instruction)
        for block in artifact.blocks
        for index, instruction in enumerate(block.instrs)
        if instruction.addr == 0x1000 and instruction.op == "Iop_Add16"
    )


def test_call_output_preserves_prewrite_operand_for_carry_proof() -> None:
    artifact = _lift_after_dx_ax_call()
    adds = _low_adds(artifact)

    assert len(adds) == 2
    for _index, addition in adds:
        lhs = addition.args[0]
        assert isinstance(lhs, IRValue)
        assert (lhs.name, lhs.version, lhs.source_tmp) == ("ax", 0, 0)

    evidence = analyze_carry_borrow_links_8616(artifact)

    assert evidence.complete
    assert evidence.stats.raw_fact_count == evidence.stats.materialized_count == 1
    link = evidence.links[0]
    assert link.low_result_write.instruction.dst is not None
    assert link.low_result_write.instruction.dst.version == 1


def test_carry_proof_refuses_corrupted_temporary_snapshot_version() -> None:
    artifact = _lift_after_dx_ax_call()
    adds = _low_adds(artifact)
    flags_add_index, flags_add = adds[1]
    lhs = flags_add.args[0]
    assert isinstance(lhs, IRValue)
    changed_add = replace(flags_add, args=(replace(lhs, version=1), *flags_add.args[1:]))
    block = artifact.blocks[0]
    instructions = list(block.instrs)
    instructions[flags_add_index] = changed_add
    corrupted = replace(artifact, blocks=(replace(block, instrs=tuple(instructions)),))

    evidence = analyze_carry_borrow_links_8616(corrupted)

    assert evidence.complete
    assert evidence.stats.raw_fact_count == evidence.stats.failure_count == 1
    assert evidence.stats.materialized_count == 0
    assert evidence.resolutions[0].failure is CarryBorrowFailure8616.LOW_RESULT_AMBIGUOUS
