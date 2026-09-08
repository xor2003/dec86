"""Tests for CFG-owned multi-arm condition provenance."""

from dataclasses import replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.structuring.multi_arm_condition_ownership import (
    MultiArmConditionOwnershipStatus8616,
    materialize_multi_arm_condition_owners_8616,
    select_multi_arm_condition_owners_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._next_index += 1
        return self._next_index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _dispatch_conditions() -> tuple[ConditionIR, ConditionIR]:
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    return (
        ConditionIR(
            op="zero",
            lhs=argument,
            source=("test", "je"),
            src_insn=0x1012,
            block_addr=0x1010,
            producer_insn=0x1010,
            taken_target=0x1100,
            fallthrough_target=0x1020,
        ),
        ConditionIR(
            op="eq",
            lhs=argument,
            rhs=IRValue(MemSpace.CONST, const=1, size=2),
            source=("cmp", "je"),
            src_insn=0x1021,
            block_addr=0x1020,
            producer_insn=0x1020,
            taken_target=0x1200,
            fallthrough_target=0x1030,
            producer_semantics=("dec_reg16", "ax", 1),
        ),
    )


def test_multi_arm_ownership_selects_exact_taken_edges_in_fallthrough_order() -> None:
    root, second = _dispatch_conditions()

    result = select_multi_arm_condition_owners_8616(
        (0x1100, 0x1200),
        (root, second),
        root=root,
        successors={
            0x1010: (0x1100, 0x1020),
            0x1020: (0x1200, 0x1030),
        },
    )

    assert result.status is MultiArmConditionOwnershipStatus8616.SELECTED
    assert result.facts == (root, second)


def test_multi_arm_ownership_refuses_a_disconnected_decision_ladder() -> None:
    root, second = _dispatch_conditions()
    disconnected_root = replace(root, fallthrough_target=0x1090)

    result = select_multi_arm_condition_owners_8616(
        (0x1100, 0x1200),
        (disconnected_root, second),
        root=disconnected_root,
        successors={
            0x1010: (0x1100, 0x1090),
            0x1020: (0x1200, 0x1030),
        },
    )

    assert (
        result.status
        is MultiArmConditionOwnershipStatus8616.DISCONNECTED_FALLTHROUGH
    )
    assert result.facts == ()


def test_multi_arm_materialization_replaces_copied_tags_with_fact_owners() -> None:
    root, second = _dispatch_conditions()
    ownership = select_multi_arm_condition_owners_8616(
        (0x1100, 0x1200),
        (root, second),
        root=root,
        successors={
            0x1010: (0x1100, 0x1020),
            0x1020: (0x1200, 0x1030),
        },
    )
    codegen = _Codegen()
    first_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    second_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    copied_tags = {"ins_addr": root.src_insn, "vex_block_addr": root.block_addr}
    first_condition.tags = dict(copied_tags)
    second_condition.tags = dict(copied_tags)
    first_body = CStatements([], codegen=codegen, tags={"ins_addr": 0x1100})
    second_body = CStatements([], codegen=codegen, tags={"ins_addr": 0x1200})

    result = materialize_multi_arm_condition_owners_8616(
        ((first_condition, first_body), (second_condition, second_body)),
        ownership,
        lambda fact: CConstant(
            fact.src_insn,
            SimTypeShort(False),
            codegen=codegen,
        ),
    )

    assert result.raw_fact_count == 2
    assert result.normalized_fact_count == 2
    assert result.classified_fact_count == 2
    assert result.materialized_count == 2
    assert result.failure_count == 0
    assert result.condition_and_nodes[0][1] is first_body
    assert result.condition_and_nodes[1][1] is second_body
    replacements = tuple(condition for condition, _body in result.condition_and_nodes)
    assert replacements[0].tags["ins_addr"] == 0x1012
    assert replacements[1].tags["ins_addr"] == 0x1021
    assert replacements[1].tags["vex_block_addr"] == 0x1020
    assert replacements[1].tags[
        "inertia_structuring_multi_arm_owner_materialized_8616"
    ] is True
