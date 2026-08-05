"""Focused tests for typed loop continuation materialization."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CForLoop,
    CStatements,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.structuring.loop_condition_materialization import (
    materialize_typed_loop_continuation_conditions_8616,
)


class _Codegen:
    """Minimal angr structured-C codegen fixture."""

    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return one deterministic structured-C node index."""
        self._next_idx += 1
        return self._next_idx


def _loop_fixture() -> tuple[_Codegen, CForLoop, CStatements, ConditionIR]:
    """Build one loop whose JCC fallthrough edge is the continuation."""
    codegen = _Codegen()
    value_type = SimTypeShort(True).with_arch(codegen.project.arch)
    condition = CBinaryOp(
        "CmpGE",
        CConstant(1, value_type, codegen=codegen),
        CConstant(4, value_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10126, "vex_block_addr": 0x10120},
    )
    loop = CForLoop(
        None,
        condition,
        None,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    typed = ConditionIR(
        op="sge",
        lhs=1,
        rhs=4,
        src_insn=0x10126,
        block_addr=0x10120,
        taken_target=0x1012B,
        fallthrough_target=0x10128,
    )
    return codegen, loop, root, typed


def test_materializes_inverted_fallthrough_loop_continuation() -> None:
    """The loop guard must use the edge that returns to the condition block."""
    codegen, loop, root, typed = _loop_fixture()
    successors = {0x10128: (0x10093,), 0x10093: (0x10120,), 0x1012B: ()}

    def lower_condition(_condition: ConditionIR) -> CBinaryOp:
        return CBinaryOp(
            "CmpGE",
            CConstant(1, SimTypeShort(True), codegen=codegen),
            CConstant(4, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lower_condition,
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.changed_count == 1
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpLT"
    assert loop.condition.tags["inertia_typed_loop_condition_key_8616"] == (0x10126, 0x10120)
    assert loop.condition.tags["inertia_typed_loop_continuation_edge_8616"] == "fallthrough"

    repeated = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lower_condition,
    )
    assert repeated.materialized_count == 1
    assert repeated.changed_count == 0


def test_refuses_ambiguous_loop_continuation_polarity() -> None:
    """No condition is replaced when both JCC edges can return to the header."""
    codegen, loop, root, typed = _loop_fixture()
    original = loop.condition
    successors = {
        0x10128: (0x10120,),
        0x1012B: (0x10120,),
    }

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lambda _condition: None,
    )

    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.changed is False
    assert loop.condition is original
    assert loop.condition.tags["inertia_typed_loop_condition_bound_8616"] is True


def test_linear_jump_trampoline_preserves_nested_loop_edge_ownership() -> None:
    """A jump-only latch block must retain the inner loop's continuation edge."""
    codegen, loop, root, typed = _loop_fixture()
    loop.body.tags = {"vex_block_addr": 0x10100}
    successors = {
        0x10128: (0x10100,),
        0x10100: (0x10120,),
        0x1012B: (0x10080,),
        0x10080: (0x10090, 0x100A0),
    }

    def lower_condition(_condition: ConditionIR) -> CBinaryOp:
        return CBinaryOp(
            "CmpGE",
            CConstant(1, SimTypeShort(True), codegen=codegen),
            CConstant(4, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lower_condition,
    )

    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpLT"
    assert loop.condition.tags["inertia_typed_loop_continuation_edge_8616"] == "fallthrough"


def test_nested_loop_uses_structured_body_ownership_when_both_edges_return() -> None:
    """An outer-loop re-entry must not make an inner-loop edge ambiguous."""
    codegen, loop, root, typed = _loop_fixture()
    loop.body.tags = {"vex_block_addr": 0x1012B}
    successors = {
        0x10128: (0x10080,),
        0x10080: (0x10120,),
        0x1012B: (0x10120,),
    }

    def lower_condition(_condition: ConditionIR) -> CBinaryOp:
        return CBinaryOp(
            "CmpGE",
            CConstant(1, SimTypeShort(True), codegen=codegen),
            CConstant(4, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        successors,
        lower_condition,
    )

    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpGE"
    assert loop.condition.tags["inertia_typed_loop_continuation_edge_8616"] == "taken"
