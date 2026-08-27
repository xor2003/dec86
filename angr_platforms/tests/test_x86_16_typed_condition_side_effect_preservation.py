from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr_platforms.X86_16 import decompiler_postprocess_jcc
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.condition_call_effects import (
    ConditionCallEffectKind8616,
    classify_condition_call_effects_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_typed_conditions import (
    _apply_typed_conditions_to_codegen_8616,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.structuring import condition_materialization


class _Graph:
    def __init__(self, edges: tuple[tuple[int, int], ...]) -> None:
        self._successors: dict[int, list[int]] = {}
        for source, target in edges:
            self._successors.setdefault(source, []).append(target)
            self._successors.setdefault(target, [])
        self.nodes = tuple(self._successors)

    def successors(self, node: int) -> tuple[int, ...]:
        return tuple(self._successors[node])


def _codegen() -> SimpleNamespace:
    project = SimpleNamespace(arch=Arch86_16())
    node_ids = iter(range(1, 100))
    return SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: next(node_ids),
        next_node_idx=lambda: next(node_ids),
        next_ident=lambda name: name,
    )


def _semantic_call(codegen: object, *, callsite: int = 0x101D4) -> CFunctionCall:
    return CFunctionCall(
        "sub_10010",
        SimpleNamespace(
            addr=0x10010,
            name="sub_10010",
            prototype=SimTypeFunction([], SimTypeShort(False)),
            prototype_libname=None,
        ),
        [],
        codegen=codegen,
        tags={"ins_addr": callsite},
    )


def test_typed_condition_cleanup_preserves_side_effecting_call_predicate() -> None:
    """Do not replace a Structuring-owned call predicate with raw register IR."""
    codegen = _codegen()
    project = codegen.project
    call = _semantic_call(codegen)
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x101DA, "vex_block_addr": 0x101D7},
    )
    branch = CIfElse(
        [(condition, CStatements([], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x101A7, statements=root, body=root)
    codegen._inertia_typed_conditions = (
        ConditionIR(
            op="ne",
            lhs=IRValue(MemSpace.REG, name="ax", offset=8, size=2),
            rhs=IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=0x101DA,
            block_addr=0x101D7,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is False
    assert branch.condition_and_nodes[0][0] is condition


def test_condition_call_effects_distinguish_runtime_access_from_semantic_call() -> None:
    codegen = _codegen()
    runtime_access = CFunctionCall(
        "SEG_U16",
        None,
        [CConstant(0, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )

    runtime_evidence = classify_condition_call_effects_8616(runtime_access)
    semantic_evidence = classify_condition_call_effects_8616(
        _semantic_call(codegen)
    )

    assert runtime_evidence.kind is ConditionCallEffectKind8616.TRANSPARENT_RUNTIME_ACCESS
    assert runtime_evidence.has_semantic_call is False
    assert semantic_evidence.kind is ConditionCallEffectKind8616.SEMANTIC_CALL
    assert semantic_evidence.has_semantic_call is True


def test_jcc_refresh_preserves_side_effecting_call_predicate(monkeypatch) -> None:
    codegen = _codegen()
    project = codegen.project
    flags_offset = project.arch.registers["flags"][0]
    flags = CConstant(flags_offset, SimTypeShort(False), codegen=codegen)
    call = _semantic_call(codegen)
    condition = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, call, codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x101DA, "vex_block_addr": 0x101D7},
    )
    branch = CIfElse(
        [(condition, CStatements([], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x101A7, statements=root, body=root)
    replacement = CConstant(1, SimTypeShort(False), codegen=codegen)
    monkeypatch.setattr(
        decompiler_postprocess_jcc,
        "_translate_cmp_jcc_guard_8616",
        lambda *_args: decompiler_postprocess_jcc._DecodedCmpGuard8616(
            lhs=replacement,
            rhs=CConstant(0, SimTypeShort(False), codegen=codegen),
            op="CmpNE",
        ),
    )

    changed = decompiler_postprocess_jcc._rewrite_decoded_jcc_conditions_8616(
        project,
        codegen,
    )

    assert changed is False
    assert branch.condition_and_nodes[0][0] is condition


def test_structuring_condition_chain_preserves_side_effecting_call(
    monkeypatch,
) -> None:
    codegen = _codegen()
    call = _semantic_call(codegen)
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x101DA, "vex_block_addr": 0x101D7},
    )
    body = CStatements([], codegen=codegen)
    body.tags = {"ins_addr": 0x101E0, "vex_block_addr": 0x101E0}
    branch = CIfElse(
        [(condition, body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    graph = _Graph(
        (
            (0x101D7, 0x101E0),
            (0x101D7, 0x101DC),
            (0x101DC, 0x101D7),
            (0x101E0, 0x101E8),
        )
    )
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes),
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: function)
        )
    )
    codegen.cfunc = SimpleNamespace(addr=0x101A7, statements=root)
    codegen._inertia_typed_conditions = (
        ConditionIR(
            op="ne",
            lhs=IRValue(MemSpace.REG, name="ax", offset=8, size=2),
            rhs=IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=0x101DA,
            block_addr=0x101D7,
            producer_insn=0x101D9,
            taken_target=0x101E0,
            fallthrough_target=0x101DC,
        ),
    )
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CConstant(1, SimTypeShort(False), codegen=codegen),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(
        project,
        codegen,
    )

    assert changed is False
    assert branch.condition_and_nodes[0][0] is condition
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.preserved_side_effect_count == 1
