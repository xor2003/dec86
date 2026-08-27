from __future__ import annotations

import io
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import angr
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.rustylib.ailment import Tags as AilmentTags
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering import call_return_frame_arguments as frame_argument_lowering
from angr_platforms.X86_16.lowering.call_return_frame_arguments import (
    CallReturnFrameArgumentPruneStatus8616,
    prune_exact_call_return_frame_arguments_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import (
    prune_call_return_frame_stack_assignments_8616,
)
from angr_platforms.X86_16.semantics.call_return_frame_effects import (
    CallReturnFrameEffectCollection8616,
    CallReturnFrameEffectFact8616,
    CallReturnFrameEffectKey8616,
    CallReturnFrameEffectRole8616,
    collect_call_return_frame_effects_8616,
)
from angr_platforms.X86_16.semantics.call_return_frame_projections import (
    CallReturnFrameProjectionCollection8616,
    CallReturnFrameProjectionFact8616,
    CallReturnFrameProjectionRefusalReason8616,
    CallReturnFrameProjectionRole8616,
    collect_call_return_frame_store_projections_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0

    def next_idx(self, _kind: str) -> int:
        self._next_index += 1
        return self._next_index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _project_for_code(code: bytes) -> tuple[Any, Any]:
    arch = Arch86_16()
    arch.bits = max(arch.bits, 32)
    project = angr.Project(
        io.BytesIO(code),
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": arch,
            "base_addr": 0x100,
            "entry_point": 0x100,
        },
        simos="DOS",
    )
    block = project.factory.block(0x100, size=len(code), opt_level=0)
    return project, SimpleNamespace(addr=0x100, blocks=(block,))


@pytest.fixture(scope="module")
def far_call_facts() -> tuple[Any, Any, CallReturnFrameEffectCollection8616]:
    project, function = _project_for_code(b"\x9a\x78\x56\x34\x12")
    collection = collect_call_return_frame_effects_8616(
        project,
        function,
        {0x100: 0x105},
    )
    return project, function, collection


def test_collects_complete_near_call_return_frame_effects() -> None:
    project, function = _project_for_code(b"\xe8\x00\x00")

    collection = collect_call_return_frame_effects_8616(project, function, {0x100: 0x103})

    assert collection.raw_fact_count == 1
    assert collection.normalized_fact_count == 1
    assert collection.failure_count == 0
    assert tuple(effect.role for effect in collection.effects) == (
        CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE,
        CallReturnFrameEffectRole8616.STACK_STORE,
        CallReturnFrameEffectRole8616.STACK_STORE,
    )
    assert (
        collection.raw_fact_count,
        collection.normalized_fact_count,
        collection.classified_fact_count,
        collection.materialized_count,
        collection.failure_count,
    ) == (1, 1, 3, 3, 0)
    projections = collection.projection_collection
    assert (
        projections.raw_fact_count,
        projections.normalized_fact_count,
        projections.classified_fact_count,
        projections.materialized_count,
        projections.failure_count,
    ) == (2, 2, 5, 5, 0)
    assert projections.closed
    assert tuple(
        (
            fact.store_key.vex_stmt_idx,
            fact.projection_key.vex_stmt_idx,
            fact.role,
        )
        for fact in projections.projections
    ) == (
        (16, 16, CallReturnFrameProjectionRole8616.STORE_STATEMENT),
        (16, 15, CallReturnFrameProjectionRole8616.VALUE_PRODUCER),
        (19, 19, CallReturnFrameProjectionRole8616.STORE_STATEMENT),
        (19, 17, CallReturnFrameProjectionRole8616.VALUE_PRODUCER),
        (19, 18, CallReturnFrameProjectionRole8616.VALUE_PRODUCER),
    )


def test_collects_complete_far_call_return_frame_effects(
    far_call_facts: tuple[Any, Any, CallReturnFrameEffectCollection8616],
) -> None:
    _project, _function, collection = far_call_facts

    assert collection.raw_fact_count == 1
    assert collection.normalized_fact_count == 1
    assert collection.failure_count == 0
    assert tuple(effect.role for effect in collection.effects) == (
        CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE,
        CallReturnFrameEffectRole8616.STACK_STORE,
        CallReturnFrameEffectRole8616.STACK_STORE,
        CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE,
        CallReturnFrameEffectRole8616.STACK_STORE,
        CallReturnFrameEffectRole8616.STACK_STORE,
    )


def test_prunes_only_exact_far_call_vex_projections(
    far_call_facts: tuple[Any, Any, CallReturnFrameEffectCollection8616],
) -> None:
    project, function, collection = far_call_facts
    codegen = _Codegen()
    unrelated_source = CVariable(
        SimMemoryVariable(0x220, 2, name="source"),
        codegen=codegen,
    )
    assignments = []
    for index, effect in enumerate(collection.effects):
        lhs = (
            CVariable(
                SimRegisterVariable(project.arch.sp_offset, 2, name="sp"),
                codegen=codegen,
            )
            if effect.role is CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE
            else CVariable(
                SimStackVariable(
                    -2 - index,
                    1,
                    base="bp",
                    name=f"frame_{index}",
                    region=0x100,
                ),
                codegen=codegen,
            )
        )
        assignments.append(
            CAssignment(
                lhs,
                unrelated_source,
                codegen=codegen,
                tags={
                    "ins_addr": effect.key.callsite_addr,
                    "vex_block_addr": effect.key.vex_block_addr,
                    "vex_stmt_idx": effect.key.vex_stmt_idx,
                },
            )
        )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=CStatements(assignments, codegen=codegen),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x100: 0x105},
        function=function,
    )

    assert changed is True
    assert codegen.cfunc.statements.statements == []
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (6, 6, 6, 6, 0)


def test_refuses_exact_store_fact_with_non_stack_lvalue(
    far_call_facts: tuple[Any, Any, CallReturnFrameEffectCollection8616],
) -> None:
    project, function, collection = far_call_facts
    store_effect = next(
        effect
        for effect in collection.effects
        if effect.role is CallReturnFrameEffectRole8616.STACK_STORE
    )
    codegen = _Codegen()
    global_variable = CVariable(
        SimMemoryVariable(0x240, 1, name="global_byte"),
        codegen=codegen,
    )
    assignment = CAssignment(
        global_variable,
        global_variable,
        codegen=codegen,
        tags={
            "ins_addr": store_effect.key.callsite_addr,
            "vex_block_addr": store_effect.key.vex_block_addr,
            "vex_stmt_idx": store_effect.key.vex_stmt_idx,
        },
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=CStatements([assignment], codegen=codegen),
    )

    changed = prune_call_return_frame_stack_assignments_8616(
        project,
        codegen,
        {0x100: 0x105},
        function=function,
    )

    assert changed is False
    assert codegen.cfunc.statements.statements == [assignment]
    stats = codegen._inertia_call_return_frame_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def _near_call_argument_surface(
    *,
    argument_value: int = 0x103,
    exact_argument_tags: bool = True,
    argument_statement_index: int | None = None,
    argument_callsite_addr: int = 0x100,
    structured_callsite_addr: int = 0x100,
) -> tuple[Any, Any, _Codegen, CFunctionCall, CConstant]:
    project, function = _project_for_code(b"\xe8\x00\x00")
    collection = collect_call_return_frame_effects_8616(
        project,
        function,
        {0x100: 0x103},
    )
    store_effect = next(
        effect
        for effect in collection.effects
        if effect.role is CallReturnFrameEffectRole8616.STACK_STORE
    )
    argument_key = CallReturnFrameEffectKey8616(
        argument_callsite_addr,
        store_effect.key.vex_block_addr,
        store_effect.key.vex_stmt_idx
        if argument_statement_index is None
        else argument_statement_index,
    )
    argument_tags = (
        {
            "ins_addr": argument_key.callsite_addr,
            "vex_block_addr": argument_key.vex_block_addr,
            "vex_stmt_idx": argument_key.vex_stmt_idx,
        }
        if exact_argument_tags
        else {"ins_addr": store_effect.key.callsite_addr}
    )
    codegen = _Codegen()
    codegen.project = project
    argument = CConstant(
        argument_value,
        SimTypeShort(False),
        tags=argument_tags,
        codegen=codegen,
    )
    call = CFunctionCall(
        "sub_103",
        SimpleNamespace(addr=0x103, name="sub_103"),
        [argument],
        tags={"ins_addr": structured_callsite_addr},
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x100,
        statements=CStatements([CExpressionStatement(call, codegen=codegen)], codegen=codegen),
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x100,
            target_addr=0x103,
            return_addr=0x103,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=None,
            return_used=False,
        )
    }
    return project, function, codegen, call, argument


def test_prunes_exact_return_address_projected_as_call_argument() -> None:
    project, function, codegen, call, _argument = _near_call_argument_surface()

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert call.args == []
    assert result.status is CallReturnFrameArgumentPruneStatus8616.MATERIALIZED
    assert (
        result.stats.raw_fact_count,
        result.stats.normalized_fact_count,
        result.stats.classified_fact_count,
        result.stats.materialized_count,
        result.stats.failure_count,
    ) == (1, 1, 1, 1, 0)
    assert result.stats.closed


def test_prunes_transformed_projection_by_exact_semantic_key() -> None:
    project, function, codegen, call, _argument = _near_call_argument_surface(
        argument_value=0x104,
    )

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert call.args == []
    assert result.status is CallReturnFrameArgumentPruneStatus8616.MATERIALIZED
    assert result.stats.closed
    assert result.stats.failure_count == 0
    assert result.stats.materialized_count == 1


def test_publishes_and_prunes_real_near_call_value_producer_projection() -> None:
    project, function, codegen, call, _argument = _near_call_argument_surface(
        argument_statement_index=17,
    )
    dead_variable = SimStackVariable(-1, 1, base="bp", name="frame_dead", region=0x100)
    live_variable = SimStackVariable(-2, 1, base="bp", name="frame_live", region=0x100)
    dead_cvar = CVariable(dead_variable, codegen=codegen)
    live_cvar = CVariable(live_variable, codegen=codegen)
    codegen.cfunc.variables_in_use = {
        dead_variable: dead_cvar,
        live_variable: live_cvar,
    }
    codegen.cfunc.unified_local_vars = {
        dead_variable: {(dead_cvar, SimTypeShort(False))},
        live_variable: {(live_cvar, SimTypeShort(False))},
    }
    codegen.cfunc.statements.statements.append(CExpressionStatement(live_cvar, codegen=codegen))

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    collection = codegen._inertia_call_return_frame_effect_collection_8616
    assert any(
        fact.store_key.vex_stmt_idx == 19
        and fact.projection_key.vex_stmt_idx == 17
        and fact.role is CallReturnFrameProjectionRole8616.VALUE_PRODUCER
        for fact in collection.projection_collection.projections
    )
    assert call.args == []
    assert result.status is CallReturnFrameArgumentPruneStatus8616.MATERIALIZED
    assert (
        result.stats.raw_fact_count,
        result.stats.normalized_fact_count,
        result.stats.classified_fact_count,
        result.stats.materialized_count,
        result.stats.failure_count,
    ) == (1, 1, 1, 1, 0)
    assert result.stats.closed
    assert dead_variable not in codegen.cfunc.variables_in_use
    assert dead_variable not in codegen.cfunc.unified_local_vars
    assert live_variable in codegen.cfunc.variables_in_use
    assert live_variable in codegen.cfunc.unified_local_vars


def test_prunes_value_producer_from_live_ailment_tag_carrier() -> None:
    project, function, codegen, call, argument = _near_call_argument_surface(
        argument_statement_index=17,
    )
    argument.tags = AilmentTags(argument.tags)

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert call.args == []
    assert result.status is CallReturnFrameArgumentPruneStatus8616.MATERIALIZED
    assert result.stats.materialized_count == 1
    assert result.stats.closed


def test_preserves_address_only_argument_tag() -> None:
    project, function, codegen, call, argument = _near_call_argument_surface(
        argument_value=0x104,
        exact_argument_tags=False,
    )

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert call.args == [argument]
    assert result.status is CallReturnFrameArgumentPruneStatus8616.NOT_APPLICABLE
    assert result.stats.raw_fact_count == 0


def test_preserves_equal_return_constant_without_semantic_key() -> None:
    project, function, codegen, call, argument = _near_call_argument_surface(
        exact_argument_tags=False,
    )
    argument.tags = {}
    declaration = SimStackVariable(-1, 1, base="bp", name="kept", region=0x100)
    declaration_cvar = CVariable(declaration, codegen=codegen)
    codegen.cfunc.variables_in_use = {declaration: declaration_cvar}
    codegen.cfunc.unified_local_vars = {
        declaration: {(declaration_cvar, SimTypeShort(False))},
    }

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert call.args == [argument]
    assert result.status is CallReturnFrameArgumentPruneStatus8616.NOT_APPLICABLE
    assert result.stats.raw_fact_count == 0
    assert declaration in codegen.cfunc.variables_in_use
    assert declaration in codegen.cfunc.unified_local_vars


def test_refuses_exact_frame_key_owned_by_another_structured_callsite() -> None:
    project, function, codegen, call, argument = _near_call_argument_surface(
        argument_statement_index=17,
        structured_callsite_addr=0x101,
    )

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert call.args == [argument]
    assert result.status is CallReturnFrameArgumentPruneStatus8616.UNKNOWN_REFUSE
    assert result.stats.failure_count == 1
    assert result.stats.closed


def test_refuses_non_frame_producer_from_exact_call_imark() -> None:
    project, function, codegen, call, argument = _near_call_argument_surface(
        argument_statement_index=14,
    )

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert call.args == [argument]
    assert result.status is CallReturnFrameArgumentPruneStatus8616.UNKNOWN_REFUSE
    assert (
        result.stats.raw_fact_count,
        result.stats.normalized_fact_count,
        result.stats.classified_fact_count,
        result.stats.materialized_count,
        result.stats.failure_count,
    ) == (1, 0, 0, 0, 1)
    assert result.stats.closed


def test_refuses_producer_claimed_by_multiple_frame_stores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, function, codegen, call, argument = _near_call_argument_surface(
        argument_statement_index=17,
    )
    real_collection = collect_call_return_frame_effects_8616(
        project,
        function,
        {0x100: 0x103},
    )
    real_projections = real_collection.projection_collection
    producer = next(
        fact
        for fact in real_projections.projections
        if fact.projection_key.vex_stmt_idx == 17
    )
    other_store = next(
        effect.key
        for effect in real_collection.effects
        if effect.role is CallReturnFrameEffectRole8616.STACK_STORE
        and effect.key != producer.store_key
    )
    duplicate = CallReturnFrameProjectionFact8616(
        other_store,
        producer.projection_key,
        CallReturnFrameProjectionRole8616.VALUE_PRODUCER,
    )
    ambiguous_projections = replace(
        real_projections,
        classified_fact_count=real_projections.classified_fact_count + 1,
        materialized_count=real_projections.materialized_count + 1,
        projections=(*real_projections.projections, duplicate),
    )
    ambiguous_collection = replace(
        real_collection,
        projection_collection=ambiguous_projections,
    )
    monkeypatch.setattr(
        frame_argument_lowering,
        "collect_call_return_frame_effects_8616",
        lambda *_args, **_kwargs: ambiguous_collection,
    )

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert ambiguous_projections.closed
    assert call.args == [argument]
    assert result.status is CallReturnFrameArgumentPruneStatus8616.UNKNOWN_REFUSE
    assert result.stats.failure_count == 1
    assert result.stats.closed


def _vex_expr(tag: str, *, temporary: int | None = None, children: tuple[Any, ...] = ()) -> Any:
    values: dict[str, Any] = {"tag": tag, "child_expressions": children}
    if temporary is not None:
        values["tmp"] = temporary
    return SimpleNamespace(**values)


def _vex_imark(address: int) -> Any:
    return SimpleNamespace(tag="Ist_IMark", addr=address)


def _vex_wrtmp(temporary: int, data: Any) -> Any:
    return SimpleNamespace(tag="Ist_WrTmp", tmp=temporary, data=data)


def _vex_store(data: Any, *, address: Any | None = None) -> Any:
    return SimpleNamespace(tag="Ist_Store", data=data, addr=address)


def _refusal_case(
    case: str,
) -> tuple[Any, tuple[int, ...], CallReturnFrameEffectKey8616, CallReturnFrameProjectionRefusalReason8616]:
    const = _vex_expr("Iex_Const")
    if case == "incomplete":
        malformed = SimpleNamespace(tag="Iex_Unop")
        statements = (_vex_imark(0x100), _vex_wrtmp(1, malformed), _vex_store(_vex_expr("Iex_RdTmp", temporary=1)))
        return SimpleNamespace(statements=statements), (2,), CallReturnFrameEffectKey8616(0x100, 0x100, 1), CallReturnFrameProjectionRefusalReason8616.INCOMPLETE_DEPENDENCY
    if case == "cyclic":
        statements = (
            _vex_imark(0x100),
            _vex_wrtmp(1, _vex_expr("Iex_RdTmp", temporary=2)),
            _vex_wrtmp(2, _vex_expr("Iex_RdTmp", temporary=1)),
            _vex_store(_vex_expr("Iex_RdTmp", temporary=1)),
        )
        return SimpleNamespace(statements=statements), (3,), CallReturnFrameEffectKey8616(0x100, 0x100, 1), CallReturnFrameProjectionRefusalReason8616.CYCLIC_DEPENDENCY
    if case == "ambiguous":
        statements = (
            _vex_imark(0x100),
            _vex_wrtmp(1, const),
            _vex_wrtmp(1, const),
            _vex_store(_vex_expr("Iex_RdTmp", temporary=1)),
        )
        return SimpleNamespace(statements=statements), (3,), CallReturnFrameEffectKey8616(0x100, 0x100, 1), CallReturnFrameProjectionRefusalReason8616.AMBIGUOUS_DEFINITION
    if case == "cross_callsite":
        statements = (
            _vex_imark(0x90),
            _vex_wrtmp(1, const),
            _vex_imark(0x100),
            _vex_store(_vex_expr("Iex_RdTmp", temporary=1)),
        )
        return SimpleNamespace(statements=statements), (3,), CallReturnFrameEffectKey8616(0x90, 0x100, 1), CallReturnFrameProjectionRefusalReason8616.CROSS_CALLSITE_DEPENDENCY
    if case == "shared":
        statements = (
            _vex_imark(0x100),
            _vex_wrtmp(1, const),
            _vex_store(_vex_expr("Iex_RdTmp", temporary=1)),
            _vex_store(_vex_expr("Iex_RdTmp", temporary=1)),
        )
        return SimpleNamespace(statements=statements), (2, 3), CallReturnFrameEffectKey8616(0x100, 0x100, 1), CallReturnFrameProjectionRefusalReason8616.SHARED_PRODUCER
    raise AssertionError(f"unknown refusal case: {case}")


def _effect_collection_with_projections(
    projections: CallReturnFrameProjectionCollection8616,
    store_indices: tuple[int, ...],
) -> CallReturnFrameEffectCollection8616:
    effects = tuple(
        CallReturnFrameEffectFact8616(
            CallReturnFrameEffectKey8616(0x100, 0x100, store_index),
            CallReturnFrameEffectRole8616.STACK_STORE,
        )
        for store_index in store_indices
    )
    return CallReturnFrameEffectCollection8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=len(effects),
        materialized_count=len(effects),
        failure_count=0,
        effects=effects,
        projection_collection=projections,
    )


@pytest.mark.parametrize(
    "case",
    ("incomplete", "cyclic", "ambiguous", "cross_callsite", "shared"),
)
def test_invalid_dependency_ancestry_is_published_as_refusal_and_kept(
    case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vex, store_indices, argument_key, expected_reason = _refusal_case(case)
    projections = collect_call_return_frame_store_projections_8616(
        vex,
        callsite_addr=0x100,
        vex_block_addr=0x100,
        store_statement_indices=store_indices,
    )
    collection = _effect_collection_with_projections(projections, store_indices)
    project, function, codegen, call, argument = _near_call_argument_surface(
        argument_statement_index=argument_key.vex_stmt_idx,
        argument_callsite_addr=argument_key.callsite_addr,
    )
    monkeypatch.setattr(
        frame_argument_lowering,
        "collect_call_return_frame_effects_8616",
        lambda *_args, **_kwargs: collection,
    )

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert projections.closed
    assert expected_reason in {refusal.reason for refusal in projections.refusals}
    assert argument_key in {
        producer_key
        for refusal in projections.refusals
        for producer_key in refusal.producer_keys
    }
    assert not any(
        fact.projection_key == argument_key
        and fact.role is CallReturnFrameProjectionRole8616.VALUE_PRODUCER
        for fact in projections.projections
    )
    assert call.args == [argument]
    assert result.status is CallReturnFrameArgumentPruneStatus8616.UNKNOWN_REFUSE
    assert (
        result.stats.raw_fact_count,
        result.stats.normalized_fact_count,
        result.stats.classified_fact_count,
        result.stats.materialized_count,
        result.stats.failure_count,
    ) == (1, 0, 0, 0, 1)
    assert result.stats.closed


def test_address_only_vex_dependency_is_not_published_and_is_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer_key = CallReturnFrameEffectKey8616(0x100, 0x100, 1)
    vex = SimpleNamespace(
        statements=(
            _vex_imark(0x100),
            _vex_wrtmp(1, _vex_expr("Iex_Const")),
            _vex_store(
                _vex_expr("Iex_Const"),
                address=_vex_expr("Iex_RdTmp", temporary=1),
            ),
        )
    )
    projections = collect_call_return_frame_store_projections_8616(
        vex,
        callsite_addr=0x100,
        vex_block_addr=0x100,
        store_statement_indices=(2,),
    )
    collection = _effect_collection_with_projections(projections, (2,))
    project, function, codegen, call, argument = _near_call_argument_surface(
        argument_statement_index=producer_key.vex_stmt_idx,
    )
    monkeypatch.setattr(
        frame_argument_lowering,
        "collect_call_return_frame_effects_8616",
        lambda *_args, **_kwargs: collection,
    )

    result = prune_exact_call_return_frame_arguments_8616(
        project,
        codegen,
        function=function,
    )

    assert projections.closed
    assert projections.refusals == ()
    assert all(fact.projection_key != producer_key for fact in projections.projections)
    assert call.args == [argument]
    assert result.status is CallReturnFrameArgumentPruneStatus8616.UNKNOWN_REFUSE
    assert result.stats.failure_count == 1
    assert result.stats.closed
