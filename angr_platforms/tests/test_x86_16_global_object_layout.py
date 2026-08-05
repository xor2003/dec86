from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CIndexedVariable,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimTypeShort, TypeRef
from angr.sim_variable import SimMemoryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from angr_platforms.X86_16.lowering.global_declarations import (
    NamedAggregateDeclarationCType8616,
    reconcile_strong_global_declaration_specs_8616,
    replace_global_declaration_spec_from_stronger_typed_evidence_8616,
)
from angr_platforms.X86_16.lowering.project_global_object_layout import (
    collect_project_global_object_layout_evidence_8616,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    AggregateTypeIdentityStrength8616,
    IndexedSegmentedGlobalEvidence8616,
    NamedGlobalAggregateTypeFact8616,
    _augment_indexed_evidence_with_project_layouts_8616,
    _preferred_named_global_aggregate_type_8616,
    _project_two_byte_aggregate_char_casts_8616,
    _record_named_global_aggregate_type_fact_8616,
    _two_byte_global_struct_declaration_ctype_8616,
    _two_byte_global_struct_type_8616,
    reapply_proven_named_global_aggregate_types_8616,
)
from angr_platforms.X86_16.widening.global_object_layout import (
    IndexedStorageCopy8616,
    IndexedStorageView8616,
    recover_global_object_layout_evidence_8616,
)


def _view(function_addr: int, offset: int, size: int, stack_offset: int = -2) -> IndexedStorageView8616:
    return IndexedStorageView8616(
        function_addr=function_addr,
        address=IRAddress(space=MemSpace.DS, offset=offset, size=size),
        index_stack_offset=stack_offset,
        index_shift=1,
    )


@dataclass(frozen=True)
class _Fact:
    base_offset: int
    width: int
    index_stack_offset: int = -2
    index_shift: int = 1


@dataclass(frozen=True)
class _CopyFact(_Fact):
    source_base_offset: int | None = None
    source_width: int | None = None
    source_index_stack_offset: int | None = None
    source_index_shift: int | None = None


class _Project:
    def __init__(self, original_project: object) -> None:
        self._inertia_original_project = original_project
        self._inertia_caller_function_ranges_8616 = ((0x1000, 0x1010), (0x1100, 0x1110))


def test_project_layout_joins_byte_fields_with_word_view_across_functions() -> None:
    evidence = recover_global_object_layout_evidence_8616(
        (
            _view(0x1000, 0x200, 1),
            _view(0x1000, 0x201, 1),
            _view(0x1100, 0x200, 2),
        )
    )

    assert tuple(layout.address.offset for layout in evidence.layouts) == (0x200,)
    assert evidence.layouts[0].field_offsets == (0, 1)
    assert evidence.layouts[0].address.status is AddressStatus.STABLE
    assert evidence.layouts[0].address.segment_origin is SegmentOrigin.PROVEN
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 3
    assert evidence.classified_fact_count == evidence.materialized_count == 1
    assert evidence.failure_count == 0


def test_project_layout_refuses_byte_pair_without_word_extent() -> None:
    evidence = recover_global_object_layout_evidence_8616(
        (_view(0x1000, 0x200, 1), _view(0x1000, 0x201, 1))
    )

    assert evidence.layouts == ()
    assert evidence.classified_fact_count == evidence.materialized_count == 0


def test_project_layout_refuses_fields_from_different_index_identities() -> None:
    evidence = recover_global_object_layout_evidence_8616(
        (
            _view(0x1000, 0x200, 1, -2),
            _view(0x1000, 0x201, 1, -4),
            _view(0x1100, 0x200, 2),
        )
    )

    assert evidence.layouts == ()


def test_project_collector_uses_original_binary_and_caches_layout_evidence() -> None:
    original_project = object()
    project = _Project(original_project)
    seen_projects: list[object] = []

    def collect(source_project: object, function: object) -> tuple[_Fact, ...]:
        seen_projects.append(source_project)
        if function.addr == 0x1000:
            return (
                _Fact(0x200, 1),
                _Fact(0x201, 1),
                _Fact(0x300, 1),
                _Fact(0x301, 1),
            )
        return (
            _Fact(0x200, 2),
            _CopyFact(
                0x300,
                2,
                source_base_offset=0x200,
                source_width=2,
                source_index_stack_offset=-2,
                source_index_shift=1,
            ),
        )

    first = collect_project_global_object_layout_evidence_8616(project, (collect,))
    second = collect_project_global_object_layout_evidence_8616(project, (collect,))

    assert first is second
    assert seen_projects == [original_project, original_project]
    assert tuple(layout.address.offset for layout in first.layouts) == (0x200, 0x300)
    assert tuple(layout.family_base_offset for layout in first.layouts) == (0x200, 0x200)
    assert first.raw_fact_count == first.normalized_fact_count == 7
    assert first.classified_fact_count == first.materialized_count == 3


def test_project_layout_unifies_type_family_only_from_exact_whole_copy() -> None:
    views = (
        _view(0x1000, 0x200, 1),
        _view(0x1000, 0x201, 1),
        _view(0x1000, 0x300, 1),
        _view(0x1000, 0x301, 1),
        _view(0x1100, 0x200, 2),
        _view(0x1100, 0x300, 2),
    )
    copy = IndexedStorageCopy8616(
        function_addr=0x1100,
        source_address=IRAddress(space=MemSpace.DS, offset=0x200, size=2),
        destination_address=IRAddress(space=MemSpace.DS, offset=0x300, size=2),
        source_index_stack_offset=-2,
        destination_index_stack_offset=-2,
        source_index_shift=1,
        destination_index_shift=1,
    )

    evidence = recover_global_object_layout_evidence_8616(views, (copy,))

    assert tuple(layout.family_base_offset for layout in evidence.layouts) == (0x200, 0x200)
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 7
    assert evidence.classified_fact_count == evidence.materialized_count == 3


def test_lowering_augments_only_current_exact_storage_identity() -> None:
    layouts = recover_global_object_layout_evidence_8616(
        (
            _view(0x1000, 0x200, 1),
            _view(0x1000, 0x201, 1),
            _view(0x1100, 0x200, 2),
        )
    )
    current = (
        IndexedSegmentedGlobalEvidence8616(
            base_offset=0x200,
            name="g_0200",
            relative_disp=0,
            width=2,
        ),
    )

    augmented = _augment_indexed_evidence_with_project_layouts_8616(current, layouts)

    assert tuple((item.base_offset, item.width, item.relative_disp) for item in augmented) == (
        (0x200, 2, 0),
        (0x200, 1, 0),
        (0x201, 1, 1),
    )
    assert {item.aggregate_type_name for item in augmented} == {"g_0200"}
    byte_augmented = _augment_indexed_evidence_with_project_layouts_8616(
        (IndexedSegmentedGlobalEvidence8616(0x200, "g_0200", 0, 1),),
        layouts,
    )
    assert tuple((item.base_offset, item.width) for item in byte_augmented) == (
        (0x200, 1),
        (0x201, 1),
    )
    assert {item.aggregate_type_name for item in byte_augmented} == {"g_0200"}
    assert _augment_indexed_evidence_with_project_layouts_8616((), layouts) == ()


def test_lowering_projects_zero_extended_aggregate_low_byte_to_field_zero() -> None:
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
        project=SimpleNamespace(arch=Arch86_16()),
    )
    struct_type = _two_byte_global_struct_type_8616("g_0200")
    base = CVariable(
        SimMemoryVariable(0x200, 2, name="g_0200"),
        variable_type=struct_type,
        codegen=codegen,
    )
    indexed = CIndexedVariable(
        base,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        variable_type=struct_type,
        codegen=codegen,
    )
    indexed.variable_type = TypeRef(struct_type.name, struct_type)
    expression = CBinaryOp(
        "And",
        indexed,
        CConstant(0xFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    projected = _project_two_byte_aggregate_char_casts_8616(codegen, expression)

    assert projected == 1
    assert isinstance(expression.lhs, CVariableField)
    assert expression.lhs.field.field == "field_0"


def test_named_aggregate_replay_restores_expression_type_before_low_byte_projection() -> None:
    struct_type = _two_byte_global_struct_type_8616("g_0200")
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
        project=SimpleNamespace(arch=Arch86_16()),
        _inertia_global_declaration_specs_8616=(("unsigned short", "g_0200", 1),),
        _inertia_named_global_aggregate_type_facts_8616=(
            NamedGlobalAggregateTypeFact8616("g_0200", struct_type, 1),
        ),
    )
    base = CVariable(
        SimMemoryVariable(0x200, 2, name="g_0200"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    indexed = CIndexedVariable(
        base,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expression = CBinaryOp(
        "And",
        indexed,
        CConstant(0xFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        body=expression,
        variable_manager=SimpleNamespace(types={}),
    )

    assert reapply_proven_named_global_aggregate_types_8616(codegen) is True

    assert isinstance(indexed.type, TypeRef)
    assert isinstance(expression.lhs, CVariableField)
    assert expression.lhs.field.field == "field_0"
    stats = codegen._inertia_named_global_aggregate_expression_replay_stats_8616
    assert stats.raw_fact_count == stats.normalized_fact_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.field_projection_count == 1


def test_stronger_family_fact_replaces_weaker_local_type_and_declaration() -> None:
    local_type = _two_byte_global_struct_type_8616("g_0300")
    family_type = _two_byte_global_struct_type_8616("g_0200")
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(("g_0300_entry", "g_0300", 1),),
        _inertia_named_global_aggregate_type_facts_8616=(
            NamedGlobalAggregateTypeFact8616("g_0300", local_type, 1),
        ),
    )

    upgraded = _record_named_global_aggregate_type_fact_8616(
        codegen,
        "g_0300",
        family_type,
        1,
        allow_layout_equivalent_type_upgrade=True,
    )
    replace_global_declaration_spec_from_stronger_typed_evidence_8616(
        codegen,
        ctype=_two_byte_global_struct_declaration_ctype_8616(
            "g_0200",
            registered=True,
        ),
        name="g_0300",
        array_len=1,
    )

    assert upgraded is True
    assert codegen._inertia_named_global_aggregate_type_facts_8616 == (
        NamedGlobalAggregateTypeFact8616(
            "g_0300",
            family_type,
            1,
            AggregateTypeIdentityStrength8616.PROJECT_COPY_FAMILY,
        ),
    )
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("g_0200_entry", "g_0300", 1),
    )

    assert (
        _preferred_named_global_aggregate_type_8616(codegen, "g_0300", local_type)
        is family_type
    )
    assert (
        _record_named_global_aggregate_type_fact_8616(
            codegen,
            "g_0300",
            local_type,
            1,
        )
        is False
    )
    assert codegen._inertia_named_global_aggregate_type_facts_8616[0].struct_type is family_type


def test_stronger_typed_global_declaration_replays_after_weaker_alias_shape() -> None:
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(("unsigned short", "rin", 7),),
    )
    aggregate = NamedAggregateDeclarationCType8616(
        type_name="REGS",
        inline_definition="typedef union REGS { unsigned short ax; } REGS;",
        registered=True,
    )
    replace_global_declaration_spec_from_stronger_typed_evidence_8616(
        codegen,
        ctype=aggregate,
        name="rin",
        array_len=None,
    )
    codegen._inertia_global_declaration_specs_8616 = (
        ("unsigned short", "rin", 7),
    )

    changed = reconcile_strong_global_declaration_specs_8616(codegen)

    assert changed is True
    assert codegen._inertia_global_declaration_specs_8616 == (("REGS", "rin", None),)
