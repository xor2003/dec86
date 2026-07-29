"""Materialize proven segmented global loads and stores in generated C.

Layer: Types/Lowering.
Responsibility: materialize proven segmented global loads and stores from alias, widening, and typed evidence.
Consumes alias, widening, and typed facts; helper-shaped C nodes are rewritten
only after recovered segmented-memory evidence identifies the storage.
Do not recover semantics from COD, source, assembly, or rendered C text.
Postprocess and CLI may consume materialized loads, but proof belongs here.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import typing
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import Enum
from types import SimpleNamespace
from typing import Any, TypeAlias

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CExpression,
    CExpressionStatement,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CStructField,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimType, SimTypeChar, SimTypeLong, SimTypePointer, SimTypeShort, TypeRef
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimVariable
from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_CWD,
    X86_INS_IDIV,
    X86_INS_INC,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_INS_SAL,
    X86_INS_SHL,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_DX,
    X86_REG_INVALID,
    X86_REG_SP,
)

from ..alias.domains import register_domain_for_name
from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616, _same_c_expression_8616
from ..callsite_summary import CallsiteSummary8616, build_callsite_summary_inventory_8616
from ..pipeline.errors import PipelineHardError
from ..structuring.simple_loop_recovery import InsnSummary8616, _function_instruction_summaries_8616
from .global_declarations import (
    NamedAggregateDeclarationCType8616,
    ctype_for_global_width_8616,
    record_global_declaration_spec_8616,
)
from .real_mode_linear import (
    _callee_name_for_direct_stack_move_8616,
    _capstone_insns_for_direct_global_update_8616,
    _direct_global_update_blocks_8616,
    _direct_global_update_ordered_insns_8616,
    _direct_stack_move_register_name_8616,
    _direct_stack_move_segment_name_8616,
    _direct_zero_arg_call_before_8616,
    _stack_mem_operand_offset_width_8616,
)

log: logging.Logger = logging.getLogger(__name__)

CopyKey8616: TypeAlias = str | tuple[str, int | str]
CodegenBoundary8616: TypeAlias = Any
ProjectBoundary8616: TypeAlias = Any
SyntheticGlobalsBoundary8616: TypeAlias = object
CodMetadataBoundary8616: TypeAlias = object | None
DwordUpdateMatch8616: TypeAlias = tuple[CAssignment, int] | None
DwordStorePairMatch8616: TypeAlias = tuple[CAssignment, bool] | None


@dataclass(frozen=True, slots=True)
class CapstoneMemoryView8616:
    """Typed snapshot of one dynamic Capstone memory operand."""

    segment: int | None
    base: int | None
    index: int | None
    displacement: int | None


@dataclass(frozen=True, slots=True)
class CapstoneOperandView8616:
    """Typed snapshot of one dynamic Capstone x86 operand."""

    raw: object
    kind: int | None
    register: int | None
    size: int | None
    immediate: int | None
    memory: CapstoneMemoryView8616 | None


@dataclass(frozen=True, slots=True)
class CapstoneInstructionView8616:
    """Typed snapshot of one dynamic angr/Capstone instruction wrapper."""

    raw: object
    instruction_id: int | None
    address: int | None
    operands: tuple[CapstoneOperandView8616, ...]


class _CapstoneMemoryBoundary8616(typing.Protocol):
    """Dynamic fields exposed by a third-party Capstone memory operand."""

    segment: object
    base: object
    index: object
    disp: object


class _CapstoneOperandBoundary8616(typing.Protocol):
    """Dynamic fields exposed by a third-party Capstone x86 operand."""

    type: object
    reg: object
    size: object
    imm: object
    mem: _CapstoneMemoryBoundary8616


class _CapstoneInstructionBoundary8616(typing.Protocol):
    """Dynamic fields exposed by a third-party Capstone instruction."""

    id: object
    address: object
    operands: object


class _CapstoneWrapperBoundary8616(typing.Protocol):
    """Dynamic instruction field exposed by an angr Capstone wrapper."""

    insn: object


class _TypeStoreBoundary8616(typing.Protocol):
    """Type registration surface exposed by angr's per-function type store."""

    def __getitem__(self, name: str) -> SimType:
        """Return one registered named type."""
        ...

    def __setitem__(self, name: str, value: TypeRef) -> None:
        """Register one named type reference."""

    def iter_own(self) -> Iterable[SimType]:
        """Iterate types rendered by this function's own type store."""
        ...


class _VariableManagerTypeBoundary8616(typing.Protocol):
    """Type-store field exposed by an angr function variable manager."""

    types: _TypeStoreBoundary8616

    def set_variable_type(
        self,
        variable: SimVariable,
        type_: SimType,
        *,
        name: str | None = None,
        override_bot: bool = True,
        all_unified: bool = False,
    ) -> None:
        """Assign one recovered type to a variable storage identity."""
        _ = variable, type_, name, override_bot, all_unified
        raise NotImplementedError

    def get_variable_type(self, variable: SimVariable) -> SimType | None:
        """Return the current type for one variable storage identity."""

    def get_variables(self, sort: object = None, collapse_same_ident: bool = False) -> Iterable[SimVariable]:
        """Return variables known to this function manager."""
        _ = sort, collapse_same_ident
        raise NotImplementedError


class _CFunctionTypeBoundary8616(typing.Protocol):
    """Variable-manager field exposed by an angr structured C function."""

    variable_manager: _VariableManagerTypeBoundary8616
    variables_in_use: dict[SimVariable, CVariable]
    unified_local_vars: dict[SimVariable, set[tuple[CVariable, SimType]]]


class _CodegenTypeBoundary8616(typing.Protocol):
    """Fields needed to register and render a recovered local aggregate type."""

    cfunc: _CFunctionTypeBoundary8616 | None
    show_local_types: bool


class _CodegenStackAggregateFactBoundary8616(typing.Protocol):
    """Owned Lowering metadata used to survive later CFunction rebuilds."""

    _inertia_global_declaration_specs_8616: tuple[tuple[str, str, int | None], ...]
    _inertia_named_global_aggregate_declaration_reconcile_stats_8616: NamedGlobalAggregateTypeReplayStats8616
    _inertia_named_global_aggregate_type_facts_8616: tuple[NamedGlobalAggregateTypeFact8616, ...]
    _inertia_named_global_aggregate_type_replay_stats_8616: NamedGlobalAggregateTypeReplayStats8616
    _inertia_stack_aggregate_type_facts_8616: tuple[StackAggregateTypeFact8616, ...]
    _inertia_stack_aggregate_type_replay_stats_8616: StackAggregateTypeReplayStats8616
    _inertia_stack_aggregate_field_projection_facts_8616: tuple[StackAggregateFieldProjectionFact8616, ...]
    _inertia_stack_aggregate_field_projection_replay_stats_8616: StackAggregateFieldProjectionReplayStats8616
    _inertia_indexed_global_stack_aggregate_copy_facts_8616: tuple[
        IndexedGlobalStackAggregateCopyFact8616,
        ...,
    ]


def _optional_int_boundary_8616(value: object) -> int | None:
    """Narrow one dynamic third-party scalar to an integer."""

    return value if isinstance(value, int) else None


def _capstone_memory_view_8616(memory_raw: object) -> CapstoneMemoryView8616:
    """Snapshot one dynamic third-party Capstone memory operand."""

    memory = typing.cast(_CapstoneMemoryBoundary8616, memory_raw)
    try:
        segment = memory.segment
    except AttributeError:
        segment = None
    try:
        base = memory.base
    except AttributeError:
        base = None
    try:
        index = memory.index
    except AttributeError:
        index = None
    try:
        displacement = memory.disp
    except AttributeError:
        displacement = None
    return CapstoneMemoryView8616(
        segment=_optional_int_boundary_8616(segment),
        base=_optional_int_boundary_8616(base),
        index=_optional_int_boundary_8616(index),
        displacement=_optional_int_boundary_8616(displacement),
    )


def _capstone_instruction_view_8616(wrapper: object) -> CapstoneInstructionView8616:
    """Snapshot one dynamic angr/Capstone wrapper into a typed local contract."""

    wrapper_boundary = typing.cast(_CapstoneWrapperBoundary8616, wrapper)
    try:
        raw = wrapper_boundary.insn
    except AttributeError:
        raw = wrapper
    instruction_boundary = typing.cast(_CapstoneInstructionBoundary8616, raw)
    try:
        raw_operands = instruction_boundary.operands
    except AttributeError:
        raw_operands = ()
    operands: list[CapstoneOperandView8616] = []
    for operand in tuple(raw_operands) if isinstance(raw_operands, Iterable) else ():
        operand_boundary = typing.cast(_CapstoneOperandBoundary8616, operand)
        try:
            memory_raw = operand_boundary.mem
        except AttributeError:
            memory_raw = None
        memory = _capstone_memory_view_8616(memory_raw) if memory_raw is not None else None
        try:
            operand_kind = operand_boundary.type
        except AttributeError:
            operand_kind = None
        try:
            operand_register = operand_boundary.reg
        except AttributeError:
            operand_register = None
        try:
            operand_size = operand_boundary.size
        except AttributeError:
            operand_size = None
        try:
            operand_immediate = operand_boundary.imm
        except AttributeError:
            operand_immediate = None
        operands.append(
            CapstoneOperandView8616(
                raw=operand,
                kind=_optional_int_boundary_8616(operand_kind),
                register=_optional_int_boundary_8616(operand_register),
                size=_optional_int_boundary_8616(operand_size),
                immediate=_optional_int_boundary_8616(operand_immediate),
                memory=memory,
            )
        )
    try:
        instruction_id = instruction_boundary.id
    except AttributeError:
        instruction_id = None
    try:
        instruction_address = instruction_boundary.address
    except AttributeError:
        instruction_address = None
    return CapstoneInstructionView8616(
        raw=raw,
        instruction_id=_optional_int_boundary_8616(instruction_id),
        address=_optional_int_boundary_8616(instruction_address),
        operands=tuple(operands),
    )


def _codegen_switch_case_bodies_8616(node: object) -> tuple[object, ...]:
    """Return child bodies from an angr codegen switch-case node.

    Dynamic boundary: angr codegen CSwitchCase nodes do not expose a stable typed
    public contract for their ``cases`` field.
    """

    cases = getattr(node, "cases", ())
    if not isinstance(cases, Iterable):
        return ()
    bodies: list[object] = []
    for item in cases:
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        _case_value, body = item
        bodies.append(body)
    return tuple(bodies)


def _capstone_operands_8616(insn: object) -> tuple[object, ...]:
    """Return operands from a capstone instruction object.

    Dynamic boundary: capstone instruction operands are third-party runtime
    attributes rather than owned Inertia contracts.
    """

    operands = getattr(insn, "operands", ())
    if not isinstance(operands, Iterable):
        return ()
    return tuple(operands)


def _signed_remainder_register_aliases_8616(register_name: str) -> frozenset[str]:
    """Return the DX-family names that can carry a signed remainder."""
    if register_name.lower() in {"dx", "dl", "dh"}:
        return frozenset({"dx", "dl", "dh"})
    return frozenset({register_name.lower()})


def _invalidate_register_storage_carriers_8616(carriers: dict[str, int], register_name: str) -> None:
    """Drop all carrier views sharing the written register's storage identity."""

    storage_domain = register_domain_for_name(register_name)
    for candidate_name in tuple(carriers):
        if candidate_name == register_name or (
            storage_domain is not None
            and register_domain_for_name(candidate_name) == storage_domain
        ):
            carriers.pop(candidate_name, None)


def _unwrap_codegen_expr_8616(node: object) -> object:
    """Unwrap nested angr codegen expression wrappers.

    Dynamic boundary: angr codegen nodes may carry an ``expr`` wrapper field
    without a stable typed class shared by all wrapper variants.
    """

    current = node
    while True:
        wrapped = getattr(current, "expr", None)
        if wrapped is None:
            return current
        current = wrapped


def _codegen_project_optional_8616(codegen: CodegenBoundary8616) -> object | None:
    """Return optional project context from dynamic angr codegen metadata."""

    # Dynamic boundary: angr codegen attaches project context opportunistically.
    return getattr(codegen, "project", None)


def _codegen_cfunc_optional_8616(codegen: CodegenBoundary8616) -> object | None:
    """Return optional CFunction context from dynamic angr codegen metadata."""

    # Dynamic boundary: angr codegen cfunc is optional on compatibility/test surfaces.
    return getattr(codegen, "cfunc", None)


def _debug_segmented_global_materialized_8616(kind: str, original: object, replacement: object) -> None:
    if not os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        return
    log.warning(
        "[seg-global-materialized] kind=%s original=%s replacement=%s",
        kind,
        _debug_c_repr_8616(original),
        _debug_c_repr_8616(replacement),
    )


class SegmentedGlobalLoadDecision8616(Enum):
    """Classification for named segmented-global load materialization."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_HELPER_MISMATCH = "refused_helper_mismatch"
    REFUSED_SEGMENT_MISMATCH = "refused_segment_mismatch"
    REFUSED_OFFSET_MISMATCH = "refused_offset_mismatch"


class CompareRegisterGlobalCarrierDecision8616(Enum):
    """Classification for compare-register carrier materialization."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_NO_MATCHING_GLOBAL = "refused_no_matching_global"


class IndexedSegmentedGlobalDecision8616(Enum):
    """Classification for indexed segmented-global materialization."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_SHAPE_MISMATCH = "refused_shape_mismatch"


class SegmentLoadHelper8616(Enum):
    """Segmented memory load helper names and their proven widths."""

    SEG_U8 = "SEG_U8"
    SEG_U16 = "SEG_U16"
    SEG_U32 = "SEG_U32"

    @property
    def helper_name(self) -> str:
        """Return the generated helper function name."""

        return self.value

    @property
    def width(self) -> int:
        """Return the byte width loaded by the helper."""

        if self is SegmentLoadHelper8616.SEG_U8:
            return 1
        if self is SegmentLoadHelper8616.SEG_U32:
            return 4
        return 2


class MemoryPointerHelper8616(Enum):
    """Memory pointer helper names and their dereference widths."""

    MEM_U8 = "MEM_U8"
    MEM_U16 = "MEM_U16"
    MEM_U32 = "MEM_U32"

    @property
    def helper_name(self) -> str:
        """Return the generated helper function name."""

        return self.value

    @property
    def width(self) -> int:
        """Return the byte width dereferenced by the helper."""

        if self is MemoryPointerHelper8616.MEM_U8:
            return 1
        if self is MemoryPointerHelper8616.MEM_U32:
            return 4
        return 2


class SegmentPointerHelper8616(Enum):
    """Segment pointer helper names used by generated C expressions."""

    SEG_PTR = "SEG_PTR"
    MK_FP = "MK_FP"

    @property
    def helper_name(self) -> str:
        """Return the generated helper function name."""

        return self.value


@dataclass(frozen=True, slots=True)
class NamedGlobalEvidence8616:
    """Named direct global evidence keyed by DS offset."""

    offset: int
    name: str
    width: int


@dataclass(frozen=True, slots=True)
class CompareRegisterGlobalCarrierEvidence8616:
    """Register carrier evidence for compares against direct globals."""

    reg_name: str
    offset: int
    width: int


@dataclass(frozen=True, slots=True)
class DwordGlobalZeroTestEvidence8616:
    """Adjacent low/high word evidence for a scalar dword zero-test."""

    base_offset: int
    low_offset: int
    high_offset: int
    reg_name: str


@dataclass(frozen=True, slots=True)
class DwordGlobalZeroTestMaterializationRecord8616:
    """Closed evidence loop for materialized scalar dword zero-tests."""

    evidence: tuple[DwordGlobalZeroTestEvidence8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class IndexedSegmentedGlobalEvidence8616:
    """Indexed global load evidence keyed by base offset and width."""

    base_offset: int
    name: str
    relative_disp: int
    width: int


@dataclass(frozen=True, slots=True)
class IndexedSegmentedGlobalMaterializationRecord8616:
    """Cumulative typed evidence consumed by indexed-global materialization."""

    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...]
    materialized_count: int


@dataclass(frozen=True, slots=True)
class IndexedGlobalReadCarrierMaterializationRecord8616:
    """Closed evidence loop for indexed loads replacing register carriers."""

    evidence: tuple[IndexedSegmentedGlobalLoadSiteEvidence8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class NamedGlobalAggregateTypeFact8616:
    """Proven named global aggregate that must survive codegen rebuilds."""

    global_name: str
    struct_type: SimStruct
    array_len: int


@dataclass(frozen=True, slots=True)
class NamedGlobalAggregateTypeReplayStats8616:
    """Closed evidence loop for replaying named global aggregate declarations."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class StackAggregateTypeFact8616:
    """Proven aggregate type for one exact BP-relative stack identity."""

    base: str
    offset: int
    width: int
    struct_type: SimStruct


@dataclass(frozen=True, slots=True)
class StackAggregateTypeReplayStats8616:
    """Closed evidence loop for replaying aggregate stack declaration types."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class StackAggregateFieldProjectionFact8616:
    """Proven field projection between two exact BP-relative stack identities."""

    source_base: str
    source_offset: int
    destination_base: str
    destination_offset: int
    field_offset: int
    struct_type: SimStruct
    cast_source_type: SimType | None
    cast_destination_type: SimTypeChar


@dataclass(frozen=True, slots=True)
class StackAggregateFieldProjectionReplayStats8616:
    """Closed evidence loop for replaying proven stack aggregate projections."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class IndexedGlobalStackAggregateCopyFact8616:
    """Proven whole-value copy from one indexed DS aggregate into BP storage."""

    source_global_offset: int
    source_index_base: str
    source_index_offset: int
    source_index_adjustment: int
    destination_base: str
    destination_offset: int
    width: int
    struct_type: SimStruct
    load_ins_addr: int
    store_ins_addr: int


@dataclass(frozen=True, slots=True)
class IndexedSegmentedGlobalStackStore8616:
    """Exact BP-relative store consuming one indexed segmented-global load."""

    stack_offset: int
    width: int
    ins_addr: int


@dataclass(frozen=True, slots=True)
class IndexedSegmentedGlobalLoadSiteEvidence8616:
    """Binary-proven indexed DS load site and its stack-index provenance."""

    base_offset: int
    width: int
    index_stack_offset: int
    index_shift: int
    ins_addr: int
    stack_stores: tuple[IndexedSegmentedGlobalStackStore8616, ...] = ()
    destination_register: str | None = None
    index_stack_width: int = 2


@dataclass(frozen=True, slots=True)
class SignedRemainderStackSource8616:
    """Binary-proven signed remainder source carried from DX/DL into a store."""

    dividend_stack_offset: int
    divisor_stack_offset: int
    width: int
    post_adjust: int = 0


@dataclass(frozen=True, slots=True)
class IndexedSegmentedGlobalStoreEvidence8616:
    """Indexed global store evidence recovered from binary instructions."""

    base_offset: int
    width: int
    index_stack_offset: int
    index_shift: int
    ins_addr: int
    source_base_offset: int | None = None
    source_width: int | None = None
    source_index_stack_offset: int | None = None
    source_index_shift: int | None = None
    source_stack_offset: int | None = None
    source_stack_width: int | None = None
    source_signed_remainder: SignedRemainderStackSource8616 | None = None


@dataclass(frozen=True, slots=True)
class DirectGlobalSymbolRef8616:
    """Direct global symbol reference aligned with binary memory evidence."""

    offset: int
    name: str
    relative_disp: int
    width: int
    max_relative_disp: int


@dataclass(frozen=True, slots=True)
class GlobalAddressLiteralEvidence8616:
    """Global address literal evidence for pointer materialization."""

    offset: int
    value: str


@dataclass(frozen=True, slots=True)
class CodOffsetGlobalRef8616:
    """COD sidecar global-offset reference record."""

    ins_addr: int
    name: str
    relative_disp: int
    opcode: int | None = None
    literal: str | None = None


@dataclass(frozen=True, slots=True)
class DirectGlobalUpdateEvidence8616:
    """Direct global word update evidence with a signed delta."""

    offset: int
    width: int
    delta: int


@dataclass(frozen=True, slots=True)
class DirectGlobalBooleanStoreEvidence8616:
    """Evidence for CMP/SBB/NEG materialized boolean stores to direct globals."""

    source_offset: int
    source_width: int
    compare_value: int
    dest_offset: int
    dest_width: int
    store_ins_addr: int | None = None


@dataclass(frozen=True, slots=True)
class DirectGlobalCallReturnStoreEvidence8616:
    """Direct scalar or dword global store evidence sourced from a call return."""

    offset: int
    width: int
    source_call_name: str
    source_call_target: int | None
    source_call_ins_addr: int
    low_store_ins_addr: int
    high_store_ins_addr: int | None

    @property
    def store_ins_addrs(self) -> tuple[int, ...]:
        """Return the complete ordered instruction identity of the proven store."""

        if self.high_store_ins_addr is None:
            return (self.low_store_ins_addr,)
        return (self.low_store_ins_addr, self.high_store_ins_addr)


@dataclass(slots=True)
class SegmentedGlobalLoadStats8616:
    """Materialization counters for segmented global lowering evidence."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_no_evidence: int = 0
    refused_no_cfunc: int = 0
    refused_helper_mismatch: int = 0
    refused_segment_mismatch: int = 0
    refused_offset_mismatch: int = 0
    compare_register_raw_fact_count: int = 0
    compare_register_classified_count: int = 0
    compare_register_materialized_count: int = 0
    compare_register_refused_no_evidence: int = 0
    compare_register_refused_no_cfunc: int = 0
    compare_register_refused_no_matching_global: int = 0
    indexed_raw_fact_count: int = 0
    indexed_classified_count: int = 0
    indexed_materialized_count: int = 0
    indexed_load_site_raw_fact_count: int = 0
    indexed_load_site_materialized_count: int = 0
    indexed_store_materialized_count: int = 0
    indexed_store_lvalue_raw_fact_count: int = 0
    indexed_store_lvalue_materialized_count: int = 0
    indexed_store_source_carrier_removed_count: int = 0
    indexed_stack_aggregate_type_promoted_count: int = 0
    indexed_stack_aggregate_byte_cast_projected_count: int = 0
    indexed_byte_store_lvalue_materialized_count: int = 0
    indexed_byte_store_source_materialized_count: int = 0
    direct_symbol_store_materialized_count: int = 0
    direct_symbol_update_raw_fact_count: int = 0
    direct_symbol_update_materialized_count: int = 0
    direct_symbol_boolean_store_raw_fact_count: int = 0
    direct_symbol_boolean_store_materialized_count: int = 0
    direct_symbol_boolean_duplicate_pruned_count: int = 0
    direct_symbol_call_return_raw_fact_count: int = 0
    direct_symbol_call_return_materialized_count: int = 0
    direct_symbol_call_return_carrier_removed_count: int = 0
    direct_symbol_segment_pointer_self_assignment_removed_count: int = 0
    indexed_refused_no_evidence: int = 0
    indexed_refused_no_cfunc: int = 0
    indexed_refused_shape_mismatch: int = 0
    direct_symbol_raw_fact_count: int = 0
    direct_symbol_materialized_count: int = 0

    def record(self, decision: SegmentedGlobalLoadDecision8616) -> None:
        """Record a named/direct segmented-global materialization decision."""

        if decision is SegmentedGlobalLoadDecision8616.MATERIALIZED:
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is SegmentedGlobalLoadDecision8616.REFUSED_NO_EVIDENCE:
            self.refused_no_evidence += 1
        elif decision is SegmentedGlobalLoadDecision8616.REFUSED_NO_CFUNC:
            self.refused_no_cfunc += 1
        elif decision is SegmentedGlobalLoadDecision8616.REFUSED_HELPER_MISMATCH:
            self.refused_helper_mismatch += 1
        elif decision is SegmentedGlobalLoadDecision8616.REFUSED_SEGMENT_MISMATCH:
            self.refused_segment_mismatch += 1
        elif decision is SegmentedGlobalLoadDecision8616.REFUSED_OFFSET_MISMATCH:
            self.refused_offset_mismatch += 1

    def record_compare(self, decision: CompareRegisterGlobalCarrierDecision8616) -> None:
        """Record a compare-register carrier materialization decision."""

        if decision is CompareRegisterGlobalCarrierDecision8616.MATERIALIZED:
            self.compare_register_materialized_count += 1
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is CompareRegisterGlobalCarrierDecision8616.REFUSED_NO_EVIDENCE:
            self.compare_register_refused_no_evidence += 1
        elif decision is CompareRegisterGlobalCarrierDecision8616.REFUSED_NO_CFUNC:
            self.compare_register_refused_no_cfunc += 1
        elif decision is CompareRegisterGlobalCarrierDecision8616.REFUSED_NO_MATCHING_GLOBAL:
            self.compare_register_refused_no_matching_global += 1

    def record_indexed(self, decision: IndexedSegmentedGlobalDecision8616) -> None:
        """Record an indexed segmented-global materialization decision."""

        if decision is IndexedSegmentedGlobalDecision8616.MATERIALIZED:
            self.indexed_materialized_count += 1
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is IndexedSegmentedGlobalDecision8616.REFUSED_NO_EVIDENCE:
            self.indexed_refused_no_evidence += 1
        elif decision is IndexedSegmentedGlobalDecision8616.REFUSED_NO_CFUNC:
            self.indexed_refused_no_cfunc += 1
        elif decision is IndexedSegmentedGlobalDecision8616.REFUSED_SHAPE_MISMATCH:
            self.indexed_refused_shape_mismatch += 1


def materialize_named_segmented_global_loads_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: SyntheticGlobalsBoundary8616,
    cod_metadata: CodMetadataBoundary8616 = None,
) -> bool:
    """Materialize named DS global loads from proven lowering evidence."""

    stats = SegmentedGlobalLoadStats8616()
    evidence = _collect_named_global_evidence_8616(project, codegen, synthetic_globals, cod_metadata=cod_metadata)
    function = _active_function_8616(project, codegen)
    summaries = _function_instruction_summaries_8616(project, function) if function is not None else []
    direct_refs = _merge_direct_global_symbol_refs_8616(
        _collect_direct_global_symbol_refs_8616(cod_metadata, summaries),
        _collect_synthetic_direct_global_symbol_refs_8616(synthetic_globals, summaries),
    )
    zero_test_evidence = recover_dword_global_zero_test_evidence_8616(summaries)
    stats.raw_fact_count = len(evidence)
    stats.normalized_fact_count = len(evidence)
    stats.classified_fact_count = len(evidence)
    stats.direct_symbol_raw_fact_count = len(direct_refs)
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        log.warning(
            "[seg-global-loads] evidence=%s direct_refs=%s",
            tuple((item.offset & 0xFFFF, item.name, item.width) for item in evidence),
            tuple((item.offset & 0xFFFF, item.name, item.relative_disp, item.width) for item in direct_refs),
        )
    if not evidence and not direct_refs:
        stats.record(SegmentedGlobalLoadDecision8616.REFUSED_NO_EVIDENCE)
        _store_stats_8616(codegen, stats)
        return False
    cfunc = codegen.cfunc
    if cfunc is None:
        stats.record(SegmentedGlobalLoadDecision8616.REFUSED_NO_CFUNC)
        _store_stats_8616(codegen, stats)
        return False

    evidence_by_offset = {item.offset & 0xFFFF: item for item in evidence}
    direct_by_offset = {(item.offset & 0xFFFF, item.width): item for item in direct_refs}
    dirty_assignments = _collect_unique_dirty_assignment_rhs_8616(cfunc)
    created: dict[tuple[int, int], CVariable] = {}
    materialized_zero_test_evidence: set[DwordGlobalZeroTestEvidence8616] = set()
    zero_test_materialized_count = 0

    def transform(node: object) -> object:
        nonlocal zero_test_materialized_count
        zero_test_expr = _materialize_direct_global_zero_test_or_expr_8616(
            codegen,
            node,
            direct_by_offset,
            zero_test_evidence,
        )
        if zero_test_expr is not None:
            variable = zero_test_expr.variable if isinstance(zero_test_expr, CVariable) else None
            scalar_addr = variable.addr if isinstance(variable, SimMemoryVariable) else None
            if isinstance(scalar_addr, int):
                matched_evidence = next(
                    (
                        item
                        for item in zero_test_evidence
                        if (item.base_offset & 0xFFFF) == (scalar_addr & 0xFFFF)
                    ),
                    None,
                )
                if matched_evidence is not None:
                    materialized_zero_test_evidence.add(matched_evidence)
                    zero_test_materialized_count += 1
            stats.direct_symbol_materialized_count += 1
            stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
            return zero_test_expr
        pair_expr = _materialize_direct_global_load_pair_expr_8616(
            codegen,
            node,
            evidence_by_offset,
            direct_by_offset,
            stats,
            dirty_assignments=dirty_assignments,
        )
        if pair_expr is not None:
            return pair_expr
        if isinstance(node, CVariable):
            direct_ref = _direct_ref_for_cvariable_8616(node, direct_by_offset)
            if direct_ref is not None:
                expr = _make_direct_global_symbol_or_projection_expr_8616(
                    codegen,
                    direct_ref,
                    direct_ref.width,
                    direct_by_offset,
                )
                if expr is not None:
                    stats.direct_symbol_materialized_count += 1
                    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
                    return expr
            return node
        indexed_projection = _make_dword_scalar_indexed_subword_projection_expr_8616(
            codegen,
            node,
            direct_by_offset,
        )
        if indexed_projection is not None:
            stats.direct_symbol_materialized_count += 1
            stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
            return indexed_projection
        if not isinstance(node, CFunctionCall):
            return node
        helper = _segment_load_helper_8616(node)
        if helper is None:
            stats.record(SegmentedGlobalLoadDecision8616.REFUSED_HELPER_MISMATCH)
            return node
        args = tuple(node.args or ())
        if len(args) != 2:
            stats.record(SegmentedGlobalLoadDecision8616.REFUSED_SEGMENT_MISMATCH)
            return node
        offset = _constant_int_8616(args[1])
        if offset is None:
            stats.record(SegmentedGlobalLoadDecision8616.REFUSED_OFFSET_MISMATCH)
            return node
        direct_ref = direct_by_offset.get((offset & 0xFFFF, helper.width))
        if direct_ref is not None:
            expr = _make_direct_global_symbol_or_projection_expr_8616(
                codegen,
                direct_ref,
                helper.width,
                direct_by_offset,
            )
            if expr is not None:
                stats.direct_symbol_materialized_count += 1
                stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
                return expr
        if not _is_ds_segment_expr_8616(project, args[0]):
            stats.record(SegmentedGlobalLoadDecision8616.REFUSED_SEGMENT_MISMATCH)
            return node
        if helper.width == 1:
            covering_ref = _direct_global_ref_covering_byte_8616(direct_by_offset, offset & 0xFFFF)
            if covering_ref is not None:
                expr = _make_direct_global_byte_projection_expr_8616(
                    codegen,
                    covering_ref,
                    offset & 0xFFFF,
                    direct_by_offset,
                )
                if expr is not None:
                    stats.direct_symbol_materialized_count += 1
                    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
                    return expr
        item = evidence_by_offset.get(offset & 0xFFFF)
        if item is None or item.width < helper.width:
            stats.record(SegmentedGlobalLoadDecision8616.REFUSED_OFFSET_MISMATCH)
            return node
        key = (item.offset & 0xFFFF, helper.width)
        cvar = created.get(key)
        if cvar is None:
            cvar = CVariable(
                SimMemoryVariable(
                    item.offset & 0xFFFF, helper.width, name=_sanitize_identifier_8616(item.name), region=cfunc.addr
                ),
                variable_type=_type_for_width_8616(helper.width),
                codegen=codegen,
            )
            created[key] = cvar
            _record_global_declaration_8616(codegen, helper.width, _sanitize_identifier_8616(item.name))
        stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
        return cvar

    def should_process_child(current: object, attr: str) -> bool:
        if isinstance(current, CAssignment) and attr == "lhs":
            return False
        return not (isinstance(current, CIndexedVariable) and attr == "variable")

    changed = False
    for root in _cfunc_roots_8616(cfunc):
        new_root = transform(root)
        if new_root is not root:
            changed = True
        if isinstance(root, CStatements) and _replace_c_children_8616(
            root, transform, should_process_child=should_process_child
        ):
            changed = True
    if zero_test_materialized_count > 0:
        try:
            previous_record = codegen._inertia_dword_global_zero_test_materialization_record_8616
        except AttributeError:
            previous_record = None
        previous_evidence = (
            previous_record.evidence
            if isinstance(previous_record, DwordGlobalZeroTestMaterializationRecord8616)
            else ()
        )
        previous_materialized_count = (
            previous_record.materialized_count
            if isinstance(previous_record, DwordGlobalZeroTestMaterializationRecord8616)
            else 0
        )
        combined_evidence = tuple(
            dict.fromkeys((*previous_evidence, *sorted(materialized_zero_test_evidence, key=lambda item: item.base_offset)))
        )
        raw_fact_count = max(
            len(zero_test_evidence),
            previous_record.raw_fact_count
            if isinstance(previous_record, DwordGlobalZeroTestMaterializationRecord8616)
            else 0,
        )
        codegen._inertia_dword_global_zero_test_materialization_record_8616 = (
            DwordGlobalZeroTestMaterializationRecord8616(
                evidence=combined_evidence,
                raw_fact_count=raw_fact_count,
                normalized_fact_count=raw_fact_count,
                classified_fact_count=len(combined_evidence),
                materialized_count=previous_materialized_count + zero_test_materialized_count,
                failure_count=max(raw_fact_count - len(combined_evidence), 0),
            )
        )
    _debug_remaining_segmented_global_load_nodes_8616(cfunc)
    _store_stats_8616(codegen, stats)
    return changed


def materialize_direct_global_symbol_stores_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: SyntheticGlobalsBoundary8616 | None = None,
    cod_metadata: CodMetadataBoundary8616 = None,
) -> bool:
    """Materialize direct global stores after symbol evidence is proven."""

    stats = SegmentedGlobalLoadStats8616()
    function = _active_function_8616(project, codegen)
    summaries = _function_instruction_summaries_8616(project, function) if function is not None else []
    direct_refs = _merge_direct_global_symbol_refs_8616(
        _collect_direct_global_symbol_refs_8616(cod_metadata, summaries),
        _collect_synthetic_direct_global_symbol_refs_8616(synthetic_globals, summaries),
    )
    codegen._inertia_direct_global_symbol_store_spans_8616 = tuple(
        (item.offset & 0xFFFF, max(1, int(item.width))) for item in direct_refs
    )
    direct_updates = _collect_direct_global_update_evidence_8616(summaries)
    direct_boolean_stores = _collect_direct_global_boolean_store_evidence_8616(summaries)
    direct_call_return_stores = _collect_direct_global_call_return_store_evidence_8616(project, function)
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        log.warning(
            "[seg-global-stores] refs=%s updates=%s",
            tuple((item.offset & 0xFFFF, item.name, item.relative_disp, item.width) for item in direct_refs),
            tuple((item.offset & 0xFFFF, item.width, item.delta) for item in direct_updates),
        )
    stats.raw_fact_count = len(summaries)
    stats.direct_symbol_raw_fact_count = len(direct_refs)
    stats.direct_symbol_update_raw_fact_count = len(direct_updates)
    stats.direct_symbol_boolean_store_raw_fact_count = len(direct_boolean_stores)
    stats.direct_symbol_call_return_raw_fact_count = len(direct_call_return_stores)
    changed = materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen,
        direct_refs,
        direct_updates=direct_updates,
        direct_boolean_stores=direct_boolean_stores,
        direct_call_return_stores=direct_call_return_stores,
        stats=stats,
    )
    _store_stats_8616(codegen, stats)
    return changed


def materialize_direct_global_symbol_stores_from_evidence_8616(
    codegen: CodegenBoundary8616,
    direct_refs: tuple[DirectGlobalSymbolRef8616, ...],
    *,
    direct_updates: tuple[DirectGlobalUpdateEvidence8616, ...] = (),
    direct_boolean_stores: tuple[DirectGlobalBooleanStoreEvidence8616, ...] = (),
    direct_call_return_stores: tuple[DirectGlobalCallReturnStoreEvidence8616, ...] = (),
    stats: SegmentedGlobalLoadStats8616 | None = None,
) -> bool:
    """Materialize direct global stores from already-collected lowering evidence."""

    if stats is None:
        stats = SegmentedGlobalLoadStats8616()
    if not direct_refs:
        stats.record(SegmentedGlobalLoadDecision8616.REFUSED_NO_EVIDENCE)
        return False
    cfunc = codegen.cfunc
    if cfunc is None:
        stats.record(SegmentedGlobalLoadDecision8616.REFUSED_NO_CFUNC)
        return False
    direct_by_offset = {(item.offset & 0xFFFF, item.width): item for item in direct_refs}
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]] = {}
    for item in direct_updates:
        direct_update_by_offset.setdefault((item.offset & 0xFFFF, item.width), []).append(item)
    direct_boolean_by_offset: dict[tuple[int, int], list[DirectGlobalBooleanStoreEvidence8616]] = {}
    for item in direct_boolean_stores:
        direct_boolean_by_offset.setdefault((item.dest_offset & 0xFFFF, item.dest_width), []).append(item)
    direct_call_return_by_offset: dict[tuple[int, int], list[DirectGlobalCallReturnStoreEvidence8616]] = {}
    for item in direct_call_return_stores:
        direct_call_return_by_offset.setdefault((item.offset & 0xFFFF, item.width), []).append(item)
    changed = False
    for root in tuple(_cfunc_roots_8616(cfunc)):
        root_changed = False
        if isinstance(root, CStatements) and _materialize_direct_global_dword_update_from_low_word_high_bytes_8616(
            root,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_word_store_pairs_8616(
            root,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_dword_update_from_low_word_high_bytes_8616(
            root,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_dword_update_preserving_carriers_8616(
            root,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_dword_update_from_scalar_preserve_8616(
            root,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_dword_update_from_low_word_scalar_preserve_8616(
            root,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_dword_store_pairs_8616(
            root,
            codegen,
            direct_by_offset,
            direct_call_return_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_boolean_stores_8616(
            root,
            codegen,
            direct_by_offset,
            direct_boolean_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _remove_duplicate_direct_global_boolean_store_artifacts_8616(
            root,
            direct_boolean_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _remove_direct_global_boolean_store_high_byte_merges_8616(
            root,
            direct_boolean_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        for stmt in _iter_c_nodes_deep_8616(root):
            assignment = _assignment_statement_8616(stmt)
            if assignment is None:
                continue
            lhs = assignment.lhs
            identity = _direct_global_lvalue_identity_8616(lhs)
            if identity is None:
                continue
            addr, width = identity
            ref = _direct_global_store_lvalue_ref_8616(direct_by_offset, addr, width)
            if ref is None:
                continue
            replacement, replacement_rhs = _make_direct_global_store_assignment_exprs_8616(
                codegen,
                ref,
                int(ref.width or width),
                assignment.rhs,
                direct_by_offset,
            )
            if replacement is None or _same_c_expression_8616(lhs, replacement):
                continue
            assignment.lhs = replacement
            if replacement_rhs is not None:
                assignment.rhs = replacement_rhs
            stats.direct_symbol_materialized_count += 1
            stats.direct_symbol_store_materialized_count += 1
            stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_nested_direct_global_call_return_store_8616(
            root,
            codegen,
            direct_by_offset,
            direct_call_return_stores,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _remove_materialized_direct_global_call_return_carriers_8616(
            root,
            codegen,
            direct_call_return_stores,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_dword_update_from_scalar_preserve_8616(
            root,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _remove_direct_global_redundant_high_byte_stores_8616(
            root,
            codegen,
            direct_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _remove_segment_pointer_helper_self_assignments_8616(root, stats):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _materialize_direct_global_single_byte_stores_8616(
            root,
            codegen,
            direct_by_offset,
            stats,
        ):
            changed = True
            root_changed = True
        if root_changed:
            _sync_cfunc_statement_roots_8616(cfunc, root)
    return changed


def _materialize_nested_direct_global_call_return_store_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    evidence_items: tuple[DirectGlobalCallReturnStoreEvidence8616, ...],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    """Fold an evidenced call/store sequence split across straight-line statement groups.

    angr may place a call carrier and the immediately following AX/DX stores
    in separate nested ``CStatements`` nodes.  Machine instruction addresses
    and complete destination-byte coverage prove the connection; groups with
    control flow, calls, unrelated tagged instructions, or ambiguous matches
    are refused.
    """

    groups = [root]
    groups.extend(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements) and node is not root)
    changed = False
    debug_enabled = bool(os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"))
    for evidence in evidence_items:
        dword_ref = direct_by_offset.get((evidence.offset & 0xFFFF, evidence.width))
        if dword_ref is None:
            continue
        call_matches: list[tuple[CStatements, int, CAssignment]] = []
        store_matches: list[CStatements] = []
        expected_store_addrs = set(evidence.store_ins_addrs)
        for group in groups:
            for index, stmt in enumerate(group.statements):
                assignment = _assignment_statement_8616(stmt)
                if assignment is None:
                    continue
                if (
                    _cfunction_call_name_8616(assignment.rhs) == evidence.source_call_name
                    and _statement_ins_addr_8616(stmt) == evidence.source_call_ins_addr
                ):
                    call_matches.append((group, index, assignment))
            assignments = tuple(_assignment_statement_8616(stmt) for stmt in group.statements)
            if not assignments or any(assignment is None for assignment in assignments):
                continue
            call_assignments = tuple(
                assignment
                for assignment in assignments
                if assignment is not None and _cfunction_call_name_8616(assignment.rhs) is not None
            )
            if any(
                _direct_global_lvalue_identity_8616(assignment.lhs)
                != (evidence.offset & 0xFFFF, evidence.width)
                or _cfunction_call_name_8616(assignment.rhs) != evidence.source_call_name
                for assignment in call_assignments
            ):
                continue
            tagged_addrs = {
                ins_addr
                for stmt in group.statements
                if (ins_addr := _statement_ins_addr_8616(stmt)) is not None
            }
            if not tagged_addrs or not tagged_addrs.issubset(expected_store_addrs):
                continue
            covered_offsets: set[int] = set()
            for stmt, assignment in zip(group.statements, assignments, strict=True):
                if assignment is None or _statement_ins_addr_8616(stmt) not in expected_store_addrs:
                    continue
                identity = _direct_global_lvalue_identity_8616(assignment.lhs)
                if identity is None:
                    continue
                offset, width = identity
                covered_offsets.update((offset + byte_index) & 0xFFFF for byte_index in range(width))
            expected_offsets = {(evidence.offset + byte_index) & 0xFFFF for byte_index in range(evidence.width)}
            if debug_enabled:
                log.warning(
                    "[seg-global-call-return-group] statements=%d tagged=%s covered=%s expected=%s",
                    len(group.statements),
                    tuple(hex(item) for item in sorted(tagged_addrs)),
                    tuple(hex(item) for item in sorted(covered_offsets)),
                    tuple(hex(item) for item in sorted(expected_offsets)),
                )
            exact_store_tags_present = expected_store_addrs.issubset(tagged_addrs)
            if exact_store_tags_present or expected_offsets.issubset(covered_offsets):
                store_matches.append(group)
        if debug_enabled:
            log.warning(
                "[seg-global-call-return-match] call_matches=%d store_matches=%d evidence=%s",
                len(call_matches),
                len(store_matches),
                evidence,
            )
        if len(call_matches) != 1 or len(store_matches) != 1:
            continue
        call_group, call_index, call_assignment = call_matches[0]
        store_group = store_matches[0]
        if call_group is store_group:
            continue
        lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, evidence.width)
        if lhs is None:
            continue
        canonical_assignment = CAssignment(
            lhs,
            call_assignment.rhs,
            codegen=codegen,
            tags=call_assignment.tags,
        )
        del call_group.statements[call_index]
        store_group.statements[:] = [canonical_assignment]
        stats.direct_symbol_materialized_count += 1
        stats.direct_symbol_store_materialized_count += 1
        stats.direct_symbol_call_return_materialized_count += 1
        stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
        changed = True
    return changed


def _materialize_direct_global_dword_update_from_low_word_high_bytes_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    """Rewrite dword update sequences across a dynamic boundary: angr codegen statement trees."""

    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            index = 0
            while index < len(statements):
                match = _match_direct_global_dword_update_from_low_word_high_bytes_8616(
                    root,
                    statements,
                    index,
                    codegen,
                    direct_by_offset,
                    direct_update_by_offset,
                    stats,
                )
                if match is None:
                    process_statements(statements[index])
                    index += 1
                    continue
                replacement, last_index = match
                statements[index] = replacement
                del statements[index + 1 : last_index + 1]
                changed = True
            while index < len(statements):
                process_statements(statements[index])
                index += 1
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _materialize_direct_global_dword_update_from_scalar_preserve_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    """Rewrite scalar-preserve updates across a dynamic boundary: angr codegen statement trees."""

    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            index = 0
            while index < len(statements):
                match = _match_direct_global_dword_update_from_scalar_preserve_8616(
                    root,
                    statements,
                    index,
                    codegen,
                    direct_by_offset,
                    direct_update_by_offset,
                    stats,
                )
                if match is None:
                    process_statements(statements[index])
                    index += 1
                    continue
                replacement, last_index = match
                statements[index] = replacement
                del statements[index + 1 : last_index + 1]
                changed = True
            while index < len(statements):
                process_statements(statements[index])
                index += 1
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _materialize_direct_global_dword_update_from_low_word_scalar_preserve_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    """Rewrite low-word scalar-preserve updates across a dynamic boundary: angr codegen statement trees."""

    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            index = 0
            while index < len(statements):
                match = _match_direct_global_dword_update_from_low_word_scalar_preserve_8616(
                    root,
                    statements,
                    index,
                    codegen,
                    direct_by_offset,
                    direct_update_by_offset,
                    stats,
                )
                if match is None:
                    process_statements(statements[index])
                    index += 1
                    continue
                replacement, last_index = match
                statements[index] = replacement
                del statements[index + 1 : last_index + 1]
                changed = True
            while index < len(statements):
                process_statements(statements[index])
                index += 1
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _match_direct_global_dword_update_from_scalar_preserve_8616(
    root: CStatements,
    statements: list[object],
    index: int,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> DwordUpdateMatch8616:
    assignment = _assignment_statement_8616(statements[index])
    if assignment is None:
        return None
    scalar_identity = _direct_global_lvalue_identity_8616(assignment.lhs)
    if scalar_identity is None:
        return None
    low_addr, width = scalar_identity
    if width != 4:
        return None
    dword_ref = direct_by_offset.get((low_addr & 0xFFFF, 4))
    low_ref = direct_by_offset.get((low_addr & 0xFFFF, 2))
    high_ref = direct_by_offset.get(((low_addr + 2) & 0xFFFF, 2))
    update_candidates = direct_update_by_offset.get((low_addr & 0xFFFF, 2), [])
    if dword_ref is None or low_ref is None or high_ref is None or not update_candidates:
        return None
    delta = _scalar_preserve_low_word_update_delta_8616(assignment.rhs, codegen, dword_ref)
    update_evidence = _direct_global_update_evidence_for_delta_8616(update_candidates, delta)
    if update_evidence is None:
        return None
    upper_index = _scalar_preserve_upper_word_store_index_8616(statements, index, codegen, dword_ref)
    if upper_index is None:
        return None
    last_index = _direct_global_dword_update_dependent_copy_window_end_8616(statements, index, upper_index)
    if not _direct_global_dword_update_gap_is_removable_8616(root, statements, index, last_index):
        return None
    lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    rhs_lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    if lhs is None or rhs_lhs is None:
        return None
    op = "Add" if int(update_evidence.delta) > 0 else "Sub"
    rhs = CBinaryOp(
        op,
        rhs_lhs,
        CConstant(abs(int(update_evidence.delta)), SimTypeLong(False), codegen=codegen),
        codegen=codegen,
    )
    stats.direct_symbol_materialized_count += 1
    stats.direct_symbol_store_materialized_count += 1
    stats.direct_symbol_update_materialized_count += 1
    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
    return CAssignment(lhs, rhs, codegen=codegen, tags=assignment.tags), last_index


def _match_direct_global_dword_update_from_low_word_scalar_preserve_8616(
    root: CStatements,
    statements: list[object],
    index: int,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> DwordUpdateMatch8616:
    low_assignment = _assignment_statement_8616(statements[index])
    if low_assignment is None:
        return None
    low_identity = _direct_global_lvalue_identity_8616(low_assignment.lhs)
    if low_identity is None:
        return None
    low_addr, low_width = low_identity
    if low_width != 2:
        return None
    dword_ref = direct_by_offset.get((low_addr & 0xFFFF, 4))
    low_ref = direct_by_offset.get((low_addr & 0xFFFF, 2))
    high_ref = direct_by_offset.get(((low_addr + 2) & 0xFFFF, 2))
    update_candidates = direct_update_by_offset.get((low_addr & 0xFFFF, 2), [])
    if dword_ref is None or low_ref is None or high_ref is None or not update_candidates:
        _debug_direct_dword_update_refusal_8616(
            "low_word_scalar_missing_evidence",
            low_assignment,
            low_addr=f"{low_addr:#x}",
            dword=bool(dword_ref),
            low=bool(low_ref),
            high=bool(high_ref),
            update=bool(update_candidates),
        )
        return None
    source_delta = _direct_global_word_update_expr_delta_8616(low_assignment.rhs)
    update_evidence = _direct_global_update_evidence_for_delta_8616(update_candidates, source_delta)
    if update_evidence is None:
        _debug_direct_dword_update_refusal_8616(
            "low_word_scalar_delta",
            low_assignment,
            low_addr=f"{low_addr:#x}",
            source_delta=source_delta,
        )
        return None
    upper_index = _scalar_preserve_upper_word_store_index_8616(statements, index, codegen, dword_ref)
    if upper_index is None:
        _debug_direct_dword_update_refusal_8616(
            "low_word_scalar_upper",
            low_assignment,
            low_addr=f"{low_addr:#x}",
        )
        return None
    last_index = _direct_global_dword_update_removable_window_end_8616(statements, upper_index)
    if not _direct_global_dword_update_gap_is_removable_8616(root, statements, index, last_index):
        _debug_direct_dword_update_refusal_8616(
            "low_word_scalar_gap",
            low_assignment,
            low_addr=f"{low_addr:#x}",
            upper_index=upper_index,
            last_index=last_index,
        )
        return None
    lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    rhs_lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    if lhs is None or rhs_lhs is None:
        return None
    op = "Add" if int(update_evidence.delta) > 0 else "Sub"
    rhs = CBinaryOp(
        op,
        rhs_lhs,
        CConstant(abs(int(update_evidence.delta)), SimTypeLong(False), codegen=codegen),
        codegen=codegen,
    )
    stats.direct_symbol_materialized_count += 1
    stats.direct_symbol_store_materialized_count += 1
    stats.direct_symbol_update_materialized_count += 1
    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
    return CAssignment(lhs, rhs, codegen=codegen, tags=low_assignment.tags), last_index


def _direct_global_dword_update_dependent_copy_window_end_8616(
    statements: list[object],
    first_index: int,
    seed_last_index: int,
) -> int:
    consumed_keys: set[object] = set()
    for stmt in statements[first_index + 1 : seed_last_index + 1]:
        assignment = _assignment_statement_8616(stmt)
        if assignment is None:
            continue
        consumed_keys.update(_copy_keys_8616(assignment.lhs))

    last_index = seed_last_index
    max_index = min(len(statements), seed_last_index + 96)
    for candidate_index in range(seed_last_index + 1, max_index):
        assignment = _assignment_statement_8616(statements[candidate_index])
        if assignment is None:
            break
        if _direct_global_lvalue_identity_8616(assignment.lhs) is not None:
            break
        lhs_keys = set(_copy_keys_8616(assignment.lhs))
        if not lhs_keys:
            break
        rhs = assignment.rhs
        if _rhs_has_obvious_side_effect_8616(rhs):
            break
        rhs_keys = _copy_keys_read_by_expr_8616(rhs)
        if not rhs_keys.intersection(consumed_keys):
            break
        consumed_keys.update(lhs_keys)
        last_index = candidate_index
    return last_index


def _copy_keys_read_by_expr_8616(node: object) -> set[object]:
    keys: set[object] = set()
    for child in _iter_c_nodes_deep_8616(node):
        keys.update(_copy_keys_8616(child))
    return keys


def _scalar_preserve_upper_word_store_index_8616(
    statements: list[object],
    index: int,
    codegen: CodegenBoundary8616,
    dword_ref: DirectGlobalSymbolRef8616,
) -> int | None:
    """Return the last consecutive scalar write that preserves the updated low word."""
    scalar = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    if scalar is None:
        return None
    matched_index: int | None = None
    max_index = min(len(statements), index + 96)
    for candidate_index in range(index + 1, max_index):
        assignment = _assignment_statement_8616(statements[candidate_index])
        if assignment is None:
            return matched_index
        lhs = assignment.lhs
        if _same_c_expression_8616(lhs, scalar):
            if not _scalar_preserves_low_word_8616(assignment.rhs, scalar):
                return matched_index
            matched_index = candidate_index
            continue
        if _direct_global_lvalue_identity_8616(lhs) is not None:
            return matched_index
    return matched_index


def _scalar_preserve_low_word_update_delta_8616(
    expr: object,
    codegen: CodegenBoundary8616,
    dword_ref: DirectGlobalSymbolRef8616,
) -> int | None:
    scalar = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    if scalar is None or not isinstance(expr, CBinaryOp) or expr.op != "Or":
        return None
    preserved, updated = expr.lhs, expr.rhs
    if not _scalar_preserves_high_word_8616(preserved, scalar):
        return None
    while isinstance(updated, CBinaryOp) and updated.op == "And" and _constant_int_8616(updated.rhs) == 0xFFFF:
        updated = updated.lhs
    while isinstance(updated, CTypeCast):
        updated = updated.expr
    return _direct_global_word_update_expr_delta_8616(updated)


def _scalar_preserves_high_word_8616(expr: object, scalar: object) -> bool:
    return (
        isinstance(expr, CBinaryOp)
        and expr.op == "And"
        and _same_c_expression_8616(expr.lhs, scalar)
        and _constant_int_8616(expr.rhs) == 0xFFFF0000
    )


def _scalar_preserves_low_word_8616(expr: object, scalar: object) -> bool:
    if not isinstance(expr, CBinaryOp) or expr.op != "Or":
        return False
    lhs = expr.lhs
    rhs = expr.rhs
    return (
        isinstance(lhs, CBinaryOp)
        and lhs.op == "And"
        and _same_c_expression_8616(lhs.lhs, scalar)
        and _constant_int_8616(lhs.rhs) == 0xFFFF
        and isinstance(rhs, CBinaryOp)
        and rhs.op == "Shl"
        and _constant_int_8616(rhs.rhs) == 16
    )


def _materialize_direct_global_boolean_stores_8616(
    root: CStatements,
    codegen: object,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_boolean_by_offset: dict[tuple[int, int], list[DirectGlobalBooleanStoreEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    consumed: set[DirectGlobalBooleanStoreEvidence8616] = set()
    changed = False

    for stmt in _iter_c_nodes_deep_8616(root):
        assignment = _assignment_statement_8616(stmt)
        if assignment is None:
            continue
        lhs_identity = _direct_global_lvalue_identity_8616(assignment.lhs)
        if lhs_identity is None:
            continue
        dest_offset, dest_width = lhs_identity
        candidates = direct_boolean_by_offset.get((dest_offset & 0xFFFF, dest_width), ())
        if not candidates:
            continue
        stmt_ins_addr = _statement_ins_addr_8616(stmt)
        evidence = _select_direct_global_boolean_store_evidence_8616(candidates, consumed, stmt_ins_addr)
        if evidence is None:
            continue
        dest_ref = direct_by_offset.get((evidence.dest_offset & 0xFFFF, evidence.dest_width))
        source_ref = direct_by_offset.get((evidence.source_offset & 0xFFFF, evidence.source_width))
        if dest_ref is None or source_ref is None:
            continue
        lhs = _make_direct_global_symbol_expr_8616(codegen, dest_ref, evidence.dest_width)
        source = _make_direct_global_symbol_expr_8616(codegen, source_ref, evidence.source_width)
        if lhs is None or source is None:
            continue
        rhs = CBinaryOp(
            "CmpLT",
            source,
            CConstant(int(evidence.compare_value) & 0xFFFF, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        assignment.lhs = lhs
        assignment.rhs = rhs
        consumed.add(evidence)
        stats.direct_symbol_materialized_count += 1
        stats.direct_symbol_store_materialized_count += 1
        stats.direct_symbol_boolean_store_materialized_count += 1
        stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
        changed = True
    return changed


def _select_direct_global_boolean_store_evidence_8616(
    candidates: Iterable[DirectGlobalBooleanStoreEvidence8616],
    consumed: set[DirectGlobalBooleanStoreEvidence8616],
    stmt_ins_addr: int | None,
) -> DirectGlobalBooleanStoreEvidence8616 | None:
    available = [item for item in candidates if item not in consumed]
    if not available:
        return None
    if stmt_ins_addr is not None:
        for item in available:
            if item.store_ins_addr == stmt_ins_addr:
                return item
        return None
    if len(available) == 1:
        return available[0]
    without_addr = [item for item in available if item.store_ins_addr is None]
    return without_addr[0] if len(without_addr) == 1 else None


def _direct_global_boolean_assignment_evidence_8616(
    assignment: CAssignment,
    direct_boolean_by_offset: dict[tuple[int, int], list[DirectGlobalBooleanStoreEvidence8616]],
) -> DirectGlobalBooleanStoreEvidence8616 | None:
    """Return exact instruction evidence for one direct-global assignment."""
    identity = _direct_global_lvalue_identity_8616(assignment.lhs)
    if identity is None:
        return None
    ins_addr = _statement_ins_addr_8616(assignment)
    if ins_addr is None:
        return None
    matches = tuple(
        evidence
        for evidence in direct_boolean_by_offset.get((identity[0] & 0xFFFF, identity[1]), ())
        if evidence.store_ins_addr == ins_addr
    )
    return matches[0] if len(matches) == 1 else None


def _direct_global_boolean_rhs_matches_evidence_8616(
    rhs: object,
    evidence: DirectGlobalBooleanStoreEvidence8616,
) -> bool:
    """Return whether an RHS is the explicit comparison proven by evidence."""
    if not isinstance(rhs, CBinaryOp) or rhs.op != "CmpLT":
        return False
    source_identity = _direct_global_lvalue_identity_8616(rhs.lhs)
    return (
        source_identity == (evidence.source_offset & 0xFFFF, evidence.source_width)
        and _constant_int_8616(rhs.rhs) == (evidence.compare_value & 0xFFFF)
    )


def _remove_duplicate_direct_global_boolean_store_artifacts_8616(
    root: CStatements,
    direct_boolean_by_offset: dict[tuple[int, int], list[DirectGlobalBooleanStoreEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    """Remove duplicate C assignments for one exact binary boolean store."""
    changed = False

    def process_statements(node: object) -> None:
        """Walk the dynamic boundary: third-party angr C AST statement containers."""
        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            canonical = {
                evidence
                for statement in statements
                if (assignment := _assignment_statement_8616(statement)) is not None
                and (evidence := _direct_global_boolean_assignment_evidence_8616(
                    assignment,
                    direct_boolean_by_offset,
                ))
                is not None
                and _direct_global_boolean_rhs_matches_evidence_8616(assignment.rhs, evidence)
            }
            index = 0
            while index < len(statements):
                statement = statements[index]
                assignment = _assignment_statement_8616(statement)
                evidence = (
                    _direct_global_boolean_assignment_evidence_8616(
                        assignment,
                        direct_boolean_by_offset,
                    )
                    if assignment is not None
                    else None
                )
                if (
                    assignment is not None
                    and evidence in canonical
                    and not _direct_global_boolean_rhs_matches_evidence_8616(assignment.rhs, evidence)
                    and not _rhs_has_obvious_side_effect_8616(assignment.rhs)
                ):
                    del statements[index]
                    stats.direct_symbol_materialized_count += 1
                    stats.direct_symbol_store_materialized_count += 1
                    stats.direct_symbol_boolean_store_materialized_count += 1
                    stats.direct_symbol_boolean_duplicate_pruned_count += 1
                    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
                    changed = True
                    continue
                process_statements(statement)
                index += 1
            return
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _remove_direct_global_boolean_store_high_byte_merges_8616(
    root: CStatements,
    direct_boolean_by_offset: dict[tuple[int, int], list[DirectGlobalBooleanStoreEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            index = 0
            while index < len(statements):
                assignment = _assignment_statement_8616(statements[index])
                if assignment is None:
                    process_statements(statements[index])
                    index += 1
                    continue
                identity = _direct_global_lvalue_identity_8616(assignment.lhs)
                if identity is None or not direct_boolean_by_offset.get((identity[0] & 0xFFFF, identity[1])):
                    process_statements(statements[index])
                    index += 1
                    continue
                delete_index = _direct_global_boolean_store_high_byte_merge_index_8616(
                    statements,
                    index,
                    identity,
                    assignment.lhs,
                )
                if delete_index is None:
                    process_statements(statements[index])
                    index += 1
                    continue
                del statements[delete_index]
                stats.direct_symbol_materialized_count += 1
                stats.direct_symbol_store_materialized_count += 1
                stats.direct_symbol_boolean_store_materialized_count += 1
                stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
                changed = True
                process_statements(statements[index])
                index += 1
            return
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _direct_global_boolean_store_high_byte_merge_index_8616(
    statements: list[object],
    index: int,
    identity: tuple[int, int],
    lhs: object,
) -> int | None:
    max_index = min(len(statements), index + 16)
    for candidate_index in range(index + 1, max_index):
        assignment = _assignment_statement_8616(statements[candidate_index])
        if assignment is None:
            return None
        candidate_lhs = assignment.lhs
        candidate_identity = _direct_global_lvalue_identity_8616(candidate_lhs)
        if candidate_identity is None:
            if _rhs_has_obvious_side_effect_8616(assignment.rhs):
                return None
            if not _copy_keys_8616(candidate_lhs):
                return None
            continue
        if candidate_identity != identity:
            return None
        if _direct_global_boolean_high_byte_merge_rhs_8616(assignment.rhs, lhs):
            return candidate_index
        return None
    return None


def _direct_global_boolean_high_byte_merge_rhs_8616(rhs: object, global_lvalue: object) -> bool:
    if not isinstance(rhs, CBinaryOp) or rhs.op != "Or":
        return False
    pairs = ((rhs.lhs, rhs.rhs), (rhs.rhs, rhs.lhs))
    for low_part, high_part in pairs:
        if not _direct_global_boolean_low_preserving_part_8616(low_part, global_lvalue):
            continue
        if _direct_global_boolean_high_byte_part_8616(high_part):
            return True
    return False


def _direct_global_boolean_low_preserving_part_8616(node: object, global_lvalue: object) -> bool:
    if not isinstance(node, CBinaryOp) or node.op != "And":
        return False
    pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
    return any(_same_c_expression_8616(value, global_lvalue) and _constant_int_8616(mask) == 0xFF for value, mask in pairs)


def _direct_global_boolean_high_byte_part_8616(node: object) -> bool:
    if not isinstance(node, CBinaryOp) or node.op != "Shl":
        return False
    return _constant_int_8616(node.rhs) == 8


def _materialize_direct_global_dword_update_preserving_carriers_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            index = 0
            while index < len(statements):
                match = _match_direct_global_dword_update_preserving_carriers_8616(
                    statements,
                    index,
                    codegen,
                    direct_by_offset,
                    direct_update_by_offset,
                    stats,
                )
                if match is None:
                    process_statements(statements[index])
                    index += 1
                    continue
                replacement, delete_indices = match
                statements[index] = replacement
                for delete_index in sorted(delete_indices, reverse=True):
                    del statements[delete_index]
                changed = True
            while index < len(statements):
                process_statements(statements[index])
                index += 1
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _match_direct_global_dword_update_preserving_carriers_8616(
    statements: list[object],
    index: int,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> tuple[CAssignment, tuple[int, int]] | None:
    low_assignment = _assignment_statement_8616(statements[index])
    if low_assignment is None:
        return None
    low_identity = _direct_global_lvalue_identity_8616(low_assignment.lhs)
    if low_identity is None:
        return None
    low_addr, low_width = low_identity
    if low_width != 2:
        return None
    low_ref = direct_by_offset.get((low_addr & 0xFFFF, 2))
    high_ref = direct_by_offset.get(((low_addr + 2) & 0xFFFF, 2))
    dword_ref = direct_by_offset.get((low_addr & 0xFFFF, 4))
    update_candidates = direct_update_by_offset.get((low_addr & 0xFFFF, 2), [])
    if low_ref is None or high_ref is None or dword_ref is None or not update_candidates:
        return None
    low_is_dword_base = int(low_ref.relative_disp) == 0 and int(dword_ref.offset) == int(low_ref.offset)
    if not low_is_dword_base and _sanitize_identifier_8616(low_ref.name) != _sanitize_identifier_8616(high_ref.name):
        return None
    if _sanitize_identifier_8616(low_ref.name) != _sanitize_identifier_8616(dword_ref.name):
        if not low_is_dword_base:
            return None
    if int(low_ref.relative_disp) != 0 or int(high_ref.relative_disp) != 2:
        return None
    source_delta = _direct_global_word_update_expr_delta_8616(low_assignment.rhs)
    update_evidence = _direct_global_update_evidence_for_delta_8616(update_candidates, source_delta)
    if update_evidence is None:
        return None
    match_window = _direct_global_dword_update_high_byte_window_8616(statements, index, low_addr)
    if match_window is None:
        return None
    high_low_index, high_high_index = match_window
    lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    rhs_lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    if lhs is None or rhs_lhs is None:
        return None
    op = "Add" if int(update_evidence.delta) > 0 else "Sub"
    rhs = CBinaryOp(
        op,
        rhs_lhs,
        CConstant(abs(int(update_evidence.delta)), SimTypeLong(False), codegen=codegen),
        codegen=codegen,
    )
    stats.direct_symbol_materialized_count += 1
    stats.direct_symbol_store_materialized_count += 1
    stats.direct_symbol_update_materialized_count += 1
    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
    return CAssignment(lhs, rhs, codegen=codegen, tags=low_assignment.tags), (
        high_low_index,
        high_high_index,
    )


def _match_direct_global_dword_update_from_low_word_high_bytes_8616(
    root: CStatements,
    statements: list[object],
    index: int,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> DwordUpdateMatch8616:
    low_word_stmt = statements[index]
    low_assignment = _assignment_statement_8616(low_word_stmt)
    if low_assignment is None:
        _debug_direct_dword_update_refusal_8616("not_assignment", low_word_stmt)
        return None
    low_identity = _direct_global_lvalue_identity_8616(low_assignment.lhs)
    if low_identity is None:
        _debug_direct_dword_update_refusal_8616(
            "low_lvalue_shape",
            low_word_stmt,
            low_lvalue=_debug_lvalue_8616(low_assignment.lhs),
        )
        return None
    low_addr, low_width = low_identity
    if low_width == 1:
        byte_match = _match_direct_global_dword_update_from_low_word_upper_word_8616(
            root,
            statements,
            index,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
            low_addr,
        )
        if byte_match is not None:
            return byte_match
    if low_width != 2:
        _debug_direct_dword_update_refusal_8616("low_width", low_word_stmt, low_addr=f"{low_addr:#x}", width=low_width)
        return None
    low_ref = direct_by_offset.get((low_addr & 0xFFFF, 2))
    high_ref = direct_by_offset.get(((low_addr + 2) & 0xFFFF, 2))
    dword_ref = direct_by_offset.get((low_addr & 0xFFFF, 4))
    update_candidates = direct_update_by_offset.get((low_addr & 0xFFFF, 2), [])
    if low_ref is None or high_ref is None or dword_ref is None or not update_candidates:
        _debug_direct_dword_update_refusal_8616(
            "missing_evidence",
            low_word_stmt,
            low_addr=f"{low_addr:#x}",
            low=low_ref is not None,
            high=high_ref is not None,
            dword=dword_ref is not None,
            update=bool(update_candidates),
        )
        return None
    low_is_dword_base = int(low_ref.relative_disp) == 0 and int(dword_ref.offset) == int(low_ref.offset)
    if not low_is_dword_base and _sanitize_identifier_8616(low_ref.name) != _sanitize_identifier_8616(high_ref.name):
        _debug_direct_dword_update_refusal_8616("name_mismatch_high", low_word_stmt, low=low_ref.name, high=high_ref.name)
        return None
    if _sanitize_identifier_8616(low_ref.name) != _sanitize_identifier_8616(dword_ref.name):
        if not low_is_dword_base:
            _debug_direct_dword_update_refusal_8616(
                "name_mismatch_dword",
                low_word_stmt,
                low=low_ref.name,
                dword=dword_ref.name,
            )
            return None
    if int(low_ref.relative_disp) != 0 or int(high_ref.relative_disp) != 2:
        _debug_direct_dword_update_refusal_8616(
            "relative_disp",
            low_word_stmt,
            low=low_ref.relative_disp,
            high=high_ref.relative_disp,
        )
        return None
    source_delta = _direct_global_word_update_expr_delta_8616(low_assignment.rhs)
    update_evidence = _direct_global_update_evidence_for_delta_8616(update_candidates, source_delta)
    if update_evidence is None:
        _debug_direct_dword_update_refusal_8616(
            "delta",
            low_word_stmt,
            source_delta=source_delta,
            evidence_delta=tuple(item.delta for item in update_candidates),
        )
        return None
    match_window = _direct_global_dword_update_high_byte_window_8616(statements, index, low_addr)
    if match_window is None:
        upper_word_match = _match_direct_global_dword_update_from_low_word_upper_word_8616(
            root,
            statements,
            index,
            codegen,
            direct_by_offset,
            direct_update_by_offset,
            stats,
            low_addr,
        )
        if upper_word_match is not None:
            return upper_word_match
        _debug_direct_dword_update_refusal_8616("window", low_word_stmt, low_addr=f"{low_addr:#x}")
        return None
    high_low_index, high_high_index = match_window
    last_index = _direct_global_dword_update_removable_window_end_8616(statements, high_high_index)
    if not _direct_global_dword_update_gap_is_removable_8616(root, statements, index, last_index):
        _debug_direct_dword_update_refusal_8616(
            "gap_live",
            low_word_stmt,
            high_low_index=high_low_index,
            high_high_index=high_high_index,
            last_index=last_index,
        )
        return None
    lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    if lhs is None:
        return None
    rhs_lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    if rhs_lhs is None:
        return None
    op = "Add" if int(update_evidence.delta) > 0 else "Sub"
    rhs = CBinaryOp(
        op,
        rhs_lhs,
        CConstant(abs(int(update_evidence.delta)), SimTypeLong(False), codegen=codegen),
        codegen=codegen,
    )
    stats.direct_symbol_materialized_count += 1
    stats.direct_symbol_store_materialized_count += 1
    stats.direct_symbol_update_materialized_count += 1
    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
    return CAssignment(lhs, rhs, codegen=codegen, tags=low_assignment.tags), last_index


def _match_direct_global_dword_update_from_low_word_upper_word_8616(
    root: CStatements,
    statements: list[object],
    index: int,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
    low_addr: int,
) -> DwordUpdateMatch8616:
    """Fold low-word updates plus upper-word carry stores.

    Some VEX/AST shapes expose ``add/sub word ptr [global], imm`` as a base
    lvalue rendered like ``global[0]``, followed by an upper-word carry store
    instead of separate high-byte stores. The instruction-summary update fact
    is still word-sized; without it this matcher refuses the shape as too weak
    to widen to a dword update.
    """
    low_assignment = _assignment_statement_8616(statements[index])
    if low_assignment is None:
        return None
    low_addr &= 0xFFFF
    low_ref = direct_by_offset.get((low_addr, 2))
    high_ref = direct_by_offset.get(((low_addr + 2) & 0xFFFF, 2))
    dword_ref = direct_by_offset.get((low_addr, 4))
    update_candidates = direct_update_by_offset.get((low_addr, 2), [])
    if low_ref is None or high_ref is None or dword_ref is None or not update_candidates:
        _debug_direct_dword_update_refusal_8616(
            "low_word_upper_missing_evidence",
            statements[index],
            low_addr=f"{low_addr:#x}",
            low=low_ref is not None,
            high=high_ref is not None,
            dword=dword_ref is not None,
            update=bool(update_candidates),
        )
        return None
    low_is_dword_base = int(low_ref.relative_disp) == 0 and int(dword_ref.offset) == int(low_ref.offset)
    if not low_is_dword_base:
        _debug_direct_dword_update_refusal_8616("low_word_upper_not_dword_base", statements[index], low=low_ref.name)
        return None
    if int(high_ref.relative_disp) != 2:
        _debug_direct_dword_update_refusal_8616(
            "low_word_upper_high_relative_disp",
            statements[index],
            high=high_ref.relative_disp,
        )
        return None
    source_delta = _direct_global_word_update_expr_delta_8616(low_assignment.rhs)
    update_evidence = _direct_global_update_evidence_for_delta_8616(update_candidates, source_delta)
    if update_evidence is None:
        _debug_direct_dword_update_refusal_8616(
            "low_word_upper_delta",
            statements[index],
            source_delta=source_delta,
            evidence_delta=tuple(item.delta for item in update_candidates),
        )
        return None
    upper_index = _direct_global_dword_update_upper_word_window_8616(statements, index, low_addr)
    if upper_index is None:
        _debug_direct_dword_update_refusal_8616("low_word_upper_window", statements[index], low_addr=f"{low_addr:#x}")
        return None
    last_index = _direct_global_dword_update_removable_window_end_8616(statements, upper_index)
    if not _direct_global_dword_update_gap_is_removable_8616(root, statements, index, last_index):
        _debug_direct_dword_update_refusal_8616(
            "low_word_upper_gap_live",
            statements[index],
            upper_index=upper_index,
            last_index=last_index,
        )
        return None
    lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    rhs_lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    if lhs is None or rhs_lhs is None:
        return None
    op = "Add" if int(update_evidence.delta) > 0 else "Sub"
    rhs = CBinaryOp(
        op,
        rhs_lhs,
        CConstant(abs(int(update_evidence.delta)), SimTypeLong(False), codegen=codegen),
        codegen=codegen,
    )
    stats.direct_symbol_materialized_count += 1
    stats.direct_symbol_store_materialized_count += 1
    stats.direct_symbol_update_materialized_count += 1
    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
    return CAssignment(lhs, rhs, codegen=codegen, tags=low_assignment.tags), last_index


def _direct_global_dword_update_upper_word_window_8616(
    statements: list[object],
    index: int,
    low_addr: int,
) -> int | None:
    upper_addr = (low_addr + 2) & 0xFFFF
    max_index = min(len(statements), index + 96)
    for candidate_index in range(index + 1, max_index):
        assignment = _assignment_statement_8616(statements[candidate_index])
        if assignment is None:
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                _debug_direct_dword_update_refusal_8616(
                    "low_word_upper_window_non_assignment",
                    statements[candidate_index],
                    candidate_index=candidate_index,
                )
            return None
        identity = _direct_global_lvalue_identity_8616(assignment.lhs)
        if identity is None:
            continue
        addr, width = identity
        addr &= 0xFFFF
        if addr == (low_addr & 0xFFFF):
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                _debug_direct_dword_update_refusal_8616(
                    "low_word_upper_window_low_rewrite",
                    statements[candidate_index],
                    candidate_index=candidate_index,
                    addr=f"{addr:#x}",
                    width=width,
                )
            return None
        if addr == upper_addr and width in {1, 2}:
            return candidate_index
        if _direct_global_lvalue_identity_8616(assignment.lhs) is not None:
            return None
    return None


def _debug_direct_dword_update_refusal_8616(reason: str, stmt: object, **fields: object) -> None:
    if not os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        return
    rendered = _debug_c_repr_8616(stmt)
    if "clPause" not in rendered and "mem_0132" not in rendered and "mem_0134" not in rendered:
        return
    extras = " ".join(f"{key}={value}" for key, value in sorted(fields.items()))
    log.warning("[seg-global-dword-update] refused reason=%s %s stmt=%s", reason, extras, rendered)


def _debug_c_repr_8616(node: object) -> str:
    rendered = type(node).__name__ if node is not None else "None"
    with contextlib.suppress(Exception):
        if node is None:
            return rendered
        # Dynamic boundary: angr codegen nodes expose c_repr() at runtime.
        render = getattr(node, "c_repr", None)
        if callable(render):
            rendered = str(render())
    return rendered


def _direct_global_dword_update_high_byte_window_8616(
    statements: list[object],
    index: int,
    low_addr: int,
) -> tuple[int, int] | None:
    high_low_addr = (low_addr + 2) & 0xFFFF
    high_high_addr = (low_addr + 3) & 0xFFFF
    high_low_index: int | None = None
    max_index = min(len(statements), index + 96)
    for candidate_index in range(index + 1, max_index):
        assignment = _assignment_statement_8616(statements[candidate_index])
        if assignment is None:
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                _debug_direct_dword_update_refusal_8616(
                    "window_non_assignment",
                    statements[candidate_index],
                    candidate_index=candidate_index,
                )
            return None
        identity = _direct_global_lvalue_identity_8616(assignment.lhs)
        if identity is None:
            continue
        addr, width = identity
        addr &= 0xFFFF
        if addr == (low_addr & 0xFFFF):
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                _debug_direct_dword_update_refusal_8616(
                    "window_low_rewrite",
                    statements[candidate_index],
                    candidate_index=candidate_index,
                    addr=f"{addr:#x}",
                    width=width,
                )
            return None
        if width != 1:
            continue
        if addr == high_low_addr:
            high_low_index = candidate_index
            continue
        if addr == high_high_addr:
            return (high_low_index, candidate_index) if high_low_index is not None else None
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        _debug_direct_dword_update_refusal_8616(
            "window_exhausted",
            statements[index],
            high_low_index=high_low_index,
            max_index=max_index,
        )
    return None


def _direct_global_dword_update_removable_window_end_8616(statements: list, high_high_index: int) -> int:
    last_index = high_high_index
    # MS C 16-bit arithmetic commonly emits a long, pure flag-reconstruction
    # suffix after a split dword update.  The later liveness gate below proves
    # these carriers do not escape before we remove them.
    max_index = min(len(statements), high_high_index + 160)
    for candidate_index in range(high_high_index + 1, max_index):
        assignment = _assignment_statement_8616(statements[candidate_index])
        if assignment is None:
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                log.warning(
                    "[seg-global-dword-update] removable-window stop non-assignment index=%d stmt=%s",
                    candidate_index,
                    _debug_c_repr_8616(statements[candidate_index]),
                )
            break
        if _direct_global_lvalue_identity_8616(assignment.lhs) is not None:
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                log.warning(
                    "[seg-global-dword-update] removable-window stop direct-global-lhs index=%d stmt=%s",
                    candidate_index,
                    _debug_c_repr_8616(statements[candidate_index]),
                )
            break
        if not _copy_keys_8616(assignment.lhs):
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                log.warning(
                    "[seg-global-dword-update] removable-window stop untracked-lhs index=%d stmt=%s",
                    candidate_index,
                    _debug_c_repr_8616(statements[candidate_index]),
                )
            break
        if _rhs_has_obvious_side_effect_8616(assignment.rhs):
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                log.warning(
                    "[seg-global-dword-update] removable-window stop side-effect index=%d stmt=%s",
                    candidate_index,
                    _debug_c_repr_8616(statements[candidate_index]),
                )
            break
        last_index = candidate_index
    return last_index


def _direct_global_dword_update_gap_is_removable_8616(
    _root: CStatements,
    statements: list,
    first_index: int,
    last_index: int,
) -> bool:
    consumed = statements[first_index : last_index + 1]
    consumed_ids = {id(stmt) for stmt in consumed}
    for stmt in consumed:
        consumed_ids.update(id(child) for child in _iter_c_nodes_deep_8616(stmt))
    assigned_keys: set[object] = set()
    for stmt in statements[first_index + 1 : last_index]:
        assignment = _assignment_statement_8616(stmt)
        if assignment is None:
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                log.warning("[seg-global-dword-update] gap non-assignment stmt=%s", _debug_c_repr_8616(stmt))
            return False
        lhs = assignment.lhs
        if _direct_global_lvalue_identity_8616(lhs) is not None:
            continue
        rhs = assignment.rhs
        if _same_c_expression_8616(lhs, rhs) or _same_segment_pointer_helper_self_assignment_8616(lhs, rhs):
            continue
        keys = _copy_keys_8616(lhs)
        if not keys or _rhs_has_obvious_side_effect_8616(rhs):
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                log.warning(
                    "[seg-global-dword-update] gap non-removable keys=%r side_effect=%s stmt=%s",
                    keys,
                    _rhs_has_obvious_side_effect_8616(rhs),
                    _debug_c_repr_8616(stmt),
                )
            return False
        assigned_keys.update(keys)
    for key in assigned_keys:
        if _copy_key_used_outside_ids_in_statement_list_8616(statements, consumed_ids, key):
            if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
                log.warning("[seg-global-dword-update] gap live key=%r", key)
            return False
    return True


def _same_segment_pointer_helper_self_assignment_8616(lhs: object, rhs: object) -> bool:
    if not isinstance(lhs, CFunctionCall) or not isinstance(rhs, CFunctionCall):
        return False
    helper_names = {helper.helper_name for helper in SegmentPointerHelper8616}
    lhs_name = (_cfunction_call_name_8616(lhs) or "").upper()
    rhs_name = (_cfunction_call_name_8616(rhs) or "").upper()
    if lhs_name != rhs_name or lhs_name not in helper_names:
        return False
    lhs_args = tuple(lhs.args or ())
    rhs_args = tuple(rhs.args or ())
    if len(lhs_args) != len(rhs_args):
        return False
    return all(
        _same_segment_pointer_helper_arg_8616(lhs_arg, rhs_arg)
        for lhs_arg, rhs_arg in zip(lhs_args, rhs_args, strict=True)
    )


def _same_segment_pointer_helper_arg_8616(lhs: object, rhs: object) -> bool:
    if _same_c_expression_8616(lhs, rhs):
        return True
    lhs_keys = _copy_keys_8616(lhs)
    rhs_keys = _copy_keys_8616(rhs)
    return bool(lhs_keys) and lhs_keys == rhs_keys


def _remove_segment_pointer_helper_self_assignments_8616(
    root: CStatements,
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            index = 0
            while index < len(statements):
                assignment = _assignment_statement_8616(statements[index])
                if assignment is not None and _same_segment_pointer_helper_self_assignment_8616(
                    assignment.lhs,
                    assignment.rhs,
                ):
                    del statements[index]
                    stats.direct_symbol_segment_pointer_self_assignment_removed_count += 1
                    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
                    changed = True
                    continue
                process_statements(statements[index])
                index += 1
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _materialize_direct_global_word_store_pairs_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            copies: dict[CopyKey8616, object] = {}
            index = 0
            while index + 1 < len(statements):
                replacement = _match_direct_global_word_store_pair_8616(
                    statements[index],
                    statements[index + 1],
                    codegen,
                    direct_by_offset,
                    direct_update_by_offset,
                    stats,
                    copies,
                )
                if replacement is None:
                    process_statements(statements[index])
                    _record_assignment_copy_8616(statements[index], copies)
                    index += 1
                    continue
                statements[index] = replacement
                del statements[index + 1]
                changed = True
                continue
            if index < len(statements):
                process_statements(statements[index])
                _record_assignment_copy_8616(statements[index], copies)
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _materialize_direct_global_dword_store_pairs_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_call_return_by_offset: dict[tuple[int, int], list[DirectGlobalCallReturnStoreEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            index = 0
            while index + 1 < len(statements):
                match = _match_direct_global_dword_store_pair_8616(
                    statements[index - 1] if index > 0 else None,
                    statements[index],
                    statements[index + 1],
                    codegen,
                    direct_by_offset,
                    direct_call_return_by_offset,
                    stats,
                )
                if match is None:
                    process_statements(statements[index])
                    index += 1
                    continue
                replacement, consume_previous = match
                if consume_previous and index > 0:
                    statements[index - 1] = replacement
                    del statements[index + 1]
                    del statements[index]
                    index = max(index - 1, 0)
                    changed = True
                    continue
                statements[index] = replacement
                del statements[index + 1]
                changed = True
                continue
            if index < len(statements):
                process_statements(statements[index])
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)
        if type(node).__name__ == "CSwitchCase":
            for body in _codegen_switch_case_bodies_8616(node):
                process_statements(body)
            default = getattr(node, "default", None)
            if default is not None:
                process_statements(default)

    process_statements(root)
    return changed


def _match_direct_global_dword_store_pair_8616(
    previous_stmt: object,
    low_stmt: object,
    high_stmt: object,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_call_return_by_offset: dict[tuple[int, int], list[DirectGlobalCallReturnStoreEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
) -> DwordStorePairMatch8616:
    low_assignment = _assignment_statement_8616(low_stmt)
    high_assignment = _assignment_statement_8616(high_stmt)
    if low_assignment is None or high_assignment is None:
        return None
    low_lhs = low_assignment.lhs
    high_lhs = high_assignment.lhs
    low_identity = _direct_global_lvalue_identity_8616(low_lhs)
    high_identity = _direct_global_lvalue_identity_8616(high_lhs)
    if low_identity is None or high_identity is None:
        return None
    low_addr, low_width = low_identity
    high_addr, high_width = high_identity
    if low_width != 2 or high_width != 2 or ((low_addr + 2) & 0xFFFF) != (high_addr & 0xFFFF):
        return None
    low_ref = direct_by_offset.get((low_addr & 0xFFFF, 2))
    high_ref = direct_by_offset.get((high_addr & 0xFFFF, 2))
    dword_ref = direct_by_offset.get((low_addr & 0xFFFF, 4))
    if low_ref is None or high_ref is None or dword_ref is None:
        return None
    if _sanitize_identifier_8616(low_ref.name) != _sanitize_identifier_8616(high_ref.name):
        return None
    if _sanitize_identifier_8616(low_ref.name) != _sanitize_identifier_8616(dword_ref.name):
        return None
    if int(low_ref.relative_disp) != 0 or int(high_ref.relative_disp) != 2:
        return None
    lhs = _make_direct_global_symbol_expr_8616(codegen, dword_ref, 4)
    consume_previous = False
    call_return_evidence = None
    rhs = _make_wide_call_return_dword_store_rhs_8616(
        codegen,
        previous_stmt,
        low_assignment.rhs,
        high_assignment.rhs,
    )
    if rhs is not None:
        consume_previous = True
    else:
        call_return_evidence = _direct_global_call_return_store_evidence_for_pair_8616(
            direct_call_return_by_offset.get((low_addr & 0xFFFF, 4), ()),
            low_assignment,
            high_assignment,
        )
        rhs = _make_direct_global_call_return_store_rhs_8616(
            codegen,
            call_return_evidence,
            low_assignment.rhs,
            high_assignment.rhs,
        )
    if rhs is not None and call_return_evidence is not None:
        consume_previous = _direct_global_call_return_previous_call_matches_8616(
            previous_stmt,
            call_return_evidence,
        )
        stats.direct_symbol_call_return_materialized_count += 1
    if rhs is None:
        rhs = _make_direct_global_dword_store_rhs_8616(
            codegen,
            low_assignment.rhs,
            high_assignment.rhs,
        )
    if lhs is None or rhs is None:
        return None
    stats.direct_symbol_materialized_count += 1
    stats.direct_symbol_store_materialized_count += 1
    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
    return CAssignment(lhs, rhs, codegen=codegen, tags=low_assignment.tags), consume_previous


def _make_wide_call_return_dword_store_rhs_8616(
    codegen: CodegenBoundary8616,
    previous_stmt: object,
    low_rhs: object,
    high_rhs: object,
) -> CExpression | None:
    previous_assignment = _assignment_statement_8616(previous_stmt)
    if previous_assignment is None:
        return None
    previous_lhs = previous_assignment.lhs
    previous_rhs = previous_assignment.rhs
    if not isinstance(previous_rhs, CFunctionCall):
        return None
    if _cvariable_key_8616(previous_lhs) is None or _cvariable_key_8616(previous_lhs) != _cvariable_key_8616(low_rhs):
        return None
    high_reg_name = _register_name_for_dword_high_half_8616(codegen, high_rhs)
    if high_reg_name not in {"dx", "edx"}:
        return None
    return previous_rhs


def _direct_global_call_return_store_evidence_for_pair_8616(
    candidates: tuple[DirectGlobalCallReturnStoreEvidence8616, ...] | list[DirectGlobalCallReturnStoreEvidence8616],
    low_assignment: object,
    high_assignment: object,
) -> DirectGlobalCallReturnStoreEvidence8616 | None:
    if not candidates:
        return None
    low_ins_addr = _statement_ins_addr_8616(low_assignment)
    high_ins_addr = _statement_ins_addr_8616(high_assignment)
    if low_ins_addr is None and high_ins_addr is None:
        return candidates[0] if len(candidates) == 1 else None
    for candidate in candidates:
        if candidate.width != 4 or candidate.high_store_ins_addr is None:
            continue
        if low_ins_addr is not None and low_ins_addr != candidate.low_store_ins_addr:
            continue
        if high_ins_addr is not None and high_ins_addr != candidate.high_store_ins_addr:
            continue
        return candidate
    return None


def _statement_ins_addr_8616(stmt: object) -> int | None:
    """Return a C AST statement instruction address from dynamic angr codegen tags.

    Dynamic boundary: angr codegen statement nodes expose ``tags`` at runtime.
    """

    tags = getattr(stmt, "tags", None)
    if not isinstance(tags, dict):
        return None
    ins_addr = tags.get("ins_addr")
    return int(ins_addr) if isinstance(ins_addr, int) else None


def _cfunction_call_name_8616(node: object) -> str | None:
    """Return a call name from dynamic angr codegen call metadata.

    Dynamic boundary: angr codegen call nodes expose callee metadata by runtime surface.
    """

    if not isinstance(node, CFunctionCall):
        return None
    raw_name = node.callee_target
    if not isinstance(raw_name, str):
        raw_name = getattr(node.callee_func, "name", None)
    if not isinstance(raw_name, str):
        return None
    name = raw_name.strip().lstrip("_")
    return name or None


def _direct_global_call_return_previous_call_matches_8616(
    previous_stmt: object,
    evidence: DirectGlobalCallReturnStoreEvidence8616 | None,
) -> bool:
    if evidence is None:
        return False
    previous_assignment = _assignment_statement_8616(previous_stmt)
    if previous_assignment is None:
        return False
    previous_rhs = previous_assignment.rhs
    call_name = _cfunction_call_name_8616(previous_rhs)
    if call_name is None or call_name != evidence.source_call_name:
        return False
    previous_ins_addr = _statement_ins_addr_8616(previous_stmt)
    if previous_ins_addr is not None and previous_ins_addr != evidence.source_call_ins_addr:
        return False
    return True


def _remove_materialized_direct_global_call_return_carriers_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    evidence_items: tuple[DirectGlobalCallReturnStoreEvidence8616, ...],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    """Remove exact call/store carriers consumed by call-return materialization."""

    active_evidence = _materialized_direct_global_call_return_evidence_8616(root, evidence_items)
    if not active_evidence:
        return False
    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            kept = []
            for stmt in statements:
                carrier_key = _direct_global_call_return_carrier_key_8616(root, stmt, active_evidence)
                if carrier_key is not None:
                    changed = True
                    continue
                if _direct_global_call_return_stale_recombine_8616(codegen, stmt, active_evidence):
                    changed = True
                    continue
                consumed_store = _direct_global_call_return_consumed_store_8616(codegen, stmt, active_evidence)
                if consumed_store is not None:
                    stats.direct_symbol_call_return_carrier_removed_count += 1
                    if consumed_store.width in {1, 2}:
                        stats.direct_symbol_call_return_materialized_count += 1
                    changed = True
                    continue
                process_statements(stmt)
                kept.append(stmt)
            if changed:
                statements[:] = kept
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)

    process_statements(root)
    return changed


def _direct_global_call_return_consumed_store_8616(
    codegen: CodegenBoundary8616,
    stmt: object,
    evidence_items: tuple[DirectGlobalCallReturnStoreEvidence8616, ...],
) -> DirectGlobalCallReturnStoreEvidence8616 | None:
    """Match an exact pure AX/DX store already represented by a canonical call assignment."""

    assignment = _assignment_statement_8616(stmt)
    if assignment is None or not isinstance(assignment.rhs, CVariable):
        return None
    ins_addr = _statement_ins_addr_8616(stmt)
    lhs_identity = _direct_global_lvalue_identity_8616(assignment.lhs)
    project = _codegen_project_optional_8616(codegen)
    if ins_addr is None or lhs_identity is None or project is None:
        return None
    register_name = _cvariable_register_name_8616(project, assignment.rhs)
    for evidence in evidence_items:
        offset = evidence.offset & 0xFFFF
        if (
            evidence.width == 1
            and ins_addr == evidence.low_store_ins_addr
            and lhs_identity == (offset, 1)
            and register_name == "al"
        ):
            return evidence
        if (
            evidence.width == 2
            and ins_addr == evidence.low_store_ins_addr
            and lhs_identity == (offset, 2)
            and register_name in {"ax", "eax"}
        ):
            return evidence
        if evidence.width != 4:
            continue
        if (
            ins_addr == evidence.low_store_ins_addr
            and lhs_identity == (offset, 2)
            and register_name in {"ax", "eax"}
        ):
            return evidence
        if (
            evidence.high_store_ins_addr is not None
            and ins_addr == evidence.high_store_ins_addr
            and lhs_identity == ((offset + 2) & 0xFFFF, 2)
            and register_name in {"dx", "edx"}
        ):
            return evidence
    return None


def _direct_global_call_return_stale_recombine_8616(
    codegen: CodegenBoundary8616,
    stmt: object,
    evidence_items: tuple[DirectGlobalCallReturnStoreEvidence8616, ...],
) -> bool:
    assignment = _assignment_statement_8616(stmt)
    if assignment is None:
        return False
    lhs_identity = _direct_global_lvalue_identity_8616(assignment.lhs)
    if lhs_identity is None:
        return False
    if not any((item.offset & 0xFFFF, item.width) == (lhs_identity[0] & 0xFFFF, lhs_identity[1]) for item in evidence_items):
        return False
    return _rhs_is_dx_ax_return_recombine_8616(codegen, assignment.rhs)


def _rhs_is_dx_ax_return_recombine_8616(codegen: CodegenBoundary8616, rhs: object) -> bool:
    if not isinstance(rhs, CBinaryOp) or rhs.op != "Or":
        return False
    lhs = rhs.lhs
    rhs_node = rhs.rhs
    if _register_name_for_dword_low_half_8616(codegen, lhs) in {"ax", "eax"} and _rhs_is_dx_shift_16_8616(
        codegen,
        rhs_node,
    ):
        return True
    if _register_name_for_dword_low_half_8616(codegen, rhs_node) in {"ax", "eax"} and _rhs_is_dx_shift_16_8616(
        codegen,
        lhs,
    ):
        return True
    return False


def _rhs_is_dx_shift_16_8616(codegen: CodegenBoundary8616, node: object) -> bool:
    if not isinstance(node, CBinaryOp) or node.op not in {"Shl", "LShift"}:
        return False
    if _constant_int_8616(node.rhs) != 16:
        return False
    return _register_name_for_dword_high_half_8616(codegen, node.lhs) in {"dx", "edx"}


def _materialized_direct_global_call_return_evidence_8616(
    root: CStatements,
    evidence_items: tuple[DirectGlobalCallReturnStoreEvidence8616, ...],
) -> tuple[DirectGlobalCallReturnStoreEvidence8616, ...]:
    if not evidence_items:
        return ()
    by_key = {(item.offset & 0xFFFF, item.width, item.source_call_name): item for item in evidence_items}
    active: list[DirectGlobalCallReturnStoreEvidence8616] = []
    for node in _iter_c_nodes_deep_8616(root):
        assignment = _assignment_statement_8616(node)
        if assignment is None:
            continue
        lhs_identity = _direct_global_lvalue_identity_8616(assignment.lhs)
        if lhs_identity is None:
            continue
        rhs_name = _cfunction_call_name_8616(assignment.rhs)
        if rhs_name is None:
            continue
        item = by_key.get((lhs_identity[0] & 0xFFFF, lhs_identity[1], rhs_name))
        if item is not None:
            active.append(item)
    return tuple(active)


def _direct_global_call_return_carrier_key_8616(
    root: CStatements,
    stmt: object,
    evidence_items: tuple[DirectGlobalCallReturnStoreEvidence8616, ...],
) -> str | None:
    assignment = _assignment_statement_8616(stmt)
    if assignment is None:
        return None
    rhs_name = _cfunction_call_name_8616(assignment.rhs)
    if rhs_name is None:
        return None
    ins_addr = _statement_ins_addr_8616(stmt)
    matching_evidence = tuple(
        item
        for item in evidence_items
        if item.source_call_name == rhs_name
        and (ins_addr is None or item.source_call_ins_addr == ins_addr)
    )
    if not matching_evidence:
        return None
    lhs_identity = _direct_global_lvalue_identity_8616(assignment.lhs)
    if lhs_identity is not None and any(
        (item.offset & 0xFFFF, item.width) == lhs_identity for item in matching_evidence
    ):
        return None
    lhs_key = _cvariable_key_8616(assignment.lhs)
    if lhs_key is None or _cvariable_key_used_outside_statement_8616(root, stmt, lhs_key):
        return None
    return lhs_key


def _cvariable_key_used_outside_statement_8616(root: CStatements, skip_stmt: object, key: str) -> bool:
    skip_ids = {id(skip_stmt)}
    skip_ids.update(id(child) for child in _iter_c_nodes_deep_8616(skip_stmt))
    return _cvariable_key_used_outside_ids_8616(root, skip_ids, key)


def _cvariable_key_used_outside_ids_8616(root: CStatements, skip_ids: set[int], key: str) -> bool:
    for node in _iter_c_nodes_deep_8616(root):
        if id(node) in skip_ids:
            continue
        if _cvariable_key_8616(node) == key:
            return True
    return False


def _copy_key_used_outside_ids_8616(root: CStatements, skip_ids: set[int], key: object) -> bool:
    debug_enabled = bool(os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"))
    for node in _iter_c_nodes_deep_8616(root):
        if id(node) in skip_ids:
            continue
        if key in _copy_keys_8616(node):
            if debug_enabled:
                log.warning("[seg-global-dword-update] outside live key=%r node=%s", key, _debug_c_repr_8616(node))
            return True
    return False


def _copy_key_used_outside_ids_in_statement_list_8616(statements: list, skip_ids: set[int], key: object) -> bool:
    debug_enabled = bool(os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"))
    for stmt in statements:
        for node in _iter_c_nodes_deep_8616(stmt):
            if id(node) in skip_ids:
                continue
            if key in _copy_keys_8616(node):
                if debug_enabled:
                    log.warning(
                        "[seg-global-dword-update] outside live key=%r node=%s",
                        key,
                        _debug_c_repr_8616(node),
                    )
                return True
    return False


def _make_direct_global_call_return_store_rhs_8616(
    codegen: CodegenBoundary8616,
    evidence: DirectGlobalCallReturnStoreEvidence8616 | None,
    low_rhs: object,
    high_rhs: object,
) -> CExpression | None:
    if evidence is None:
        return None
    if _register_name_for_dword_low_half_8616(codegen, low_rhs) not in {"ax", "eax"}:
        return None
    if _register_name_for_dword_high_half_8616(codegen, high_rhs) not in {"dx", "edx"}:
        return None
    return CFunctionCall(evidence.source_call_name, None, [], codegen=codegen)


def _register_name_for_dword_low_half_8616(codegen: CodegenBoundary8616, expr: object) -> str | None:
    return _register_name_for_dword_half_8616(codegen, expr)


def _register_name_for_dword_high_half_8616(codegen: CodegenBoundary8616, expr: object) -> str | None:
    return _register_name_for_dword_half_8616(codegen, expr)


def _register_name_for_dword_half_8616(codegen: CodegenBoundary8616, expr: object) -> str | None:
    if not isinstance(expr, CVariable):
        return None
    project = _codegen_project_optional_8616(codegen)
    if project is not None:
        reg_name = _cvariable_register_name_8616(project, expr)
        if isinstance(reg_name, str) and reg_name:
            return reg_name.lower()
    variable = expr.variable
    raw_name = expr.name or variable.name
    if isinstance(raw_name, str) and raw_name:
        return raw_name.lower()
    if isinstance(variable, SimRegisterVariable):
        reg = variable.reg
        return f"reg:{reg}" if isinstance(reg, int) else None
    return None


def _make_direct_global_dword_store_rhs_8616(
    codegen: CodegenBoundary8616,
    low_rhs: object,
    high_rhs: object,
) -> object | None:
    low_constant = _constant_int_8616(low_rhs)
    high_constant = _constant_int_8616(high_rhs)
    if low_constant is not None and high_constant is not None:
        value = (int(low_constant) & 0xFFFF) | ((int(high_constant) & 0xFFFF) << 16)
        return CConstant(value, SimTypeLong(False), codegen=codegen)
    if high_constant == 0:
        return low_rhs
    high_shifted = CBinaryOp(
        "Shl",
        high_rhs,
        CConstant(16, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    return CBinaryOp("Or", low_rhs, high_shifted, codegen=codegen)


def _match_direct_global_word_store_pair_8616(
    low_stmt: object,
    high_stmt: object,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    direct_update_by_offset: dict[tuple[int, int], list[DirectGlobalUpdateEvidence8616]],
    stats: SegmentedGlobalLoadStats8616,
    copies: dict[CopyKey8616, object] | None = None,
) -> CAssignment | None:
    if copies is None:
        copies = {}
    low_assignment = _assignment_statement_8616(low_stmt)
    high_assignment = _assignment_statement_8616(high_stmt)
    if low_assignment is None or high_assignment is None:
        _debug_direct_store_refusal_8616("not_assignment_pair", low_stmt, high_stmt)
        return None
    low_lhs = low_assignment.lhs
    high_lhs = high_assignment.lhs
    low_identity = _direct_global_lvalue_identity_8616(low_lhs)
    high_identity = _direct_global_lvalue_identity_8616(high_lhs)
    if low_identity is None or high_identity is None:
        _debug_direct_store_refusal_8616(
            "lvalue_shape",
            low_stmt,
            high_stmt,
            low_lvalue=_debug_lvalue_8616(low_lhs),
            high_lvalue=_debug_lvalue_8616(high_lhs),
        )
        return None
    low_addr, low_width = low_identity
    high_addr, high_width = high_identity
    if low_width != 1 or high_width != 1 or ((low_addr + 1) & 0xFFFF) != (high_addr & 0xFFFF):
        _debug_direct_store_refusal_8616(
            "byte_sequence",
            low_stmt,
            high_stmt,
            low_addr=f"{low_addr:#x}",
            low_width=low_width,
            high_addr=f"{high_addr:#x}",
            high_width=high_width,
        )
        return None
    ref = direct_by_offset.get((low_addr & 0xFFFF, 2))
    if ref is None:
        _debug_direct_store_refusal_8616(
            "no_direct_ref",
            low_stmt,
            high_stmt,
            low_addr=f"{low_addr:#x}",
            evidence_keys=tuple(sorted(direct_by_offset)),
        )
        return None
    normalized_rhs = _direct_global_word_update_rhs_from_byte_pair_8616(
        codegen,
        ref,
        low_assignment.rhs,
        high_assignment.rhs,
        direct_update_by_offset.get((low_addr & 0xFFFF, 2), []),
        copies,
    )
    if normalized_rhs is not None:
        lhs = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
        if lhs is None:
            return None
        stats.direct_symbol_materialized_count += 1
        stats.direct_symbol_store_materialized_count += 1
        if (low_addr & 0xFFFF, 2) in direct_update_by_offset:
            stats.direct_symbol_update_materialized_count += 1
        stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
        return CAssignment(lhs, normalized_rhs, codegen=codegen, tags=low_assignment.tags)
    low_source = _resolve_copy_8616(low_assignment.rhs, copies)
    high_source = _resolve_copy_8616(high_assignment.rhs, copies)
    if _word_store_source_is_safe_8616(low_source) and _word_store_source_is_safe_8616(high_source):
        lhs = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
        rhs = _make_direct_global_word_store_rhs_from_byte_exprs_8616(codegen, low_source, high_source)
        if lhs is not None and rhs is not None:
            stats.direct_symbol_materialized_count += 1
            stats.direct_symbol_store_materialized_count += 1
            stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
            return CAssignment(lhs, rhs, codegen=codegen, tags=low_assignment.tags)
    low_value = _constant_int_8616(_resolve_copy_8616(low_assignment.rhs, copies))
    high_value = _constant_int_8616(_resolve_copy_8616(high_assignment.rhs, copies))
    if low_value is None or high_value is None:
        _debug_direct_store_refusal_8616(
            "rhs_shape",
            low_stmt,
            high_stmt,
            low_rhs=_debug_source_8616(low_assignment.rhs),
            high_rhs=_debug_source_8616(high_assignment.rhs),
            resolved_low=_debug_source_8616(_resolve_copy_8616(low_assignment.rhs, copies)),
            resolved_high=_debug_source_8616(_resolve_copy_8616(high_assignment.rhs, copies)),
        )
        return None
    value = (int(low_value) & 0xFF) | ((int(high_value) & 0xFF) << 8)
    lhs = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
    if lhs is None:
        return None
    rhs = CConstant(value, SimTypeShort(False), codegen=codegen)
    stats.direct_symbol_materialized_count += 1
    stats.direct_symbol_store_materialized_count += 1
    stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
    return CAssignment(lhs, rhs, codegen=codegen, tags=low_assignment.tags)


def _make_direct_global_word_store_rhs_from_byte_exprs_8616(
    codegen: CodegenBoundary8616,
    low_rhs: object,
    high_rhs: object,
) -> object:
    low_const = _constant_int_8616(low_rhs)
    high_const = _constant_int_8616(high_rhs)
    if low_const is not None and high_const is not None:
        return CConstant(((int(high_const) & 0xFF) << 8) | (int(low_const) & 0xFF), SimTypeShort(False), codegen=codegen)
    low_expr = CBinaryOp(
        "And",
        low_rhs,
        CConstant(0xFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    high_expr = CBinaryOp(
        "Shl",
        CBinaryOp(
            "And",
            high_rhs,
            CConstant(0xFF, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    return CBinaryOp("Or", low_expr, high_expr, codegen=codegen)


def _make_direct_global_store_assignment_exprs_8616(
    codegen: CodegenBoundary8616,
    ref: DirectGlobalSymbolRef8616,
    width: int,
    rhs: object,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
) -> tuple[object | None, object | None]:
    scalar_ref = _dword_scalar_ref_for_subword_ref_8616(ref, direct_by_offset)
    if scalar_ref is None:
        return _make_direct_global_symbol_expr_8616(codegen, ref, width), rhs
    scalar = _make_direct_global_symbol_expr_8616(codegen, scalar_ref, 4)
    if scalar is None:
        return None, None
    rhs = _project_direct_global_subword_refs_in_expr_8616(codegen, ref, rhs, direct_by_offset)
    merged_rhs = _make_dword_scalar_subword_store_rhs_8616(codegen, scalar, int(ref.relative_disp), rhs)
    if merged_rhs is None:
        return None, None
    return scalar, merged_rhs


def _project_direct_global_subword_refs_in_expr_8616(
    codegen: CodegenBoundary8616,
    ref: DirectGlobalSymbolRef8616,
    expr: object,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
) -> object:
    direct_expr = _make_direct_global_symbol_expr_8616(codegen, ref, int(ref.width or 2))
    projected_expr = _make_direct_global_symbol_or_projection_expr_8616(
        codegen,
        ref,
        int(ref.width or 2),
        direct_by_offset,
    )
    if direct_expr is None or projected_expr is None:
        return expr
    if _same_c_expression_8616(expr, direct_expr):
        return projected_expr

    def transform(node: object) -> object:
        if _same_c_expression_8616(node, direct_expr):
            return projected_expr
        return node

    if _replace_c_children_8616(expr, transform):
        return expr
    return expr


def _make_dword_scalar_subword_store_rhs_8616(
    codegen: CodegenBoundary8616,
    scalar: object,
    relative_disp: int,
    word_rhs: object,
) -> object | None:
    if not isinstance(word_rhs, CExpression) or _rhs_has_obvious_side_effect_8616(word_rhs):
        return None
    wide_word_rhs = CTypeCast(None, SimTypeLong(False), word_rhs, codegen=codegen)
    word_value = CBinaryOp(
        "And",
        wide_word_rhs,
        CConstant(0xFFFF, SimTypeLong(False), codegen=codegen),
        codegen=codegen,
    )
    if int(relative_disp) == 0:
        preserved = CBinaryOp(
            "And",
            scalar,
            CConstant(0xFFFF0000, SimTypeLong(False), codegen=codegen),
            codegen=codegen,
        )
        return CBinaryOp("Or", preserved, word_value, codegen=codegen)
    if int(relative_disp) == 2:
        preserved = CBinaryOp(
            "And",
            scalar,
            CConstant(0xFFFF, SimTypeLong(False), codegen=codegen),
            codegen=codegen,
        )
        shifted = CBinaryOp(
            "Shl",
            word_value,
            CConstant(16, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        return CBinaryOp("Or", preserved, shifted, codegen=codegen)
    return None


def _direct_global_word_update_rhs_from_byte_pair_8616(
    codegen: CodegenBoundary8616,
    ref: DirectGlobalSymbolRef8616,
    low_rhs: object,
    high_rhs: object,
    update_evidence: tuple[DirectGlobalUpdateEvidence8616, ...] | list[DirectGlobalUpdateEvidence8616],
    copies: dict[CopyKey8616, object] | None = None,
) -> object | None:
    word_source = _word_source_for_byte_pair_store_8616(high_rhs, low_rhs, copies or {})
    if word_source is None:
        return None
    word_constant = _constant_int_8616(word_source)
    if word_constant is not None:
        return CConstant(int(word_constant) & 0xFFFF, SimTypeShort(False), codegen=codegen)
    normalized = _normalize_direct_global_word_update_rhs_8616(codegen, ref, word_source)
    if normalized is not None:
        return normalized
    source_delta = _direct_global_word_update_expr_delta_8616(word_source)
    matched_update = _direct_global_update_evidence_for_delta_8616(update_evidence, source_delta)
    if matched_update is not None:
        return _direct_global_delta_rhs_8616(codegen, ref, matched_update.delta)
    if _word_store_source_is_safe_8616(word_source):
        return word_source
    return None


def _direct_global_word_update_expr_delta_8616(expr: object) -> int | None:
    if not isinstance(expr, CBinaryOp) or expr.op not in {"Add", "Sub"}:
        return None
    rhs_const = _constant_int_8616(expr.rhs)
    if rhs_const is None:
        return None
    delta = int(rhs_const)
    return delta if expr.op == "Add" else -delta


def _direct_global_update_evidence_for_delta_8616(
    candidates: tuple[DirectGlobalUpdateEvidence8616, ...] | list[DirectGlobalUpdateEvidence8616],
    delta: int | None,
) -> DirectGlobalUpdateEvidence8616 | None:
    if delta is None:
        return None
    for candidate in candidates:
        if int(candidate.delta) == int(delta):
            return candidate
    return None


def _direct_global_store_lvalue_ref_8616(
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    addr: int,
    width: int,
) -> DirectGlobalSymbolRef8616 | None:
    ref = direct_by_offset.get((addr & 0xFFFF, width))
    if ref is not None:
        return ref
    if width != 1:
        return None
    word_ref = direct_by_offset.get((addr & 0xFFFF, 2))
    if word_ref is None or int(word_ref.relative_disp) != 0:
        return None
    return word_ref


def _materialize_direct_global_single_byte_stores_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False
    for stmt in _iter_c_nodes_deep_8616(root):
        assignment = _assignment_statement_8616(stmt)
        if assignment is None:
            continue
        lhs_identity = _direct_global_lvalue_identity_8616(assignment.lhs)
        if lhs_identity is None:
            continue
        addr, width = lhs_identity
        if width != 1:
            continue
        ref = _direct_global_ref_covering_byte_8616(direct_by_offset, addr)
        if ref is None or int(ref.width or 0) != 2:
            continue
        byte_delta = (int(addr) - int(ref.offset)) & 0xFFFF
        if byte_delta not in {0, 1}:
            continue
        base_expr = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
        if not isinstance(base_expr, CExpression):
            continue
        rhs = _make_direct_global_single_byte_store_rhs_8616(
            codegen,
            base_expr,
            assignment.rhs,
            byte_delta,
        )
        if rhs is None:
            continue
        assignment.lhs = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
        assignment.rhs = rhs
        stats.direct_symbol_materialized_count += 1
        stats.direct_symbol_store_materialized_count += 1
        stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
        changed = True
    return changed


def _make_direct_global_single_byte_store_rhs_8616(
    codegen: CodegenBoundary8616,
    base_expr: CExpression,
    byte_rhs: object,
    byte_delta: int,
) -> object | None:
    if not isinstance(byte_rhs, CExpression) or _rhs_has_obvious_side_effect_8616(byte_rhs):
        return None
    byte_value = CBinaryOp(
        "And",
        byte_rhs,
        CConstant(0xFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    if byte_delta == 0:
        preserved = CBinaryOp(
            "And",
            base_expr,
            CConstant(0xFF00, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        return CBinaryOp("Or", preserved, byte_value, codegen=codegen)
    preserved = CBinaryOp(
        "And",
        base_expr,
        CConstant(0x00FF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    shifted = CBinaryOp(
        "Shl",
        byte_value,
        CConstant(8, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    return CBinaryOp("Or", preserved, shifted, codegen=codegen)


def _direct_global_ref_covering_byte_8616(
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    addr: int,
) -> DirectGlobalSymbolRef8616 | None:
    addr &= 0xFFFF
    candidates = []
    for ref in direct_by_offset.values():
        ref_offset = int(ref.offset) & 0xFFFF
        ref_width = int(ref.width or 0)
        if ref_width <= 1:
            continue
        if ref_offset <= addr < ref_offset + ref_width:
            candidates.append(ref)
    if not candidates:
        for ref in direct_by_offset.values():
            ref_offset = int(ref.offset) & 0xFFFF
            ref_width = int(ref.width or 0)
            if ref_width <= 1:
                continue
            if 0 <= ((addr - ref_offset) & 0xFFFF) < ref_width:
                candidates.append(ref)
    if not candidates:
        return None
    candidates.sort(key=lambda item: int(item.width or 0))
    return candidates[0]


def _direct_global_delta_rhs_8616(
    codegen: CodegenBoundary8616,
    ref: DirectGlobalSymbolRef8616,
    delta: int,
) -> CExpression | None:
    direct_expr = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
    if direct_expr is None or delta == 0:
        return None
    op = "Add" if delta > 0 else "Sub"
    return CBinaryOp(op, direct_expr, CConstant(abs(delta), SimTypeShort(False), codegen=codegen), codegen=codegen)


def _normalize_direct_global_word_update_rhs_8616(
    codegen: CodegenBoundary8616,
    ref: DirectGlobalSymbolRef8616,
    expr: object,
) -> object | None:
    direct_expr = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
    if direct_expr is None:
        return None
    identity = _direct_global_lvalue_identity_8616(expr)
    if identity == (ref.offset & 0xFFFF, 2):
        return direct_expr
    if _direct_global_word_byte_pair_source_8616(expr, ref):
        return direct_expr
    if not isinstance(expr, CBinaryOp) or expr.op not in {"Add", "Sub"}:
        return None
    rhs_const = _constant_int_8616(expr.rhs)
    if rhs_const is not None and _direct_global_word_byte_pair_source_8616(expr.lhs, ref):
        return CBinaryOp(expr.op, direct_expr, expr.rhs, codegen=codegen)
    if expr.op == "Add":
        lhs_const = _constant_int_8616(expr.lhs)
        if lhs_const is not None and _direct_global_word_byte_pair_source_8616(expr.rhs, ref):
            return CBinaryOp("Add", direct_expr, expr.lhs, codegen=codegen)
    return None


def _direct_global_word_byte_pair_source_8616(
    expr: object,
    ref: DirectGlobalSymbolRef8616,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> bool:
    expr = _resolve_dirty_global_carrier_8616(expr, dirty_assignments)
    if not isinstance(expr, CBinaryOp) or expr.op not in {"Add", "Or"}:
        return False
    lhs = expr.lhs
    rhs = expr.rhs
    matched = (
        _is_direct_global_low_byte_ref_8616(lhs, ref, dirty_assignments=dirty_assignments)
        and _is_direct_global_shifted_high_byte_ref_8616(rhs, ref, dirty_assignments=dirty_assignments)
    ) or (
        _is_direct_global_low_byte_ref_8616(rhs, ref, dirty_assignments=dirty_assignments)
        and _is_direct_global_shifted_high_byte_ref_8616(lhs, ref, dirty_assignments=dirty_assignments)
    )
    _debug_direct_global_load_pair_candidate_8616(
        "word",
        expr,
        ref,
        matched,
        dirty_assignments=dirty_assignments,
    )
    return matched


def _is_direct_global_low_byte_ref_8616(
    expr: object,
    ref: DirectGlobalSymbolRef8616,
    *,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> bool:
    identity = _direct_global_lvalue_identity_8616(expr, dirty_assignments=dirty_assignments)
    return identity == (ref.offset & 0xFFFF, 1)


def _is_direct_global_shifted_high_byte_ref_8616(
    expr: object,
    ref: DirectGlobalSymbolRef8616,
    *,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> bool:
    expr = _resolve_dirty_global_carrier_8616(expr, dirty_assignments)
    if not isinstance(expr, CBinaryOp):
        return False
    lhs = expr.lhs
    rhs = expr.rhs
    identity = _direct_global_lvalue_identity_8616(lhs, dirty_assignments=dirty_assignments)
    if identity != (((ref.offset + 1) & 0xFFFF), 1):
        return False
    if expr.op == "Shl":
        return _constant_int_8616(rhs) == 8
    if expr.op == "Mul":
        return _constant_int_8616(rhs) == 0x100
    return False


def _direct_global_dword_word_pair_source_8616(
    expr: object,
    ref: DirectGlobalSymbolRef8616,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> bool:
    expr = _resolve_dirty_global_carrier_8616(expr, dirty_assignments)
    if not isinstance(expr, CBinaryOp) or expr.op not in {"Add", "Or"}:
        return False
    lhs = expr.lhs
    rhs = expr.rhs
    matched = (
        _is_direct_global_low_word_ref_8616(lhs, ref, dirty_assignments=dirty_assignments)
        and _is_direct_global_shifted_high_word_ref_8616(rhs, ref, dirty_assignments=dirty_assignments)
    ) or (
        _is_direct_global_low_word_ref_8616(rhs, ref, dirty_assignments=dirty_assignments)
        and _is_direct_global_shifted_high_word_ref_8616(lhs, ref, dirty_assignments=dirty_assignments)
    )
    _debug_direct_global_load_pair_candidate_8616(
        "dword",
        expr,
        ref,
        matched,
        dirty_assignments=dirty_assignments,
    )
    return matched


def _debug_direct_global_load_pair_candidate_8616(
    kind: str,
    expr: object,
    ref: DirectGlobalSymbolRef8616,
    matched: bool,
    *,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> None:
    if not os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOAD_PAIRS"):
        return
    expr_text = _debug_c_repr_8616(expr)
    if ref.name not in {"cszMenu", "clPause"} and "mem_0160" not in expr_text and "mem_0132" not in expr_text:
        return
    lhs = expr.lhs if isinstance(expr, CBinaryOp) else None
    rhs = expr.rhs if isinstance(expr, CBinaryOp) else None
    log.warning(
        "[seg-global-load-pair] kind=%s ref=%s offset=%#x width=%d matched=%s expr=%s lhs=%s lhs_id=%r rhs=%s rhs_id=%r",
        kind,
        ref.name,
        ref.offset & 0xFFFF,
        ref.width,
        matched,
        expr_text,
        type(lhs).__name__,
        _direct_global_lvalue_identity_8616(lhs, dirty_assignments=dirty_assignments),
        type(rhs).__name__,
        _direct_global_lvalue_identity_8616(rhs, dirty_assignments=dirty_assignments),
    )


def _is_direct_global_low_word_ref_8616(
    expr: object,
    ref: DirectGlobalSymbolRef8616,
    *,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> bool:
    identity = _direct_global_lvalue_identity_8616(expr, dirty_assignments=dirty_assignments)
    return identity == (ref.offset & 0xFFFF, 2)


def _is_direct_global_shifted_high_word_ref_8616(
    expr: object,
    ref: DirectGlobalSymbolRef8616,
    *,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> bool:
    expr = _resolve_dirty_global_carrier_8616(expr, dirty_assignments)
    if not isinstance(expr, CBinaryOp):
        return False
    lhs = expr.lhs
    rhs = expr.rhs
    identity = _direct_global_lvalue_identity_8616(lhs, dirty_assignments=dirty_assignments)
    if identity != (((ref.offset + 2) & 0xFFFF), 2):
        return False
    if expr.op == "Shl":
        return _constant_int_8616(rhs) == 16
    if expr.op == "Mul":
        return _constant_int_8616(rhs) == 0x10000
    return False


def _materialize_direct_global_load_pair_expr_8616(
    codegen: CodegenBoundary8616,
    node: object,
    evidence_by_offset: dict[int, NamedGlobalEvidence8616],
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    stats: SegmentedGlobalLoadStats8616,
    *,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> object | None:
    direct_expr = _materialize_direct_ref_load_pair_expr_8616(
        codegen,
        node,
        direct_by_offset,
        stats,
        dirty_assignments=dirty_assignments,
    )
    if direct_expr is not None:
        return direct_expr
    for width, predicate in (
        (2, _direct_global_word_byte_pair_source_8616),
        (4, _direct_global_dword_word_pair_source_8616),
    ):
        for item in evidence_by_offset.values():
            if int(item.width) != width:
                continue
            ref = DirectGlobalSymbolRef8616(
                offset=item.offset & 0xFFFF,
                name=item.name,
                relative_disp=0,
                width=width,
                max_relative_disp=0,
            )
            if not predicate(node, ref, dirty_assignments):
                continue
            expr = _make_direct_global_symbol_expr_8616(codegen, ref, width)
            if expr is None:
                continue
            stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
            return expr
    return None


def _materialize_direct_ref_load_pair_expr_8616(
    codegen: CodegenBoundary8616,
    node: object,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    stats: SegmentedGlobalLoadStats8616,
    *,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> object | None:
    for (_offset, width), ref in direct_by_offset.items():
        if width == 2:
            matched = _direct_global_word_byte_pair_source_8616(node, ref, dirty_assignments)
        elif width == 4:
            matched = _direct_global_dword_word_pair_source_8616(node, ref, dirty_assignments)
        else:
            continue
        if not matched:
            continue
        expr = _make_direct_global_symbol_expr_8616(codegen, ref, width)
        if expr is None:
            continue
        stats.direct_symbol_materialized_count += 1
        stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
        return expr
    return None


def _remove_direct_global_redundant_high_byte_stores_8616(
    root: CStatements,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False

    def process_statements(node: object) -> None:
        """Walk a dynamic boundary: angr codegen statement-node attributes."""

        nonlocal changed
        statements = getattr(node, "statements", None)
        if isinstance(statements, list):
            copies: dict[CopyKey8616, object] = {}
            index = 0
            while index + 1 < len(statements):
                word_ref, word_rhs = _direct_global_word_assignment_8616(
                    statements[index],
                    codegen,
                    direct_by_offset,
                )
                if word_ref is None or not _is_direct_global_high_byte_projection_store_8616(
                    statements[index + 1],
                    word_ref,
                    word_rhs,
                    copies,
                ):
                    if word_ref is not None and _remove_direct_global_high_byte_for_initializer_8616(
                        statements[index + 1],
                        word_ref,
                        word_rhs,
                        copies,
                    ):
                        stats.direct_symbol_store_materialized_count += 1
                        stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
                        changed = True
                        process_statements(statements[index])
                        _record_assignment_copy_8616(_assignment_statement_8616(statements[index]) or statements[index], copies)
                        index += 1
                        continue
                    process_statements(statements[index])
                    _record_assignment_copy_8616(_assignment_statement_8616(statements[index]) or statements[index], copies)
                    index += 1
                    continue
                del statements[index + 1]
                stats.direct_symbol_store_materialized_count += 1
                stats.record(SegmentedGlobalLoadDecision8616.MATERIALIZED)
                changed = True
                continue
            if index < len(statements):
                process_statements(statements[index])
                _record_assignment_copy_8616(_assignment_statement_8616(statements[index]) or statements[index], copies)
        for attr in ("body", "else_node", "initializer", "iterator", "iteration"):
            child = getattr(node, attr, None)
            if child is not None:
                process_statements(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, body in tuple(pairs):
                process_statements(body)

    process_statements(root)
    return changed


def _direct_global_word_assignment_8616(
    stmt: object,
    codegen: CodegenBoundary8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
) -> tuple[DirectGlobalSymbolRef8616 | None, object | None]:
    assignment = _assignment_statement_8616(stmt)
    if assignment is None:
        return None, None
    lhs = assignment.lhs
    for ref in direct_by_offset.values():
        if int(ref.width) != 2:
            continue
        identity = _direct_global_lvalue_identity_8616(lhs)
        if identity == (ref.offset & 0xFFFF, 2):
            return ref, assignment.rhs
        replacement = _make_direct_global_symbol_expr_8616(codegen, ref, 2)
        if replacement is not None and _same_c_expression_8616(lhs, replacement):
            return ref, assignment.rhs
    return None, None


def _is_direct_global_high_byte_projection_store_8616(
    stmt: object,
    ref: DirectGlobalSymbolRef8616,
    word_rhs: object,
    copies: dict[CopyKey8616, object] | None = None,
) -> bool:
    assignment = _assignment_statement_8616(stmt)
    if assignment is None:
        return False
    high_identity = _direct_global_lvalue_identity_8616(assignment.lhs)
    if high_identity is None:
        return False
    high_addr, high_width = high_identity
    if high_width != 1 or (high_addr & 0xFFFF) != ((ref.offset + 1) & 0xFFFF):
        return False
    rhs = _resolve_expr_copies_8616(assignment.rhs, copies)
    rhs_const = _constant_int_8616(rhs)
    word_const = _constant_int_8616(_resolve_expr_copies_8616(word_rhs, copies))
    if rhs_const == 0 and word_const is not None and 0 <= int(word_const) <= 0xFF:
        return True
    rhs_range = _unsigned_expr_range_8616(rhs, copies)
    word_range = _unsigned_expr_range_8616(word_rhs, copies)
    if rhs_range == (0, 0) and word_range is not None and 0 <= word_range[0] <= word_range[1] <= 0xFF:
        return True
    if not isinstance(rhs, CBinaryOp) or rhs.op != "Shr":
        return False
    shift = _constant_int_8616(rhs.rhs)
    if shift != 8:
        return False
    projected = rhs.lhs
    return (word_rhs is not None and _same_c_expression_8616(projected, word_rhs)) or (
        _direct_global_update_delta_8616(ref, projected) == _direct_global_update_delta_8616(ref, word_rhs)
    )


def _remove_direct_global_high_byte_for_initializer_8616(
    stmt: object,
    ref: DirectGlobalSymbolRef8616,
    word_rhs: object,
    copies: dict[CopyKey8616, object] | None = None,
) -> bool:
    """Clear a dynamic angr codegen initializer that only mirrors a materialized global.

    Dynamic boundary: arbitrary angr codegen statement nodes expose initializer at runtime.
    """

    initializer = getattr(stmt, "initializer", None)
    if initializer is None:
        return False
    if not _is_direct_global_high_byte_projection_store_8616(initializer, ref, word_rhs, copies):
        return False
    try:
        # Dynamic boundary: arbitrary angr codegen statement nodes expose initializer at runtime.
        typing.cast(typing.Any, stmt).initializer = None
    except Exception:
        return False
    return True


def _resolve_expr_copies_8616(node: object, copies: dict[CopyKey8616, object] | None, depth: int = 0) -> object:
    if node is None or not copies or depth > 16:
        return node
    resolved = _resolve_copy_8616(node, copies)
    if resolved is not node:
        return _resolve_expr_copies_8616(resolved, copies, depth + 1)
    if isinstance(node, CBinaryOp):
        lhs = _resolve_expr_copies_8616(node.lhs, copies, depth + 1)
        rhs = _resolve_expr_copies_8616(node.rhs, copies, depth + 1)
        if lhs is not node.lhs or rhs is not node.rhs:
            # Dynamic boundary: angr C AST nodes carry codegen context opportunistically.
            return CBinaryOp(node.op, lhs, rhs, codegen=node.codegen)
    return node


def _unsigned_expr_range_8616(
    node: object,
    copies: dict[CopyKey8616, object] | None = None,
    depth: int = 0,
) -> tuple[int, int] | None:
    if node is None or depth > 16:
        return None
    node = _resolve_expr_copies_8616(node, copies, depth)
    const = _constant_int_8616(node)
    if const is not None:
        return int(const), int(const)
    if isinstance(node, CBinaryOp) and str(node.op).startswith("Cmp"):
        return 0, 1
    if not isinstance(node, CBinaryOp):
        return None
    if node.op == "And":
        lhs_const = _constant_int_8616(node.lhs)
        rhs_const = _constant_int_8616(node.rhs)
        if lhs_const is not None and int(lhs_const) >= 0:
            return 0, int(lhs_const)
        if rhs_const is not None and int(rhs_const) >= 0:
            return 0, int(rhs_const)
    lhs = _unsigned_expr_range_8616(node.lhs, copies, depth + 1)
    rhs = _unsigned_expr_range_8616(node.rhs, copies, depth + 1)
    if node.op == "Shr" and lhs is not None:
        shift = _constant_int_8616(node.rhs)
        if shift is not None and int(shift) >= 0 and lhs[0] >= 0:
            return lhs[0] >> int(shift), lhs[1] >> int(shift)
    if lhs is None or rhs is None:
        return None
    if node.op == "Sub":
        return lhs[0] - rhs[1], lhs[1] - rhs[0]
    if node.op == "Add":
        return lhs[0] + rhs[0], lhs[1] + rhs[1]
    if node.op == "Mul":
        products = (lhs[0] * rhs[0], lhs[0] * rhs[1], lhs[1] * rhs[0], lhs[1] * rhs[1])
        return min(products), max(products)
    return None


def _direct_global_update_delta_8616(ref: DirectGlobalSymbolRef8616, expr: object) -> int | None:
    if not isinstance(expr, CBinaryOp) or expr.op not in {"Add", "Sub"}:
        return None
    rhs_const = _constant_int_8616(expr.rhs)
    if rhs_const is None:
        return None
    lhs = expr.lhs
    identity = _direct_global_lvalue_identity_8616(lhs)
    if identity != (ref.offset & 0xFFFF, 2):
        return None
    delta = int(rhs_const)
    return delta if expr.op == "Add" else -delta


def _assignment_statement_8616(node: object) -> CAssignment | None:
    if isinstance(node, CAssignment):
        return node
    if isinstance(node, CExpressionStatement):
        expr = node.expr
        if isinstance(expr, CAssignment):
            return expr
    return None


def _direct_memory_cvar_identity_8616(node: object) -> tuple[int, int] | None:
    if not isinstance(node, CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = variable.addr
    width = variable.size
    if not isinstance(addr, int) or not isinstance(width, int):
        return None
    return addr, width


def _direct_global_lvalue_identity_8616(
    node: object,
    *,
    dirty_assignments: dict[tuple[str, int | str], object] | None = None,
) -> tuple[int, int] | None:
    node = _resolve_dirty_global_carrier_8616(node, dirty_assignments)
    identity = _direct_memory_cvar_identity_8616(node)
    if identity is not None:
        return identity
    indexed_identity = _direct_indexed_global_identity_8616(node)
    if indexed_identity is not None:
        return indexed_identity
    if not isinstance(node, CFunctionCall):
        return None
    helper = _segment_load_helper_8616(node)
    if helper is None:
        return None
    args = tuple(node.args or ())
    if len(args) != 2:
        return None
    offset = _constant_int_8616(args[1])
    if offset is None:
        return None
    return int(offset) & 0xFFFF, int(helper.width)


def _collect_unique_dirty_assignment_rhs_8616(cfunc: object) -> dict[tuple[str, int | str], object]:
    roots = _cfunc_roots_8616(cfunc)
    if not roots:
        return {}
    assignments: dict[tuple[str, int | str], object | None] = {}
    ambiguous: set[tuple[str, int | str]] = set()
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            assignment = _assignment_statement_8616(node)
            if assignment is None:
                continue
            keys = _dirty_expr_keys_8616(assignment.lhs)
            if not keys:
                continue
            rhs = assignment.rhs
            if _rhs_has_obvious_side_effect_8616(rhs):
                ambiguous.update(keys)
                continue
            for key in keys:
                previous = assignments.get(key)
                if previous is not None and previous is not rhs:
                    ambiguous.add(key)
                    assignments[key] = None
                    continue
                if key not in ambiguous:
                    assignments[key] = rhs
    return {key: rhs for key, rhs in assignments.items() if rhs is not None and key not in ambiguous}


def _resolve_dirty_global_carrier_8616(
    node: object,
    dirty_assignments: dict[tuple[str, int | str], object] | None,
    *,
    seen: set[tuple[str, int | str]] | None = None,
) -> object:
    if not dirty_assignments:
        return node
    keys = _dirty_expr_keys_8616(node)
    if not keys:
        return node
    if seen is None:
        seen = set()
    for key in keys:
        if key in seen:
            continue
        rhs = dirty_assignments.get(key)
        if rhs is None:
            continue
        seen.add(key)
        return _resolve_dirty_global_carrier_8616(rhs, dirty_assignments, seen=seen)
    return node


def _dirty_expr_keys_8616(node: object) -> tuple[tuple[str, int | str], ...]:
    """Return keys from dynamic angr codegen dirty-expression metadata.

    Dynamic boundary: angr codegen dirty expressions expose helper identifiers at runtime.
    """

    if not isinstance(node, CDirtyExpression):
        return ()
    dirty = node.dirty
    keys: list[tuple[str, int | str]] = []
    for attr in ("varid", "idx", "oident"):
        value = getattr(dirty, attr, None)
        if isinstance(value, (int, str)):
            keys.append((attr, value))
    name = getattr(dirty, "name", None)
    if isinstance(name, str) and name:
        keys.append(("name", _normalized_cvariable_name_8616(name)))
    expr_idx = node.idx
    if isinstance(expr_idx, (int, str)):
        keys.append(("expr_idx", expr_idx))
    seen: set[tuple[str, int | str]] = set()
    ordered: list[tuple[str, int | str]] = []
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return tuple(ordered)


def _debug_remaining_segmented_global_load_nodes_8616(cfunc: object) -> None:
    """Log remaining loads from a dynamic boundary: angr codegen dirty-expression metadata."""

    if not os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        return
    for root in _cfunc_roots_8616(cfunc):
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, CFunctionCall):
                helper = _segment_load_helper_8616(node)
                if helper is None:
                    continue
                args = tuple(node.args or ())
                offset = _constant_int_8616(args[1]) if len(args) == 2 else None
                if offset not in {306, 308, 352}:
                    continue
                log.warning(
                    "[seg-global-loads-remaining] helper=%s offset=%r node=%s arg_types=%s",
                    helper.helper_name,
                    offset,
                    _debug_source_8616(node),
                    tuple(type(arg).__name__ for arg in args),
                )
                continue
            if not isinstance(node, CDirtyExpression):
                continue
            try:
                rendered = _debug_c_repr_8616(node)
            except Exception:
                rendered = repr(node)
            if "SEG_U" not in rendered:
                continue
            dirty = node.dirty
            log.warning(
                "[seg-global-loads-remaining] dirty=%s dirty_type=%s keys=%s attrs=%s",
                rendered,
                type(dirty).__name__,
                _dirty_expr_keys_8616(node),
                {
                    name: getattr(dirty, name, None)
                    for name in ("name", "varid", "idx", "oident", "reg", "reg_offset", "bits", "size")
                },
            )


def _direct_indexed_global_identity_8616(node: object) -> tuple[int, int] | None:
    if not isinstance(node, CIndexedVariable):
        return None
    base = node.variable
    if not isinstance(base, CVariable):
        return None
    variable = base.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    base_addr = variable.addr
    width = variable.size
    index_value = _constant_int_8616(node.index)
    if not isinstance(base_addr, int) or not isinstance(width, int) or index_value is None:
        return None
    if width == 4 and int(index_value) in {0, 1}:
        return (base_addr + int(index_value) * 2) & 0xFFFF, 2
    return (base_addr + int(index_value) * width) & 0xFFFF, width


def _direct_ref_for_cvariable_8616(
    node: CVariable,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
) -> DirectGlobalSymbolRef8616 | None:
    variable = node.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = variable.addr
    width = variable.size
    if not isinstance(addr, int) or not isinstance(width, int):
        return None
    exact = direct_by_offset.get((addr & 0xFFFF, width))
    if exact is not None:
        return exact
    if width != 1:
        return None
    name = variable.name
    if isinstance(name, str) and re.fullmatch(r"mem_[0-9a-fA-F]{4,}", name) is None:
        return None
    for widened_width in (2, 4):
        widened = direct_by_offset.get((addr & 0xFFFF, widened_width))
        if widened is not None:
            return widened
    return None


def materialize_compare_register_global_carriers_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: SyntheticGlobalsBoundary8616,
    cod_metadata: CodMetadataBoundary8616 = None,
) -> bool:
    """Materialize compare-register carriers from proven global evidence."""

    stats = SegmentedGlobalLoadStats8616()
    function = _active_function_8616(project, codegen)
    summaries = _function_instruction_summaries_8616(project, function) if function is not None else []
    compare_evidence = recover_compare_register_global_carriers_8616(summaries)
    named_evidence = _collect_named_global_evidence_8616(project, codegen, synthetic_globals, cod_metadata=cod_metadata)
    stats.raw_fact_count = len(summaries)
    stats.compare_register_raw_fact_count = len(compare_evidence)
    stats.normalized_fact_count = len(compare_evidence)
    stats.classified_fact_count = len(compare_evidence)
    stats.compare_register_classified_count = len(compare_evidence)
    changed = materialize_compare_register_global_carriers_from_evidence_8616(
        project,
        codegen,
        named_evidence,
        compare_evidence,
        stats=stats,
    )
    _store_stats_8616(codegen, stats)
    return changed


def materialize_indexed_segmented_global_loads_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    cod_metadata: CodMetadataBoundary8616 = None,
) -> bool:
    """Materialize indexed DS global loads and stores from lowering evidence."""

    stats = SegmentedGlobalLoadStats8616()
    function = _active_function_8616(project, codegen)
    summaries = _function_instruction_summaries_8616(project, function) if function is not None else []
    indexed_evidence = recover_indexed_segmented_global_evidence_8616(summaries, cod_metadata)
    direct_refs = _collect_direct_global_symbol_refs_8616(cod_metadata, summaries)
    address_refs = _collect_global_address_symbol_refs_8616(cod_metadata, summaries)
    address_literals = _collect_global_address_literal_evidence_8616(cod_metadata, summaries)
    evidence = _merge_indexed_global_evidence_8616(
        indexed_evidence,
        _indexed_evidence_from_direct_symbol_refs_8616((*direct_refs, *address_refs)),
    )
    codegen._inertia_indexed_global_evidence_8616 = evidence
    load_site_evidence = recover_indexed_segmented_global_load_site_evidence_8616(project, function)
    store_evidence = recover_indexed_segmented_global_store_evidence_8616(project, function)
    codegen._inertia_indexed_global_store_evidence_8616 = store_evidence
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        log.warning(
            "[seg-global-indexed] evidence=%s load_site_evidence=%s store_evidence=%s",
            tuple((hex(item.base_offset & 0xFFFF), item.width, item.name, item.relative_disp) for item in evidence),
                    tuple(
                        (
                            hex(fact.base_offset & 0xFFFF),
                            fact.width,
                            fact.index_stack_offset,
                            fact.index_shift,
                            hex(fact.ins_addr),
                            tuple(
                                (store.stack_offset, store.width, hex(store.ins_addr))
                                for store in fact.stack_stores
                            ),
                        )
                        for fact in load_site_evidence
                    ),
            tuple(
                (
                    hex(fact.base_offset & 0xFFFF),
                    fact.width,
                    fact.index_stack_offset,
                    fact.index_shift,
                    None
                    if fact.source_base_offset is None
                    else hex(fact.source_base_offset & 0xFFFF),
                    fact.source_width,
                    fact.source_index_stack_offset,
                    fact.source_index_shift,
                    fact.source_stack_offset,
                    fact.source_stack_width,
                )
                for fact in store_evidence
            ),
        )
    stats.raw_fact_count = len(summaries)
    stats.indexed_raw_fact_count = len(evidence)
    stats.indexed_load_site_raw_fact_count = len(load_site_evidence)
    stats.direct_symbol_raw_fact_count = len(direct_refs) + len(address_refs)
    stats.indexed_store_lvalue_raw_fact_count = len(store_evidence)
    stats.normalized_fact_count = len(evidence)
    stats.classified_fact_count = len(evidence)
    stats.indexed_classified_count = len(evidence)
    consumed_load_sites: list[IndexedSegmentedGlobalLoadSiteEvidence8616] = []
    changed = materialize_indexed_segmented_global_loads_from_evidence_8616(
        project,
        codegen,
        evidence,
        load_site_evidence=load_site_evidence,
        store_evidence=store_evidence,
        address_literals=address_literals,
        stats=stats,
        consumed_load_sites=consumed_load_sites,
    )
    if consumed_load_sites:
        # Dynamic angr codegen boundary: retain typed Lowering proof across rebuilds.
        previous_read_record = getattr(
            codegen,
            "_inertia_indexed_global_read_carrier_record_8616",
            None,
        )
        previous_read_evidence = (
            previous_read_record.evidence
            if isinstance(
                previous_read_record,
                IndexedGlobalReadCarrierMaterializationRecord8616,
            )
            else ()
        )
        previous_raw = (
            previous_read_record.raw_fact_count
            if isinstance(
                previous_read_record,
                IndexedGlobalReadCarrierMaterializationRecord8616,
            )
            else 0
        )
        previous_normalized = (
            previous_read_record.normalized_fact_count
            if isinstance(
                previous_read_record,
                IndexedGlobalReadCarrierMaterializationRecord8616,
            )
            else 0
        )
        previous_classified = (
            previous_read_record.classified_fact_count
            if isinstance(
                previous_read_record,
                IndexedGlobalReadCarrierMaterializationRecord8616,
            )
            else 0
        )
        previous_materialized = (
            previous_read_record.materialized_count
            if isinstance(
                previous_read_record,
                IndexedGlobalReadCarrierMaterializationRecord8616,
            )
            else 0
        )
        previous_failures = (
            previous_read_record.failure_count
            if isinstance(
                previous_read_record,
                IndexedGlobalReadCarrierMaterializationRecord8616,
            )
            else 0
        )
        consumed = tuple(dict.fromkeys(consumed_load_sites))
        codegen._inertia_indexed_global_read_carrier_record_8616 = (
            IndexedGlobalReadCarrierMaterializationRecord8616(
                evidence=tuple(dict.fromkeys((*previous_read_evidence, *consumed))),
                raw_fact_count=previous_raw + len(load_site_evidence),
                normalized_fact_count=previous_normalized + len(load_site_evidence),
                classified_fact_count=previous_classified + len(consumed),
                materialized_count=previous_materialized + len(consumed),
                failure_count=previous_failures,
            )
        )
    if stats.indexed_materialized_count > 0:
        # Dynamic angr codegen boundary: retain Lowering evidence across idempotent replays.
        previous_record = getattr(codegen, "_inertia_indexed_global_materialization_record_8616", None)
        previous_evidence = (
            previous_record.evidence
            if isinstance(previous_record, IndexedSegmentedGlobalMaterializationRecord8616)
            else ()
        )
        previous_count = (
            previous_record.materialized_count
            if isinstance(previous_record, IndexedSegmentedGlobalMaterializationRecord8616)
            else 0
        )
        codegen._inertia_indexed_global_materialization_record_8616 = (
            IndexedSegmentedGlobalMaterializationRecord8616(
                evidence=tuple(dict.fromkeys((*previous_evidence, *evidence))),
                materialized_count=previous_count + stats.indexed_materialized_count,
            )
        )
    _store_stats_8616(codegen, stats)
    return changed


def recover_indexed_segmented_global_evidence_8616(
    summaries: list[InsnSummary8616],
    cod_metadata: CodMetadataBoundary8616,
) -> tuple[IndexedSegmentedGlobalEvidence8616, ...]:
    """Recover indexed global load evidence from instruction summaries and optional sidecar refs."""

    cod_refs = _cod_indexed_global_refs_8616(cod_metadata)
    binary_refs: list[tuple[int, int]] = []
    for insn in summaries:
        if insn.op0_kind == "indexed_mem" and isinstance(insn.op0_value, int):
            binary_refs.append((int(insn.op0_value) & 0xFFFF, int(insn.op0_size or 2)))
        if insn.op1_kind == "indexed_mem" and isinstance(insn.op1_value, int):
            binary_refs.append((int(insn.op1_value) & 0xFFFF, int(insn.op1_size or 2)))
    if not cod_refs or len(cod_refs) != len(binary_refs):
        if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
            log.warning(
                "[seg-global-indexed] refused sidecar_join cod_refs=%s binary_refs=%s",
                cod_refs,
                tuple(binary_refs),
            )
        return ()
    recovered: list[IndexedSegmentedGlobalEvidence8616] = []
    for (base_offset, actual_width), (name, relative_disp, cod_width) in zip(binary_refs, cod_refs, strict=False):
        recovered.append(
            IndexedSegmentedGlobalEvidence8616(
                base_offset=base_offset,
                name=name,
                relative_disp=relative_disp,
                width=int(actual_width or cod_width or 2),
            )
        )
    return tuple(recovered)


def recover_indexed_segmented_global_load_site_evidence_8616(
    project: ProjectBoundary8616,
    function: object,
) -> tuple[IndexedSegmentedGlobalLoadSiteEvidence8616, ...]:
    """Recover indexed DS loads and exact BP stores through register carriers."""

    if project is None or function is None:
        return ()
    recovered: list[IndexedSegmentedGlobalLoadSiteEvidence8616] = []
    for block in _direct_global_update_blocks_8616(project, function):
        reg_stack_index: dict[str, tuple[int, int, int]] = {}
        reg_indexed_load: dict[str, int] = {}
        for wrapper in _capstone_insns_for_direct_global_update_8616(project, block):
            insn = _capstone_instruction_view_8616(wrapper)
            operands = insn.operands
            insn_id = insn.instruction_id
            if insn_id == X86_INS_MOV and len(operands) == 2:
                dst, src = operands
                if dst.kind != X86_OP_REG:
                    stack_store = _stack_mem_operand_offset_width_8616(dst.raw)
                    if stack_store is None or src.kind != X86_OP_REG:
                        continue
                    src_name = _direct_stack_move_register_name_8616(insn.raw, src.register)
                    load_index = reg_indexed_load.get(src_name) if src_name is not None else None
                    if load_index is None:
                        continue
                    stack_offset, stack_width = stack_store
                    load = recovered[load_index]
                    if load.width != stack_width or not isinstance(insn.address, int):
                        continue
                    store = IndexedSegmentedGlobalStackStore8616(
                        stack_offset=int(stack_offset),
                        width=int(stack_width),
                        ins_addr=int(insn.address),
                    )
                    recovered[load_index] = replace(
                        load,
                        stack_stores=tuple(dict.fromkeys((*load.stack_stores, store))),
                    )
                    continue
                dst_name = _direct_stack_move_register_name_8616(insn.raw, dst.register)
                if dst_name is None:
                    continue
                stack_slot = _stack_mem_operand_offset_width_8616(src.raw)
                if stack_slot is not None:
                    stack_offset, stack_width = stack_slot
                    reg_stack_index[dst_name] = (stack_offset, stack_width, 0)
                    _invalidate_register_storage_carriers_8616(reg_indexed_load, dst_name)
                    continue
                mem = src.memory
                if src.kind == X86_OP_MEM and mem is not None:
                    segment_name = _direct_stack_move_segment_name_8616(insn.raw, mem.segment)
                    displacement = mem.displacement
                    access_width = src.size
                    ins_addr = insn.address
                    base_name = _direct_stack_move_register_name_8616(insn.raw, mem.base)
                    index_name = _direct_stack_move_register_name_8616(insn.raw, mem.index)
                    base_value = reg_stack_index.get(base_name) if base_name is not None else None
                    index_value = reg_stack_index.get(index_name) if index_name is not None else None
                    index_sources = [
                        value
                        for value in (base_value, index_value)
                        if value is not None
                    ]
                    if (
                        segment_name == "ds"
                        and isinstance(displacement, int)
                        and access_width in {1, 2}
                        and isinstance(ins_addr, int)
                        and len(index_sources) == 1
                    ):
                        stack_offset, _stack_width, shift = index_sources[0]
                        destination_domain = register_domain_for_name(dst_name)
                        load = IndexedSegmentedGlobalLoadSiteEvidence8616(
                            base_offset=int(displacement) & 0xFFFF,
                            width=int(access_width),
                            index_stack_offset=int(stack_offset),
                            index_shift=int(shift),
                            ins_addr=int(ins_addr),
                            destination_register=(
                                destination_domain.name.lower()
                                if destination_domain is not None
                                else dst_name.lower()
                            ),
                            index_stack_width=int(_stack_width),
                        )
                        recovered.append(load)
                        _invalidate_register_storage_carriers_8616(reg_indexed_load, dst_name)
                        reg_indexed_load[dst_name] = len(recovered) - 1
                    else:
                        _invalidate_register_storage_carriers_8616(reg_indexed_load, dst_name)
                    reg_stack_index.pop(dst_name, None)
                    continue
                if src.kind == X86_OP_REG:
                    src_name = _direct_stack_move_register_name_8616(insn.raw, src.register)
                    copied = reg_stack_index.get(src_name) if src_name is not None else None
                    if copied is not None:
                        reg_stack_index[dst_name] = copied
                    load_index = reg_indexed_load.get(src_name) if src_name is not None else None
                    _invalidate_register_storage_carriers_8616(reg_indexed_load, dst_name)
                    if load_index is not None:
                        reg_indexed_load[dst_name] = load_index
                    if copied is not None or load_index is not None:
                        continue
                reg_stack_index.pop(dst_name, None)
                _invalidate_register_storage_carriers_8616(reg_indexed_load, dst_name)
                continue
            if insn_id in {X86_INS_SHL, X86_INS_SAL} and len(operands) == 2:
                dst, amount = operands
                if dst.kind != X86_OP_REG:
                    continue
                reg_name = _direct_stack_move_register_name_8616(insn.raw, dst.register)
                previous = reg_stack_index.get(reg_name) if reg_name is not None else None
                immediate = amount.immediate
                if reg_name is not None and previous is not None and isinstance(immediate, int) and immediate >= 0:
                    stack_offset, stack_width, _old_shift = previous
                    reg_stack_index[reg_name] = (stack_offset, stack_width, int(immediate))
                elif reg_name is not None:
                    reg_stack_index.pop(reg_name, None)
                if reg_name is not None:
                    _invalidate_register_storage_carriers_8616(reg_indexed_load, reg_name)
                continue
            if operands and operands[0].kind == X86_OP_REG:
                reg_name = _direct_stack_move_register_name_8616(insn.raw, operands[0].register)
                if reg_name is not None:
                    reg_stack_index.pop(reg_name, None)
                    _invalidate_register_storage_carriers_8616(reg_indexed_load, reg_name)
    return tuple(dict.fromkeys(recovered))


def recover_indexed_segmented_global_store_evidence_8616(
    project: ProjectBoundary8616,
    function: object,
) -> tuple[IndexedSegmentedGlobalStoreEvidence8616, ...]:
    """Recover indexed global store lvalue evidence from a dynamic boundary: third-party Capstone instructions."""

    if project is None or function is None:
        return ()
    recovered: list[IndexedSegmentedGlobalStoreEvidence8616] = []
    for block in _direct_global_update_blocks_8616(project, function):
        insns = tuple(_capstone_insns_for_direct_global_update_8616(project, block))
        reg_stack_index: dict[str, tuple[int, int, int]] = {}
        reg_indexed_global: dict[str, tuple[int, int, int, int]] = {}
        reg_signed_remainder: dict[str, SignedRemainderStackSource8616] = {}
        for wrapper in insns:
            insn = _capstone_instruction_view_8616(wrapper)
            operands = insn.operands
            insn_id = insn.instruction_id
            if insn_id == X86_INS_CWD:
                for alias in _signed_remainder_register_aliases_8616("dx"):
                    reg_signed_remainder.pop(alias, None)
                continue
            if insn_id == X86_INS_IDIV and len(operands) == 1:
                divisor_slot = _stack_mem_operand_offset_width_8616(operands[0].raw)
                dividend_slot = reg_stack_index.get("ax")
                for alias in _signed_remainder_register_aliases_8616("dx"):
                    reg_stack_index.pop(alias, None)
                    reg_indexed_global.pop(alias, None)
                    reg_signed_remainder.pop(alias, None)
                reg_stack_index.pop("ax", None)
                reg_indexed_global.pop("ax", None)
                if divisor_slot is None or dividend_slot is None:
                    continue
                divisor_offset, divisor_width = divisor_slot
                dividend_offset, dividend_width, dividend_shift = dividend_slot
                if divisor_width != 2 or dividend_width != 2 or dividend_shift != 0:
                    continue
                remainder = SignedRemainderStackSource8616(
                    int(dividend_offset),
                    int(divisor_offset),
                    2,
                )
                for alias in _signed_remainder_register_aliases_8616("dx"):
                    reg_signed_remainder[alias] = remainder
                continue
            if insn_id == X86_INS_INC and len(operands) == 1 and operands[0].kind == X86_OP_REG:
                register_name = _direct_stack_move_register_name_8616(
                    insn.raw,
                    operands[0].register,
                )
                remainder = reg_signed_remainder.get(register_name) if register_name is not None else None
                if register_name is not None and remainder is not None:
                    adjusted = replace(remainder, post_adjust=remainder.post_adjust + 1)
                    for alias in _signed_remainder_register_aliases_8616(register_name):
                        reg_signed_remainder[alias] = adjusted
                    continue
            if insn_id == X86_INS_MOV and len(operands) == 2:
                dst, src = operands
                if dst.kind == X86_OP_REG:
                    dst_name = _direct_stack_move_register_name_8616(insn.raw, dst.register)
                    if dst_name is None:
                        continue
                    for alias in _signed_remainder_register_aliases_8616(dst_name):
                        reg_signed_remainder.pop(alias, None)
                    stack_slot = _stack_mem_operand_offset_width_8616(src.raw)
                    if stack_slot is not None:
                        stack_offset, stack_width = stack_slot
                        reg_stack_index[dst_name] = (stack_offset, stack_width, 0)
                        reg_indexed_global.pop(dst_name, None)
                        continue
                    mem = src.memory
                    if src.kind == X86_OP_MEM and mem is not None:
                        segment_name = _direct_stack_move_segment_name_8616(insn.raw, mem.segment)
                        displacement = mem.displacement
                        access_width = src.size
                        base_name = _direct_stack_move_register_name_8616(insn.raw, mem.base)
                        index_name = _direct_stack_move_register_name_8616(insn.raw, mem.index)
                        base_value = reg_stack_index.get(base_name) if base_name is not None else None
                        index_value = reg_stack_index.get(index_name) if index_name is not None else None
                        index_sources = [value for value in (base_value, index_value) if value is not None]
                        if (
                            segment_name == "ds"
                            and isinstance(displacement, int)
                            and access_width in {1, 2}
                            and len(index_sources) == 1
                        ):
                            stack_offset, _stack_width, shift = index_sources[0]
                            reg_indexed_global[dst_name] = (
                                int(displacement) & 0xFFFF,
                                int(access_width),
                                int(stack_offset),
                                int(shift),
                            )
                            reg_stack_index.pop(dst_name, None)
                            continue
                        reg_stack_index.pop(dst_name, None)
                        reg_indexed_global.pop(dst_name, None)
                        continue
                    if src.kind == X86_OP_REG:
                        src_name = _direct_stack_move_register_name_8616(insn.raw, src.register)
                        copied = reg_stack_index.get(src_name) if src_name is not None else None
                        if copied is not None:
                            reg_stack_index[dst_name] = copied
                            reg_indexed_global.pop(dst_name, None)
                            continue
                        copied_global = reg_indexed_global.get(src_name) if src_name is not None else None
                        if copied_global is not None:
                            reg_indexed_global[dst_name] = copied_global
                            reg_stack_index.pop(dst_name, None)
                            continue
                    reg_stack_index.pop(dst_name, None)
                    reg_indexed_global.pop(dst_name, None)
                    continue
                if dst.kind != X86_OP_MEM:
                    continue
                width = dst.size
                if width not in {1, 2}:
                    continue
                mem = dst.memory
                if mem is None:
                    continue
                segment_name = _direct_stack_move_segment_name_8616(insn.raw, mem.segment)
                if segment_name != "ds":
                    continue
                displacement = mem.displacement
                ins_addr = insn.address
                if not isinstance(displacement, int) or not isinstance(ins_addr, int):
                    continue
                base_name = _direct_stack_move_register_name_8616(insn.raw, mem.base)
                index_name = _direct_stack_move_register_name_8616(insn.raw, mem.index)
                base_value = reg_stack_index.get(base_name) if base_name is not None else None
                index_value = reg_stack_index.get(index_name) if index_name is not None else None
                index_sources = [value for value in (base_value, index_value) if value is not None]
                if len(index_sources) != 1:
                    continue
                stack_offset, _stack_width, shift = index_sources[0]
                source_name = _direct_stack_move_register_name_8616(insn.raw, src.register)
                source_global = reg_indexed_global.get(source_name) if source_name is not None else None
                source_base_offset = None
                source_width = None
                source_index_stack_offset = None
                source_index_shift = None
                if source_global is not None:
                    (
                        source_base_offset,
                        source_width,
                        source_index_stack_offset,
                        source_index_shift,
                    ) = source_global
                source_stack_offset = None
                source_stack_width = None
                source_stack = reg_stack_index.get(source_name) if source_name is not None else None
                if source_global is None and source_stack is not None:
                    stack_source_offset, stack_source_width, stack_source_shift = source_stack
                    if stack_source_shift == 0 and stack_source_width == width:
                        source_stack_offset = int(stack_source_offset)
                        source_stack_width = int(stack_source_width)
                source_signed_remainder = (
                    reg_signed_remainder.get(source_name) if source_name is not None else None
                )
                recovered.append(
                    IndexedSegmentedGlobalStoreEvidence8616(
                        base_offset=int(displacement) & 0xFFFF,
                        width=int(width),
                        index_stack_offset=int(stack_offset),
                        index_shift=int(shift),
                        ins_addr=int(ins_addr),
                        source_base_offset=source_base_offset,
                        source_width=source_width,
                        source_index_stack_offset=source_index_stack_offset,
                        source_index_shift=source_index_shift,
                        source_stack_offset=source_stack_offset,
                        source_stack_width=source_stack_width,
                        source_signed_remainder=source_signed_remainder,
                    )
                )
                continue
            if insn_id in {X86_INS_SHL, X86_INS_SAL} and len(operands) == 2:
                dst, amount = operands
                if dst.kind != X86_OP_REG:
                    continue
                reg_name = _direct_stack_move_register_name_8616(insn.raw, dst.register)
                if reg_name is None:
                    continue
                previous = reg_stack_index.get(reg_name)
                immediate = amount.immediate
                if previous is not None and isinstance(immediate, int) and immediate >= 0:
                    stack_offset, stack_width, _old_shift = previous
                    reg_stack_index[reg_name] = (stack_offset, stack_width, int(immediate))
                else:
                    reg_stack_index.pop(reg_name, None)
                reg_indexed_global.pop(reg_name, None)
                continue
            if operands and operands[0].kind == X86_OP_REG:
                reg_name = _direct_stack_move_register_name_8616(insn.raw, operands[0].register)
                if reg_name is not None:
                    reg_stack_index.pop(reg_name, None)
                    reg_indexed_global.pop(reg_name, None)
                    for alias in _signed_remainder_register_aliases_8616(reg_name):
                        reg_signed_remainder.pop(alias, None)
    return tuple(dict.fromkeys(recovered))


def materialize_indexed_segmented_global_loads_from_evidence_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    *,
    load_site_evidence: tuple[IndexedSegmentedGlobalLoadSiteEvidence8616, ...] = (),
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...] = (),
    address_literals: tuple[GlobalAddressLiteralEvidence8616, ...] = (),
    stats: SegmentedGlobalLoadStats8616 | None = None,
    consumed_load_sites: list[IndexedSegmentedGlobalLoadSiteEvidence8616] | None = None,
) -> bool:
    """Materialize indexed global expressions from pre-collected evidence."""

    if stats is None:
        stats = SegmentedGlobalLoadStats8616()
    if not evidence and not address_literals:
        stats.record_indexed(IndexedSegmentedGlobalDecision8616.REFUSED_NO_EVIDENCE)
        return False
    cfunc = codegen.cfunc
    if cfunc is None:
        stats.record_indexed(IndexedSegmentedGlobalDecision8616.REFUSED_NO_CFUNC)
        return False
    evidence_by_base = {(item.base_offset & 0xFFFF, item.width): item for item in evidence}
    load_sites_by_ins_addr = {item.ins_addr: item for item in load_site_evidence}
    literals_by_offset = {item.offset & 0xFFFF: item for item in address_literals}
    changed = False

    def transform(node: object, copies: dict[CopyKey8616, object] | None = None) -> object:
        nonlocal changed
        indexed = _materialize_indexed_global_expr_node_8616(
            project,
            codegen,
            node,
            evidence_by_base,
            literals_by_offset,
            load_sites_by_ins_addr=load_sites_by_ins_addr,
            copies=copies,
            stats=stats,
            consumed_load_sites=consumed_load_sites,
        )
        if indexed is None:
            return node
        _debug_segmented_global_materialized_8616("indexed", node, indexed)
        changed = True
        return indexed

    for root in tuple(_cfunc_roots_8616(cfunc)):
        if root not in _cfunc_roots_8616(cfunc):
            continue
        root_changed = False
        new_root = transform(root)
        if new_root is not root:
            changed = True
            root_changed = True
        if _materialize_indexed_global_word_store_pairs_8616(
            root,
            project,
            codegen,
            evidence_by_base,
            store_evidence,
            stats,
        ):
            changed = True
            root_changed = True
        if isinstance(root, CStatements) and _replace_c_children_8616(root, transform):
            changed = True
            root_changed = True
        if _materialize_indexed_global_word_store_lvalues_8616(
            root,
            codegen,
            evidence_by_base,
            store_evidence,
            stats,
        ):
            changed = True
            root_changed = True
        if _materialize_indexed_global_byte_store_lvalues_8616(
            root,
            codegen,
            evidence_by_base,
            store_evidence,
            stats,
        ):
            changed = True
            root_changed = True
        if _remove_indexed_global_store_source_carriers_8616(root, evidence_by_base, store_evidence, stats):
            changed = True
            root_changed = True
        aggregate_promoted_count = _promote_stack_assignment_aggregate_types_8616(
            codegen,
            root,
            load_site_evidence,
        )
        if aggregate_promoted_count:
            stats.indexed_stack_aggregate_type_promoted_count += aggregate_promoted_count
            changed = True
            root_changed = True
        aggregate_byte_cast_projected_count = _project_two_byte_aggregate_char_casts_8616(codegen, root)
        if aggregate_byte_cast_projected_count:
            stats.indexed_stack_aggregate_byte_cast_projected_count += aggregate_byte_cast_projected_count
            changed = True
            root_changed = True
        if root_changed:
            _sync_cfunc_statement_roots_8616(cfunc, root)
    return changed


def _materialize_indexed_global_expr_node_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    literals_by_offset: dict[int, GlobalAddressLiteralEvidence8616] | None = None,
    *,
    load_sites_by_ins_addr: dict[int, IndexedSegmentedGlobalLoadSiteEvidence8616] | None = None,
    copies: dict[CopyKey8616, object] | None = None,
    stats: SegmentedGlobalLoadStats8616 | None = None,
    consumed_load_sites: list[IndexedSegmentedGlobalLoadSiteEvidence8616] | None = None,
) -> object | None:
    """Lower one segmented-global helper expression from structured evidence."""

    load_site_expr = _indexed_global_load_from_site_evidence_8616(
        codegen,
        node,
        evidence_by_base,
        load_sites_by_ins_addr or {},
        consumed_load_sites=consumed_load_sites,
    )
    if load_site_expr is not None:
        if stats is not None:
            stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
            stats.indexed_load_site_materialized_count += 1
        return load_site_expr

    byte_pair_load = _indexed_word_load_from_byte_pair_8616(
        codegen,
        node,
        evidence_by_base,
        copies=copies,
    )
    if byte_pair_load is not None:
        if stats is not None:
            stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
        return byte_pair_load

    if not isinstance(node, CFunctionCall):
        return None

    segment_helper = _segment_load_helper_8616(node)
    if segment_helper is not None:
        args = tuple(node.args or ())
        if len(args) != 2 or not _is_ds_segment_expr_8616(project, args[0]):
            return None
        if segment_helper.width == 1:
            stride_matched = _match_indexed_offset_expr_with_stride_8616(args[1], copies=copies)
            if stride_matched is not None:
                base_offset, stride, index_expr = stride_matched
                value_expr = _make_indexed_global_value_from_stride_evidence_8616(
                    codegen,
                    evidence_by_base,
                    base_offset,
                    stride,
                    index_expr,
                    segment_helper.width,
                )
                if value_expr is not None:
                    if stats is not None:
                        stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                    return value_expr
        matched = _match_indexed_offset_expr_8616(args[1], segment_helper.width, copies=copies)
        width = segment_helper.width
        if matched is None:
            matched = _match_indexed_offset_expr_for_evidence_8616(args[1], evidence_by_base, copies=copies)
            if matched is not None:
                _base_offset, width, _index_expr = matched
        if matched is None:
            direct_offset = _constant_int_8616(args[1])
            if direct_offset is not None:
                item = evidence_by_base.get((direct_offset & 0xFFFF, segment_helper.width))
                if item is not None:
                    direct_expr = _make_direct_global_symbol_expr_8616(
                        codegen,
                        DirectGlobalSymbolRef8616(
                            offset=item.base_offset & 0xFFFF,
                            name=item.name,
                            relative_disp=int(item.relative_disp),
                            width=segment_helper.width,
                            max_relative_disp=max(0, int(item.relative_disp)),
                        ),
                        segment_helper.width,
                    )
                    if direct_expr is not None:
                        if stats is not None:
                            stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                        return direct_expr
        if matched is None:
            stride_matched = _match_indexed_offset_expr_with_stride_8616(args[1], copies=copies)
            if stride_matched is not None:
                base_offset, stride, index_expr = stride_matched
                value_expr = _make_indexed_global_value_from_stride_evidence_8616(
                    codegen,
                    evidence_by_base,
                    base_offset,
                    stride,
                    index_expr,
                    segment_helper.width,
                )
                if value_expr is not None:
                    if stats is not None:
                        stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                    return value_expr
    else:
        args = tuple(node.args or ())
        segment_pointer_helper = _segment_pointer_helper_8616(node)
        if segment_pointer_helper is not None:
            if len(args) != 2 or not _is_ds_segment_expr_8616(project, args[0]):
                return None
            direct_offset = _constant_int_8616(args[1])
            if direct_offset is not None:
                literal = (literals_by_offset or {}).get(direct_offset & 0xFFFF)
                if literal is not None:
                    if stats is not None:
                        stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                    char_ptr = SimTypePointer(SimTypeChar(False))
                    return CConstant(0, char_ptr, reference_values={char_ptr: literal.value}, codegen=codegen)
                address_expr = _make_direct_global_address_from_evidence_8616(
                    codegen,
                    evidence_by_base,
                    direct_offset,
                )
                if address_expr is not None:
                    if stats is not None:
                        stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                    return address_expr
            near_pointer_element = _near_pointer_table_element_from_ds_offset_8616(
                codegen,
                args[1],
                evidence_by_base,
            )
            if near_pointer_element is not None:
                if stats is not None:
                    stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                return near_pointer_element
            near_pointer_load = _near_pointer_table_element_from_ds_load_8616(
                project,
                codegen,
                args[1],
                evidence_by_base,
                copies=copies,
            )
            if near_pointer_load is not None:
                if stats is not None:
                    stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                return near_pointer_load
            matched = _match_indexed_offset_expr_for_evidence_8616(args[1], evidence_by_base, copies=copies)
            if matched is None:
                stride_matched = _match_indexed_offset_expr_with_stride_8616(args[1], copies=copies)
                if stride_matched is not None:
                    base_offset, stride, index_expr = stride_matched
                    address_expr = _make_indexed_global_address_from_stride_evidence_8616(
                        codegen,
                        evidence_by_base,
                        base_offset,
                        stride,
                        index_expr,
                    )
                    if address_expr is not None:
                        if stats is not None:
                            stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                        return address_expr
                _debug_indexed_expr_refusal_8616(
                    "segment_pointer_offset_shape",
                    args[1],
                    evidence_keys=tuple(sorted(evidence_by_base)),
                )
                if stats is not None:
                    stats.record_indexed(IndexedSegmentedGlobalDecision8616.REFUSED_SHAPE_MISMATCH)
                return None
            base_offset, width, index_expr = matched
            item = _indexed_evidence_for_base_stride_8616(evidence_by_base, base_offset, width)
            if item is None:
                return None
            indexed = _make_indexed_global_value_expr_8616(
                codegen,
                item,
                index_expr,
                evidence_by_base,
                allow_unregistered_for_address=True,
            )
            if indexed is None:
                return None
            if stats is not None:
                stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
            if isinstance(indexed, CExpression):
                return CUnaryOp("Reference", indexed, codegen=codegen)
            return None
        memory_helper = _memory_pointer_helper_8616(node)
        if memory_helper is None:
            return None
        if len(args) != 1:
            return None
        matched = _match_indexed_pointer_expr_8616(args[0], memory_helper.width, copies=copies)
        width = memory_helper.width
        if matched is None:
            if memory_helper is MemoryPointerHelper8616.MEM_U8:
                byte_matched = _match_indexed_global_byte_address_8616(args[0], evidence_by_base, copies=copies)
                if byte_matched is not None:
                    base_offset, index_expr = byte_matched
                    typed_field_expr = _make_indexed_global_byte_field_expr_from_reference_8616(
                        codegen,
                        args[0],
                        base_offset,
                        index_expr,
                        evidence_by_base,
                    )
                    if typed_field_expr is not None:
                        if stats is not None:
                            stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                        return typed_field_expr
                    value_expr = _make_indexed_global_value_from_stride_evidence_8616(
                        codegen,
                        evidence_by_base,
                        base_offset,
                        2,
                        index_expr,
                        memory_helper.width,
                    )
                    if value_expr is not None:
                        if stats is not None:
                            stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                        return value_expr
            stride_matched = _match_indexed_pointer_expr_with_stride_8616(args[0], copies=copies)
            if stride_matched is not None:
                base_offset, stride, index_expr = stride_matched
                value_expr = _make_indexed_global_value_from_stride_evidence_8616(
                    codegen,
                    evidence_by_base,
                    base_offset,
                    stride,
                    index_expr,
                    memory_helper.width,
                )
                if value_expr is not None:
                    if stats is not None:
                        stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                    return value_expr

    if matched is None:
        _debug_indexed_expr_refusal_8616(
            "indexed_expr_shape",
            args[1] if segment_helper is not None and len(args) >= 2 else args[0] if args else node,
            width=width,
            evidence_keys=tuple(sorted(evidence_by_base)),
        )
        if stats is not None:
            stats.record_indexed(IndexedSegmentedGlobalDecision8616.REFUSED_SHAPE_MISMATCH)
        return None
    if len(matched) == 3:
        base_offset, width, index_expr = matched
    else:
        base_offset, index_expr = matched
    item = _indexed_evidence_for_base_stride_8616(evidence_by_base, base_offset, width)
    if item is None:
        return None
    indexed = _make_indexed_global_value_expr_8616(codegen, item, index_expr, evidence_by_base)
    if indexed is None:
        return None
    if stats is not None:
        stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
    return indexed


def _indexed_global_load_from_site_evidence_8616(
    codegen: CodegenBoundary8616,
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    load_sites_by_ins_addr: dict[int, IndexedSegmentedGlobalLoadSiteEvidence8616],
    *,
    consumed_load_sites: list[IndexedSegmentedGlobalLoadSiteEvidence8616] | None = None,
) -> object | None:
    """Materialize a raw dereference only when its instruction tag has binary load evidence."""

    if not isinstance(node, CUnaryOp) or node.op != "Dereference" or not load_sites_by_ins_addr:
        return None
    ins_addrs = {
        ins_addr
        for child in _iter_c_nodes_deep_8616(node)
        if (ins_addr := _statement_ins_addr_8616(child)) is not None
    }
    matching_sites = [load_sites_by_ins_addr[addr] for addr in ins_addrs if addr in load_sites_by_ins_addr]
    if len(matching_sites) != 1:
        return None
    site = matching_sites[0]
    item = evidence_by_base.get((site.base_offset & 0xFFFF, site.width))
    index_expr = _stack_cvar_for_offset_8616(codegen, site.index_stack_offset)
    if item is None or index_expr is None or site.index_shift < 0 or site.index_shift > 4:
        return None
    materialized = _make_indexed_global_value_from_stride_evidence_8616(
        codegen,
        evidence_by_base,
        site.base_offset,
        1 << site.index_shift,
        index_expr,
        site.width,
    )
    if materialized is not None and consumed_load_sites is not None:
        consumed_load_sites.append(site)
    return materialized


def _indexed_word_load_from_byte_pair_8616(
    codegen: CodegenBoundary8616,
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> CExpression | None:
    if not isinstance(node, CBinaryOp) or node.op != "Or":
        return None

    def _shifted_high_byte(expr: object) -> object | None:
        if not isinstance(expr, CBinaryOp) or expr.op != "Shl":
            return None
        if _constant_int_8616(expr.rhs) != 8:
            return None
        return expr.lhs

    candidates = ((node.lhs, _shifted_high_byte(node.rhs)), (node.rhs, _shifted_high_byte(node.lhs)))
    for low_expr, high_expr in candidates:
        if high_expr is None:
            continue
        low_match = _indexed_byte_load_match_8616(low_expr, evidence_by_base, copies=copies)
        high_match = _indexed_byte_load_match_8616(high_expr, evidence_by_base, copies=copies)
        if low_match is None or high_match is None:
            continue
        low_base, low_index = low_match
        high_base, high_index = high_match
        if ((low_base + 1) & 0xFFFF) != (high_base & 0xFFFF):
            continue
        if not _same_c_expression_8616(low_index, high_index):
            continue
        evidence = evidence_by_base.get((low_base & 0xFFFF, 2))
        if evidence is None:
            continue
        indexed = _make_indexed_global_expr_8616(codegen, evidence, low_index)
        if isinstance(indexed, CExpression):
            return indexed
    return None


def _indexed_byte_load_match_8616(
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> tuple[int, object] | None:
    node = _unwrap_codegen_expr_8616(node)
    memory_helper = _memory_pointer_helper_8616(node)
    if memory_helper is MemoryPointerHelper8616.MEM_U8:
        if not isinstance(node, CFunctionCall):
            return None
        args = tuple(node.args or ())
        if len(args) != 1:
            return None
        matched = _match_indexed_pointer_expr_8616(args[0], 2, copies=copies)
        if matched is not None:
            return matched
        return _match_indexed_global_byte_address_8616(args[0], evidence_by_base, copies=copies)
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None
    matched = _match_indexed_pointer_expr_8616(node.operand, 2, copies=copies)
    if matched is not None:
        return matched
    return _match_indexed_global_byte_address_8616(node.operand, evidence_by_base, copies=copies)


def _near_pointer_table_element_from_ds_offset_8616(
    codegen: CodegenBoundary8616,
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
) -> CExpression | None:
    if not isinstance(node, CIndexedVariable):
        return None
    variable_expr = node.variable
    if not isinstance(variable_expr, CVariable):
        return None
    variable = variable_expr.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    base_addr = variable.addr
    width = variable.size
    raw_name = variable.name
    if not isinstance(base_addr, int) or int(width or 0) != 2 or not isinstance(raw_name, str):
        return None
    evidence = evidence_by_base.get((base_addr & 0xFFFF, 2))
    if evidence is None:
        return None
    name = _sanitize_identifier_8616(raw_name)
    if _sanitize_identifier_8616(evidence.name) != name:
        return None
    record_global_declaration_spec_8616(
        codegen,
        ctype="char *",
        name=name,
        array_len=1,
    )
    return node


def _near_pointer_table_element_from_ds_load_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> object | None:
    if not isinstance(node, CFunctionCall):
        return None
    segment_helper = _segment_load_helper_8616(node)
    if segment_helper is None or int(segment_helper.width) != 2:
        return None
    args = tuple(node.args or ())
    if len(args) != 2 or not _is_ds_segment_expr_8616(project, args[0]):
        return None
    matched = _match_indexed_offset_expr_for_evidence_8616(args[1], evidence_by_base, copies=copies)
    if matched is None:
        return None
    base_offset, width, index_expr = matched
    if int(width) != 2:
        return None
    evidence = evidence_by_base.get((base_offset & 0xFFFF, width))
    if evidence is None:
        return None
    indexed = _make_indexed_global_expr_8616(codegen, evidence, index_expr)
    if not isinstance(indexed, CIndexedVariable):
        return None
    record_global_declaration_spec_8616(
        codegen,
        ctype="char *",
        name=_sanitize_identifier_8616(evidence.name),
        array_len=1,
    )
    return indexed


def _materialize_indexed_global_word_store_pairs_8616(
    root: object,
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False
    statement_roots = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements)]
    if isinstance(root, CStatements) and root not in statement_roots:
        statement_roots.append(root)

    for statements_node in statement_roots:
        statements = list(statements_node.statements or ())
        if not statements:
            continue
        copies: dict[CopyKey8616, object] = {}
        store_facts = _indexed_word_store_facts_for_pairs_8616(evidence_by_base, store_evidence)
        rewritten: list[object] = []
        idx = 0
        local_changed = False
        while idx < len(statements):
            stmt = statements[idx]
            next_stmt = statements[idx + 1] if idx + 1 < len(statements) else None
            replacement = _match_indexed_global_word_store_pair_8616(
                stmt,
                next_stmt,
                project,
                codegen,
                evidence_by_base,
                copies,
                stats,
            )
            if replacement is not None:
                _consume_indexed_word_store_fact_for_pair_8616(stmt, next_stmt, evidence_by_base, copies, store_facts)
                rewritten.append(replacement)
                _record_assignment_copy_8616(replacement, copies)
                idx += 2
                local_changed = True
                changed = True
                continue
            replacement = _match_indexed_global_word_store_pair_from_store_evidence_8616(
                stmt,
                next_stmt,
                project,
                codegen,
                evidence_by_base,
                copies,
                stats,
                store_facts,
            )
            if replacement is not None:
                rewritten.append(replacement)
                _record_assignment_copy_8616(replacement, copies)
                idx += 2
                local_changed = True
                changed = True
                continue
            if idx + 2 < len(statements):
                intervening_stmt = statements[idx + 1]
                following_stmt = statements[idx + 2]
                if _can_move_intervening_assignment_after_word_store_8616(
                    intervening_stmt,
                    stmt,
                    following_stmt,
                ):
                    replacement = _match_indexed_global_word_store_pair_8616(
                        stmt,
                        following_stmt,
                        project,
                        codegen,
                        evidence_by_base,
                        copies,
                        stats,
                    )
                    if replacement is not None:
                        _consume_indexed_word_store_fact_for_pair_8616(
                            stmt,
                            following_stmt,
                            evidence_by_base,
                            copies,
                            store_facts,
                        )
                        rewritten.append(replacement)
                        _record_assignment_copy_8616(replacement, copies)
                        rewritten.append(intervening_stmt)
                        _record_assignment_copy_8616(intervening_stmt, copies)
                        idx += 3
                        local_changed = True
                        changed = True
                        continue
                replacement = _match_indexed_global_word_store_pair_from_store_evidence_8616(
                    stmt,
                    following_stmt,
                    project,
                    codegen,
                    evidence_by_base,
                    copies,
                    stats,
                    store_facts,
                )
                if replacement is not None:
                    rewritten.append(replacement)
                    _record_assignment_copy_8616(replacement, copies)
                    rewritten.append(intervening_stmt)
                    _record_assignment_copy_8616(intervening_stmt, copies)
                    idx += 3
                    local_changed = True
                    changed = True
                    continue
            rewritten.append(stmt)
            _record_assignment_copy_8616(stmt, copies)
            idx += 1
        if local_changed:
            statements_node.statements = rewritten
    return changed


def _indexed_word_store_facts_for_pairs_8616(
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
) -> list[IndexedSegmentedGlobalStoreEvidence8616]:
    facts: list[IndexedSegmentedGlobalStoreEvidence8616] = []
    for fact in sorted(store_evidence, key=lambda item: item.ins_addr):
        if fact.width != 2 or not _store_index_shift_matches_width_8616(fact):
            continue
        if (fact.base_offset & 0xFFFF, fact.width) not in evidence_by_base:
            continue
        facts.append(fact)
    return facts


def _consume_indexed_word_store_fact_for_pair_8616(
    low_stmt: object,
    high_stmt: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    copies: dict[CopyKey8616, object],
    store_facts: list[IndexedSegmentedGlobalStoreEvidence8616],
) -> None:
    matched = _match_indexed_word_store_pair_lvalues_8616(low_stmt, high_stmt, evidence_by_base, copies)
    if matched is None:
        return
    low_base, _low_index = matched
    selected = _select_indexed_word_store_fact_for_pair_8616(low_stmt, low_base, store_facts)
    if selected is None:
        return
    fact_index, _fact = selected
    del store_facts[fact_index]


def _select_indexed_word_store_fact_for_pair_8616(
    low_stmt: object,
    low_base: int,
    store_facts: list[IndexedSegmentedGlobalStoreEvidence8616],
) -> tuple[int, IndexedSegmentedGlobalStoreEvidence8616] | None:
    """Select one word-store fact by exact instruction provenance.

    angr may traverse structured blocks in a different order than binary
    instructions. A single destination match is sufficient, but multiple
    matches require the low-byte C assignment to retain the originating
    instruction address.
    """

    candidates = tuple(
        (index, fact)
        for index, fact in enumerate(store_facts)
        if (fact.base_offset & 0xFFFF) == (low_base & 0xFFFF) and fact.width == 2
    )
    statement_ins_addr = _statement_ins_addr_8616(low_stmt)
    if isinstance(statement_ins_addr, int):
        candidates = tuple(
            candidate for candidate in candidates if candidate[1].ins_addr == statement_ins_addr
        )
    if len(candidates) != 1:
        return None
    return candidates[0]


def _match_indexed_global_word_store_pair_from_store_evidence_8616(
    low_stmt: object,
    high_stmt: object,
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    copies: dict[CopyKey8616, object],
    stats: SegmentedGlobalLoadStats8616,
    store_facts: list[IndexedSegmentedGlobalStoreEvidence8616],
) -> CAssignment | None:
    del project
    matched = _match_indexed_word_store_pair_lvalues_8616(low_stmt, high_stmt, evidence_by_base, copies)
    if matched is None:
        return None
    low_base, _low_index = matched
    item = evidence_by_base.get((low_base & 0xFFFF, 2))
    if item is None:
        return None
    selected = _select_indexed_word_store_fact_for_pair_8616(low_stmt, low_base, store_facts)
    if selected is None:
        return None
    fact_index, fact = selected
    index_expr = _stack_cvar_for_offset_8616(codegen, fact.index_stack_offset)
    source_expr = _indexed_global_store_source_expr_8616(codegen, evidence_by_base, fact)
    if index_expr is None or source_expr is None:
        return None
    lhs = _make_indexed_global_expr_8616(codegen, item, index_expr)
    if lhs is None:
        return None
    _promote_stack_value_expr_to_width_8616(codegen, source_expr, 2)
    del store_facts[fact_index]
    stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
    stats.indexed_store_materialized_count += 1
    tags = low_stmt.tags if isinstance(low_stmt, CAssignment) else None
    return CAssignment(lhs, source_expr, codegen=codegen, tags=tags)


def _match_indexed_word_store_pair_lvalues_8616(
    low_stmt: object,
    high_stmt: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    copies: dict[CopyKey8616, object],
) -> tuple[int, object] | None:
    if high_stmt is None or not isinstance(low_stmt, CAssignment) or not isinstance(high_stmt, CAssignment):
        return None
    low_match = _match_byte_store_lvalue_8616(
        low_stmt.lhs,
        copies=copies,
        evidence_by_base=evidence_by_base,
    )
    high_match = _match_byte_store_lvalue_8616(
        high_stmt.lhs,
        copies=copies,
        evidence_by_base=evidence_by_base,
    )
    if low_match is None or high_match is None:
        return None
    low_base, low_index = low_match
    high_base, high_index = high_match
    if ((low_base + 1) & 0xFFFF) != (high_base & 0xFFFF):
        return None
    if not _same_c_expression_8616(low_index, high_index):
        return None
    return low_base, low_index


def _materialize_indexed_global_byte_store_lvalues_8616(
    root: object,
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    changed = False
    statement_roots = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements)]
    if isinstance(root, CStatements) and root not in statement_roots:
        statement_roots.append(root)

    for statements_node in statement_roots:
        copies: dict[CopyKey8616, object] = {}
        for stmt in tuple(statements_node.statements or ()):
            if isinstance(stmt, CAssignment):
                matched_lvalue = _match_byte_store_lvalue_8616(stmt.lhs, copies=copies)
                replacement = _indexed_global_byte_store_lvalue_8616(
                    codegen,
                    evidence_by_base,
                    stmt.lhs,
                    copies,
                    store_evidence,
                )
                if replacement is not None and not _same_c_expression_8616(stmt.lhs, replacement):
                    stmt.lhs = replacement
                    stats.indexed_byte_store_lvalue_materialized_count += 1
                    stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                    changed = True
                if matched_lvalue is not None:
                    source = _evidenced_indexed_byte_store_source_expr_8616(
                        codegen,
                        evidence_by_base,
                        matched_lvalue[0],
                        _statement_ins_addr_8616(stmt),
                        store_evidence,
                    )
                    if source is not None and not _same_c_expression_8616(stmt.rhs, source):
                        stmt.rhs = source
                        stats.indexed_byte_store_source_materialized_count += 1
                        stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
                        changed = True
            _record_assignment_copy_8616(stmt, copies)
    return changed


def _evidenced_indexed_byte_store_source_expr_8616(
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    base_offset: int,
    statement_ins_addr: int | None,
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
) -> object | None:
    """Recover one byte-store source from one exact decoded instruction fact."""
    if not isinstance(statement_ins_addr, int):
        return None
    candidates = tuple(
        fact
        for fact in store_evidence
        if fact.ins_addr == statement_ins_addr
        and (fact.base_offset & 0xFFFF) == (base_offset & 0xFFFF)
        and fact.width == 1
        and fact.index_shift == 1
        and (
            (isinstance(fact.source_stack_offset, int) and fact.source_stack_width == 1)
            or fact.source_signed_remainder is not None
        )
    )
    if len(candidates) != 1:
        return None
    return _indexed_global_store_source_expr_8616(
        codegen,
        evidence_by_base,
        candidates[0],
    )


def _indexed_global_byte_store_lvalue_8616(
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    lhs: object,
    copies: dict[CopyKey8616, object],
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
) -> object | None:
    matched = _match_byte_store_lvalue_8616(lhs, copies=copies)
    if matched is None:
        return None
    base_offset, index_expr = matched
    evidenced_index_expr = _evidenced_byte_store_index_expr_8616(
        codegen,
        base_offset,
        store_evidence,
    )
    if evidenced_index_expr is not None:
        index_expr = evidenced_index_expr
    address_expr = _make_indexed_global_address_from_stride_evidence_8616(
        codegen,
        evidence_by_base,
        base_offset,
        2,
        index_expr,
    )
    if address_expr is None:
        return None
    helper_name = _memory_pointer_helper_name_for_width_8616(1)
    if helper_name is None:
        return None
    return CFunctionCall(helper_name, None, [address_expr], codegen=codegen)


def _evidenced_byte_store_index_expr_8616(
    codegen: CodegenBoundary8616,
    base_offset: int,
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
) -> object | None:
    """Recover a byte-store index only from one unambiguous decoded stack identity."""

    stack_offsets = {
        fact.index_stack_offset
        for fact in store_evidence
        if (fact.base_offset & 0xFFFF) == (base_offset & 0xFFFF)
        and fact.width == 1
        and fact.index_shift == 1
    }
    if len(stack_offsets) != 1:
        return None
    return _stack_cvar_for_offset_8616(codegen, stack_offsets.pop())


def _can_move_intervening_assignment_after_word_store_8616(
    intervening_stmt: object,
    low_stmt: object,
    high_stmt: object,
) -> bool:
    if not isinstance(intervening_stmt, CAssignment):
        return False
    lhs = intervening_stmt.lhs
    rhs = intervening_stmt.rhs
    if not isinstance(lhs, CVariable):
        return False
    if _rhs_has_obvious_side_effect_8616(rhs):
        return False
    lhs_key = _cvariable_key_8616(lhs)
    if lhs_key is None:
        return False
    low_assignment = _assignment_statement_8616(low_stmt)
    high_assignment = _assignment_statement_8616(high_stmt)
    if low_assignment is None or high_assignment is None:
        return False
    for node in (
        low_assignment.lhs,
        low_assignment.rhs,
        high_assignment.lhs,
        high_assignment.rhs,
    ):
        if _expr_contains_cvariable_key_8616(node, lhs_key):
            return False
    return True


def _expr_contains_cvariable_key_8616(node: object, key: str) -> bool:
    if _cvariable_key_8616(node) == key:
        return True
    for child in _iter_c_nodes_deep_8616(node):
        if child is not node and _cvariable_key_8616(child) == key:
            return True
    return False


def _expr_contains_stack_offset_8616(node: object, offset: int) -> bool:
    if isinstance(node, CVariable):
        variable = node.variable
        if isinstance(variable, SimStackVariable) and variable.offset == offset:
            return True
    for child in _iter_c_nodes_deep_8616(node):
        if isinstance(child, CVariable):
            variable = child.variable
            if isinstance(variable, SimStackVariable) and variable.offset == offset:
                return True
    return False


def _materialize_indexed_global_word_store_lvalues_8616(
    root: object,
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    if not store_evidence:
        return False
    facts_by_name: dict[
        str, list[tuple[IndexedSegmentedGlobalEvidence8616, IndexedSegmentedGlobalStoreEvidence8616]]
    ] = {}
    for fact in store_evidence:
        if not _store_index_shift_matches_width_8616(fact):
            continue
        item = evidence_by_base.get((fact.base_offset & 0xFFFF, fact.width))
        if item is None:
            continue
        facts_by_name.setdefault(_sanitize_identifier_8616(item.name), []).append((item, fact))
    if not facts_by_name:
        return False

    changed = False
    for stmt in _iter_c_nodes_deep_8616(root):
        if not isinstance(stmt, CAssignment):
            continue
        lhs = stmt.lhs
        if not isinstance(lhs, CIndexedVariable):
            continue
        lhs_name = _indexed_global_name_8616(lhs)
        candidates = facts_by_name.get(lhs_name or "")
        if not candidates:
            continue
        indexed_candidates = tuple(enumerate(candidates))
        statement_ins_addr = _statement_ins_addr_8616(stmt)
        if isinstance(statement_ins_addr, int):
            statement_candidates = tuple(
                candidate
                for candidate in indexed_candidates
                if candidate[1][1].ins_addr == statement_ins_addr
            )
        elif len(indexed_candidates) == 1:
            statement_candidates = indexed_candidates
        else:
            statement_candidates = ()
        if len(statement_candidates) != 1:
            stats.record_indexed(
                IndexedSegmentedGlobalDecision8616.REFUSED_SHAPE_MISMATCH
            )
            continue
        lhs_index = lhs.index
        for candidate_index, (item, fact) in statement_candidates:
            source_replacement = _indexed_global_store_source_expr_8616(codegen, evidence_by_base, fact)
            if source_replacement is None:
                source_replacement = _materialize_indexed_global_expr_node_8616(
                    None,
                    codegen,
                    stmt.rhs,
                    evidence_by_base,
                    stats=stats,
                )
            if _same_indexed_global_storage_expr_8616(stmt.rhs, source_replacement):
                source_replacement = None
            lhs_already_matches = _expr_contains_stack_offset_8616(lhs_index, fact.index_stack_offset)
            _debug_indexed_store_lvalue_candidate_8616(
                lhs,
                stmt.rhs,
                lhs_name=lhs_name,
                lhs_already_matches=lhs_already_matches,
                source_replacement=source_replacement,
                fact=fact,
            )
            index_expr = _stack_cvar_for_offset_8616(codegen, fact.index_stack_offset)
            if index_expr is None:
                continue
            replacement = _make_indexed_global_value_expr_8616(
                codegen,
                item,
                index_expr,
                evidence_by_base,
            )
            if (
                isinstance(replacement, CIndexedVariable)
                and _same_c_expression_8616(lhs, replacement)
                and lhs.type == replacement.type
                and any(
                    node is index_expr
                    for node in _iter_c_nodes_deep_8616(lhs.index)
                )
            ):
                replacement = None
            if replacement is None and source_replacement is None:
                continue
            if replacement is not None:
                stmt.lhs = replacement
            if source_replacement is not None and not _same_c_expression_8616(stmt.rhs, source_replacement):
                stmt.rhs = source_replacement
            del candidates[candidate_index]
            stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
            stats.indexed_store_lvalue_materialized_count += 1
            changed = True
            break
    return changed


def _same_indexed_global_storage_expr_8616(lhs: object, rhs: object) -> bool:
    """Compare indexed globals without depending on mutable stack presentation width."""

    if not isinstance(lhs, CIndexedVariable) or not isinstance(rhs, CIndexedVariable):
        return False
    lhs_base = lhs.variable
    rhs_base = rhs.variable
    if not isinstance(lhs_base, CVariable) or not isinstance(rhs_base, CVariable):
        return False
    lhs_memory = lhs_base.variable
    rhs_memory = rhs_base.variable
    if not isinstance(lhs_memory, SimMemoryVariable) or not isinstance(rhs_memory, SimMemoryVariable):
        return False
    if lhs_memory.addr != rhs_memory.addr or lhs_memory.size != rhs_memory.size:
        return False
    return _same_index_storage_expr_8616(lhs.index, rhs.index)


def _same_index_storage_expr_8616(lhs: object, rhs: object) -> bool:
    """Compare an indexed-address expression by exact stack storage identity."""

    if isinstance(lhs, CVariable) and isinstance(rhs, CVariable):
        lhs_variable = lhs.variable
        rhs_variable = rhs.variable
        if isinstance(lhs_variable, SimStackVariable) and isinstance(rhs_variable, SimStackVariable):
            return (
                lhs_variable.offset == rhs_variable.offset
                and lhs_variable.base == rhs_variable.base
                and lhs_variable.region == rhs_variable.region
            )
    if isinstance(lhs, CTypeCast) and isinstance(rhs, CTypeCast):
        return _same_index_storage_expr_8616(lhs.expr, rhs.expr)
    if isinstance(lhs, CBinaryOp) and isinstance(rhs, CBinaryOp):
        return (
            lhs.op == rhs.op
            and _same_index_storage_expr_8616(lhs.lhs, rhs.lhs)
            and _same_index_storage_expr_8616(lhs.rhs, rhs.rhs)
        )
    return _same_c_expression_8616(lhs, rhs)


def _remove_indexed_global_store_source_carriers_8616(
    root: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    store_evidence: tuple[IndexedSegmentedGlobalStoreEvidence8616, ...],
    stats: SegmentedGlobalLoadStats8616,
) -> bool:
    pairs_by_source_key: dict[tuple[int, int], list[tuple[str, str]]] = {}
    for fact in store_evidence:
        if (
            not isinstance(fact.source_base_offset, int)
            or not isinstance(fact.source_width, int)
            or not isinstance(fact.base_offset, int)
            or not isinstance(fact.width, int)
        ):
            continue
        source_key = (fact.source_base_offset & 0xFFFF, fact.source_width)
        dest_item = evidence_by_base.get((fact.base_offset & 0xFFFF, fact.width))
        source_item = evidence_by_base.get(source_key)
        if dest_item is None or source_item is None:
            continue
        pairs_by_source_key.setdefault(source_key, []).append(
            (_sanitize_identifier_8616(dest_item.name), _sanitize_identifier_8616(source_item.name))
        )
    if not pairs_by_source_key:
        return False

    changed = False
    statement_roots = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements)]
    if isinstance(root, CStatements) and root not in statement_roots:
        statement_roots.append(root)
    for statements_node in statement_roots:
        statements = list(statements_node.statements or ())
        if len(statements) < 2:
            continue
        rewritten: list[object] = []
        idx = 0
        local_changed = False
        while idx < len(statements):
            stmt = statements[idx]
            next_stmt = statements[idx + 1] if idx + 1 < len(statements) else None
            read_key = _standalone_indexed_memory_read_key_8616(stmt, evidence_by_base)
            assignment = _assignment_statement_8616(next_stmt)
            if (
                read_key is not None
                and assignment is not None
                and _assignment_matches_indexed_store_source_pair_8616(
                    assignment,
                    pairs_by_source_key.get(read_key, ()),
                )
            ):
                stats.indexed_store_source_carrier_removed_count += 1
                local_changed = True
                changed = True
                idx += 1
                continue
            rewritten.append(stmt)
            idx += 1
        if local_changed:
            statements_node.statements = rewritten
    return changed


def _standalone_indexed_memory_read_key_8616(
    stmt: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
) -> tuple[int, int] | None:
    expr = stmt.expr if isinstance(stmt, CExpressionStatement) else stmt
    indexed_key = _indexed_global_read_key_from_indexed_var_8616(expr, evidence_by_base)
    if indexed_key is not None:
        return indexed_key
    if not isinstance(expr, CFunctionCall):
        return None
    memory_helper = _memory_pointer_helper_8616(expr)
    if memory_helper is None:
        return None
    args = tuple(expr.args or ())
    if len(args) != 1:
        return None
    matched = _match_indexed_pointer_expr_8616(args[0], memory_helper.width)
    if matched is None:
        stride_matched = _match_indexed_pointer_expr_with_stride_8616(args[0])
        if stride_matched is None:
            return None
        base_offset, stride, _index_expr = stride_matched
        if stride != memory_helper.width:
            return None
    else:
        base_offset, _index_expr = matched
    key = (base_offset & 0xFFFF, memory_helper.width)
    return key if key in evidence_by_base else None


def _indexed_global_read_key_from_indexed_var_8616(
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
) -> tuple[int, int] | None:
    if not isinstance(node, CIndexedVariable):
        return None
    base = node.variable
    if not isinstance(base, CVariable):
        return None
    variable = base.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    base_addr = variable.addr
    width = variable.size
    if not isinstance(base_addr, int) or not isinstance(width, int):
        return None
    key = (base_addr & 0xFFFF, width)
    return key if key in evidence_by_base else None


def _assignment_matches_indexed_store_source_pair_8616(
    assignment: CAssignment,
    pairs: Iterable[tuple[str, str]],
) -> bool:
    lhs_name = _indexed_global_name_8616(assignment.lhs)
    rhs_name = _indexed_global_name_8616(assignment.rhs)
    if lhs_name is None or rhs_name is None:
        return False
    return any(lhs_name == dest_name and rhs_name == source_name for dest_name, source_name in pairs)


def _indexed_global_store_source_expr_8616(
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    fact: IndexedSegmentedGlobalStoreEvidence8616,
) -> object | None:
    if isinstance(fact.source_stack_offset, int) and isinstance(fact.source_stack_width, int):
        if fact.source_stack_width != fact.width:
            return None
        source = _stack_cvar_for_offset_8616(codegen, fact.source_stack_offset)
        if source is not None:
            _promote_stack_value_expr_to_width_8616(codegen, source, fact.source_stack_width)
        return source
    if fact.source_signed_remainder is not None:
        remainder = fact.source_signed_remainder
        dividend = _stack_cvar_for_offset_8616(codegen, remainder.dividend_stack_offset)
        divisor = _stack_cvar_for_offset_8616(codegen, remainder.divisor_stack_offset)
        if dividend is None or divisor is None or remainder.width != 2:
            return None
        signed_type = SimTypeShort(True)
        storage_type = SimTypeShort(False)
        source: object = CBinaryOp(
            "Mod",
            CTypeCast(storage_type, signed_type, dividend, codegen=codegen),
            CTypeCast(storage_type, signed_type, divisor, codegen=codegen),
            codegen=codegen,
        )
        if remainder.post_adjust:
            source = CBinaryOp(
                "Add" if remainder.post_adjust > 0 else "Sub",
                source,
                CConstant(abs(remainder.post_adjust), signed_type, codegen=codegen),
                codegen=codegen,
            )
        return source
    if (
        not isinstance(fact.source_base_offset, int)
        or not isinstance(fact.source_width, int)
        or not isinstance(fact.source_index_stack_offset, int)
        or not isinstance(fact.source_index_shift, int)
    ):
        return None
    if not _store_index_shift_matches_width_8616(
        IndexedSegmentedGlobalStoreEvidence8616(
            base_offset=fact.source_base_offset,
            width=fact.source_width,
            index_stack_offset=fact.source_index_stack_offset,
            index_shift=fact.source_index_shift,
            ins_addr=fact.ins_addr,
        )
    ):
        return None
    item = evidence_by_base.get((fact.source_base_offset & 0xFFFF, fact.source_width))
    if item is None:
        return None
    index_expr = _stack_cvar_for_offset_8616(codegen, fact.source_index_stack_offset)
    if index_expr is None:
        return None
    return _make_indexed_global_value_expr_8616(
        codegen,
        item,
        index_expr,
        evidence_by_base,
    )


def _store_index_shift_matches_width_8616(fact: IndexedSegmentedGlobalStoreEvidence8616) -> bool:
    if fact.width == 1:
        return fact.index_shift == 0
    if fact.width == 2:
        return fact.index_shift == 1
    return False


def _indexed_global_name_8616(node: object) -> str | None:
    if not isinstance(node, CIndexedVariable):
        return None
    base = node.variable
    if isinstance(base, CVariable):
        name = base.name
        if isinstance(name, str) and name:
            return _sanitize_identifier_8616(name)
        variable = base.variable
        name = variable.name
        if isinstance(name, str) and name:
            return _sanitize_identifier_8616(name)
    return None


def _stack_cvar_for_offset_8616(codegen: CodegenBoundary8616, offset: int) -> CVariable | None:
    """Find a stack C variable across a dynamic boundary: angr codegen CFunction indexes."""

    cfunc = _codegen_cfunc_optional_8616(codegen)
    variables_in_use = getattr(cfunc, "variables_in_use", {}) if cfunc is not None else {}
    if isinstance(variables_in_use, dict):
        for candidate in variables_in_use.values():
            if isinstance(candidate, CVariable) and _cvar_stack_offset_8616(candidate) == offset:
                return candidate
    roots = _cfunc_roots_8616(cfunc)
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, CVariable) and _cvar_stack_offset_8616(node) == offset:
                return node
    return None


def _cvar_stack_offset_8616(node: object) -> int | None:
    if not isinstance(node, CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimStackVariable):
        return None
    value = variable.offset
    return int(value) if isinstance(value, int) else None


def _match_indexed_global_word_store_pair_8616(
    low_stmt: object,
    high_stmt: object,
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    copies: dict[CopyKey8616, object],
    stats: SegmentedGlobalLoadStats8616,
) -> CAssignment | None:
    if high_stmt is None or not isinstance(low_stmt, CAssignment) or not isinstance(high_stmt, CAssignment):
        _debug_indexed_store_refusal_8616("not_assignment_pair", low_stmt, high_stmt)
        return None
    low_match = _match_byte_store_lvalue_8616(
        low_stmt.lhs,
        copies=copies,
        evidence_by_base=evidence_by_base,
    )
    high_match = _match_byte_store_lvalue_8616(
        high_stmt.lhs,
        copies=copies,
        evidence_by_base=evidence_by_base,
    )
    if low_match is None or high_match is None:
        _debug_indexed_store_refusal_8616(
            "lvalue_shape",
            low_stmt,
            high_stmt,
            high_lvalue=_debug_lvalue_8616(high_stmt.lhs),
            high_rhs=_debug_source_8616(high_stmt.rhs),
            low_lvalue=_debug_lvalue_8616(low_stmt.lhs),
            low_rhs=_debug_source_8616(low_stmt.rhs),
        )
        return None
    low_base, low_index = low_match
    high_base, high_index = high_match
    if ((low_base + 1) & 0xFFFF) != (high_base & 0xFFFF):
        _debug_indexed_store_refusal_8616(
            "non_adjacent_bytes", low_stmt, high_stmt, low_base=low_base, high_base=high_base
        )
        return None
    if not _same_c_expression_8616(low_index, high_index):
        _debug_indexed_store_refusal_8616("index_mismatch", low_stmt, high_stmt, low_base=low_base, high_base=high_base)
        return None
    item = evidence_by_base.get((low_base & 0xFFFF, 2))
    if item is None:
        _debug_indexed_store_refusal_8616(
            "no_word_evidence", low_stmt, high_stmt, low_base=low_base, high_base=high_base
        )
        return None
    word_source = _word_source_for_byte_pair_store_8616(high_stmt.rhs, low_stmt.rhs, copies)
    if word_source is None:
        _debug_indexed_store_refusal_8616(
            "high_source_mismatch",
            low_stmt,
            high_stmt,
            low_base=low_base,
            high_base=high_base,
            high_key=_high_byte_source_key_8616(high_stmt.rhs),
            low_key=_cvariable_key_8616(low_stmt.rhs),
            resolved_high=_debug_resolved_source_8616(high_stmt.rhs, copies),
            resolved_low=_debug_source_8616(low_stmt.rhs),
            copy_keys=",".join(str(key) for key in sorted(copies, key=str)),
        )
        return None
    lhs = _make_indexed_global_expr_8616(codegen, item, low_index)
    if lhs is None:
        return None
    rhs = _materialize_indexed_global_expr_node_8616(
        project,
        codegen,
        word_source,
        evidence_by_base,
        copies=copies,
        stats=stats,
    )
    if rhs is None:
        rhs = word_source
    _promote_stack_value_expr_to_width_8616(codegen, rhs, 2)
    stats.record_indexed(IndexedSegmentedGlobalDecision8616.MATERIALIZED)
    stats.indexed_store_materialized_count += 1
    return CAssignment(lhs, rhs, codegen=codegen, tags=low_stmt.tags)


def _debug_indexed_store_refusal_8616(reason: str, low_stmt: object, high_stmt: object, **fields: object) -> None:
    if not os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        return
    extras = " ".join(f"{key}={value}" for key, value in sorted(fields.items()))
    log.warning(
        "[seg-global-store] refused reason=%s %s low=%s high=%s",
        reason,
        extras,
        type(low_stmt).__name__ if low_stmt is not None else "None",
        type(high_stmt).__name__ if high_stmt is not None else "None",
    )


def _debug_direct_store_refusal_8616(reason: str, low_stmt: object, high_stmt: object, **fields: object) -> None:
    if not os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        return
    extras = " ".join(f"{key}={value}" for key, value in sorted(fields.items()))
    log.warning(
        "[seg-global-direct-store] refused reason=%s %s low=%s high=%s",
        reason,
        extras,
        type(low_stmt).__name__ if low_stmt is not None else "None",
        type(high_stmt).__name__ if high_stmt is not None else "None",
    )


def _debug_lvalue_8616(node: object) -> str:
    """Render lvalue diagnostics from a dynamic boundary: angr codegen call metadata."""

    identity = _direct_global_lvalue_identity_8616(node)
    if identity is not None:
        addr, width = identity
        return f"{type(node).__name__}:addr={addr:#x}:width={width}"
    if isinstance(node, CVariable):
        variable = node.variable
        name = variable.name
        return f"CVariable:{type(variable).__name__}:name={name}"
    if isinstance(node, CFunctionCall):
        callee = node.callee_target or getattr(node.callee_func, "name", None)
        return f"CFunctionCall:{callee}"
    return type(node).__name__


def _debug_indexed_store_lvalue_candidate_8616(
    lhs: object,
    rhs: object,
    *,
    lhs_name: str | None,
    lhs_already_matches: bool,
    source_replacement: object,
    fact: IndexedSegmentedGlobalStoreEvidence8616,
) -> None:
    if not os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        return
    with contextlib.suppress(Exception):
        rhs_text = str(rhs)
    if "rhs_text" not in locals():
        rhs_text = type(rhs).__name__ if rhs is not None else "None"
    log.warning(
        "[seg-global-store-lvalue] lhs=%s lhs_name=%s lhs_matches=%s source_replacement=%s fact=(base=%#x width=%d index_stack=%d shift=%d source_base=%s source_width=%s source_index=%s source_shift=%s) rhs=%s rhs_rendered=%s",
        type(lhs).__name__,
        lhs_name,
        lhs_already_matches,
        type(source_replacement).__name__ if source_replacement is not None else "None",
        fact.base_offset & 0xFFFF,
        fact.width,
        fact.index_stack_offset,
        fact.index_shift,
        None if fact.source_base_offset is None else hex(fact.source_base_offset & 0xFFFF),
        fact.source_width,
        fact.source_index_stack_offset,
        fact.source_index_shift,
        type(rhs).__name__ if rhs is not None else "None",
        rhs_text,
    )


def _debug_indexed_expr_refusal_8616(reason: str, node: object, **fields: object) -> None:
    if not os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        return
    extras = " ".join(f"{key}={value}" for key, value in sorted(fields.items()))
    rendered = _debug_c_repr_8616(node)
    call_name = _cfunction_call_name_8616(node)
    arg_shapes = ()
    if isinstance(node, CFunctionCall):
        rendered_args = []
        for arg in tuple(node.args or ()):
            arg_text = type(arg).__name__
            with contextlib.suppress(Exception):
                arg_text = _debug_c_repr_8616(arg)
            rendered_args.append((type(arg).__name__, arg_text))
        arg_shapes = tuple(rendered_args)
    log.warning(
        "[seg-global-indexed] refused reason=%s %s node=%s call=%s args=%s rendered=%s",
        reason,
        extras,
        type(node).__name__,
        call_name,
        arg_shapes,
        rendered,
    )


def _record_stack_aggregate_type_fact_8616(
    codegen: object,
    stack_variable: SimStackVariable,
    width: int,
    struct_type: SimStruct,
) -> None:
    """Persist one proven stack aggregate type across later CFunction rebuilds."""

    offset = stack_variable.offset
    base = stack_variable.base
    if not isinstance(offset, int) or not isinstance(base, str) or width <= 0:
        return
    fact = StackAggregateTypeFact8616(base, offset, width, struct_type)
    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        existing_facts = typed_codegen._inertia_stack_aggregate_type_facts_8616
    except AttributeError:
        existing_facts = ()
    retained: list[StackAggregateTypeFact8616] = []
    for existing in existing_facts:
        if existing.base != fact.base or existing.offset != fact.offset:
            retained.append(existing)
            continue
        if existing.width != fact.width or existing.struct_type != fact.struct_type:
            raise PipelineHardError(
                "conflicting stack aggregate type facts "
                f"base={fact.base} offset={fact.offset:#x} "
                f"existing={existing.struct_type!r} candidate={fact.struct_type!r}"
            )
    retained.append(fact)
    typed_codegen._inertia_stack_aggregate_type_facts_8616 = tuple(dict.fromkeys(retained))


def _record_named_global_aggregate_type_fact_8616(
    codegen: object,
    global_name: str,
    struct_type: SimStruct,
    array_len: int,
) -> None:
    """Persist one proven global aggregate across later CFunction rebuilds."""

    normalized_name = _sanitize_identifier_8616(global_name)
    if not normalized_name or not struct_type.name or array_len <= 0:
        return
    fact = NamedGlobalAggregateTypeFact8616(normalized_name, struct_type, array_len)
    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        existing_facts = typed_codegen._inertia_named_global_aggregate_type_facts_8616
    except AttributeError:
        existing_facts = ()
    retained: list[NamedGlobalAggregateTypeFact8616] = []
    for existing in existing_facts:
        if existing.global_name != fact.global_name:
            retained.append(existing)
            continue
        if existing.struct_type != fact.struct_type:
            raise PipelineHardError(
                "conflicting named global aggregate facts "
                f"name={fact.global_name} existing={existing.struct_type!r} candidate={fact.struct_type!r}"
            )
        fact = replace(fact, array_len=max(existing.array_len, fact.array_len))
    retained.append(fact)
    typed_codegen._inertia_named_global_aggregate_type_facts_8616 = tuple(dict.fromkeys(retained))


def _promote_stack_value_expr_to_type_8616(
    codegen: CodegenBoundary8616,
    expr: object,
    width: int,
    target_type: SimType,
) -> None:
    """Promote one stack storage identity across angr codegen variable indexes."""

    if width <= 0 or not isinstance(expr, CVariable):
        return
    stack_variable = expr.variable
    if not isinstance(stack_variable, SimStackVariable):
        return
    offset = stack_variable.offset
    if not isinstance(offset, int):
        return
    base = stack_variable.base
    if isinstance(target_type, SimStruct):
        _record_stack_aggregate_type_fact_8616(codegen, stack_variable, width, target_type)
    declaration_type: SimType = target_type
    if isinstance(target_type, SimStruct):
        registered_type = _register_codegen_struct_type_8616(codegen, target_type)
        if registered_type is not None:
            declaration_type = registered_type

    cfunc = _codegen_cfunc_optional_8616(codegen)
    variable_manager: _VariableManagerTypeBoundary8616 | None = None
    if cfunc is not None:
        typed_cfunc = typing.cast(_CFunctionTypeBoundary8616, cfunc)
        try:
            variable_manager = typed_cfunc.variable_manager
        except AttributeError:
            # Dynamic boundary: synthetic CFunction fixtures may omit angr's
            # variable manager.
            variable_manager = None

    def promote_manager_type(variable: SimVariable) -> None:
        """Apply the recovered type to one exact variable-manager identity."""

        if variable_manager is None:
            return
        if isinstance(target_type, SimStruct) and target_type.name:
            variable_manager.set_variable_type(
                variable,
                target_type,
                name=target_type.name,
                override_bot=True,
                all_unified=True,
            )
            return
        variable_manager.set_variable_type(
            variable,
            target_type,
            override_bot=True,
            all_unified=True,
        )

    if variable_manager is not None:
        try:
            managed_variables = tuple(variable_manager.get_variables())
        except AttributeError:
            # Dynamic boundary: small synthetic managers may expose only type
            # assignment, not their complete variable inventory.
            managed_variables = ()
        for managed_variable in managed_variables:
            if _same_stack_storage_8616(managed_variable, stack_variable):
                promote_manager_type(managed_variable)

    def promote_cvar(node: object) -> None:
        """Promote one CVariable while preserving a dynamic boundary: angr codegen unification metadata."""

        if not isinstance(node, CVariable):
            return
        node_var = node.variable
        if not isinstance(node_var, SimStackVariable):
            return
        if node_var.offset != offset or node_var.base != stack_variable.base:
            return
        promote_manager_type(node_var)
        if isinstance(node_var.size, int) and int(node_var.size) < width:
            with contextlib.suppress(Exception):
                node_var.size = width
        if node.variable_type != target_type:
            with contextlib.suppress(Exception):
                node.variable_type = target_type
        unified = getattr(node, "unified_variable", None)
        if unified is not None and getattr(unified, "variable_type", None) != target_type:
            with contextlib.suppress(Exception):
                unified.variable_type = target_type

    promote_cvar(expr)
    # Dynamic boundary: angr CFunction variable indexes are optional on synthetic codegen surfaces.
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for indexed_variable, cvar in tuple(variables_in_use.items()):
            if isinstance(indexed_variable, SimStackVariable):
                if indexed_variable.offset == offset and indexed_variable.base == base:
                    promote_manager_type(indexed_variable)
                    with contextlib.suppress(Exception):
                        indexed_variable.size = max(int(indexed_variable.size or 0), width)
            promote_cvar(cvar)
    # Dynamic boundary: angr CFunction unification metadata is optional across codegen versions.
    unified_locals = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, entries in tuple(unified_locals.items()):
            if not isinstance(variable, SimStackVariable):
                continue
            if variable.offset != offset or variable.base != base:
                continue
            promote_manager_type(variable)
            with contextlib.suppress(Exception):
                variable.size = max(int(variable.size or 0), width)
            if isinstance(entries, set):
                new_entries = set()
                for cvariable, _vartype in entries:
                    promote_cvar(cvariable)
                    new_entries.add((cvariable, declaration_type))
                unified_locals[variable] = new_entries
    for root in _cfunc_roots_8616(cfunc):
        for node in _iter_c_nodes_deep_8616(root):
            promote_cvar(node)
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        manager_types: list[str] = []
        if variable_manager is not None:
            try:
                debug_variables = tuple(variable_manager.get_variables())
            except AttributeError:
                debug_variables = ()
            for debug_variable in debug_variables:
                if not _same_stack_storage_8616(debug_variable, stack_variable):
                    continue
                try:
                    debug_type = variable_manager.get_variable_type(debug_variable)
                except (AttributeError, KeyError):
                    debug_type = None
                manager_types.append(repr(debug_type))
        unified_types: tuple[str, ...] = ()
        if isinstance(unified_locals, dict):
            unified_types = tuple(
                repr(vartype)
                for variable, entries in tuple(unified_locals.items())
                if _same_stack_storage_8616(variable, stack_variable)
                for _cvar, vartype in entries
            )
        log.warning(
            "[seg-global-stack-type] offset=%#x width=%d target=%r declaration=%r manager=%s "
            "manager_types=%s unified_types=%s",
            offset & 0xFFFF,
            width,
            target_type,
            declaration_type,
            variable_manager is not None,
            tuple(manager_types),
            unified_types,
        )


def _is_aggregate_stack_type_8616(candidate: object) -> bool:
    """Return whether one angr type preserves a recovered aggregate layout."""

    if isinstance(candidate, SimStruct):
        return True
    return isinstance(candidate, TypeRef) and isinstance(candidate.type, SimStruct)


def _stack_type_matches_fact_8616(candidate: object, fact: StackAggregateTypeFact8616) -> bool:
    """Return whether one declaration type matches the exact recorded layout."""

    resolved = candidate.type if isinstance(candidate, TypeRef) else candidate
    return isinstance(resolved, SimStruct) and resolved == fact.struct_type


def _same_stack_storage_8616(candidate: object, target: SimStackVariable) -> bool:
    """Return whether a dynamic variable denotes the same BP stack identity."""

    return (
        isinstance(candidate, SimStackVariable)
        and candidate.offset == target.offset
        and candidate.base == target.base
    )


def _stack_storage_has_aggregate_type_8616(codegen: object, expr: CVariable) -> bool:
    """Check all angr declaration indexes for stronger aggregate type evidence."""

    stack_variable = expr.variable
    if not isinstance(stack_variable, SimStackVariable):
        return False
    if _is_aggregate_stack_type_8616(expr.variable_type):
        return True
    cfunc_raw = _codegen_cfunc_optional_8616(codegen)
    if cfunc_raw is None:
        return False
    cfunc = typing.cast(_CFunctionTypeBoundary8616, cfunc_raw)
    try:
        variables_in_use = cfunc.variables_in_use
    except AttributeError:
        variables_in_use = {}
    for variable, cvar in tuple(variables_in_use.items()):
        if not _same_stack_storage_8616(variable, stack_variable):
            continue
        if _is_aggregate_stack_type_8616(cvar.variable_type):
            return True
        try:
            manager_type = cfunc.variable_manager.get_variable_type(variable)
        except (AttributeError, KeyError):
            manager_type = None
        if _is_aggregate_stack_type_8616(manager_type):
            return True
    try:
        managed_variables = tuple(cfunc.variable_manager.get_variables())
    except AttributeError:
        managed_variables = ()
    for variable in managed_variables:
        if not _same_stack_storage_8616(variable, stack_variable):
            continue
        try:
            manager_type = cfunc.variable_manager.get_variable_type(variable)
        except (AttributeError, KeyError):
            manager_type = None
        if _is_aggregate_stack_type_8616(manager_type):
            return True
    try:
        unified_locals = cfunc.unified_local_vars
    except AttributeError:
        unified_locals = {}
    for variable, entries in tuple(unified_locals.items()):
        if not _same_stack_storage_8616(variable, stack_variable):
            continue
        if any(
            _is_aggregate_stack_type_8616(vartype) or _is_aggregate_stack_type_8616(cvar.variable_type)
            for cvar, vartype in entries
        ):
            return True
    for root in _cfunc_roots_8616(cfunc):
        for node in _iter_c_nodes_deep_8616(root):
            if (
                isinstance(node, CVariable)
                and _same_stack_storage_8616(node.variable, stack_variable)
                and _is_aggregate_stack_type_8616(node.variable_type)
            ):
                return True
    return False


def reapply_proven_named_global_aggregate_types_8616(codegen: object) -> bool:
    """Replay Lowering-owned named aggregate declarations after a rebuild."""

    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        raw_facts = typed_codegen._inertia_named_global_aggregate_type_facts_8616
    except AttributeError:
        raw_facts = ()
    facts = tuple(
        dict.fromkeys(
            fact
            for fact in raw_facts
            if isinstance(fact, NamedGlobalAggregateTypeFact8616)
            and isinstance(fact.global_name, str)
            and bool(fact.global_name)
            and isinstance(fact.struct_type, SimStruct)
            and fact.array_len > 0
        )
    )
    cfunc = _codegen_cfunc_optional_8616(codegen)
    classified = 0
    materialized = 0
    failures = 0
    changed = False
    if cfunc is not None:
        for fact in facts:
            registered_type = _register_codegen_struct_type_8616(codegen, fact.struct_type)
            if registered_type is None:
                continue
            classified += 1
            declaration_type = _two_byte_global_struct_declaration_ctype_8616(
                fact.global_name,
                registered=True,
            )
            record_global_declaration_spec_8616(
                codegen,
                ctype=declaration_type,
                name=fact.global_name,
                array_len=fact.array_len,
            )
            if _named_global_aggregate_declaration_materialized_8616(
                codegen,
                fact,
                declaration_type,
            ):
                materialized += 1
                changed = True
            else:
                failures += 1
    stats = NamedGlobalAggregateTypeReplayStats8616(
        raw_fact_count=len(raw_facts),
        normalized_fact_count=len(facts),
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
    )
    typed_codegen._inertia_named_global_aggregate_type_replay_stats_8616 = stats
    if classified > 0 and materialized == 0:
        raise PipelineHardError(
            "named global aggregate replay classified facts without materialization "
            f"raw={stats.raw_fact_count} normalized={stats.normalized_fact_count} "
            f"classified={classified} failures={failures}"
        )
    return changed


def reconcile_registered_named_global_aggregate_declarations_8616(codegen: object) -> bool:
    """Reconcile rollback-restored declarations with the live angr type store.

    Validation rollback may restore an earlier inline declaration while
    retaining a matching registered ``TypeRef`` in the rebuilt CFunction.
    This consumer uses only persistent Lowering facts and that typed registry;
    it does not inspect rendered C.
    """

    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        raw_facts = typed_codegen._inertia_named_global_aggregate_type_facts_8616
    except AttributeError:
        raw_facts = ()
    facts = tuple(
        dict.fromkeys(
            fact
            for fact in raw_facts
            if isinstance(fact, NamedGlobalAggregateTypeFact8616)
            and isinstance(fact.global_name, str)
            and bool(fact.global_name)
            and isinstance(fact.struct_type, SimStruct)
            and fact.array_len > 0
        )
    )
    cfunc = _codegen_cfunc_optional_8616(codegen)
    classified = 0
    materialized = 0
    failures = 0
    changed = False
    registered_types: tuple[SimType, ...] = ()
    if cfunc is not None:
        try:
            type_store = typing.cast(_CFunctionTypeBoundary8616, cfunc).variable_manager.types
        except AttributeError:
            type_store = None
        if type_store is not None:
            try:
                registered_types = tuple(type_store.iter_own())
            except AttributeError:
                # Dynamic boundary: compact synthetic type stores may expose
                # keyed access without angr's TypeStore iterator.
                registered_types = ()
            for fact in facts:
                resolved_types = tuple(
                    registered_type.type if isinstance(registered_type, TypeRef) else registered_type
                    for registered_type in registered_types
                )
                if not any(
                    named_global_aggregate_types_match_8616(
                        candidate,
                        fact.struct_type,
                    )
                    for candidate in resolved_types
                ):
                    try:
                        registered_type = type_store[fact.struct_type.name]
                    except (KeyError, TypeError):
                        continue
                    resolved_type = registered_type.type if isinstance(registered_type, TypeRef) else registered_type
                    if not named_global_aggregate_types_match_8616(
                        resolved_type,
                        fact.struct_type,
                    ):
                        continue
                if not fact.struct_type.name:
                    continue
                classified += 1
                declaration_type = _two_byte_global_struct_declaration_ctype_8616(
                    fact.global_name,
                    registered=True,
                )
                before = tuple(typed_codegen._inertia_global_declaration_specs_8616)
                record_global_declaration_spec_8616(
                    codegen,
                    ctype=declaration_type,
                    name=fact.global_name,
                    array_len=fact.array_len,
                )
                if _named_global_aggregate_declaration_materialized_8616(
                    codegen,
                    fact,
                    declaration_type,
                ):
                    materialized += 1
                    changed = changed or before != typed_codegen._inertia_global_declaration_specs_8616
                else:
                    failures += 1
    stats = NamedGlobalAggregateTypeReplayStats8616(
        raw_fact_count=len(raw_facts),
        normalized_fact_count=len(facts),
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
    )
    typed_codegen._inertia_named_global_aggregate_declaration_reconcile_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        log.warning(
            "[named-global-aggregate-reconcile] raw=%d normalized=%d classified=%d "
            "materialized=%d failures=%d cfunc=%s facts=%s registered=%s specs=%s",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            cfunc is not None,
            tuple((fact.global_name, fact.struct_type.name, fact.array_len) for fact in facts),
            tuple(repr(registered_type) for registered_type in registered_types),
            tuple(typed_codegen._inertia_global_declaration_specs_8616),
        )
    if classified > 0 and materialized == 0:
        raise PipelineHardError(
            "named global aggregate declaration reconcile classified facts without materialization "
            f"raw={stats.raw_fact_count} normalized={stats.normalized_fact_count} "
            f"classified={classified} failures={failures}"
        )
    return changed


def named_global_aggregate_types_match_8616(
    candidate: object,
    expected: SimStruct,
) -> bool:
    """Return whether two angr types carry the same exact named byte layout."""

    if not isinstance(candidate, SimStruct):
        return False
    if candidate.name != expected.name or candidate.pack != expected.pack:
        return False
    if tuple(candidate.fields) != tuple(expected.fields):
        return False
    for field_name, expected_field in expected.fields.items():
        candidate_field = candidate.fields[field_name]
        if not isinstance(candidate_field, SimTypeChar) or not isinstance(expected_field, SimTypeChar):
            return False
        if candidate_field.signed != expected_field.signed:
            return False
    return True


def _named_global_aggregate_declaration_materialized_8616(
    codegen: object,
    fact: NamedGlobalAggregateTypeFact8616,
    declaration_type: NamedAggregateDeclarationCType8616,
) -> bool:
    """Return whether the serialized declaration contains the registered view."""

    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        specs = tuple(typing.cast(Iterable[object], typed_codegen._inertia_global_declaration_specs_8616))
    except AttributeError:
        return False
    for spec in specs:
        if not isinstance(spec, (tuple, list)) or len(spec) != 3:
            continue
        ctype, name, array_len = spec
        if (
            ctype == declaration_type.c_name
            and name == fact.global_name
            and isinstance(array_len, int)
            and array_len >= fact.array_len
        ):
            return True
    return False


def reapply_proven_stack_aggregate_types_8616(codegen: object) -> bool:
    """Replay Lowering-owned aggregate types after a CFunction lifecycle rebuild.

    This consumer does not infer types from rendered C or expression shape. It
    applies only persistent facts recorded when binary load-site evidence first
    classified and materialized the aggregate stack copy.
    """

    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        raw_facts = typed_codegen._inertia_stack_aggregate_type_facts_8616
    except AttributeError:
        raw_facts = ()
    facts = tuple(
        dict.fromkeys(
            fact
            for fact in raw_facts
            if isinstance(fact, StackAggregateTypeFact8616)
            and isinstance(fact.base, str)
            and isinstance(fact.offset, int)
            and fact.width > 0
        )
    )
    cfunc = _codegen_cfunc_optional_8616(codegen)
    classified = 0
    materialized = 0
    failures = 0
    changed = False
    if cfunc is not None:
        candidates: list[CVariable] = []
        typed_cfunc = typing.cast(_CFunctionTypeBoundary8616, cfunc)
        try:
            candidates.extend(typed_cfunc.variables_in_use.values())
        except AttributeError:
            pass
        try:
            for entries in typed_cfunc.unified_local_vars.values():
                candidates.extend(cvar for cvar, _vartype in entries)
        except AttributeError:
            pass
        for root in _cfunc_roots_8616(cfunc):
            candidates.extend(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CVariable))
        candidates = list({id(candidate): candidate for candidate in candidates}.values())
        for fact in facts:
            matching = [
                candidate
                for candidate in candidates
                if isinstance(candidate.variable, SimStackVariable)
                and candidate.variable.base == fact.base
                and candidate.variable.offset == fact.offset
            ]
            if not matching:
                continue
            classified += 1
            was_materialized = all(_stack_type_matches_fact_8616(candidate.variable_type, fact) for candidate in matching)
            _promote_stack_value_expr_to_type_8616(codegen, matching[0], fact.width, fact.struct_type)
            if _stack_storage_has_aggregate_type_8616(codegen, matching[0]):
                materialized += 1
                changed = changed or not was_materialized
            else:
                failures += 1
    stats = StackAggregateTypeReplayStats8616(
        raw_fact_count=len(raw_facts),
        normalized_fact_count=len(facts),
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
    )
    typed_codegen._inertia_stack_aggregate_type_replay_stats_8616 = stats
    if classified > 0 and materialized == 0:
        raise PipelineHardError(
            "stack aggregate type replay classified facts without materialization "
            f"raw={stats.raw_fact_count} normalized={stats.normalized_fact_count} "
            f"classified={classified} failures={failures}"
        )
    return changed


def _field_projection_source_8616(
    expression: object,
    fact: StackAggregateFieldProjectionFact8616,
) -> tuple[CVariable, bool, CTypeCast | None] | None:
    """Match one expression against a persistent stack field-projection fact."""

    cast_expr = expression if isinstance(expression, CTypeCast) else None
    candidate = cast_expr.expr if cast_expr is not None else expression
    already_projected = False
    if isinstance(candidate, CVariableField):
        expected_field = _two_byte_global_struct_field_name_8616(fact.field_offset)
        if candidate.field.field != expected_field:
            return None
        candidate = candidate.variable
        already_projected = True
    if not isinstance(candidate, CVariable):
        return None
    variable = candidate.variable
    if (
        not isinstance(variable, SimStackVariable)
        or variable.base != fact.source_base
        or variable.offset != fact.source_offset
    ):
        return None
    return candidate, already_projected, cast_expr


def stack_aggregate_field_projection_facts_8616(
    codegen: object,
) -> tuple[StackAggregateFieldProjectionFact8616, ...]:
    """Return the owned typed stack field-projection fact contract."""

    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        facts = typed_codegen._inertia_stack_aggregate_field_projection_facts_8616
    except AttributeError:
        return ()
    if not isinstance(facts, tuple):
        raise TypeError(
            "stack aggregate field projection facts must be a tuple"
        )
    if not all(
        isinstance(fact, StackAggregateFieldProjectionFact8616)
        for fact in facts
    ):
        raise TypeError(
            "stack aggregate field projection facts must contain only "
            "StackAggregateFieldProjectionFact8616"
        )
    return facts


def named_global_aggregate_type_facts_8616(
    codegen: object,
) -> tuple[NamedGlobalAggregateTypeFact8616, ...]:
    """Return the owned typed named-global aggregate fact contract."""

    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        facts = typed_codegen._inertia_named_global_aggregate_type_facts_8616
    except AttributeError:
        return ()
    if not isinstance(facts, tuple):
        raise TypeError("named global aggregate type facts must be a tuple")
    if not all(
        isinstance(fact, NamedGlobalAggregateTypeFact8616)
        for fact in facts
    ):
        raise TypeError(
            "named global aggregate type facts must contain only "
            "NamedGlobalAggregateTypeFact8616"
        )
    return facts


def indexed_global_stack_aggregate_copy_facts_8616(
    codegen: object,
) -> tuple[IndexedGlobalStackAggregateCopyFact8616, ...]:
    """Return the owned typed indexed-global aggregate-copy fact contract."""

    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        facts = typed_codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616
    except AttributeError:
        return ()
    if not isinstance(facts, tuple):
        raise TypeError(
            "indexed global stack aggregate copy facts must be a tuple"
        )
    if not all(
        isinstance(fact, IndexedGlobalStackAggregateCopyFact8616)
        for fact in facts
    ):
        raise TypeError(
            "indexed global stack aggregate copy facts must contain only "
            "IndexedGlobalStackAggregateCopyFact8616"
        )
    return facts


def reapply_proven_stack_aggregate_field_projections_8616(codegen: object) -> bool:
    """Replay Lowering-owned field projections after a CFunction rebuild."""

    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    raw_facts = stack_aggregate_field_projection_facts_8616(codegen)
    facts = tuple(
        dict.fromkeys(
            fact
            for fact in raw_facts
            if isinstance(fact, StackAggregateFieldProjectionFact8616)
            and isinstance(fact.source_base, str)
            and isinstance(fact.destination_base, str)
            and isinstance(fact.source_offset, int)
            and isinstance(fact.destination_offset, int)
            and fact.field_offset >= 0
        )
    )
    cfunc = _codegen_cfunc_optional_8616(codegen)
    assignments: list[CAssignment] = []
    if cfunc is not None:
        for root in _cfunc_roots_8616(cfunc):
            assignments.extend(node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CAssignment))
    assignments = list({id(assignment): assignment for assignment in assignments}.values())
    classified = 0
    materialized = 0
    failures = 0
    changed = False
    for fact in facts:
        matches: list[tuple[CAssignment, CVariable, bool, CTypeCast | None]] = []
        for assignment in assignments:
            destination = assignment.lhs
            if not isinstance(destination, CVariable):
                continue
            destination_variable = destination.variable
            if (
                not isinstance(destination_variable, SimStackVariable)
                or destination_variable.base != fact.destination_base
                or destination_variable.offset != fact.destination_offset
            ):
                continue
            source_match = _field_projection_source_8616(assignment.rhs, fact)
            if source_match is not None:
                source, already_projected, cast_expr = source_match
                matches.append((assignment, source, already_projected, cast_expr))
        if not matches:
            continue
        classified += 1
        fact_materialized = False
        for assignment, source, already_projected, cast_expr in matches:
            if already_projected and cast_expr is not None:
                fact_materialized = True
                continue
            if already_projected:
                field_expr = assignment.rhs
            else:
                field_expr = CVariableField(
                    source,
                    CStructField(
                        fact.struct_type,
                        fact.field_offset,
                        _two_byte_global_struct_field_name_8616(fact.field_offset),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                )
            if cast_expr is not None:
                cast_expr.expr = field_expr
            else:
                assignment.rhs = CTypeCast(
                    fact.cast_source_type,
                    fact.cast_destination_type,
                    field_expr,
                    codegen=codegen,
                )
            changed = True
            fact_materialized = True
        if fact_materialized:
            materialized += 1
        else:
            failures += 1
    stats = StackAggregateFieldProjectionReplayStats8616(
        raw_fact_count=len(raw_facts),
        normalized_fact_count=len(facts),
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
    )
    typed_codegen._inertia_stack_aggregate_field_projection_replay_stats_8616 = stats
    if classified > 0 and materialized == 0:
        raise PipelineHardError(
            "stack aggregate field replay classified facts without materialization "
            f"raw={stats.raw_fact_count} normalized={stats.normalized_fact_count} "
            f"classified={classified} failures={failures}"
        )
    return changed


def _promote_stack_value_expr_to_width_8616(codegen: CodegenBoundary8616, expr: object, width: int) -> None:
    """Promote stack value width across a dynamic boundary: angr codegen CFunction indexes."""

    if width <= 1 or not isinstance(expr, CVariable):
        return
    if _stack_storage_has_aggregate_type_8616(codegen, expr):
        if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
            stack_variable = expr.variable
            stack_offset = stack_variable.offset if isinstance(stack_variable, SimStackVariable) else None
            log.warning(
                "[seg-global-stack-type] refused scalar demotion offset=%r width=%d",
                stack_offset,
                width,
            )
        return
    _promote_stack_value_expr_to_type_8616(codegen, expr, width, _type_for_width_8616(width))


def _stack_index_identity_and_adjustment_8616(
    expression: object,
) -> tuple[str, int, int] | None:
    """Return one BP-stack index identity and its logical element adjustment."""

    if isinstance(expression, CTypeCast):
        return _stack_index_identity_and_adjustment_8616(expression.expr)
    if isinstance(expression, CVariable):
        variable = expression.variable
        if (
            isinstance(variable, SimStackVariable)
            and isinstance(variable.base, str)
            and isinstance(variable.offset, int)
        ):
            return variable.base, variable.offset, 0
        return None
    if not isinstance(expression, CBinaryOp) or expression.op not in {"Add", "Sub"}:
        return None
    base = _stack_index_identity_and_adjustment_8616(expression.lhs)
    amount = _constant_int_8616(expression.rhs)
    if base is None or amount is None:
        return None
    base_name, base_offset, adjustment = base
    return (
        base_name,
        base_offset,
        adjustment + amount if expression.op == "Add" else adjustment - amount,
    )


def _record_indexed_global_stack_aggregate_copy_fact_8616(
    codegen: object,
    *,
    source: CIndexedVariable,
    destination: CVariable,
    struct_type: SimStruct,
    load_site: IndexedSegmentedGlobalLoadSiteEvidence8616,
    store_site: IndexedSegmentedGlobalStackStore8616,
) -> None:
    """Persist one exact Lowering-proven whole aggregate copy."""

    source_variable = source.variable
    source_storage = (
        source_variable.variable
        if isinstance(source_variable, CVariable)
        else None
    )
    destination_storage = destination.variable
    index_identity = _stack_index_identity_and_adjustment_8616(source.index)
    if (
        not isinstance(source_storage, SimMemoryVariable)
        or not isinstance(source_storage.addr, int)
        or not isinstance(destination_storage, SimStackVariable)
        or not isinstance(destination_storage.base, str)
        or not isinstance(destination_storage.offset, int)
        or index_identity is None
    ):
        return
    index_base, index_offset, index_adjustment = index_identity
    logical_source_offset = (
        source_storage.addr + index_adjustment * load_site.width
    ) & 0xFFFF
    if (
        index_base != "bp"
        or destination_storage.base != "bp"
        or index_offset != load_site.index_stack_offset
        or load_site.width != store_site.width
        or load_site.width <= 0
        or load_site.index_shift < 0
        or (1 << load_site.index_shift) != load_site.width
        or logical_source_offset != load_site.base_offset & 0xFFFF
    ):
        return
    fact = IndexedGlobalStackAggregateCopyFact8616(
        source_global_offset=source_storage.addr & 0xFFFF,
        source_index_base=index_base,
        source_index_offset=index_offset,
        source_index_adjustment=index_adjustment,
        destination_base=destination_storage.base,
        destination_offset=destination_storage.offset,
        width=load_site.width,
        struct_type=struct_type,
        load_ins_addr=load_site.ins_addr,
        store_ins_addr=store_site.ins_addr,
    )
    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        existing_facts = typed_codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616
    except AttributeError:
        existing_facts = ()
    retained: list[IndexedGlobalStackAggregateCopyFact8616] = []
    for existing in existing_facts:
        same_evidence = (
            existing.load_ins_addr == fact.load_ins_addr
            and existing.store_ins_addr == fact.store_ins_addr
        )
        if same_evidence and existing != fact:
            raise PipelineHardError(
                "conflicting indexed global stack aggregate copy facts "
                f"load={fact.load_ins_addr:#x} store={fact.store_ins_addr:#x}"
            )
        retained.append(existing)
    retained.append(fact)
    typed_codegen._inertia_indexed_global_stack_aggregate_copy_facts_8616 = tuple(
        dict.fromkeys(retained)
    )


def _promote_stack_assignment_aggregate_types_8616(
    codegen: CodegenBoundary8616,
    root: object,
    load_site_evidence: tuple[IndexedSegmentedGlobalLoadSiteEvidence8616, ...],
) -> int:
    """Propagate aggregate types only to exact binary-proven BP store destinations."""

    promoted: set[tuple[int, int]] = set()
    proven_copies: dict[
        tuple[int, int],
        list[
            tuple[
                IndexedSegmentedGlobalLoadSiteEvidence8616,
                IndexedSegmentedGlobalStackStore8616,
            ]
        ],
    ] = {}
    for load in load_site_evidence:
        for store in load.stack_stores:
            if load.width != store.width:
                continue
            proven_copies.setdefault(
                (store.stack_offset, store.width),
                [],
            ).append((load, store))
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CAssignment):
            continue
        lhs = node.lhs
        rhs = node.rhs
        if not isinstance(lhs, CVariable) or not isinstance(rhs, CIndexedVariable):
            continue
        stack_variable = lhs.variable
        aggregate_type = rhs.type
        if (
            not isinstance(stack_variable, SimStackVariable)
            or int(stack_variable.size or 0) != 2
            or not _is_two_byte_global_struct_type_8616(aggregate_type)
        ):
            continue
        offset = stack_variable.offset
        if not isinstance(offset, int):
            continue
        identity = (offset, int(stack_variable.size))
        candidate_copies = proven_copies.get(identity, ())
        if not candidate_copies or identity in promoted:
            continue
        _promote_stack_value_expr_to_type_8616(codegen, lhs, 2, aggregate_type)
        promoted.add(identity)
        source_index = _stack_index_identity_and_adjustment_8616(rhs.index)
        if source_index is None:
            continue
        _index_base, index_offset, _index_adjustment = source_index
        matching_copies = tuple(
            (load, store)
            for load, store in candidate_copies
            if load.index_stack_offset == index_offset
            and load.index_shift >= 0
            and (1 << load.index_shift) == load.width
        )
        if len(matching_copies) != 1:
            continue
        load_site, store_site = matching_copies[0]
        _record_indexed_global_stack_aggregate_copy_fact_8616(
            codegen,
            source=rhs,
            destination=lhs,
            struct_type=aggregate_type,
            load_site=load_site,
            store_site=store_site,
        )
    return len(promoted)


def _record_stack_aggregate_field_projection_fact_8616(
    codegen: object,
    destination: CVariable,
    source: CVariable,
    struct_type: SimStruct,
    field_offset: int,
    cast_source_type: SimType | None,
    cast_destination_type: SimTypeChar,
) -> None:
    """Persist one typed stack field projection across CFunction rebuilds."""

    destination_variable = destination.variable
    source_variable = source.variable
    if not isinstance(destination_variable, SimStackVariable) or not isinstance(source_variable, SimStackVariable):
        return
    if (
        not isinstance(destination_variable.base, str)
        or not isinstance(destination_variable.offset, int)
        or not isinstance(source_variable.base, str)
        or not isinstance(source_variable.offset, int)
    ):
        return
    fact = StackAggregateFieldProjectionFact8616(
        source_base=source_variable.base,
        source_offset=source_variable.offset,
        destination_base=destination_variable.base,
        destination_offset=destination_variable.offset,
        field_offset=field_offset,
        struct_type=struct_type,
        cast_source_type=cast_source_type,
        cast_destination_type=cast_destination_type,
    )
    typed_codegen = typing.cast(_CodegenStackAggregateFactBoundary8616, codegen)
    try:
        existing_facts = typed_codegen._inertia_stack_aggregate_field_projection_facts_8616
    except AttributeError:
        existing_facts = ()
    retained: list[StackAggregateFieldProjectionFact8616] = []
    for existing in existing_facts:
        same_storage = (
            existing.source_base == fact.source_base
            and existing.source_offset == fact.source_offset
            and existing.destination_base == fact.destination_base
            and existing.destination_offset == fact.destination_offset
        )
        if not same_storage:
            retained.append(existing)
            continue
        if (
            existing.field_offset != fact.field_offset
            or existing.struct_type != fact.struct_type
            or existing.cast_source_type != fact.cast_source_type
            or existing.cast_destination_type != fact.cast_destination_type
        ):
            raise PipelineHardError(
                "conflicting stack aggregate projection facts "
                f"source={fact.source_base}:{fact.source_offset:#x} "
                f"destination={fact.destination_base}:{fact.destination_offset:#x}"
            )
    retained.append(fact)
    typed_codegen._inertia_stack_aggregate_field_projection_facts_8616 = tuple(dict.fromkeys(retained))


def _project_two_byte_aggregate_char_casts_8616(codegen: CodegenBoundary8616, root: object) -> int:
    """Project low-byte scalar casts after binary evidence promotes their source to an aggregate.

    A pre-promotion ``(char)word`` expression denotes the low byte.  Once the
    same two-byte storage is proven to be an aggregate, casting the aggregate
    itself is invalid C; its equivalent typed expression is a cast of field 0.
    """

    projected = 0
    for assignment in _iter_c_nodes_deep_8616(root):
        if not isinstance(assignment, CAssignment):
            continue
        cast_expr = assignment.rhs
        if not isinstance(cast_expr, CTypeCast) or not isinstance(cast_expr.dst_type, SimTypeChar):
            continue
        aggregate_expr = cast_expr.expr
        if not isinstance(aggregate_expr, CVariable) or not isinstance(assignment.lhs, CVariable):
            continue
        aggregate_type = aggregate_expr.type
        if not _is_two_byte_global_struct_type_8616(aggregate_type):
            continue
        _record_stack_aggregate_field_projection_fact_8616(
            codegen,
            assignment.lhs,
            aggregate_expr,
            aggregate_type,
            0,
            cast_expr.src_type,
            cast_expr.dst_type,
        )
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CTypeCast) or not isinstance(node.dst_type, SimTypeChar):
            continue
        aggregate_expr = node.expr
        if not isinstance(aggregate_expr, CExpression):
            continue
        aggregate_type = aggregate_expr.type
        if not _is_two_byte_global_struct_type_8616(aggregate_type):
            continue
        node.expr = CVariableField(
            aggregate_expr,
            CStructField(
                aggregate_type,
                0,
                _two_byte_global_struct_field_name_8616(0),
                codegen=codegen,
            ),
            codegen=codegen,
        )
        projected += 1
    return projected


def recover_compare_register_global_carriers_8616(
    summaries: list[InsnSummary8616],
) -> tuple[CompareRegisterGlobalCarrierEvidence8616, ...]:
    """Recover register carriers that compare values loaded from globals."""

    reg_sources: dict[str, tuple[int, int]] = {}
    recovered: dict[tuple[str, int], CompareRegisterGlobalCarrierEvidence8616] = {}

    for insn in summaries:
        mnemonic = insn.mnemonic.lower()
        if mnemonic == "mov" and insn.op0_kind == "reg":
            reg_name = str(insn.op0_value or "").lower()
            if insn.op1_kind == "direct_mem" and isinstance(insn.op1_value, int):
                width = int(insn.op1_size or insn.op0_size or 2)
                reg_sources[reg_name] = (int(insn.op1_value) & 0xFFFF, width)
            else:
                reg_sources.pop(reg_name, None)
            continue

        if mnemonic == "cmp":
            for kind, value in ((insn.op0_kind, insn.op0_value), (insn.op1_kind, insn.op1_value)):
                if kind != "reg":
                    continue
                reg_name = str(value or "").lower()
                source = reg_sources.get(reg_name)
                if source is None:
                    continue
                offset, width = source
                recovered[(reg_name, offset)] = CompareRegisterGlobalCarrierEvidence8616(
                    reg_name=reg_name,
                    offset=offset,
                    width=width,
                )
            continue

        for reg_name in _written_registers_8616(insn):
            reg_sources.pop(reg_name, None)

    return tuple(recovered[key] for key in sorted(recovered))


def recover_dword_global_zero_test_evidence_8616(
    summaries: list[InsnSummary8616],
) -> tuple[DwordGlobalZeroTestEvidence8616, ...]:
    """Recover MOV/OR/Jcc evidence that tests a direct dword global for zero."""

    reg_sources: dict[str, tuple[int, int]] = {}
    recovered: dict[tuple[int, str], DwordGlobalZeroTestEvidence8616] = {}

    for index, insn in enumerate(summaries):
        mnemonic = insn.mnemonic.lower()
        if mnemonic == "mov" and insn.op0_kind == "reg":
            reg_name = str(insn.op0_value or "").lower()
            if insn.op1_kind == "direct_mem" and isinstance(insn.op1_value, int):
                width = int(insn.op1_size or insn.op0_size or 2)
                reg_sources[reg_name] = (int(insn.op1_value) & 0xFFFF, width)
            else:
                reg_sources.pop(reg_name, None)
            continue

        if mnemonic == "or" and insn.op0_kind == "reg" and insn.op1_kind == "direct_mem":
            reg_name = str(insn.op0_value or "").lower()
            prior = reg_sources.get(reg_name)
            if prior is not None and isinstance(insn.op1_value, int):
                prior_offset, prior_width = prior
                current_offset = int(insn.op1_value) & 0xFFFF
                current_width = int(insn.op1_size or insn.op0_size or prior_width or 2)
                if prior_width == 2 and current_width == 2:
                    low_offset = min(prior_offset, current_offset)
                    high_offset = max(prior_offset, current_offset)
                    next_insn = summaries[index + 1] if index + 1 < len(summaries) else None
                    next_mnemonic = next_insn.mnemonic.lower() if next_insn is not None else ""
                    if ((low_offset + 2) & 0xFFFF) == high_offset and next_mnemonic.startswith("j"):
                        recovered[(low_offset, reg_name)] = DwordGlobalZeroTestEvidence8616(
                            base_offset=low_offset,
                            low_offset=low_offset,
                            high_offset=high_offset,
                            reg_name=reg_name,
                        )
            reg_sources.pop(reg_name, None)
            continue

        for reg_name in _written_registers_8616(insn):
            reg_sources.pop(reg_name, None)

    return tuple(recovered[key] for key in sorted(recovered))


def materialize_compare_register_global_carriers_from_evidence_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    named_evidence: tuple[NamedGlobalEvidence8616, ...],
    compare_evidence: tuple[CompareRegisterGlobalCarrierEvidence8616, ...],
    *,
    stats: SegmentedGlobalLoadStats8616 | None = None,
) -> bool:
    """Materialize compare-register globals from already-recovered evidence."""

    if stats is None:
        stats = SegmentedGlobalLoadStats8616()
    if not compare_evidence:
        stats.record_compare(CompareRegisterGlobalCarrierDecision8616.REFUSED_NO_EVIDENCE)
        return False
    cfunc = codegen.cfunc
    if cfunc is None:
        stats.record_compare(CompareRegisterGlobalCarrierDecision8616.REFUSED_NO_CFUNC)
        return False

    named_by_offset = {item.offset & 0xFFFF: item for item in named_evidence}
    evidence_by_reg: dict[str, CompareRegisterGlobalCarrierEvidence8616] = {}
    for item in compare_evidence:
        if item.reg_name in evidence_by_reg and evidence_by_reg[item.reg_name].offset != item.offset:
            evidence_by_reg.pop(item.reg_name, None)
            continue
        evidence_by_reg[item.reg_name] = item

    created: dict[tuple[str, int], object] = {}
    changed = False
    for root in _cfunc_roots_8616(cfunc):
        for node in _iter_c_nodes_deep_8616(root):
            if not _is_comparison_binary_op_8616(node):
                continue
            if not isinstance(node, CBinaryOp):
                continue
            for attr in ("lhs", "rhs"):
                original = node.lhs if attr == "lhs" else node.rhs
                reg_name = _cvariable_register_name_8616(project, original)
                if reg_name is None:
                    continue
                evidence = evidence_by_reg.get(reg_name)
                if evidence is None:
                    continue
                replacement = created.get((reg_name, evidence.offset))
                if replacement is None:
                    replacement = _make_global_value_expr_8616(
                        project,
                        codegen,
                        named_by_offset.get(evidence.offset & 0xFFFF),
                        evidence,
                    )
                    created[(reg_name, evidence.offset)] = replacement
                if attr == "lhs":
                    node.lhs = replacement
                else:
                    node.rhs = replacement
                stats.record_compare(CompareRegisterGlobalCarrierDecision8616.MATERIALIZED)
                changed = True
    if compare_evidence and not changed:
        stats.record_compare(CompareRegisterGlobalCarrierDecision8616.REFUSED_NO_MATCHING_GLOBAL)
    return changed


def _collect_named_global_evidence_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: SyntheticGlobalsBoundary8616,
    *,
    cod_metadata: CodMetadataBoundary8616 = None,
) -> tuple[NamedGlobalEvidence8616, ...]:
    items: dict[int, NamedGlobalEvidence8616] = {}
    if isinstance(synthetic_globals, dict):
        for raw_offset, raw_entry in synthetic_globals.items():
            if not isinstance(raw_offset, int) or not isinstance(raw_entry, tuple) or len(raw_entry) < 2:
                continue
            raw_name, raw_width = raw_entry[0], raw_entry[1]
            if isinstance(raw_name, str) and raw_name:
                width = int(raw_width) if isinstance(raw_width, int) and raw_width > 0 else 1
                items[raw_offset & 0xFFFF] = NamedGlobalEvidence8616(raw_offset & 0xFFFF, raw_name, width)
    # Dynamic boundary: angr project knowledge bases expose labels at runtime.
    labels = getattr(getattr(project, "kb", None), "labels", None)
    if isinstance(labels, dict):
        for raw_offset, raw_name in labels.items():
            if (
                isinstance(raw_offset, int)
                and isinstance(raw_name, str)
                and raw_name
                and (raw_offset & 0xFFFF) not in items
            ):
                items[raw_offset & 0xFFFF] = NamedGlobalEvidence8616(raw_offset & 0xFFFF, raw_name, 2)
    return tuple(items[offset] for offset in sorted(items))


def _direct_word_global_load_offsets_8616(project: ProjectBoundary8616, codegen: CodegenBoundary8616) -> tuple[int, ...]:
    """Find direct word global loads from a dynamic boundary: third-party Capstone metadata."""

    function = _active_function_8616(project, codegen)
    if function is None:
        return ()
    # Dynamic boundary: angr function objects expose addr/size at runtime.
    addr = getattr(function, "addr", None)
    if not isinstance(addr, int):
        return ()
    # Dynamic boundary: angr function objects expose addr/size at runtime.
    size = getattr(function, "size", None)
    size = int(size) if isinstance(size, int) and size > 0 else 0x300
    try:
        code = bytes(project.loader.memory.load(addr, max(1, min(size, 0x300))))
    except Exception:
        return ()
    # Dynamic boundary: angr project arch exposes capstone when available.
    capstone = getattr(getattr(project, "arch", None), "capstone", None)
    if capstone is None:
        return ()
    try:
        capstone.detail = True
        insns = tuple(capstone.disasm(code, addr))
    except Exception:
        return ()
    offsets: set[int] = set()
    for insn in insns:
        if str(getattr(insn, "mnemonic", "")).lower() != "mov":
            continue
        operands = _capstone_operands_8616(insn)
        if len(operands) < 2:
            continue
        dst, src = operands[0], operands[1]
        if int(getattr(dst, "type", -1)) != 1 or int(getattr(src, "type", -1)) != 3:
            continue
        if getattr(src, "size", None) != 2:
            continue
        mem = getattr(src, "mem", None)
        if mem is None:
            continue
        if int(getattr(mem, "base", 0) or 0) != 0 or int(getattr(mem, "index", 0) or 0) != 0:
            continue
        disp = getattr(mem, "disp", None)
        if isinstance(disp, int) and disp >= 0:
            offsets.add(disp & 0xFFFF)
    return tuple(sorted(offsets))


_COD_INDEXED_GLOBAL_REF_RE_8616 = re.compile(
    r"\b(?P<width>BYTE|WORD|DWORD)\s+PTR\s+_?(?P<name>[A-Za-z_$?@][\w$?@]*)"
    r"\[(?P<bracket>[^\]]*)\]",
    re.IGNORECASE,
)
_COD_INDEXED_GLOBAL_DISP_RE_8616 = re.compile(r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))", re.IGNORECASE)
_COD_DIRECT_GLOBAL_REF_RE_8616 = re.compile(
    r"\b(?P<width>BYTE|WORD|DWORD)\s+PTR\s+_?(?P<name>[A-Za-z_$?@][\w$?@]*)"
    r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))?\b(?!\s*\[)",
    re.IGNORECASE,
)
_COD_OFFSET_GLOBAL_REF_RE_8616 = re.compile(
    r"\bOFFSET\s+(?:(?:DGROUP|GROUP):)?_?(?P<name>[A-Za-z_$?@][\w$?@]*)"
    r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))?\b",
    re.IGNORECASE,
)


def _cod_indexed_global_refs_8616(cod_metadata: CodMetadataBoundary8616) -> tuple[tuple[str, int, int], ...]:
    """Return indexed global references from a dynamic boundary: optional third-party COD metadata."""

    refs: list[tuple[str, int, int]] = []
    for ref in tuple(getattr(cod_metadata, "global_refs", ()) or ()):
        if not bool(getattr(ref, "indexed", False)):
            continue
        name = getattr(ref, "name", None)
        relative_disp = getattr(ref, "relative_disp", None)
        width = getattr(ref, "width", None)
        if not isinstance(name, str) or not isinstance(relative_disp, int) or not isinstance(width, int):
            continue
        refs.append((name, relative_disp, width))
    return tuple(refs)


def _collect_direct_global_symbol_refs_8616(
    cod_metadata: CodMetadataBoundary8616,
    summaries: list[InsnSummary8616],
) -> tuple[DirectGlobalSymbolRef8616, ...]:
    cod_refs = _cod_direct_global_refs_8616(cod_metadata)
    binary_refs: list[tuple[int, int]] = []
    for insn in summaries:
        if insn.op0_kind == "direct_mem" and isinstance(insn.op0_value, int):
            binary_refs.append((int(insn.op0_value) & 0xFFFF, int(insn.op0_size or 2)))
        if insn.op1_kind == "direct_mem" and isinstance(insn.op1_value, int):
            binary_refs.append((int(insn.op1_value) & 0xFFFF, int(insn.op1_size or 2)))
    if not cod_refs or len(cod_refs) != len(binary_refs):
        if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
            log.warning(
                "[seg-global-direct] refused cod_refs=%d binary_refs=%d",
                len(cod_refs),
                len(binary_refs),
            )
        return ()
    max_by_name: dict[str, int] = {}
    for name, rel_disp, _width in cod_refs:
        max_by_name[name] = max(max_by_name.get(name, 0), int(rel_disp))
    refs: list[DirectGlobalSymbolRef8616] = []
    for (offset, actual_width), (name, rel_disp, cod_width) in zip(binary_refs, cod_refs, strict=False):
        width = int(actual_width or cod_width or 2)
        refs.append(
            DirectGlobalSymbolRef8616(
                offset=offset & 0xFFFF,
                name=name,
                relative_disp=int(rel_disp),
                width=width,
                max_relative_disp=max_by_name.get(name, int(rel_disp)),
            )
        )
    return tuple(refs)


def _collect_synthetic_direct_global_symbol_refs_8616(
    synthetic_globals: SyntheticGlobalsBoundary8616,
    summaries: list[InsnSummary8616],
) -> tuple[DirectGlobalSymbolRef8616, ...]:
    if not isinstance(synthetic_globals, dict):
        return ()
    direct_operands: set[tuple[int, int]] = set()
    for insn in summaries:
        for kind, value, size in (
            (insn.op0_kind, insn.op0_value, insn.op0_size),
            (insn.op1_kind, insn.op1_value, insn.op1_size),
        ):
            if kind != "direct_mem" or not isinstance(value, int):
                continue
            width = int(size or 0)
            if width > 0:
                direct_operands.add((value & 0xFFFF, width))
    refs: list[DirectGlobalSymbolRef8616] = []
    for raw_offset, raw_entry in synthetic_globals.items():
        if not isinstance(raw_offset, int) or not isinstance(raw_entry, tuple) or len(raw_entry) < 2:
            continue
        raw_name, raw_width = raw_entry[0], raw_entry[1]
        if not isinstance(raw_name, str) or not raw_name:
            continue
        width = int(raw_width) if isinstance(raw_width, int) and raw_width > 0 else 2
        offset = raw_offset & 0xFFFF
        for operand_offset, operand_width in sorted(direct_operands):
            relative_disp = (operand_offset - offset) & 0xFFFF
            if relative_disp >= width or relative_disp + operand_width > width:
                continue
            refs.append(
                DirectGlobalSymbolRef8616(
                    offset=operand_offset,
                    name=raw_name,
                    relative_disp=relative_disp,
                    width=operand_width,
                    max_relative_disp=max(0, width - operand_width),
                )
            )
    return tuple(refs)


def _collect_direct_global_update_evidence_8616(
    summaries: list[InsnSummary8616],
) -> tuple[DirectGlobalUpdateEvidence8616, ...]:
    updates: list[DirectGlobalUpdateEvidence8616] = []
    for insn in summaries:
        if insn.op0_kind != "direct_mem" or not isinstance(insn.op0_value, int):
            continue
        width = int(insn.op0_size or 0)
        if width != 2:
            continue
        mnemonic = str(insn.mnemonic or "").lower()
        delta = None
        if mnemonic == "inc":
            delta = 1
        elif mnemonic == "dec":
            delta = -1
        elif mnemonic in {"add", "sub"} and isinstance(insn.op1_value, int):
            amount = int(insn.op1_value)
            delta = amount if mnemonic == "add" else -amount
        if delta is None or delta == 0:
            continue
        updates.append(DirectGlobalUpdateEvidence8616(insn.op0_value & 0xFFFF, width, delta))
    return tuple(dict.fromkeys(updates))


def _collect_direct_global_boolean_store_evidence_8616(
    summaries: list[InsnSummary8616],
) -> tuple[DirectGlobalBooleanStoreEvidence8616, ...]:
    evidence: list[DirectGlobalBooleanStoreEvidence8616] = []
    for index in range(0, max(0, len(summaries) - 3)):
        cmp_insn = summaries[index]
        sbb_insn = summaries[index + 1]
        neg_insn = summaries[index + 2]
        mov_insn = summaries[index + 3]
        if str(cmp_insn.mnemonic or "").lower() != "cmp":
            continue
        if cmp_insn.op0_kind != "direct_mem" or not isinstance(cmp_insn.op0_value, int):
            continue
        if cmp_insn.op1_kind != "imm" or not isinstance(cmp_insn.op1_value, int):
            continue
        source_width = int(cmp_insn.op0_size or 0)
        if source_width != 2:
            continue
        if str(sbb_insn.mnemonic or "").lower() != "sbb":
            continue
        if sbb_insn.op0_kind != "reg" or sbb_insn.op1_kind != "reg" or sbb_insn.op0_value != sbb_insn.op1_value:
            continue
        carrier_reg = sbb_insn.op0_value
        if str(neg_insn.mnemonic or "").lower() != "neg":
            continue
        if neg_insn.op0_kind != "reg" or neg_insn.op0_value != carrier_reg:
            continue
        if str(mov_insn.mnemonic or "").lower() != "mov":
            continue
        if mov_insn.op0_kind != "direct_mem" or not isinstance(mov_insn.op0_value, int):
            continue
        if mov_insn.op1_kind != "reg" or mov_insn.op1_value != carrier_reg:
            continue
        dest_width = int(mov_insn.op0_size or 0)
        if dest_width != source_width:
            continue
        evidence.append(
            DirectGlobalBooleanStoreEvidence8616(
                source_offset=cmp_insn.op0_value & 0xFFFF,
                source_width=source_width,
                compare_value=int(cmp_insn.op1_value),
                dest_offset=mov_insn.op0_value & 0xFFFF,
                dest_width=dest_width,
                store_ins_addr=mov_insn.address if isinstance(mov_insn.address, int) else None,
            )
        )
    return tuple(dict.fromkeys(evidence))


def _collect_direct_global_call_return_store_evidence_8616(
    project: ProjectBoundary8616,
    function: object,
) -> tuple[DirectGlobalCallReturnStoreEvidence8616, ...]:
    """Collect direct global call-return stores from typed callsite and instruction facts."""

    if project is None or function is None:
        return ()
    insns = _direct_global_update_ordered_insns_8616(project, function)
    views = tuple(_capstone_instruction_view_8616(insn) for insn in insns)
    evidence: list[DirectGlobalCallReturnStoreEvidence8616] = []
    callsite_addrs = tuple(
        view.address
        for view in views
        if view.instruction_id in {X86_INS_CALL, X86_INS_LCALL} and view.address is not None
    )
    summaries = build_callsite_summary_inventory_8616(function, callsite_addrs)
    call_index_by_addr = {
        view.address: index
        for index, view in enumerate(views)
        if view.address is not None and view.instruction_id in {X86_INS_CALL, X86_INS_LCALL}
    }
    for summary in summaries.values():
        item = _direct_global_call_return_evidence_from_summary_8616(
            project,
            views,
            call_index_by_addr,
            summary,
        )
        if item is not None:
            evidence.append(item)
    for index in range(1, len(insns) - 1):
        low_store = views[index]
        high_store = views[index + 1]
        low = _direct_global_call_return_store_operand_8616(low_store, X86_REG_AX, 2)
        high = _direct_global_call_return_store_operand_8616(high_store, X86_REG_DX, 2)
        if low is None or high is None:
            continue
        low_offset, low_width, low_ins_addr = low
        high_offset, high_width, high_ins_addr = high
        if low_width != 2 or high_width != 2 or ((low_offset + 2) & 0xFFFF) != (high_offset & 0xFFFF):
            continue
        call = _direct_zero_arg_call_before_8616(project, insns, index)
        if call is None:
            continue
        source_call_name, source_call_target, source_call_ins_addr = call
        if not isinstance(source_call_name, str) or not source_call_name:
            continue
        evidence.append(
            DirectGlobalCallReturnStoreEvidence8616(
                offset=low_offset & 0xFFFF,
                width=4,
                source_call_name=source_call_name,
                source_call_target=source_call_target if isinstance(source_call_target, int) else None,
                source_call_ins_addr=source_call_ins_addr,
                low_store_ins_addr=low_ins_addr,
                high_store_ins_addr=high_ins_addr,
            )
        )
    return tuple(dict.fromkeys(evidence))


def _direct_global_call_return_evidence_from_summary_8616(
    project: ProjectBoundary8616,
    views: tuple[CapstoneInstructionView8616, ...],
    call_index_by_addr: dict[int, int],
    summary: CallsiteSummary8616,
) -> DirectGlobalCallReturnStoreEvidence8616 | None:
    """Join a callsite return-store summary to its exact Capstone store identities."""

    destination = summary.return_store_destination
    width = summary.return_store_width
    target = summary.target_addr
    call_index = call_index_by_addr.get(summary.callsite_addr)
    if (
        destination is None
        or destination[0] != "global"
        or width not in {1, 2, 4}
        or target is None
        or call_index is None
    ):
        return None
    store_index = call_index + 1
    if store_index >= len(views):
        return None
    cleanup_amount = _post_call_stack_cleanup_amount_8616(views[store_index])
    if cleanup_amount is not None:
        if summary.stack_cleanup != cleanup_amount:
            return None
        store_index += 1
    if store_index >= len(views):
        return None
    offset = destination[1] & 0xFFFF
    source_register = X86_REG_AL if width == 1 else X86_REG_AX
    low_width = 1 if width == 1 else 2
    low_store = _direct_global_call_return_store_operand_8616(
        views[store_index],
        source_register,
        low_width,
    )
    if low_store is None or low_store[:2] != (offset, low_width):
        return None
    high_store_ins_addr = None
    if width == 4:
        high_index = store_index + 1
        if high_index >= len(views):
            return None
        high_store = _direct_global_call_return_store_operand_8616(
            views[high_index],
            X86_REG_DX,
            2,
        )
        if high_store is None or high_store[:2] != (((offset + 2) & 0xFFFF), 2):
            return None
        high_store_ins_addr = high_store[2]
    source_call_name, _callee, resolved_target = _callee_name_for_direct_stack_move_8616(project, target)
    return DirectGlobalCallReturnStoreEvidence8616(
        offset=offset,
        width=width,
        source_call_name=source_call_name,
        source_call_target=resolved_target,
        source_call_ins_addr=summary.callsite_addr,
        low_store_ins_addr=low_store[2],
        high_store_ins_addr=high_store_ins_addr,
    )


def _post_call_stack_cleanup_amount_8616(view: CapstoneInstructionView8616) -> int | None:
    """Return an exact positive ``ADD SP, imm`` cleanup amount."""

    if view.instruction_id != X86_INS_ADD or len(view.operands) != 2:
        return None
    destination, amount = view.operands
    if (
        destination.kind != X86_OP_REG
        or destination.register != X86_REG_SP
        or amount.kind != X86_OP_IMM
        or amount.immediate is None
        or amount.immediate <= 0
    ):
        return None
    return amount.immediate


def _direct_global_call_return_store_operand_8616(
    insn: object,
    source_reg: int,
    expected_width: int,
) -> tuple[int, int, int] | None:
    """Return one typed direct DS store from exact Capstone metadata."""

    view = insn if isinstance(insn, CapstoneInstructionView8616) else _capstone_instruction_view_8616(insn)
    if view.instruction_id != X86_INS_MOV or len(view.operands) != 2:
        return None
    destination, source = view.operands
    if source.kind != X86_OP_REG or source.register != source_reg:
        return None
    if destination.kind != X86_OP_MEM or destination.size != expected_width:
        return None
    memory = destination.memory
    if memory is None:
        return None
    segment_name = _direct_stack_move_segment_name_8616(view.raw, memory.segment)
    if segment_name != "ds":
        return None
    if memory.base not in {None, 0, X86_REG_INVALID} or memory.index not in {None, 0, X86_REG_INVALID}:
        return None
    if memory.displacement is None or view.address is None:
        return None
    return memory.displacement & 0xFFFF, expected_width, view.address


def _merge_direct_global_symbol_refs_8616(
    *groups: tuple[DirectGlobalSymbolRef8616, ...],
) -> tuple[DirectGlobalSymbolRef8616, ...]:
    refs: dict[tuple[int, int], DirectGlobalSymbolRef8616] = {}
    for group in groups:
        for ref in group:
            width = int(ref.width or 0)
            if width <= 0:
                continue
            refs.setdefault((ref.offset & 0xFFFF, width), ref)
    for ref in _derive_direct_global_dword_scalar_refs_8616(tuple(refs.values())):
        refs.setdefault((ref.offset & 0xFFFF, ref.width), ref)
    return tuple(refs[key] for key in sorted(refs))


def _derive_direct_global_dword_scalar_refs_8616(
    refs: tuple[DirectGlobalSymbolRef8616, ...],
) -> tuple[DirectGlobalSymbolRef8616, ...]:
    by_name_rel: dict[tuple[str, int, int], DirectGlobalSymbolRef8616] = {}
    for ref in refs:
        by_name_rel[(_sanitize_identifier_8616(ref.name), int(ref.relative_disp), int(ref.width))] = ref

    derived: list[DirectGlobalSymbolRef8616] = []
    for ref in refs:
        if int(ref.width) != 2 or int(ref.relative_disp) != 0 or int(ref.max_relative_disp) != 2:
            continue
        name = _sanitize_identifier_8616(ref.name)
        high_ref = by_name_rel.get((name, 2, 2))
        if high_ref is None:
            continue
        if ((ref.offset + 2) & 0xFFFF) != (high_ref.offset & 0xFFFF):
            continue
        derived.append(
            DirectGlobalSymbolRef8616(
                offset=ref.offset & 0xFFFF,
                name=ref.name,
                relative_disp=0,
                width=4,
                max_relative_disp=0,
            )
        )
    return tuple(dict.fromkeys(derived))


def _collect_global_address_symbol_refs_8616(
    cod_metadata: CodMetadataBoundary8616,
    summaries: list[InsnSummary8616],
) -> tuple[DirectGlobalSymbolRef8616, ...]:
    cod_refs = _cod_offset_global_ref_records_8616(cod_metadata)
    if not cod_refs:
        return ()
    delta = _cod_to_summary_address_delta_8616(cod_metadata, summaries)
    by_addr: dict[int, list[CodOffsetGlobalRef8616]] = {}
    max_by_name: dict[str, int] = {}
    for ref in cod_refs:
        by_addr.setdefault((ref.ins_addr + delta) & 0xFFFF, []).append(ref)
        max_by_name[ref.name] = max(max_by_name.get(ref.name, 0), int(ref.relative_disp))

    refs: list[DirectGlobalSymbolRef8616] = []
    debug_imm_addrs: list[int] = []
    for insn in summaries:
        if not isinstance(insn.address, int):
            continue
        if insn.op0_kind == "imm" or insn.op1_kind == "imm":
            debug_imm_addrs.append(insn.address & 0xFFFF)
        symbol_refs = _lookup_cod_address_refs_8616(by_addr, insn, slop=8)
        if not symbol_refs:
            continue
        immediate: int | None = None
        immediate_size: int | None = None
        if insn.op0_kind == "imm" and isinstance(insn.op0_value, int):
            immediate = int(insn.op0_value)
            immediate_size = insn.op0_size
        elif insn.op1_kind == "imm" and isinstance(insn.op1_value, int):
            immediate = int(insn.op1_value)
            immediate_size = insn.op1_size
        if immediate is None:
            continue
        for ref in symbol_refs:
            for width in _offset_symbol_candidate_widths_8616(immediate_size):
                refs.append(
                    DirectGlobalSymbolRef8616(
                        offset=immediate & 0xFFFF,
                        name=ref.name,
                        relative_disp=int(ref.relative_disp),
                        width=width,
                        max_relative_disp=max_by_name.get(ref.name, int(ref.relative_disp)),
                    )
                )
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        log.warning(
            "[seg-global-offset] cod_refs=%s imm_addrs=%s materialized_refs=%d",
            tuple(hex((ref.ins_addr + delta) & 0xFFFF) for ref in cod_refs),
            tuple(hex(addr) for addr in debug_imm_addrs[:12]),
            len(refs),
        )
    return tuple(refs)


def _collect_global_address_literal_evidence_8616(
    cod_metadata: CodMetadataBoundary8616,
    summaries: list[InsnSummary8616],
) -> tuple[GlobalAddressLiteralEvidence8616, ...]:
    cod_refs = tuple(ref for ref in _cod_offset_global_ref_records_8616(cod_metadata) if ref.literal is not None)
    if not cod_refs:
        return ()
    delta = _cod_to_summary_address_delta_8616(cod_metadata, summaries)
    by_addr: dict[int, list[CodOffsetGlobalRef8616]] = {}
    for ref in cod_refs:
        by_addr.setdefault((ref.ins_addr + delta) & 0xFFFF, []).append(ref)

    evidence: list[GlobalAddressLiteralEvidence8616] = []
    for insn in summaries:
        if not isinstance(insn.address, int):
            continue
        literal_refs = _lookup_cod_address_refs_8616(by_addr, insn, slop=8)
        if not literal_refs:
            continue
        immediate: int | None = None
        if insn.op0_kind == "imm" and isinstance(insn.op0_value, int):
            immediate = int(insn.op0_value)
        elif insn.op1_kind == "imm" and isinstance(insn.op1_value, int):
            immediate = int(insn.op1_value)
        if immediate is None:
            continue
        for ref in literal_refs:
            if ref.literal is not None:
                evidence.append(GlobalAddressLiteralEvidence8616(immediate & 0xFFFF, ref.literal))
    return tuple(dict.fromkeys(evidence))


def _cod_direct_global_refs_8616(cod_metadata: CodMetadataBoundary8616) -> tuple[tuple[str, int, int], ...]:
    """Return direct global references from a dynamic boundary: optional third-party COD metadata."""

    refs: list[tuple[str, int, int]] = []
    for ref in tuple(getattr(cod_metadata, "global_refs", ()) or ()):
        if bool(getattr(ref, "indexed", False)):
            continue
        name = getattr(ref, "name", None)
        relative_disp = getattr(ref, "relative_disp", None)
        width = getattr(ref, "width", None)
        if not isinstance(name, str) or not isinstance(relative_disp, int) or not isinstance(width, int):
            continue
        refs.append((name, relative_disp, width))
    return tuple(refs)


def _lookup_cod_address_refs_8616(
    by_addr: dict[int, list[CodOffsetGlobalRef8616]],
    insn: InsnSummary8616,
    *,
    slop: int = 3,
) -> list[CodOffsetGlobalRef8616]:
    if not isinstance(insn.address, int):
        return []
    normalized = insn.address & 0xFFFF
    exact = by_addr.get(normalized)
    if exact:
        exact = [ref for ref in exact if _summary_matches_cod_offset_opcode_8616(insn, ref.opcode)]
    if exact:
        return exact
    nearby: list[CodOffsetGlobalRef8616] = []
    for delta in range(-slop, slop + 1):
        if delta == 0:
            continue
        nearby.extend(
            ref
            for ref in by_addr.get((normalized + delta) & 0xFFFF, ())
            if _summary_matches_cod_offset_opcode_8616(insn, ref.opcode)
        )
    return nearby if len(nearby) == 1 else []


def _summary_matches_cod_offset_opcode_8616(insn: InsnSummary8616, opcode: int | None) -> bool:
    if opcode is None:
        return True
    mnemonic = insn.mnemonic.lower()
    if 0xB8 <= opcode <= 0xBF:
        return mnemonic == "mov" and (insn.op0_kind == "imm" or insn.op1_kind == "imm")
    if opcode == 0x68:
        return mnemonic == "push" and (insn.op0_kind == "imm" or insn.op1_kind == "imm")
    return True


def _cod_offset_global_refs_8616(cod_metadata: CodMetadataBoundary8616) -> tuple[tuple[int, str, int], ...]:
    return tuple((ref.ins_addr, ref.name, ref.relative_disp) for ref in _cod_offset_global_ref_records_8616(cod_metadata))


def _cod_offset_global_ref_records_8616(cod_metadata: CodMetadataBoundary8616) -> tuple[CodOffsetGlobalRef8616, ...]:
    """Return offset global refs from a dynamic boundary: optional third-party COD metadata."""

    records: list[CodOffsetGlobalRef8616] = []
    for ref in tuple(getattr(cod_metadata, "global_address_refs", ()) or ()):
        offset = getattr(ref, "offset", None)
        name = getattr(ref, "name", None)
        relative_disp = getattr(ref, "relative_disp", None)
        if not isinstance(offset, int) or not isinstance(name, str) or not isinstance(relative_disp, int):
            continue
        instruction_bytes = getattr(ref, "instruction_bytes", None)
        opcode = int(instruction_bytes[0]) if isinstance(instruction_bytes, bytes) and instruction_bytes else None
        literal = getattr(ref, "string_literal", None)
        records.append(
            CodOffsetGlobalRef8616(
                ins_addr=offset,
                name=name,
                relative_disp=relative_disp,
                opcode=opcode,
                literal=literal if isinstance(literal, str) else None,
            )
        )
    return tuple(records)


def _cod_offset_global_literal_refs_8616(cod_metadata: CodMetadataBoundary8616) -> tuple[tuple[int, str], ...]:
    """Return literal global refs from a dynamic boundary: optional third-party COD metadata."""

    refs: list[tuple[int, str]] = []
    for ref in tuple(getattr(cod_metadata, "global_address_refs", ()) or ()):
        offset = getattr(ref, "offset", None)
        literal = getattr(ref, "string_literal", None)
        if not isinstance(offset, int) or not isinstance(literal, str):
            continue
        refs.append((offset, literal))
    return tuple(refs)


def _cod_instruction_offsets_8616(cod_metadata: CodMetadataBoundary8616) -> tuple[int, ...]:
    """Return instruction offsets from a dynamic boundary: optional third-party COD metadata."""

    offsets: list[int] = []
    for offset in tuple(getattr(cod_metadata, "instruction_offsets", ()) or ()):
        if isinstance(offset, int):
            offsets.append(offset)
    return tuple(offsets)


def _cod_to_summary_address_delta_8616(cod_metadata: CodMetadataBoundary8616, summaries: list[InsnSummary8616]) -> int:
    cod_offsets = _cod_instruction_offsets_8616(cod_metadata)
    summary_addrs = tuple(insn.address for insn in summaries if isinstance(insn.address, int))
    if not cod_offsets or not summary_addrs:
        return 0
    return (summary_addrs[0] - cod_offsets[0]) & 0xFFFF


def _offset_symbol_candidate_widths_8616(operand_size: int | None) -> tuple[int, ...]:
    # OFFSET operands prove the global base address, not the element width.  Seed
    # the primitive widths used by segmented pointer lowering; the actual access
    # width is still selected by the binary scale or helper width.
    if operand_size == 1:
        return (1,)
    if operand_size == 4:
        return (1, 2, 4)
    return (1, 2)


def _parse_cod_global_disp_8616(text: str | None) -> int:
    if not text:
        return 0
    sign = -1 if text[0] == "-" else 1
    body = text[1:]
    if body.lower().startswith("0x"):
        value = int(body, 16)
    elif body.upper().endswith("H"):
        value = int(body[:-1], 16)
    else:
        value = int(body, 10)
    return sign * value


def _match_indexed_offset_expr_8616(
    node: object,
    width: int,
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> tuple[int, object] | None:
    if not isinstance(node, CBinaryOp) or node.op != "Add":
        return None
    for maybe_base, maybe_index in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        base = _constant_int_8616(maybe_base)
        if base is None:
            continue
        scaled = _match_scaled_index_expr_8616(_resolve_copy_8616(maybe_index, copies), width, copies=copies)
        if scaled is not None:
            return base, scaled
    return None


def _match_indexed_offset_expr_for_evidence_8616(
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> tuple[int, int, object] | None:
    for _base_offset, width in sorted(evidence_by_base):
        matched = _match_indexed_offset_expr_8616(node, width, copies=copies)
        if matched is not None:
            base_offset, index_expr = matched
            if (base_offset & 0xFFFF, width) in evidence_by_base:
                return base_offset, width, index_expr
    return None


def _match_indexed_pointer_expr_8616(
    node: object,
    width: int,
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> tuple[int, object] | None:
    node = _unwrap_codegen_expr_8616(node)
    if not isinstance(node, CBinaryOp) or node.op != "Add":
        return None
    for maybe_base, maybe_index in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        base = _memory_reference_addr_8616(maybe_base)
        if base is None:
            continue
        scaled = _match_scaled_index_expr_8616(_resolve_copy_8616(maybe_index, copies), width, copies=copies)
        if scaled is not None:
            return base, scaled
    return None


def _match_indexed_pointer_expr_with_stride_8616(
    node: object,
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> tuple[int, int, object] | None:
    node = _unwrap_codegen_expr_8616(node)
    if not isinstance(node, CBinaryOp) or node.op != "Add":
        return None
    for maybe_base, maybe_index in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        base = _memory_reference_addr_8616(maybe_base)
        if base is None:
            continue
        scaled = _match_scaled_index_expr_with_stride_8616(_resolve_copy_8616(maybe_index, copies), copies=copies)
        if scaled is not None:
            stride, index_expr = scaled
            return base, stride, index_expr
    return None


def _match_indexed_offset_expr_with_stride_8616(
    node: object,
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> tuple[int, int, object] | None:
    if not isinstance(node, CBinaryOp) or node.op != "Add":
        return None
    for maybe_base, maybe_index in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        base = _constant_int_8616(maybe_base)
        if base is None:
            continue
        scaled = _match_scaled_index_expr_with_stride_8616(_resolve_copy_8616(maybe_index, copies), copies=copies)
        if scaled is not None:
            stride, index_expr = scaled
            return base, stride, index_expr
    return None


def _match_byte_store_lvalue_8616(
    node: object,
    *,
    copies: dict[CopyKey8616, object] | None = None,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616] | None = None,
) -> tuple[int, object] | None:
    node = _unwrap_codegen_expr_8616(node)
    memory_helper = _memory_pointer_helper_8616(node)
    if memory_helper is MemoryPointerHelper8616.MEM_U8:
        if not isinstance(node, CFunctionCall):
            return None
        args = tuple(node.args or ())
        if len(args) == 1:
            matched = _match_indexed_pointer_expr_8616(args[0], 2, copies=copies)
            if matched is not None:
                return matched
            if evidence_by_base is not None:
                return _match_indexed_global_byte_address_8616(
                    args[0],
                    evidence_by_base,
                    copies=copies,
                )
        return None
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None
    return _match_indexed_pointer_expr_8616(node.operand, 2, copies=copies)


def _match_indexed_global_byte_address_8616(
    node: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> tuple[int, object] | None:
    """Match a byte address formed from an already-typed indexed global."""

    node = _unwrap_codegen_expr_8616(node)
    if isinstance(node, CBinaryOp) and node.op == "Add":
        for maybe_address, maybe_disp in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            disp = _constant_int_8616(maybe_disp)
            if disp is None:
                continue
            matched = _match_indexed_global_byte_address_8616(
                maybe_address,
                evidence_by_base,
                copies=copies,
            )
            if matched is not None:
                base_offset, index_expr = matched
                return (base_offset + disp) & 0xFFFF, index_expr
        return None
    if isinstance(node, CUnaryOp) and node.op in {"Reference", "AddressOf"}:
        node = node.operand
        node = _unwrap_codegen_expr_8616(node)
    if not isinstance(node, CIndexedVariable):
        return None
    indexed_name = _indexed_global_name_8616(node)
    if indexed_name is None:
        return None
    base = node.variable
    if not isinstance(base, CVariable):
        return None
    base_variable = base.variable
    if not isinstance(base_variable, SimMemoryVariable):
        return None
    base_addr = base_variable.addr
    if not isinstance(base_addr, int):
        return None
    base_size = base_variable.size
    exact_byte = evidence_by_base.get((base_addr & 0xFFFF, 1))
    if (
        isinstance(base_size, int)
        and base_size == 2
        and exact_byte is not None
        and _sanitize_identifier_8616(exact_byte.name) == indexed_name
    ):
        return base_addr & 0xFFFF, _resolve_copy_8616(node.index, copies)
    for (candidate_base, width), item in sorted(evidence_by_base.items()):
        if width != 2 or item.relative_disp != 0:
            continue
        if candidate_base != (item.base_offset & 0xFFFF):
            continue
        if _sanitize_identifier_8616(item.name) != indexed_name:
            continue
        if (item.base_offset & 0xFFFF) != (base_addr & 0xFFFF):
            continue
        return item.base_offset & 0xFFFF, _resolve_copy_8616(node.index, copies)
    return None


def _memory_reference_addr_8616(node: object) -> int | None:
    node = _unwrap_codegen_expr_8616(node)
    if isinstance(node, CUnaryOp) and node.op in {"Reference", "AddressOf"}:
        node = node.operand
        node = _unwrap_codegen_expr_8616(node)
    if not isinstance(node, CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = variable.addr
    return addr if isinstance(addr, int) else None


def _match_scaled_index_expr_8616(
    node: object,
    width: int,
    *,
    copies: dict[CopyKey8616, object] | None = None,
) -> object | None:
    node = _resolve_copy_8616(node, copies)
    if width == 2 and isinstance(node, CBinaryOp) and node.op == "Shl" and _constant_int_8616(node.rhs) == 1:
        return _resolve_copy_8616(node.lhs, copies)
    if isinstance(node, CBinaryOp) and node.op == "Mul":
        if _constant_int_8616(node.lhs) == width:
            return _resolve_copy_8616(node.rhs, copies)
        if _constant_int_8616(node.rhs) == width:
            return _resolve_copy_8616(node.lhs, copies)
    return None


def _match_scaled_index_expr_with_stride_8616(
    node: object, *, copies: dict[CopyKey8616, object] | None = None
) -> tuple[int, object] | None:
    node = _resolve_copy_8616(node, copies)
    if isinstance(node, CBinaryOp) and node.op == "Shl":
        shift = _constant_int_8616(node.rhs)
        if shift is not None and 0 <= shift <= 4:
            return 1 << shift, node.lhs
    if isinstance(node, CBinaryOp) and node.op == "Mul":
        lhs_const = _constant_int_8616(node.lhs)
        if lhs_const is not None and lhs_const > 0:
            return lhs_const, node.rhs
        rhs_const = _constant_int_8616(node.rhs)
        if rhs_const is not None and rhs_const > 0:
            return rhs_const, node.lhs
    return None


def _make_indexed_global_byte_field_expr_from_reference_8616(
    codegen: object,
    address_expr: object,
    byte_offset: int,
    index_expr: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
) -> object | None:
    """Use a typed indexed-global address as proof for a byte field load."""

    indexed = _typed_indexed_global_address_operand_8616(address_expr)
    if indexed is None:
        return None
    base = indexed.variable
    if not isinstance(base, CVariable):
        return None
    storage = base.variable
    if not isinstance(storage, SimMemoryVariable):
        return None
    base_addr = storage.addr
    storage_size = storage.size
    storage_name = storage.name
    if not isinstance(base_addr, int) or not isinstance(storage_size, int) or storage_size != 2:
        return None
    if not isinstance(storage_name, str):
        return None
    field_disp = (int(byte_offset) - base_addr) & 0xFFFF
    if field_disp >= storage_size:
        return None
    byte_evidence = evidence_by_base.get((int(byte_offset) & 0xFFFF, 1))
    if byte_evidence is None or _sanitize_identifier_8616(byte_evidence.name) != _sanitize_identifier_8616(storage_name):
        return None
    element_item = IndexedSegmentedGlobalEvidence8616(
        base_offset=base_addr & 0xFFFF,
        name=storage_name,
        relative_disp=0,
        width=storage_size,
    )
    return _make_indexed_global_byte_field_expr_8616(
        codegen,
        element_item,
        index_expr,
        field_disp,
        evidence_by_base,
    )


def _typed_indexed_global_address_operand_8616(address_expr: object) -> CIndexedVariable | None:
    """Extract the indexed global operand from a typed address expression."""

    node = address_expr
    node = _unwrap_codegen_expr_8616(node)
    if isinstance(node, CBinaryOp) and node.op == "Add":
        for maybe_address in (node.lhs, node.rhs):
            indexed = _typed_indexed_global_address_operand_8616(maybe_address)
            if indexed is not None:
                return indexed
        return None
    if isinstance(node, CUnaryOp) and node.op in {"Reference", "AddressOf"}:
        node = node.operand
        node = _unwrap_codegen_expr_8616(node)
    return node if isinstance(node, CIndexedVariable) else None


def _make_indexed_global_value_from_stride_evidence_8616(
    codegen: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    base_offset: int,
    stride: int,
    index_expr: object,
    load_width: int,
) -> object | None:
    """Build an indexed global value from stride and exact byte evidence."""

    if stride <= 0 or load_width <= 0 or load_width > stride:
        return None
    address_expr = _make_indexed_global_address_from_stride_evidence_8616(
        codegen,
        evidence_by_base,
        base_offset,
        stride,
        index_expr,
    )
    if address_expr is None:
        return None
    if load_width == stride and isinstance(address_expr, CUnaryOp) and address_expr.op == "Reference":
        return address_expr.operand
    if stride == 2 and load_width == 1:
        item = _indexed_evidence_for_base_stride_8616(evidence_by_base, base_offset, stride)
        if item is not None:
            field_disp = item.relative_disp % stride
            element_base = (item.base_offset - field_disp) & 0xFFFF
            word_item = item if int(item.width or 0) == stride else evidence_by_base.get((element_base, stride))
            if word_item is None:
                low_item = evidence_by_base.get((element_base, 1))
                high_item = evidence_by_base.get(((element_base + 1) & 0xFFFF, 1))
                if low_item is not None and high_item is not None and low_item.name == high_item.name:
                    word_item = IndexedSegmentedGlobalEvidence8616(
                        base_offset=element_base,
                        name=low_item.name,
                        relative_disp=low_item.relative_disp - (low_item.relative_disp % stride),
                        width=stride,
                    )
                elif low_item is not None:
                    adjacent_word = evidence_by_base.get(((element_base + stride) & 0xFFFF, stride))
                    if adjacent_word is not None and _sanitize_identifier_8616(
                        adjacent_word.name
                    ) == _sanitize_identifier_8616(low_item.name):
                        word_item = IndexedSegmentedGlobalEvidence8616(
                            base_offset=element_base,
                            name=low_item.name,
                            relative_disp=low_item.relative_disp - field_disp,
                            width=stride,
                        )
                    elif (
                        isinstance(address_expr, CUnaryOp)
                        and address_expr.op == "Reference"
                        and isinstance(address_expr.operand, CIndexedVariable)
                    ):
                        indexed_variable = address_expr.operand.variable
                        indexed_storage = indexed_variable.variable if isinstance(indexed_variable, CVariable) else None
                        indexed_size = indexed_storage.size if isinstance(indexed_storage, SimMemoryVariable) else None
                        if (
                            isinstance(indexed_storage, SimMemoryVariable)
                            and isinstance(indexed_size, int)
                            and indexed_size == stride
                            and _sanitize_identifier_8616(low_item.name)
                            == _sanitize_identifier_8616(indexed_storage.name or "")
                        ):
                            word_item = IndexedSegmentedGlobalEvidence8616(
                                base_offset=element_base,
                                name=low_item.name,
                                relative_disp=low_item.relative_disp - field_disp,
                                width=stride,
                            )
                        else:
                            return CFunctionCall(
                                _memory_pointer_helper_name_for_width_8616(load_width),
                                None,
                                [address_expr],
                                codegen=codegen,
                            )
                    else:
                        return CFunctionCall(
                            _memory_pointer_helper_name_for_width_8616(load_width),
                            None,
                            [address_expr],
                            codegen=codegen,
                        )
                else:
                    return CFunctionCall(
                        _memory_pointer_helper_name_for_width_8616(load_width),
                        None,
                        [address_expr],
                        codegen=codegen,
                    )
            element_item = IndexedSegmentedGlobalEvidence8616(
                base_offset=element_base,
                name=word_item.name,
                relative_disp=word_item.relative_disp,
                width=stride,
            )
            field_expr = _make_indexed_global_byte_field_expr_8616(
                codegen,
                element_item,
                index_expr,
                field_disp,
                evidence_by_base,
            )
            if field_expr is not None:
                return field_expr
            indexed = _make_indexed_global_expr_8616(codegen, element_item, index_expr)
            if indexed is not None:
                mask = CConstant(0xFF, SimTypeShort(False), codegen=codegen)
                if field_disp == 0:
                    return CBinaryOp("And", indexed, mask, codegen=codegen)
                if field_disp == 1:
                    shifted = CBinaryOp(
                        "Shr",
                        indexed,
                        CConstant(8, SimTypeShort(False), codegen=codegen),
                        codegen=codegen,
                    )
                    return CBinaryOp("And", shifted, mask, codegen=codegen)
    helper_name = _memory_pointer_helper_name_for_width_8616(load_width)
    if helper_name is None:
        return None
    return CFunctionCall(helper_name, None, [address_expr], codegen=codegen)


def _make_direct_global_address_from_evidence_8616(
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    offset: int,
) -> object | None:
    """Build a typed address for an exact global object backed by evidence."""

    normalized_offset = offset & 0xFFFF
    candidates = [
        item
        for (candidate_offset, width), item in evidence_by_base.items()
        if candidate_offset == normalized_offset and width > 0
    ]
    if not candidates:
        return None
    item = max(candidates, key=lambda candidate: candidate.width)
    indexed = _make_indexed_global_value_expr_8616(
        codegen,
        item,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        evidence_by_base,
        allow_unregistered_for_address=True,
    )
    if not isinstance(indexed, CExpression):
        return None
    return CUnaryOp("Reference", indexed, codegen=codegen)


def _make_indexed_global_address_from_stride_evidence_8616(
    codegen: CodegenBoundary8616,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    base_offset: int,
    stride: int,
    index_expr: object,
) -> object | None:
    """Build an indexed global address while preserving proven element types."""

    item = _indexed_evidence_for_base_stride_8616(evidence_by_base, base_offset, stride)
    if item is None:
        return None
    field_disp = item.relative_disp % stride
    element_item = IndexedSegmentedGlobalEvidence8616(
        base_offset=(item.base_offset - field_disp) & 0xFFFF,
        name=item.name,
        relative_disp=item.relative_disp - field_disp,
        width=stride,
    )
    if field_disp == 0:
        indexed = _make_indexed_global_value_expr_8616(
            codegen,
            element_item,
            index_expr,
            evidence_by_base,
            allow_unregistered_for_address=True,
        )
    else:
        indexed = _make_indexed_global_expr_8616(codegen, element_item, index_expr)
    if indexed is None:
        return None
    if not isinstance(indexed, CExpression):
        return None
    address_expr = CUnaryOp("Reference", indexed, codegen=codegen)
    if field_disp == 0:
        return address_expr
    return CBinaryOp(
        "Add",
        address_expr,
        CConstant(field_disp, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )


def _indexed_evidence_for_base_stride_8616(
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    base_offset: int,
    stride: int,
) -> IndexedSegmentedGlobalEvidence8616 | None:
    """Select the strongest indexed-global evidence for an offset/stride pair."""

    normalized_base = base_offset & 0xFFFF
    direct = evidence_by_base.get((normalized_base, stride))
    field_candidates = [
        item
        for (candidate_base, width), item in evidence_by_base.items()
        if candidate_base == normalized_base
        and 0 < width <= stride
        and int(item.relative_disp) > 0
        and int(item.relative_disp) % stride == 0
        and (direct is None or _sanitize_identifier_8616(item.name) == _sanitize_identifier_8616(direct.name))
    ]
    if field_candidates:
        field = max(field_candidates, key=lambda item: (int(item.relative_disp), int(item.width or 0)))
        if direct is None or int(direct.relative_disp) == 0:
            return IndexedSegmentedGlobalEvidence8616(
                base_offset=field.base_offset,
                name=field.name,
                relative_disp=field.relative_disp,
                width=stride,
            )
    if direct is not None:
        return direct
    candidates = [
        item
        for (candidate_base, width), item in evidence_by_base.items()
        if candidate_base == normalized_base and 0 < width <= stride
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item.width)


def _indexed_evidence_from_direct_symbol_refs_8616(
    refs: tuple[DirectGlobalSymbolRef8616, ...],
) -> tuple[IndexedSegmentedGlobalEvidence8616, ...]:
    evidence: list[IndexedSegmentedGlobalEvidence8616] = []
    for ref in refs:
        width = int(ref.width or 2)
        if width <= 0:
            continue
        evidence.append(
            IndexedSegmentedGlobalEvidence8616(
                base_offset=ref.offset & 0xFFFF,
                name=ref.name,
                relative_disp=int(ref.relative_disp),
                width=width,
            )
        )
    return tuple(evidence)


def _merge_indexed_global_evidence_8616(
    primary: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    fallback: tuple[IndexedSegmentedGlobalEvidence8616, ...],
) -> tuple[IndexedSegmentedGlobalEvidence8616, ...]:
    merged: dict[tuple[int, int, str], IndexedSegmentedGlobalEvidence8616] = {}
    for item in (*fallback, *primary):
        key = (item.base_offset & 0xFFFF, int(item.width or 0), str(item.name))
        merged[key] = item
    return tuple(merged.values())


def _memory_pointer_helper_name_for_width_8616(width: int) -> str | None:
    for helper in MemoryPointerHelper8616:
        if helper.width == width:
            return helper.helper_name
    return None


def _word_source_for_byte_pair_store_8616(
    high_rhs: object,
    low_rhs: object,
    copies: dict[CopyKey8616, object],
) -> object | None:
    if not isinstance(high_rhs, CBinaryOp) or high_rhs.op != "Shr" or _constant_int_8616(high_rhs.rhs) != 8:
        return None
    high_source = _resolve_copy_8616(high_rhs.lhs, copies)
    if _same_word_store_source_8616(high_source, low_rhs):
        return low_rhs
    low_source = _resolve_copy_8616(low_rhs, copies)
    if _same_word_store_source_8616(high_source, low_source):
        return low_source
    if _low_byte_source_is_artifact_8616(low_rhs, copies) and _word_store_source_is_safe_8616(high_source):
        return high_source
    return None


def _word_store_source_is_safe_8616(node: object) -> bool:
    if isinstance(node, (CVariable, CFunctionCall, CIndexedVariable)):
        return True
    return isinstance(node, CBinaryOp) and node.op in {"Add", "Sub", "Shl", "Shr", "And", "Or"}


def _low_byte_source_is_artifact_8616(node: object, copies: dict[CopyKey8616, object]) -> bool:
    if not isinstance(node, CVariable):
        return False
    key = _cvariable_key_8616(node)
    if key is not None and key in copies:
        return False
    variable = node.variable
    if isinstance(variable, SimStackVariable):
        return variable.base == "bp" and variable.offset == 0
    if isinstance(variable, SimMemoryVariable):
        return False
    if isinstance(variable, SimRegisterVariable):
        return True
    return False


def _high_byte_source_key_8616(high_rhs: object) -> str | None:
    if not isinstance(high_rhs, CBinaryOp) or high_rhs.op != "Shr":
        return None
    return _cvariable_key_8616(high_rhs.lhs)


def _debug_resolved_source_8616(high_rhs: object, copies: dict[CopyKey8616, object]) -> str:
    if not isinstance(high_rhs, CBinaryOp) or high_rhs.op != "Shr":
        return "not_shr"
    return _debug_source_8616(_resolve_copy_8616(high_rhs.lhs, copies))


def _debug_source_8616(node: object) -> str:
    key = _cvariable_key_8616(node)
    return f"{type(node).__name__}:{key}" if key is not None else type(node).__name__


def _same_word_store_source_8616(lhs: object, rhs: object) -> bool:
    if _same_c_expression_8616(lhs, rhs):
        return True
    if isinstance(lhs, CFunctionCall) and isinstance(rhs, CFunctionCall):
        # Dynamic boundary: angr codegen call nodes expose callee metadata by runtime surface.
        lhs_name = lhs.callee_target
        # Dynamic boundary: angr codegen call nodes expose callee metadata by runtime surface.
        rhs_name = rhs.callee_target
        if lhs_name == rhs_name and lhs_name in {helper.helper_name for helper in MemoryPointerHelper8616}:
            lhs_args = tuple(lhs.args or ())
            rhs_args = tuple(rhs.args or ())
            return len(lhs_args) == len(rhs_args) and all(
                _same_c_expression_8616(lhs_arg, rhs_arg) for lhs_arg, rhs_arg in zip(lhs_args, rhs_args, strict=True)
            )
    lhs_key = _cvariable_key_8616(lhs)
    rhs_key = _cvariable_key_8616(rhs)
    if lhs_key is not None and lhs_key == rhs_key:
        return True
    if not isinstance(lhs, CVariable) or not isinstance(rhs, CVariable):
        return False
    lvar = lhs.variable
    rvar = rhs.variable
    if not isinstance(lvar, SimStackVariable) or not isinstance(rvar, SimStackVariable):
        return False
    return (
        lvar.offset == rvar.offset
        and lvar.base == rvar.base
        and lvar.region == rvar.region
    )


def _make_indexed_global_value_expr_8616(
    codegen: CodegenBoundary8616,
    evidence: IndexedSegmentedGlobalEvidence8616,
    index_expr: object,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
    *,
    allow_unregistered_for_address: bool = False,
) -> object | None:
    """Build an indexed value, retaining unregistered aggregates only for addresses."""

    element_type: SimType | None = None
    declaration_ctype: NamedAggregateDeclarationCType8616 | None = None
    if int(evidence.width or 0) == 2:
        canonical_base = (int(evidence.base_offset) - int(evidence.relative_disp)) & 0xFFFF
        expected_name = _sanitize_identifier_8616(evidence.name)
        byte_field_proven = any(
            int(field_width) == 1
            and _sanitize_identifier_8616(field_evidence.name) == expected_name
            and (int(field_evidence.base_offset) - int(field_evidence.relative_disp)) & 0xFFFF == canonical_base
            and int(field_evidence.relative_disp) % 2 in {0, 1}
            for (_field_base, field_width), field_evidence in evidence_by_base.items()
        )
        if byte_field_proven:
            candidate_type = _two_byte_global_struct_type_8616(expected_name)
            _record_named_global_aggregate_type_fact_8616(codegen, expected_name, candidate_type, 1)
            registered_type = _register_codegen_struct_type_8616(codegen, candidate_type)
            if registered_type is not None or allow_unregistered_for_address:
                element_type = candidate_type
                declaration_ctype = _two_byte_global_struct_declaration_ctype_8616(
                    expected_name,
                    registered=registered_type is not None,
                )
    return _make_indexed_global_expr_8616(
        codegen,
        evidence,
        index_expr,
        element_type=element_type,
        declaration_ctype=declaration_ctype,
    )


def _make_indexed_global_expr_8616(
    codegen: CodegenBoundary8616,
    evidence: IndexedSegmentedGlobalEvidence8616,
    index_expr: object,
    *,
    element_type: SimType | None = None,
    declaration_ctype: NamedAggregateDeclarationCType8616 | str | None = None,
) -> object | None:
    width = int(evidence.width or 2)
    if width <= 0 or evidence.relative_disp % width != 0:
        return None
    base_addr = (evidence.base_offset - evidence.relative_disp) & 0xFFFF
    name = _sanitize_identifier_8616(evidence.name)
    resolved_type = element_type if element_type is not None else _type_for_width_8616(width)
    base_var = CVariable(
        SimMemoryVariable(base_addr, width, name=name, region=_codegen_function_addr_8616(codegen)),
        variable_type=resolved_type,
        codegen=codegen,
    )
    index_adjust = evidence.relative_disp // width
    if index_adjust < 0:
        final_index = CBinaryOp(
            "Sub",
            index_expr,
            CConstant(abs(index_adjust), SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    elif index_adjust > 0:
        final_index = CBinaryOp(
            "Add",
            index_expr,
            CConstant(index_adjust, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    else:
        final_index = index_expr
    if not isinstance(final_index, CExpression):
        return None
    record_global_declaration_spec_8616(
        codegen,
        ctype=declaration_ctype or ctype_for_global_width_8616(width),
        name=name,
        array_len=1,
    )
    return CIndexedVariable(
        base_var,
        final_index,
        variable_type=resolved_type,
        codegen=codegen,
    )


def _make_indexed_global_byte_field_expr_8616(
    codegen: object,
    evidence: IndexedSegmentedGlobalEvidence8616,
    index_expr: object,
    field_disp: int,
    evidence_by_base: dict[tuple[int, int], IndexedSegmentedGlobalEvidence8616],
) -> CExpression | None:
    """Build a generic struct-field expression from byte subfield evidence."""

    width = int(evidence.width or 0)
    field_offset = int(field_disp)
    if width != 2 or field_offset not in {0, 1}:
        return None
    element_physical_base = (int(evidence.base_offset) - (int(evidence.relative_disp) % width)) & 0xFFFF
    field_base = (element_physical_base + field_offset) & 0xFFFF
    field_evidence = evidence_by_base.get((field_base, 1))
    if field_evidence is None or _sanitize_identifier_8616(field_evidence.name) != _sanitize_identifier_8616(evidence.name):
        return None
    base_addr = (int(evidence.base_offset) - int(evidence.relative_disp)) & 0xFFFF
    name = _sanitize_identifier_8616(evidence.name)
    struct_type = _two_byte_global_struct_type_8616(name)
    _record_named_global_aggregate_type_fact_8616(codegen, name, struct_type, 1)
    type_registered = _register_codegen_struct_type_8616(codegen, struct_type) is not None
    cfunc = _codegen_cfunc_optional_8616(codegen)
    base_var = CVariable(
        # Dynamic boundary: angr codegen CFunction addr is optional on synthetic cfunc values.
        SimMemoryVariable(base_addr, width, name=name, region=getattr(cfunc, "addr", None)),
        variable_type=struct_type,
        codegen=codegen,
    )
    index_adjust = int(evidence.relative_disp) // width
    if index_adjust < 0:
        final_index = CBinaryOp(
            "Sub",
            index_expr,
            CConstant(abs(index_adjust), SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    elif index_adjust > 0:
        final_index = CBinaryOp(
            "Add",
            index_expr,
            CConstant(index_adjust, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    else:
        final_index = index_expr
    if not isinstance(final_index, CExpression):
        return None
    indexed = CIndexedVariable(base_var, final_index, variable_type=struct_type, codegen=codegen)
    field_name = _two_byte_global_struct_field_name_8616(field_offset)
    record_global_declaration_spec_8616(
        codegen,
        ctype=_two_byte_global_struct_declaration_ctype_8616(
            name,
            registered=type_registered,
        ),
        name=name,
        array_len=1,
    )
    return CVariableField(
        indexed,
        CStructField(struct_type, field_offset, field_name, codegen=codegen),
        codegen=codegen,
    )


def _two_byte_global_struct_field_name_8616(field_offset: int) -> str:
    """Return the deterministic field name for a proven byte offset."""

    return f"field_{int(field_offset)}"


def _two_byte_global_struct_ctype_8616(name: str) -> str:
    """Return the named C struct definition used for generic two-byte object fields."""

    tag = f"{_sanitize_identifier_8616(name)}_entry"
    return f"struct {tag} {{ unsigned char field_0; unsigned char field_1; }}"


def _two_byte_global_struct_declaration_ctype_8616(
    name: str,
    *,
    registered: bool,
) -> NamedAggregateDeclarationCType8616:
    """Return typed lifecycle metadata for a proven two-byte global aggregate."""

    tag = f"{_sanitize_identifier_8616(name)}_entry"
    return NamedAggregateDeclarationCType8616(
        type_name=tag,
        inline_definition=_two_byte_global_struct_ctype_8616(name),
        registered=registered,
    )


def _two_byte_global_struct_type_8616(name: str) -> SimStruct:
    """Return an angr struct whose name is a tag, not a rendered C specifier."""

    return SimStruct(
        OrderedDict(
            (
                (_two_byte_global_struct_field_name_8616(0), SimTypeChar(False)),
                (_two_byte_global_struct_field_name_8616(1), SimTypeChar(False)),
            )
        ),
        name=f"{_sanitize_identifier_8616(name)}_entry",
        pack=True,
    )


def _register_codegen_struct_type_8616(codegen: object, struct_type: SimStruct) -> TypeRef | None:
    """Register a recovered aggregate so angr emits its typedef before local uses.

    angr renders a local ``SimStruct`` as its bare name and emits the matching
    typedef only when that struct is present in the function type store. A
    whole-value aggregate must therefore refuse promotion when this boundary is
    unavailable; otherwise generated C contains an undefined type name.
    """

    typed_codegen = typing.cast(_CodegenTypeBoundary8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
        if cfunc is None:
            return None
        registered_type = TypeRef(struct_type.name, struct_type)
        cfunc.variable_manager.types[struct_type.name] = registered_type
        typed_codegen.show_local_types = True
    except AttributeError:
        # Dynamic boundary: synthetic codegen fixtures may omit angr's function
        # and variable-manager type stores.
        return None
    return registered_type


def _is_two_byte_global_struct_type_8616(candidate: object) -> typing.TypeGuard[SimStruct]:
    """Return whether a type is the binary-proven two-byte global field layout."""

    if not isinstance(candidate, SimStruct):
        return False
    fields = candidate.fields
    if tuple(fields) != (
        _two_byte_global_struct_field_name_8616(0),
        _two_byte_global_struct_field_name_8616(1),
    ):
        return False
    return all(isinstance(field_type, SimTypeChar) for field_type in fields.values())


def _make_direct_global_symbol_or_projection_expr_8616(
    codegen: CodegenBoundary8616,
    ref: DirectGlobalSymbolRef8616,
    width: int,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
) -> CExpression | None:
    scalar_ref = _dword_scalar_ref_for_subword_ref_8616(ref, direct_by_offset)
    if scalar_ref is not None:
        projected = _make_dword_scalar_subword_projection_expr_8616(
            codegen,
            scalar_ref,
            int(ref.relative_disp),
        )
        if projected is not None:
            return projected
    expr = _make_direct_global_symbol_expr_8616(codegen, ref, width)
    return expr if isinstance(expr, CExpression) else None


def _make_direct_global_byte_projection_expr_8616(
    codegen: CodegenBoundary8616,
    ref: DirectGlobalSymbolRef8616,
    addr: int,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
) -> CExpression | None:
    ref_width = int(ref.width or 0)
    if ref_width <= 1:
        return None
    byte_delta = (int(addr) - int(ref.offset)) & 0xFFFF
    if byte_delta >= ref_width:
        return None
    expr = _make_direct_global_symbol_or_projection_expr_8616(codegen, ref, ref_width, direct_by_offset)
    if expr is None:
        return None
    if byte_delta:
        expr = CBinaryOp(
            "Shr",
            expr,
            CConstant(byte_delta * 8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return CBinaryOp(
        "And",
        expr,
        CConstant(0xFF, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )


def _dword_scalar_ref_for_subword_ref_8616(
    ref: DirectGlobalSymbolRef8616,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
) -> DirectGlobalSymbolRef8616 | None:
    if int(ref.width or 0) != 2 or int(ref.relative_disp) not in {0, 2}:
        return None
    base_offset = (int(ref.offset) - int(ref.relative_disp)) & 0xFFFF
    scalar_ref = direct_by_offset.get((base_offset, 4))
    if scalar_ref is None:
        return None
    if _sanitize_identifier_8616(scalar_ref.name) != _sanitize_identifier_8616(ref.name):
        return None
    if int(scalar_ref.relative_disp) != 0 or int(scalar_ref.width or 0) != 4:
        return None
    return scalar_ref


def _make_dword_scalar_subword_projection_expr_8616(
    codegen: CodegenBoundary8616,
    scalar_ref: DirectGlobalSymbolRef8616,
    relative_disp: int,
) -> CExpression | None:
    scalar = _make_direct_global_symbol_expr_8616(codegen, scalar_ref, 4)
    if scalar is None:
        return None
    if int(relative_disp) == 0:
        return CBinaryOp(
            "And",
            scalar,
            CConstant(0xFFFF, SimTypeLong(False), codegen=codegen),
            codegen=codegen,
        )
    if int(relative_disp) == 2:
        return CBinaryOp(
            "Shr",
            scalar,
            CConstant(16, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return None


def _make_dword_scalar_indexed_subword_projection_expr_8616(
    codegen: CodegenBoundary8616,
    node: object,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
) -> CExpression | None:
    if not isinstance(node, CIndexedVariable):
        return None
    variable_expr = node.variable
    if not isinstance(variable_expr, CVariable):
        return None
    variable = variable_expr.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    width = variable.size
    base_addr = variable.addr
    name = variable.name
    if not isinstance(width, int) or width != 2 or not isinstance(base_addr, int) or not isinstance(name, str):
        return None
    index_value = _constant_int_8616(node.index)
    if index_value not in {0, 1}:
        return None
    ref = direct_by_offset.get(((base_addr + (index_value * width)) & 0xFFFF, width))
    if ref is None or _sanitize_identifier_8616(ref.name) != _sanitize_identifier_8616(name):
        return None
    scalar_ref = _dword_scalar_ref_for_subword_ref_8616(ref, direct_by_offset)
    if scalar_ref is None:
        return None
    return _make_dword_scalar_subword_projection_expr_8616(codegen, scalar_ref, int(ref.relative_disp))


def _flatten_or_terms_8616(node: object) -> tuple[object, ...]:
    """Return all terms in a nested C AST OR expression."""

    if isinstance(node, CBinaryOp) and node.op == "Or":
        return _flatten_or_terms_8616(node.lhs) + _flatten_or_terms_8616(node.rhs)
    return (node,)


def _is_dword_scalar_low_projection_expr_8616(node: object, scalar: object) -> bool:
    """Check whether an expression is the low word projection of a dword scalar."""

    return (
        isinstance(node, CBinaryOp)
        and node.op == "And"
        and _same_c_expression_8616(node.lhs, scalar)
        and _constant_int_8616(node.rhs) == 0xFFFF
    )


def _is_dword_scalar_high_projection_expr_8616(node: object, scalar: object) -> bool:
    """Check whether an expression is the high word projection of a dword scalar."""

    return (
        isinstance(node, CBinaryOp)
        and node.op == "Shr"
        and _same_c_expression_8616(node.lhs, scalar)
        and _constant_int_8616(node.rhs) == 16
    )


def _materialize_direct_global_zero_test_or_expr_8616(
    codegen: object,
    node: object,
    direct_by_offset: dict[tuple[int, int], DirectGlobalSymbolRef8616],
    zero_test_evidence: tuple[DwordGlobalZeroTestEvidence8616, ...],
) -> CExpression | None:
    """Replace a proven split dword OR zero-test carrier with the scalar global.

    The first lowering traversal may still expose one dirty register carrier.
    A later replay sees the same proven test as explicit low/high projections
    after its children were lowered. Both representations require the exact
    binary MOV/OR/Jcc evidence.
    """

    if not zero_test_evidence or not isinstance(node, CBinaryOp) or node.op != "Or":
        return None
    terms = _flatten_or_terms_8616(node)
    has_dirty_carrier = any(isinstance(term, CDirtyExpression) for term in terms)
    debug_zero_test = os.environ.get("INERTIA_DEBUG_DWORD_ZERO_TEST") == "1"
    for evidence in zero_test_evidence:
        scalar_ref = direct_by_offset.get((int(evidence.base_offset) & 0xFFFF, 4))
        if scalar_ref is None:
            continue
        scalar = _make_direct_global_symbol_expr_8616(codegen, scalar_ref, 4)
        if scalar is None:
            continue
        has_low = any(_is_dword_scalar_low_projection_expr_8616(term, scalar) for term in terms)
        has_high = any(_is_dword_scalar_high_projection_expr_8616(term, scalar) for term in terms)
        if debug_zero_test and (has_low or has_high):
            log.warning(
                "[dword-zero-test] base=%#x dirty=%s low=%s high=%s terms=%r",
                evidence.base_offset,
                has_dirty_carrier,
                has_low,
                has_high,
                tuple(_debug_c_repr_8616(term) for term in terms),
            )
        if (has_low and has_high) or (has_dirty_carrier and (has_low or has_high)):
            return scalar
    return None


def _make_direct_global_symbol_expr_8616(
    codegen: CodegenBoundary8616,
    ref: DirectGlobalSymbolRef8616,
    width: int,
) -> CExpression | None:
    width = int(width or ref.width or 2)
    if width <= 0:
        return None
    name = _sanitize_identifier_8616(ref.name)
    max_disp = int(ref.max_relative_disp)
    relative_disp = int(ref.relative_disp)
    if max_disp > 0 and relative_disp % width == 0:
        base_addr = (ref.offset - relative_disp) & 0xFFFF
        array_len = max(1, (max_disp // width) + 1)
        if array_len == 1:
            _record_global_declaration_8616(codegen, width, name)
            return CVariable(
                SimMemoryVariable(base_addr, width, name=name, region=_codegen_function_addr_8616(codegen)),
                variable_type=_type_for_width_8616(width),
                codegen=codegen,
            )
        record_global_declaration_spec_8616(
            codegen,
            ctype=ctype_for_global_width_8616(width),
            name=name,
            array_len=array_len,
        )
        base_var = CVariable(
            SimMemoryVariable(base_addr, width, name=name, region=_codegen_function_addr_8616(codegen)),
            variable_type=_type_for_width_8616(width),
            codegen=codegen,
        )
        return CIndexedVariable(
            base_var,
            CConstant(relative_disp // width, SimTypeShort(False), codegen=codegen),
            variable_type=_type_for_width_8616(width),
            codegen=codegen,
        )
    _record_global_declaration_8616(codegen, width, name)
    return CVariable(
        SimMemoryVariable(ref.offset & 0xFFFF, width, name=name, region=_codegen_function_addr_8616(codegen)),
        variable_type=_type_for_width_8616(width),
        codegen=codegen,
    )


def _written_registers_8616(insn: InsnSummary8616) -> tuple[str, ...]:
    mnemonic = insn.mnemonic.lower()
    if insn.op0_kind != "reg":
        return ()
    if mnemonic in {"mov", "add", "sub", "xor", "or", "and", "inc", "dec", "shl", "shr", "sar", "rol", "ror"}:
        return (str(insn.op0_value or "").lower(),)
    return ()


def _is_comparison_binary_op_8616(node: object) -> bool:
    return isinstance(node, CBinaryOp) and str(node.op).startswith("Cmp")


def _cvariable_register_name_8616(project: ProjectBoundary8616, node: object) -> str | None:
    if not isinstance(node, CVariable):
        return None
    variable = node.variable
    if isinstance(variable, SimRegisterVariable):
        reg = variable.reg
        if isinstance(reg, int):
            # Dynamic boundary: angr arch register tables are runtime project metadata.
            reg_name = getattr(project.arch, "register_names", {}).get(reg)
            if isinstance(reg_name, str):
                return reg_name.lower()
    raw_name = node.name or variable.name
    return raw_name.lower() if isinstance(raw_name, str) else None


def _make_global_value_expr_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    named: NamedGlobalEvidence8616 | None,
    evidence: CompareRegisterGlobalCarrierEvidence8616,
) -> object:
    width = int(evidence.width or 2)
    if named is not None and named.width >= width:
        name = _sanitize_identifier_8616(named.name)
        _record_global_declaration_8616(codegen, width, name)
        return CVariable(
            SimMemoryVariable(evidence.offset & 0xFFFF, width, name=name, region=codegen.cfunc.addr),
            variable_type=_type_for_width_8616(width),
            codegen=codegen,
        )
    helper = (
        SegmentLoadHelper8616.SEG_U8
        if width == 1
        else SegmentLoadHelper8616.SEG_U32
        if width == 4
        else SegmentLoadHelper8616.SEG_U16
    )
    return CFunctionCall(
        helper.helper_name,
        None,
        [
            _make_segment_register_variable_8616(project, codegen, "ds"),
            CConstant(evidence.offset & 0xFFFF, SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )


def _make_segment_register_variable_8616(project: ProjectBoundary8616, codegen: CodegenBoundary8616, name: str) -> CVariable:
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _codegen_function_addr_8616(codegen: CodegenBoundary8616) -> int | None:
    """Return optional function addr from a dynamic boundary: angr codegen CFunction metadata."""

    return getattr(codegen.cfunc, "addr", None)


def _active_function_8616(project: ProjectBoundary8616, codegen: CodegenBoundary8616) -> object | None:
    """Return the active function through a dynamic boundary: angr codegen/project metadata."""

    cfunc = _codegen_cfunc_optional_8616(codegen)
    addr = getattr(cfunc, "addr", None)
    if not isinstance(addr, int):
        return None
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if functions is not None:
        try:
            function = functions.function(addr=addr, create=False)
        except Exception:
            function = None
        if function is not None:
            return function
    return SimpleNamespace(addr=addr, size=getattr(cfunc, "size", None), name=getattr(cfunc, "name", None))


def _segment_load_helper_8616(node: object) -> SegmentLoadHelper8616 | None:
    """Return the segment load helper from a dynamic boundary: angr codegen call metadata."""

    raw_name = getattr(node, "callee_target", None)
    if not isinstance(raw_name, str):
        raw_name = getattr(getattr(node, "callee_func", None), "name", None)
    if not isinstance(raw_name, str):
        return None
    normalized = raw_name.strip().upper()
    for helper in SegmentLoadHelper8616:
        if normalized == helper.helper_name:
            return helper
    return None


def _segment_pointer_helper_8616(node: object) -> SegmentPointerHelper8616 | None:
    """Return the segment pointer helper from a dynamic boundary: angr codegen call metadata."""

    raw_name = getattr(node, "callee_target", None)
    if not isinstance(raw_name, str):
        raw_name = getattr(getattr(node, "callee_func", None), "name", None)
    if not isinstance(raw_name, str):
        return None
    normalized = raw_name.strip().upper()
    for helper in SegmentPointerHelper8616:
        if normalized == helper.helper_name:
            return helper
    return None


def _memory_pointer_helper_8616(node: object) -> MemoryPointerHelper8616 | None:
    """Return the memory pointer helper from a dynamic boundary: angr codegen call metadata."""

    raw_name = getattr(node, "callee_target", None)
    if not isinstance(raw_name, str):
        raw_name = getattr(getattr(node, "callee_func", None), "name", None)
    if not isinstance(raw_name, str):
        return None
    normalized = raw_name.strip().upper()
    for helper in MemoryPointerHelper8616:
        if normalized == helper.helper_name:
            return helper
    return None


def _is_ds_segment_expr_8616(project: ProjectBoundary8616, node: object) -> bool:
    if isinstance(node, CVariable):
        variable = node.variable
        if isinstance(variable, SimRegisterVariable):
            reg = variable.reg
            if isinstance(reg, int):
                # Dynamic boundary: angr arch register tables are runtime project metadata.
                return getattr(project.arch, "register_names", {}).get(reg) == "ds"
        raw_name = node.name or variable.name
        return isinstance(raw_name, str) and raw_name.lower() == "ds"
    return False


def _constant_int_8616(node: object) -> int | None:
    node = _unwrap_codegen_expr_8616(node)
    return node.value if isinstance(node, CConstant) and isinstance(node.value, int) else None


def _cvariable_key_8616(node: object) -> str | None:
    if not isinstance(node, CVariable):
        return None
    variable = node.variable
    raw_name = node.name or variable.name
    if isinstance(raw_name, str) and raw_name:
        return _normalized_cvariable_name_8616(raw_name)
    if isinstance(variable, SimRegisterVariable):
        reg = variable.reg
        return f"reg:{reg}" if isinstance(reg, int) else None
    if isinstance(variable, SimMemoryVariable):
        addr = variable.addr
        return f"mem:{addr:x}" if isinstance(addr, int) else None
    return None


def _normalized_cvariable_name_8616(name: str) -> str:
    if name.endswith("}"):
        brace_pos = name.find("{")
        if brace_pos >= 0:
            return name[:brace_pos]
    return name


def _copy_keys_8616(node: object) -> tuple[CopyKey8616, ...]:
    key = _cvariable_key_8616(node)
    if key is not None:
        return (key,)
    return tuple(_dirty_expr_copy_keys_8616(node))


def _dirty_expr_copy_keys_8616(node: object) -> tuple[tuple[str, int | str], ...]:
    keys = _dirty_expr_keys_8616(node)
    if not keys:
        return ()
    precise = tuple(key for key in keys if key[0] in {"varid", "idx", "name", "expr_idx"})
    if precise:
        return precise
    return tuple(key for key in keys if key[0] == "oident")


def _resolve_copy_8616(node: object, copies: dict[CopyKey8616, object] | None) -> object:
    """Resolve SSA-like carriers without replacing mutable storage identities."""

    if isinstance(node, CVariable) and isinstance(node.variable, SimMemoryVariable):
        return node
    if not copies:
        return node
    for key in _copy_keys_8616(node):
        replacement = copies.get(key)
        if replacement is not None:
            return replacement
    return node


def _record_assignment_copy_8616(stmt: object, copies: dict[CopyKey8616, object]) -> None:
    if not isinstance(stmt, CAssignment):
        return
    keys = _copy_keys_8616(stmt.lhs)
    if not keys:
        return
    if _rhs_has_obvious_side_effect_8616(stmt.rhs):
        for key in keys:
            copies.pop(key, None)
        return
    for key in keys:
        copies[key] = stmt.rhs


def _rhs_has_obvious_side_effect_8616(node: object) -> bool:
    """Classify side effects from a dynamic boundary: angr codegen call metadata."""

    if isinstance(node, CFunctionCall):
        helper_name = node.callee_target
        if not isinstance(helper_name, str):
            helper_name = getattr(node.callee_func, "name", None)
        normalized = helper_name.strip().upper() if isinstance(helper_name, str) else ""
        segment_helpers = {helper.helper_name for helper in SegmentLoadHelper8616}
        memory_helpers = {helper.helper_name for helper in MemoryPointerHelper8616}
        return normalized not in segment_helpers and normalized not in memory_helpers
    for child in _iter_c_nodes_deep_8616(node):
        if child is not node and isinstance(child, CFunctionCall) and _rhs_has_obvious_side_effect_8616(child):
            return True
    return False


def _type_for_width_8616(width: int) -> SimType:
    if width == 1:
        return SimTypeChar(False)
    if width == 4:
        return SimTypeLong(False)
    return SimTypeShort(False)


def _record_global_declaration_8616(codegen: CodegenBoundary8616, width: int, name: str) -> None:
    record_global_declaration_spec_8616(
        codegen,
        ctype=ctype_for_global_width_8616(width),
        name=name,
        array_len=None,
    )


def _sanitize_identifier_8616(name: str) -> str:
    source = name if re.match(r"^_S\d+_[A-Za-z_]\w*$", name) is not None else name.lstrip("_")
    cleaned = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in source)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"g_{cleaned}" if cleaned else "g"
    return cleaned


def _cfunc_roots_8616(cfunc: object) -> tuple[object, ...]:
    """Return roots from a dynamic boundary: angr codegen CFunction runtime slots."""

    roots: list[object] = []
    seen: set[int] = set()
    for attr in ("body", "statements", "stmt"):
        root = getattr(cfunc, attr, None)
        if root is None or id(root) in seen:
            continue
        roots.append(root)
        seen.add(id(root))
    return tuple(roots)


def _sync_cfunc_statement_roots_8616(cfunc: CodegenBoundary8616, root: object) -> None:
    if cfunc is None or root is None:
        return
    with contextlib.suppress(Exception):
        # Dynamic boundary: angr CFunction objects expose mutable root slots at runtime.
        cfunc.body = root
    with contextlib.suppress(Exception):
        # Dynamic boundary: angr CFunction objects expose mutable root slots at runtime.
        cfunc.statements = root
    with contextlib.suppress(Exception):
        # Dynamic boundary: angr CFunction objects expose mutable root slots at runtime.
        cfunc.stmt = root


def _store_stats_8616(codegen: CodegenBoundary8616, stats: SegmentedGlobalLoadStats8616) -> None:
    if codegen is not None:
        codegen._inertia_segmented_global_load_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        log.warning(
            "[seg-global-loads] raw=%d normalized=%d classified=%d materialized=%d failures=%d no_evidence=%d no_cfunc=%d helper=%d segment=%d offset=%d cmp_raw=%d cmp_classified=%d cmp_materialized=%d direct_raw=%d direct_materialized=%d direct_call_return_raw=%d direct_call_return_materialized=%d direct_call_return_carrier_removed=%d indexed_store_materialized=%d indexed_store_lvalue_raw=%d indexed_store_lvalue_materialized=%d indexed_store_source_carrier_removed=%d indexed_stack_aggregate_type_promoted=%d",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            stats.refused_no_evidence,
            stats.refused_no_cfunc,
            stats.refused_helper_mismatch,
            stats.refused_segment_mismatch,
            stats.refused_offset_mismatch,
            stats.compare_register_raw_fact_count,
            stats.compare_register_classified_count,
            stats.compare_register_materialized_count,
            stats.direct_symbol_raw_fact_count,
            stats.direct_symbol_materialized_count,
            stats.direct_symbol_call_return_raw_fact_count,
            stats.direct_symbol_call_return_materialized_count,
            stats.direct_symbol_call_return_carrier_removed_count,
            stats.indexed_store_materialized_count,
            stats.indexed_store_lvalue_raw_fact_count,
            stats.indexed_store_lvalue_materialized_count,
            stats.indexed_store_source_carrier_removed_count,
            stats.indexed_stack_aggregate_type_promoted_count,
        )
