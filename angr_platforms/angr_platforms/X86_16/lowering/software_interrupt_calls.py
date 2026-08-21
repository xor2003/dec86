"""Materialize typed software-interrupt inputs in structured C calls.

Layer: Types/Lowering.
Responsibility: consume Semantics-owned interrupt input facts and map exact
constants, stack variables, and value operations to C arguments. No register
recovery, disassembly parsing, source metadata, or rendered-C matching belongs
here.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _clone_c_ast_tree_8616, _iter_c_nodes_deep_8616
from ..codegen_metadata import get_codegen_side_metadata
from ..ir.core import IRBinaryValue, IRFunctionArtifact, IRValue, MemSpace
from ..pipeline.errors import PipelineHardError
from ..semantics.software_interrupt_inputs import (
    IRScalarValue8616,
    SoftwareInterruptInputArtifact8616,
    SoftwareInterruptInputFact8616,
    build_software_interrupt_input_artifact_8616,
    software_interrupt_value_fingerprint_8616,
)

__all__ = [
    "SoftwareInterruptMaterializationStats8616",
    "materialize_software_interrupt_calls_8616",
]


@dataclass(slots=True)
class SoftwareInterruptMaterializationStats8616:
    """Closed evidence counters for interrupt call argument lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class _CFunctionSurface8616(Protocol):
    """Third-party C function fields consumed by interrupt lowering."""

    addr: int
    statements: object
    arg_list: object


class _CodegenSurface8616(Protocol):
    """Codegen fields carrying typed IR and interrupt facts."""

    cfunc: _CFunctionSurface8616
    _inertia_vex_ir_artifact: IRFunctionArtifact
    _inertia_software_interrupt_input_artifact_8616: SoftwareInterruptInputArtifact8616


class _TaggedCallSurface8616(Protocol):
    """Third-party structured call fields used at the Lowering boundary."""

    tags: object
    args: object


class _CVariableSurface8616(Protocol):
    """Third-party C variable storage field."""

    variable: object


def _callsite_addr_8616(call: structured_c.CFunctionCall) -> int | None:
    """Return the exact instruction address tagged on a structured call."""
    try:
        tags = cast(_TaggedCallSurface8616, call).tags
    except AttributeError:
        return None
    if not isinstance(tags, dict):
        return None
    value = tags.get("ins_addr")
    return value if isinstance(value, int) else None


def _stack_variable_8616(node: object) -> SimStackVariable | None:
    """Return exact stack storage from one C variable expression."""
    if not isinstance(node, structured_c.CVariable):
        return None
    try:
        variable = cast(_CVariableSurface8616, node).variable
    except AttributeError:
        return None
    return variable if isinstance(variable, SimStackVariable) else None


def _candidate_stack_cvars_8616(
    codegen: _CodegenSurface8616,
    root: object,
) -> tuple[structured_c.CVariable, ...]:
    """Collect deterministic C variable candidates from arguments and body."""
    candidates: list[structured_c.CVariable] = []
    seen: set[int] = set()
    arg_list = codegen.cfunc.arg_list
    sources: list[object] = []
    if isinstance(arg_list, Sequence) and not isinstance(arg_list, (str, bytes)):
        sources.extend(arg_list)
    sources.extend(_iter_c_nodes_deep_8616(root))
    for node in sources:
        if not isinstance(node, structured_c.CVariable) or id(node) in seen:
            continue
        seen.add(id(node))
        candidates.append(node)
    return tuple(candidates)


def _stack_cvar_for_value_8616(
    value: IRValue,
    candidates: tuple[structured_c.CVariable, ...],
    codegen: object,
) -> structured_c.CVariable | None:
    """Resolve or rematerialize an exact Semantics-proven SS stack value."""
    if value.space is not MemSpace.SS or value.name not in {"bp", "sp"}:
        return None
    for candidate in candidates:
        variable = _stack_variable_8616(candidate)
        if variable is None:
            continue
        if variable.offset == value.offset and variable.size == value.size:
            return cast(structured_c.CVariable, _clone_c_ast_tree_8616(candidate))
    surface = cast(_CodegenSurface8616, codegen)
    try:
        region = surface.cfunc.addr
    except AttributeError:
        region = None
    is_argument = value.name == "bp" and value.offset >= 4
    name = f"arg_{value.offset:x}" if is_argument else f"local_{abs(value.offset):x}"
    variable = SimStackVariable(
        value.offset,
        value.size,
        base=value.name,
        name=name,
        region=region,
    )
    return structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _lower_value_8616(
    value: IRScalarValue8616,
    codegen: object,
    candidates: tuple[structured_c.CVariable, ...],
) -> structured_c.CExpression | None:
    """Lower one typed interrupt argument without rediscovering semantics."""
    if isinstance(value, IRBinaryValue):
        lhs = _lower_value_8616(value.lhs, codegen, candidates)
        rhs = _lower_value_8616(value.rhs, codegen, candidates)
        if lhs is None or rhs is None:
            return None
        return structured_c.CBinaryOp(value.op, lhs, rhs, codegen=codegen)
    if value.space is MemSpace.CONST and value.const is not None:
        value_type = {
            1: SimTypeChar(False),
            2: SimTypeShort(False),
        }.get(value.size)
        if value_type is None:
            return None
        return structured_c.CConstant(value.const, value_type, codegen=codegen)
    return _stack_cvar_for_value_8616(value, candidates, codegen)


def _actual_value_fingerprint_8616(node: object) -> str | None:
    """Fingerprint the final C subset emitted from interrupt input facts."""
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        if isinstance(node.type, SimTypeChar):
            size = 1
        elif isinstance(node.type, SimTypeShort):
            size = 2
        else:
            return None
        return f"const:{node.value:#x}:size{size}"
    if isinstance(node, structured_c.CVariable):
        variable = _stack_variable_8616(node)
        if variable is not None:
            return f"stack:SS:BP{variable.offset:+#x}:size{variable.size}"
        return None
    if isinstance(node, structured_c.CBinaryOp):
        lhs = _actual_value_fingerprint_8616(node.lhs)
        rhs = _actual_value_fingerprint_8616(node.rhs)
        if lhs is None or rhs is None:
            return None
        size = 2
        return f"{node.op}({lhs},{rhs}):size{size}"
    return None


def _call_has_expected_arguments_8616(
    call: structured_c.CFunctionCall,
    fact: SoftwareInterruptInputFact8616,
) -> bool:
    """Return whether final call arguments match all proven input values."""
    args = cast(_TaggedCallSurface8616, call).args
    if not isinstance(args, Sequence) or isinstance(args, (str, bytes)):
        return False
    actual = tuple(_actual_value_fingerprint_8616(arg) for arg in args)
    expected = tuple(
        software_interrupt_value_fingerprint_8616(value)
        for value in fact.argument_values
    )
    return actual == expected


def _materialize_fact_8616(
    codegen: _CodegenSurface8616,
    root: object,
    fact: SoftwareInterruptInputFact8616,
    candidates: tuple[structured_c.CVariable, ...],
) -> tuple[bool, bool]:
    """Materialize one exact fact and report success plus AST change."""
    calls = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CFunctionCall)
        and _callsite_addr_8616(node) == fact.callsite_addr
    )
    if len(calls) != 1:
        return False, False
    call = calls[0]
    if _call_has_expected_arguments_8616(call, fact):
        return True, False
    arguments = tuple(
        _lower_value_8616(value, codegen, candidates)
        for value in fact.argument_values
    )
    if any(argument is None for argument in arguments):
        return False, False
    cast(_TaggedCallSurface8616, call).args = [
        cast(structured_c.CExpression, argument) for argument in arguments
    ]
    return _call_has_expected_arguments_8616(call, fact), True


def materialize_software_interrupt_calls_8616(codegen: object) -> bool:
    """Attach Semantics facts and materialize every classified interrupt call."""
    surface = cast(_CodegenSurface8616, codegen)
    try:
        ir_artifact = surface._inertia_vex_ir_artifact
        root = surface.cfunc.statements
    except AttributeError:
        return False
    artifact = build_software_interrupt_input_artifact_8616(ir_artifact)
    surface._inertia_software_interrupt_input_artifact_8616 = artifact
    stats = SoftwareInterruptMaterializationStats8616(
        raw_fact_count=artifact.stats.raw_fact_count,
        normalized_fact_count=artifact.stats.normalized_fact_count,
        classified_fact_count=artifact.stats.classified_fact_count,
        failure_count=artifact.stats.failure_count,
    )
    candidates = _candidate_stack_cvars_8616(surface, root)
    changed = False
    for fact in artifact.facts:
        materialized, fact_changed = _materialize_fact_8616(surface, root, fact, candidates)
        if materialized:
            stats.materialized_count += 1
        else:
            stats.failure_count += 1
        changed = fact_changed or changed
    get_codegen_side_metadata(codegen)["software_interrupt_materialization_8616"] = stats
    if stats.failure_count > 0 or stats.classified_fact_count != stats.materialized_count:
        raise PipelineHardError(
            "classified software interrupt inputs were not materialized",
            layer="lowering",
        )
    return changed
