"""Materialize typed direct-call declarations without changing call semantics.

Layer: Types/lowering.
Responsibility: lower typed callsite summaries and structured argument types
into recompilable C declaration metadata after structuring creates direct calls.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: source/COD/assembly/rendered-C recovery, callee prototype mutation,
call-argument repair, or AST mutation.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr.sim_type import SimStruct, SimType, SimTypeArray, SimTypeFixedSizeArray, SimTypePointer

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import (
    CallsiteSummary8616,
    caller_return_use_evidence_by_addr_8616,
)
from ..codegen_metadata import get_codegen_sequence_attr, set_codegen_sequence_attr
from .c_runtime_header import (
    KNOWN_EXTERNAL_RETURN_TYPES_8616,
    runtime_helper_declaration_8616,
)
from .return_type_evidence import caller_return_use_evidence_proves_unused_8616

__all__ = ["materialize_callsite_prototype_declarations_8616"]

_C_IDENTIFIER_RE_8616 = re.compile(r"[A-Za-z_]\w*")
_DECLARATION_NAME_RE_8616 = re.compile(
    r"^\s*[A-Za-z_][\w\s*]*?\s+(?P<name>[A-Za-z_]\w*)\s*\("
)
_LOGGER = logging.getLogger(__name__)


class _CodegenSurface8616(Protocol):
    """Owned view of dynamic codegen fields consumed by this lowering pass."""

    cfunc: object
    _inertia_callsite_summaries: object


class _CFunctionSurface8616(Protocol):
    """Minimal structured function boundary used to find the current root."""

    statements: object
    body: object


class _NamedFunctionSurface8616(Protocol):
    """Minimal callee identity exposed by angr function objects."""

    name: object


class _AddressedFunctionSurface8616(Protocol):
    """Minimal callee identity used for target-backed summary rebinding."""

    addr: object
    name: object


class _FunctionManagerSurface8616(Protocol):
    """Minimal project function lookup used at the angr boundary."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Return the function at an exact target address."""


class _KnowledgeBaseSurface8616(Protocol):
    """Minimal knowledge-base surface used for exact target lookup."""

    functions: _FunctionManagerSurface8616


class _ProjectSurface8616(Protocol):
    """Minimal project surface used for exact target lookup."""

    kb: _KnowledgeBaseSurface8616


class _TargetProjectSurface8616(Protocol):
    """Minimal owned project policy used to select the generated-C ABI."""

    _inertia_c_target: str


class _TypedExpressionSurface8616(Protocol):
    """Minimal structured expression type boundary exposed by angr."""

    type: object


@dataclass(frozen=True, slots=True)
class _CallsiteDeclarationInterface8616:
    """Typed callsite fields that determine one generated C declaration."""

    target_addr: int | None
    argument_widths: tuple[int, ...]
    stack_probe_helper: bool


class _CallsiteReturnClass8616(Enum):
    """ABI-visible return classes proven by caller-side use."""

    UNKNOWN = "unknown"
    AX = "unsigned short"
    DX_AX = "unsigned long"


def _structured_root_8616(cfunc: object) -> object | None:
    """Return the current structured root from the angr C function boundary."""
    if cfunc is None:
        return None
    surface = cast(_CFunctionSurface8616, cfunc)
    try:
        statements = surface.statements
    except AttributeError:
        statements = None
    if statements is not None:
        return statements
    try:
        return surface.body
    except AttributeError:
        return None


def _call_name_8616(node: CFunctionCall) -> str | None:
    """Return a valid direct-call name from typed structured-call identity."""
    target = node.callee_target
    if isinstance(target, str) and _C_IDENTIFIER_RE_8616.fullmatch(target) is not None:
        return target
    callee = node.callee_func
    if callee is None:
        return None
    try:
        name = cast(_NamedFunctionSurface8616, callee).name
    except AttributeError:
        return None
    return name if isinstance(name, str) and _C_IDENTIFIER_RE_8616.fullmatch(name) is not None else None


def _typed_summary_map_8616(value: object) -> dict[int, CallsiteSummary8616]:
    """Narrow dynamic codegen metadata to the owned typed summary contract."""
    if not isinstance(value, Mapping):
        return {}
    return {
        node_id: summary
        for node_id, summary in value.items()
        if isinstance(node_id, int) and isinstance(summary, CallsiteSummary8616)
    }


def _summary_for_call_8616(
    project: object,
    node: CFunctionCall,
    summaries: Mapping[int, CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Resolve exact identity or repeated summaries with one proven interface."""
    exact = summaries.get(id(node))
    if exact is not None:
        return exact
    tags = node.tags
    callsite_addr = None
    if isinstance(tags, Mapping):
        for key in ("ins_addr", "insn_addr", "stmt_addr", "addr"):
            value = tags.get(key)
            if isinstance(value, int):
                callsite_addr = value
                break
    if not isinstance(callsite_addr, int):
        matches = ()
    else:
        matches = tuple(summary for summary in summaries.values() if summary.callsite_addr == callsite_addr)
    compatible = _compatible_summary_8616(matches)
    if compatible is not None:
        return compatible
    callee = node.callee_func
    if callee is not None:
        try:
            callee_addr = cast(_AddressedFunctionSurface8616, callee).addr
        except AttributeError:
            callee_addr = None
        if isinstance(callee_addr, int):
            matches = tuple(summary for summary in summaries.values() if summary.target_addr == callee_addr)
            compatible = _compatible_summary_8616(matches)
            if compatible is not None:
                return compatible
    call_name = _call_name_8616(node)
    if call_name is None:
        return None
    try:
        functions = cast(_ProjectSurface8616, project).kb.functions
    except AttributeError:
        return None
    target_matches: list[CallsiteSummary8616] = []
    for summary in summaries.values():
        if not isinstance(summary.target_addr, int):
            continue
        try:
            function = functions.function(addr=summary.target_addr, create=False)
        except (KeyError, TypeError):
            continue
        if function is None:
            continue
        try:
            target_name = cast(_AddressedFunctionSurface8616, function).name
        except AttributeError:
            continue
        if target_name == call_name:
            target_matches.append(summary)
    return _compatible_summary_8616(target_matches)


def _summary_arg_widths_8616(summary: CallsiteSummary8616) -> tuple[int, ...] | None:
    """Return exact logical argument widths or refuse an incomplete summary."""
    if not isinstance(summary.arg_count, int) or summary.arg_count < 0:
        return None
    logical = summary.logical_arg_widths
    if logical:
        if not all(isinstance(width, int) and width > 0 for width in logical):
            return None
        return logical
    widths = summary.arg_widths
    if len(widths) != summary.arg_count or not all(isinstance(width, int) and width > 0 for width in widths):
        return None
    return widths


def _scalar_decl_for_width_8616(width: int, name: str) -> str:
    """Render a target-width scalar argument declaration."""
    if width >= 4:
        return f"unsigned long {name}"
    if width == 1:
        return f"unsigned char {name}"
    return f"unsigned short {name}"


def _argument_decl_8616(argument: object, width: int, index: int) -> str:
    """Render pointer class from typed AST evidence, otherwise summary width."""
    try:
        argument_type = cast(_TypedExpressionSurface8616, argument).type
    except AttributeError:
        argument_type = None
    if isinstance(argument_type, SimTypePointer):
        return cast(SimType, argument_type).c_repr(name=f"a{index}")
    if isinstance(argument_type, (SimTypeArray, SimTypeFixedSizeArray)):
        return cast(SimType, argument_type).c_repr(name=f"a{index}")
    return _scalar_decl_for_width_8616(width, f"a{index}")


def _argument_forward_declarations_8616(argument: object) -> tuple[str, ...]:
    """Return file-scope tag declarations required by one typed argument."""
    try:
        argument_type = cast(_TypedExpressionSurface8616, argument).type
    except AttributeError:
        return ()
    if not isinstance(argument_type, SimTypePointer):
        return ()
    pointee = argument_type.pts_to
    if not isinstance(pointee, SimStruct) or not isinstance(pointee.name, str):
        return ()
    if _C_IDENTIFIER_RE_8616.fullmatch(pointee.name) is None:
        return ()
    return (f"struct {pointee.name};",)


def _used_return_class_8616(
    summary: CallsiteSummary8616,
) -> _CallsiteReturnClass8616 | None:
    """Return a proven used-result class; unused results provide no evidence."""
    if summary.return_used is not True:
        return None
    if summary.return_shape == "dx_ax":
        return _CallsiteReturnClass8616.DX_AX
    if summary.return_register == "ax" or summary.return_shape == "ax":
        return _CallsiteReturnClass8616.AX
    return _CallsiteReturnClass8616.UNKNOWN


def _joined_return_type_8616(
    project: object,
    summary: CallsiteSummary8616,
    summaries: Sequence[CallsiteSummary8616],
) -> str | None:
    """Join caller-use evidence for one exact target or refuse ABI conflict."""
    if isinstance(summary.target_addr, int):
        related = tuple(candidate for candidate in summaries if candidate.target_addr == summary.target_addr)
    else:
        related = (summary,)
    used_classes = {
        return_class
        for candidate in related
        if (return_class := _used_return_class_8616(candidate)) is not None
    }
    if _CallsiteReturnClass8616.UNKNOWN in used_classes or len(used_classes) > 1:
        return None
    if not used_classes:
        evidence = (
            caller_return_use_evidence_by_addr_8616(project).get(summary.target_addr)
            if isinstance(summary.target_addr, int)
            else None
        )
        if os.environ.get("INERTIA_DEBUG_RETURN_TYPE_EVIDENCE") == "1":
            _LOGGER.warning(
                "callsite return declaration evidence: target=%s verdict=%s raw=%d classified=%d "
                "materialized=%d failures=%d",
                hex(summary.target_addr) if isinstance(summary.target_addr, int) else None,
                evidence.verdict.value if evidence is not None else "missing",
                evidence.raw_fact_count if evidence is not None else 0,
                evidence.classified_fact_count if evidence is not None else 0,
                evidence.materialized_count if evidence is not None else 0,
                evidence.failure_count if evidence is not None else 0,
            )
        if evidence is not None and caller_return_use_evidence_proves_unused_8616(evidence):
            return "void"
        return "int"
    return next(iter(used_classes)).value


def _declaration_interface_8616(
    summary: CallsiteSummary8616,
) -> _CallsiteDeclarationInterface8616 | None:
    """Return the declaration contract or refuse incomplete argument evidence."""
    widths = _summary_arg_widths_8616(summary)
    if widths is None:
        return None
    return _CallsiteDeclarationInterface8616(
        target_addr=summary.target_addr,
        argument_widths=widths,
        stack_probe_helper=summary.stack_probe_helper,
    )


def _compatible_summary_8616(
    summaries: Sequence[CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Return one representative only when every summary proves one interface."""
    if not summaries:
        return None
    first = summaries[0]
    expected = _declaration_interface_8616(first)
    if expected is None:
        return None
    for summary in summaries[1:]:
        if _declaration_interface_8616(summary) != expected:
            return None
    return first


def _prototype_decl_8616(
    node: CFunctionCall,
    summary: CallsiteSummary8616,
    return_type: str,
) -> str | None:
    """Build one declaration when name, arity, widths, and arguments agree."""
    name = _call_name_8616(node)
    widths = _summary_arg_widths_8616(summary)
    arguments = tuple(cast(Sequence[object], node.args or ()))
    if name is None or widths is None or len(arguments) != len(widths):
        return None
    args = "void" if not arguments else ", ".join(
        _argument_decl_8616(argument, width, index)
        for index, (argument, width) in enumerate(zip(arguments, widths, strict=True))
    )
    return f"{return_type} {name}({args});"


def _declaration_name_8616(declaration: str) -> str | None:
    """Return the outer function name from a generated C declaration."""
    match = _DECLARATION_NAME_RE_8616.match(declaration)
    return match.group("name") if match is not None else None


def _project_c_target_8616(project: object) -> str | None:
    """Return the configured generated-C target from the project policy."""
    try:
        target = cast(_TargetProjectSurface8616, project)._inertia_c_target
    except AttributeError:
        return None
    return target if isinstance(target, str) else None


def materialize_callsite_prototype_declarations_8616(project: object, codegen: object) -> bool:
    """Store evidence-backed declaration metadata for current direct calls.

    This pass deliberately does not assign ``callee.prototype``. It runs after
    call-producing structuring passes, where semantic prototype mutation can
    invalidate an already materialized return call.
    """
    surface = cast(_CodegenSurface8616, codegen)
    try:
        root = _structured_root_8616(surface.cfunc)
        summaries = _typed_summary_map_8616(surface._inertia_callsite_summaries)
    except AttributeError:
        return False
    if root is None or not summaries:
        if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
            _LOGGER.warning(
                "callsite declaration lowering unavailable: root=%s summaries=%d",
                root is not None,
                len(summaries),
            )
        return False
    existing = get_codegen_sequence_attr(codegen, surface.cfunc, "_inertia_callsite_prototype_decls")
    desired_by_name: dict[str, str] = {}
    required_forward_decls: set[str] = set()
    ambiguous_names: set[str] = set()
    call_count = 0
    matched_count = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        call_count += 1
        summary = _summary_for_call_8616(project, node, summaries)
        if summary is None or summary.stack_probe_helper:
            continue
        matched_count += 1
        if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
            _LOGGER.warning(
                "callsite declaration evidence: name=%s callsite=%#x target=%s "
                "arg_count=%s arg_widths=%s logical_widths=%s return_register=%s "
                "return_used=%s return_shape=%s",
                _call_name_8616(node),
                summary.callsite_addr,
                None if summary.target_addr is None else hex(summary.target_addr),
                summary.arg_count,
                summary.arg_widths,
                summary.logical_arg_widths,
                summary.return_register,
                summary.return_used,
                summary.return_shape,
            )
        call_name = _call_name_8616(node)
        inferred_return_type = _joined_return_type_8616(project, summary, tuple(summaries.values()))
        return_type = (
            KNOWN_EXTERNAL_RETURN_TYPES_8616.get(call_name, inferred_return_type)
            if call_name is not None
            else inferred_return_type
        )
        runtime_declaration = (
            runtime_helper_declaration_8616(call_name, _project_c_target_8616(project))
            if call_name is not None
            else None
        )
        declaration = runtime_declaration
        if declaration is None and return_type is not None:
            declaration = _prototype_decl_8616(node, summary, return_type)
        if declaration is None:
            if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
                _LOGGER.warning(
                    "callsite declaration refused: callsite=%#x name=%s args=%d widths=%s",
                    summary.callsite_addr,
                    _call_name_8616(node),
                    len(tuple(cast(Sequence[object], node.args or ()))),
                    _summary_arg_widths_8616(summary),
                )
            continue
        for argument in tuple(cast(Sequence[object], node.args or ())):
            required_forward_decls.update(_argument_forward_declarations_8616(argument))
        name = _declaration_name_8616(declaration)
        if name is None or name in ambiguous_names:
            continue
        previous = desired_by_name.get(name)
        if previous is not None and previous != declaration:
            if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
                _LOGGER.warning(
                    "callsite declaration conflict: name=%s previous=%s current=%s callsite=%#x",
                    name,
                    previous,
                    declaration,
                    summary.callsite_addr,
                )
            desired_by_name.pop(name, None)
            ambiguous_names.add(name)
            continue
        desired_by_name[name] = declaration
    if not desired_by_name:
        if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
            _LOGGER.warning(
                "callsite declaration lowering produced no declarations: "
                "calls=%d summaries=%d matched=%d existing=%d ambiguous=%s",
                call_count,
                len(summaries),
                matched_count,
                len(existing),
                tuple(sorted(ambiguous_names)),
            )
        return False
    merged: list[str] = []
    materialized_names: set[str] = set()
    for declaration in existing:
        name = _declaration_name_8616(declaration)
        desired = desired_by_name.get(name or "")
        if desired is None:
            merged.append(declaration)
            continue
        if name is not None and name not in materialized_names:
            merged.append(desired)
            materialized_names.add(name)
    for name, declaration in desired_by_name.items():
        if name not in materialized_names:
            merged.append(declaration)
            materialized_names.add(name)
    ordered_forward_decls = tuple(sorted(required_forward_decls))
    merged_tuple = (
        *ordered_forward_decls,
        *(declaration for declaration in merged if declaration not in required_forward_decls),
    )
    if merged_tuple == existing:
        return False
    if os.environ.get("INERTIA_DEBUG_CALLSITE_PROTOTYPE_DECLS") == "1":
        _LOGGER.warning(
            "callsite declaration lowering materialized: calls=%d summaries=%d matched=%d declarations=%s",
            call_count,
            len(summaries),
            matched_count,
            tuple(desired_by_name.values()),
        )
    set_codegen_sequence_attr(
        codegen,
        surface.cfunc,
        "_inertia_callsite_prototype_decls",
        merged_tuple,
    )
    return True
