"""Lower closed caller-use evidence into a function return type.

Layer: Types/lowering.
Responsibility: materialize a void return type only when binary caller analysis
proves every discovered call result is unused.
Consumes alias, widening, and typed facts from typed caller-use evidence.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not inspect function names or postprocess output.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from enum import StrEnum
from typing import Protocol, cast

from angr.sim_type import SimTypeBottom, SimTypeFunction
from archinfo import Arch

from ..annotations import ANNOTATION_KEY
from ..callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    caller_return_use_evidence_by_addr_8616,
)

__all__ = [
    "caller_return_use_evidence_proves_used_8616",
    "caller_return_use_evidence_proves_unused_8616",
    "FunctionReturnClass8616",
    "function_has_proven_void_return_type_8616",
    "materialize_proven_void_return_type_8616",
    "proven_function_return_class_8616",
]

_LOGGER = logging.getLogger(__name__)


class _ProjectReturnTypeSurface8616(Protocol):
    """Third-party project fields required for return-type materialization."""

    arch: Arch


class _FunctionReturnTypeSurface8616(Protocol):
    """Third-party function fields required for return-type materialization."""

    addr: int
    info: object
    prototype: object
    is_prototype_guessed: bool


class FunctionReturnClass8616(StrEnum):
    """Binary-proven logical class of one function result."""

    VOID = "void"
    VALUE = "value"


def _function_has_explicit_prototype_annotation_8616(function: _FunctionReturnTypeSurface8616) -> bool:
    """Return whether the function carries a direct explicit prototype annotation."""
    annotations = function.info.get(ANNOTATION_KEY) if isinstance(function.info, Mapping) else None
    return isinstance(annotations, Mapping) and isinstance(annotations.get("prototype"), SimTypeFunction)


def caller_return_use_evidence_proves_used_8616(
    evidence: CallerReturnUseEvidence8616,
) -> bool:
    """Return whether at least one classified caller provably consumes the result."""
    return (
        evidence.verdict is CallerReturnUseVerdict8616.USED
        and evidence.raw_fact_count > 0
        and evidence.normalized_fact_count == evidence.raw_fact_count
        and evidence.classified_fact_count > 0
        and evidence.materialized_count == evidence.classified_fact_count
        and evidence.used_callsite_count > 0
        and evidence.used_callsite_count <= evidence.classified_fact_count
    )


def caller_return_use_evidence_proves_unused_8616(
    evidence: CallerReturnUseEvidence8616,
) -> bool:
    """Return whether caller-use evidence proves an unused result without gaps."""
    return (
        evidence.verdict is CallerReturnUseVerdict8616.UNUSED
        and evidence.raw_fact_count > 0
        and evidence.normalized_fact_count == evidence.raw_fact_count
        and evidence.classified_fact_count == evidence.normalized_fact_count
        and evidence.materialized_count == evidence.classified_fact_count
        and evidence.failure_count == 0
        and evidence.used_callsite_count == 0
        and evidence.unused_callsite_count == evidence.classified_fact_count
    )


def proven_function_return_class_8616(
    project: object,
    function_addr: int,
) -> FunctionReturnClass8616 | None:
    """Classify a function result only from closed binary caller-use evidence."""
    evidence = caller_return_use_evidence_by_addr_8616(project).get(function_addr)
    if not isinstance(evidence, CallerReturnUseEvidence8616):
        return None
    if caller_return_use_evidence_proves_used_8616(evidence):
        return FunctionReturnClass8616.VALUE
    if caller_return_use_evidence_proves_unused_8616(evidence):
        return FunctionReturnClass8616.VOID
    return None


def function_has_proven_void_return_type_8616(project: object, function: object) -> bool:
    """Return whether Lowering retains complete caller-use proof for a void result."""
    function_surface = cast(_FunctionReturnTypeSurface8616, function)
    try:
        function_addr = function_surface.addr
        prototype = function_surface.prototype
        prototype_guessed = function_surface.is_prototype_guessed
    except AttributeError:
        return False
    evidence = (
        caller_return_use_evidence_by_addr_8616(project).get(function_addr)
        if isinstance(function_addr, int)
        else None
    )
    return (
        isinstance(evidence, CallerReturnUseEvidence8616)
        and caller_return_use_evidence_proves_unused_8616(evidence)
        and isinstance(prototype, SimTypeFunction)
        and isinstance(prototype.returnty, SimTypeBottom)
        and prototype.returnty.label == "void"
        and prototype_guessed is False
    )


def materialize_proven_void_return_type_8616(project: object, function: object) -> bool:
    """Set a non-explicit function return to void from closed binary caller evidence."""
    function_surface = cast(_FunctionReturnTypeSurface8616, function)
    try:
        function_addr = function_surface.addr
        has_explicit_prototype = _function_has_explicit_prototype_annotation_8616(function_surface)
        prototype = function_surface.prototype
        prototype_guessed = function_surface.is_prototype_guessed
    except AttributeError:
        return False
    evidence_by_addr = caller_return_use_evidence_by_addr_8616(project)
    evidence = evidence_by_addr.get(function_addr) if isinstance(function_addr, int) else None
    if os.environ.get("INERTIA_DEBUG_RETURN_TYPE_EVIDENCE") == "1":
        _LOGGER.warning(
            "return-type evidence input: function=%s guessed=%s explicit=%s prototype=%s "
            "evidence_keys=%s verdict=%s",
            hex(function_addr) if isinstance(function_addr, int) else function_addr,
            prototype_guessed,
            has_explicit_prototype,
            type(prototype).__name__,
            tuple(hex(addr) for addr in sorted(evidence_by_addr)),
            evidence.verdict.value if evidence is not None else None,
        )
    if (
        not isinstance(function_addr, int)
        or (prototype is not None and not isinstance(prototype, SimTypeFunction))
        or not isinstance(prototype_guessed, bool)
        or (prototype_guessed is False and has_explicit_prototype)
    ):
        return False

    if evidence is None or not caller_return_use_evidence_proves_unused_8616(evidence):
        return False

    project_surface = cast(_ProjectReturnTypeSurface8616, project)
    try:
        void_type = SimTypeBottom(label="void").with_arch(project_surface.arch)
        prototype_args = list(prototype.args) if isinstance(prototype, SimTypeFunction) else []
        prototype_arg_names = prototype.arg_names if isinstance(prototype, SimTypeFunction) else None
        prototype_variadic = prototype.variadic if isinstance(prototype, SimTypeFunction) else False
        new_prototype = SimTypeFunction(
            prototype_args,
            void_type,
            arg_names=prototype_arg_names,
            variadic=prototype_variadic,
        ).with_arch(project_surface.arch)
    except AttributeError:
        return False

    function_surface.prototype = new_prototype
    function_surface.is_prototype_guessed = False
    if os.environ.get("INERTIA_DEBUG_RETURN_TYPE_EVIDENCE") == "1":
        _LOGGER.warning(
            "return-type evidence materialized void: function=%#x callers=%d",
            function_addr,
            evidence.materialized_count,
        )
    return True
