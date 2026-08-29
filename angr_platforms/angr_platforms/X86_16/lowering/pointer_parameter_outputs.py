"""Publish terminal pointer-output bindings on the Types/Lowering path.

Layer: Types/Lowering.
Responsibility: run the Semantics, Alias, and Widening pointer-output owners,
bind each resulting view to exact callee argument-width evidence, and publish
one immutable per-function result. This module does not infer caller targets,
pointee types, signatures, or rendered expressions.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from ..alias.terminal_pointer_output_contracts import TerminalPointerAliasEvidence8616
from ..alias.terminal_pointer_outputs import classify_terminal_pointer_output_aliases_8616
from ..ir.function_ssa_registry import FunctionSSAArtifactFailure8616
from ..pipeline.errors import PipelineHardError
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from ..semantics.terminal_pointer_output_contracts import TerminalPointerOutputEvidence8616
from ..semantics.terminal_pointer_outputs import (
    collect_terminal_pointer_output_evidence_8616,
)
from ..widening.terminal_pointer_output_contracts import (
    TerminalPointerOutputViewEvidence8616,
)
from ..widening.terminal_pointer_output_views import (
    widen_terminal_pointer_output_views_8616,
)
from .callee_argument_width_evidence import collect_callee_argument_width_evidence_8616
from .pointer_parameter_output_contracts import (
    PointerParameterOutputContract8616,
    PointerParameterOutputEvidence8616,
    PointerParameterOutputFailure8616,
    PointerParameterOutputStats8616,
)


class _FunctionManager8616(Protocol):
    """Third-party function lookup required at the exact boundary."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return one existing function without creating a guessed owner."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge-base surface used for exact function lookup."""

    functions: _FunctionManager8616


class _ProjectSurface8616(Protocol):
    """Owned project registry plus the third-party knowledge base."""

    kb: _KnowledgeBase8616
    _inertia_pointer_parameter_outputs_8616: dict[
        int, PointerParameterOutputEvidence8616
    ]


def _refused_8616(
    function_addr: int,
    failure: PointerParameterOutputFailure8616,
    *,
    raw_count: int = 1,
    normalized_count: int = 0,
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None,
    terminal: TerminalPointerOutputEvidence8616 | None = None,
    aliases: TerminalPointerAliasEvidence8616 | None = None,
    views: TerminalPointerOutputViewEvidence8616 | None = None,
) -> PointerParameterOutputEvidence8616:
    """Build one atomic typed refusal with retained upstream evidence."""
    return PointerParameterOutputEvidence8616(
        function_addr,
        (),
        failure,
        PointerParameterOutputStats8616(
            raw_fact_count=max(1, raw_count),
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
        ssa_failure=ssa_failure,
        terminal=terminal,
        aliases=aliases,
        views=views,
    )


def _registry_8616(
    project: object,
) -> dict[int, PointerParameterOutputEvidence8616]:
    """Return the owned per-project immutable publication registry."""
    surface = cast(_ProjectSurface8616, project)
    try:
        registry = surface._inertia_pointer_parameter_outputs_8616
    except AttributeError:
        registry = {}
        surface._inertia_pointer_parameter_outputs_8616 = registry
    if not isinstance(registry, dict):
        raise TypeError("pointer-parameter output registry must be a dict")
    return registry


def _publish_8616(
    project: object,
    evidence: PointerParameterOutputEvidence8616,
) -> PointerParameterOutputEvidence8616:
    """Publish once, replay equal evidence, and reject conflicting truth."""
    registry = _registry_8616(project)
    existing = registry.get(evidence.function_addr)
    if existing is not None and existing != evidence:
        raise PipelineHardError(
            "pointer-parameter output publication conflict",
            layer="types/lowering",
            function_addr=evidence.function_addr,
        )
    registry[evidence.function_addr] = evidence
    return evidence


def pointer_parameter_output_evidence_8616(
    project: object,
    function_addr: int,
) -> PointerParameterOutputEvidence8616 | None:
    """Return the published exact-function result when available."""
    return _registry_8616(project).get(function_addr)


def publish_pointer_parameter_outputs_8616(
    project: object,
    function_addr: int,
    *,
    function: object | None = None,
) -> PointerParameterOutputEvidence8616:
    """Materialize exact logical-input output bindings for one function."""
    owner = function
    if owner is None:
        try:
            owner = cast(_ProjectSurface8616, project).kb.functions.function(
                addr=function_addr,
                create=False,
            )
        except (AttributeError, KeyError, TypeError):
            owner = None
    if owner is None:
        return _publish_8616(
            project,
            _refused_8616(
                function_addr,
                PointerParameterOutputFailure8616.FUNCTION_UNAVAILABLE,
            ),
        )

    ssa = semantic_function_ssa_artifact_at_address_8616(
        project,
        function_addr,
        function=owner,
    )
    if ssa.artifact is None:
        return _publish_8616(
            project,
            _refused_8616(
                function_addr,
                PointerParameterOutputFailure8616.CALLEE_SSA_UNAVAILABLE,
                ssa_failure=ssa.failure,
            ),
        )
    terminal = collect_terminal_pointer_output_evidence_8616(project, ssa.artifact)
    if not terminal.complete:
        return _publish_8616(
            project,
            _refused_8616(
                function_addr,
                PointerParameterOutputFailure8616.SEMANTICS_REFUSED,
                raw_count=terminal.stats.raw_fact_count,
                normalized_count=terminal.stats.normalized_fact_count,
                terminal=terminal,
            ),
        )
    aliases = classify_terminal_pointer_output_aliases_8616(owner, terminal)
    if not aliases.complete:
        return _publish_8616(
            project,
            _refused_8616(
                function_addr,
                PointerParameterOutputFailure8616.ALIAS_REFUSED,
                raw_count=aliases.stats.raw_fact_count,
                normalized_count=aliases.stats.normalized_fact_count,
                terminal=terminal,
                aliases=aliases,
            ),
        )
    views = widen_terminal_pointer_output_views_8616(aliases)
    if not views.complete:
        return _publish_8616(
            project,
            _refused_8616(
                function_addr,
                PointerParameterOutputFailure8616.WIDENING_REFUSED,
                raw_count=views.stats.raw_fact_count,
                normalized_count=views.stats.normalized_fact_count,
                terminal=terminal,
                aliases=aliases,
                views=views,
            ),
        )
    if not views.facts:
        return _publish_8616(
            project,
            PointerParameterOutputEvidence8616(
                function_addr,
                (),
                None,
                PointerParameterOutputStats8616(),
                terminal=terminal,
                aliases=aliases,
                views=views,
            ),
        )

    widths = collect_callee_argument_width_evidence_8616(project, function_addr)
    if not widths.closes_census:
        return _publish_8616(
            project,
            _refused_8616(
                function_addr,
                PointerParameterOutputFailure8616.ARGUMENT_WIDTHS_REFUSED,
                raw_count=len(views.facts),
                terminal=terminal,
                aliases=aliases,
                views=views,
            ),
        )
    facts: list[PointerParameterOutputContract8616] = []
    for view in views.facts:
        matches = tuple(
            (logical_index, storage)
            for logical_index, storage in enumerate(widths.argument_storage)
            if storage.space is view.parameter_storage.space
            and storage.base == view.parameter_storage.base
            and storage.offset == view.parameter_storage.offset
            and storage.size == view.parameter_storage.size
        )
        if len(matches) != 1:
            failure = (
                PointerParameterOutputFailure8616.PARAMETER_STORAGE_UNMATCHED
                if not matches
                else PointerParameterOutputFailure8616.PARAMETER_STORAGE_CONFLICT
            )
            return _publish_8616(
                project,
                _refused_8616(
                    function_addr,
                    failure,
                    raw_count=len(views.facts),
                    normalized_count=len(facts),
                    terminal=terminal,
                    aliases=aliases,
                    views=views,
                ),
            )
        logical_index, storage = matches[0]
        facts.append(PointerParameterOutputContract8616(logical_index, storage, view))

    count = len(facts)
    result = PointerParameterOutputEvidence8616(
        function_addr,
        tuple(facts),
        None,
        PointerParameterOutputStats8616(count, count, count, count),
        terminal=terminal,
        aliases=aliases,
        views=views,
    )
    if not result.complete:
        raise PipelineHardError(
            "classified pointer-parameter outputs were not materialized",
            layer="types/lowering",
            function_addr=function_addr,
        )
    return _publish_8616(project, result)


__all__ = [
    "pointer_parameter_output_evidence_8616",
    "publish_pointer_parameter_outputs_8616",
]
