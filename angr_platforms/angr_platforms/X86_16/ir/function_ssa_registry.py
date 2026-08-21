"""Cache exact function SSA artifacts on one analysis project.

Layer: IR.
Responsibility: build and retain one typed ``SSAFunctionArtifact`` for an exact
function boundary so later Alias and Types/Lowering consumers share the same
program-owned dataflow truth.
This module does not classify interfaces or mutate codegen.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import SimpleNamespace
from typing import Protocol, cast

from .ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from .vex_import import build_x86_16_ir_function_artifact

__all__ = [
    "FunctionSSAArtifactFailure8616",
    "FunctionSSAArtifactResolution8616",
    "FunctionSSAArtifactStage8616",
    "FunctionSSAArtifactVerdict8616",
    "function_boundary_at_address_8616",
    "function_ssa_artifact_at_address_8616",
    "publish_function_ssa_artifact_8616",
    "registered_function_ssa_artifact_8616",
]


class FunctionSSAArtifactVerdict8616(StrEnum):
    """Typed outcome of one program-owned SSA lookup."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class FunctionSSAArtifactStage8616(StrEnum):
    """Earliest pipeline stage whose facts are present in one SSA artifact."""

    IR = "ir"
    SEMANTIC = "semantic"


class FunctionSSAArtifactFailure8616(StrEnum):
    """Stable reasons why one exact caller SSA artifact is unavailable."""

    FUNCTION_NOT_FOUND = "function_not_found"
    IR_BUILD_FAILED = "ir_build_failed"
    IR_BUILD_REFUSED = "ir_build_refused"
    SEMANTIC_BUILD_FAILED = "semantic_build_failed"
    ARTIFACT_NOT_REGISTERED = "artifact_not_registered"
    ARTIFACT_CONFLICT = "artifact_conflict"


@dataclass(frozen=True, slots=True)
class FunctionSSAArtifactResolution8616:
    """One exact function SSA artifact or a typed refusal."""

    function_addr: int
    verdict: FunctionSSAArtifactVerdict8616
    artifact: SSAFunctionArtifact | None
    failure: FunctionSSAArtifactFailure8616 | None
    stage: FunctionSSAArtifactStage8616 | None


class _FunctionManager8616(Protocol):
    """Third-party function-manager surface used for exact lookup."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function without inventing a boundary."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge-base surface used by this IR owner."""

    functions: _FunctionManager8616


class _ProjectSSARegistrySurface8616(Protocol):
    """angr project plus the owned typed SSA registry extension."""

    kb: _KnowledgeBase8616
    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_function_ssa_artifacts_8616: dict[int, SSAFunctionArtifact]
    _inertia_function_ssa_stages_8616: dict[int, FunctionSSAArtifactStage8616]


def _registry_8616(project: object) -> dict[int, SSAFunctionArtifact]:
    """Return the validated project-owned SSA artifact registry."""
    surface = cast(_ProjectSSARegistrySurface8616, project)
    try:
        registry = surface._inertia_function_ssa_artifacts_8616
    except AttributeError:
        registry = {}
        surface._inertia_function_ssa_artifacts_8616 = registry
    if not isinstance(registry, dict):
        raise TypeError("function SSA artifact registry must be a dict")
    return registry


def _stage_registry_8616(
    project: object,
) -> dict[int, FunctionSSAArtifactStage8616]:
    """Return the project-owned readiness stage for every cached SSA artifact."""
    surface = cast(_ProjectSSARegistrySurface8616, project)
    try:
        registry = surface._inertia_function_ssa_stages_8616
    except AttributeError:
        registry = {}
        surface._inertia_function_ssa_stages_8616 = registry
    if not isinstance(registry, dict):
        raise TypeError("function SSA stage registry must be a dict")
    return registry


def function_boundary_at_address_8616(
    project: object,
    function_addr: int,
) -> object | None:
    """Return an exact CFG function or an independently framed range boundary."""
    surface = cast(_ProjectSSARegistrySurface8616, project)
    try:
        function = surface.kb.functions.function(addr=function_addr, create=False)
    except (AttributeError, KeyError, TypeError):
        function = None
    if function is not None:
        return function
    try:
        ranges = surface._inertia_caller_function_ranges_8616
    except AttributeError:
        ranges = ()
    matching = tuple(
        (start, end)
        for start, end in ranges
        if isinstance(start, int)
        and isinstance(end, int)
        and start == function_addr
        and end > start
    )
    if len(matching) != 1:
        return None
    start, end = matching[0]
    return SimpleNamespace(
        addr=start,
        size=end - start,
        block_addrs_set={start},
        info={},
    )


def registered_function_ssa_artifact_8616(
    project: object,
    function_addr: int,
) -> FunctionSSAArtifactResolution8616:
    """Return one registered artifact and its readiness without rebuilding it."""
    cached = _registry_8616(project).get(function_addr)
    if cached is None:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.ARTIFACT_NOT_REGISTERED,
            None,
        )
    if not isinstance(cached, SSAFunctionArtifact) or cached.function_addr != function_addr:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            None,
        )
    stages = _stage_registry_8616(project)
    stage = stages.get(function_addr, FunctionSSAArtifactStage8616.IR)
    if not isinstance(stage, FunctionSSAArtifactStage8616):
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            None,
        )
    stages[function_addr] = stage
    return FunctionSSAArtifactResolution8616(
        function_addr,
        FunctionSSAArtifactVerdict8616.PROVEN,
        cached,
        None,
        stage,
    )


def publish_function_ssa_artifact_8616(
    project: object,
    artifact: SSAFunctionArtifact,
    stage: FunctionSSAArtifactStage8616,
) -> FunctionSSAArtifactResolution8616:
    """Publish one exact artifact, allowing only the IR-to-Semantics upgrade."""
    function_addr = artifact.function_addr
    registered = registered_function_ssa_artifact_8616(project, function_addr)
    if registered.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT:
        return registered
    artifacts = _registry_8616(project)
    stages = _stage_registry_8616(project)
    if registered.artifact is None:
        artifacts[function_addr] = artifact
        stages[function_addr] = stage
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.PROVEN,
            artifact,
            None,
            stage,
        )
    current_stage = registered.stage
    if current_stage is FunctionSSAArtifactStage8616.SEMANTIC:
        if stage is FunctionSSAArtifactStage8616.IR or registered.artifact == artifact:
            return registered
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            current_stage,
        )
    if stage is FunctionSSAArtifactStage8616.IR:
        if registered.artifact == artifact:
            return registered
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            current_stage,
        )
    artifacts[function_addr] = artifact
    stages[function_addr] = stage
    return FunctionSSAArtifactResolution8616(
        function_addr,
        FunctionSSAArtifactVerdict8616.PROVEN,
        artifact,
        None,
        stage,
    )


def function_ssa_artifact_at_address_8616(
    project: object,
    function_addr: int,
) -> FunctionSSAArtifactResolution8616:
    """Build or return one exact caller SSA artifact without guessing gaps."""
    registered = registered_function_ssa_artifact_8616(project, function_addr)
    if registered.verdict is FunctionSSAArtifactVerdict8616.PROVEN:
        return registered
    if registered.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT:
        return registered
    function = function_boundary_at_address_8616(project, function_addr)
    if function is None:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.FUNCTION_NOT_FOUND,
            None,
        )
    try:
        ir_artifact = build_x86_16_ir_function_artifact(project, function)
        function_ssa = build_x86_16_function_ssa(ir_artifact)
    except (AttributeError, KeyError, TypeError, ValueError):
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.IR_BUILD_FAILED,
            None,
        )
    if ir_artifact.refusals:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.IR_BUILD_REFUSED,
            None,
        )
    return publish_function_ssa_artifact_8616(
        project,
        function_ssa,
        FunctionSSAArtifactStage8616.IR,
    )
