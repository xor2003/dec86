from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir import IRFunctionArtifact
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    publish_function_ssa_artifact_8616,
    registered_function_ssa_artifact_8616,
)
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.semantics import call_stack_effect_pipeline
from angr_platforms.X86_16.semantics.call_output_contracts import CallOutputStats8616
from angr_platforms.X86_16.semantics.call_outputs import CallOutputArtifact8616
from angr_platforms.X86_16.semantics.call_stack_effect_contracts import (
    CallStackEffectStats8616,
)
from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
    apply_x86_16_call_stack_effects_8616,
    semantic_function_ssa_artifact_at_address_8616,
)
from angr_platforms.X86_16.semantics.call_stack_effects import (
    CallStackEffectArtifact8616,
)


def _ssa(function_addr: int, marker: str) -> SSAFunctionArtifact:
    return SSAFunctionArtifact(function_addr, (), summary={"marker": marker})


class _Functions:
    def __init__(self, *addresses: int) -> None:
        self._functions = {
            address: SimpleNamespace(addr=address, info=None) for address in addresses
        }

    def function(self, *, addr: int, create: bool = False) -> object | None:
        assert create is False
        return self._functions.get(addr)


def _project(*addresses: int) -> SimpleNamespace:
    return SimpleNamespace(kb=SimpleNamespace(functions=_Functions(*addresses)))


def test_registry_upgrades_ir_to_semantics_without_downgrade() -> None:
    project = _project()
    raw = _ssa(0x1000, "raw")
    semantic = _ssa(0x1000, "semantic")

    raw_result = publish_function_ssa_artifact_8616(
        project,
        raw,
        FunctionSSAArtifactStage8616.IR,
    )
    semantic_result = publish_function_ssa_artifact_8616(
        project,
        semantic,
        FunctionSSAArtifactStage8616.SEMANTIC,
    )
    downgrade_result = publish_function_ssa_artifact_8616(
        project,
        raw,
        FunctionSSAArtifactStage8616.IR,
    )

    assert raw_result.artifact is raw
    assert semantic_result.artifact is semantic
    assert semantic_result.stage is FunctionSSAArtifactStage8616.SEMANTIC
    assert downgrade_result.artifact is semantic
    assert registered_function_ssa_artifact_8616(project, 0x1000).artifact is semantic


def test_registry_refuses_divergent_semantics_without_replacement() -> None:
    project = _project()
    accepted = _ssa(0x1000, "accepted")
    conflicting = _ssa(0x1000, "conflicting")
    publish_function_ssa_artifact_8616(
        project,
        accepted,
        FunctionSSAArtifactStage8616.SEMANTIC,
    )

    result = publish_function_ssa_artifact_8616(
        project,
        conflicting,
        FunctionSSAArtifactStage8616.SEMANTIC,
    )

    assert result.verdict is FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT
    assert registered_function_ssa_artifact_8616(project, 0x1000).artifact is accepted


def test_semantic_lookup_caches_distinct_exact_functions(monkeypatch) -> None:
    project = _project(0x1000, 0x2000)
    publish_function_ssa_artifact_8616(
        project,
        _ssa(0x1000, "raw"),
        FunctionSSAArtifactStage8616.IR,
    )
    built: list[int] = []

    def _build(
        _project: object,
        function: object,
        *,
        ir_artifact: IRFunctionArtifact | None = None,
    ) -> tuple[object, object, SSAFunctionArtifact]:
        assert ir_artifact is None
        function_addr = function.addr
        built.append(function_addr)
        ir = IRFunctionArtifact(function_addr, ())
        return object(), SimpleNamespace(function=ir), _ssa(function_addr, "semantic")

    monkeypatch.setattr(
        call_stack_effect_pipeline,
        "build_semantic_function_ssa_8616",
        _build,
    )

    first = semantic_function_ssa_artifact_at_address_8616(project, 0x1000)
    replay = semantic_function_ssa_artifact_at_address_8616(project, 0x1000)
    second = semantic_function_ssa_artifact_at_address_8616(project, 0x2000)

    assert built == [0x1000, 0x2000]
    assert first.artifact is replay.artifact
    assert first.stage is second.stage is FunctionSSAArtifactStage8616.SEMANTIC
    assert first.artifact is not second.artifact
    assert semantic_function_ssa_artifact_at_address_8616(
        project,
        0x3000,
    ).failure is FunctionSSAArtifactFailure8616.FUNCTION_NOT_FOUND


def test_main_semantics_path_publishes_its_exact_ssa(monkeypatch) -> None:
    function_addr = 0x1000
    project = _project(function_addr)
    raw_ir = IRFunctionArtifact(function_addr, ())
    semantic_ir = IRFunctionArtifact(function_addr, (), summary={"stage": "semantic"})
    semantic_ssa = _ssa(function_addr, "semantic")
    effects = CallStackEffectArtifact8616(raw_ir, (), CallStackEffectStats8616())
    outputs = CallOutputArtifact8616(semantic_ir, (), CallOutputStats8616())
    build_count = 0

    def _build(
        _project: object,
        function: object,
        *,
        ir_artifact: IRFunctionArtifact | None = None,
    ) -> tuple[object, object, SSAFunctionArtifact]:
        nonlocal build_count
        build_count += 1
        assert function.addr == function_addr
        assert ir_artifact is raw_ir
        return effects, outputs, semantic_ssa

    monkeypatch.setattr(
        call_stack_effect_pipeline,
        "build_semantic_function_ssa_8616",
        _build,
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=function_addr),
        _inertia_vex_ir_artifact=raw_ir,
        _inertia_raw_vex_ir_artifact_8616=raw_ir,
    )

    assert apply_x86_16_call_stack_effects_8616(project, codegen) is False
    assert apply_x86_16_call_stack_effects_8616(project, codegen) is False

    registered = registered_function_ssa_artifact_8616(project, function_addr)
    assert registered.artifact is semantic_ssa
    assert registered.stage is FunctionSSAArtifactStage8616.SEMANTIC
    assert codegen._inertia_vex_ir_function_ssa is semantic_ssa
    assert codegen._inertia_vex_ir_artifact is semantic_ir
    assert (
        codegen._inertia_vex_ir_function_ssa_stage_8616
        is FunctionSSAArtifactStage8616.SEMANTIC
    )
    assert build_count == 1
