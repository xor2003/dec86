from __future__ import annotations

from pathlib import Path

from angr_platforms.X86_16.alias.terminal_pointer_outputs import (
    classify_terminal_pointer_output_aliases_8616,
)
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lowering.callee_callsite_census import (
    collect_callee_callsite_census_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_memory_output_objects import (
    join_memory_output_object_contracts_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_memory_output_validation import (
    validate_memory_output_transaction_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_contracts import (
    CallsiteStorageTrials8616,
    FunctionStorageTrials8616,
    StorageTrialVerdict8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_function_solver import (
    join_function_storage_trials_8616,
    resolve_joined_function_storage_trials_8616,
)
from angr_platforms.X86_16.lowering.interprocedural_storage_live_out import (
    attach_callsite_memory_live_out_evidence_8616,
    collect_function_memory_live_out_trials_8616,
)
from angr_platforms.X86_16.lowering.pointer_parameter_caller_targets import (
    pointer_parameter_caller_target_evidence_8616,
    publish_pointer_parameter_caller_targets_8616,
)
from angr_platforms.X86_16.lowering.pointer_parameter_object_types import (
    recover_pointer_parameter_object_types_8616,
)
from angr_platforms.X86_16.lowering.pointer_parameter_outputs import (
    pointer_parameter_output_evidence_8616,
    publish_pointer_parameter_outputs_8616,
)
from angr_platforms.X86_16.semantics.terminal_pointer_outputs import (
    collect_terminal_pointer_output_evidence_8616,
)
from angr_platforms.X86_16.widening.global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)
from angr_platforms.X86_16.widening.terminal_pointer_output_views import (
    widen_terminal_pointer_output_views_8616,
)

from inertia_decompiler.cli_function_discovery import (
    _recover_fast_exe_catalog,
    attach_direct_target_argument_evidence_context_8616,
)
from inertia_decompiler.project_loading import _build_project
from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
SORTD_EXE = REPO_ROOT / "SORTD.EXE"
SWAPS_ADDR = 0x107B8


def test_sortd_swaps_materializes_pointer_outputs_through_storage_pipeline(
    tmp_path: Path,
) -> None:
    """Prove binary IR targets survive the real collector and transaction."""
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTD_EXE.read_bytes()))
    project = _build_project(
        isolated_binary,
        force_blob=False,
        base_addr=0x10000,
        entry_point=0x1000,
    )
    recovered = _recover_fast_exe_catalog(
        project,
        timeout=120,
        window=0x300,
        low_memory=False,
        limit=None,
    )
    function = next(
        candidate for _cfg, candidate in recovered if candidate.addr == SWAPS_ADDR
    )
    assert attach_direct_target_argument_evidence_context_8616(
        project, project, SWAPS_ADDR
    )
    artifact = build_x86_16_ir_function_artifact(project, function)
    ssa = build_x86_16_function_ssa(artifact)

    terminal = collect_terminal_pointer_output_evidence_8616(project, ssa)
    aliases = classify_terminal_pointer_output_aliases_8616(function, terminal)
    views = widen_terminal_pointer_output_views_8616(aliases)
    lowered = publish_pointer_parameter_outputs_8616(
        project, SWAPS_ADDR, function=function
    )

    assert terminal.complete
    assert {
        (fact.base_register, fact.base_version, fact.relative_offset, fact.width)
        for fact in terminal.facts
    } == {
        ("bx", 2, 0, 1),
        ("bx", 2, 1, 1),
        ("bx", 3, 0, 1),
        ("bx", 3, 1, 1),
    }
    assert aliases.complete
    assert {
        (fact.parameter_storage.offset, fact.terminal_output.base_version)
        for fact in aliases.facts
    } == {(4, 2), (6, 3)}
    assert views.complete
    assert {
        (fact.parameter_storage.offset, fact.relative_offset, fact.width)
        for fact in views.facts
    } == {(4, 0, 2), (6, 0, 2)}
    assert lowered.complete
    assert {
        (fact.logical_index, fact.argument_storage.offset, fact.output_view.width)
        for fact in lowered.facts
    } == {(0, 4, 2), (1, 6, 2)}
    assert pointer_parameter_output_evidence_8616(project, SWAPS_ADDR) is lowered

    census = collect_callee_callsite_census_8616(project, SWAPS_ADDR)
    assert census.complete
    assert len(census.facts) == 9
    caller_targets = publish_pointer_parameter_caller_targets_8616(
        project,
        SWAPS_ADDR,
        function=function,
    )
    assert caller_targets.complete
    assert len(caller_targets.facts) == 18
    assert pointer_parameter_caller_target_evidence_8616(
        project, SWAPS_ADDR
    ) is caller_targets
    assert {fact.segment for fact in caller_targets.facts} == {MemSpace.DS}
    assert {fact.width for fact in caller_targets.facts} == {2}
    assert {fact.target_base_offset for fact in caller_targets.facts} == {
        0x0B4C,
        0x0B4E,
    }
    assert sum(not fact.near_offset.terms for fact in caller_targets.facts) == 1
    assert sum(len(fact.near_offset.terms) == 2 for fact in caller_targets.facts) == 1
    assert {
        (fact.callsite_addr, fact.logical_index) for fact in caller_targets.facts
    } == {
        (caller.callsite_addr, logical_index)
        for caller in census.facts
        for logical_index in (0, 1)
    }

    expressions = tuple(
        fact.near_offset for fact in caller_targets.facts if fact.near_offset.terms
    )
    assert len(expressions) == 17
    assert {item.constant for item in expressions} == {0x0B4C, 0x0B4E}
    assert sum(len(item.terms) == 2 for item in expressions) == 1
    assert {
        (term.source.space, term.source.base, term.source.size, term.coefficient)
        for item in expressions
        for term in item.terms
    } == {(MemSpace.SS, ("bp",), 2, 2)}

    base_callsites = tuple(
        CallsiteStorageTrials8616(
            caller_addr=caller_fact.caller_addr,
            callee_addr=SWAPS_ADDR,
            callsite_addr=caller_fact.callsite_addr,
            stack_delta=0,
        )
        for caller_fact in census.facts
        if caller_fact.caller_addr is not None
    )
    live_outs = collect_function_memory_live_out_trials_8616(
        project,
        SWAPS_ADDR,
        base_callsites,
        tuple(candidate.addr for _cfg, candidate in recovered),
        pointer_targets=caller_targets,
    )
    assert live_outs.complete, live_outs.failures
    assert live_outs.stats.raw_fact_count == 18
    assert sum(len(item.pointer_effects) for item in live_outs.callsites) == 18
    callsites = tuple(
        attach_callsite_memory_live_out_evidence_8616(callsite, live_outs.callsites)
        for callsite in base_callsites
    )

    joined = join_memory_output_object_contracts_8616(callsites)
    assert joined.complete
    assert joined.objects == ()
    assert len(joined.pointer_objects) == 2
    assert {len(item.views) for item in joined.pointer_objects} == {9}

    function_join = join_function_storage_trials_8616(
        FunctionStorageTrials8616(
            function_addr=SWAPS_ADDR,
            caller_census_complete=True,
            expected_callsite_addrs=tuple(item.callsite_addr for item in callsites),
            callsites=callsites,
        )
    )
    resolution = resolve_joined_function_storage_trials_8616(function_join, None)
    assert resolution.verdict is StorageTrialVerdict8616.ACCEPTED
    assert resolution.contract is not None
    assert resolution.contract.memory_outputs == ()
    assert len(resolution.contract.pointer_memory_outputs) == 2
    assert validate_memory_output_transaction_8616(resolution.contract).complete

    layout = GlobalObjectLayout8616(
        address=IRAddress(
            space=MemSpace.DS,
            offset=0x0B4C,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        element_width=2,
        field_offsets=(0, 1),
        family_base_offset=0x08F0,
    )
    object_types = recover_pointer_parameter_object_types_8616(
        SWAPS_ADDR,
        resolution.contract.pointer_memory_outputs,
        GlobalObjectLayoutEvidence8616(
            layouts=(layout,),
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        ),
    )
    assert object_types.complete
    assert object_types.stats.raw_fact_count == 18
    assert {fact.logical_index for fact in object_types.facts} == {0, 1}
    assert {fact.family_base_offset for fact in object_types.facts} == {0x08F0}
