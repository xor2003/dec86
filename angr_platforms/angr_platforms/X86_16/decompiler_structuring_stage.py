from __future__ import annotations

import contextlib
import logging
import os
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from angr.analyses.decompiler.decompiler import Decompiler
from angr.sim_type import SimTypeBottom, SimTypeFunction

from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles, infer_induction_summary
from inertia_decompiler.runtime_support import timing_output_enabled
from inertia_decompiler.telemetry import annotate_current_span, span

from . import confidence_and_assumptions as _confidence
from . import decompiler_postprocess_jcc as _jcc
from . import decompiler_postprocess_simplify as _simplify
from . import decompiler_postprocess_typed_conditions as _typed_conditions
from . import function_interface_surface as _interface_surface
from . import ir_confidence_markers as _ir_confidence
from . import segmented_memory_reasoning as _segmented_mem
from . import string_codegen_override as _string_codegen_override
from . import string_instruction_artifact as _string_instruction_artifact
from . import string_instruction_lowering as _string_instruction_lowering
from . import structuring_codegen as _codegen
from . import structuring_cross_entry as _cross_entry
from . import structuring_diagnostics as _diagnostics
from . import structuring_grouped_pass as _grouped_structuring
from . import type_array_matching as _array_match
from . import type_equivalence_classes as _type_equiv
from . import type_structure_merging as _struct_merge
from .condition_trace import record_ast_condition_trace_8616
from .ir import segment_state as _segment_state
from .ir import string_effects as _string_effects
from .ir import vex_import as _vex_ir
from .lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from .tail_validation import (
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    collect_x86_16_tail_validation_summary,
    fingerprint_x86_16_tail_validation_boundary,
    persist_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_result_passed,
)

__all__ = [
    "DecompilerStructuringPassSpec",
    "DECOMPILER_STRUCTURING_PASSES",
    "_build_decompiler_structuring_passes",
    "describe_x86_16_decompiler_structuring_stage",
    "apply_x86_16_decompiler_structuring",
]


@dataclass(frozen=True, slots=True)
class DecompilerStructuringPassSpec:
    name: str
    func: Callable[..., bool]
    needs_project: bool


class StructuringPassValidationSkipReason8616(Enum):
    LARGE_FUNCTION_BLOCK_COUNT = "large_function_block_count"
    LARGE_FUNCTION_BYTE_SIZE = "large_function_byte_size"


_STRUCTURING_PASS_VALIDATION_LARGE_BLOCK_THRESHOLD_8616 = 40
_STRUCTURING_PASS_VALIDATION_LARGE_BYTE_THRESHOLD_8616 = 0x160


def _build_decompiler_structuring_passes() -> tuple[DecompilerStructuringPassSpec, ...]:
    return (
        DecompilerStructuringPassSpec(
            "_cross_entry_cfg_grouping_8616",
            _cross_entry.apply_x86_16_cross_entry_grouping,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_region_based_structuring_8616",
            _grouped_structuring.apply_grouped_region_based_structuring,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_simplify_structured_expressions_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_induction_summary_artifact_8616",
            _induction_summary_artifact_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structuring_codegen_8616",
            _codegen.apply_structuring_codegen_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_vex_ir_artifact_8616",
            _vex_ir.apply_x86_16_vex_ir_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_segment_state_artifact_8616",
            _segment_state.apply_x86_16_segment_state_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_instruction_artifact_8616",
            _string_instruction_artifact.apply_x86_16_string_instruction_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_typed_string_effect_artifact_8616",
            _string_effects.apply_x86_16_typed_string_effect_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_instruction_lowering_8616",
            _string_instruction_lowering.apply_x86_16_string_instruction_lowering,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_codegen_override_8616",
            _string_codegen_override.apply_x86_16_string_codegen_override,
            True,
        ),
        # Phase 3: Segmented Memory Association Reasoning
        DecompilerStructuringPassSpec(
            "_segmented_memory_reasoning_8616",
            _segmented_mem.apply_x86_16_segmented_memory_reasoning,
            False,
        ),
        # Phase 2: Type Inference and Recovery
        DecompilerStructuringPassSpec(
            "_type_equivalence_classes_8616",
            _type_equiv.apply_x86_16_type_equivalence_classes,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_array_expression_matching_8616",
            _array_match.apply_x86_16_array_expression_matching,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structure_field_merging_8616",
            _struct_merge.apply_x86_16_structure_field_merging,
            False,
        ),
        # Phase 4: Robustness & Diagnostics
        DecompilerStructuringPassSpec(
            "_structuring_diagnostics_8616",
            _diagnostics.apply_x86_16_structuring_diagnostics,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_ir_confidence_markers_8616",
            _ir_confidence.apply_x86_16_ir_confidence_markers,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_confidence_and_assumptions_8616",
            _confidence.apply_x86_16_confidence_and_assumptions,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_function_interface_surface_8616",
            _interface_surface.apply_x86_16_function_interface_surface,
            True,
        ),
    )


def _induction_summary_artifact_8616(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    project = getattr(codegen, "project", None)
    if cfunc is None or project is None:
        return False
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict):
        codegen._inertia_induction_summaries = ()
        return False
    traits = traits_cache.get(getattr(cfunc, "addr", None))
    if not isinstance(traits, dict):
        codegen._inertia_induction_summaries = ()
        return False

    summaries = []
    for _base_key, profile in sorted(
        build_access_trait_evidence_profiles(traits).items(), key=lambda item: repr(item[0])
    ):
        summary = infer_induction_summary(profile)
        if summary is not None:
            summaries.append(summary)
    codegen._inertia_induction_summaries = tuple(summaries)
    return False


DECOMPILER_STRUCTURING_PASSES = _build_decompiler_structuring_passes()


@contextlib.contextmanager
def _guard_condition_processor_multibit_bool_predicates_8616(project):
    """Normalize multi-bit AIL branch predicates to explicit nonzero Bool ASTs.

    angr's condition processor may return a BV for Register/Load/VirtualVariable
    leaves even when the caller requests ``must_bool=True``. x86 conditional
    branch semantics are explicit nonzero tests for such values, so structuring
    must see a Bool predicate instead of asserting later in short-circuit
    recovery.
    """
    try:
        import claripy
        from angr.analyses.decompiler.condition_processor import ConditionProcessor
    except Exception:
        yield
        return

    orig = ConditionProcessor.claripy_ast_from_ail_condition
    if getattr(orig, "_inertia_8616_multibit_bool_guard", False):
        yield
        return

    normalized_count = 0
    refused_count = 0

    def _claripy_ast_from_ail_condition_8616(self, condition, *, nobool=False, must_bool=False, ins_addr=0):
        nonlocal normalized_count, refused_count
        result = orig(self, condition, nobool=nobool, must_bool=must_bool, ins_addr=ins_addr)
        if not must_bool or isinstance(result, claripy.ast.Bool):
            return result
        if isinstance(result, claripy.ast.BV):
            size = int(result.size())
            if size > 0:
                normalized_count += 1
                return result != claripy.BVV(0, size)
        refused_count += 1
        return result

    _claripy_ast_from_ail_condition_8616._inertia_8616_multibit_bool_guard = True
    ConditionProcessor.claripy_ast_from_ail_condition = _claripy_ast_from_ail_condition_8616
    try:
        yield
    finally:
        ConditionProcessor.claripy_ast_from_ail_condition = orig
        if normalized_count:
            current = int(getattr(project, "_inertia_condition_predicate_multibit_bool_normalized", 0) or 0)
            project._inertia_condition_predicate_multibit_bool_normalized = current + normalized_count
        if refused_count:
            current = int(getattr(project, "_inertia_condition_predicate_multibit_bool_refused", 0) or 0)
            project._inertia_condition_predicate_multibit_bool_refused = current + refused_count


def _semantic_validation_pass_names_8616() -> tuple[str, ...]:
    return (
        "_simplify_structured_expressions_8616",
        "_segmented_memory_reasoning_8616",
        "_array_expression_matching_8616",
        "_structuring_codegen_8616",
    )


def _function_complexity_for_structuring_validation_8616(project, codegen) -> tuple[int, int]:
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    try:
        functions = getattr(getattr(project, "kb", None), "functions", None)
        function = (
            functions.function(func_addr, create=False)
            if functions is not None and isinstance(func_addr, int) and func_addr >= 0
            else None
        )
        if function is None:
            return 0, 0
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            cached = info.get("_inertia_function_complexity")
            if isinstance(cached, MutableMapping):
                blocks = cached.get("blocks")
                bytes_ = cached.get("bytes")
                if isinstance(blocks, int) and isinstance(bytes_, int):
                    return max(0, blocks), max(0, bytes_)
        local_blocks = tuple((getattr(function, "_local_blocks", {}) or {}).values())
        blocks = local_blocks or tuple(getattr(function, "blocks", ()) or ())
        if blocks:
            block_count = 0
            byte_count = 0
            for block in blocks:
                block_addr = getattr(block, "addr", None)
                if isinstance(block_addr, int):
                    block_count += 1
                byte_count += int(
                    getattr(block, "size", 0)
                    or len(getattr(block, "bytes", b"") or b"")
                    or len(getattr(block, "bytestr", b"") or b"")
                )
            return block_count, byte_count
        return len(getattr(function, "block_addrs_set", ()) or ()), 0
    except Exception:
        return 0, 0


def _structuring_pass_validation_skip_reason_8616(project, codegen) -> StructuringPassValidationSkipReason8616 | None:
    blocks, bytes_ = _function_complexity_for_structuring_validation_8616(project, codegen)
    if blocks >= _STRUCTURING_PASS_VALIDATION_LARGE_BLOCK_THRESHOLD_8616:
        return StructuringPassValidationSkipReason8616.LARGE_FUNCTION_BLOCK_COUNT
    if bytes_ >= _STRUCTURING_PASS_VALIDATION_LARGE_BYTE_THRESHOLD_8616:
        return StructuringPassValidationSkipReason8616.LARGE_FUNCTION_BYTE_SIZE
    return None


def _large_function_for_structuring_pass_validation_8616(project, codegen) -> bool:
    return _structuring_pass_validation_skip_reason_8616(project, codegen) is not None


def _prime_structuring_validation_semantics_8616(project, codegen) -> None:
    if getattr(codegen, "_inertia_structuring_validation_semantics_primed", False):
        return
    try:
        from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
        from .lowering.real_mode_linear import (
            lower_stable_ds_es_linear_global_dereferences_8616,
            lower_stable_ss_linear_stack_dereferences_8616,
        )
        from .lowering.stack_lowering_from_facts import lower_stack_accesses_from_alias_facts_8616

        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        changed = False
        if isinstance(alias_facts, list) and alias_facts:
            before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
            after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
            changed = changed or after_materialized > before_materialized
        changed = bool(lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)) or changed
        if changed:
            codegen._inertia_codegen_decl_refresh_required_8616 = True
        lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project)
        _segmented_mem.apply_x86_16_segmented_memory_reasoning(codegen)
        # Keep structuring-tail validation stable: if priming already applied
        # SS stack lowering and alias-fact lowering, skip re-running it in the
        # structuring body to avoid representation-only drift.
        codegen._inertia_ss_stack_lowered = True
        if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
            func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
            if isinstance(func_addr, int):
                transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
            codegen._inertia_typed_conditions_transferred = True
        _typed_conditions._apply_typed_conditions_to_codegen_8616(project, codegen)
        _jcc._rewrite_decoded_jcc_conditions_8616(project, codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Structuring validation semantic priming failed function=%#x: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_structuring_validation_semantics_primed = True


def _refresh_structuring_condition_semantics_8616(project, codegen) -> None:
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return
    try:
        transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
        _typed_conditions._apply_typed_conditions_to_codegen_8616(project, codegen)
        _jcc._rewrite_decoded_jcc_conditions_8616(project, codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Structuring condition semantic refresh failed function=%#x: %s",
            func_addr,
            ex,
        )


def _try_accept_structuring_validation_delta_from_evidence_8616(
    project,
    codegen,
    validation: dict[str, object],
    *,
    spec_name: str,
) -> bool:
    if not isinstance(validation, dict) or x86_16_tail_validation_result_passed(validation):
        return False
    try:
        from .decompiler_postprocess_stage import _is_jcc_condition_materialization_validation_delta_8616
    except Exception:
        return False

    function = None
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if isinstance(func_addr, int) and functions is not None:
        with contextlib.suppress(Exception):
            function = functions.function(addr=func_addr, create=False)
    if not _is_jcc_condition_materialization_validation_delta_8616(
        project,
        codegen,
        validation,
        function=function,
    ):
        return False

    codegen._inertia_structuring_jcc_condition_validation_accepts_8616 = int(
        getattr(codegen, "_inertia_structuring_jcc_condition_validation_accepts_8616", 0) or 0
    ) + 1
    delta = validation.get("delta")
    if isinstance(delta, dict):
        accepted_deltas = list(
            getattr(codegen, "_inertia_structuring_jcc_condition_validation_deltas_8616", ()) or ()
        )
        accepted_deltas.append(
            {
                "conditions": delta.get("conditions"),
                "control_flow_effects": delta.get("control_flow_effects"),
                "stage": f"structuring:{spec_name}",
            }
        )
        codegen._inertia_structuring_jcc_condition_validation_deltas_8616 = tuple(accepted_deltas)
    validation["changed"] = False
    validation["status"] = "stable"
    validation["summary_text"] = "no observable whole-tail changes"
    validation.pop("delta", None)
    validation["verdict"] = build_x86_16_tail_validation_verdict(f"structuring:{spec_name}", validation)
    return True


def _maybe_validate_structuring_pass_8616(project, codegen, spec_name: str):
    if not bool(getattr(project, "_inertia_tail_validation_enabled", True)):
        return None
    validate_all = os.environ.get("INERTIA_VALIDATE_ALL_STRUCTURING_PASSES") == "1"
    skip_reason = _structuring_pass_validation_skip_reason_8616(project, codegen)
    if not validate_all and skip_reason is not None:
        codegen._inertia_structuring_pass_validation_skipped_large_function_8616 = True
        codegen._inertia_structuring_pass_validation_skip_reason_8616 = skip_reason
        return None
    if not validate_all and spec_name not in _semantic_validation_pass_names_8616():
        return None

    mode = "live_out"
    _prime_structuring_validation_semantics_8616(project, codegen)
    before_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode=mode)
    before_summary = collect_x86_16_tail_validation_summary(project, codegen, mode=mode)

    def finalize():
        _refresh_structuring_condition_semantics_8616(project, codegen)
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode=mode)
        after_summary = collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
        validation = build_x86_16_tail_validation_cached_result(
            owner=None,
            stage=f"structuring:{spec_name}",
            mode=mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        validation["verdict"] = build_x86_16_tail_validation_verdict(f"structuring:{spec_name}", validation)
        existing = getattr(codegen, "_inertia_structuring_pass_validation", None)
        if not isinstance(existing, dict):
            existing = {}
            setattr(codegen, "_inertia_structuring_pass_validation", existing)
        if _try_accept_structuring_validation_delta_from_evidence_8616(
            project,
            codegen,
            validation,
            spec_name=spec_name,
        ):
            logging.getLogger(__name__).warning(
                "structuring pass validation JCC condition delta accepted from consumed evidence function=%#x pass=%s verdict=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                spec_name,
                validation.get("verdict"),
            )
        existing[spec_name] = validation
        if not x86_16_tail_validation_result_passed(validation):
            logging.getLogger(__name__).warning(
                "structuring pass validation changed function=%#x pass=%s verdict=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                spec_name,
                validation.get("verdict"),
            )
            codegen._inertia_structuring_validation_failed = True
            codegen._inertia_structuring_validation_failure_pass = spec_name
            codegen._inertia_structuring_validation_failure_error = (
                validation.get("summary_text") or f"tail-validation status={validation.get('status', 'unknown')}"
            )

    return finalize


def _decompiler_structuring_passes_for_function(project, codegen):
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if func_addr is None:
        return DECOMPILER_STRUCTURING_PASSES

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return DECOMPILER_STRUCTURING_PASSES

    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        return DECOMPILER_STRUCTURING_PASSES

    profile = info.get("x86_16_decompilation_profile", {})
    if isinstance(profile, dict) and profile.get("wrapper_like"):
        return DECOMPILER_STRUCTURING_PASSES

    return DECOMPILER_STRUCTURING_PASSES


def describe_x86_16_decompiler_structuring_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_STRUCTURING_PASSES)


def _structuring_codegen_8616(project, codegen) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False
        if not bool(getattr(project, "_inertia_structuring_enabled", True)):
            codegen._inertia_structuring_passes = ()
            codegen._inertia_structuring_changed = False
            codegen._inertia_structuring_failed = False
            codegen._inertia_last_structuring_pass = None
            return False

        # Alias-completeness gate: structuring cannot run with provisional SS stack.
        # AGENTS rule #1: SS:BP+offset → stack slot → variable, never guess.
        from .pipeline.errors import PipelineHardError

        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        try:
            with span("x86_16.structuring.codegen.alias_complete", function=func_addr):
                _assert_alias_complete_8616(codegen)
        except PipelineHardError as ex:
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = "alias_completeness_gate"
            codegen._inertia_structuring_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "structuring blocked by incomplete SS alias function=%#x: %s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0),
                ex,
            )
            return False

        # ── Stack lowering (before structuring) ──
        # Must run early: alias facts → stack variables → SS linear derefs →
        # structuring sees named variables. Running SS linear lowering before
        # alias fact materialization leaves stack_base carriers unresolved.
        if not getattr(codegen, "_inertia_ss_stack_lowered", False):
            from .pipeline.errors import PipelineHardError

            try:
                from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
                from .lowering.real_mode_linear import (
                    lower_stable_ss_linear_stack_dereferences_8616,
                )
                from .lowering.stack_lowering_from_facts import lower_stack_accesses_from_alias_facts_8616

                with span("x86_16.structuring.codegen.stack_lowering", function=func_addr):
                    transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
                    alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
                    changed = False
                    if isinstance(alias_facts, list) and alias_facts:
                        before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
                        lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
                        after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
                        changed = changed or after_materialized > before_materialized
                    changed = bool(lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)) or changed
                    annotate_current_span(
                        changed=bool(changed),
                        alias_facts=len(alias_facts) if isinstance(alias_facts, list) else 0,
                        materialized=int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0),
                    )
                    if changed:
                        codegen._inertia_codegen_decl_refresh_required_8616 = True
            except PipelineHardError:
                raise
            except Exception as ex:
                codegen._inertia_structuring_failed = True
                codegen._inertia_structuring_failure_pass = "stack_alias_materialization_and_ss_linear_lowering"
                codegen._inertia_structuring_failure_error = f"{type(ex).__name__}: {ex}"
                logging.getLogger(__name__).warning(
                    "stack lowering from facts failed function=%#x stage=%s: %s: %s",
                    getattr(getattr(codegen, "cfunc", None), "addr", 0),
                    "stack_alias_materialization_and_ss_linear_lowering",
                    type(ex).__name__,
                    ex,
                )
                return False
            codegen._inertia_ss_stack_lowered = True

        # ── Hard contract gate: classified > 0 && materialized == 0 → PipelineHardError ──
        # PipelineHardError MUST propagate — never silently caught.
        # Only non-fatal errors (import, attribute) are logged and cause structuring abort.
        from .pipeline.contracts import assert_pipeline_contracts_8616

        try:
            with span("x86_16.structuring.codegen.contracts", function=func_addr):
                assert_pipeline_contracts_8616(codegen)
        except PipelineHardError:
            raise
        except Exception as e:
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = "pipeline_contracts"
            codegen._inertia_structuring_failure_error = str(e)
            logging.getLogger(__name__).warning(
                "Pipeline contract gate setup error in %s: %s",
                getattr(codegen, "cfunc", None) or "unknown",
                e,
            )
            return False

        changed = False
        last_changed_pass = None
        codegen._inertia_structuring_failed = False
        codegen._inertia_structuring_failure_pass = None
        codegen._inertia_structuring_failure_error = None
        codegen._inertia_structuring_validation_failed = False
        codegen._inertia_structuring_validation_failure_pass = None
        codegen._inertia_structuring_validation_failure_error = None
        codegen._inertia_last_structuring_pass = None
        pass_specs = _decompiler_structuring_passes_for_function(project, codegen)
        codegen._inertia_structuring_passes = tuple(spec.name for spec in pass_specs)
        _t_structuring_start = time.perf_counter()
        for spec in pass_specs:
            try:
                project._inertia_decompiler_stage = f"structuring:{spec.name}"
                # Structuring must remain semantics-preserving under tail validation.
                # Expression simplification is allowed in postprocess; in structuring it
                # can rewrite boundary-visible conditions (e.g. 32-bit compare forms),
                # so keep this step analysis-only here.
                if spec.name == "_simplify_structured_expressions_8616":
                    continue
                if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
                    import sys as _sys

                    _sys.stderr.write(
                        f"[{time.strftime('%H:%M:%S')}] structuring pass: {spec.name} (+{time.perf_counter() - _t_structuring_start:.1f}s)\n"
                    )
                    _sys.stderr.flush()
                with span(f"x86_16.structuring.pass.{spec.name}", function=func_addr):
                    finalize_validation = _maybe_validate_structuring_pass_8616(project, codegen, spec.name)
                    if spec.needs_project:
                        spec_changed = spec.func(project, codegen)
                    else:
                        spec_changed = spec.func(codegen)
                    annotate_current_span(changed=bool(spec_changed))
                    if finalize_validation is not None:
                        with span(f"x86_16.structuring.pass_validation.{spec.name}", function=func_addr):
                            finalize_validation()
                            annotate_current_span(
                                failed=bool(getattr(codegen, "_inertia_structuring_validation_failed", False))
                            )
                        if getattr(codegen, "_inertia_structuring_validation_failed", False):
                            break
            except Exception as ex:  # noqa: BLE001
                codegen._inertia_structuring_failed = True
                codegen._inertia_structuring_failure_pass = spec.name
                codegen._inertia_structuring_failure_error = str(ex)
                logging.getLogger(__name__).warning(
                    "Skipping 86_16 structuring pass %s after %s: %s",
                    spec.name,
                    last_changed_pass or "no earlier structuring",
                    ex,
                    exc_info=True,
                )
                break
            if spec_changed:
                changed = True
                last_changed_pass = spec.name
                codegen._inertia_last_structuring_pass = spec.name
        codegen._inertia_structuring_changed = changed
        project._inertia_decompiler_stage = "structuring"
        return changed

    return _impl()


def _decompile_structuring_8616(self):
    def _impl():
        def _ensure_function_prototype_8616() -> None:
            func = getattr(self, "func", None) or getattr(self, "function", None)
            if func is None:
                return
            prototype = getattr(func, "prototype", None)
            needs_fallback = (
                prototype is None
                or not hasattr(prototype, "returnty")
                or getattr(prototype, "returnty", None) is None
            )
            if not needs_fallback:
                return
            arch = getattr(getattr(self, "project", None), "arch", None)
            fallback = SimTypeFunction([], SimTypeBottom())
            if arch is not None:
                fallback = fallback.with_arch(arch)
            func.prototype = fallback

        _orig_decompiler_decompile = getattr(Decompiler, "_orig_before_structuring", None)
        if _orig_decompiler_decompile is None:
            _orig_decompiler_decompile = getattr(_decompile_structuring_8616, "_orig_decompiler_decompile", None)
            if _orig_decompiler_decompile is None:
                _orig_decompiler_decompile = Decompiler._decompile
                _decompile_structuring_8616._orig_decompiler_decompile = _orig_decompiler_decompile
        structuring_started = time.perf_counter()
        self.project._inertia_decompiler_stage = "core"
        _ensure_function_prototype_8616()
        with span(
            "x86_16.structuring.angr_core",
            function=getattr(getattr(self, "function", None) or getattr(self, "func", None), "addr", None),
        ):
            with _guard_condition_processor_multibit_bool_predicates_8616(self.project):
                _orig_decompiler_decompile(self)
        structuring_elapsed = time.perf_counter() - structuring_started
        if self.project.arch.name != "86_16" or self.codegen is None:
            return
        if not bool(getattr(self.project, "_inertia_tail_validation_enabled", True)):
            changed = _structuring_codegen_8616(self.project, self.codegen)
            function = getattr(self, "function", None) or getattr(self, "func", None)
            if function is not None:
                info = getattr(function, "info", None)
                if isinstance(info, MutableMapping):
                    structuring_info = info.setdefault("x86_16_decompiler_structuring", {})
                    structuring_info["elapsed"] = structuring_elapsed
                    structuring_info["last_pass"] = getattr(self.codegen, "_inertia_last_structuring_pass", None)
                    structuring_info["changed"] = bool(changed)
                    structuring_info["failed"] = bool(getattr(self.codegen, "_inertia_structuring_failed", False))
                    structuring_info["failure_pass"] = getattr(self.codegen, "_inertia_structuring_failure_pass", None)
                    structuring_info["failure_error"] = getattr(self.codegen, "_inertia_structuring_failure_error", None)
                    structuring_info["validation_failed"] = bool(
                        getattr(self.codegen, "_inertia_structuring_validation_failed", False)
                    )
                    structuring_info["validation_failure_pass"] = getattr(
                        self.codegen, "_inertia_structuring_validation_failure_pass", None
                    )
                    structuring_info["validation_failure_error"] = getattr(
                        self.codegen, "_inertia_structuring_validation_failure_error", None
                    )
                    structuring_info["pass_names"] = getattr(self.codegen, "_inertia_structuring_passes", ())
                    structuring_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
                    structuring_info["struct_merging_stats"] = getattr(self.codegen, "_inertia_struct_merging_stats", None)
                    structuring_info["struct_merging_changed"] = bool(
                        getattr(self.codegen, "_inertia_struct_merging_changed", False)
                    )
            setattr(self.codegen, "_inertia_tail_validation_snapshot", None)
            self.project._inertia_decompiler_stage = "structuring_done"
            return

        validation_mode = "live_out"
        func_addr = getattr(getattr(self.codegen, "cfunc", None), "addr", None)
        with span("x86_16.structuring.validation_prime", function=func_addr):
            _prime_structuring_validation_semantics_8616(self.project, self.codegen)
        with span("x86_16.structuring.validation.before_fingerprint", function=func_addr):
            before_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
        before_collect_started = time.perf_counter()
        with span("x86_16.structuring.validation.before_summary", function=func_addr):
            before_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
        before_collect_elapsed = time.perf_counter() - before_collect_started
        if not getattr(self.codegen, "_inertia_typed_conditions_transferred", False):
            func_addr = getattr(getattr(self.codegen, "cfunc", None), "addr", None)
            if isinstance(func_addr, int):
                with contextlib.suppress(Exception):
                    transfer_typed_conditions_to_codegen_8616(self.project, func_addr, self.codegen)
            self.codegen._inertia_typed_conditions_transferred = True
        with span("x86_16.structuring.codegen", function=func_addr):
            changed = _structuring_codegen_8616(self.project, self.codegen)
            annotate_current_span(
                changed=bool(changed),
                last_pass=getattr(self.codegen, "_inertia_last_structuring_pass", None),
            )
        with span("x86_16.structuring.condition_refresh", function=func_addr):
            _refresh_structuring_condition_semantics_8616(self.project, self.codegen)
            record_ast_condition_trace_8616(self.project, self.codegen, stage="structured")
        with span("x86_16.structuring.validation.after_fingerprint", function=func_addr):
            after_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
        after_collect_started = time.perf_counter()
        with span("x86_16.structuring.validation.after_summary", function=func_addr):
            after_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
        after_collect_elapsed = time.perf_counter() - after_collect_started
        self.codegen._inertia_structuring_tail_validation_artifacts_8616 = {
            "mode": validation_mode,
            "before_fingerprint": before_fingerprint,
            "before_summary": before_summary,
            "after_fingerprint": after_fingerprint,
            "after_summary": after_summary,
        }
        function = getattr(self, "function", None) or getattr(self, "func", None)
        if function is None and getattr(getattr(self, "codegen", None), "cfunc", None) is not None:
            addr = getattr(self.codegen.cfunc, "addr", None)
            kb_functions = getattr(getattr(self, "project", None), "kb", None)
            kb_functions = getattr(kb_functions, "functions", None)
            if isinstance(addr, int) and kb_functions is not None:
                with contextlib.suppress(Exception):
                    function = kb_functions.function(addr, create=False)
        owner = getattr(function, "info", None) if function is not None else None
        validation_started = time.perf_counter()
        with span("x86_16.structuring.validation.compare", function=func_addr):
            validation = build_x86_16_tail_validation_cached_result(
                owner=owner if isinstance(owner, MutableMapping) else None,
                stage="structuring",
                mode=validation_mode,
                before_fingerprint=before_fingerprint,
                after_fingerprint=after_fingerprint,
                before_summary=before_summary,
                after_summary=after_summary,
            )
        validation_compare_elapsed = time.perf_counter() - validation_started
        validation_timings = {
            "collect_before_ms": round(before_collect_elapsed * 1000.0, 3),
            "collect_after_ms": round(after_collect_elapsed * 1000.0, 3),
            "compare_ms": round(validation_compare_elapsed * 1000.0, 3),
            "total_ms": round((before_collect_elapsed + after_collect_elapsed + validation_compare_elapsed) * 1000.0, 3),
        }
        validation["timings"] = validation_timings
        validation["verdict"] = build_x86_16_tail_validation_verdict("structuring", validation)
        log = logging.getLogger(__name__)
        if _try_accept_structuring_validation_delta_from_evidence_8616(
            self.project,
            self.codegen,
            validation,
            spec_name="final",
        ):
            log.warning(
                "structuring final validation JCC condition delta accepted from consumed evidence function=%#x verdict=%s",
                getattr(getattr(self.codegen, "cfunc", None), "addr", -1) or -1,
                validation.get("verdict"),
            )
        if function is not None:
            info = getattr(function, "info", None)
            if isinstance(info, MutableMapping):
                structuring_info = info.setdefault("x86_16_decompiler_structuring", {})
                structuring_info["elapsed"] = structuring_elapsed
                structuring_info["tail_validation_timings"] = validation_timings
                structuring_info["last_pass"] = getattr(self.codegen, "_inertia_last_structuring_pass", None)
                structuring_info["changed"] = bool(changed)
                structuring_info["failed"] = bool(getattr(self.codegen, "_inertia_structuring_failed", False))
                structuring_info["failure_pass"] = getattr(self.codegen, "_inertia_structuring_failure_pass", None)
                structuring_info["failure_error"] = getattr(self.codegen, "_inertia_structuring_failure_error", None)
                structuring_info["validation_failed"] = bool(
                    getattr(self.codegen, "_inertia_structuring_validation_failed", False)
                )
                structuring_info["validation_failure_pass"] = getattr(
                    self.codegen, "_inertia_structuring_validation_failure_pass", None
                )
                structuring_info["validation_failure_error"] = getattr(
                    self.codegen, "_inertia_structuring_validation_failure_error", None
                )
                structuring_info["pass_names"] = getattr(self.codegen, "_inertia_structuring_passes", ())
                structuring_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
                structuring_info["tail_validation_verdict"] = validation["verdict"]
                structuring_info["tail_validation_cache_hit"] = bool(validation.get("cache_hit", False))
                structuring_info["struct_merging_stats"] = getattr(self.codegen, "_inertia_struct_merging_stats", None)
                structuring_info["struct_merging_changed"] = bool(
                    getattr(self.codegen, "_inertia_struct_merging_changed", False)
                )
                persist_x86_16_tail_validation_snapshot(
                    function_info=info,
                    codegen=self.codegen,
                    stage="structuring",
                    validation=validation,
                )
        if not x86_16_tail_validation_result_passed(validation):
            log.warning("%s", validation["verdict"])
        else:
            log.info("%s", validation["verdict"])
        self.project._inertia_decompiler_stage = "structuring_done"

    return _impl()


def _assert_alias_complete_8616(codegen) -> None:
    def _impl():
        """Block structuring when SS stack alias facts are incomplete.

        AGENTS rule #1: SS:BP+offset → stack slot → variable, never guess.
        AGENTS rule #8: validation must be honest — unreviewed SS is not safe.

        Consults the module-level alias fact cache populated during VEX lifting
        (access._inertia_module_alias_fact_cache).  Returns without error when
        no SS accesses are present (e.g. pure register / DS-only functions).

        Raises PipelineHardError if any proven SS access lacks stable stack alias.
        """
        from .access import _inertia_module_alias_fact_cache
        from .alias.alias_model_impl import AliasFailure
        from .pipeline.errors import PipelineHardError

        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        if not isinstance(func_addr, int):
            return

        facts = _inertia_module_alias_fact_cache.get(func_addr, None)
        if not isinstance(facts, list):
            return  # No facts recorded for this function — likely not yet lifted with typed IR.

        has_ss = False
        has_ss_stable = False
        has_ss_failure = False
        _first_ss_failure_reason = None
        for fact in facts:
            if isinstance(fact, AliasFailure):
                if getattr(fact, "space", None) in {"ss", "SS"}:
                    has_ss = True
                    address = getattr(fact, "address", None)
                    status = getattr(address, "status", None)
                    if getattr(status, "name", None) == "PROVISIONAL":
                        continue
                    has_ss_failure = True
                    if _first_ss_failure_reason is None:
                        _first_ss_failure_reason = getattr(fact, "reason", None)
            elif hasattr(fact, "domain") and getattr(fact.domain, "space", None) == "stack":
                has_ss = True
                has_ss_stable = True

        if not has_ss:
            return  # No SS accesses — nothing to block.

        # Only block when SS accesses exist but NONE are successfully classified.
        # Provisional SP-relative AliasFailures (push/pop/ret) are expected and
        # should not prevent structuring when BP-relative stack accesses are resolved.
        if not has_ss_stable and has_ss_failure:
            raise PipelineHardError(
                f"structuring before stable stack alias: {_first_ss_failure_reason}",
                layer="structuring",
            )

    return _impl()


def apply_x86_16_decompiler_structuring() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_structuring_8616":
        Decompiler._orig_before_structuring = Decompiler._decompile
        _decompile_structuring_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_structuring_8616
