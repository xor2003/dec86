from __future__ import annotations

import contextlib
import copy
import itertools
import logging
import os
import re
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Callable

from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.structured_codegen.c import CStatements

from . import decompiler_postprocess as _post
from . import decompiler_postprocess_calls as _calls
from . import decompiler_postprocess_flags as _flags
from . import decompiler_postprocess_globals as _globals
from . import decompiler_postprocess_jcc as _jcc
from . import decompiler_postprocess_simplify as _simplify
from . import segmented_memory_reasoning as _segmented_mem
from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616
from .decompiler_postprocess_typed_conditions import _apply_typed_conditions_to_codegen_8616
from .condition_trace import (
    dump_condition_trace_8616,
    materialized_condition_drift_detected_8616,
    record_ast_condition_trace_8616,
    record_tail_validation_condition_trace_8616,
)
from .lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
from .lowering.stack_lowering import run_stack_lowering_pass_8616
from .lowering.stack_lowering_from_facts import (
    lower_stack_accesses_from_alias_facts_8616,
    build_stack_variable_bindings_from_alias_facts_8616,
)
from .lowering.ss_bp_substitution import (
    apply_stack_variable_bindings_to_c_text,
    substitute_ss_bp_dereferences_with_variables,
)
from .pipeline.contracts import assert_pipeline_contracts_8616
from .pipeline.errors import PipelineHardError
from .pipeline.invariants import format_invariant_report_8616, validate_before_rewrite_8616
from .postprocess.optimization.pass_driver import _run_optimization_passes_8616
from .tail_validation import (
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    fingerprint_x86_16_tail_validation_boundary,
    persist_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_result_passed,
)

__all__ = [
    "DecompilerPostprocessPassSpec",
    "DECOMPILER_POSTPROCESS_PASSES",
    "_build_decompiler_postprocess_passes",
    "describe_x86_16_decompiler_postprocess_stage",
    "apply_x86_16_decompiler_postprocess",
]


def _debug_dump_calls_8616(label: str, ctext: str, function_addr: int) -> None:
    if not os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
        return
    target_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else 0x10970
    if function_addr != target_addr:
        return
    log = logging.getLogger(__name__)
    tracked = ("Swaps(", "SwapBars(", "PercolateDown(", "PercolateUp(", "DrawBar(", "DrawTime(")
    for line in str(ctext or "").splitlines():
        if any(name in line for name in tracked):
            log.warning("[call-mutation] %s: %s", label, line.strip())


def _debug_heap_call_lines_8616(label: str, c_text: str, function_addr: int) -> None:
    if not os.environ.get("INERTIA_DEBUG_HEAPSORT_CALLS"):
        return
    if function_addr != 0x10970:
        return
    log = logging.getLogger(__name__)
    for line in str(c_text or "").splitlines():
        if any(x in line for x in ("PercolateUp(", "Swaps(", "SwapBars(", "PercolateDown(")):
            log.warning("[heapsort-call-boundary] %s: %s", label, line.strip())


def _debug_stack_noise_8616(label: str, c_text: str, function_addr: int) -> None:
    if not os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        return
    if function_addr != 0x10970:
        return
    log = logging.getLogger(__name__)
    for line in str(c_text or "").splitlines():
        if "&s_" in line or "s_" in line or "stack[" in line:
            log.warning("[stack-noise] %s: %s", label, line.strip())


def _rerun_stack_lowering_consumers_after_calls_8616(project, codegen) -> bool:
    from inertia_decompiler.cli_c_ast_rewrites import (
        _canonicalize_stack_cvars as _rewrite_canonicalize_stack_cvars,
        _rewrite_ss_stack_byte_offsets as _rewrite_stack_byte_offsets,
    )

    return run_stack_lowering_pass_8616(
        lower_stable_ss_stack_accesses=lambda: False,
        rewrite_ss_stack_byte_offsets=lambda: _rewrite_stack_byte_offsets(project, codegen),
        canonicalize_stack_cvars=lambda: _rewrite_canonicalize_stack_cvars(codegen),
        codegen=codegen,
        project=project,
        max_rounds=2,
    )


def _coalesce_linear_recurrence_after_stack_lowering_8616(project, codegen) -> bool:
    from inertia_decompiler.cli_c_ast_rewrites import (
        _coalesce_linear_recurrence_statements as _coalesce_linear_recurrence_statements,
    )

    return _coalesce_linear_recurrence_statements(project, codegen)


@dataclass(frozen=True, slots=True)
class DecompilerPostprocessPassSpec:
    name: str
    func: Callable[..., bool]
    needs_project: bool


def _build_decompiler_postprocess_passes():
    return (
        DecompilerPostprocessPassSpec("_apply_word_global_types_8616", _globals._apply_word_global_types_8616, True),
        DecompilerPostprocessPassSpec("_apply_annotations_8616", _post._apply_annotations_8616, True),
        DecompilerPostprocessPassSpec(
            "_promote_stack_prototype_from_bp_loads_8616",
            _post._promote_stack_prototype_from_bp_loads_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_return_address_stack_arguments_8616",
            _post._prune_return_address_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unused_unnamed_memory_declarations_8616",
            _globals._prune_unused_unnamed_memory_declarations_8616,
            False,
        ),
        DecompilerPostprocessPassSpec("_rewrite_decoded_jcc_conditions_8616", _jcc._rewrite_decoded_jcc_conditions_8616, True),
        DecompilerPostprocessPassSpec("_rewrite_flag_condition_pairs_8616", _flags._rewrite_flag_condition_pairs_8616, False),
        DecompilerPostprocessPassSpec("_rewrite_flag_bit_value_uses_8616", _flags._rewrite_flag_bit_value_uses_8616, False),
        DecompilerPostprocessPassSpec("_prune_unused_flag_assignments_8616", _flags._prune_unused_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_prune_overwritten_flag_assignments_8616", _flags._prune_overwritten_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_fix_interval_guard_conditions_8616", _flags._fix_interval_guard_conditions_8616, False),
        DecompilerPostprocessPassSpec(
            "_simplify_boolean_cites_8616",
            _simplify._simplify_boolean_cites_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_maybe_eliminate_single_use_temporaries_8616",
            _simplify._maybe_eliminate_single_use_temporaries_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_attach_callsite_summaries_8616",
            _calls._attach_callsite_summaries_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_lower_stable_ss_stack_accesses_8616",
            _segmented_mem._lower_stable_ss_stack_accesses_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_8616",
            _calls._materialize_callsite_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_prototypes_8616",
            _calls._materialize_callsite_prototypes_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rerun_stack_lowering_consumers_after_calls_8616",
            _rerun_stack_lowering_consumers_after_calls_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_coalesce_linear_recurrence_after_stack_lowering_8616",
            _coalesce_linear_recurrence_after_stack_lowering_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_function_prototype_arg_names_8616",
            _post._normalize_function_prototype_arg_names_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_8616",
            _calls._normalize_call_target_names_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_classify_return_shape_8616",
            _post._classify_return_shape_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_void_function_return_values_8616",
            _post._prune_void_function_return_values_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dedupe_codegen_variable_names_8616",
            _post._dedupe_codegen_variable_names_8616,
            False,
        ),
    )


DECOMPILER_POSTPROCESS_PASSES = _build_decompiler_postprocess_passes()


def _decompiler_postprocess_passes_for_function(project, codegen):
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if func_addr is None:
        return DECOMPILER_POSTPROCESS_PASSES

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return DECOMPILER_POSTPROCESS_PASSES

    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        return DECOMPILER_POSTPROCESS_PASSES

    profile = info.get("x86_16_decompilation_profile", {})
    if isinstance(profile, dict) and profile.get("wrapper_like"):
        wrapper_pass_names = {
            "_lower_stable_ss_stack_accesses_8616",
            "_attach_callsite_summaries_8616",
            "_materialize_callsite_stack_arguments_8616",
            "_materialize_callsite_prototypes_8616",
            "_normalize_call_target_names_8616",
        }
        return tuple(
            spec for spec in DECOMPILER_POSTPROCESS_PASSES
            if spec.name in wrapper_pass_names or DECOMPILER_POSTPROCESS_PASSES.index(spec) < 11
        )

    return DECOMPILER_POSTPROCESS_PASSES


def describe_x86_16_decompiler_postprocess_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_POSTPROCESS_PASSES)


def _snapshot_codegen_cfunc(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    try:
        return _deepcopy_cfunc_for_validation_8616(cfunc)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Failed to snapshot codegen cfunc at function=%#x stage=postprocess-snapshot: %s",
            getattr(cfunc, "addr", -1) or -1,
            ex,
        )
        return None


def _repair_cfunc_statements_wrapper(codegen) -> bool:
    """Ensure codegen.cfunc.statements is always a CStatements, not a raw list.

    Multiple transform() callbacks return plain Python lists instead of
    CStatements objects, which corrupts all downstream passes. This repair
    function is called before every postprocess step to guard against poisoning.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    statements = getattr(cfunc, "statements", None)
    if statements is None:
        return False
    if isinstance(statements, list) and not isinstance(statements, CStatements):
        cfunc.statements = CStatements(statements=statements, codegen=codegen)
        return True
    return False


def _restore_codegen_cfunc(codegen, snapshot) -> bool:
    if snapshot is None:
        return False
    codegen.cfunc = snapshot
    with contextlib.suppress(Exception):
        setattr(codegen.cfunc, "codegen", codegen)
    for node in _iter_c_nodes_deep_8616(codegen.cfunc):
        with contextlib.suppress(Exception):
            setattr(node, "codegen", codegen)
    return True


_IT_COUNT_TYPE = type(itertools.count())


def _deepcopy_cfunc_for_validation_8616(cfunc):
    dispatch = getattr(copy, "_deepcopy_dispatch", None)
    sentinel = object()
    previous = sentinel

    def _deepcopy_count(value, memo):
        match = re.fullmatch(r"count\(([-+]?\d+)(?:,\s*([-+]?\d+))?\)", repr(value))
        if match is None:
            raise TypeError(f"Unsupported itertools.count repr during validation clone: {value!r}")
        start = int(match.group(1))
        step = int(match.group(2)) if match.group(2) is not None else 1
        cloned = itertools.count(start, step)
        memo[id(value)] = cloned
        return cloned

    if isinstance(dispatch, dict):
        previous = dispatch.get(_IT_COUNT_TYPE, sentinel)
        dispatch[_IT_COUNT_TYPE] = _deepcopy_count
    try:
        return copy.deepcopy(cfunc)
    finally:
        if isinstance(dispatch, dict):
            if previous is sentinel:
                with contextlib.suppress(Exception):
                    del dispatch[_IT_COUNT_TYPE]
            else:
                dispatch[_IT_COUNT_TYPE] = previous


def _clone_codegen_for_validation_summary_8616(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    try:
        cloned_codegen = copy.copy(codegen)
        cloned_codegen.cfunc = _deepcopy_cfunc_for_validation_8616(cfunc)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Failed to clone codegen at function=%#x stage=tail-validation-baseline: %s",
            getattr(cfunc, "addr", -1) or -1,
            ex,
        )
        return None
    with contextlib.suppress(Exception):
        setattr(cloned_codegen.cfunc, "codegen", cloned_codegen)
    for node in _iter_c_nodes_deep_8616(cloned_codegen.cfunc):
        with contextlib.suppress(Exception):
            setattr(node, "codegen", cloned_codegen)
    _clear_tail_validation_clone_caches_8616(cloned_codegen)
    return cloned_codegen


def _clear_tail_validation_clone_caches_8616(codegen) -> None:
    # Force validation-side canonicalization to rebuild from the cloned AST
    # instead of reusing stale caches copied from the live codegen.
    for attr in (
        "_inertia_tail_validation_summary_cache",
        "_inertia_assignment_maps",
        "_inertia_vvar_carrier_deltas",
        "_inertia_stack_offset_cache",
        "_inertia_stack_pointer_aliases_for_cvars",
        "_inertia_stack_variable_bindings",
        "_inertia_stack_bindings",
        "_inertia_stack_canonicalization_bridges",
        "_inertia_stack_lowering_debug",
        "_inertia_has_rebound_materialized_recurrence",
        "_inertia_pre_validation_stack_semantics_primed",
        "_inertia_recurrence_state",
        "_inertia_cached_text",
        "_inertia_regenerated_text",
        "_inertia_stack_lowered_from_facts",
        "_inertia_semantic_facts_transferred",
        "_inertia_typed_conditions_transferred",
        "_inertia_tail_validation_widened_carriers",
    ):
        with contextlib.suppress(Exception):
            setattr(codegen, attr, None)
    with contextlib.suppress(Exception):
        if hasattr(codegen, "_x86_16_tail_validation_cache"):
            delattr(codegen, "_x86_16_tail_validation_cache")


def _attach_tail_validation_widened_carrier_provenance_8616(codegen, cfunc, *, function_addr: int) -> None:
    """
    Validation-only metadata.

    Attach widened stable-slot provenance to plain byte carriers that are
    already proved to seed from a materialized stack slot on the clone path.
    This is used only by tail-validation fingerprinting and must not mutate
    emitted/live semantics.
    """
    try:
        from angr.sim_variable import SimStackVariable
        from angr.analyses.decompiler.structured_codegen.c import CVariable

        from .lowering.real_mode_linear import _ensure_assignment_maps_8616
        from .tail_validation_fingerprint import _expr_fingerprint
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation widened-carrier provenance import failed at function=%#x stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
        return

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return

    def _name_candidates(variable, cvar) -> tuple[str, ...]:
        names: list[str] = []
        for candidate in (
            getattr(cvar, "name", None),
            getattr(variable, "name", None),
        ):
            if isinstance(candidate, str) and candidate and candidate not in names:
                names.append(candidate)
        return tuple(names)

    def _parse_stack_slot_fingerprint(fingerprint: str) -> tuple[int, int | None, str | None] | None:
        if not isinstance(fingerprint, str):
            return None
        if fingerprint.startswith("Reference(") and fingerprint.endswith(")"):
            fingerprint = fingerprint[len("Reference(") : -1]
        match = re.fullmatch(r"stack_slot:SS:BP([+-]0x[0-9a-fA-F]+)(?::size(\d+))?", fingerprint)
        if match is None:
            return None
        try:
            offset = int(match.group(1), 16)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "stack slot fingerprint offset parse failed: %s",
                ex,
            )
            return None
        size_text = match.group(2)
        size = int(size_text) if isinstance(size_text, str) else None
        return offset, size, fingerprint

    carrier_map: dict[str, dict[str, object]] = {}
    try:
        var_id_map, name_map, _reg_map, _multi_var, _multi_name, _multi_reg, first_name_map = _ensure_assignment_maps_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation widened-carrier provenance assignment-map build failed at function=%#x stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
        return

    recurrence_state = getattr(codegen, "_inertia_recurrence_state", None)
    if recurrence_state is not None and hasattr(recurrence_state, "resolve_known_copy_alias_expr"):
        for walk_node in _iter_c_nodes_deep_8616(getattr(cfunc, "statements", None)):
            if not isinstance(walk_node, CVariable):
                continue
            variable = getattr(walk_node, "variable", None)
            if not isinstance(variable, SimStackVariable):
                continue
            carrier_size = getattr(variable, "size", None)
            if not isinstance(carrier_size, int) or carrier_size >= 2:
                continue
            try:
                resolved_expr = recurrence_state.resolve_known_copy_alias_expr(walk_node)
                resolved_fp = _expr_fingerprint(resolved_expr, codegen.project)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "stack slot fingerprint via recurrence state failed: %s",
                    ex,
                )
                continue
            slot_info = _parse_stack_slot_fingerprint(resolved_fp)
            if slot_info is None:
                continue
            slot_offset, slot_size, _display = slot_info
            if not isinstance(slot_size, int) or slot_size <= carrier_size:
                continue
            variable_offset = getattr(variable, "offset", None)
            proof = {
                "offset": slot_offset,
                "size": slot_size,
                "carrier_size": carrier_size,
                "source": "recurrence_state_resolved_expr",
            }
            carrier_map[id(walk_node)] = proof
            carrier_map[id(variable)] = proof
            for name in _name_candidates(variable, walk_node):
                carrier_map[name] = proof
                carrier_map[(name, carrier_size)] = proof
            if isinstance(variable_offset, int):
                carrier_map[(variable_offset, carrier_size)] = proof

    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        carrier_size = getattr(variable, "size", None)
        if not isinstance(carrier_size, int) or carrier_size >= 2:
            continue
        for name in _name_candidates(variable, cvar):
            if re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is None:
                continue
            rhs = first_name_map.get(name)
            if rhs is None:
                rhs = var_id_map.get(id(variable))
            if rhs is None:
                rhs = name_map.get(name)
            if rhs is None:
                continue
            try:
                rhs_fp = _expr_fingerprint(rhs, codegen.project)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "rhs fingerprint via name map failed name=%s: %s",
                    name,
                    ex,
                )
                continue
            slot_info = _parse_stack_slot_fingerprint(rhs_fp)
            if slot_info is None:
                continue
            slot_offset, slot_size, _display = slot_info
            if not isinstance(slot_size, int) or slot_size <= carrier_size:
                continue
            variable_offset = getattr(variable, "offset", None)
            proof = {
                "offset": slot_offset,
                "size": slot_size,
                "carrier_size": carrier_size,
                "source": "first_assignment_stack_slot",
            }
            carrier_map[id(cvar)] = proof
            carrier_map[id(variable)] = proof
            carrier_map[name] = proof
            carrier_map[(name, carrier_size)] = proof
            if isinstance(variable_offset, int):
                carrier_map[(variable_offset, carrier_size)] = proof

    if carrier_map:
        setattr(codegen, "_inertia_tail_validation_widened_carriers", carrier_map)
        if os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
            logging.getLogger(__name__).warning(
                "[tail-widened-carriers] func=%#x entries=%r",
                function_addr,
                carrier_map,
            )
    elif os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
        logging.getLogger(__name__).warning(
            "[tail-widened-carriers] func=%#x entries=()",
            function_addr,
        )


def _prepare_tail_validation_baseline_clone_8616(project, codegen, *, function_addr: int):
    cloned_codegen = _clone_codegen_for_validation_summary_8616(codegen)
    if cloned_codegen is None:
        return None
    _repair_cfunc_statements_wrapper(cloned_codegen)
    debug_stats = {
        "validation_clone_stack_alias_facts": 0,
        "validation_clone_stack_bindings": 0,
        "validation_clone_stack_materialized": 0,
        "validation_clone_recurrence_materialized": 0,
        "validation_clone_failure_count": 0,
    }
    try:
        transfer_semantic_alias_facts_to_codegen_8616(project, cloned_codegen)
        alias_facts = getattr(cloned_codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list):
            debug_stats["validation_clone_stack_alias_facts"] = len(alias_facts)
            if alias_facts:
                lower_stack_accesses_from_alias_facts_8616(cloned_codegen, alias_facts)
        bindings = getattr(cloned_codegen, "_inertia_stack_variable_bindings", None)
        if isinstance(bindings, tuple | list):
            debug_stats["validation_clone_stack_bindings"] = len(bindings)
        for spec in DECOMPILER_POSTPROCESS_PASSES:
            if spec.needs_project:
                spec.func(project, cloned_codegen)
            else:
                spec.func(cloned_codegen)
            if spec.name == "_coalesce_linear_recurrence_after_stack_lowering_8616":
                break
        _attach_tail_validation_widened_carrier_provenance_8616(
            cloned_codegen,
            cloned_codegen.cfunc,
            function_addr=function_addr,
        )
        clone_debug = getattr(cloned_codegen, "_inertia_stack_lowering_debug", None)
        if isinstance(clone_debug, dict):
            debug_stats["validation_clone_stack_materialized"] = int(
                clone_debug.get("stack_slot_materialized", 0) or 0
            )
            debug_stats["validation_clone_recurrence_materialized"] = int(
                clone_debug.get("recurrence_bound_to_materialized_local", 0) or 0
            )
        if (
            debug_stats["validation_clone_stack_bindings"] > 0
            and debug_stats["validation_clone_stack_materialized"] == 0
        ):
            raise PipelineHardError(
                "validation baseline clone stack bindings not materialized",
                layer="tail_validation",
            )
    except Exception:
        debug_stats["validation_clone_failure_count"] += 1
        cloned_codegen._inertia_validation_clone_debug = debug_stats
        raise
    cloned_codegen._inertia_validation_clone_debug = debug_stats
    return cloned_codegen


def _debug_tail_validation_baseline_condition_8616(project, codegen, *, function_addr: int, label: str) -> None:
    if not os.environ.get("INERTIA_DEBUG_REINITBARS_BASELINE"):
        return
    try:
        from angr.analyses.decompiler.structured_codegen.c import CForLoop, CVariable

        from .tail_validation_fingerprint import _expr_fingerprint, _lookup_widened_carrier_proof_8616
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Baseline condition debug import failed at function=%#x stage=%s: %s",
            function_addr,
            label,
            ex,
        )
        return

    log = logging.getLogger(__name__)
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CForLoop):
            continue
        cond = getattr(node, "condition", None)
        try:
            cond_fp = _expr_fingerprint(cond, project)
        except Exception as ex:
            cond_fp = f"<fingerprint-error:{type(ex).__name__}:{ex}>"
        log.warning("[baseline-cond] %s cond=%r fp=%s", label, cond, cond_fp)
        for child in _iter_c_nodes_deep_8616(cond):
            if not isinstance(child, CVariable):
                continue
            variable = getattr(child, "variable", None)
            resolved_fp = None
            recurrence_state = getattr(codegen, "_inertia_recurrence_state", None)
            if recurrence_state is not None and hasattr(recurrence_state, "resolve_known_copy_alias_expr"):
                with contextlib.suppress(Exception):
                    resolved_fp = _expr_fingerprint(
                        recurrence_state.resolve_known_copy_alias_expr(child),
                        project,
                    )
            log.warning(
                "[baseline-cond] %s cvar_id=%s name=%r offset=%r size=%r proof=%r resolved=%r",
                label,
                id(child),
                getattr(child, "name", None) or getattr(variable, "name", None),
                getattr(variable, "offset", None),
                getattr(variable, "size", None),
                _lookup_widened_carrier_proof_8616(child, getattr(child, "codegen", None)),
                resolved_fp,
            )
        break


def _debug_reinitbars_condition_progress_8616(project, codegen, *, function_addr: int, label: str) -> None:
    if not os.environ.get("INERTIA_DEBUG_REINITBARS_CONDITION"):
        return
    if function_addr != 0x1000 and function_addr != 0x10678:
        return
    try:
        from angr.analyses.decompiler.structured_codegen.c import CForLoop

        from .tail_validation_fingerprint import _expr_fingerprint
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Condition progress debug import failed at function=%#x stage=%s: %s",
            function_addr,
            label,
            ex,
        )
        return
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CForLoop):
            continue
        cond = getattr(node, "condition", None)
        try:
            cond_fp = _expr_fingerprint(cond, project)
        except Exception as ex:
            cond_fp = f"<fingerprint-error:{type(ex).__name__}:{ex}>"
        logging.getLogger(__name__).warning(
            "[reinitbars-cond] %s fp=%s repr=%r",
            label,
            cond_fp,
            cond,
        )
        break


def _collect_tail_validation_summary_with_baseline_canonicalization_8616(project, codegen, *, mode: str):
    function_addr = getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1
    cloned_codegen = None
    if cloned_codegen is None:
        try:
            cloned_codegen = _prepare_tail_validation_baseline_clone_8616(
                project,
                codegen,
                function_addr=function_addr,
            )
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Tail-validation baseline canonicalization failed at function=%#x stage=baseline-canonicalization: %s",
                function_addr,
                ex,
            )
            return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
    if cloned_codegen is None:
        return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
    try:
        _repair_cfunc_statements_wrapper(cloned_codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation baseline clone final repair failed at function=%#x stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
    if os.environ.get("INERTIA_DEBUG_REINITBARS_BASELINE"):
        rs = getattr(cloned_codegen, "_inertia_recurrence_state", None)
        wc = getattr(cloned_codegen, "_inertia_tail_validation_widened_carriers", None)
        logging.getLogger(__name__).warning(
            "[baseline-debug] func=%#x recurrence_state=%s widened_carriers=%s entries=%s",
            function_addr,
            rs is not None,
            bool(wc),
            len(wc) if isinstance(wc, dict) else "N/A",
        )
        if isinstance(wc, dict) and wc:
            for key, proof in list(wc.items())[:6]:
                logging.getLogger(__name__).warning(
                    "[baseline-debug] proof key=%r offset=%r size=%r carrier_size=%r source=%r",
                    key,
                    proof.get("offset"),
                    proof.get("size"),
                    proof.get("carrier_size"),
                    proof.get("source"),
                )
    _debug_tail_validation_baseline_condition_8616(
        project,
        cloned_codegen,
        function_addr=function_addr,
        label="baseline-clone",
    )
    return collect_x86_16_tail_validation_summary(project, cloned_codegen, mode=mode)


def _prime_stack_semantics_before_validation_baseline_8616(project, codegen) -> None:
    if getattr(codegen, "_inertia_pre_validation_stack_semantics_primed", False):
        return
    try:
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        _segmented_mem._lower_stable_ss_stack_accesses_8616(codegen)
        _rerun_stack_lowering_consumers_after_calls_8616(project, codegen)
        _coalesce_linear_recurrence_after_stack_lowering_8616(project, codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation stack semantics priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_stack_semantics_primed = True


def _postprocess_codegen_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    accepted_changed = False
    last_changed_pass = None
    codegen._inertia_rewrite_failed = False
    codegen._inertia_rewrite_failure_pass = None
    codegen._inertia_rewrite_failure_error = None
    codegen._inertia_last_postprocess_pass = None
    codegen._inertia_postprocess_validation_failed = False
    codegen._inertia_postprocess_validation_failure_pass = None
    codegen._inertia_postprocess_validation_failure_error = None
    pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)
    codegen._inertia_postprocess_passes = tuple(spec.name for spec in pass_specs)
    validation_enabled = bool(getattr(project, "_inertia_tail_validation_enabled", True))
    per_pass_validation_enabled = bool(
        getattr(project, "_inertia_postprocess_per_pass_validation_enabled", False)
    )
    if os.environ.get("INERTIA_DEBUG_CONDITION_TRACE"):
        per_pass_validation_enabled = True

    baseline_summary = (
        _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            project,
            codegen,
            mode="live_out",
        )
        if validation_enabled and per_pass_validation_enabled
        else None
    )

    def _apply_step(pass_name: str, step_func) -> bool:
        nonlocal accepted_changed, last_changed_pass
        # Repair: ensure statements is always CStatements before every pass.
        # Many transform() callbacks return plain lists, which corrupts downstream.
        _repair_cfunc_statements_wrapper(codegen)
        snapshot = _snapshot_codegen_cfunc(codegen) if per_pass_validation_enabled else None
        try:
            step_changed = bool(step_func())
        except PipelineHardError:
            if per_pass_validation_enabled:
                _restore_codegen_cfunc(codegen, snapshot)
            raise
        except Exception as ex:  # noqa: BLE001
            if per_pass_validation_enabled:
                _restore_codegen_cfunc(codegen, snapshot)
            codegen._inertia_rewrite_failed = True
            codegen._inertia_rewrite_failure_pass = pass_name
            codegen._inertia_rewrite_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "Skipping 86_16 postprocess pass %s after %s: %s",
                pass_name,
                last_changed_pass or "no earlier rewrite",
                ex,
            )
            return False
        if validation_enabled and per_pass_validation_enabled:
            current_summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
            validation = compare_x86_16_tail_validation_summaries(baseline_summary, current_summary)
            if not x86_16_tail_validation_result_passed(validation):
                codegen._inertia_postprocess_validation_failed = True
                codegen._inertia_postprocess_validation_failure_pass = pass_name
                codegen._inertia_postprocess_validation_failure_error = (
                    validation.get("summary_text")
                    or f"tail-validation status={validation.get('status', 'unknown')}"
                )
                if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
                    logging.getLogger(__name__).warning(
                        "[postprocess-validation] function=%#x pass=%s delta=%s",
                        trace_func_addr if isinstance(trace_func_addr, int) else -1,
                        pass_name,
                        validation.get("summary_text") or validation.get("delta"),
                    )
                _restore_codegen_cfunc(codegen, snapshot)
                return False

        if step_changed:
            accepted_changed = True
            last_changed_pass = pass_name
            codegen._inertia_last_postprocess_pass = pass_name
        return True

    # ── Transfer typed conditions BEFORE typed condition pass ──
    if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        if func_addr is not None:
            try:
                transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Typed condition transfer failed at function=%#x stage=postprocess-transfer: %s",
                    func_addr,
                    ex,
                )
        codegen._inertia_typed_conditions_transferred = True

    # ── Typed condition rewriting pass (ConditionIR → explicit C comparisons) ──
    if not _apply_step(
        "_apply_typed_conditions_to_codegen_8616",
        lambda: _apply_typed_conditions_to_codegen_8616(project, codegen),
    ):
        codegen._inertia_postprocess_changed = accepted_changed
        project._inertia_decompiler_stage = "postprocess"
        return accepted_changed
    if codegen._inertia_postprocess_validation_failed:
        codegen._inertia_postprocess_changed = accepted_changed
        project._inertia_decompiler_stage = "postprocess"
        return accepted_changed

    # ── Optimization layer ──
    if not per_pass_validation_enabled:
        # Skip optimization for now — widening passes handle
        # CStatements internally via _unwrap_statements_8616
        if not _apply_step(
            "optimization",
            lambda: _run_optimization_passes_8616(codegen),
        ):
            codegen._inertia_postprocess_changed = accepted_changed
            project._inertia_decompiler_stage = "postprocess"
            return accepted_changed
        if codegen._inertia_postprocess_validation_failed:
            codegen._inertia_postprocess_changed = accepted_changed
            project._inertia_decompiler_stage = "postprocess"
            return accepted_changed

    import time as _ppt
    _t_pp_start = _ppt.perf_counter()
    trace_after_callsite = False
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    trace_func_addr = func_addr
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(trace_func_addr, int) and isinstance(delta, int):
        trace_func_addr = trace_func_addr + delta
    for spec in pass_specs:
        project._inertia_decompiler_stage = f"postprocess:{spec.name}"
        _t_pass = _ppt.perf_counter()
        if os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            import sys as _ppsys
            _ppsys.stderr.write(f"[{_ppt.strftime('%H:%M:%S')}] postprocess pass: {spec.name} (+{_t_pass - _t_pp_start:.1f}s)\n")
            _ppsys.stderr.flush()
        if spec.needs_project:
            step = lambda spec=spec: spec.func(project, codegen)
        else:
            step = lambda spec=spec: spec.func(codegen)
        if not _apply_step(spec.name, step):
            break
        if codegen._inertia_postprocess_validation_failed:
            break
        if isinstance(trace_func_addr, int):
            _debug_reinitbars_condition_progress_8616(
                project,
                codegen,
                function_addr=trace_func_addr,
                label=spec.name,
            )
        if spec.name == "_materialize_callsite_stack_arguments_8616":
            trace_after_callsite = True
        if trace_after_callsite and os.environ.get("INERTIA_DEBUG_CALL_MUTATION") and isinstance(trace_func_addr, int):
            if _regenerate_text_safely(codegen, context=f"{trace_func_addr:#x} trace:{spec.name}"):
                _debug_dump_calls_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)
        if trace_after_callsite and isinstance(trace_func_addr, int):
            if _regenerate_text_safely(codegen, context=f"{trace_func_addr:#x} heap-trace:{spec.name}"):
                _debug_heap_call_lines_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)
                _debug_stack_noise_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)
    if accepted_changed and not codegen._inertia_postprocess_validation_failed:
        final_context = f"{trace_func_addr:#x} postprocess:final" if isinstance(trace_func_addr, int) else "postprocess:final"
        _regenerate_text_safely(codegen, context=final_context)
    codegen._inertia_postprocess_changed = accepted_changed
    project._inertia_decompiler_stage = "postprocess"
    return accepted_changed


def _regenerate_text_safely(codegen, *, context: str) -> bool:
    try:
        codegen.regenerate_text()
    except Exception as ex:
        codegen._inertia_regeneration_failed = True
        codegen._inertia_regeneration_error = str(ex)
        codegen._inertia_regeneration_context = context
        codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
        logging.getLogger(__name__).warning(
            "Skipping 86_16 postprocess regeneration for %s after %s: %s",
            context,
            getattr(codegen, "_inertia_last_postprocess_pass", None) or "no prior rewrite",
            ex,
        )
        return False
    codegen._inertia_regeneration_failed = False
    codegen._inertia_regeneration_error = None
    codegen._inertia_regeneration_context = context
    codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
    return True


def _inertia_run_pre_rewrite_invariant_gate(project, codegen, function) -> None:
    """Run the pre-rewrite invariant checks and record results on codegen.

    AGENTS rule: rewrite must not hide bad alias/type/condition recovery.
    If invariants fail, rewrite is skipped and honest partial output is emitted.
    
    CRITICAL: transfer semantic alias facts from lifter/emulator to codegen
    BEFORE running invariants, so the invariant checks can see them.
    """
    # Transfer alias facts from emulator → codegen
    if not getattr(codegen, "_inertia_semantic_facts_transferred", False):
        try:
            transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        except Exception as ex:
            setattr(codegen, "_inertia_semantic_facts_transfer_error", str(ex))
        finally:
            codegen._inertia_semantic_facts_transferred = True

    # ── Materialize stack facts into real SimStackVariables ──
    # This must run AFTER fact transfer and BEFORE the invariant gate.
    # AGENTS rule: facts are not success, only materialized output is success.
    if not getattr(codegen, "_inertia_stack_lowered_from_facts", False):
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            try:
                lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
            except Exception as ex:
                setattr(codegen, "_inertia_stack_lowering_error", str(ex))
        codegen._inertia_stack_lowered_from_facts = True

    # Transfer typed conditions from emulator → codegen
    if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
        cfunc = getattr(codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        if func_addr is not None:
            try:
                transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Typed condition transfer failed at function=%#x stage=invariant-gate: %s",
                    func_addr,
                    ex,
                )
        codegen._inertia_typed_conditions_transferred = True

    # Repair statements wrapper before invariant check (last pass may have corrupted it)
    _repair_cfunc_statements_wrapper(codegen)

    c_text = ""
    with contextlib.suppress(Exception):
        c_text = getattr(codegen, "text", "") or getattr(codegen, "_text", "") or ""

    # ── Apply fact-based ss << 4 → variable name substitution ──
    # This is rewrite-layer cleanup using already-materialized alias facts.
    # DISABLED in normal path: text-based substitution violates AGENTS rule
    # "no text-based recovery".  Kept behind debug flag for emergency use.
    if c_text and getattr(codegen, "_inertia_allow_late_stack_text_bridge", False):
        try:
            c_text = apply_stack_variable_bindings_to_c_text(c_text, codegen)
        except Exception as ex:
            logging.getLogger(__name__).warning(
                "Late stack text bridge fallback failed at function=%#x stage=invariant-gate: %s",
                getattr(function, "addr", -1) or -1,
                ex,
            )

    report = validate_before_rewrite_8616(codegen, c_text=c_text, project=project)

    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            info["x86_16_pre_rewrite_invariant_report"] = report.to_dict()

    codegen._inertia_invariant_report = report
    codegen._inertia_invariant_checked = True

    # ── HARD CONTRACT GATE: abort if facts exist but aren't materialized ──
    # This MUST run after lowering and before any output is emitted.
    # If stack_facts > 0 and stack_materialized == 0, raise PipelineHardError.
    assert_pipeline_contracts_8616(codegen)

    if report.rewrite_blocked:
        codegen._inertia_rewrite_failed = True
        codegen._inertia_rewrite_failure_pass = "invariant_gate"
        codegen._inertia_rewrite_failure_error = report.skip_reason

        formatted = format_invariant_report_8616(report)
        log = logging.getLogger(__name__)
        log.warning("Pre-rewrite invariant gate BLOCKED rewrite for %#x (%s): %s",
                     getattr(function, 'addr', 0),
                     getattr(function, 'name', '?'),
                     report.skip_reason)
        log.warning("Invariant report:\n%s", formatted)
    else:
        log = logging.getLogger(__name__)
        log.debug("Pre-rewrite invariant gate passed for %#x (%s)",
                   getattr(function, 'addr', 0),
                   getattr(function, 'name', '?'))


def _decompile_8616(self):
    _orig_decompiler_decompile = getattr(_decompile_8616, "_orig_decompiler_decompile", None)
    if _orig_decompiler_decompile is None:
        _orig_decompiler_decompile = Decompiler._decompile
        _decompile_8616._orig_decompiler_decompile = _orig_decompiler_decompile
    core_started = time.perf_counter()
    self.project._inertia_decompiler_stage = "core"
    _orig_decompiler_decompile(self)
    core_elapsed = time.perf_counter() - core_started
    cfunc = getattr(self.codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    func_name = getattr(cfunc, "name", None) if cfunc is not None else None
    tv_enabled = bool(getattr(self.project, "_inertia_tail_validation_enabled", True))
    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        import sys as _tv_sys
        _tv_sys.stderr.write(f"[dbg] _decompile_8616: addr={func_addr} name={func_name} codegen_is_none={self.codegen is None} tv_enabled={tv_enabled}\n")
        _tv_sys.stderr.flush()
    if self.project.arch.name != "86_16" or self.codegen is None:
        return
    if not tv_enabled:
        postprocess_started = time.perf_counter()
        changed = _postprocess_codegen_8616(self.project, self.codegen)
        postprocess_elapsed = time.perf_counter() - postprocess_started
        function = getattr(self, "function", None) or getattr(self, "func", None)
        if function is not None:
            info = getattr(function, "info", None)
            if isinstance(info, MutableMapping):
                postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
                postprocess_info["core_elapsed"] = core_elapsed
                postprocess_info["elapsed"] = postprocess_elapsed
                postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
                postprocess_info["changed"] = bool(changed)
                postprocess_info["failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
                postprocess_info["failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
                postprocess_info["failure_error"] = getattr(self.codegen, "_inertia_rewrite_failure_error", None)
                postprocess_info["validation_failed"] = bool(
                    getattr(self.codegen, "_inertia_postprocess_validation_failed", False)
                )
                postprocess_info["validation_failure_pass"] = getattr(
                    self.codegen, "_inertia_postprocess_validation_failure_pass", None
                )
                postprocess_info["validation_failure_error"] = getattr(
                    self.codegen, "_inertia_postprocess_validation_failure_error", None
                )
                postprocess_info["pass_names"] = getattr(self.codegen, "_inertia_postprocess_passes", ())
        setattr(self.codegen, "_inertia_tail_validation_snapshot", None)
        self.project._inertia_decompiler_stage = "postprocess_done"
        return

    validation_mode = "live_out"
    import sys as _tv_sys3
    _tv_sys3.stderr.write(f"[dbg] _decompile_8616 ENTER validation path: addr={func_addr} id={id(self.codegen)}\n")
    _tv_sys3.stderr.flush()
    before_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    before_collect_started = time.perf_counter()
    before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
        self.project,
        self.codegen,
        mode=validation_mode,
    )
    before_collect_elapsed = time.perf_counter() - before_collect_started
    # Snapshot pre-postprocess codegen for semantic gate
    pre_postprocess_cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    postprocess_started = time.perf_counter()
    changed = _postprocess_codegen_8616(self.project, self.codegen)
    postprocess_elapsed = time.perf_counter() - postprocess_started
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is None and getattr(getattr(self, "codegen", None), "cfunc", None) is not None:
        addr = getattr(self.codegen.cfunc, "addr", None)
        kb_functions = getattr(getattr(self, "project", None), "kb", None)
        kb_functions = getattr(kb_functions, "functions", None)
        if isinstance(addr, int) and kb_functions is not None:
            with contextlib.suppress(Exception):
                function = kb_functions.function(addr, create=False)
    context = f"{getattr(function, 'addr', 'unknown')!r} {getattr(function, 'name', 'unknown')}"
    if changed:
        _regenerate_text_safely(self.codegen, context=context)
    record_ast_condition_trace_8616(self.project, self.codegen, stage="emitted_c")
    # ── Pre-rewrite invariant gate ──
    _inertia_run_pre_rewrite_invariant_gate(self.project, self.codegen, function)
    after_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
    after_collect_started = time.perf_counter()
    after_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
    after_collect_elapsed = time.perf_counter() - after_collect_started
    owner = getattr(function, "info", None) if function is not None else None
    validation_started = time.perf_counter()
    validation = build_x86_16_tail_validation_cached_result(
        owner=owner if isinstance(owner, MutableMapping) else None,
        stage="postprocess",
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
    validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
    snapshot_function_info = None
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            snapshot_function_info = info
            postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
            postprocess_info["core_elapsed"] = core_elapsed
            postprocess_info["postprocess_elapsed"] = postprocess_elapsed
            postprocess_info["tail_validation_timings"] = validation_timings
            postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
            postprocess_info["rewrite_failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
            postprocess_info["rewrite_failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
            postprocess_info["rewrite_failure_error"] = getattr(self.codegen, "_inertia_rewrite_failure_error", None)
            postprocess_info["validation_failed"] = bool(
                getattr(self.codegen, "_inertia_postprocess_validation_failed", False)
            )
            postprocess_info["validation_failure_pass"] = getattr(
                self.codegen,
                "_inertia_postprocess_validation_failure_pass",
                None,
            )
            postprocess_info["validation_failure_error"] = getattr(
                self.codegen,
                "_inertia_postprocess_validation_failure_error",
                None,
            )
            postprocess_info["regeneration_failed"] = bool(getattr(self.codegen, "_inertia_regeneration_failed", False))
            postprocess_info["regeneration_failure_pass"] = getattr(
                self.codegen,
                "_inertia_regeneration_last_pass",
                None,
            )
            postprocess_info["regeneration_failure_error"] = getattr(
                self.codegen,
                "_inertia_regeneration_error",
                None,
            )
            postprocess_info["pass_names"] = getattr(self.codegen, "_inertia_postprocess_passes", ())
            postprocess_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
            postprocess_info["tail_validation_verdict"] = validation["verdict"]
            postprocess_info["tail_validation_cache_hit"] = bool(validation.get("cache_hit", False))
    persist_x86_16_tail_validation_snapshot(
        function_info=snapshot_function_info,
        codegen=self.codegen,
        stage="postprocess",
        validation=validation,
    )
    record_tail_validation_condition_trace_8616(self.project, self.codegen, validation)
    materialized_condition_drift_detected_8616(self.project, self.codegen)
    dump_condition_trace_8616(self.project, self.codegen, label="postprocess")
    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        import sys as _tv_sys2
        _tv_sys2.stderr.write(f"[dbg] _decompile_8616 persist: addr={func_addr} name={func_name} snapshot_stages={list(snapshot.keys()) if isinstance(snapshot, dict) else 'NONE'} codegen_id={id(self.codegen)}\n")
        _tv_sys2.stderr.flush()
    log = logging.getLogger(__name__)
    if not x86_16_tail_validation_result_passed(validation):
        if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
            delta = validation.get("delta") if isinstance(validation, dict) else None
            log.warning(
                "[postprocess-validation] final function=%#x verdict=%s stack_delta=%s before=%s after=%s",
                function_original_addr(function) if function is not None else -1,
                validation.get("verdict"),
                (delta or {}).get("stack_writes"),
                (validation.get("before") or {}).get("stack_writes"),
                (validation.get("after") or {}).get("stack_writes"),
            )
        log.warning(
            "Postprocess validation changed — discarding postprocessed C, emitting pre-postprocess C: %s",
            validation["verdict"],
        )
        # Semantic gate: restore pre-postprocess codegen when postprocess changed live-out observables
        if pre_postprocess_cfunc_snapshot is not None:
            _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
            codegen._inertia_postprocess_discarded = True
            codegen._inertia_postprocess_discard_verdict = validation["verdict"]
    else:
        log.info("%s", validation["verdict"])
    self.project._inertia_decompiler_stage = "done"
    import sys as _tv_sys4
    tv_snap = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    _tv_sys4.stderr.write(f"[dbg] _decompile_8616 DONE: addr={func_addr} codegen_id={id(self.codegen)} snapshot_stages={list(tv_snap.keys()) if isinstance(tv_snap, dict) else 'NONE'} proj_fb_stages={list(getattr(self.project, '_inertia_last_tail_validation_snapshot', {}).keys())}\n")
    _tv_sys4.stderr.flush()


def apply_x86_16_decompiler_postprocess() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_8616":
        _decompile_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_8616
