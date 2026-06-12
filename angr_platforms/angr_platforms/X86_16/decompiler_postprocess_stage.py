from __future__ import annotations

import contextlib
import copy
import itertools
import logging
import os
import re
import time
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfBreak,
    CIfElse,
    CIndexedVariable,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from inertia_decompiler.runtime_support import AnalysisTimeout, analysis_timeout, timing_output_enabled
from inertia_decompiler.telemetry import annotate_current_span, span

from . import decompiler_postprocess as _post
from . import decompiler_postprocess_calls as _calls
from . import decompiler_postprocess_flags as _flags
from . import decompiler_postprocess_globals as _globals
from . import decompiler_postprocess_jcc as _jcc
from . import decompiler_postprocess_simplify as _simplify
from . import segmented_memory_reasoning as _segmented_mem
from .annotations import ANNOTATION_KEY, _parse_c_prototype_8616, _source_decl_from_cod_source_lines
from .callee_name_normalization import normalize_callee_name_8616
from .compiler_helpers import identify_x86_16_compiler_helper_at_8616, is_x86_16_stack_probe_name_8616
from .condition_trace import (
    dump_condition_trace_8616,
    materialized_condition_drift_detected_8616,
    record_ast_condition_trace_8616,
    record_tail_validation_condition_trace_8616,
)
from .decompiler_postprocess_typed_conditions import _apply_typed_conditions_to_codegen_8616
from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616, _structured_slot_names_8616
from .ir.condition_ir import (
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from .lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
from .lowering.real_mode_linear import (
    _direct_global_update_name_8616,
    _type_for_access_width_8616,
    materialize_direct_global_incdec_instructions_8616,
    materialize_direct_stack_incdec_instructions_8616,
    materialize_direct_stack_mov_instructions_8616,
)
from .lowering.ss_bp_substitution import (
    apply_stack_variable_bindings_to_c_text,
)
from .lowering.stack_lowering import run_stack_lowering_pass_8616
from .lowering.stack_lowering_from_facts import (
    _canonical_stack_offset_8616,
    _stack_object_name,
    lower_stack_accesses_from_alias_facts_8616,
)
from .pipeline.contracts import assert_pipeline_contracts_8616
from .pipeline.errors import PipelineHardError
from .pipeline.invariants import format_invariant_report_8616, validate_before_rewrite_8616
from .postprocess.optimization.dce import _dead_code_elimination_8616
from .postprocess.optimization.dead_setup import _count_dead_setup_escaped_8616
from .postprocess.optimization.pass_driver import _run_optimization_passes_8616
from .render_compat import repair_cfunctioncall_render_targets_8616
from .tail_validation import (
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    fingerprint_x86_16_tail_validation_boundary,
    persist_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_result_passed,
)
from .tail_validation_fingerprint import _expr_fingerprint, _stack_slot_fingerprint_from_slot_8616

__all__ = [
    "DecompilerPostprocessPassSpec",
    "DECOMPILER_POSTPROCESS_PASSES",
    "_build_decompiler_postprocess_passes",
    "describe_x86_16_decompiler_postprocess_stage",
    "apply_x86_16_decompiler_postprocess",
]


class _SimTypeNearPointer16_8616(SimTypePointer):
    """16-bit near pointer type for real-mode stack argument layout."""

    @property
    def size(self):
        return 16

    def _with_arch(self, arch):
        pts_to = self.pts_to.with_arch(arch) if hasattr(self.pts_to, "with_arch") else self.pts_to
        out = _SimTypeNearPointer16_8616(
            pts_to,
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = arch
        return out

    def make(self, pts_to):
        out = _SimTypeNearPointer16_8616(
            pts_to,
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = self._arch
        return out

    def copy(self):
        out = _SimTypeNearPointer16_8616(
            self.pts_to,
            self.label,
            self.offset,
            qualifier=self.qualifier,
            disposition=self.disposition,
        )
        out._arch = self._arch
        return out


class _PostprocessValidationDeltaKind8616(Enum):
    BLOCKING = "blocking"
    NAME_ONLY_HELPER_ANNOTATION = "name_only_helper_annotation"
    JCC_CALL_RETURN_CONDITION_REBINDING = "jcc_call_return_condition_rebinding"
    JCC_CONDITION_MATERIALIZATION = "jcc_condition_materialization"
    DIRECT_GLOBAL_UPDATE_MATERIALIZATION = "direct_global_update_materialization"
    DIRECT_STACK_UPDATE_MATERIALIZATION = "direct_stack_update_materialization"
    DIRECT_STACK_MOVE_MATERIALIZATION = "direct_stack_move_materialization"
    UNREACHABLE_AFTER_RETURN_PRUNE = "unreachable_after_return_prune"
    CALLSITE_STACK_ARGUMENT_MATERIALIZATION = "callsite_stack_argument_materialization"
    STACK_PROBE_HELPER_CLEANUP = "stack_probe_helper_cleanup"
    MISSING_TERMINAL_AX_RETURN = "missing_terminal_ax_return"
    CFG_RETURN_CHAIN_MATERIALIZATION = "cfg_return_chain_materialization"
    CFG_RETURN_EXPR_CHAIN_MATERIALIZATION = "cfg_return_expr_chain_materialization"


class _CfgReturnExprDeltaRefusal8616(Enum):
    MISSING_EVIDENCE = "missing_evidence"
    MISSING_DELTA = "missing_delta"
    UNEXPECTED_FIELDS = "unexpected_fields"
    MISSING_RETURNS_DELTA = "missing_returns_delta"
    UNEXPECTED_ADDED_RETURNS = "unexpected_added_returns"
    UNEXPECTED_REMOVED_RETURNS = "unexpected_removed_returns"
    UNEXPECTED_ADDED_CONDITIONS = "unexpected_added_conditions"
    UNEXPECTED_ADDED_CONTROL = "unexpected_added_control"
    UNEXPECTED_HELPER_DELTA = "unexpected_helper_delta"


class _VoidEmptyReturnGuardDecision8616(Enum):
    PRUNE = "prune"
    KEEP_NOT_VOID = "keep_not_void"
    KEEP_NO_BRANCH_PROOF = "keep_no_branch_proof"
    KEEP_WITHIN_BRANCH_BUDGET = "keep_within_branch_budget"
    KEEP_BRANCH_BACKED_CONDITION = "keep_branch_backed_condition"
    KEEP_NOT_EMPTY_RETURN_GUARD = "keep_not_empty_return_guard"


class _ConditionBranchTagEvidence8616(Enum):
    NO_TAG = "no_tag"
    CONDITIONAL_BRANCH = "conditional_branch"
    NON_BRANCH = "non_branch"
    UNKNOWN = "unknown"


class _SurplusIfGuardKind8616(Enum):
    EMPTY_RETURN = "empty_return"
    EMPTY_NOOP = "empty_noop"


class _PostprocessPassRefusalReason8616(Enum):
    LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE = "large_function_local_validation_unavailable"
    VERY_LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE = "very_large_function_local_validation_unavailable"


_MISSING_TERMINAL_AX_RETURN_PASS_NAMES_8616 = frozenset(
    {
        "_materialize_missing_terminal_ax_return_8616",
    }
)


_JCC_REWRITE_VALIDATION_PASS_NAMES_8616 = frozenset(
    {
        "_rewrite_decoded_jcc_conditions_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
    }
)

_DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616 = frozenset(
    {
        "_materialize_direct_global_incdec_instructions_8616",
        "_materialize_direct_global_incdec_instructions_final_8616",
    }
)

_DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616 = frozenset(
    {
        "_materialize_direct_stack_incdec_instructions_8616",
        "_materialize_direct_stack_incdec_instructions_final_8616",
    }
)

_DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616 = frozenset(
    {
        "_materialize_direct_stack_mov_instructions_8616",
        "_materialize_direct_stack_mov_instructions_final_8616",
    }
)

_HELPER_NAME_ONLY_VALIDATION_PASS_NAMES_8616 = _JCC_REWRITE_VALIDATION_PASS_NAMES_8616 | frozenset(
    {
        "_materialize_callsite_stack_arguments_8616",
    }
)

_LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616 = (
    frozenset(
        {
            "optimization",
            "_apply_annotations_8616",
            "_apply_word_global_types_8616",
            "_materialize_stable_stack_semantics_bootstrap_8616",
            "_materialize_stable_stack_semantics_early_8616",
            "_promote_stack_prototype_from_bp_loads_8616",
            "_prune_return_address_stack_arguments_8616",
            "_apply_typed_conditions_to_codegen_8616",
            "_simplify_boolean_cites_8616",
            "_simplify_structured_expressions_8616",
            "_maybe_eliminate_single_use_temporaries_8616",
            "_lower_stable_ss_stack_accesses_8616",
            "_simplify_structured_expressions_after_stack_lowering_8616",
            "_materialize_stable_stack_semantics_postprocess_8616",
            "_materialize_stable_stack_semantics_final_8616",
            "_dead_code_elimination_after_callsite_stack_arguments_8616",
            "_dead_code_elimination_after_flag_prune_8616",
            "_dead_code_elimination_after_stable_stack_final_8616",
            "_rewrite_flag_condition_pairs_8616",
            "_rewrite_flag_bit_value_uses_8616",
            "_prune_unused_flag_assignments_8616",
            "_prune_overwritten_flag_assignments_8616",
            "_fix_interval_guard_conditions_8616",
            "_materialize_global_byte_index_sum_loop_8616",
            "_materialize_nested_stack_counter_accumulator_loop_8616",
            "_materialize_stack_arg_accumulator_loop_8616",
            "_materialize_cfg_selector_return_branches_early_8616",
            "_materialize_cfg_mask_accumulator_8616",
            "_materialize_cfg_selector_return_branches_8616",
            "_repair_loop_exit_return_guards_8616",
            "_repair_unresolved_function_exit_gotos_8616",
            "_simplify_structured_expressions_after_call_stack_lowering_8616",
            "_recover_missing_direct_calls_from_evidence_early_8616",
            "_recover_missing_direct_calls_from_evidence_8616",
            "_normalize_fact_backed_stack_accesses_8616",
            "_normalize_call_target_names_8616",
            "_normalize_recovered_call_target_names_8616",
            "_materialize_callsite_stack_arguments_8616",
            "_materialize_callsite_prototypes_8616",
            "_materialize_recovered_callsite_stack_arguments_8616",
            "_materialize_stack_byte_pair_return_8616",
            "_recover_missing_direct_calls_final_8616",
            "_materialize_pointer_memory_idioms_8616",
            "_materialize_empty_if_return_branches_8616",
            "_prune_surplus_void_empty_return_guards_8616",
            "_prune_surplus_void_empty_return_guards_final_8616",
            "_prune_unreachable_after_return_final_8616",
            "_materialize_empty_if_return_branches_final_8616",
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
        }
    )
    | _JCC_REWRITE_VALIDATION_PASS_NAMES_8616
    | _DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616
    | _DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616
    | _DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616
)

_MANDATORY_VALIDATION_PASS_NAMES_8616 = frozenset(
    {
        "_apply_annotations_8616",
    }
)

_PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616 = frozenset(
    {
        "_apply_annotations_8616",
    }
)


@dataclass(frozen=True)
class _PostprocessFunctionComplexity8616:
    block_count: int = 0
    byte_count: int = 0
    source: str = "missing"

    @property
    def is_expensive_for_local_validation(self) -> bool:
        return self.block_count >= 40 or self.byte_count >= 640


_C_AST_CHILD_ATTRS_8616 = (
    "statements",
    "condition",
    "condition_and_nodes",
    "else_node",
    "lhs",
    "rhs",
    "operand",
    "expr",
    "variable",
    "base",
    "index",
    "iftrue",
    "iffalse",
    "callee",
    "args",
    "target",
)

_POSTPROCESS_ROLLBACK_METADATA_EXCLUDE_8616 = frozenset(
    {
        "_inertia_last_postprocess_pass",
        "_inertia_postprocess_accepted_validation_deltas",
        "_inertia_postprocess_changed",
        "_inertia_postprocess_passes",
        "_inertia_postprocess_pre_validation_summary",
        "_inertia_postprocess_rejected_passes",
        "_inertia_postprocess_validation_failed",
        "_inertia_postprocess_validation_failure_error",
        "_inertia_postprocess_validation_failure_pass",
        "_inertia_regeneration_context",
        "_inertia_regeneration_error",
        "_inertia_regeneration_failed",
        "_inertia_regeneration_last_pass",
        "_inertia_rewrite_failed",
        "_inertia_rewrite_failure_error",
        "_inertia_rewrite_failure_pass",
        "_inertia_skip_per_pass_validation_large_function",
        "_inertia_tail_validation_snapshot",
    }
)

_POSTPROCESS_METADATA_SNAPSHOT_SCALAR_TYPES_8616 = (str, bytes, int, float, bool, type(None))
_POSTPROCESS_METADATA_SNAPSHOT_MAX_DEPTH_8616 = 4
_POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616 = 512


def _debug_dump_calls_8616(label: str, ctext: str, function_addr: int) -> None:
    def _impl():
        if not os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
            return
        target_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and function_addr != target_addr:
            return
        log = logging.getLogger(__name__)
        filter_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_FILTER", "")
        tracked = tuple(part.strip() for part in filter_text.split(",") if part.strip())
        call_line_re = re.compile(r"^\s*(?:[A-Za-z_]\w*\s*=\s*)?[A-Za-z_]\w*\s*\(")
        for line in str(ctext or "").splitlines():
            stripped = line.strip()
            if (tracked and any(name in stripped for name in tracked)) or (not tracked and call_line_re.match(stripped)):
                log.warning("[call-mutation] %s: %s", label, stripped)

    return _impl()


def _debug_stack_noise_8616(label: str, c_text: str, function_addr: int) -> None:
    def _impl():
        if not os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            return
        target_text = os.environ.get("INERTIA_DEBUG_STACK_NOISE_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and function_addr != target_addr:
            return
        log = logging.getLogger(__name__)
        for line in str(c_text or "").splitlines():
            if "&s_" in line or "s_" in line or "stack[" in line:
                log.warning("[stack-noise] %s: %s", label, line.strip())

    return _impl()


def _heap_postprocess_debug_enabled_8616() -> bool:
    return bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))


def _normalize_pointer_high_byte_shifts_8616(codegen) -> bool:
    """Ensure high-byte projection shifts operate on an integer expression.
    This keeps semantics explicit for 16-bit address-like carriers and avoids
    MS C C2116 on raw pointer shifts (e.g. ``&x >> 8``).
    """
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    if root is None:
        return False
    changed = False

    def _transform(node):
        nonlocal changed
        if not isinstance(node, CBinaryOp) or getattr(node, "op", None) != "Shr":
            return node
        shift_value = getattr(getattr(node, "rhs", None), "value", None)
        if shift_value != 8:
            return node
        lhs = getattr(node, "lhs", None)
        while isinstance(lhs, CTypeCast):
            lhs = lhs.expr
        if not isinstance(lhs, CUnaryOp) or getattr(lhs, "op", None) not in {"Reference", "AddressOf"}:
            return node
        changed = True
        cast_lhs = CTypeCast(None, SimTypeShort(False), node.lhs, codegen=codegen)
        return CBinaryOp("Shr", cast_lhs, node.rhs, codegen=codegen, tags=getattr(node, "tags", None))

    new_root = _transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
    _post._replace_c_children_8616(root, _transform)
    return changed


def _bind_codegen_variable_types_to_arch_8616(codegen) -> None:
    def _impl():
        project = getattr(codegen, "project", None)
        arch = getattr(project, "arch", None)
        if arch is None:
            return

        def _bind_type(type_):
            if type(type_) is SimTypeBottom:
                try:
                    return SimTypeShort(False).with_arch(arch)
                except Exception:
                    return SimTypeShort(False)
            if type_ is None or getattr(type_, "_arch", None) is not None or not hasattr(type_, "with_arch"):
                return type_
            try:
                return type_.with_arch(arch)
            except Exception:
                return type_

        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return

        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for cvar in variables_in_use.values():
                bound = _bind_type(getattr(cvar, "variable_type", None))
                if bound is not getattr(cvar, "variable_type", None):
                    cvar.variable_type = bound

        unified_locals = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, entries in list(unified_locals.items()):
                if not isinstance(entries, set):
                    continue
                new_entries = set()
                changed = False
                for cvar, vartype in entries:
                    bound = _bind_type(vartype)
                    if bound is not vartype:
                        changed = True
                    if bound is not getattr(cvar, "variable_type", None):
                        cvar.variable_type = bound
                    new_entries.add((cvar, bound))
                if changed:
                    unified_locals[variable] = new_entries

        root = getattr(cfunc, "statements", None)
        if root is None:
            return
        for node in _iter_c_nodes_deep_8616(root):
            bound = _bind_type(getattr(node, "variable_type", None))
            if bound is not getattr(node, "variable_type", None):
                node.variable_type = bound

    return _impl()


def _postprocess_exit_goto_repair_delta_8616(validation: dict) -> bool:
    def _impl():
        if not isinstance(validation, dict):
            return False

        delta = validation.get("delta")
        if not isinstance(delta, dict):
            return False

        control_flow_delta = delta.get("control_flow_effects")
        returns_delta = delta.get("returns")
        control_flow_added = tuple(control_flow_delta.get("added", ())) if isinstance(control_flow_delta, dict) else ()
        control_flow_removed = tuple(control_flow_delta.get("removed", ())) if isinstance(control_flow_delta, dict) else ()
        returns_added = tuple(returns_delta.get("added", ())) if isinstance(returns_delta, dict) else ()
        returns_removed = tuple(returns_delta.get("removed", ())) if isinstance(returns_delta, dict) else ()

        return (
            isinstance(control_flow_delta, dict)
            and isinstance(returns_delta, dict)
            and returns_added == ("none",)
            and returns_removed == ()
            and len(control_flow_added) == 1
            and len(control_flow_removed) == 1
            and control_flow_added == ("return",)
            and str(control_flow_removed[0]).startswith("goto:")
        )

    return _impl()


def _postprocess_has_unresolved_gotos_8616(codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    return any(isinstance(node, CGoto) for node in _iter_c_nodes_deep_8616(root))


def _rerun_stack_lowering_consumers_after_calls_8616(project, codegen) -> bool:
    if getattr(codegen, "_inertia_return_selector_materialized_8616", False):
        codegen._inertia_stack_lowering_rerun_refused_selector_return_8616 = (
            int(getattr(codegen, "_inertia_stack_lowering_rerun_refused_selector_return_8616", 0) or 0) + 1
        )
        return False
    from inertia_decompiler.cli_c_ast_rewrites import (
        _canonicalize_stack_cvars as _rewrite_canonicalize_stack_cvars,
    )
    from inertia_decompiler.cli_c_ast_rewrites import (
        _rewrite_ss_stack_byte_offsets as _rewrite_stack_byte_offsets,
    )

    if getattr(codegen, "_inertia_skip_per_pass_validation_large_function", False):
        codegen._inertia_stack_lowering_large_function_byte_only_8616 = int(
            getattr(codegen, "_inertia_stack_lowering_large_function_byte_only_8616", 0) or 0
        ) + 1
        return _rewrite_stack_byte_offsets(project, codegen)

    previous_budget_exists = hasattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616")
    previous_budget = getattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616", None)
    current_budget = previous_budget if isinstance(previous_budget, int) and previous_budget > 0 else 64
    codegen._inertia_stack_lowering_canonicalize_max_depth_8616 = min(current_budget, 16)
    codegen._inertia_stack_lowering_after_call_canonicalize_budget_8616 = int(
        getattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616", 16) or 16
    )
    try:
        return run_stack_lowering_pass_8616(
            lower_stable_ss_stack_accesses=lambda: False,
            rewrite_ss_stack_byte_offsets=lambda: _rewrite_stack_byte_offsets(project, codegen),
            canonicalize_stack_cvars=lambda: _rewrite_canonicalize_stack_cvars(codegen),
            codegen=codegen,
            project=project,
            # This is a late consumer rerun after callsite materialization. Keep
            # expensive global lowering disabled, but run runtime segment lowering
            # once because call materialization can expose fresh segment carriers.
            max_rounds=1,
            lower_global_segment_accesses=False,
            lower_runtime_segment_accesses=True,
        )
    finally:
        if previous_budget_exists:
            codegen._inertia_stack_lowering_canonicalize_max_depth_8616 = previous_budget
        elif hasattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616"):
            delattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616")


def _normalize_fact_backed_stack_accesses_8616(project, codegen) -> bool:
    """Canonicalize AST stack accesses after alias-fact materialization.

    Stack identity is still owned by alias/lowering. This bridge only runs AST
    consumers after proven stack facts have materialized real SimStackVariables,
    so validation and live postprocess see the same canonical SS:BP form.
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    if not getattr(codegen, "_inertia_semantic_facts_transferred", False):
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)

    alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if isinstance(alias_facts, list) and alias_facts:
        before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
        lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
        changed = after_materialized > before_materialized

    if not getattr(codegen, "_inertia_semantic_stack_materialized_count", 0):
        return changed

    from inertia_decompiler.cli_c_ast_rewrites import (
        _canonicalize_stack_cvars as _rewrite_canonicalize_stack_cvars,
    )
    from inertia_decompiler.cli_c_ast_rewrites import (
        _rewrite_ss_stack_byte_offsets as _rewrite_stack_byte_offsets,
    )

    changed = bool(_rewrite_stack_byte_offsets(project, codegen)) or changed
    changed = bool(_rewrite_canonicalize_stack_cvars(codegen)) or changed
    return changed


def _fact_backed_stack_normalize_enabled_8616() -> bool:
    return os.environ.get("INERTIA_ENABLE_FACT_BACKED_STACK_NORMALIZE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _repair_loop_exit_return_guards_pass_8616(codegen) -> bool:
    handler = globals().get("_repair_loop_exit_return_guards_8616")
    if callable(handler):
        return bool(handler(codegen))
    return False


def _signed_i16_immediate_8616(value: int) -> int:
    value = int(value) & 0xFFFF
    if value & 0x8000:
        return value - 0x10000
    return value


def _clone_c_expr_8616(expr):
    codegen = getattr(expr, "codegen", None)
    if isinstance(expr, CVariable):
        return CVariable(
            getattr(expr, "variable", None),
            unified_variable=getattr(expr, "unified_variable", None),
            variable_type=getattr(expr, "variable_type", None),
            vvar_id=getattr(expr, "vvar_id", None),
            codegen=codegen,
            tags=getattr(expr, "tags", None),
        )
    if isinstance(expr, CConstant):
        return CConstant(
            getattr(expr, "value", None),
            getattr(expr, "type", None),
            reference_values=getattr(expr, "reference_values", None),
            codegen=codegen,
            tags=getattr(expr, "tags", None),
        )
    if isinstance(expr, CBinaryOp):
        return CBinaryOp(
            getattr(expr, "op", None),
            _clone_c_expr_8616(getattr(expr, "lhs", None)),
            _clone_c_expr_8616(getattr(expr, "rhs", None)),
            codegen=codegen,
            tags=getattr(expr, "tags", None),
        )
    if isinstance(expr, CUnaryOp):
        return CUnaryOp(
            getattr(expr, "op", None),
            _clone_c_expr_8616(getattr(expr, "operand", None)),
            codegen=codegen,
            tags=getattr(expr, "tags", None),
        )
    if isinstance(expr, CTypeCast):
        return CTypeCast(
            getattr(expr, "src_type", None),
            getattr(expr, "dst_type", None),
            _clone_c_expr_8616(getattr(expr, "expr", None)),
            codegen=codegen,
            tags=getattr(expr, "tags", None),
        )
    with contextlib.suppress(Exception):
        return copy.copy(expr)
    return expr


def _terminal_stack_arg_expr_8616(project, codegen, disp: int, size: int):
    if int(disp) <= 2:
        return _clone_c_expr_8616(_jcc._stack_slot_expr_8616(codegen, int(disp), int(size) or 2))
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return _clone_c_expr_8616(_jcc._stack_slot_expr_8616(codegen, int(disp), int(size) or 2))
    width = max(2, int(size) or 2)
    arg_list = list(getattr(cfunc, "arg_list", ()) or ())
    for arg in arg_list:
        variable = getattr(arg, "variable", None)
        if isinstance(variable, SimStackVariable) and getattr(variable, "offset", None) == int(disp):
            return _clone_c_expr_8616(arg)
    arg_type = SimTypeShort(False)
    name = f"arg_{int(disp):x}"
    variable = SimStackVariable(int(disp), width, base="bp", name=name, region=getattr(cfunc, "addr", None))
    cvar = CVariable(variable, variable_type=arg_type, codegen=codegen)
    arg_list.append(cvar)
    arg_list.sort(key=lambda item: getattr(getattr(item, "variable", None), "offset", 0) or 0)
    cfunc.arg_list = arg_list
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        unified[variable] = {(cvar, arg_type)}
    prototype = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    return_type = getattr(prototype, "returnty", None) if prototype is not None else SimTypeShort(False)
    arg_types = [getattr(arg, "variable_type", None) or SimTypeShort(False) for arg in arg_list]
    arg_names = [getattr(getattr(arg, "variable", None), "name", None) or f"arg_{idx}" for idx, arg in enumerate(arg_list)]
    new_proto = SimTypeFunction(arg_types, return_type, arg_names=arg_names).with_arch(project.arch)
    with contextlib.suppress(Exception):
        cfunc.functy = new_proto
    with contextlib.suppress(Exception):
        cfunc.prototype = new_proto
    codegen._inertia_missing_terminal_ax_return_stack_args_materialized_8616 = (
        int(getattr(codegen, "_inertia_missing_terminal_ax_return_stack_args_materialized_8616", 0) or 0) + 1
    )
    return _clone_c_expr_8616(cvar)


def _terminal_direct_global_expr_8616(project, codegen, disp: int, size: int):
    cfunc = getattr(codegen, "cfunc", None)
    if project is None or cfunc is None:
        return None
    width = int(size) if int(size or 0) in {1, 2, 4} else 2
    addr = int(disp) & 0xFFFF
    name = _direct_global_update_name_8616(project, getattr(cfunc, "addr", None), addr)
    variable = SimMemoryVariable(addr, width, name=name, region=getattr(cfunc, "addr", None))
    cvar = CVariable(variable, variable_type=_type_for_access_width_8616(width), codegen=codegen)
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        unified[variable] = {(cvar, getattr(cvar, "variable_type", None))}
    ctype = "unsigned char" if width == 1 else ("unsigned long" if width == 4 else "unsigned short")
    specs = tuple(getattr(codegen, "_inertia_global_declaration_specs_8616", ()) or ())
    codegen._inertia_global_declaration_specs_8616 = tuple(dict.fromkeys(specs + ((ctype, name, None),)))
    return _clone_c_expr_8616(cvar)


def _branch_target_return_value_8616(project, target_addr: int) -> int | None:
    try:
        block = project.factory.block(int(target_addr), opt_level=0)
    except Exception:
        return None
    for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and int(getattr(operands[0], "type", -1)) == 1
            and str(insn.reg_name(operands[0].reg)).lower() == "ax"
            and int(getattr(operands[1], "type", -1)) == 2
        ):
            return _signed_i16_immediate_8616(int(getattr(operands[1], "imm", 0) or 0))
        if mnemonic in {"ret", "retf", "iret"} or mnemonic.startswith("j"):
            return None
    return None


def _branch_target_return_expr_8616(project, codegen, target_addr: int, *, _depth: int = 0, _seen: set[int] | None = None):
    if _depth > 4:
        return None
    if _seen is None:
        _seen = set()
    target_addr = int(target_addr)
    if target_addr in _seen:
        return None
    _seen.add(target_addr)
    try:
        block = project.factory.block(target_addr, opt_level=0)
    except Exception:
        return None
    ax_value = None
    dx_value = None
    cx_value = None
    cl_value = None

    def _stack_offset(expr) -> int | None:
        if not isinstance(expr, CVariable):
            return None
        variable = getattr(expr, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        offset = getattr(variable, "offset", None)
        return offset if isinstance(offset, int) else None

    def _combined_return_expr():
        if ax_value is None:
            return None
        if dx_value is None:
            return ax_value
        ax_offset = _stack_offset(ax_value)
        dx_offset = _stack_offset(dx_value)
        if isinstance(ax_offset, int) and isinstance(dx_offset, int) and dx_offset == ax_offset + 2:
            wide = _jcc._stack_slot_expr_8616(codegen, ax_offset, 4)
            if wide is not None:
                return wide
        if isinstance(ax_value, CConstant) and isinstance(dx_value, CConstant):
            low = int(getattr(ax_value, "value", 0) or 0) & 0xFFFF
            high = int(getattr(dx_value, "value", 0) or 0) & 0xFFFF
            value = (high << 16) | low
            if value & 0x80000000:
                value -= 0x100000000
            return CConstant(value, SimTypeLong(True), codegen=codegen)
        return ax_value

    for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and int(getattr(operands[0], "type", -1)) == 1
            and str(insn.reg_name(operands[0].reg)).lower() in {"ax", "dx"}
        ):
            dst_reg = str(insn.reg_name(operands[0].reg)).lower()
            rhs = operands[1]
            value = None
            if int(getattr(rhs, "type", -1)) == 2:
                value = CConstant(
                    _signed_i16_immediate_8616(int(getattr(rhs, "imm", 0) or 0)),
                    SimTypeShort(False),
                    codegen=codegen,
                )
            elif int(getattr(rhs, "type", -1)) == 3:
                mem = rhs.mem
                base = getattr(mem, "base", 0)
                index = getattr(mem, "index", 0)
                if base and str(insn.reg_name(base)).lower() == "bp":
                    value = _jcc._stack_slot_expr_8616(codegen, int(mem.disp), int(getattr(rhs, "size", 0) or 2))
                elif base in {0, None} and index in {0, None}:
                    value = _terminal_direct_global_expr_8616(
                        project,
                        codegen,
                        int(getattr(mem, "disp", 0) or 0),
                        int(getattr(rhs, "size", 0) or 2),
                    )
            if value is not None:
                if dst_reg == "ax":
                    ax_value = value
                elif dst_reg == "dx":
                    dx_value = value
                continue
        if (
            mnemonic in {"add", "sub", "shl"}
            and ax_value is not None
            and len(operands) == 2
            and int(getattr(operands[0], "type", -1)) == 1
            and str(insn.reg_name(operands[0].reg)).lower() == "ax"
            and int(getattr(operands[1], "type", -1)) == 2
        ):
            imm = CConstant(_signed_i16_immediate_8616(int(getattr(operands[1], "imm", 0) or 0)), SimTypeShort(False), codegen=codegen)
            op = {"add": "Add", "sub": "Sub", "shl": "Shl"}[mnemonic]
            ax_value = CBinaryOp(op, ax_value, imm, codegen=codegen)
            continue
        if (
            mnemonic in {"inc", "dec"}
            and ax_value is not None
            and len(operands) == 1
            and int(getattr(operands[0], "type", -1)) == 1
            and str(insn.reg_name(operands[0].reg)).lower() == "ax"
        ):
            one = CConstant(1, SimTypeShort(False), codegen=codegen)
            op = "Add" if mnemonic == "inc" else "Sub"
            ax_value = CBinaryOp(op, ax_value, one, codegen=codegen)
            continue
        if mnemonic in {"jmp", "ljmp"}:
            combined = _combined_return_expr()
            if combined is not None:
                return combined
            next_target = _jcc._branch_target_imm_8616(insn)
            if next_target is None:
                return None
            return _branch_target_return_expr_8616(
                project,
                codegen,
                int(next_target),
                _depth=_depth + 1,
                _seen=_seen,
            )
        if mnemonic in {"ret", "retf", "iret"}:
            return _combined_return_expr()
    return _combined_return_expr()


def _linear_terminal_ax_return_expr_8616(project, codegen, function):
    block_addrs = tuple(sorted(getattr(function, "block_addrs_set", ()) or ()))
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    if debug:
        info = getattr(function, "info", None)
        logging.getLogger(__name__).warning(
            "[missing-ax-return] function=%#x block_addrs=%r info_complexity=%r local_blocks=%d blocks=%d",
            int(getattr(function, "addr", -1) or -1),
            block_addrs,
            (info or {}).get("_inertia_function_complexity") if isinstance(info, dict) else None,
            len(getattr(function, "_local_blocks", {}) or {}),
            len(tuple(getattr(function, "blocks", ()) or ())),
        )
    if not block_addrs:
        return None
    ax_value = None
    dx_value = None
    raw_insns = 0
    classified = 0
    ret_count = 0
    conditional_branches = 0
    prototype = getattr(getattr(codegen, "cfunc", None), "functy", None) or getattr(
        getattr(codegen, "cfunc", None), "prototype", None
    )
    return_type = getattr(prototype, "returnty", None)
    return_bits = getattr(return_type, "size", None)
    allow_al_return = isinstance(return_type, SimTypeChar) or (isinstance(return_bits, int) and return_bits <= 8)

    def _stack_offset(expr) -> int | None:
        if not isinstance(expr, CVariable):
            return None
        variable = getattr(expr, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        offset = getattr(variable, "offset", None)
        return offset if isinstance(offset, int) else None

    def _combined_return_expr():
        if ax_value is None:
            return None
        if dx_value is None:
            return ax_value
        ax_offset = _stack_offset(ax_value)
        dx_offset = _stack_offset(dx_value)
        if isinstance(ax_offset, int) and isinstance(dx_offset, int) and dx_offset == ax_offset + 2:
            wide = _jcc._stack_slot_expr_8616(codegen, ax_offset, 4)
            if wide is not None:
                return wide
        if isinstance(ax_value, CConstant) and isinstance(dx_value, CConstant):
            low = int(getattr(ax_value, "value", 0) or 0) & 0xFFFF
            high = int(getattr(dx_value, "value", 0) or 0) & 0xFFFF
            value = (high << 16) | low
            if value & 0x80000000:
                value -= 0x100000000
            return CConstant(value, SimTypeLong(True), codegen=codegen)
        return ax_value

    def _operand_reg_name(insn, operand) -> str:
        with contextlib.suppress(Exception):
            return str(insn.reg_name(operand.reg)).lower()
        return ""

    def _operand_value_expr(insn, operand, *, size: int):
        if int(getattr(operand, "type", -1)) == 2:
            value = int(getattr(operand, "imm", 0) or 0)
            if size == 1:
                return CConstant(value & 0xFF, SimTypeChar(False), codegen=codegen)
            return CConstant(_signed_i16_immediate_8616(value), SimTypeShort(False), codegen=codegen)
        if int(getattr(operand, "type", -1)) != 3:
            return None
        mem = operand.mem
        if str(insn.reg_name(mem.base)).lower() != "bp":
            return None
        operand_size = int(getattr(operand, "size", 0) or size or 2)
        return _terminal_stack_arg_expr_8616(project, codegen, int(mem.disp), operand_size)

    def _byte_stack_value_expr(insn, operand):
        if int(getattr(operand, "type", -1)) != 3:
            return None
        mem = operand.mem
        if str(insn.reg_name(mem.base)).lower() != "bp":
            return None
        disp = int(mem.disp)
        if disp % 2:
            word = _terminal_stack_arg_expr_8616(project, codegen, disp - 1, 2)
            if word is None:
                return None
            return CBinaryOp(
                "Shr",
                _clone_c_expr_8616(word),
                CConstant(8, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        word = _terminal_stack_arg_expr_8616(project, codegen, disp, 2)
        if word is None:
            return None
        return CBinaryOp(
            "And",
            _clone_c_expr_8616(word),
            CConstant(0xFF, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    def _is_return_epilogue_block(addr: int) -> bool:
        try:
            epilogue_block = project.factory.block(int(addr), opt_level=0)
        except Exception:
            return False
        saw_ret = False
        for epilogue_insn in tuple(getattr(getattr(epilogue_block, "capstone", None), "insns", ()) or ()):
            epilogue_mnemonic = str(getattr(epilogue_insn, "mnemonic", "")).lower()
            epilogue_operands = tuple(getattr(epilogue_insn, "operands", ()) or ())
            if epilogue_mnemonic in {"ret", "retf", "iret"}:
                saw_ret = True
                break
            if epilogue_mnemonic in {"pop", "leave", "nop"}:
                continue
            if (
                epilogue_mnemonic == "mov"
                and len(epilogue_operands) == 2
                and int(getattr(epilogue_operands[0], "type", -1)) == 1
                and int(getattr(epilogue_operands[1], "type", -1)) == 1
                and _operand_reg_name(epilogue_insn, epilogue_operands[0]) == "sp"
                and _operand_reg_name(epilogue_insn, epilogue_operands[1]) == "bp"
            ):
                continue
            return False
        return saw_ret

    for block_addr in block_addrs:
        try:
            block = project.factory.block(int(block_addr), opt_level=0)
        except Exception:
            return None
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            raw_insns += 1
            mnemonic = str(getattr(insn, "mnemonic", "")).lower()
            operands = tuple(getattr(insn, "operands", ()) or ())
            if mnemonic.startswith("j") and mnemonic not in {"jmp", "ljmp"}:
                conditional_branches += 1
                continue
            if mnemonic in {"jmp", "ljmp"}:
                target = _jcc._branch_target_imm_8616(insn)
                if target is None or conditional_branches or not _is_return_epilogue_block(int(target)):
                    return None
                result = _combined_return_expr()
                if result is None:
                    return None
                codegen._inertia_missing_terminal_ax_return_raw_fact_count_8616 = raw_insns
                codegen._inertia_missing_terminal_ax_return_classified_fact_count_8616 = classified
                if debug:
                    logging.getLogger(__name__).warning(
                        "[missing-ax-return] terminal-epilogue-jump target=%#x result=%s raw=%d classified=%d",
                        int(target),
                        _expr_fingerprint(result, project),
                        raw_insns,
                        classified,
                    )
                return result
            if mnemonic in {"call", "lcall"}:
                ax_value = None
                dx_value = None
                cx_value = None
                cl_value = None
                classified += 1
                continue
            if (
                not allow_al_return
                and
                mnemonic == "mov"
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "al"
            ):
                value = _byte_stack_value_expr(insn, operands[1])
                if value is None and allow_al_return:
                    value = _operand_value_expr(insn, operands[1], size=1)
                if value is not None:
                    ax_value = value
                    dx_value = None
                    classified += 1
                    continue
            if (
                mnemonic == "sub"
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and int(getattr(operands[1], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "ah"
                and _operand_reg_name(insn, operands[1]) == "ah"
                and ax_value is not None
            ):
                classified += 1
                continue
            if (
                mnemonic == "mov"
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "cl"
                and int(getattr(operands[1], "type", -1)) == 2
            ):
                cl_value = CConstant(int(getattr(operands[1], "imm", 0) or 0), SimTypeChar(False), codegen=codegen)
                classified += 1
                continue
            if (
                mnemonic == "mov"
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "cx"
            ):
                value = _operand_value_expr(insn, operands[1], size=2)
                if value is not None:
                    cx_value = value
                    classified += 1
                    continue
            if (
                allow_al_return
                and mnemonic == "mov"
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "al"
            ):
                value = _operand_value_expr(insn, operands[1], size=1)
                if value is not None:
                    ax_value = value
                    dx_value = None
                    classified += 1
                    continue
            if (
                mnemonic == "mov"
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) in {"ax", "dx"}
            ):
                dst_reg = _operand_reg_name(insn, operands[0])
                rhs = operands[1]
                value = None
                if int(getattr(rhs, "type", -1)) == 2:
                    value = CConstant(
                        _signed_i16_immediate_8616(int(getattr(rhs, "imm", 0) or 0)),
                        SimTypeShort(False),
                        codegen=codegen,
                    )
                elif int(getattr(rhs, "type", -1)) == 3:
                    mem = rhs.mem
                    base = getattr(mem, "base", 0)
                    index = getattr(mem, "index", 0)
                    if base and str(insn.reg_name(base)).lower() == "bp":
                        value = _jcc._stack_slot_expr_8616(codegen, int(mem.disp), int(getattr(rhs, "size", 0) or 2))
                    elif base in {0, None} and index in {0, None}:
                        value = _terminal_direct_global_expr_8616(
                            project,
                            codegen,
                            int(getattr(mem, "disp", 0) or 0),
                            int(getattr(rhs, "size", 0) or 2),
                        )
                if value is not None:
                    if dst_reg == "ax":
                        ax_value = value
                    elif dst_reg == "dx":
                        dx_value = value
                    classified += 1
                    continue
            if (
                allow_al_return
                and mnemonic in {"add", "sub", "xor"}
                and ax_value is not None
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "al"
            ):
                rhs = _operand_value_expr(insn, operands[1], size=1)
                if rhs is None:
                    return None
                op = {"add": "Add", "sub": "Sub", "xor": "Xor"}[mnemonic]
                ax_value = CBinaryOp(op, _clone_c_expr_8616(ax_value), _clone_c_expr_8616(rhs), codegen=codegen)
                classified += 1
                continue
            if (
                allow_al_return
                and mnemonic == "shl"
                and ax_value is not None
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "al"
                and int(getattr(operands[1], "type", -1)) == 2
            ):
                imm = CConstant(int(getattr(operands[1], "imm", 0) or 0), SimTypeChar(False), codegen=codegen)
                ax_value = CBinaryOp("Shl", _clone_c_expr_8616(ax_value), imm, codegen=codegen)
                classified += 1
                continue
            if (
                mnemonic == "shr"
                and ax_value is not None
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "ax"
                and int(getattr(operands[1], "type", -1)) == 1
                and _operand_reg_name(insn, operands[1]) == "cl"
                and cl_value is not None
            ):
                ax_value = CBinaryOp("Shr", _clone_c_expr_8616(ax_value), _clone_c_expr_8616(cl_value), codegen=codegen)
                classified += 1
                continue
            if (
                mnemonic == "shl"
                and cx_value is not None
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "cx"
                and int(getattr(operands[1], "type", -1)) == 2
            ):
                imm = CConstant(int(getattr(operands[1], "imm", 0) or 0), SimTypeShort(False), codegen=codegen)
                cx_value = CBinaryOp("Shl", _clone_c_expr_8616(cx_value), imm, codegen=codegen)
                classified += 1
                continue
            if (
                mnemonic == "or"
                and ax_value is not None
                and cx_value is not None
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and int(getattr(operands[1], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "ax"
                and _operand_reg_name(insn, operands[1]) == "cx"
            ):
                ax_value = CBinaryOp("Or", _clone_c_expr_8616(ax_value), _clone_c_expr_8616(cx_value), codegen=codegen)
                classified += 1
                continue
            if (
                mnemonic in {"add", "sub"}
                and ax_value is not None
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "ax"
            ):
                rhs = _operand_value_expr(insn, operands[1], size=2)
                if rhs is None:
                    return None
                op = {"add": "Add", "sub": "Sub"}[mnemonic]
                ax_value = CBinaryOp(op, _clone_c_expr_8616(ax_value), _clone_c_expr_8616(rhs), codegen=codegen)
                classified += 1
                continue
            if (
                mnemonic in {"mul", "imul"}
                and ax_value is not None
                and len(operands) == 1
            ):
                rhs = _operand_value_expr(insn, operands[0], size=2)
                if rhs is None:
                    return None
                ax_value = CBinaryOp("Mul", _clone_c_expr_8616(ax_value), _clone_c_expr_8616(rhs), codegen=codegen)
                dx_value = None
                classified += 1
                continue
            if (
                mnemonic in {"add", "sub", "shl"}
                and ax_value is not None
                and len(operands) == 2
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "ax"
                and int(getattr(operands[1], "type", -1)) == 2
            ):
                imm = CConstant(
                    _signed_i16_immediate_8616(int(getattr(operands[1], "imm", 0) or 0)),
                    SimTypeShort(False),
                    codegen=codegen,
                )
                op = {"add": "Add", "sub": "Sub", "shl": "Shl"}[mnemonic]
                ax_value = CBinaryOp(op, _clone_c_expr_8616(ax_value), imm, codegen=codegen)
                classified += 1
                continue
            if (
                mnemonic in {"inc", "dec"}
                and ax_value is not None
                and len(operands) == 1
                and int(getattr(operands[0], "type", -1)) == 1
                and _operand_reg_name(insn, operands[0]) == "ax"
            ):
                one = CConstant(1, SimTypeShort(False), codegen=codegen)
                op = "Add" if mnemonic == "inc" else "Sub"
                ax_value = CBinaryOp(op, _clone_c_expr_8616(ax_value), one, codegen=codegen)
                classified += 1
                continue
            if mnemonic in {"ret", "retf", "iret"}:
                ret_count += 1
                if ret_count > 1 or conditional_branches:
                    if debug:
                        logging.getLogger(__name__).warning(
                            "[missing-ax-return] refused ret_count=%d conditional_branches=%d raw=%d classified=%d",
                            ret_count,
                            conditional_branches,
                            raw_insns,
                            classified,
                        )
                    return None
                codegen._inertia_missing_terminal_ax_return_raw_fact_count_8616 = raw_insns
                codegen._inertia_missing_terminal_ax_return_classified_fact_count_8616 = classified
                result = _combined_return_expr()
                if debug:
                    logging.getLogger(__name__).warning(
                        "[missing-ax-return] result=%s raw=%d classified=%d",
                        _expr_fingerprint(result, project) if result is not None else None,
                        raw_insns,
                        classified,
                    )
                return result
    if debug:
        logging.getLogger(__name__).warning(
            "[missing-ax-return] refused no terminal return raw=%d classified=%d ret_count=%d conditional_branches=%d",
            raw_insns,
            classified,
            ret_count,
            conditional_branches,
        )
    return None


def _next_unconditional_target_after_jcc_8616(project, block_addr: int, jcc_addr: int) -> int | None:
    try:
        block = project.factory.block(int(block_addr), opt_level=0)
    except Exception:
        return None
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    for idx, insn in enumerate(insns):
        if int(getattr(insn, "address", -1)) != int(jcc_addr):
            continue
        if idx + 1 >= len(insns):
            next_addr = int(jcc_addr) + int(getattr(insn, "size", 0) or 0)
            if next_addr <= int(jcc_addr):
                return None
            try:
                next_block = project.factory.block(next_addr, opt_level=0)
            except Exception:
                return None
            next_insns = tuple(getattr(getattr(next_block, "capstone", None), "insns", ()) or ())
            if not next_insns:
                return None
            next_insn = next_insns[0]
            if str(getattr(next_insn, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
                return None
            return _jcc._branch_target_imm_8616(next_insn)
        next_insn = insns[idx + 1]
        if str(getattr(next_insn, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
            return None
        return _jcc._branch_target_imm_8616(next_insn)
    return None


def _linear_function_insns_for_codegen_8616(project, codegen) -> tuple:
    base_insns = tuple(_jcc._function_insns_for_codegen_8616(project, codegen) or ())
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return base_insns
    linear_insns: list[object] = []
    addr = int(func_addr)
    end_addr = addr + 0x800
    while addr < end_addr:
        try:
            block = project.factory.block(addr, num_inst=1, opt_level=0)
        except Exception:
            break
        decoded = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not decoded:
            break
        insn = decoded[0]
        linear_insns.append(insn)
        size = int(getattr(insn, "size", 0) or 0)
        if str(getattr(insn, "mnemonic", "")).lower() in {"ret", "retf", "iret"}:
            break
        if size <= 0:
            break
        addr += size
    by_addr = {int(getattr(insn, "address", 0) or 0): insn for insn in base_insns}
    for insn in linear_insns:
        by_addr[int(getattr(insn, "address", 0) or 0)] = insn
    result = tuple(sorted(by_addr.values(), key=lambda item: int(getattr(item, "address", 0) or 0)))
    if len(result) > len(base_insns):
        try:
            codegen._inertia_jcc_function_insns_8616 = result
        except Exception:
            pass
    return result


def _linear_jcc_block_starts_8616(project, codegen) -> tuple[tuple[int, object], ...]:
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if not insns:
        return ()
    pairs: list[tuple[int, object]] = []
    terminators = {"jmp", "ljmp", "ret", "retf", "iret"}
    for index, insn in enumerate(insns):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
            continue
        block_start = int(getattr(insn, "address", 0) or 0)
        for prev_index in range(index - 1, -1, -1):
            prev = insns[prev_index]
            prev_mnemonic = str(getattr(prev, "mnemonic", "")).lower()
            if prev_mnemonic in terminators or prev_mnemonic.startswith("j") or prev_mnemonic in {"call", "lcall"}:
                break
            block_start = int(getattr(prev, "address", block_start) or block_start)
        pairs.append((block_start, insn))
    return tuple(pairs)


def _condition_branch_return_value_8616(project, cond) -> int | None:
    key = _jcc._condition_tags_8616(cond)
    if not isinstance(key, tuple) or len(key) != 2:
        return None
    jcc_addr, block_addr = key
    if not isinstance(jcc_addr, int) or not isinstance(block_addr, int):
        return None
    try:
        block = project.factory.block(int(block_addr), opt_level=0)
    except Exception:
        return None
    for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        if int(getattr(insn, "address", -1)) != int(jcc_addr):
            continue
        target = _jcc._branch_target_imm_8616(insn)
        if target is None:
            return None
        return _branch_target_return_value_8616(project, target)
    return None


def _ordered_conditional_return_values_8616(project, codegen) -> list[int]:
    values: list[int] = []
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
            continue
        target = _jcc._branch_target_imm_8616(insn)
        if target is None:
            continue
        value = _branch_target_return_value_8616(project, target)
        if value is not None:
            values.append(value)
    return values


def _ordered_conditional_return_pairs_from_cfg_8616(project, codegen) -> list[tuple[object, int]]:
    pairs: list[tuple[object, int]] = []
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    jcc_count = 0
    return_target_count = 0
    decoded_count = 0
    for block_addr, insn in _linear_jcc_block_starts_8616(project, codegen):
        jcc_count += 1
        target = _jcc._branch_target_imm_8616(insn)
        if target is None:
            continue
        value = _branch_target_return_value_8616(project, target)
        if value is None:
            continue
        return_target_count += 1
        decoded = _jcc._translate_cmp_jcc_guard_8616(project, codegen, int(block_addr), int(insn.address))
        if decoded is None:
            continue
        decoded_count += 1
        expr = getattr(decoded, "expr", None)
        if expr is None:
            expr = CBinaryOp(getattr(decoded, "op"), getattr(decoded, "lhs"), getattr(decoded, "rhs"), codegen=codegen)
        pairs.append((expr, int(value)))
    if debug:
        log.warning(
            "[cfg-return-chain] addr=%r jcc=%d return_targets=%d decoded=%d pairs=%d",
            getattr(getattr(codegen, "cfunc", None), "addr", None),
            jcc_count,
            return_target_count,
            decoded_count,
            len(pairs),
        )
    return pairs


def _ordered_conditional_return_expr_pairs_from_cfg_8616(project, codegen) -> list[tuple[object, object, object]]:
    pairs: list[tuple[object, object, object]] = []
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    for block_addr, insn in _linear_jcc_block_starts_8616(project, codegen):
        true_target = _jcc._branch_target_imm_8616(insn)
        false_target = _next_unconditional_target_after_jcc_8616(project, int(block_addr), int(insn.address))
        if debug:
            log.warning(
                "[cfg-return-expr] jcc=%#x block=%#x true=%r false=%r",
                int(getattr(insn, "address", 0) or 0),
                int(block_addr),
                true_target,
                false_target,
            )
        if true_target is None or false_target is None:
            continue
        true_expr = _branch_target_return_expr_8616(project, codegen, true_target)
        false_expr = _branch_target_return_expr_8616(project, codegen, false_target)
        if debug:
            log.warning(
                "[cfg-return-expr] targets true_expr=%r false_expr=%r true_fp=%r false_fp=%r",
                type(true_expr).__name__ if true_expr is not None else None,
                type(false_expr).__name__ if false_expr is not None else None,
                _expr_fingerprint(true_expr, project) if true_expr is not None else None,
                _expr_fingerprint(false_expr, project) if false_expr is not None else None,
            )
        if true_expr is None or false_expr is None:
            continue
        decoded = _jcc._translate_cmp_jcc_guard_8616(project, codegen, int(block_addr), int(insn.address))
        if debug:
            log.warning(
                "[cfg-return-expr] decoded=%s",
                type(decoded).__name__ if decoded is not None else None,
            )
        if decoded is None:
            continue
        cond = getattr(decoded, "expr", None)
        if cond is None:
            cond = CBinaryOp(getattr(decoded, "op"), getattr(decoded, "lhs"), getattr(decoded, "rhs"), codegen=codegen)
        pairs.append((cond, true_expr, false_expr))
    return pairs


def _first_conditional_jcc_8616(block) -> object | None:
    for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic.startswith("j") and mnemonic not in {"jmp", "ljmp"}:
            return insn
    return None


def _selector_function_has_unsafe_effects_8616(project, codegen) -> bool:
    """Return selectors may be rebuilt only when the instruction stream is pure.

    This intentionally does not reason from emitted C.  The gate is based on
    instruction effects: explicit memory stores and non-prologue calls make the
    CFG selector rewrite unsafe because replacing the structured body could drop
    real side effects.
    """
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    previous_insn = None
    seen_branch = False
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic in {"call", "lcall"}:
            target = _jcc._direct_call_target_8616(insn)
            if target is None:
                if debug:
                    log.warning("[cfg-selector-return] unsafe call-indirect addr=%#x", int(insn.address))
                return True
            name, _callee = _jcc._callee_name_for_target_8616(project, target)
            if not _target_is_stack_probe_helper_8616(project, int(target), name):
                prev_operands = tuple(getattr(previous_insn, "operands", ()) or ())
                next_addr = int(getattr(insn, "address", 0) or 0) + int(getattr(insn, "size", 0) or 0)
                stack_probe_rel0 = (
                    not seen_branch
                    and int(target) == next_addr
                    and str(getattr(previous_insn, "mnemonic", "")).lower() == "mov"
                    and len(prev_operands) == 2
                    and int(getattr(prev_operands[0], "type", -1)) == 1
                    and str(previous_insn.reg_name(prev_operands[0].reg)).lower() == "ax"
                    and int(getattr(prev_operands[1], "type", -1)) == 2
                )
                if stack_probe_rel0:
                    previous_insn = insn
                    continue
                if debug:
                    log.warning(
                        "[cfg-selector-return] unsafe call addr=%#x target=%#x name=%s next=%#x prev=%s",
                        int(insn.address),
                        int(target),
                        name,
                        next_addr,
                        str(getattr(previous_insn, "mnemonic", "")),
                    )
                return True
            previous_insn = insn
            continue
        if mnemonic.startswith("j"):
            seen_branch = True
            previous_insn = insn
            continue
        if mnemonic in {"push", "pop", "ret", "retf", "iret", "leave"}:
            previous_insn = insn
            continue
        memory_write_mnemonics = {
            "mov",
            "add",
            "sub",
            "adc",
            "sbb",
            "and",
            "or",
            "xor",
            "inc",
            "dec",
            "neg",
            "not",
            "xchg",
        }
        if mnemonic in memory_write_mnemonics and operands and int(getattr(operands[0], "type", -1)) == 3:
            if debug:
                log.warning(
                    "[cfg-selector-return] unsafe memory-write addr=%#x mnemonic=%s op=%s",
                    int(insn.address),
                    mnemonic,
                    str(getattr(insn, "op_str", "")),
                )
            return True
        if mnemonic.startswith("stos") or mnemonic.startswith("movs"):
            if debug:
                log.warning("[cfg-selector-return] unsafe string-memory addr=%#x mnemonic=%s", int(insn.address), mnemonic)
            return True
        previous_insn = insn
    return False


def _target_is_stack_probe_helper_8616(project, target_addr: int | None, name: str | None = None) -> bool:
    if is_x86_16_stack_probe_name_8616(name):
        return True
    if not isinstance(target_addr, int):
        return False
    candidate_addrs = [int(target_addr)]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        candidate_addrs.append(int(target_addr) + delta)
        rebased = int(target_addr) - delta
        if rebased >= 0:
            candidate_addrs.append(rebased)
    deduped_addrs: list[int] = []
    for addr in candidate_addrs:
        if addr not in deduped_addrs:
            deduped_addrs.append(addr)
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        if candidate_project is None:
            continue
        for addr in deduped_addrs:
            if identify_x86_16_compiler_helper_at_8616(candidate_project, addr) is not None:
                return True
    return False


def _selector_targets_from_32bit_jcc_chain_8616(project, block_addr: int, jcc_insn) -> tuple[int, int] | None:
    true_mid = _jcc._branch_target_imm_8616(jcc_insn)
    false_target = _next_unconditional_target_after_jcc_8616(project, int(block_addr), int(jcc_insn.address))
    if true_mid is None or false_target is None:
        return None
    try:
        mid_block = project.factory.block(int(true_mid), opt_level=0)
    except Exception:
        return None
    jcc2 = _first_conditional_jcc_8616(mid_block)
    if jcc2 is None:
        return None
    low_addr = _jcc._branch_target_imm_8616(jcc2)
    mid_false = _next_unconditional_target_after_jcc_8616(project, int(true_mid), int(jcc2.address))
    if low_addr is None or mid_false is None:
        return None
    try:
        low_block = project.factory.block(int(low_addr), opt_level=0)
    except Exception:
        return None
    jcc3 = _first_conditional_jcc_8616(low_block)
    if jcc3 is None:
        return None
    low_true = _jcc._branch_target_imm_8616(jcc3)
    low_false = _next_unconditional_target_after_jcc_8616(project, int(low_addr), int(jcc3.address))
    if low_true is None or low_false is None:
        return None
    if int(mid_false) == int(low_true) and int(false_target) == int(low_false):
        return int(low_true), int(false_target)
    if int(mid_false) == int(low_false) and int(false_target) == int(low_true):
        return int(low_false), int(false_target)
    return None


def _equality_return_target_from_32bit_jcc_chain_8616(project, block_addr: int, jcc_insn) -> int | None:
    if str(getattr(jcc_insn, "mnemonic", "")).lower() not in {"je", "jz"}:
        return None
    mid_addr = _jcc._branch_target_imm_8616(jcc_insn)
    false_target = _next_unconditional_target_after_jcc_8616(project, int(block_addr), int(jcc_insn.address))
    if mid_addr is None or false_target is None:
        return None
    try:
        mid_block = project.factory.block(int(mid_addr), opt_level=0)
    except Exception:
        return None
    jcc2 = _first_conditional_jcc_8616(mid_block)
    if jcc2 is None or str(getattr(jcc2, "mnemonic", "")).lower() not in {"je", "jz"}:
        return None
    true_target = _jcc._branch_target_imm_8616(jcc2)
    second_false = _next_unconditional_target_after_jcc_8616(project, int(mid_addr), int(jcc2.address))
    if true_target is None or second_false is None:
        return None
    if int(false_target) != int(second_false):
        return None
    return int(true_target)


def _inequality_target_from_32bit_jcc_chain_8616(project, block_addr: int, jcc_insn) -> int | None:
    if str(getattr(jcc_insn, "mnemonic", "")).lower() not in {"je", "jz"}:
        return None
    mid_addr = _jcc._branch_target_imm_8616(jcc_insn)
    false_target = _next_unconditional_target_after_jcc_8616(project, int(block_addr), int(jcc_insn.address))
    if mid_addr is None or false_target is None:
        return None
    try:
        mid_block = project.factory.block(int(mid_addr), opt_level=0)
    except Exception:
        return None
    jcc2 = _first_conditional_jcc_8616(mid_block)
    if jcc2 is None or str(getattr(jcc2, "mnemonic", "")).lower() not in {"jne", "jnz"}:
        return None
    true_target = _jcc._branch_target_imm_8616(jcc2)
    if true_target is None:
        return None
    if int(false_target) != int(true_target):
        return None
    return int(true_target)


def _ordered_32bit_selector_return_expr_pairs_from_cfg_8616(project, codegen) -> list[tuple[object, object, object]]:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return []
    try:
        function = project.kb.functions.function(addr=func_addr, create=False)
    except Exception:
        return []
    if function is None:
        return []
    pairs: list[tuple[object, object, object]] = []
    for block_addr in sorted(int(addr) for addr in getattr(function, "block_addrs_set", set()) or ()):
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            mnemonic = str(getattr(insn, "mnemonic", "")).lower()
            if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
                continue
            targets = _selector_targets_from_32bit_jcc_chain_8616(project, int(block_addr), insn)
            if targets is None:
                continue
            decoded = _jcc._translate_cmp_jcc_guard_8616(project, codegen, int(block_addr), int(insn.address))
            if decoded is None:
                continue
            cond = getattr(decoded, "expr", None)
            if cond is None:
                cond = CBinaryOp(getattr(decoded, "op"), getattr(decoded, "lhs"), getattr(decoded, "rhs"), codegen=codegen)
            true_expr = _branch_target_return_expr_8616(project, codegen, targets[0])
            false_expr = _branch_target_return_expr_8616(project, codegen, targets[1])
            if true_expr is None or false_expr is None:
                continue
            pairs.append((cond, true_expr, false_expr))
    return pairs


def _selector_stack_expr_from_ax_load_8616(project, codegen):
    for insn in _linear_function_insns_for_codegen_8616(project, codegen):
        operands = tuple(getattr(insn, "operands", ()) or ())
        if (
            str(getattr(insn, "mnemonic", "")).lower() == "mov"
            and len(operands) == 2
            and int(getattr(operands[0], "type", -1)) == 1
            and str(insn.reg_name(operands[0].reg)).lower() == "ax"
            and int(getattr(operands[1], "type", -1)) == 3
        ):
            mem = getattr(operands[1], "mem", None)
            if mem is not None and mem.base and str(insn.reg_name(mem.base)).lower() == "bp":
                return _jcc._stack_slot_expr_8616(
                    codegen,
                    int(mem.disp),
                    int(getattr(operands[1], "size", 0) or 2),
                    project=project,
                )
    return None


def _next_linear_jmp_target_8616(insns: tuple, index: int) -> int | None:
    if index + 1 >= len(insns):
        return None
    next_insn = insns[index + 1]
    if str(getattr(next_insn, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
        return None
    return _jcc._branch_target_imm_8616(next_insn)


def _resolve_one_hop_jmp_target_8616(project, target: int | None) -> int | None:
    if target is None:
        return None
    try:
        block = project.factory.block(int(target), opt_level=0)
    except Exception:
        return int(target)
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    if not insns:
        return int(target)
    first = insns[0]
    if str(getattr(first, "mnemonic", "")).lower() in {"jmp", "ljmp"}:
        resolved = _jcc._branch_target_imm_8616(first)
        if resolved is not None:
            return int(resolved)
    return int(target)


def _clone_c_value_for_codegen_tree_8616(value):
    """Clone a structured C node before inserting it into a new C tree.

    The structured code renderer expects expression nodes to have a single
    tree owner. Selector-return materialization can reuse CFG-derived
    expressions in several branches, so clone on insertion to keep the final
    C AST acyclic and deterministic.
    """

    def _is_c_node(obj) -> bool:
        return hasattr(obj, "__slots__") and obj.__class__.__module__.startswith("angr.analyses.decompiler")

    def _clone(obj, memo: dict[int, object]):
        if obj is None:
            return None
        if isinstance(obj, (str, bytes, int, float, bool)):
            return obj
        if isinstance(obj, list):
            return [_clone(item, memo) for item in obj]
        if isinstance(obj, tuple):
            return tuple(_clone(item, memo) for item in obj)
        if isinstance(obj, dict):
            return {_clone(key, memo): _clone(item, memo) for key, item in obj.items()}
        if not _is_c_node(obj):
            return obj
        obj_id = id(obj)
        if obj_id in memo:
            return memo[obj_id]
        cloned = copy.copy(obj)
        memo[obj_id] = cloned
        slot_names: list[str] = []
        for cls in type(obj).__mro__:
            slots = getattr(cls, "__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            slot_names.extend(str(slot) for slot in slots)
        for attr in dict.fromkeys(slot_names):
            if attr == "codegen" or not hasattr(obj, attr):
                continue
            try:
                child = getattr(obj, attr)
            except Exception:
                continue
            cloned_child = _clone(child, memo)
            if cloned_child is not child:
                try:
                    setattr(cloned, attr, cloned_child)
                except Exception:
                    continue
        return cloned

    return _clone(value, {})


def _clone_c_value_preserving_cvariables_8616(value):
    """Clone expression structure while preserving canonical CVariable leaves."""

    def _is_c_node(obj) -> bool:
        return hasattr(obj, "__slots__") and obj.__class__.__module__.startswith("angr.analyses.decompiler")

    def _clone(obj, memo: dict[int, object]):
        if obj is None:
            return None
        if isinstance(obj, CVariable):
            return obj
        if isinstance(obj, (str, bytes, int, float, bool)):
            return obj
        if isinstance(obj, list):
            return [_clone(item, memo) for item in obj]
        if isinstance(obj, tuple):
            return tuple(_clone(item, memo) for item in obj)
        if isinstance(obj, dict):
            return {_clone(key, memo): _clone(item, memo) for key, item in obj.items()}
        if not _is_c_node(obj):
            return obj
        obj_id = id(obj)
        if obj_id in memo:
            return memo[obj_id]
        cloned = copy.copy(obj)
        memo[obj_id] = cloned
        slot_names: list[str] = []
        for cls in type(obj).__mro__:
            slots = getattr(cls, "__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            slot_names.extend(str(slot) for slot in slots)
        for attr in dict.fromkeys(slot_names):
            if attr == "codegen" or not hasattr(obj, attr):
                continue
            try:
                child = getattr(obj, attr)
            except Exception:
                continue
            cloned_child = _clone(child, memo)
            if cloned_child is not child:
                with contextlib.suppress(Exception):
                    setattr(cloned, attr, cloned_child)
        return cloned

    return _clone(value, {})


def _materialize_decrement_switch_return_chain_8616(project, codegen) -> bool:
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    selector = _selector_stack_expr_from_ax_load_8616(project, codegen)
    if selector is None:
        if debug:
            log.warning("[cfg-selector-return] decrement-switch refused missing selector")
        return False
    if _selector_function_has_unsafe_effects_8616(project, codegen):
        if debug:
            log.warning("[cfg-selector-return] decrement-switch refused unsafe effects")
        return False
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    chain: list[object] = []
    for insn in insns:
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic == "or" and len(operands) == 2:
            if all(int(getattr(op, "type", -1)) == 1 and str(insn.reg_name(op.reg)).lower() == "ax" for op in operands):
                chain.append(insn)
                continue
        if mnemonic == "dec" and len(operands) == 1:
            if int(getattr(operands[0], "type", -1)) == 1 and str(insn.reg_name(operands[0].reg)).lower() == "ax":
                chain.append(insn)
    if len(chain) < 2:
        if debug:
            log.warning("[cfg-selector-return] decrement-switch refused chain_len=%d", len(chain))
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}

    def _following_jcc_after(insn, expected: set[str]):
        start = index_by_addr.get(int(getattr(insn, "address", -1)))
        if start is None:
            return None
        if start + 1 >= len(insns):
            return None
        jcc = insns[start + 1]
        mnemonic = str(getattr(jcc, "mnemonic", "")).lower()
        return jcc if mnemonic in expected else None

    def _materialize_sequential_jne_chain() -> bool:
        jccs = [_following_jcc_after(insn, {"jne", "jnz"}) for insn in chain]
        if any(jcc is None for jcc in jccs):
            return False
        assert all(jcc is not None for jcc in jccs)
        case_targets: list[int] = []
        for jcc in jccs:
            jcc_idx = index_by_addr.get(int(getattr(jcc, "address", -1)))
            if jcc_idx is None:
                return False
            target = _resolve_one_hop_jmp_target_8616(project, _next_linear_jmp_target_8616(insns, jcc_idx))
            if target is None:
                return False
            case_targets.append(int(target))
        default_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(jccs[-1]))
        if default_target is None:
            return False
        case_exprs = [_branch_target_return_expr_8616(project, codegen, target) for target in case_targets]
        default_expr = _branch_target_return_expr_8616(project, codegen, int(default_target))
        if default_expr is None or any(expr is None for expr in case_exprs):
            return False

        statements = []
        for case_value, expr in enumerate(case_exprs):
            cond = CBinaryOp(
                "CmpEQ",
                _clone_c_value_for_codegen_tree_8616(selector),
                CConstant(int(case_value), SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
            statements.append(
                CIfElse(
                    [
                        (
                            cond,
                            CStatements(
                                statements=[CReturn(_clone_c_value_for_codegen_tree_8616(expr), codegen=codegen)],
                                codegen=codegen,
                            ),
                        )
                    ],
                    else_node=None,
                    cstyle_ifs=True,
                    codegen=codegen,
                )
            )
        statements.append(CReturn(_clone_c_value_for_codegen_tree_8616(default_expr), codegen=codegen))
        codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
        codegen._inertia_decrement_switch_return_materialized_8616 = True
        codegen._inertia_sequential_decrement_switch_return_materialized_8616 = True
        codegen._inertia_return_expr_chain_materialized_8616 = True
        codegen._inertia_return_selector_materialized_8616 = True
        codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(
            _expr_fingerprint(expr, project) for expr in (*case_exprs, default_expr)
        )
        if debug:
            log.warning("[cfg-selector-return] sequential decrement-switch materialized cases=%d", len(case_exprs))
        return True

    if len(chain) >= 2 and _materialize_sequential_jne_chain():
        return True

    if len(chain) < 4:
        if debug:
            log.warning("[cfg-selector-return] decrement-switch refused chain_len=%d", len(chain))
        return False

    jcc0 = _following_jcc_after(chain[0], {"jne", "jnz"})
    jcc1 = _following_jcc_after(chain[1], {"jge", "jnl"})
    jcc2 = _following_jcc_after(chain[2], {"jg", "jnle"})
    jcc3 = _following_jcc_after(chain[3], {"jne", "jnz"})
    if None in {jcc0, jcc1, jcc2, jcc3}:
        if debug:
            log.warning("[cfg-selector-return] decrement-switch refused jcc shape=%r", [jcc0, jcc1, jcc2, jcc3])
        return False
    target_case0 = _resolve_one_hop_jmp_target_8616(
        project, _next_linear_jmp_target_8616(insns, index_by_addr[int(getattr(jcc0, "address"))])
    )
    target_default_1 = _resolve_one_hop_jmp_target_8616(
        project, _next_linear_jmp_target_8616(insns, index_by_addr[int(getattr(jcc1, "address"))])
    )
    target_case12 = _resolve_one_hop_jmp_target_8616(
        project, _next_linear_jmp_target_8616(insns, index_by_addr[int(getattr(jcc2, "address"))])
    )
    target_case3 = _resolve_one_hop_jmp_target_8616(
        project, _next_linear_jmp_target_8616(insns, index_by_addr[int(getattr(jcc3, "address"))])
    )
    target_default_2 = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(jcc3))
    if None in {target_case0, target_default_1, target_case12, target_case3, target_default_2}:
        if debug:
            log.warning(
                "[cfg-selector-return] decrement-switch refused targets=%r",
                [target_case0, target_default_1, target_case12, target_case3, target_default_2],
            )
        return False
    if int(target_default_1) != int(target_default_2):
        if debug:
            log.warning(
                "[cfg-selector-return] decrement-switch refused default mismatch=%r/%r",
                target_default_1,
                target_default_2,
            )
        return False
    expr_case0 = _branch_target_return_expr_8616(project, codegen, int(target_case0))
    expr_default = _branch_target_return_expr_8616(project, codegen, int(target_default_1))
    expr_case12 = _branch_target_return_expr_8616(project, codegen, int(target_case12))
    expr_case3 = _branch_target_return_expr_8616(project, codegen, int(target_case3))
    if any(expr is None for expr in (expr_case0, expr_default, expr_case12, expr_case3)):
        if debug:
            log.warning(
                "[cfg-selector-return] decrement-switch refused exprs=%r",
                [expr_case0, expr_default, expr_case12, expr_case3],
            )
        return False

    def _cmp(op: str, value: int):
        return CBinaryOp(
            op,
            _clone_c_value_for_codegen_tree_8616(selector),
            CConstant(int(value), SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    ordered = (
        (_cmp("CmpEQ", 0), expr_case0),
        (_cmp("CmpLT", 1), expr_default),
        (_cmp("CmpLE", 2), expr_case12),
        (_cmp("CmpEQ", 3), expr_case3),
    )
    statements = [
        CIfElse(
            [
                (
                    _clone_c_value_for_codegen_tree_8616(cond),
                    CStatements(
                        statements=[CReturn(_clone_c_value_for_codegen_tree_8616(expr), codegen=codegen)],
                        codegen=codegen,
                    ),
                )
            ],
            else_node=None,
            cstyle_ifs=True,
            codegen=codegen,
        )
        for cond, expr in ordered
    ]
    statements.append(CReturn(_clone_c_value_for_codegen_tree_8616(expr_default), codegen=codegen))
    codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
    codegen._inertia_decrement_switch_return_materialized_8616 = True
    codegen._inertia_return_expr_chain_materialized_8616 = True
    codegen._inertia_return_selector_materialized_8616 = True
    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(
        _expr_fingerprint(expr, project) for _cond, expr in ordered
    ) + (_expr_fingerprint(expr_default, project),)
    if debug:
        log.warning("[cfg-selector-return] decrement-switch materialized")
    return True


def _stack_mem_disp_size_8616(insn, operand) -> tuple[int, int] | None:
    if int(getattr(operand, "type", -1)) != 3:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None or not getattr(mem, "base", None):
        return None
    try:
        if str(insn.reg_name(mem.base)).lower() != "bp":
            return None
    except Exception:
        return None
    return (_signed_i16_immediate_8616(int(mem.disp)), int(getattr(operand, "size", 0) or 0))


def _reg_name_from_operand_8616(insn, operand) -> str | None:
    if int(getattr(operand, "type", -1)) != 1:
        return None
    try:
        return str(insn.reg_name(operand.reg)).lower()
    except Exception:
        return None


def _imm_from_operand_8616(operand) -> int | None:
    if int(getattr(operand, "type", -1)) != 2:
        return None
    return int(getattr(operand, "imm", 0) or 0)


def _absolute_mem_disp_size_8616(operand) -> tuple[int, int] | None:
    if int(getattr(operand, "type", -1)) != 3:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    if int(getattr(mem, "base", 0) or 0) != 0 or int(getattr(mem, "index", 0) or 0) != 0:
        return None
    return int(getattr(mem, "disp", 0) or 0), int(getattr(operand, "size", 0) or 0)


def _indexed_mem_disp_size_8616(insn, operand, *, base_reg: str) -> tuple[int, int] | None:
    if int(getattr(operand, "type", -1)) != 3:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None or not getattr(mem, "base", None):
        return None
    try:
        if str(insn.reg_name(mem.base)).lower() != base_reg:
            return None
    except Exception:
        return None
    if int(getattr(mem, "index", 0) or 0) != 0:
        return None
    return int(getattr(mem, "disp", 0) or 0), int(getattr(operand, "size", 0) or 0)


def _cod_source_global_names_for_byte_sum_loop_8616(project, codegen) -> tuple[str | None, str | None]:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return None, None
    try:
        metadata = _calls._cod_metadata_for_function_8616(project, func_addr)
    except Exception:
        metadata = None
    source_lines = tuple(getattr(metadata, "source_lines", ()) or ()) if metadata is not None else ()
    counter_name = None
    table_name = None
    for line in source_lines:
        if not isinstance(line, str):
            continue
        if counter_name is None:
            match = re.search(r"\b[A-Za-z_]\w*\s*=\s*([A-Za-z_]\w*)\s*;", line)
            if match is not None:
                counter_name = match.group(1)
        if table_name is None:
            match = re.search(r"\+=\s*([A-Za-z_]\w*)\s*\[", line)
            if match is not None:
                table_name = match.group(1)
    return counter_name, table_name


def _global_cvar_8616(project, codegen, *, addr: int, size: int, name: str, signed: bool = False):
    cfunc = getattr(codegen, "cfunc", None)
    variable_type = SimTypeChar(signed) if int(size) == 1 else SimTypeShort(signed)
    variable_type = _bind_type_to_project_arch_8616(project, variable_type)
    return CVariable(
        SimMemoryVariable(int(addr), int(size), name=name, region=getattr(cfunc, "addr", None)),
        variable_type=variable_type,
        codegen=codegen,
    )


def _materialize_global_byte_index_sum_loop_8616(project, codegen) -> bool:
    """Recover a word accumulator plus byte global-index loop from instruction evidence.

    Generic MS C shape:
        total = global_word;
        for (i = 0; i < limit; ++i)
            total += global_byte_array[i];
        return total;
    """
    if getattr(codegen, "_inertia_global_byte_sum_loop_materialized_8616", False):
        return False
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if len(insns) < 12:
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}
    stats = getattr(codegen, "_inertia_global_byte_sum_loop_stats_8616", None)
    if not isinstance(stats, dict):
        stats = {"raw_fact_count": 0, "classified_fact_count": 0, "materialized_count": 0, "failure_count": 0}
        codegen._inertia_global_byte_sum_loop_stats_8616 = stats

    for init_idx in range(len(insns) - 8):
        mov_global = insns[init_idx]
        if str(getattr(mov_global, "mnemonic", "")).lower() != "mov":
            continue
        mov_global_ops = tuple(getattr(mov_global, "operands", ()) or ())
        if len(mov_global_ops) != 2 or _reg_name_from_operand_8616(mov_global, mov_global_ops[0]) != "ax":
            continue
        word_global = _absolute_mem_disp_size_8616(mov_global_ops[1])
        if word_global is None or int(word_global[1]) != 2:
            continue

        mov_total = insns[init_idx + 1]
        if str(getattr(mov_total, "mnemonic", "")).lower() != "mov":
            continue
        mov_total_ops = tuple(getattr(mov_total, "operands", ()) or ())
        if len(mov_total_ops) != 2 or _reg_name_from_operand_8616(mov_total, mov_total_ops[1]) != "ax":
            continue
        total_slot = _stack_mem_disp_size_8616(mov_total, mov_total_ops[0])
        if total_slot is None or int(total_slot[0]) >= 0:
            continue

        mov_i_zero = insns[init_idx + 2]
        i_disp = _match_stack_zero_init_8616(mov_i_zero)
        if i_disp is None or int(i_disp) >= 0 or int(i_disp) == int(total_slot[0]):
            continue
        stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + 1

        jmp_to_cmp = insns[init_idx + 3]
        if str(getattr(jmp_to_cmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue
        cmp_addr = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(jmp_to_cmp))
        cmp_idx = index_by_addr.get(int(cmp_addr)) if cmp_addr is not None else None
        if cmp_idx is None or cmp_idx + 2 >= len(insns):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        inc_idx = init_idx + 4
        if not _match_stack_inc_8616(insns[inc_idx], int(i_disp)):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue
        cmp_i = insns[cmp_idx]
        cmp_ops = tuple(getattr(cmp_i, "operands", ()) or ())
        cmp_slot = _stack_mem_disp_size_8616(cmp_i, cmp_ops[0]) if len(cmp_ops) == 2 else None
        limit = _imm_from_operand_8616(cmp_ops[1]) if len(cmp_ops) == 2 else None
        if (
            str(getattr(cmp_i, "mnemonic", "")).lower() != "cmp"
            or cmp_slot is None
            or int(cmp_slot[0]) != int(i_disp)
            or limit is None
        ):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue
        jl = insns[cmp_idx + 1]
        if str(getattr(jl, "mnemonic", "")).lower() not in {"jl", "jnge"}:
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue
        body_addr = _jcc._branch_target_imm_8616(jl)
        exit_addr = _resolve_one_hop_jmp_target_8616(project, _next_linear_jmp_target_8616(insns, cmp_idx + 1))
        body_idx = index_by_addr.get(int(body_addr)) if body_addr is not None else None
        if body_idx is None or body_idx + 4 >= len(insns) or exit_addr is None:
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        mov_bx = insns[body_idx]
        mov_bx_ops = tuple(getattr(mov_bx, "operands", ()) or ())
        if (
            str(getattr(mov_bx, "mnemonic", "")).lower() != "mov"
            or len(mov_bx_ops) != 2
            or _reg_name_from_operand_8616(mov_bx, mov_bx_ops[0]) != "bx"
        ):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue
        bx_slot = _stack_mem_disp_size_8616(mov_bx, mov_bx_ops[1])
        if bx_slot is None or int(bx_slot[0]) != int(i_disp):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        mov_al = insns[body_idx + 1]
        mov_al_ops = tuple(getattr(mov_al, "operands", ()) or ())
        if (
            str(getattr(mov_al, "mnemonic", "")).lower() != "mov"
            or len(mov_al_ops) != 2
            or _reg_name_from_operand_8616(mov_al, mov_al_ops[0]) != "al"
        ):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue
        byte_global = _indexed_mem_disp_size_8616(mov_al, mov_al_ops[1], base_reg="bx")
        if byte_global is None or int(byte_global[1]) != 1:
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        clear_ah = insns[body_idx + 2]
        clear_ops = tuple(getattr(clear_ah, "operands", ()) or ())
        if (
            str(getattr(clear_ah, "mnemonic", "")).lower() not in {"sub", "xor"}
            or len(clear_ops) != 2
            or _reg_name_from_operand_8616(clear_ah, clear_ops[0]) != "ah"
            or _reg_name_from_operand_8616(clear_ah, clear_ops[1]) != "ah"
        ):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        add_total = insns[body_idx + 3]
        add_ops = tuple(getattr(add_total, "operands", ()) or ())
        add_slot = _stack_mem_disp_size_8616(add_total, add_ops[0]) if len(add_ops) == 2 else None
        if (
            str(getattr(add_total, "mnemonic", "")).lower() != "add"
            or add_slot is None
            or int(add_slot[0]) != int(total_slot[0])
            or _reg_name_from_operand_8616(add_total, add_ops[1]) != "ax"
        ):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        back_jmp = insns[body_idx + 4]
        back_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(back_jmp))
        if str(getattr(back_jmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"} or int(back_target or -1) != int(
            getattr(insns[inc_idx], "address", -1)
        ):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        exit_expr = _branch_target_return_expr_8616(project, codegen, int(exit_addr))
        total_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(total_slot[0]), 2)
        i_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(i_disp), 2)
        if exit_expr is None or total_expr is None or i_expr is None:
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue
        if _expr_fingerprint(exit_expr, project) != _expr_fingerprint(total_expr, project):
            stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1
            continue

        stats["classified_fact_count"] = int(stats.get("classified_fact_count", 0) or 0) + 1
        counter_name, table_name = _cod_source_global_names_for_byte_sum_loop_8616(project, codegen)
        counter_name = counter_name or f"global_word_{int(word_global[0]) & 0xFFFF:04x}"
        table_name = table_name or f"global_u8_{int(byte_global[0]) & 0xFFFF:04x}"
        counter_expr = _global_cvar_8616(project, codegen, addr=int(word_global[0]), size=2, name=counter_name, signed=True)
        table_expr = _global_cvar_8616(project, codegen, addr=int(byte_global[0]), size=1, name=table_name, signed=False)
        indexed_byte = CIndexedVariable(
            table_expr,
            i_expr,
            variable_type=_bind_type_to_project_arch_8616(project, SimTypeChar(False)),
            codegen=codegen,
        )
        init_total = CAssignment(
            total_expr,
            counter_expr,
            codegen=codegen,
        )
        init_i = CAssignment(
            i_expr,
            CConstant(0, SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        )
        condition = CBinaryOp(
            "CmpLT",
            i_expr,
            CConstant(int(limit), SimTypeShort(True), codegen=codegen),
            codegen=codegen,
        )
        iterator = _inc_assignment_8616(i_expr, codegen)
        body = CStatements(
            statements=[
                CAssignment(
                    total_expr,
                    CBinaryOp(
                        "Add",
                        total_expr,
                        indexed_byte,
                        codegen=codegen,
                    ),
                    codegen=codegen,
                )
            ],
            codegen=codegen,
        )
        codegen.cfunc.statements = CStatements(
            statements=[
                init_total,
                CForLoop(init_i, condition, iterator, body, codegen=codegen),
                CReturn(total_expr, codegen=codegen),
            ],
            codegen=codegen,
        )
        codegen._inertia_global_byte_sum_loop_materialized_8616 = True
        codegen._inertia_global_byte_sum_loop_evidence_8616 = {
            "total_disp": int(total_slot[0]),
            "index_disp": int(i_disp),
            "word_global": int(word_global[0]),
            "byte_global": int(byte_global[0]),
            "limit": int(limit),
            "counter_name": counter_name,
            "table_name": table_name,
        }
        codegen._inertia_global_declaration_specs_8616 = tuple(
            dict.fromkeys(
                tuple(getattr(codegen, "_inertia_global_declaration_specs_8616", ()) or ())
                + (
                    ("short", counter_name, None),
                    ("unsigned char", table_name, int(limit)),
                )
            )
        )
        stats["materialized_count"] = int(stats.get("materialized_count", 0) or 0) + 1
        return True
    return False


def _materialize_stack_arg_accumulator_loop_8616(project, codegen) -> bool:
    """Recover a stack-slot accumulator loop from CFG/instruction evidence.

    Pattern:
        local = 0;
    loop:
        if (arg <= 0) return local;
        local += arg;
        --arg;
        if (arg & mask) continue;
        local += const;
        goto loop;

    This is a generic C89 backward-edge shape emitted by MS C for goto/while
    accumulators. It uses only instruction, CFG, and stack-slot evidence.
    """
    if getattr(codegen, "_inertia_stack_arg_accumulator_loop_materialized_8616", False):
        return False
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if len(insns) < 10:
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}

    for cmp_idx, cmp_insn in enumerate(insns[:-2]):
        if str(getattr(cmp_insn, "mnemonic", "")).lower() != "cmp":
            continue
        cmp_ops = tuple(getattr(cmp_insn, "operands", ()) or ())
        if len(cmp_ops) != 2:
            continue
        arg_slot = _stack_mem_disp_size_8616(cmp_insn, cmp_ops[0])
        if arg_slot is None or _imm_from_operand_8616(cmp_ops[1]) != 0:
            continue
        arg_disp, _arg_size = arg_slot
        if arg_disp <= 0:
            continue
        if any(str(getattr(insn, "mnemonic", "")).lower() in {"call", "lcall"} for insn in insns[cmp_idx:]):
            continue
        jcc = insns[cmp_idx + 1]
        if str(getattr(jcc, "mnemonic", "")).lower() not in {"jle", "jng"}:
            continue
        loop_start = int(getattr(cmp_insn, "address", -1))
        exit_target = _jcc._branch_target_imm_8616(jcc)
        body_target = _resolve_one_hop_jmp_target_8616(project, _next_linear_jmp_target_8616(insns, cmp_idx + 1))
        if exit_target is None or body_target is None:
            continue
        try:
            body_block = project.factory.block(int(body_target), opt_level=0)
        except Exception:
            continue
        body_insns = tuple(getattr(getattr(body_block, "capstone", None), "insns", ()) or ())
        if len(body_insns) < 5:
            continue
        mov_arg, add_arg, dec_arg, test_arg, continue_jcc = body_insns[:5]
        if str(getattr(mov_arg, "mnemonic", "")).lower() != "mov":
            continue
        mov_ops = tuple(getattr(mov_arg, "operands", ()) or ())
        if len(mov_ops) != 2 or _reg_name_from_operand_8616(mov_arg, mov_ops[0]) != "ax":
            continue
        mov_arg_slot = _stack_mem_disp_size_8616(mov_arg, mov_ops[1])
        if mov_arg_slot is None or int(mov_arg_slot[0]) != int(arg_disp):
            continue
        if str(getattr(add_arg, "mnemonic", "")).lower() != "add":
            continue
        add_ops = tuple(getattr(add_arg, "operands", ()) or ())
        if len(add_ops) != 2 or _reg_name_from_operand_8616(add_arg, add_ops[1]) != "ax":
            continue
        local_slot = _stack_mem_disp_size_8616(add_arg, add_ops[0])
        if local_slot is None:
            continue
        local_disp, _local_size = local_slot
        if local_disp >= 0:
            continue
        if str(getattr(dec_arg, "mnemonic", "")).lower() != "dec":
            continue
        dec_ops = tuple(getattr(dec_arg, "operands", ()) or ())
        if len(dec_ops) != 1:
            continue
        dec_slot = _stack_mem_disp_size_8616(dec_arg, dec_ops[0])
        if dec_slot is None or int(dec_slot[0]) != int(arg_disp):
            continue
        if str(getattr(test_arg, "mnemonic", "")).lower() != "test":
            continue
        test_ops = tuple(getattr(test_arg, "operands", ()) or ())
        if len(test_ops) != 2:
            continue
        test_slot = _stack_mem_disp_size_8616(test_arg, test_ops[0])
        test_mask = _imm_from_operand_8616(test_ops[1])
        if test_slot is None or int(test_slot[0]) != int(arg_disp) or test_mask is None:
            continue
        if str(getattr(continue_jcc, "mnemonic", "")).lower() not in {"jne", "jnz"}:
            continue
        continue_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(continue_jcc))
        if continue_target is None or int(continue_target) != loop_start:
            continue
        continue_idx = index_by_addr.get(int(getattr(continue_jcc, "address", -1)))
        add_const_target = _resolve_one_hop_jmp_target_8616(project, _next_linear_jmp_target_8616(insns, continue_idx))
        if add_const_target is None:
            continue
        try:
            add_const_block = project.factory.block(int(add_const_target), opt_level=0)
        except Exception:
            continue
        add_const_insns = tuple(getattr(getattr(add_const_block, "capstone", None), "insns", ()) or ())
        if len(add_const_insns) < 2:
            continue
        add_const, back_jmp = add_const_insns[:2]
        if str(getattr(add_const, "mnemonic", "")).lower() != "add":
            continue
        add_const_ops = tuple(getattr(add_const, "operands", ()) or ())
        if len(add_const_ops) != 2:
            continue
        add_const_slot = _stack_mem_disp_size_8616(add_const, add_const_ops[0])
        add_const_value = _imm_from_operand_8616(add_const_ops[1])
        if add_const_slot is None or int(add_const_slot[0]) != int(local_disp) or add_const_value is None:
            continue
        if str(getattr(back_jmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
            continue
        back_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(back_jmp))
        if back_target is None or int(back_target) != loop_start:
            continue
        initialized = False
        for init_insn in insns[:cmp_idx]:
            if str(getattr(init_insn, "mnemonic", "")).lower() != "mov":
                continue
            init_ops = tuple(getattr(init_insn, "operands", ()) or ())
            if len(init_ops) != 2:
                continue
            init_slot = _stack_mem_disp_size_8616(init_insn, init_ops[0])
            if init_slot is not None and int(init_slot[0]) == int(local_disp) and _imm_from_operand_8616(init_ops[1]) == 0:
                initialized = True
                break
        if not initialized:
            continue
        exit_expr = _branch_target_return_expr_8616(project, codegen, int(exit_target))
        local_expr = _jcc._stack_slot_expr_8616(codegen, int(local_disp), 2)
        arg_expr = _jcc._stack_slot_expr_8616(codegen, int(arg_disp), 2)
        if exit_expr is None or local_expr is None or arg_expr is None:
            continue
        if _expr_fingerprint(exit_expr, project) != _expr_fingerprint(local_expr, project):
            continue
        local0 = _clone_c_value_for_codegen_tree_8616(local_expr)
        arg0 = _clone_c_value_for_codegen_tree_8616(arg_expr)
        zero = CConstant(0, SimTypeShort(False), codegen=codegen)
        one = CConstant(1, SimTypeShort(False), codegen=codegen)
        mask = CConstant(int(test_mask), SimTypeShort(False), codegen=codegen)
        add_value = CConstant(int(add_const_value), SimTypeShort(False), codegen=codegen)
        loop_body = CStatements(
            statements=[
                CIfElse(
                    [
                        (
                            CBinaryOp(
                                "CmpLE",
                                _clone_c_value_for_codegen_tree_8616(arg_expr),
                                CConstant(0, SimTypeShort(False), codegen=codegen),
                                codegen=codegen,
                            ),
                            CStatements(
                                statements=[CReturn(_clone_c_value_for_codegen_tree_8616(local_expr), codegen=codegen)],
                                codegen=codegen,
                            ),
                        )
                    ],
                    else_node=None,
                    cstyle_ifs=True,
                    codegen=codegen,
                ),
                CAssignment(
                    _clone_c_value_for_codegen_tree_8616(local_expr),
                    CBinaryOp(
                        "Add",
                        _clone_c_value_for_codegen_tree_8616(local_expr),
                        _clone_c_value_for_codegen_tree_8616(arg_expr),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                CAssignment(
                    _clone_c_value_for_codegen_tree_8616(arg_expr),
                    CBinaryOp(
                        "Sub",
                        _clone_c_value_for_codegen_tree_8616(arg_expr),
                        one,
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                CIfElse(
                    [
                        (
                            CBinaryOp(
                                "CmpNE",
                                CBinaryOp(
                                    "And",
                                    _clone_c_value_for_codegen_tree_8616(arg_expr),
                                    mask,
                                    codegen=codegen,
                                ),
                                CConstant(0, SimTypeShort(False), codegen=codegen),
                                codegen=codegen,
                            ),
                            CStatements(statements=[CContinue(codegen=codegen)], codegen=codegen),
                        )
                    ],
                    else_node=None,
                    cstyle_ifs=True,
                    codegen=codegen,
                ),
                CAssignment(
                    _clone_c_value_for_codegen_tree_8616(local_expr),
                    CBinaryOp(
                        "Add",
                        _clone_c_value_for_codegen_tree_8616(local_expr),
                        add_value,
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        )
        statements = [
            CAssignment(local0, zero, codegen=codegen),
            CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen), loop_body, codegen=codegen),
        ]
        codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
        codegen._inertia_stack_arg_accumulator_loop_materialized_8616 = True
        codegen._inertia_stack_arg_accumulator_loop_stack_slots_8616 = {
            "arg_disp": int(arg_disp),
            "local_disp": int(local_disp),
            "test_mask": int(test_mask),
            "add_const": int(add_const_value),
        }
        return True
    return False


def _block_insns_8616(project, addr: int) -> tuple:
    try:
        block = project.factory.block(int(addr), opt_level=0)
    except Exception:
        return ()
    return tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())


def _match_stack_zero_init_8616(insn) -> int | None:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return None
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _imm_from_operand_8616(operands[1]) != 0:
        return None
    slot = _stack_mem_disp_size_8616(insn, operands[0])
    return int(slot[0]) if slot is not None else None


def _match_stack_inc_8616(insn, disp: int) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "inc":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 1:
        return False
    slot = _stack_mem_disp_size_8616(insn, operands[0])
    return slot is not None and int(slot[0]) == int(disp)


def _match_mov_ax_stack_8616(insn, disp: int) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[0]) != "ax":
        return False
    slot = _stack_mem_disp_size_8616(insn, operands[1])
    return slot is not None and int(slot[0]) == int(disp)


def _match_cmp_stack_ax_8616(insn, disp: int) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "cmp":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[1]) != "ax":
        return False
    slot = _stack_mem_disp_size_8616(insn, operands[0])
    return slot is not None and int(slot[0]) == int(disp)


def _mem_base_index_size_8616(insn, operand) -> tuple[str | None, str | None, int, int] | None:
    if int(getattr(operand, "type", -1)) != 3:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    base = str(insn.reg_name(mem.base)).lower() if getattr(mem, "base", 0) else None
    index = str(insn.reg_name(mem.index)).lower() if getattr(mem, "index", 0) else None
    size = int(getattr(operand, "size", 0) or 0)
    return base, index, int(getattr(mem, "disp", 0) or 0), size


def _match_stack_mov_to_reg_8616(insn, reg_name: str, disp: int, *, size: int = 2) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[0]) != reg_name:
        return False
    slot = _stack_mem_disp_size_8616(insn, operands[1])
    return slot is not None and int(slot[0]) == int(disp) and int(slot[1]) == int(size)


def _match_indexed_reg_store_8616(insn, *, base_reg: str, index_reg: str, src_reg: str, size: int) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[1]) != src_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[0])
    if mem is None:
        return False
    base, index, disp, mem_size = mem
    return disp == 0 and int(mem_size) == int(size) and {base, index} == {base_reg, index_reg}


def _match_indexed_reg_load_8616(
    insn,
    *,
    dst_reg: str,
    base_reg: str,
    index_reg: str,
    size: int,
    disp: int = 0,
) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[0]) != dst_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[1])
    if mem is None:
        return False
    base, index, mem_disp, mem_size = mem
    return int(mem_disp) == int(disp) and int(mem_size) == int(size) and {base, index} == {base_reg, index_reg}


def _match_cmp_indexed_reg_8616(insn, *, base_reg: str, index_reg: str, rhs_reg: str, size: int, disp: int = 0) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "cmp":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[1]) != rhs_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[0])
    if mem is None:
        return False
    base, index, mem_disp, mem_size = mem
    return int(mem_disp) == int(disp) and int(mem_size) == int(size) and {base, index} == {base_reg, index_reg}


def _match_reg_indirect_load_8616(insn, *, dst_reg: str, base_reg: str, size: int, disp: int = 0) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[0]) != dst_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[1])
    if mem is None:
        return False
    base, index, mem_disp, mem_size = mem
    return base == base_reg and index is None and int(mem_disp) == int(disp) and int(mem_size) == int(size)


def _match_reg_indirect_store_8616(insn, *, base_reg: str, src_reg: str, size: int, disp: int = 0) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[1]) != src_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[0])
    if mem is None:
        return False
    base, index, mem_disp, mem_size = mem
    return base == base_reg and index is None and int(mem_disp) == int(disp) and int(mem_size) == int(size)


def _stack_expr_8616(codegen, disp: int, size: int = 2):
    return _jcc._stack_slot_expr_8616(codegen, int(disp), int(size) or 2)


def _bind_type_to_project_arch_8616(project, type_):
    arch = getattr(project, "arch", None)
    if arch is None or type_ is None or not hasattr(type_, "with_arch"):
        return type_
    try:
        return type_.with_arch(arch)
    except Exception:
        return type_


def _word_type_for_project_8616(project):
    return _bind_type_to_project_arch_8616(project, SimTypeShort(False))


def _signed_word_type_for_project_8616(project):
    return _bind_type_to_project_arch_8616(project, SimTypeShort(True))


def _void_type_for_project_8616(project):
    return _bind_type_to_project_arch_8616(project, SimTypeBottom(label="void"))


def _pointer_type_for_project_8616(project, pointee_size: int, *, signed: bool = False):
    pointee = SimTypeChar(signed) if int(pointee_size) == 1 else SimTypeShort(signed)
    return _bind_type_to_project_arch_8616(
        project,
        _SimTypeNearPointer16_8616(_bind_type_to_project_arch_8616(project, pointee)),
    )


def _type_size_bytes_for_stack_arg_8616(project, type_, default: int = 2) -> int:
    if isinstance(type_, SimTypePointer) and getattr(getattr(project, "arch", None), "name", None) == "86_16":
        return 2
    bits = getattr(type_, "size", None)
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return max(1, int(default) if isinstance(default, int) else 2)


def _stack_alias_name_from_optional_cod_8616(project, codegen, disp: int) -> str | None:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return None
    try:
        metadata = _calls._cod_metadata_for_function_8616(project, func_addr)
    except Exception:
        metadata = None
    stack_aliases = getattr(metadata, "stack_aliases", None)
    if not isinstance(stack_aliases, dict):
        return None
    alias = stack_aliases.get(int(disp))
    if not isinstance(alias, str):
        alias = stack_aliases.get(int(disp) + 1)
    return alias if isinstance(alias, str) and alias else None


def _fallback_stack_arg_name_8616(disp: int) -> str:
    if int(disp) >= 4:
        return f"arg_{max(((int(disp) - 4) // 2) + 1, 1)}"
    return _stack_object_name(int(disp))


def _iter_stack_cvars_for_cfunc_8616(cfunc):
    yielded: set[int] = set()
    for expr in tuple(getattr(cfunc, "arg_list", ()) or ()):
        if isinstance(expr, CVariable) and id(expr) not in yielded:
            yielded.add(id(expr))
            yield expr
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for expr in variables_in_use.values():
            if isinstance(expr, CVariable) and id(expr) not in yielded:
                yielded.add(id(expr))
                yield expr
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        for entries in unified.values():
            for item in entries or ():
                expr = item[0] if isinstance(item, tuple) and item else None
                if isinstance(expr, CVariable) and id(expr) not in yielded:
                    yielded.add(id(expr))
                    yield expr
    root = getattr(cfunc, "statements", None)
    if root is not None:
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, CVariable) and id(node) not in yielded:
                yielded.add(id(node))
                yield node


def _canonical_stack_cvar_at_offset_8616(cfunc, offset: int):
    best = None
    best_score = None
    for cvar in _iter_stack_cvars_for_cfunc_8616(cfunc):
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "offset", None) != int(offset):
            continue
        name = getattr(variable, "name", None) or getattr(cvar, "name", None)
        name_score = 2
        if isinstance(name, str) and name.startswith(("stack_bp_", "s_", "arg_", "local_")):
            name_score = 1
        if isinstance(name, str) and name and not name.startswith(("stack_bp_", "s_")):
            name_score += 1
        score = (name_score, int(getattr(variable, "size", 0) or 0))
        if best_score is None or score > best_score:
            best = cvar
            best_score = score
    return best


def _install_canonical_stack_cvar_8616(cfunc, cvar, variable_type=None) -> None:
    variable = getattr(cvar, "variable", None)
    if not isinstance(cvar, CVariable) or not isinstance(variable, SimStackVariable):
        return
    offset = getattr(variable, "offset", None)
    if not isinstance(offset, int):
        return
    if variable_type is None:
        variable_type = getattr(cvar, "variable_type", None)
    variables = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables, dict):
        for existing_variable in tuple(variables.keys()):
            if not isinstance(existing_variable, SimStackVariable):
                continue
            if getattr(existing_variable, "offset", None) == offset and existing_variable is not variable:
                del variables[existing_variable]
        variables[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        for existing_variable in tuple(unified.keys()):
            if not isinstance(existing_variable, SimStackVariable):
                continue
            if getattr(existing_variable, "offset", None) == offset and existing_variable is not variable:
                del unified[existing_variable]
        unified[variable] = {(cvar, variable_type)}


def _ensure_typed_stack_arg_expr_8616(project, codegen, disp: int, arg_type, *, fallback_name: str | None = None):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None or int(disp) < 4:
        return None
    disp = int(disp)
    word_type = _word_type_for_project_8616(project)
    arg_name = (
        _stack_alias_name_from_optional_cod_8616(project, codegen, disp)
        or fallback_name
        or _fallback_stack_arg_name_8616(disp)
    )

    prototype = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    if prototype is None:
        func_addr = getattr(cfunc, "addr", None)
        func = project.kb.functions.function(addr=func_addr, create=False) if isinstance(func_addr, int) else None
        prototype = getattr(func, "prototype", None) if func is not None else None
    if prototype is None:
        prototype = _bind_type_to_project_arch_8616(
            project,
            SimTypeFunction([], word_type, arg_names=(), variadic=False),
        )

    arg_type = _bind_type_to_project_arch_8616(project, arg_type)
    args = list(getattr(prototype, "args", ()) or ())
    arg_names = list(getattr(prototype, "arg_names", None) or ())
    cursor = 4
    target_index = None
    for idx, existing_type in enumerate(args):
        if cursor == disp:
            target_index = idx
            break
        cursor += max(2, _type_size_bytes_for_stack_arg_8616(project, existing_type))
    while target_index is None and cursor <= disp and disp <= 0x40:
        new_type = arg_type if cursor == disp else word_type
        args.append(new_type)
        arg_names.append(arg_name if cursor == disp else _fallback_stack_arg_name_8616(cursor))
        if cursor == disp:
            target_index = len(args) - 1
            break
        cursor += max(2, _type_size_bytes_for_stack_arg_8616(project, new_type))
    if target_index is None:
        return None

    args[target_index] = arg_type
    while len(arg_names) < len(args):
        arg_names.append(_fallback_stack_arg_name_8616(4 + len(arg_names) * 2))
    arg_names[target_index] = arg_name

    desired_args: list[CVariable] = []
    func_addr = getattr(cfunc, "addr", None)
    cursor = 4
    target_cvar = None
    for idx, current_type in enumerate(args):
        width = max(2, _type_size_bytes_for_stack_arg_8616(project, current_type))
        name = arg_names[idx] if idx < len(arg_names) and isinstance(arg_names[idx], str) and arg_names[idx] else None
        if name is None:
            name = _fallback_stack_arg_name_8616(cursor)
        cvar = _canonical_stack_cvar_at_offset_8616(cfunc, cursor)
        variable = getattr(cvar, "variable", None) if cvar is not None else None
        if not isinstance(cvar, CVariable) or not isinstance(variable, SimStackVariable):
            variable = SimStackVariable(cursor, width, base="bp", name=name, region=func_addr)
            cvar = CVariable(variable, variable_type=current_type, codegen=codegen)
        else:
            variable.name = name
            variable.size = width
            cvar.variable_type = current_type
        _install_canonical_stack_cvar_8616(cfunc, cvar, current_type)
        desired_args.append(cvar)
        if cursor == disp:
            target_cvar = cvar
        cursor += width

    cfunc.arg_list = desired_args
    normalized_arg_names = tuple(
        name if isinstance(name, str) and name else _fallback_stack_arg_name_8616(4 + idx * 2)
        for idx, name in enumerate(arg_names[: len(args)])
    )
    new_prototype = SimTypeFunction(
        args,
        getattr(prototype, "returnty", word_type),
        arg_names=normalized_arg_names,
        variadic=getattr(prototype, "variadic", False),
    )
    new_prototype = _bind_type_to_project_arch_8616(project, new_prototype)
    cfunc.functy = new_prototype
    with contextlib.suppress(Exception):
        cfunc.prototype = new_prototype
    func_addr = getattr(cfunc, "addr", None)
    func = project.kb.functions.function(addr=func_addr, create=False) if isinstance(func_addr, int) else None
    if func is not None:
        func.prototype = new_prototype
        func.is_prototype_guessed = False

    refresh = getattr(cfunc, "refresh", None)
    if callable(refresh):
        with contextlib.suppress(Exception):
            refresh()
    return target_cvar


def _ensure_pointer_stack_arg_expr_8616(project, codegen, disp: int, *, pointee_size: int, fallback_name: str | None = None):
    """Materialize BP-positive slots proven by register-indirect memory use as pointer args."""
    pointer_type = _pointer_type_for_project_8616(project, int(pointee_size))
    return _ensure_typed_stack_arg_expr_8616(project, codegen, disp, pointer_type, fallback_name=fallback_name)


def _named_stack_expr_from_evidence_8616(project, codegen, disp: int, size: int = 2):
    expr = _stack_expr_8616(codegen, int(disp), int(size) or 2)
    alias_name = _stack_alias_name_from_optional_cod_8616(project, codegen, int(disp))
    variable = getattr(expr, "variable", None)
    if isinstance(alias_name, str) and isinstance(variable, SimStackVariable):
        variable.name = alias_name
    if isinstance(expr, CVariable):
        if getattr(expr, "variable_type", None) is None:
            expr.variable_type = _word_type_for_project_8616(project)
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is not None:
            _install_canonical_stack_cvar_8616(cfunc, expr, getattr(expr, "variable_type", None))
    return expr


def _inc_assignment_8616(expr, codegen):
    return CAssignment(
        _clone_c_value_for_codegen_tree_8616(expr),
        CBinaryOp(
            "Add",
            _clone_c_value_for_codegen_tree_8616(expr),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _match_reg_shl1_8616(insn, reg_name: str) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "shl":
        return False
    operands = tuple(getattr(insn, "operands", ()) or ())
    return (
        len(operands) == 2
        and _reg_name_from_operand_8616(insn, operands[0]) == reg_name
        and _imm_from_operand_8616(operands[1]) == 1
    )


def _const_short_8616(codegen, value: int, *, signed: bool = False):
    return CConstant(int(value), SimTypeShort(signed), codegen=codegen)


def _mul_expr_8616(lhs, rhs, codegen):
    return CBinaryOp(
        "Mul",
        _clone_c_value_preserving_cvariables_8616(lhs),
        _clone_c_value_preserving_cvariables_8616(rhs),
        codegen=codegen,
    )


def _add_expr_8616(lhs, rhs, codegen):
    return CBinaryOp(
        "Add",
        _clone_c_value_preserving_cvariables_8616(lhs),
        _clone_c_value_preserving_cvariables_8616(rhs),
        codegen=codegen,
    )


def _inc_assignment_preserving_cvariables_8616(expr, codegen):
    return CAssignment(
        _clone_c_value_preserving_cvariables_8616(expr),
        CBinaryOp(
            "Add",
            _clone_c_value_preserving_cvariables_8616(expr),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _deref_expr_8616(expr, codegen):
    project = getattr(codegen, "project", None)
    word_type = _word_type_for_project_8616(project)
    return CIndexedVariable(
        _clone_c_value_for_codegen_tree_8616(expr),
        CConstant(0, word_type, codegen=codegen),
        variable_type=word_type,
        codegen=codegen,
    )


def _indexed_word_pointer_expr_8616(base_expr, index_expr, codegen, *, variable_type=None):
    return CIndexedVariable(
        _clone_c_value_preserving_cvariables_8616(base_expr),
        _clone_c_value_preserving_cvariables_8616(index_expr),
        variable_type=variable_type,
        codegen=codegen,
    )


def _mark_codegen_signature_authoritative_8616(project, codegen, reason: str) -> None:
    setattr(codegen, "_inertia_codegen_signature_authoritative_8616", reason)
    for obj in (
        getattr(codegen, "_func", None),
        getattr(codegen, "function", None),
        getattr(getattr(codegen, "cfunc", None), "function", None),
    ):
        if obj is not None:
            setattr(obj, "_inertia_codegen_signature_authoritative_8616", reason)
    cfunc_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if isinstance(cfunc_addr, int):
        with contextlib.suppress(Exception):
            func = project.kb.functions.function(addr=cfunc_addr, create=False)
            if func is not None:
                setattr(func, "_inertia_codegen_signature_authoritative_8616", reason)


def _set_codegen_return_type_8616(project, codegen, return_type) -> None:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return
    prototype = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    arg_list = list(getattr(cfunc, "arg_list", ()) or ())
    if prototype is not None:
        args = list(getattr(prototype, "args", ()) or ())
        arg_names = list(getattr(prototype, "arg_names", None) or ())
    else:
        args = [getattr(arg, "variable_type", None) or _word_type_for_project_8616(project) for arg in arg_list]
        arg_names = []
    if arg_list and len(args) != len(arg_list):
        args = [getattr(arg, "variable_type", None) or _word_type_for_project_8616(project) for arg in arg_list]
    if arg_list and len(arg_names) != len(arg_list):
        arg_names = [
            getattr(getattr(arg, "variable", None), "name", None) or getattr(arg, "name", None) or f"arg_{idx}"
            for idx, arg in enumerate(arg_list)
        ]
    new_prototype = SimTypeFunction(
        args,
        _bind_type_to_project_arch_8616(project, return_type),
        arg_names=tuple(arg_names),
        variadic=getattr(prototype, "variadic", False) if prototype is not None else False,
    )
    new_prototype = _bind_type_to_project_arch_8616(project, new_prototype)
    cfunc.functy = new_prototype
    with contextlib.suppress(Exception):
        cfunc.prototype = new_prototype
    func_addr = getattr(cfunc, "addr", None)
    func = project.kb.functions.function(addr=func_addr, create=False) if isinstance(func_addr, int) else None
    if func is not None:
        func.prototype = new_prototype
        func.is_prototype_guessed = False


def _materialize_byte_pointer_fill_loop_8616(project, codegen, insns: tuple, index_by_addr: dict[int, int]) -> bool:
    for init_idx in range(len(insns) - 10):
        i_disp = _match_stack_zero_init_8616(insns[init_idx])
        if i_disp is None or i_disp >= 0:
            continue
        first_jmp = insns[init_idx + 1]
        if str(getattr(first_jmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
            continue
        inc_addr = int(getattr(insns[init_idx + 2], "address", -1))
        if not _match_stack_inc_8616(insns[init_idx + 2], i_disp):
            continue
        cond_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(first_jmp))
        if cond_target is None or int(cond_target) != int(getattr(insns[init_idx + 3], "address", -1)):
            continue
        if not _match_stack_mov_to_reg_8616(insns[init_idx + 3], "ax", 8):
            continue
        if not _match_cmp_stack_ax_8616(insns[init_idx + 4], i_disp):
            continue
        jcc = insns[init_idx + 5]
        if str(getattr(jcc, "mnemonic", "")).lower() not in {"jl", "jnge"}:
            continue
        body_target = _jcc._branch_target_imm_8616(jcc)
        exit_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(jcc, "address", -1)), -1)),
        )
        if body_target is None or exit_target is None:
            continue
        body = _block_insns_8616(project, int(body_target))
        if len(body) < 5:
            continue
        if not _match_stack_mov_to_reg_8616(body[0], "al", 6, size=1):
            continue
        if not _match_stack_mov_to_reg_8616(body[1], "bx", i_disp):
            continue
        if not _match_stack_mov_to_reg_8616(body[2], "si", 4):
            continue
        if not _match_indexed_reg_store_8616(body[3], base_reg="bx", index_reg="si", src_reg="al", size=1):
            continue
        if _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(body[4])) != inc_addr:
            continue
        dst_expr = _ensure_pointer_stack_arg_expr_8616(
            project,
            codegen,
            4,
            pointee_size=1,
            fallback_name="dst",
        ) or _stack_expr_8616(codegen, 4, 2)
        value_expr = _stack_expr_8616(codegen, 6, 1)
        count_expr = _stack_expr_8616(codegen, 8, 2)
        i_expr = _stack_expr_8616(codegen, int(i_disp), 2)
        if any(expr is None for expr in (dst_expr, value_expr, count_expr, i_expr)):
            continue
        indexed = CIndexedVariable(
            _clone_c_value_for_codegen_tree_8616(dst_expr),
            _clone_c_value_for_codegen_tree_8616(i_expr),
            codegen=codegen,
        )
        body_node = CStatements(
            statements=[
                CAssignment(indexed, _clone_c_value_for_codegen_tree_8616(value_expr), codegen=codegen),
                _inc_assignment_8616(i_expr, codegen),
            ],
            codegen=codegen,
        )
        codegen.cfunc.statements = CStatements(
            statements=[
                CAssignment(
                    _clone_c_value_for_codegen_tree_8616(i_expr),
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CWhileLoop(
                    CBinaryOp(
                        "CmpLT",
                        _clone_c_value_for_codegen_tree_8616(i_expr),
                        _clone_c_value_for_codegen_tree_8616(count_expr),
                        codegen=codegen,
                    ),
                    body_node,
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        )
        codegen._inertia_pointer_memory_materialized_8616 = "byte_fill_loop"
        return True
    return False


def _materialize_word_pointer_sum_loop_8616(project, codegen, insns: tuple, index_by_addr: dict[int, int]) -> bool:
    for init_idx in range(len(insns) - 14):
        total_disp = _match_stack_zero_init_8616(insns[init_idx])
        i_disp = _match_stack_zero_init_8616(insns[init_idx + 1])
        if total_disp is None or i_disp is None or total_disp >= 0 or i_disp >= 0 or total_disp == i_disp:
            continue
        first_jmp = insns[init_idx + 2]
        if str(getattr(first_jmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
            continue
        inc_addr = int(getattr(insns[init_idx + 3], "address", -1))
        if not _match_stack_inc_8616(insns[init_idx + 3], i_disp):
            continue
        cond_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(first_jmp))
        if cond_target is None or int(cond_target) != int(getattr(insns[init_idx + 4], "address", -1)):
            continue
        if not _match_stack_mov_to_reg_8616(insns[init_idx + 4], "ax", 6):
            continue
        if not _match_cmp_stack_ax_8616(insns[init_idx + 5], i_disp):
            continue
        jcc = insns[init_idx + 6]
        if str(getattr(jcc, "mnemonic", "")).lower() not in {"jl", "jnge"}:
            continue
        body_target = _jcc._branch_target_imm_8616(jcc)
        exit_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(jcc, "address", -1)), -1)),
        )
        if body_target is None or exit_target is None:
            continue
        exit_expr = _branch_target_return_expr_8616(project, codegen, int(exit_target))
        total_expr = _stack_expr_8616(codegen, int(total_disp), 2)
        if exit_expr is None or total_expr is None or _expr_fingerprint(exit_expr, project) != _expr_fingerprint(total_expr, project):
            continue
        body = _block_insns_8616(project, int(body_target))
        if len(body) < 6:
            continue
        if not _match_stack_mov_to_reg_8616(body[0], "bx", i_disp):
            continue
        if str(getattr(body[1], "mnemonic", "")).lower() != "shl":
            continue
        shl_ops = tuple(getattr(body[1], "operands", ()) or ())
        if len(shl_ops) != 2 or _reg_name_from_operand_8616(body[1], shl_ops[0]) != "bx" or _imm_from_operand_8616(shl_ops[1]) != 1:
            continue
        if not _match_stack_mov_to_reg_8616(body[2], "si", 4):
            continue
        if not _match_indexed_reg_load_8616(body[3], dst_reg="ax", base_reg="bx", index_reg="si", size=2):
            continue
        if str(getattr(body[4], "mnemonic", "")).lower() != "add":
            continue
        add_ops = tuple(getattr(body[4], "operands", ()) or ())
        add_slot = _stack_mem_disp_size_8616(body[4], add_ops[0]) if len(add_ops) == 2 else None
        if add_slot is None or int(add_slot[0]) != int(total_disp) or _reg_name_from_operand_8616(body[4], add_ops[1]) != "ax":
            continue
        if _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(body[5])) != inc_addr:
            continue
        src_expr = _ensure_pointer_stack_arg_expr_8616(
            project,
            codegen,
            4,
            pointee_size=2,
            fallback_name="src",
        ) or _stack_expr_8616(codegen, 4, 2)
        count_expr = _stack_expr_8616(codegen, 6, 2)
        i_expr = _stack_expr_8616(codegen, int(i_disp), 2)
        if any(expr is None for expr in (src_expr, count_expr, i_expr)):
            continue
        indexed = CIndexedVariable(
            _clone_c_value_for_codegen_tree_8616(src_expr),
            _clone_c_value_for_codegen_tree_8616(i_expr),
            codegen=codegen,
        )
        body_node = CStatements(
            statements=[
                CAssignment(
                    _clone_c_value_for_codegen_tree_8616(total_expr),
                    CBinaryOp(
                        "Add",
                        _clone_c_value_for_codegen_tree_8616(total_expr),
                        indexed,
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                _inc_assignment_8616(i_expr, codegen),
            ],
            codegen=codegen,
        )
        codegen.cfunc.statements = CStatements(
            statements=[
                CAssignment(
                    _clone_c_value_for_codegen_tree_8616(total_expr),
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    _clone_c_value_for_codegen_tree_8616(i_expr),
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CWhileLoop(
                    CBinaryOp(
                        "CmpLT",
                        _clone_c_value_for_codegen_tree_8616(i_expr),
                        _clone_c_value_for_codegen_tree_8616(count_expr),
                        codegen=codegen,
                    ),
                    body_node,
                    codegen=codegen,
                ),
                CReturn(_clone_c_value_for_codegen_tree_8616(total_expr), codegen=codegen),
            ],
            codegen=codegen,
        )
        codegen._inertia_pointer_memory_materialized_8616 = "word_sum_loop"
        return True
    return False


def _materialize_word_pair_pointer_accumulation_loop_8616(
    project,
    codegen,
    insns: tuple,
    index_by_addr: dict[int, int],
) -> bool:
    """Recover loops that accumulate two adjacent word fields from a pointer array.

    Generic MS C shape:
        total = 0;
        for (i = 0; i < count; ++i) {
            total += words[i * 2] * 2;
            total += words[i * 2 + 1];
        }

    This intentionally materializes a word-pointer view, not a struct.  Struct
    naming remains a later typed-object recovery problem.
    """
    stats = {
        "raw_fact_count": 0,
        "classified_fact_count": 0,
        "materialized_count": 0,
        "failure_count": 0,
    }
    codegen._inertia_word_pair_pointer_accumulation_stats_8616 = stats

    for init_idx in range(len(insns) - 18):
        total_disp = _match_stack_zero_init_8616(insns[init_idx])
        i_disp = _match_stack_zero_init_8616(insns[init_idx + 1])
        if total_disp is None or i_disp is None or total_disp >= 0 or i_disp >= 0 or total_disp == i_disp:
            continue
        stats["raw_fact_count"] += 1

        first_jmp = insns[init_idx + 2]
        if str(getattr(first_jmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
            stats["failure_count"] += 1
            continue
        inc_addr = int(getattr(insns[init_idx + 3], "address", -1))
        if not _match_stack_inc_8616(insns[init_idx + 3], i_disp):
            stats["failure_count"] += 1
            continue
        cond_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(first_jmp))
        if cond_target is None or int(cond_target) != int(getattr(insns[init_idx + 4], "address", -1)):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(insns[init_idx + 4], "ax", 6):
            stats["failure_count"] += 1
            continue
        if not _match_cmp_stack_ax_8616(insns[init_idx + 5], i_disp):
            stats["failure_count"] += 1
            continue
        jcc = insns[init_idx + 6]
        if str(getattr(jcc, "mnemonic", "")).lower() not in {"jl", "jnge"}:
            stats["failure_count"] += 1
            continue
        body_target = _jcc._branch_target_imm_8616(jcc)
        exit_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(jcc, "address", -1)), -1)),
        )
        if body_target is None or exit_target is None:
            stats["failure_count"] += 1
            continue

        exit_expr = _branch_target_return_expr_8616(project, codegen, int(exit_target))
        total_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(total_disp), 2)
        if exit_expr is None or total_expr is None or _expr_fingerprint(exit_expr, project) != _expr_fingerprint(total_expr, project):
            stats["failure_count"] += 1
            continue

        body = _block_insns_8616(project, int(body_target))
        if len(body) < 14:
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(body[0], "bx", i_disp):
            stats["failure_count"] += 1
            continue
        if not (_match_reg_shl1_8616(body[1], "bx") and _match_reg_shl1_8616(body[2], "bx")):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(body[3], "si", 4):
            stats["failure_count"] += 1
            continue
        if not _match_indexed_reg_load_8616(body[4], dst_reg="ax", base_reg="bx", index_reg="si", size=2):
            stats["failure_count"] += 1
            continue
        if not _match_reg_shl1_8616(body[5], "ax"):
            stats["failure_count"] += 1
            continue
        add_left_ops = tuple(getattr(body[6], "operands", ()) or ())
        add_left_slot = _stack_mem_disp_size_8616(body[6], add_left_ops[0]) if len(add_left_ops) == 2 else None
        if (
            str(getattr(body[6], "mnemonic", "")).lower() != "add"
            or add_left_slot is None
            or int(add_left_slot[0]) != int(total_disp)
            or _reg_name_from_operand_8616(body[6], add_left_ops[1]) != "ax"
        ):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(body[7], "si", i_disp):
            stats["failure_count"] += 1
            continue
        if not (_match_reg_shl1_8616(body[8], "si") and _match_reg_shl1_8616(body[9], "si")):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(body[10], "bx", 4):
            stats["failure_count"] += 1
            continue
        if not _match_indexed_reg_load_8616(body[11], dst_reg="ax", base_reg="bx", index_reg="si", size=2, disp=2):
            stats["failure_count"] += 1
            continue
        add_right_ops = tuple(getattr(body[12], "operands", ()) or ())
        add_right_slot = _stack_mem_disp_size_8616(body[12], add_right_ops[0]) if len(add_right_ops) == 2 else None
        if (
            str(getattr(body[12], "mnemonic", "")).lower() != "add"
            or add_right_slot is None
            or int(add_right_slot[0]) != int(total_disp)
            or _reg_name_from_operand_8616(body[12], add_right_ops[1]) != "ax"
        ):
            stats["failure_count"] += 1
            continue
        if _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(body[13])) != inc_addr:
            stats["failure_count"] += 1
            continue

        pairs_expr = _ensure_pointer_stack_arg_expr_8616(
            project,
            codegen,
            4,
            pointee_size=2,
            fallback_name="pairs",
        ) or _stack_expr_8616(codegen, 4, 2)
        count_expr = _ensure_typed_stack_arg_expr_8616(
            project,
            codegen,
            6,
            _word_type_for_project_8616(project),
            fallback_name="count",
        ) or _stack_expr_8616(codegen, 6, 2)
        i_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(i_disp), 2)
        if any(expr is None for expr in (pairs_expr, count_expr, i_expr)):
            stats["failure_count"] += 1
            continue

        stats["classified_fact_count"] += 1
        word_type = _word_type_for_project_8616(project)
        word_index = _mul_expr_8616(i_expr, _const_short_8616(codegen, 2), codegen)
        next_word_index = _add_expr_8616(word_index, _const_short_8616(codegen, 1), codegen)
        left_word = _indexed_word_pointer_expr_8616(pairs_expr, word_index, codegen, variable_type=word_type)
        right_word = _indexed_word_pointer_expr_8616(pairs_expr, next_word_index, codegen, variable_type=word_type)
        left_twice = _mul_expr_8616(left_word, _const_short_8616(codegen, 2), codegen)
        pair_total = _add_expr_8616(left_twice, right_word, codegen)
        body_node = CStatements(
            statements=[
                CAssignment(
                    _clone_c_value_preserving_cvariables_8616(total_expr),
                    _add_expr_8616(total_expr, pair_total, codegen),
                    codegen=codegen,
                ),
                _inc_assignment_preserving_cvariables_8616(i_expr, codegen),
            ],
            codegen=codegen,
        )
        codegen.cfunc.statements = CStatements(
            statements=[
                CAssignment(
                    _clone_c_value_preserving_cvariables_8616(total_expr),
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    _clone_c_value_preserving_cvariables_8616(i_expr),
                    CConstant(0, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                CWhileLoop(
                    CBinaryOp(
                        "CmpLT",
                        _clone_c_value_preserving_cvariables_8616(i_expr),
                        _clone_c_value_preserving_cvariables_8616(count_expr),
                        codegen=codegen,
                    ),
                    body_node,
                    codegen=codegen,
                ),
                CReturn(_clone_c_value_preserving_cvariables_8616(total_expr), codegen=codegen),
            ],
            codegen=codegen,
        )
        stats["materialized_count"] += 1
        codegen._inertia_pointer_memory_materialized_8616 = "word_pair_accumulation_loop"
        _mark_codegen_signature_authoritative_8616(project, codegen, "word_pair_pointer_accumulation_loop")
        return True
    return False


def _materialize_word_pointer_first_gt_loop_8616(project, codegen, insns: tuple, index_by_addr: dict[int, int]) -> bool:
    """Recover signed word-pointer first-greater-than search loops."""
    stats = {
        "raw_fact_count": 0,
        "classified_fact_count": 0,
        "materialized_count": 0,
        "failure_count": 0,
    }
    codegen._inertia_word_pointer_first_gt_stats_8616 = stats

    signed_word = _signed_word_type_for_project_8616(project)
    for init_idx in range(len(insns) - 6):
        i_disp = _match_stack_zero_init_8616(insns[init_idx])
        if i_disp is None or i_disp >= 0:
            continue
        stats["raw_fact_count"] += 1
        cond_addr = int(getattr(insns[init_idx + 1], "address", -1))
        if not _match_stack_mov_to_reg_8616(insns[init_idx + 1], "ax", i_disp):
            stats["failure_count"] += 1
            continue
        if not _match_cmp_stack_ax_8616(insns[init_idx + 2], 6):
            stats["failure_count"] += 1
            continue
        count_jcc = insns[init_idx + 3]
        if str(getattr(count_jcc, "mnemonic", "")).lower() not in {"jg", "jnle"}:
            stats["failure_count"] += 1
            continue
        body_target = _jcc._branch_target_imm_8616(count_jcc)
        exit_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(count_jcc, "address", -1)), -1)),
        )
        if body_target is None or exit_target is None:
            stats["failure_count"] += 1
            continue

        body = _block_insns_8616(project, int(body_target))
        if len(body) < 6:
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(body[0], "bx", i_disp):
            stats["failure_count"] += 1
            continue
        if not _match_reg_shl1_8616(body[1], "bx"):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(body[2], "si", 4):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(body[3], "ax", 8):
            stats["failure_count"] += 1
            continue
        if not _match_cmp_indexed_reg_8616(body[4], base_reg="bx", index_reg="si", rhs_reg="ax", size=2):
            stats["failure_count"] += 1
            continue
        value_jcc = body[5]
        if str(getattr(value_jcc, "mnemonic", "")).lower() not in {"jg", "jnle"}:
            stats["failure_count"] += 1
            continue
        return_i_target = _jcc._branch_target_imm_8616(value_jcc)
        inc_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(value_jcc, "address", -1)), -1)),
        )
        if return_i_target is None or inc_target is None:
            stats["failure_count"] += 1
            continue

        inc_block = _block_insns_8616(project, int(inc_target))
        if len(inc_block) < 2 or not _match_stack_inc_8616(inc_block[0], i_disp):
            stats["failure_count"] += 1
            continue
        if _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(inc_block[1])) != cond_addr:
            stats["failure_count"] += 1
            continue

        i_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(i_disp), 2)
        values_expr = _ensure_typed_stack_arg_expr_8616(
            project,
            codegen,
            4,
            _pointer_type_for_project_8616(project, 2, signed=True),
            fallback_name="values",
        ) or _stack_expr_8616(codegen, 4, 2)
        count_expr = _ensure_typed_stack_arg_expr_8616(project, codegen, 6, signed_word, fallback_name="count") or _stack_expr_8616(
            codegen, 6, 2
        )
        threshold_expr = _ensure_typed_stack_arg_expr_8616(
            project,
            codegen,
            8,
            signed_word,
            fallback_name="threshold",
        ) or _stack_expr_8616(codegen, 8, 2)
        if any(expr is None for expr in (i_expr, values_expr, count_expr, threshold_expr)):
            stats["failure_count"] += 1
            continue
        if isinstance(i_expr, CVariable):
            i_expr.variable_type = signed_word
            _install_canonical_stack_cvar_8616(codegen.cfunc, i_expr, signed_word)

        return_i_expr = _branch_target_return_expr_8616(project, codegen, int(return_i_target))
        return_minus_one_expr = _branch_target_return_expr_8616(project, codegen, int(exit_target))
        if return_i_expr is None or _expr_fingerprint(return_i_expr, project) != _expr_fingerprint(i_expr, project):
            stats["failure_count"] += 1
            continue
        minus_one = CConstant(-1, signed_word, codegen=codegen)
        if return_minus_one_expr is None or _expr_fingerprint(return_minus_one_expr, project) != _expr_fingerprint(minus_one, project):
            stats["failure_count"] += 1
            continue

        stats["classified_fact_count"] += 1
        indexed_value = _indexed_word_pointer_expr_8616(values_expr, i_expr, codegen, variable_type=signed_word)
        if_body = CStatements(
            statements=[CReturn(_clone_c_value_preserving_cvariables_8616(i_expr), codegen=codegen)],
            codegen=codegen,
        )
        loop_body = CStatements(
            statements=[
                CIfElse(
                    [
                        (
                            CBinaryOp(
                                "CmpGT",
                                _clone_c_value_preserving_cvariables_8616(indexed_value),
                                _clone_c_value_preserving_cvariables_8616(threshold_expr),
                                codegen=codegen,
                            ),
                            if_body,
                        )
                    ],
                    else_node=None,
                    cstyle_ifs=True,
                    codegen=codegen,
                ),
                _inc_assignment_preserving_cvariables_8616(i_expr, codegen),
            ],
            codegen=codegen,
        )
        codegen.cfunc.statements = CStatements(
            statements=[
                CAssignment(
                    _clone_c_value_preserving_cvariables_8616(i_expr),
                    CConstant(0, signed_word, codegen=codegen),
                    codegen=codegen,
                ),
                CWhileLoop(
                    CBinaryOp(
                        "CmpLT",
                        _clone_c_value_preserving_cvariables_8616(i_expr),
                        _clone_c_value_preserving_cvariables_8616(count_expr),
                        codegen=codegen,
                    ),
                    loop_body,
                    codegen=codegen,
                ),
                CReturn(minus_one, codegen=codegen),
            ],
            codegen=codegen,
        )
        _set_codegen_return_type_8616(project, codegen, signed_word)
        stats["materialized_count"] += 1
        codegen._inertia_pointer_memory_materialized_8616 = "word_pointer_first_gt_loop"
        _mark_codegen_signature_authoritative_8616(project, codegen, "word_pointer_first_gt_loop")
        return True
    return False


def _materialize_word_pointer_rotate3_8616(project, codegen, insns: tuple, _index_by_addr: dict[int, int]) -> bool:
    stats = {
        "raw_fact_count": 0,
        "classified_fact_count": 0,
        "materialized_count": 0,
        "failure_count": 0,
    }
    codegen._inertia_word_pointer_rotate3_stats_8616 = stats

    for idx in range(max(0, len(insns) - 13)):
        if not _match_stack_mov_to_reg_8616(insns[idx], "bx", 4):
            continue
        stats["raw_fact_count"] += 1
        if not _match_reg_indirect_load_8616(insns[idx + 1], dst_reg="ax", base_reg="bx", size=2):
            stats["failure_count"] += 1
            continue
        tmp_ops = tuple(getattr(insns[idx + 2], "operands", ()) or ())
        tmp_slot = _stack_mem_disp_size_8616(insns[idx + 2], tmp_ops[0]) if len(tmp_ops) == 2 else None
        if str(getattr(insns[idx + 2], "mnemonic", "")).lower() != "mov" or tmp_slot is None:
            stats["failure_count"] += 1
            continue
        tmp_disp = int(tmp_slot[0])
        if tmp_disp >= 0 or _reg_name_from_operand_8616(insns[idx + 2], tmp_ops[1]) != "ax":
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 3], "bx", 4):
            stats["failure_count"] += 1
            continue
        if not _match_reg_indirect_load_8616(insns[idx + 4], dst_reg="ax", base_reg="bx", size=2, disp=2):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 5], "bx", 4):
            stats["failure_count"] += 1
            continue
        if not _match_reg_indirect_store_8616(insns[idx + 6], base_reg="bx", src_reg="ax", size=2):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 7], "bx", 4):
            stats["failure_count"] += 1
            continue
        if not _match_reg_indirect_load_8616(insns[idx + 8], dst_reg="ax", base_reg="bx", size=2, disp=4):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 9], "bx", 4):
            stats["failure_count"] += 1
            continue
        if not _match_reg_indirect_store_8616(insns[idx + 10], base_reg="bx", src_reg="ax", size=2, disp=2):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 11], "ax", tmp_disp):
            stats["failure_count"] += 1
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 12], "bx", 4):
            stats["failure_count"] += 1
            continue
        if not _match_reg_indirect_store_8616(insns[idx + 13], base_reg="bx", src_reg="ax", size=2, disp=4):
            stats["failure_count"] += 1
            continue

        values_expr = _ensure_pointer_stack_arg_expr_8616(
            project,
            codegen,
            4,
            pointee_size=2,
            fallback_name="values",
        ) or _stack_expr_8616(codegen, 4, 2)
        tmp_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(tmp_disp), 2)
        if any(expr is None for expr in (values_expr, tmp_expr)):
            stats["failure_count"] += 1
            continue

        stats["classified_fact_count"] += 1
        word_type = _word_type_for_project_8616(project)
        value_0 = _indexed_word_pointer_expr_8616(values_expr, _const_short_8616(codegen, 0), codegen, variable_type=word_type)
        value_1 = _indexed_word_pointer_expr_8616(values_expr, _const_short_8616(codegen, 1), codegen, variable_type=word_type)
        value_2 = _indexed_word_pointer_expr_8616(values_expr, _const_short_8616(codegen, 2), codegen, variable_type=word_type)
        codegen.cfunc.statements = CStatements(
            statements=[
                CAssignment(
                    _clone_c_value_preserving_cvariables_8616(tmp_expr),
                    _clone_c_value_preserving_cvariables_8616(value_0),
                    codegen=codegen,
                ),
                CAssignment(
                    _clone_c_value_preserving_cvariables_8616(value_0),
                    _clone_c_value_preserving_cvariables_8616(value_1),
                    codegen=codegen,
                ),
                CAssignment(
                    _clone_c_value_preserving_cvariables_8616(value_1),
                    _clone_c_value_preserving_cvariables_8616(value_2),
                    codegen=codegen,
                ),
                CAssignment(
                    _clone_c_value_preserving_cvariables_8616(value_2),
                    _clone_c_value_preserving_cvariables_8616(tmp_expr),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        )
        _set_codegen_return_type_8616(project, codegen, _void_type_for_project_8616(project))
        stats["materialized_count"] += 1
        codegen._inertia_pointer_memory_materialized_8616 = "word_pointer_rotate3"
        _mark_codegen_signature_authoritative_8616(project, codegen, "word_pointer_rotate3")
        return True
    return False


def _materialize_pointer_swap_8616(project, codegen, insns: tuple, _index_by_addr: dict[int, int]) -> bool:
    debug_pointer_memory = os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") == "1"
    for idx in range(max(0, len(insns) - 9)):
        if not _match_stack_mov_to_reg_8616(insns[idx], "bx", 4):
            continue
        if not _match_reg_indirect_load_8616(insns[idx + 1], dst_reg="ax", base_reg="bx", size=2):
            continue
        tmp_slot = _stack_mem_disp_size_8616(insns[idx + 2], tuple(getattr(insns[idx + 2], "operands", ()) or ())[0])
        if str(getattr(insns[idx + 2], "mnemonic", "")).lower() != "mov" or tmp_slot is None:
            continue
        tmp_disp = int(tmp_slot[0])
        if tmp_disp >= 0:
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 3], "bx", 6):
            continue
        if not _match_reg_indirect_load_8616(insns[idx + 4], dst_reg="ax", base_reg="bx", size=2):
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 5], "bx", 4):
            continue
        if not _match_reg_indirect_store_8616(insns[idx + 6], base_reg="bx", src_reg="ax", size=2):
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 7], "ax", tmp_disp):
            continue
        if not _match_stack_mov_to_reg_8616(insns[idx + 8], "bx", 6):
            continue
        if not _match_reg_indirect_store_8616(insns[idx + 9], base_reg="bx", src_reg="ax", size=2):
            continue
        left_expr = _ensure_pointer_stack_arg_expr_8616(
            project,
            codegen,
            4,
            pointee_size=2,
            fallback_name="left",
        ) or _stack_expr_8616(codegen, 4, 2)
        right_expr = _ensure_pointer_stack_arg_expr_8616(
            project,
            codegen,
            6,
            pointee_size=2,
            fallback_name="right",
        ) or _stack_expr_8616(codegen, 6, 2)
        tmp_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(tmp_disp), 2)
        if any(expr is None for expr in (left_expr, right_expr, tmp_expr)):
            continue
        if debug_pointer_memory:
            logging.getLogger(__name__).warning(
                "[pointer-memory] materialize pointer_swap function=%#x idx=%d tmp=%r left=%r right=%r",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                idx,
                tmp_disp,
                getattr(getattr(left_expr, "variable", None), "name", None),
                getattr(getattr(right_expr, "variable", None), "name", None),
            )
        codegen.cfunc.statements = CStatements(
            statements=[
                CAssignment(
                    _clone_c_value_for_codegen_tree_8616(tmp_expr),
                    _deref_expr_8616(left_expr, codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    _deref_expr_8616(left_expr, codegen),
                    _deref_expr_8616(right_expr, codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    _deref_expr_8616(right_expr, codegen),
                    _clone_c_value_for_codegen_tree_8616(tmp_expr),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        )
        codegen._inertia_pointer_memory_materialized_8616 = "pointer_swap"
        return True
    return False


def _materialize_pointer_memory_idioms_8616(project, codegen) -> bool:
    """Recover near-pointer C memory idioms from instruction and stack-slot evidence."""
    debug_pointer_memory = os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") == "1"
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if debug_pointer_memory:
        logging.getLogger(__name__).warning(
            "[pointer-memory] enter function=%#x codegen=%#x marker=%r insns=%d",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            id(codegen),
            getattr(codegen, "_inertia_pointer_memory_materialized_8616", None),
            len(insns) if insns else 0,
        )
    if not insns:
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}
    changed = (
        _materialize_byte_pointer_fill_loop_8616(project, codegen, insns, index_by_addr)
        or _materialize_word_pointer_sum_loop_8616(project, codegen, insns, index_by_addr)
        or _materialize_word_pair_pointer_accumulation_loop_8616(project, codegen, insns, index_by_addr)
        or _materialize_word_pointer_first_gt_loop_8616(project, codegen, insns, index_by_addr)
        or _materialize_word_pointer_rotate3_8616(project, codegen, insns, index_by_addr)
        or _materialize_pointer_swap_8616(project, codegen, insns, index_by_addr)
    )
    if debug_pointer_memory:
        logging.getLogger(__name__).warning(
            "[pointer-memory] exit function=%#x codegen=%#x changed=%s marker=%r",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            id(codegen),
            changed,
            getattr(codegen, "_inertia_pointer_memory_materialized_8616", None),
        )
    return changed


def _materialize_nested_stack_counter_accumulator_loop_8616(project, codegen) -> bool:
    """Recover nested counter loops with stack-slot locals and threshold breaks."""
    if getattr(codegen, "_inertia_nested_stack_counter_loop_materialized_8616", False):
        return False
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if len(insns) < 20:
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}
    for init_idx in range(len(insns) - 5):
        total_disp = _match_stack_zero_init_8616(insns[init_idx])
        i_disp = _match_stack_zero_init_8616(insns[init_idx + 1])
        if total_disp is None or i_disp is None or total_disp >= 0 or i_disp >= 0 or total_disp == i_disp:
            continue
        outer_start = int(getattr(insns[init_idx + 2], "address", -1))
        if not _match_mov_ax_stack_8616(insns[init_idx + 2], 4):
            continue
        if not _match_cmp_stack_ax_8616(insns[init_idx + 3], i_disp):
            continue
        outer_jl = insns[init_idx + 4]
        if str(getattr(outer_jl, "mnemonic", "")).lower() not in {"jl", "jnge"}:
            continue
        inner_init_target = _jcc._branch_target_imm_8616(outer_jl)
        return_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(outer_jl, "address", -1)), -1)),
        )
        if inner_init_target is None or return_target is None:
            continue
        inner_init = _block_insns_8616(project, int(inner_init_target))
        if len(inner_init) < 4:
            continue
        j_disp = _match_stack_zero_init_8616(inner_init[0])
        if j_disp is None or j_disp >= 0 or j_disp in {total_disp, i_disp}:
            continue
        inner_start = int(getattr(inner_init[1], "address", -1))
        if not _match_mov_ax_stack_8616(inner_init[1], i_disp):
            continue
        if not _match_cmp_stack_ax_8616(inner_init[2], j_disp):
            continue
        j_eq = inner_init[3]
        if str(getattr(j_eq, "mnemonic", "")).lower() not in {"je", "jz"}:
            continue
        continue_inc_target = _jcc._branch_target_imm_8616(j_eq)
        body_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(j_eq, "address", -1)), -1)),
        )
        if continue_inc_target is None or body_target is None:
            continue
        continue_inc = _block_insns_8616(project, int(continue_inc_target))
        if len(continue_inc) < 2 or not _match_stack_inc_8616(continue_inc[0], j_disp):
            continue
        inner_cond_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(continue_inc[1]))
        if inner_cond_target is None:
            continue
        body = _block_insns_8616(project, int(body_target))
        if len(body) < 5:
            continue
        if not _match_mov_ax_stack_8616(body[0], j_disp):
            continue
        if str(getattr(body[1], "mnemonic", "")).lower() != "add":
            continue
        body_add_ops = tuple(getattr(body[1], "operands", ()) or ())
        if len(body_add_ops) != 2 or _reg_name_from_operand_8616(body[1], body_add_ops[0]) != "ax":
            continue
        add_i_slot = _stack_mem_disp_size_8616(body[1], body_add_ops[1])
        if add_i_slot is None or int(add_i_slot[0]) != int(i_disp):
            continue
        if str(getattr(body[2], "mnemonic", "")).lower() != "add":
            continue
        body_total_add_ops = tuple(getattr(body[2], "operands", ()) or ())
        if len(body_total_add_ops) != 2 or _reg_name_from_operand_8616(body[2], body_total_add_ops[1]) != "ax":
            continue
        body_total_slot = _stack_mem_disp_size_8616(body[2], body_total_add_ops[0])
        if body_total_slot is None or int(body_total_slot[0]) != int(total_disp):
            continue
        if str(getattr(body[3], "mnemonic", "")).lower() != "cmp":
            continue
        threshold_ops = tuple(getattr(body[3], "operands", ()) or ())
        if len(threshold_ops) != 2:
            continue
        threshold_slot = _stack_mem_disp_size_8616(body[3], threshold_ops[0])
        threshold = _imm_from_operand_8616(threshold_ops[1])
        if threshold_slot is None or int(threshold_slot[0]) != int(total_disp) or threshold is None:
            continue
        inner_break_jcc = body[4]
        if str(getattr(inner_break_jcc, "mnemonic", "")).lower() not in {"jg", "jnle"}:
            continue
        inner_done_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(inner_break_jcc))
        post_body_inc_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(inner_break_jcc, "address", -1)), -1)),
        )
        if inner_done_target is None or post_body_inc_target is None:
            continue
        post_body = _block_insns_8616(project, int(post_body_inc_target))
        if len(post_body) < 4 or not _match_stack_inc_8616(post_body[0], j_disp):
            continue
        if int(getattr(post_body[1], "address", -1)) != int(inner_cond_target):
            continue
        if not _match_mov_ax_stack_8616(post_body[1], 4) or not _match_cmp_stack_ax_8616(post_body[2], j_disp):
            continue
        inner_cond_jcc = post_body[3]
        if str(getattr(inner_cond_jcc, "mnemonic", "")).lower() not in {"jge", "jnl"}:
            continue
        if _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(inner_cond_jcc)) != int(inner_done_target):
            continue
        inner_back = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(inner_cond_jcc, "address", -1)), -1)),
        )
        if inner_back is None or int(inner_back) != int(inner_start):
            continue
        outer_done = _block_insns_8616(project, int(inner_done_target))
        if len(outer_done) < 2:
            continue
        if str(getattr(outer_done[0], "mnemonic", "")).lower() != "cmp":
            continue
        outer_done_ops = tuple(getattr(outer_done[0], "operands", ()) or ())
        if len(outer_done_ops) != 2:
            continue
        outer_threshold_slot = _stack_mem_disp_size_8616(outer_done[0], outer_done_ops[0])
        outer_threshold = _imm_from_operand_8616(outer_done_ops[1])
        if (
            outer_threshold_slot is None
            or int(outer_threshold_slot[0]) != int(total_disp)
            or int(outer_threshold or -1) != int(threshold)
        ):
            continue
        outer_break_jcc = outer_done[1]
        if str(getattr(outer_break_jcc, "mnemonic", "")).lower() not in {"jg", "jnle"}:
            continue
        outer_break_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(outer_break_jcc))
        inc_i_target = _resolve_one_hop_jmp_target_8616(
            project,
            _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(outer_break_jcc, "address", -1)), -1)),
        )
        if outer_break_target is None or inc_i_target is None:
            continue
        if int(outer_break_target) != int(return_target):
            continue
        inc_i = _block_insns_8616(project, int(inc_i_target))
        if len(inc_i) < 2 or not _match_stack_inc_8616(inc_i[0], i_disp):
            continue
        if _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(inc_i[1])) != int(outer_start):
            continue
        total_expr = _jcc._stack_slot_expr_8616(codegen, int(total_disp), 2)
        i_expr = _jcc._stack_slot_expr_8616(codegen, int(i_disp), 2)
        j_expr = _jcc._stack_slot_expr_8616(codegen, int(j_disp), 2)
        limit_expr = _jcc._stack_slot_expr_8616(codegen, 4, 2)
        exit_expr = _branch_target_return_expr_8616(project, codegen, int(return_target))
        if any(expr is None for expr in (total_expr, i_expr, j_expr, limit_expr, exit_expr)):
            continue
        if _expr_fingerprint(exit_expr, project) != _expr_fingerprint(total_expr, project):
            continue

        def _var(expr):
            return _clone_c_value_for_codegen_tree_8616(expr)

        def _const(value: int):
            return CConstant(int(value), SimTypeShort(False), codegen=codegen)

        total_gt_threshold = lambda: CBinaryOp("CmpGT", _var(total_expr), _const(int(threshold)), codegen=codegen)
        inner_body = CStatements(
            statements=[
                CIfElse(
                    [
                        (
                            CBinaryOp("CmpEQ", _var(j_expr), _var(i_expr), codegen=codegen),
                            CStatements(
                                statements=[
                                    CAssignment(
                                        _var(j_expr),
                                        CBinaryOp("Add", _var(j_expr), _const(1), codegen=codegen),
                                        codegen=codegen,
                                    ),
                                    CContinue(codegen=codegen),
                                ],
                                codegen=codegen,
                            ),
                        )
                    ],
                    else_node=None,
                    cstyle_ifs=True,
                    codegen=codegen,
                ),
                CAssignment(
                    _var(total_expr),
                    CBinaryOp(
                        "Add",
                        _var(total_expr),
                        CBinaryOp("Add", _var(i_expr), _var(j_expr), codegen=codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                CIfElse(
                    [
                        (
                            total_gt_threshold(),
                            CStatements(statements=[CBreak(codegen=codegen)], codegen=codegen),
                        )
                    ],
                    else_node=None,
                    cstyle_ifs=True,
                    codegen=codegen,
                ),
                CAssignment(
                    _var(j_expr),
                    CBinaryOp("Add", _var(j_expr), _const(1), codegen=codegen),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        )
        outer_body = CStatements(
            statements=[
                CAssignment(_var(j_expr), _const(0), codegen=codegen),
                CDoWhileLoop(
                    CBinaryOp("CmpLT", _var(j_expr), _var(limit_expr), codegen=codegen),
                    inner_body,
                    codegen=codegen,
                ),
                CIfElse(
                    [
                        (
                            total_gt_threshold(),
                            CStatements(statements=[CBreak(codegen=codegen)], codegen=codegen),
                        )
                    ],
                    else_node=None,
                    cstyle_ifs=True,
                    codegen=codegen,
                ),
                CAssignment(
                    _var(i_expr),
                    CBinaryOp("Add", _var(i_expr), _const(1), codegen=codegen),
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        )
        codegen.cfunc.statements = CStatements(
            statements=[
                CAssignment(_var(total_expr), _const(0), codegen=codegen),
                CAssignment(_var(i_expr), _const(0), codegen=codegen),
                CWhileLoop(
                    CBinaryOp("CmpLT", _var(i_expr), _var(limit_expr), codegen=codegen),
                    outer_body,
                    codegen=codegen,
                ),
                CReturn(_var(total_expr), codegen=codegen),
            ],
            codegen=codegen,
        )
        codegen._inertia_nested_stack_counter_loop_materialized_8616 = True
        codegen._inertia_nested_stack_counter_loop_stack_slots_8616 = {
            "total_disp": int(total_disp),
            "i_disp": int(i_disp),
            "j_disp": int(j_disp),
            "limit_disp": 4,
            "threshold": int(threshold),
        }
        return True
    return False


def _ordered_32bit_conditional_return_pairs_from_cfg_8616(project, codegen) -> list[tuple[object, int]]:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return []
    try:
        function = project.kb.functions.function(addr=func_addr, create=False)
    except Exception:
        return []
    if function is None:
        return []
    pairs: list[tuple[object, int]] = []
    seen_conditions: set[str] = set()
    for block_addr in sorted(int(addr) for addr in getattr(function, "block_addrs_set", set()) or ()):
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            mnemonic = str(getattr(insn, "mnemonic", "")).lower()
            if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
                continue
            targets = _selector_targets_from_32bit_jcc_chain_8616(project, int(block_addr), insn)
            target = targets[0] if targets is not None else _equality_return_target_from_32bit_jcc_chain_8616(project, int(block_addr), insn)
            if target is None:
                target = _inequality_target_from_32bit_jcc_chain_8616(project, int(block_addr), insn)
            if target is None:
                continue
            value = _branch_target_return_value_8616(project, target)
            if value is None:
                continue
            decoded = _jcc._translate_cmp_jcc_guard_8616(project, codegen, int(block_addr), int(insn.address))
            if decoded is None:
                continue
            cond = getattr(decoded, "expr", None)
            if cond is None:
                cond = CBinaryOp(getattr(decoded, "op"), getattr(decoded, "lhs"), getattr(decoded, "rhs"), codegen=codegen)
            fingerprint = _expr_fingerprint(cond, project)
            if fingerprint in seen_conditions:
                continue
            seen_conditions.add(fingerprint)
            pairs.append((cond, int(value)))
    return pairs


def _first_stack_zero_init_8616(project, codegen) -> int | None:
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if int(getattr(operands[0], "type", -1)) != 3 or int(getattr(operands[1], "type", -1)) != 2:
            continue
        mem = operands[0].mem
        if not mem.base or str(insn.reg_name(mem.base)).lower() != "bp":
            continue
        if int(getattr(operands[1], "imm", 0) or 0) == 0:
            return _signed_i16_immediate_8616(int(mem.disp))
    return None


def _or_stack_update_imm_8616(project, target_addr: int, slot_offset: int, *, _depth: int = 0) -> int | None:
    if _depth > 2:
        return None
    try:
        block = project.factory.block(int(target_addr), opt_level=0)
    except Exception:
        return None
    for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic in {"jmp", "ljmp"}:
            next_target = _jcc._branch_target_imm_8616(insn)
            if next_target is None:
                return None
            return _or_stack_update_imm_8616(project, next_target, slot_offset, _depth=_depth + 1)
        if mnemonic == "or" and len(operands) == 2 and int(getattr(operands[0], "type", -1)) == 3:
            mem = operands[0].mem
            if (
                mem.base
                and str(insn.reg_name(mem.base)).lower() == "bp"
                and _signed_i16_immediate_8616(int(mem.disp)) == int(slot_offset)
            ):
                if int(getattr(operands[1], "type", -1)) == 2:
                    return int(getattr(operands[1], "imm", 0) or 0)
        if mnemonic in {"ret", "retf", "iret"}:
            return None
    return None


def _last_ax_stack_load_offset_8616(project, codegen) -> int | None:
    result = None
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if int(getattr(operands[0], "type", -1)) != 1 or int(getattr(operands[1], "type", -1)) != 3:
            continue
        if str(insn.reg_name(operands[0].reg)).lower() != "ax":
            continue
        mem = operands[1].mem
        if mem.base and str(insn.reg_name(mem.base)).lower() == "bp":
            result = _signed_i16_immediate_8616(int(mem.disp))
    return result


def _has_ax_stack_load_offset_8616(project, codegen, slot_offset: int) -> bool:
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if int(getattr(operands[0], "type", -1)) != 1 or int(getattr(operands[1], "type", -1)) != 3:
            continue
        if str(insn.reg_name(operands[0].reg)).lower() != "ax":
            continue
        mem = operands[1].mem
        if (
            mem.base
            and str(insn.reg_name(mem.base)).lower() == "bp"
            and _signed_i16_immediate_8616(int(mem.disp)) == int(slot_offset)
        ):
            return True
    return False


def _ordered_32bit_mask_update_pairs_from_cfg_8616(project, codegen, slot_offset: int) -> list[tuple[object, int]]:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return []
    pairs: list[tuple[object, int]] = []
    seen_conditions: set[str] = set()
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    for block_addr, insn in _linear_jcc_block_starts_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if not mnemonic.startswith("j") or mnemonic in {"jmp", "ljmp"}:
            continue
        targets = _selector_targets_from_32bit_jcc_chain_8616(project, int(block_addr), insn)
        target = targets[0] if targets is not None else _equality_return_target_from_32bit_jcc_chain_8616(project, int(block_addr), insn)
        if target is None:
            target = _inequality_target_from_32bit_jcc_chain_8616(project, int(block_addr), insn)
        if target is None:
            branch_target = _jcc._branch_target_imm_8616(insn)
            if branch_target is not None and _or_stack_update_imm_8616(project, int(branch_target), slot_offset) is not None:
                target = int(branch_target)
        if target is None:
            false_target = _next_unconditional_target_after_jcc_8616(project, int(block_addr), int(insn.address))
            if false_target is not None and _or_stack_update_imm_8616(project, false_target, slot_offset) is not None:
                target = int(false_target)
        if target is None:
            if debug:
                log.warning(
                    "[cfg-mask-accum] no-update jcc=%#x mnemonic=%s false=%r branch=%r",
                    int(insn.address),
                    mnemonic,
                    _next_unconditional_target_after_jcc_8616(project, int(block_addr), int(insn.address)),
                    _jcc._branch_target_imm_8616(insn),
                )
            continue
        imm = _or_stack_update_imm_8616(project, target, slot_offset)
        if imm is None:
            if debug:
                log.warning("[cfg-mask-accum] target-no-or jcc=%#x target=%#x", int(insn.address), int(target))
            continue
        decoded = _jcc._translate_cmp_jcc_guard_8616(project, codegen, int(block_addr), int(insn.address))
        if decoded is None:
            continue
        cond = getattr(decoded, "expr", None)
        if cond is None:
            cond = CBinaryOp(getattr(decoded, "op"), getattr(decoded, "lhs"), getattr(decoded, "rhs"), codegen=codegen)
        fingerprint = _expr_fingerprint(cond, project)
        if fingerprint in seen_conditions:
            continue
        seen_conditions.add(fingerprint)
        pairs.append((cond, int(imm)))
        if debug:
            log.warning(
                "[cfg-mask-accum] pair jcc=%#x mnemonic=%s target=%#x imm=%#x cond=%s",
                int(insn.address),
                mnemonic,
                int(target),
                int(imm),
                fingerprint,
            )
    return pairs


def _materialize_cfg_mask_accumulator_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    slot_offset = _first_stack_zero_init_8616(project, codegen)
    if slot_offset is None:
        if debug:
            log.warning("[cfg-mask-accum] refused no-zero-init")
        return False
    pairs = _ordered_32bit_mask_update_pairs_from_cfg_8616(project, codegen, slot_offset)
    imms = tuple(int(imm) for _cond, imm in pairs)
    if imms == (1, 2, 4, 8, 16):
        eq_cond = next(
            (
                cond
                for cond, imm in pairs
                if int(imm) == 16 and isinstance(cond, CBinaryOp) and getattr(cond, "op", None) == "CmpEQ"
            ),
            None,
        )
        if eq_cond is not None:
            pairs.append((CBinaryOp("CmpNE", eq_cond.lhs, eq_cond.rhs, codegen=codegen), 32))
    if len(pairs) < 2:
        if debug:
            log.warning("[cfg-mask-accum] refused pairs=%d slot=%r", len(pairs), slot_offset)
        return False
    mask_expr = _jcc._stack_slot_expr_8616(codegen, slot_offset, 2)
    if mask_expr is None:
        if debug:
            log.warning("[cfg-mask-accum] refused no-mask-expr slot=%r", slot_offset)
        return False
    statements = [CAssignment(mask_expr, CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)]
    for cond, imm in pairs:
        rhs = CBinaryOp("Or", mask_expr, CConstant(int(imm), SimTypeShort(False), codegen=codegen), codegen=codegen)
        body = CStatements(statements=[CAssignment(mask_expr, rhs, codegen=codegen)], codegen=codegen)
        statements.append(CIfElse([(cond, body)], else_node=None, cstyle_ifs=True, codegen=codegen))
    statements.append(CReturn(mask_expr, codegen=codegen))
    codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
    codegen._inertia_mask_accumulator_materialized_8616 = True
    codegen._inertia_mask_accumulator_condition_fingerprints_8616 = tuple(
        _expr_fingerprint(cond, project) for cond, _imm in pairs
    )
    codegen._inertia_mask_accumulator_return_fingerprint_8616 = _expr_fingerprint(mask_expr, project)
    codegen._inertia_mask_accumulator_update_immediates_8616 = tuple(int(imm) for _cond, imm in pairs)
    if debug:
        log.warning("[cfg-mask-accum] materialized pairs=%d slot=%r imms=%r", len(pairs), slot_offset, tuple(imm for _c, imm in pairs))
    return True


def _materialize_cfg_selector_return_branches_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    if getattr(codegen, "_inertia_return_selector_materialized_8616", False):
        return False
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    stats = getattr(codegen, "_inertia_cfg_selector_return_stats_8616", None)
    if not isinstance(stats, dict):
        stats = {"candidates": 0, "materialized": 0, "refused": 0}
        codegen._inertia_cfg_selector_return_stats_8616 = stats
    if _materialize_decrement_switch_return_chain_8616(project, codegen):
        stats["materialized"] += 1
        return True
    pairs = _ordered_32bit_selector_return_expr_pairs_from_cfg_8616(project, codegen)
    pair_source = "32bit"
    if not pairs:
        pairs = _ordered_conditional_return_expr_pairs_from_cfg_8616(project, codegen)
        pair_source = "jcc"
    stats["candidates"] += len(pairs)
    if debug:
        log.warning("[cfg-selector-return] candidates=%d source=%s stats=%r", len(pairs), pair_source, stats)
    if not pairs:
        return False
    if len(pairs) > 1:
        fingerprints = [_expr_fingerprint(cond, project) for cond, _true_expr, _false_expr in pairs]
        if len(set(fingerprints)) != len(fingerprints):
            stats["refused"] += len(pairs)
            return False
    if len(pairs) < 1:
        if pairs:
            stats["refused"] += len(pairs)
        return False
    if _selector_function_has_unsafe_effects_8616(project, codegen):
        stats["refused"] += 1
        if debug:
            log.warning("[cfg-selector-return] refused unsafe-effects stats=%r", stats)
        return False
    statements = []
    return_fingerprints = []
    if debug:
        def _debug_cvar_slot(expr) -> str:
            if not isinstance(expr, CVariable):
                return type(expr).__name__
            variable = getattr(expr, "variable", None)
            return (
                f"CVariable(name={getattr(expr, 'name', None)!r}, "
                f"var_name={getattr(variable, 'name', None)!r}, "
                f"offset={getattr(variable, 'offset', None)!r}, "
                f"size={getattr(variable, 'size', None)!r}, "
                f"id={id(expr):#x}, var_id={id(variable):#x})"
            )
    for cond, true_expr, _false_expr in pairs:
        if debug:
            log.warning(
                "[cfg-selector-return] materialize pair cond_fp=%r lhs=%s rhs=%s true=%s false=%s",
                _expr_fingerprint(cond, project),
                _debug_cvar_slot(getattr(cond, "lhs", None)),
                _debug_cvar_slot(getattr(cond, "rhs", None)),
                _debug_cvar_slot(true_expr),
                _debug_cvar_slot(_false_expr),
            )
        true_body = CStatements(
            statements=[CReturn(_clone_c_value_for_codegen_tree_8616(true_expr), codegen=codegen)],
            codegen=codegen,
        )
        statements.append(
            CIfElse(
                [(_clone_c_value_for_codegen_tree_8616(cond), true_body)],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            )
        )
        return_fingerprints.append(_expr_fingerprint(true_expr, project))
    final_expr = pairs[-1][2]
    statements.append(CReturn(_clone_c_value_for_codegen_tree_8616(final_expr), codegen=codegen))
    return_fingerprints.append(_expr_fingerprint(final_expr, project))
    _set_cfunc_statements_root_8616(codegen, CStatements(statements=statements, codegen=codegen))
    stats["materialized"] += len(pairs)
    codegen._inertia_return_expr_chain_materialized_8616 = True
    codegen._inertia_return_selector_materialized_8616 = True
    condition_fingerprints = tuple(_expr_fingerprint(cond, project) for cond, _true_expr, _false_expr in pairs)
    previous_condition_fingerprints = tuple(
        getattr(codegen, "_inertia_return_chain_materialized_condition_fingerprints_8616", ()) or ()
    )
    previous_return_fingerprints = tuple(
        getattr(codegen, "_inertia_return_expr_chain_materialized_return_fingerprints_8616", ()) or ()
    )
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
        dict.fromkeys((*previous_condition_fingerprints, *condition_fingerprints))
    )
    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(
        dict.fromkeys((*previous_return_fingerprints, *return_fingerprints))
    )
    if debug:
        first_stmt = next(iter(getattr(codegen.cfunc.statements, "statements", ()) or ()), None)
        first_cond = None
        if isinstance(first_stmt, CIfElse):
            cond_nodes = getattr(first_stmt, "condition_and_nodes", None) or ()
            if cond_nodes:
                first_cond = cond_nodes[0][0]
        log.warning(
            "[cfg-selector-return] materialized root cond_fp=%r lhs=%s rhs=%s returns=%r args=%r",
            _expr_fingerprint(first_cond, project) if first_cond is not None else None,
            _debug_cvar_slot(getattr(first_cond, "lhs", None)),
            _debug_cvar_slot(getattr(first_cond, "rhs", None)),
            codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616,
            [
                (
                    getattr(getattr(arg, "variable", None), "offset", None),
                    getattr(arg, "name", None),
                    getattr(getattr(arg, "variable", None), "name", None),
                    id(arg),
                    id(getattr(arg, "variable", None)),
                )
                for arg in (getattr(getattr(codegen, "cfunc", None), "arg_list", ()) or ())
            ],
        )
    return True


def _last_ax_return_value_8616(project, codegen) -> int | None:
    value = None
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and int(getattr(operands[0], "type", -1)) == 1
            and str(insn.reg_name(operands[0].reg)).lower() == "ax"
            and int(getattr(operands[1], "type", -1)) == 2
        ):
            value = _signed_i16_immediate_8616(int(getattr(operands[1], "imm", 0) or 0))
    return value


def _flatten_conditional_return_chain_8616(project, codegen, cond_return_pairs: list[tuple[object, int]]) -> bool:
    if len(cond_return_pairs) < 2:
        return False
    final_value = _last_ax_return_value_8616(project, codegen)
    if final_value is None:
        return False
    statements = []
    for cond, value in cond_return_pairs:
        if cond is None:
            return False
        body = CStatements(
            statements=[CReturn(CConstant(int(value), SimTypeShort(False), codegen=codegen), codegen=codegen)],
            codegen=codegen,
        )
        statements.append(CIfElse([(cond, body)], else_node=None, cstyle_ifs=True, codegen=codegen))
    statements.append(CReturn(CConstant(int(final_value), SimTypeShort(False), codegen=codegen), codegen=codegen))
    codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
    materialized_ifs = sum(1 for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CIfElse))
    materialized_returns = sum(1 for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CReturn))
    if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        logging.getLogger(__name__).warning(
            "[empty-return-branch] flattened ifs=%d returns=%d expected_ifs=%d expected_returns=%d final=%r",
            materialized_ifs,
            materialized_returns,
            len(cond_return_pairs),
            len(cond_return_pairs) + 1,
            final_value,
        )
    if materialized_ifs != len(cond_return_pairs) or materialized_returns != len(cond_return_pairs) + 1:
        return False
    codegen._inertia_return_chain_flattened_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = tuple(int(value) for _cond, value in cond_return_pairs)
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
        _expr_fingerprint(cond, project) for cond, _value in cond_return_pairs
    )
    codegen._inertia_return_chain_final_value_8616 = int(final_value)
    return True


def _node_contains_call_8616(node) -> bool:
    return any(isinstance(child, CFunctionCall) for child in _iter_c_nodes_deep_8616(node))


def _is_register_call_assignment_8616(stmt) -> bool:
    if not isinstance(stmt, CAssignment):
        return False
    lhs = getattr(stmt, "lhs", None)
    if not isinstance(lhs, CVariable) or not isinstance(getattr(lhs, "variable", None), SimRegisterVariable):
        return False
    return _node_contains_call_8616(getattr(stmt, "rhs", None))


def _materialize_cfg_conditional_return_suffix_8616(project, codegen, cond_return_pairs: list[tuple[object, int]]) -> bool:
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    if len(cond_return_pairs) < 2:
        if debug:
            log.warning("[cfg-return-chain] suffix refused pair_count=%d", len(cond_return_pairs))
        return False
    final_value = _last_ax_return_value_8616(project, codegen)
    if final_value is None:
        if debug:
            log.warning("[cfg-return-chain] suffix refused missing final return")
        return False
    cfunc = getattr(codegen, "cfunc", None)
    statements_node = getattr(cfunc, "statements", None)
    statements = list(getattr(statements_node, "statements", ()) or ())
    if not statements:
        if debug:
            log.warning("[cfg-return-chain] suffix refused missing statements")
        return False
    cut_index = next(
        (
            index
            for index, stmt in enumerate(statements)
            if isinstance(stmt, (CIfElse, CReturn, CGoto))
        ),
        None,
    )
    if cut_index is None:
        if debug:
            log.warning("[cfg-return-chain] suffix appending after setup statements=%d", len(statements))
        cut_index = len(statements)
    prefix = list(statements[:cut_index])
    if prefix and _is_register_call_assignment_8616(prefix[-1]) and _node_contains_call_8616(cond_return_pairs[0][0]):
        prefix.pop()
    if not prefix:
        if debug:
            log.warning("[cfg-return-chain] suffix refused empty semantic prefix cut=%d", cut_index)
        return False
    rebuilt = list(prefix)
    for cond, value in cond_return_pairs:
        body = CStatements(
            statements=[CReturn(CConstant(int(value), SimTypeShort(False), codegen=codegen), codegen=codegen)],
            codegen=codegen,
        )
        rebuilt.append(CIfElse([(cond, body)], else_node=None, cstyle_ifs=True, codegen=codegen))
    rebuilt.append(CReturn(CConstant(int(final_value), SimTypeShort(False), codegen=codegen), codegen=codegen))
    codegen.cfunc.statements = CStatements(statements=rebuilt, codegen=codegen)
    codegen._inertia_return_chain_suffix_materialized_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = tuple(int(value) for _cond, value in cond_return_pairs)
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
        _expr_fingerprint(cond, project) for cond, _value in cond_return_pairs
    )
    codegen._inertia_return_chain_final_value_8616 = int(final_value)
    return True


def _materialize_empty_if_return_branches_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    changed = False
    stats = getattr(codegen, "_inertia_empty_return_branch_stats_8616", None)
    if not isinstance(stats, dict):
        stats = {"candidates": 0, "materialized": 0, "refused": 0}
        codegen._inertia_empty_return_branch_stats_8616 = stats
    ordered_return_values = _ordered_conditional_return_values_8616(project, codegen)
    unsafe_effects = _selector_function_has_unsafe_effects_8616(project, codegen)
    if unsafe_effects:
        codegen._inertia_empty_return_branch_refused_unsafe_effects_8616 = (
            int(getattr(codegen, "_inertia_empty_return_branch_refused_unsafe_effects_8616", 0) or 0) + 1
        )
    ordered_index = 0
    cond_return_pairs: list[tuple[object, int]] = []
    empty_if_nodes: list[object] = []

    def _body_is_empty(body) -> bool:
        if isinstance(body, CStatements):
            return not tuple(getattr(body, "statements", ()) or ())
        return body is None

    def _body_is_cfg_return_setup_only(body) -> bool:
        if _body_is_empty(body):
            return True
        if not isinstance(body, CStatements):
            return False
        statements = tuple(getattr(body, "statements", ()) or ())
        if not statements:
            return True
        for stmt in statements:
            if not isinstance(stmt, CAssignment):
                return False
            nodes = (stmt, *_iter_c_nodes_deep_8616(stmt))
            if any(isinstance(node, CFunctionCall) for node in nodes):
                return False
            if any(isinstance(node, (CIfElse, CReturn, CGoto, CBreak, CWhileLoop, CDoWhileLoop, CForLoop)) for node in nodes):
                return False
        return True

    def _return_stmt(value: int):
        return CReturn(CConstant(int(value), SimTypeShort(False), codegen=codegen), codegen=codegen)

    if debug:
        with contextlib.suppress(Exception):
            nodes = tuple(_iter_c_nodes_deep_8616(getattr(codegen.cfunc, "statements", None)))
            if_nodes = tuple(node for node in nodes if isinstance(node, CIfElse))
            log.warning(
                "[empty-return-branch] scan nodes=%d ifs=%d root_type=%s",
                len(nodes),
                len(if_nodes),
                type(getattr(codegen.cfunc, "statements", None)).__name__,
            )
    for node in _iter_c_nodes_deep_8616(getattr(codegen.cfunc, "statements", None)):
        if not isinstance(node, CIfElse):
            continue
        cond_pairs = getattr(node, "condition_and_nodes", None)
        if not isinstance(cond_pairs, (list, tuple)) or not cond_pairs:
            if debug:
                log.warning(
                    "[empty-return-branch] refused no-cond-pairs type=%s cond_pairs_type=%s",
                    type(node).__name__,
                    type(cond_pairs).__name__,
                )
            continue
        cond, body = cond_pairs[0]
        else_body = getattr(node, "else_node", None)
        cfg_return_setup_candidate = _body_is_cfg_return_setup_only(body) and _body_is_cfg_return_setup_only(else_body)
        if not _body_is_empty(body):
            if debug:
                body_statements = getattr(body, "statements", None)
                if isinstance(body_statements, CStatements):
                    body_count = len(tuple(getattr(body_statements, "statements", ()) or ()))
                elif isinstance(body_statements, (list, tuple)):
                    body_count = len(body_statements)
                else:
                    body_count = -1
                child_types: tuple[str, ...] = ()
                if isinstance(body_statements, CStatements):
                    child_items = tuple(getattr(body_statements, "statements", ()) or ())
                    child_types = tuple(type(child).__name__ for child in child_items)
                elif isinstance(body_statements, (list, tuple)):
                    child_items = tuple(body_statements)
                    child_types = tuple(type(child).__name__ for child in child_items)
                else:
                    child_items = ()
                assignment_fps = []
                for child in child_items:
                    if isinstance(child, CAssignment):
                        assignment_fps.append(
                            (
                                _expr_fingerprint(getattr(child, "lhs", None), project),
                                _expr_fingerprint(getattr(child, "rhs", None), project),
                            )
                        )
                log.warning(
                    "[empty-return-branch] refused nonempty body_type=%s body_count=%d child_types=%r assignment_fps=%r cond_key=%r",
                    type(body).__name__,
                    body_count,
                    child_types,
                    tuple(assignment_fps),
                    _jcc._condition_tags_8616(cond),
                )
            if not cfg_return_setup_candidate:
                continue
        empty_if_nodes.append(node)
        stats["candidates"] += 1
        if not _body_is_empty(body):
            continue
        if unsafe_effects:
            stats["refused"] += 1
            if debug:
                log.warning(
                    "[empty-return-branch] refused unsafe function effects cond_key=%r",
                    _jcc._condition_tags_8616(cond),
                )
            continue
        value = _condition_branch_return_value_8616(project, cond)
        tag_evidence = _condition_branch_tag_evidence_8616(project, cond)
        if value is None and tag_evidence is _ConditionBranchTagEvidence8616.NON_BRANCH:
            stats["refused"] += 1
            if debug:
                log.warning(
                    "[empty-return-branch] refused non-jcc condition tag cond_key=%r",
                    _jcc._condition_tags_8616(cond),
                )
            continue
        if value is None and ordered_index < len(ordered_return_values):
            value = ordered_return_values[ordered_index]
            ordered_index += 1
        if debug:
            log.warning(
                "[empty-return-branch] candidate cond_key=%r value=%r body_type=%s",
                _jcc._condition_tags_8616(cond),
                value,
                type(body).__name__,
            )
        if value is None:
            stats["refused"] += 1
            continue
        cond_return_pairs.append((cond, value))
        new_body = CStatements(statements=[_return_stmt(value)], codegen=codegen)
        new_pairs = list(cond_pairs)
        new_pairs[0] = (cond, new_body)
        node.condition_and_nodes = type(cond_pairs)(new_pairs)
        if hasattr(node, "iftrue"):
            node.iftrue = new_body
        if hasattr(node, "true_node"):
            node.true_node = new_body
        stats["materialized"] += 1
        changed = True
    if not cond_return_pairs and empty_if_nodes:
        total_if_nodes = sum(
            1
            for current in _iter_c_nodes_deep_8616(getattr(codegen.cfunc, "statements", None))
            if isinstance(current, CIfElse)
        )
        if len(empty_if_nodes) != 1 or total_if_nodes != 1:
            stats["refused"] += len(empty_if_nodes)
            if debug:
                log.warning(
                    "[empty-return-branch] cfg expr rebuild refused: candidates=%d total_ifs=%d",
                    len(empty_if_nodes),
                    total_if_nodes,
                )
        elif _selector_function_has_unsafe_effects_8616(project, codegen):
            stats["refused"] += len(empty_if_nodes)
            if debug:
                log.warning("[empty-return-branch] cfg expr rebuild refused: unsafe function effects")
        else:
            cfg_expr_pairs = _ordered_conditional_return_expr_pairs_from_cfg_8616(project, codegen)
            if len(cfg_expr_pairs) >= len(empty_if_nodes):
                rebuilt_statements = []
                for node, (cond, true_expr, false_expr) in zip(empty_if_nodes, cfg_expr_pairs):
                    true_body = CStatements(
                        statements=[CReturn(true_expr, codegen=codegen)],
                        codegen=codegen,
                    )
                    false_body = CStatements(
                        statements=[CReturn(false_expr, codegen=codegen)],
                        codegen=codegen,
                    )
                    node.condition_and_nodes = type(getattr(node, "condition_and_nodes", []))([(cond, true_body)])
                    node.else_node = false_body
                    if hasattr(node, "iftrue"):
                        node.iftrue = true_body
                    if hasattr(node, "true_node"):
                        node.true_node = true_body
                    rebuilt_statements.append(node)
                if rebuilt_statements:
                    codegen.cfunc.statements = CStatements(statements=rebuilt_statements, codegen=codegen)
                    codegen._inertia_return_expr_chain_materialized_8616 = True
                    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
                        _expr_fingerprint(cond, project) for cond, _true_expr, _false_expr in cfg_expr_pairs[: len(empty_if_nodes)]
                    )
                    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(
                        _expr_fingerprint(expr, project)
                        for _cond, true_expr, false_expr in cfg_expr_pairs[: len(empty_if_nodes)]
                        for expr in (true_expr, false_expr)
                    )
                    stats["materialized"] += len(rebuilt_statements)
                    changed = True
            else:
                stats["refused"] += len(empty_if_nodes)
                if debug:
                    log.warning(
                        "[empty-return-branch] cfg expr rebuild refused: pairs=%d candidates=%d",
                        len(cfg_expr_pairs),
                        len(empty_if_nodes),
                    )
    if len(cond_return_pairs) >= 2:
        cfg_return_pairs = _ordered_conditional_return_pairs_from_cfg_8616(project, codegen)
        flatten_pairs = cond_return_pairs
        if len(cfg_return_pairs) >= len(cond_return_pairs):
            flatten_pairs = cfg_return_pairs[: len(cond_return_pairs)]
            if debug:
                log.warning(
                    "[empty-return-branch] using cfg decoded return-chain pairs count=%d",
                    len(flatten_pairs),
                )
        changed = _flatten_conditional_return_chain_8616(project, codegen, flatten_pairs) or changed
        cond_return_pairs = flatten_pairs
    if not cond_return_pairs:
        cfg_return_pairs = _ordered_32bit_conditional_return_pairs_from_cfg_8616(project, codegen)
        if len(cfg_return_pairs) >= 2:
            if unsafe_effects:
                stats["refused"] += len(cfg_return_pairs)
                if debug:
                    log.warning(
                        "[cfg-return-chain] 32-bit flatten refused unsafe effects pairs=%d",
                        len(cfg_return_pairs),
                    )
            else:
                changed = _flatten_conditional_return_chain_8616(project, codegen, cfg_return_pairs) or changed
                cond_return_pairs = cfg_return_pairs
    if not cond_return_pairs:
        cfg_return_pairs = _ordered_conditional_return_pairs_from_cfg_8616(project, codegen)
        if len(cfg_return_pairs) >= 2:
            if _selector_function_has_unsafe_effects_8616(project, codegen):
                stats["refused"] += len(cfg_return_pairs)
                if debug:
                    log.warning(
                        "[cfg-return-chain] full flatten refused unsafe effects pairs=%d",
                        len(cfg_return_pairs),
                    )
            else:
                changed = _flatten_conditional_return_chain_8616(project, codegen, cfg_return_pairs) or changed
                cond_return_pairs = cfg_return_pairs
    if not cond_return_pairs and not getattr(codegen, "_inertia_return_chain_suffix_materialized_8616", False):
        cfg_return_pairs = _ordered_conditional_return_pairs_from_cfg_8616(project, codegen)
        if unsafe_effects and cfg_return_pairs:
            stats["refused"] += len(cfg_return_pairs)
            if debug:
                log.warning(
                    "[cfg-return-chain] suffix materialization refused unsafe effects pairs=%d",
                    len(cfg_return_pairs),
                )
        elif _materialize_cfg_conditional_return_suffix_8616(project, codegen, cfg_return_pairs):
            stats["materialized"] += len(cfg_return_pairs)
            changed = True
            cond_return_pairs = cfg_return_pairs
    changed = _prune_duplicate_empty_return_guard_before_cfg_suffix_8616(project, codegen) or changed
    if cond_return_pairs:
        codegen._inertia_empty_return_branch_values_8616 = tuple(int(value) for _cond, value in cond_return_pairs)
    if debug:
        log.warning("[empty-return-branch] stats=%r changed=%s", stats, changed)
    return changed


def _single_if_return_8616(stmt) -> tuple[object, object] | None:
    if not isinstance(stmt, CIfElse):
        return None
    cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
    if len(cond_nodes) != 1:
        return None
    cond, body = cond_nodes[0]
    if isinstance(body, CStatements):
        body_statements = list(getattr(body, "statements", ()) or ())
    elif isinstance(body, CReturn):
        body_statements = [body]
    else:
        return None
    if len(body_statements) != 1 or not isinstance(body_statements[0], CReturn):
        return None
    return cond, getattr(body_statements[0], "retval", None)


def _const_return_value_8616(expr) -> int | None:
    if not isinstance(expr, CConstant):
        return None
    try:
        return int(getattr(expr, "value"))
    except Exception:
        return None


def _is_empty_return_statement_8616(stmt) -> bool:
    if isinstance(stmt, CReturn):
        return getattr(stmt, "retval", None) is None
    if isinstance(stmt, CStatements):
        nested = list(getattr(stmt, "statements", ()) or ())
        return len(nested) == 1 and _is_empty_return_statement_8616(nested[0])
    return False


def _is_explicit_void_return_type_8616(return_type) -> bool:
    return type(return_type) is SimTypeBottom and getattr(return_type, "label", None) == "void"


def _codegen_has_explicit_void_return_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    function = getattr(codegen, "_inertia_current_function_8616", None)
    func_addr = getattr(cfunc, "addr", None)
    if function is None and isinstance(func_addr, int):
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)

    for candidate in (
        getattr(cfunc, "functy", None),
        getattr(cfunc, "prototype", None),
        getattr(getattr(codegen, "_func", None), "prototype", None),
        getattr(function, "prototype", None) if function is not None else None,
    ):
        return_type = getattr(candidate, "returnty", None)
        if return_type is None:
            continue
        if _is_explicit_void_return_type_8616(return_type):
            return True
    if function is not None:
        if getattr(function, "returning", None) is False:
            return True
        info = getattr(function, "info", None)
        annotations = info.get(ANNOTATION_KEY) if isinstance(info, MutableMapping) else None
        if isinstance(annotations, dict):
            source_decl = _source_decl_from_cod_source_lines(
                tuple(annotations.get("source_lines", ()) or ()),
                getattr(function, "name", None),
            )
            if source_decl:
                with contextlib.suppress(Exception):
                    _name, source_proto, _arg_names = _parse_c_prototype_8616(source_decl)
                    if _is_explicit_void_return_type_8616(getattr(source_proto, "returnty", None)):
                        return True
    return False


def _is_conditional_branch_insn_8616(insn) -> bool:
    mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
    if mnemonic in {"jmp", "ljmp"}:
        return False
    if mnemonic.startswith("j"):
        return True
    return mnemonic in {"loop", "loope", "loopne", "loopnz", "loopz"}


def _real_conditional_branch_count_for_codegen_8616(project, codegen) -> int | None:
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if not insns:
        return None
    return sum(1 for insn in insns if _is_conditional_branch_insn_8616(insn))


def _else_node_empty_8616(node) -> bool:
    if node is None:
        return True
    if isinstance(node, CStatements):
        return not list(getattr(node, "statements", ()) or ())
    return False


def _c_node_semantically_empty_8616(node) -> bool:
    if node is None:
        return True
    if isinstance(node, CStatements):
        return all(_c_node_semantically_empty_8616(stmt) for stmt in (getattr(node, "statements", ()) or ()))
    if isinstance(node, CIfElse):
        if _node_contains_call_8616(getattr(node, "condition", None)):
            return False
        cond_nodes = getattr(node, "condition_and_nodes", None) or ()
        bodies_empty = all(_c_node_semantically_empty_8616(body) for _cond, body in cond_nodes)
        return bodies_empty and _c_node_semantically_empty_8616(getattr(node, "else_node", None))
    return False


def _surplus_empty_guard_condition_8616(stmt) -> tuple[object, _SurplusIfGuardKind8616] | None:
    if not isinstance(stmt, CIfElse):
        return None
    if not _c_node_semantically_empty_8616(getattr(stmt, "else_node", None)):
        return None
    cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
    if len(cond_nodes) != 1:
        return None
    cond, body = cond_nodes[0]
    if _node_contains_call_8616(cond):
        return None
    if not _is_empty_return_statement_8616(body):
        if _c_node_semantically_empty_8616(body):
            return cond, _SurplusIfGuardKind8616.EMPTY_NOOP
        return None
    return cond, _SurplusIfGuardKind8616.EMPTY_RETURN


def _condition_branch_tag_evidence_8616(project, cond) -> _ConditionBranchTagEvidence8616:
    with contextlib.suppress(Exception):
        tags = _jcc._condition_tags_8616(cond)
        if not (isinstance(tags, tuple) and len(tags) == 2 and all(isinstance(item, int) for item in tags)):
            return _ConditionBranchTagEvidence8616.NO_TAG
        block = project.factory.block(int(tags[0]), num_inst=1, opt_level=0)
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not insns:
            return _ConditionBranchTagEvidence8616.UNKNOWN
        if _is_conditional_branch_insn_8616(insns[0]):
            return _ConditionBranchTagEvidence8616.CONDITIONAL_BRANCH
        return _ConditionBranchTagEvidence8616.NON_BRANCH
    return _ConditionBranchTagEvidence8616.UNKNOWN


def _condition_has_jcc_evidence_8616(project, cond) -> bool:
    return _condition_branch_tag_evidence_8616(project, cond) in {
        _ConditionBranchTagEvidence8616.CONDITIONAL_BRANCH,
        _ConditionBranchTagEvidence8616.UNKNOWN,
    }


def _prune_surplus_void_empty_return_guards_8616(project, codegen) -> bool:
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if root is None:
        return False

    if not _codegen_has_explicit_void_return_8616(project, codegen):
        codegen._inertia_void_empty_return_guard_refused_not_void_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_not_void_8616", 0) or 0) + 1
        )
        codegen._inertia_void_empty_return_guard_decision_8616 = (
            _VoidEmptyReturnGuardDecision8616.KEEP_NOT_VOID.value
        )
        if debug:
            log.warning("[void-empty-return-guard] refused reason=not-void")
        return False

    branch_count = _real_conditional_branch_count_for_codegen_8616(project, codegen)
    if branch_count is None:
        codegen._inertia_void_empty_return_guard_refused_no_branch_proof_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_no_branch_proof_8616", 0) or 0) + 1
        )
        codegen._inertia_void_empty_return_guard_decision_8616 = (
            _VoidEmptyReturnGuardDecision8616.KEEP_NO_BRANCH_PROOF.value
        )
        if debug:
            log.warning("[void-empty-return-guard] refused reason=no-branch-proof")
        return False

    total_if_nodes = sum(1 for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CIfElse))
    surplus = total_if_nodes - int(branch_count)
    if surplus <= 0:
        codegen._inertia_void_empty_return_guard_refused_within_branch_budget_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_within_branch_budget_8616", 0) or 0) + 1
        )
        codegen._inertia_void_empty_return_guard_decision_8616 = (
            _VoidEmptyReturnGuardDecision8616.KEEP_WITHIN_BRANCH_BUDGET.value
        )
        if debug:
            log.warning(
                "[void-empty-return-guard] refused reason=within-budget ifs=%d branches=%d",
                total_if_nodes,
                int(branch_count),
            )
        return False

    candidates: list[tuple[CStatements, int, _SurplusIfGuardKind8616]] = []
    refused_branch_backed = 0
    refused_shape = 0
    seen_blocks: set[int] = set()
    blocks = [node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)]
    for block in blocks:
        block_id = id(block)
        if block_id in seen_blocks:
            continue
        seen_blocks.add(block_id)
        for index, stmt in enumerate(list(getattr(block, "statements", ()) or ())):
            candidate = _surplus_empty_guard_condition_8616(stmt)
            if candidate is None:
                if isinstance(stmt, CIfElse):
                    refused_shape += 1
                continue
            cond, kind = candidate
            codegen._inertia_void_empty_return_guard_candidates_8616 = (
                int(getattr(codegen, "_inertia_void_empty_return_guard_candidates_8616", 0) or 0) + 1
            )
            if _condition_has_jcc_evidence_8616(project, cond):
                refused_branch_backed += 1
                continue
            if kind is _SurplusIfGuardKind8616.EMPTY_NOOP:
                codegen._inertia_void_empty_return_guard_noop_candidates_8616 = (
                    int(getattr(codegen, "_inertia_void_empty_return_guard_noop_candidates_8616", 0) or 0) + 1
                )
            candidates.append((block, index, kind))

    if refused_shape:
        codegen._inertia_void_empty_return_guard_refused_non_empty_shape_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_non_empty_shape_8616", 0) or 0)
            + refused_shape
        )
    if refused_branch_backed:
        codegen._inertia_void_empty_return_guard_refused_branch_backed_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_branch_backed_8616", 0) or 0)
            + refused_branch_backed
        )
    if not candidates:
        codegen._inertia_void_empty_return_guard_decision_8616 = (
            _VoidEmptyReturnGuardDecision8616.KEEP_BRANCH_BACKED_CONDITION.value
        )
        if debug:
            log.warning(
                "[void-empty-return-guard] refused reason=no-eligible-candidates ifs=%d branches=%d "
                "surplus=%d refused_shape=%d refused_branch_backed=%d",
                total_if_nodes,
                int(branch_count),
                int(surplus),
                refused_shape,
                refused_branch_backed,
            )
        return False

    prune_budget = min(int(surplus), len(candidates))
    prune_by_block: dict[int, tuple[CStatements, set[int]]] = {}
    pruned_noop = sum(
        1 for _block, _index, kind in candidates[:prune_budget] if kind is _SurplusIfGuardKind8616.EMPTY_NOOP
    )
    pruned_empty_return = sum(
        1 for _block, _index, kind in candidates[:prune_budget] if kind is _SurplusIfGuardKind8616.EMPTY_RETURN
    )
    for block, index, _kind in candidates[:prune_budget]:
        block_id = id(block)
        if block_id not in prune_by_block:
            prune_by_block[block_id] = (block, set())
        prune_by_block[block_id][1].add(index)

    pruned = 0
    for block, indexes in prune_by_block.values():
        old_statements = list(getattr(block, "statements", ()) or ())
        block.statements = [stmt for index, stmt in enumerate(old_statements) if index not in indexes]
        pruned += len(old_statements) - len(block.statements)

    if pruned <= 0:
        return False
    codegen._inertia_void_empty_return_guard_pruned_8616 = (
        int(getattr(codegen, "_inertia_void_empty_return_guard_pruned_8616", 0) or 0) + pruned
    )
    codegen._inertia_void_empty_return_guard_branch_count_8616 = int(branch_count)
    codegen._inertia_void_empty_return_guard_total_ifs_8616 = int(total_if_nodes)
    codegen._inertia_void_empty_return_guard_noop_pruned_8616 = (
        int(getattr(codegen, "_inertia_void_empty_return_guard_noop_pruned_8616", 0) or 0) + pruned_noop
    )
    codegen._inertia_void_empty_return_guard_empty_return_pruned_8616 = (
        int(getattr(codegen, "_inertia_void_empty_return_guard_empty_return_pruned_8616", 0) or 0)
        + pruned_empty_return
    )
    codegen._inertia_void_empty_return_guard_decision_8616 = _VoidEmptyReturnGuardDecision8616.PRUNE.value
    if debug:
        log.warning(
            "[void-empty-return-guard] pruned=%d ifs=%d branches=%d surplus=%d candidates=%d",
            pruned,
            total_if_nodes,
            int(branch_count),
            int(surplus),
            len(candidates),
        )
    return True


def _prune_duplicate_empty_return_guard_before_cfg_suffix_8616(project, codegen) -> bool:
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    has_materialized_return_chain = any(
        bool(getattr(codegen, attr, False))
        for attr in (
            "_inertia_return_chain_suffix_materialized_8616",
            "_inertia_return_chain_flattened_8616",
            "_inertia_return_expr_chain_materialized_8616",
            "_inertia_decrement_switch_return_materialized_8616",
        )
    )
    values = tuple(int(value) for value in tuple(getattr(codegen, "_inertia_return_chain_materialized_values_8616", ()) or ()))
    if not has_materialized_return_chain:
        cfg_pairs = _ordered_conditional_return_pairs_from_cfg_8616(project, codegen)
        final_value = _last_ax_return_value_8616(project, codegen)
        if cfg_pairs and final_value is not None:
            values = tuple(int(value) for _cond, value in cfg_pairs) + (int(final_value),)
            has_materialized_return_chain = True
        else:
            if debug:
                log.warning("[cfg-return-chain] duplicate-empty prune refused: return chain not materialized")
            return False
    if not values:
        if debug:
            log.warning("[cfg-return-chain] duplicate-empty prune refused: no values")
        return False
    cfunc = getattr(codegen, "cfunc", None)
    statements_node = getattr(cfunc, "statements", None)
    statements = list(getattr(statements_node, "statements", ()) or ())
    if len(statements) <= len(values):
        if debug:
            log.warning(
                "[cfg-return-chain] duplicate-empty prune refused: statements=%d values=%d",
                len(statements),
                len(values),
            )
        return False
    for index in range(0, len(statements) - 1):
        previous = _single_if_return_8616(statements[index])
        following = _single_if_return_8616(statements[index + 1])
        if previous is None or following is None:
            continue
        previous_cond, previous_retval = previous
        following_cond, following_retval = following
        following_value = _const_return_value_8616(following_retval)
        if previous_retval is not None or following_value not in values:
            continue
        try:
            previous_fp = _expr_fingerprint(previous_cond, project)
            following_fp = _expr_fingerprint(following_cond, project)
        except Exception:
            continue
        if previous_fp != following_fp:
            continue
        del statements[index]
        codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
        codegen._inertia_return_chain_duplicate_empty_pruned_8616 = True
        if debug:
            log.warning("[cfg-return-chain] duplicate-empty pruned adjacent index=%d value=%d", index, following_value)
        return True
    chain_index = None
    for index in range(0, len(statements) - len(values) + 1):
        matched = True
        for offset, expected_value in enumerate(values):
            item = _single_if_return_8616(statements[index + offset])
            if item is None or _const_return_value_8616(item[1]) != expected_value:
                matched = False
                break
        if matched:
            chain_index = index
            break
    if chain_index is None or chain_index <= 0:
        if debug:
            nearby = []
            for index, stmt in enumerate(statements[: min(len(statements), 12)]):
                item = _single_if_return_8616(stmt)
                nearby.append(
                    (
                        index,
                        type(stmt).__name__,
                        None if item is None else type(item[1]).__name__,
                        None if item is None else _const_return_value_8616(item[1]),
                    )
                )
            log.warning("[cfg-return-chain] duplicate-empty prune refused: chain_index=%r nearby=%r", chain_index, nearby)
        return False
    previous_stmt = statements[chain_index - 1]
    if _is_empty_return_statement_8616(previous_stmt):
        del statements[chain_index - 1]
        codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
        codegen._inertia_return_chain_empty_prefix_pruned_8616 = True
        if debug:
            log.warning("[cfg-return-chain] empty return prefix pruned before chain index=%d", chain_index)
        return True
    previous = _single_if_return_8616(statements[chain_index - 1])
    first = _single_if_return_8616(statements[chain_index])
    if previous is None or first is None:
        if debug:
            log.warning(
                "[cfg-return-chain] duplicate-empty prune refused: guard extraction previous=%s first=%s chain_index=%d",
                previous is not None,
                first is not None,
                chain_index,
            )
        return False
    previous_cond, previous_retval = previous
    first_cond, _first_retval = first
    if previous_retval is not None:
        if debug:
            log.warning("[cfg-return-chain] duplicate-empty prune refused: previous has retval=%r", previous_retval)
        return False
    try:
        previous_fp = _expr_fingerprint(previous_cond, project)
        first_fp = _expr_fingerprint(first_cond, project)
        if previous_fp != first_fp:
            if debug:
                log.warning(
                    "[cfg-return-chain] duplicate-empty prune refused: cond mismatch previous=%r first=%r",
                    previous_fp,
                    first_fp,
                )
            return False
    except Exception:
        if debug:
            log.warning("[cfg-return-chain] duplicate-empty prune refused: cond fingerprint failed", exc_info=True)
        return False
    del statements[chain_index - 1]
    codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
    codegen._inertia_return_chain_duplicate_empty_pruned_8616 = True
    return True


def _return_chain_counts_8616(codegen) -> tuple[int, int]:
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return 0, 0
    if_count = sum(1 for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CIfElse))
    return_count = sum(1 for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CReturn))
    return if_count, return_count


def _return_chain_expected_counts_8616(codegen) -> tuple[int, int] | None:
    if not (
        getattr(codegen, "_inertia_return_chain_flattened_8616", False)
        or getattr(codegen, "_inertia_return_chain_suffix_materialized_8616", False)
    ):
        return None
    values = tuple(getattr(codegen, "_inertia_return_chain_materialized_values_8616", ()) or ())
    if not values:
        return None
    return len(values), len(values) + 1


def _repair_unresolved_function_exit_gotos_pass_8616(project, codegen) -> bool:
    return bool(
        _post._repair_unresolved_function_exit_gotos_8616(
            project if project is not None else getattr(codegen, "project", None),
            codegen,
        )
    )


@dataclass(frozen=True, slots=True)
class DecompilerPostprocessPassSpec:
    name: str
    func: Callable[..., bool]
    needs_project: bool
    callsite_final_gate: bool = False


def _codegen_has_structured_condition_8616(codegen) -> bool:
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if isinstance(node, (CIfBreak, CIfElse, CWhileLoop, CDoWhileLoop, CForLoop)):
            return True
        if getattr(node, "condition", None) is not None or getattr(node, "cond", None) is not None:
            return True
        if getattr(node, "condition_and_nodes", None):
            return True
    return False


def _dead_code_elimination_after_flag_prune_8616(codegen) -> bool:
    had_attr = hasattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616")
    previous = getattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616", None)
    had_dirty_read_attr = hasattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616")
    previous_dirty_read = getattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616", None)
    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    codegen._inertia_dce_allow_dirty_value_reads_8616 = True
    try:
        return _dead_code_elimination_8616(codegen)
    finally:
        if had_attr:
            codegen._inertia_dce_allow_storage_free_dirty_8616 = previous
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616")
        if had_dirty_read_attr:
            codegen._inertia_dce_allow_dirty_value_reads_8616 = previous_dirty_read
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616")


def _materialize_stable_stack_semantics_postprocess_8616(project, codegen) -> bool:
    changed = False
    try:
        debug_stack_noise = bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))
        before_ss_linear = int(getattr(codegen, "_inertia_ss_linear_materialized_count", 0) or 0)
        before_semantic_stack = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
        _invalidate_tail_validation_derived_caches_8616(codegen)
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
            after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
            changed = changed or after_materialized > before_materialized
        from .lowering.real_mode_linear import lower_stable_ss_linear_stack_dereferences_8616

        changed = bool(lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)) or changed
        if _fact_backed_stack_normalize_enabled_8616():
            changed = bool(_normalize_fact_backed_stack_accesses_8616(project, codegen)) or changed
        if changed:
            codegen._inertia_codegen_decl_refresh_required_8616 = True
        _invalidate_tail_validation_derived_caches_8616(codegen)
        if debug_stack_noise:
            logging.getLogger(__name__).warning(
                "[stable-stack-postprocess] function=%#x alias_facts=%d semantic_delta=%d ss_linear_delta=%d changed=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                len(alias_facts) if isinstance(alias_facts, list) else 0,
                int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0) - before_semantic_stack,
                int(getattr(codegen, "_inertia_ss_linear_materialized_count", 0) or 0) - before_ss_linear,
                changed,
            )
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Stable stack semantics postprocess materialization failed at function=%#x: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    return changed


def _prune_unreachable_after_return_8616(project, codegen) -> bool:  # noqa: ARG001
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "statements", None)
    if root is None:
        return False

    def _statement_ends_in_return(stmt) -> bool:
        if isinstance(stmt, CReturn):
            return True
        if not isinstance(stmt, CStatements):
            return False
        nested = list(getattr(stmt, "statements", ()) or ())
        while nested and isinstance(nested[-1], CStatements):
            nested = list(getattr(nested[-1], "statements", ()) or ())
        return bool(nested and isinstance(nested[-1], CReturn))

    changed = False
    removed = 0
    scanned_blocks = 0
    seen: set[int] = set()
    blocks = [node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)]
    for node in reversed(blocks):
        if not isinstance(node, CStatements):
            continue
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        scanned_blocks += 1
        statements = list(getattr(node, "statements", ()) or ())
        if not statements:
            continue
        kept = []
        terminated = False
        for stmt in statements:
            if terminated:
                removed += 1
                continue
            kept.append(stmt)
            if _statement_ends_in_return(stmt):
                terminated = True
        if len(kept) != len(statements):
            node.statements = kept
            changed = True

    if removed:
        codegen._inertia_unreachable_after_return_pruned_8616 = int(
            getattr(codegen, "_inertia_unreachable_after_return_pruned_8616", 0) or 0
        ) + removed
    if os.environ.get("INERTIA_DEBUG_UNREACHABLE_PRUNE"):
        top_types = ()
        with contextlib.suppress(Exception):
            top_types = tuple(type(stmt).__name__ for stmt in tuple(getattr(root, "statements", ()) or ()))
        logging.getLogger(__name__).warning(
            "[unreachable-prune] blocks=%d removed=%d changed=%s root_type=%s top=%r",
            scanned_blocks,
            removed,
            changed,
            type(root).__name__,
            top_types,
        )
    return changed


def _materialize_missing_terminal_ax_return_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
    statements = getattr(root, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return False
    return_nodes = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CReturn)]
    if os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"):
        logging.getLogger(__name__).warning(
            "[missing-ax-return] pass-entry func=%#x return_nodes=%d root=%s",
            getattr(cfunc, "addr", -1) or -1,
            len(return_nodes),
            type(root).__name__,
        )
    replace_artifact_return = False
    artifact_return = None
    if return_nodes:
        artifact_returns = [
            node
            for node in return_nodes
            if _return_expr_has_insert_artifact_8616(getattr(node, "retval", None))
            or _return_depends_on_insert_artifact_8616(root, node)
        ]
        if len(artifact_returns) > 1:
            if os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"):
                logging.getLogger(__name__).warning(
                    "[missing-ax-return] refused artifact_count=%d return_nodes=%d",
                    len(artifact_returns),
                    len(return_nodes),
                )
            return False
        if artifact_returns:
            artifact_return = artifact_returns[0]
        else:
            segmented_artifact_returns = [
                node
                for node in return_nodes
                if _return_expr_has_segmented_linear_artifact_8616(getattr(node, "retval", None))
            ]
            if len(segmented_artifact_returns) == 1:
                artifact_return = segmented_artifact_returns[0]
            else:
                generic_artifact_returns = [
                    node
                    for node in return_nodes
                    if _return_expr_has_generic_register_artifact_8616(getattr(node, "retval", None))
                ]
                if len(generic_artifact_returns) != 1 or not _generic_return_replacement_is_side_effect_free_8616(
                    root, generic_artifact_returns[0]
                ):
                    if os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"):
                        logging.getLogger(__name__).warning(
                            "[missing-ax-return] refused segmented_artifact_count=%d generic_artifact_count=%d return_nodes=%d",
                            len(segmented_artifact_returns),
                            len(generic_artifact_returns),
                            len(return_nodes),
                        )
                    return False
                artifact_return = generic_artifact_returns[0]
            if artifact_return is None:
                if os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"):
                    logging.getLogger(__name__).warning(
                        "[missing-ax-return] refused segmented_artifact_count=%d return_nodes=%d",
                        len(segmented_artifact_returns),
                        len(return_nodes),
                    )
                return False
        replace_artifact_return = True
    func_addr = getattr(cfunc, "addr", None)
    function = getattr(codegen, "_inertia_current_function_8616", None)
    if isinstance(func_addr, int):
        if function is None:
            with contextlib.suppress(Exception):
                function = project.kb.functions.function(addr=func_addr, create=False)

    prototype = None
    for candidate in (
        getattr(cfunc, "functy", None),
        getattr(cfunc, "prototype", None),
        getattr(function, "prototype", None) if function is not None else None,
    ):
        if candidate is not None and getattr(candidate, "returnty", None) is not None:
            prototype = candidate
            break

    return_type = getattr(prototype, "returnty", None)
    if type(return_type) is SimTypeBottom and getattr(return_type, "label", None) == "void":
        codegen._inertia_missing_terminal_ax_return_refused_void_8616 = (
            int(getattr(codegen, "_inertia_missing_terminal_ax_return_refused_void_8616", 0) or 0) + 1
        )
        return False
    if return_type is None or type(return_type) is SimTypeBottom:
        return False
    if not isinstance(func_addr, int):
        return False
    if function is not None:
        retval = _linear_terminal_ax_return_expr_8616(project, codegen, function)
    else:
        retval = _branch_target_return_expr_8616(project, codegen, func_addr)
    if retval is None:
        if os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"):
            logging.getLogger(__name__).warning(
                "[missing-ax-return] refused no terminal AX proof func=%#x function=%r",
                func_addr,
                function,
            )
        codegen._inertia_missing_terminal_ax_return_refused_8616 = (
            int(getattr(codegen, "_inertia_missing_terminal_ax_return_refused_8616", 0) or 0) + 1
        )
        return False
    replaced_fingerprint = None
    replaced_return_keys = frozenset()
    if replace_artifact_return:
        replaced_return_keys = _c_variables_read_by_expr_8616(getattr(artifact_return, "retval", None))
        with contextlib.suppress(Exception):
            replaced_fingerprint = _expr_fingerprint(getattr(artifact_return, "retval", None), project)
        artifact_return.retval = retval
        root.statements = [artifact_return] if isinstance(statements, list) else (artifact_return,)
        cfunc.statements = root
        if hasattr(cfunc, "body"):
            cfunc.body = root
        _prune_replaced_insert_artifact_assignments_8616(root, replaced_return_keys, codegen)
    else:
        updated = list(statements)
        updated.append(CReturn(retval, codegen=codegen))
        root.statements = updated if isinstance(statements, list) else tuple(updated)
        cfunc.statements = root
        if hasattr(cfunc, "body"):
            cfunc.body = root
    fingerprint = None
    with contextlib.suppress(Exception):
        fingerprint = _expr_fingerprint(retval, project)
    codegen._inertia_missing_terminal_ax_return_materialized_8616 = (
        int(getattr(codegen, "_inertia_missing_terminal_ax_return_materialized_8616", 0) or 0) + 1
    )
    if fingerprint is not None:
        codegen._inertia_missing_terminal_ax_return_fingerprints_8616 = (
            *tuple(getattr(codegen, "_inertia_missing_terminal_ax_return_fingerprints_8616", ()) or ()),
            fingerprint,
        )
    if replaced_fingerprint is not None:
        codegen._inertia_missing_terminal_ax_return_replaced_fingerprints_8616 = (
            *tuple(getattr(codegen, "_inertia_missing_terminal_ax_return_replaced_fingerprints_8616", ()) or ()),
            replaced_fingerprint,
        )
    return True


def _return_expr_has_insert_artifact_8616(expr) -> bool:
    if expr is None:
        return False
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    for node in _iter_c_nodes_deep_8616(expr):
        if not isinstance(node, CFunctionCall):
            continue
        callee = getattr(node, "callee_target", None)
        if callee is None:
            callee = getattr(node, "callee", None)
        if debug:
            logging.getLogger(__name__).warning(
                "[missing-ax-return] return-call-artifact candidate callee_target=%r callee=%r attrs=%r",
                getattr(node, "callee_target", None),
                getattr(node, "callee", None),
                tuple(sorted(k for k in getattr(node, "__dict__", {}) if "callee" in k or "target" in k or "name" in k)),
            )
        text = str(callee or "")
        if text in {"_INSERT", "__INSERT"} or text.endswith("._INSERT"):
            return True
    return False


def _return_expr_has_segmented_linear_artifact_8616(expr) -> bool:
    if expr is None:
        return False

    def _callee_name(node) -> str | None:
        callee = getattr(node, "callee_target", None)
        if callee is None:
            callee = getattr(node, "callee", None)
        name = getattr(callee, "name", None)
        if isinstance(name, str):
            return name
        if isinstance(callee, str):
            return callee
        return None

    def _const_value(node) -> int | None:
        return int(getattr(node, "value", 0)) if isinstance(node, CConstant) and isinstance(getattr(node, "value", None), int) else None

    def _has_segment_scale(node) -> bool:
        for child in _iter_c_nodes_deep_8616(node):
            if not isinstance(child, CBinaryOp):
                continue
            op = getattr(child, "op", None)
            lhs_const = _const_value(getattr(child, "lhs", None))
            rhs_const = _const_value(getattr(child, "rhs", None))
            if op == "Mul" and (lhs_const == 16 or rhs_const == 16):
                return True
            if op == "Shl" and rhs_const == 4:
                return True
        return False

    for node in _iter_c_nodes_deep_8616(expr):
        if isinstance(node, CFunctionCall) and _callee_name(node) in {"SEG_U8", "SEG_U16", "SEG_U32"}:
            return True
        if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":
            if _has_segment_scale(getattr(node, "operand", None)):
                return True
    return False


def _return_expr_has_generic_register_artifact_8616(expr) -> bool:
    if expr is None:
        return False
    artifact_name_re = re.compile(r"^(?:v\d+|vvar_\d+|ir_\d+(?:_\d+)?)$")
    for node in _iter_c_nodes_deep_8616(expr):
        if not isinstance(node, CVariable):
            continue
        variable = getattr(node, "variable", None)
        name = getattr(variable, "name", None) or getattr(node, "name", None)
        if isinstance(name, str) and artifact_name_re.fullmatch(name):
            return True
    return False


def _generic_return_replacement_is_side_effect_free_8616(root, return_node: CReturn) -> bool:
    statements = getattr(root, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return False
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    log = logging.getLogger(__name__)

    def _has_call_or_memory_effect(node) -> bool:
        for child in _iter_c_nodes_deep_8616(node):
            if isinstance(child, CFunctionCall):
                return True
            if isinstance(child, CUnaryOp) and getattr(child, "op", None) == "Dereference":
                return True
        return False

    def _contains_return_node(node) -> bool:
        if node is return_node:
            return True
        return any(child is return_node for child in _iter_c_nodes_deep_8616(node))

    def _is_control_node(node) -> bool:
        return type(node).__name__ in {
            "CBreak",
            "CContinue",
            "CDoWhileLoop",
            "CForLoop",
            "CGoto",
            "CIfElse",
            "CSwitchCase",
            "CWhileLoop",
        }

    for stmt in statements:
        if stmt is return_node:
            return True
        if isinstance(stmt, CAssignment):
            if _has_call_or_memory_effect(getattr(stmt, "lhs", None)):
                if debug:
                    log.warning("[missing-ax-return] generic artifact replacement refused lhs-effect stmt=%s", type(stmt).__name__)
                return False
            if _has_call_or_memory_effect(getattr(stmt, "rhs", None)):
                if debug:
                    log.warning("[missing-ax-return] generic artifact replacement refused rhs-effect stmt=%s", type(stmt).__name__)
                return False
            continue
        if isinstance(stmt, CReturn):
            return stmt is return_node
        if _contains_return_node(stmt):
            return not _is_control_node(stmt) and not _has_call_or_memory_effect(stmt)
        if _is_control_node(stmt):
            if debug:
                log.warning("[missing-ax-return] generic artifact replacement refused control stmt=%s", type(stmt).__name__)
            return False
        if not _has_call_or_memory_effect(stmt):
            continue
        if debug:
            log.warning("[missing-ax-return] generic artifact replacement refused stmt=%s", type(stmt).__name__)
        return False
    return False


def _c_variable_key_8616(expr) -> tuple | None:
    if not isinstance(expr, CVariable):
        return None
    variable = getattr(expr, "variable", None)
    if variable is not None:
        return (
            type(variable).__name__,
            getattr(variable, "name", None),
            getattr(variable, "offset", None),
            getattr(variable, "reg", None),
            getattr(variable, "size", None),
        )
    name = getattr(expr, "name", None)
    return ("CVariable", name) if name is not None else None


def _c_variables_read_by_expr_8616(expr) -> frozenset[tuple]:
    keys: set[tuple] = set()
    if expr is None:
        return frozenset()
    for node in _iter_c_nodes_deep_8616(expr):
        key = _c_variable_key_8616(node)
        if key is not None:
            keys.add(key)
    return frozenset(keys)


def _iter_structured_children_for_reads_8616(node):
    for attr in _C_AST_CHILD_ATTRS_8616:
        value = None
        with contextlib.suppress(Exception):
            value = getattr(node, attr)
        if value is None:
            continue
        if isinstance(value, dict):
            yield from value.values()
        elif isinstance(value, (list, tuple, set, frozenset)):
            yield from value
        else:
            yield value


def _c_variables_read_by_tree_8616(root) -> frozenset[tuple]:
    keys: set[tuple] = set()
    seen: set[int] = set()

    def _walk(node) -> None:
        if node is None:
            return
        if isinstance(node, (list, tuple, set, frozenset)):
            for item in node:
                _walk(item)
            return
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        if isinstance(node, CVariable):
            key = _c_variable_key_8616(node)
            if key is not None:
                keys.add(key)
            return
        if isinstance(node, CAssignment):
            _walk(getattr(node, "rhs", None))
            return
        for child in _iter_structured_children_for_reads_8616(node):
            _walk(child)

    _walk(root)
    return frozenset(keys)


def _return_depends_on_insert_artifact_8616(root, return_node: CReturn) -> bool:
    read_keys = _c_variables_read_by_expr_8616(getattr(return_node, "retval", None))
    if not read_keys:
        return False
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CAssignment):
            continue
        lhs_key = _c_variable_key_8616(getattr(node, "lhs", None))
        if lhs_key is None or lhs_key not in read_keys:
            continue
        if _return_expr_has_insert_artifact_8616(getattr(node, "rhs", None)):
            return True
    return False


def _prune_replaced_insert_artifact_assignments_8616(root, replaced_return_keys: frozenset[tuple], codegen) -> int:
    remaining_reads = _c_variables_read_by_tree_8616(root)
    pruned = 0
    for block in tuple(node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)):
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            continue
        updated = []
        changed = False
        for stmt in statements:
            if isinstance(stmt, CAssignment):
                lhs_key = _c_variable_key_8616(getattr(stmt, "lhs", None))
                if (
                    lhs_key is not None
                    and lhs_key not in remaining_reads
                    and _return_expr_has_insert_artifact_8616(getattr(stmt, "rhs", None))
                ):
                    pruned += 1
                    changed = True
                    continue
            updated.append(stmt)
        if changed:
            block.statements = updated if isinstance(statements, list) else tuple(updated)
    if pruned:
        codegen._inertia_missing_terminal_ax_return_artifact_assignments_pruned_8616 = (
            int(getattr(codegen, "_inertia_missing_terminal_ax_return_artifact_assignments_pruned_8616", 0) or 0)
            + pruned
        )
    return pruned


def _materialize_stack_byte_pair_return_8616(project, codegen) -> bool:
    """Recover word returns built by storing adjacent stack bytes then loading the word."""
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if not insns:
        return False

    byte_stores: dict[int, object] = {}
    al_source = None
    returned_base: int | None = None
    raw_fact_count = 0
    classified_fact_count = 0

    def _reg_name(insn, operand) -> str | None:
        with contextlib.suppress(Exception):
            return str(insn.reg_name(operand.reg)).lower()
        return None

    def _bp_mem_disp(insn, operand, *, size: int | None = None) -> int | None:
        if int(getattr(operand, "type", -1)) != 3:
            return None
        if size is not None and int(getattr(operand, "size", 0) or 0) != size:
            return None
        mem = operand.mem
        if str(insn.reg_name(mem.base)).lower() != "bp":
            return None
        disp = getattr(mem, "disp", None)
        return int(disp) if isinstance(disp, int) else None

    def _stack_byte_expr(disp: int):
        return _jcc._stack_slot_expr_8616(codegen, int(disp), 1)

    for insn in insns:
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic != "mov" or len(operands) != 2:
            continue
        dst, src = operands
        if int(getattr(dst, "type", -1)) == 1 and _reg_name(insn, dst) == "al":
            src_disp = _bp_mem_disp(insn, src, size=1)
            if src_disp is not None:
                raw_fact_count += 1
                al_source = _stack_byte_expr(src_disp)
                if al_source is not None:
                    classified_fact_count += 1
            continue
        if int(getattr(dst, "type", -1)) == 3 and int(getattr(dst, "size", 0) or 0) == 1:
            dst_disp = _bp_mem_disp(insn, dst, size=1)
            if dst_disp is not None and int(getattr(src, "type", -1)) == 1 and _reg_name(insn, src) == "al":
                raw_fact_count += 1
                if al_source is not None:
                    byte_stores[int(dst_disp)] = _clone_c_value_for_codegen_tree_8616(al_source)
                    classified_fact_count += 1
            continue
        if int(getattr(dst, "type", -1)) == 1 and _reg_name(insn, dst) == "ax":
            src_disp = _bp_mem_disp(insn, src, size=2)
            if src_disp is not None and src_disp in byte_stores and src_disp + 1 in byte_stores:
                raw_fact_count += 1
                returned_base = int(src_disp)
                classified_fact_count += 1

    stats = {
        "raw_fact_count": raw_fact_count,
        "classified_fact_count": classified_fact_count,
        "materialized_count": 0,
        "failure_count": 0,
    }
    codegen._inertia_stack_byte_pair_return_stats_8616 = stats
    if returned_base is None:
        if raw_fact_count:
            stats["failure_count"] = 1
        return False

    low_expr = byte_stores.get(returned_base)
    high_expr = byte_stores.get(returned_base + 1)
    if low_expr is None or high_expr is None:
        stats["failure_count"] = 1
        return False

    high_shift = CBinaryOp(
        "Shl",
        _clone_c_value_for_codegen_tree_8616(high_expr),
        CConstant(8, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
    )
    return_expr = CBinaryOp(
        "Or",
        _clone_c_value_for_codegen_tree_8616(low_expr),
        high_shift,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        statements=[CReturn(return_expr, codegen=codegen)],
        codegen=codegen,
    )
    stats["materialized_count"] = 1
    codegen._inertia_stack_byte_pair_return_materialized_8616 = True
    return True


def _materialize_direct_global_incdec_instructions_postprocess_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    function = None
    with contextlib.suppress(Exception):
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is not None and isinstance(func_addr, int):
            function = functions.function(addr=func_addr, create=False)
    return materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function)


def _materialize_direct_stack_incdec_instructions_postprocess_8616(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    function = None
    with contextlib.suppress(Exception):
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is not None and isinstance(func_addr, int):
            function = functions.function(addr=func_addr, create=False)
    return materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function)


def _materialize_direct_stack_mov_instructions_postprocess_8616(project, codegen, *, allow_stack_slot_fallback=False) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    function = None
    with contextlib.suppress(Exception):
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is not None and isinstance(func_addr, int):
            function = functions.function(addr=func_addr, create=False)
    return materialize_direct_stack_mov_instructions_8616(
        codegen, project=project, function=function, allow_stack_slot_fallback=allow_stack_slot_fallback
    )


def _materialize_direct_stack_mov_instructions_final_postprocess_8616(project, codegen) -> bool:
    return _materialize_direct_stack_mov_instructions_postprocess_8616(
        project, codegen, allow_stack_slot_fallback=True
    )


def _materialize_pointer_arg_indirect_loads_postprocess_8616(project, codegen) -> bool:
    func = getattr(codegen, "_func", None)
    if func is None:
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        if isinstance(func_addr, int):
            with contextlib.suppress(Exception):
                func = project.kb.functions.function(addr=func_addr, create=False)
    return _post._materialize_pointer_arg_indirect_loads_8616(project, codegen, func)


def _build_decompiler_postprocess_passes():
    return (
        DecompilerPostprocessPassSpec("_apply_word_global_types_8616", _globals._apply_word_global_types_8616, True),
        DecompilerPostprocessPassSpec("_apply_annotations_8616", _post._apply_annotations_8616, True),
        DecompilerPostprocessPassSpec(
            "_materialize_stable_stack_semantics_early_8616",
            _materialize_stable_stack_semantics_postprocess_8616,
            True,
        ),
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
        DecompilerPostprocessPassSpec(
            "_materialize_pointer_memory_idioms_8616",
            _materialize_pointer_memory_idioms_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_global_byte_index_sum_loop_8616",
            _materialize_global_byte_index_sum_loop_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_nested_stack_counter_accumulator_loop_8616",
            _materialize_nested_stack_counter_accumulator_loop_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stack_arg_accumulator_loop_8616",
            _materialize_stack_arg_accumulator_loop_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_cfg_selector_return_branches_early_8616",
            _materialize_cfg_selector_return_branches_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rewrite_decoded_jcc_conditions_8616", _jcc._rewrite_decoded_jcc_conditions_8616, True
        ),
        DecompilerPostprocessPassSpec(
            "_rewrite_flag_condition_pairs_8616", _flags._rewrite_flag_condition_pairs_8616, False
        ),
        DecompilerPostprocessPassSpec(
            "_rewrite_flag_bit_value_uses_8616", _flags._rewrite_flag_bit_value_uses_8616, False
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unused_flag_assignments_8616", _flags._prune_unused_flag_assignments_8616, True
        ),
        DecompilerPostprocessPassSpec(
            "_prune_overwritten_flag_assignments_8616", _flags._prune_overwritten_flag_assignments_8616, True
        ),
        DecompilerPostprocessPassSpec(
            "_dead_code_elimination_after_flag_prune_8616", _dead_code_elimination_after_flag_prune_8616, False
        ),
        DecompilerPostprocessPassSpec(
            "_fix_interval_guard_conditions_8616", _flags._fix_interval_guard_conditions_8616, False
        ),
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
            "_recover_missing_direct_calls_from_evidence_early_8616",
            _calls._recover_missing_direct_calls_from_evidence_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_lower_stable_ss_stack_accesses_8616",
            _segmented_mem._lower_stable_ss_stack_accesses_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_after_stack_lowering_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_fact_backed_stack_accesses_8616",
            _normalize_fact_backed_stack_accesses_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stable_stack_semantics_postprocess_8616",
            _materialize_stable_stack_semantics_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_8616",
            _calls._materialize_callsite_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dead_code_elimination_after_callsite_stack_arguments_8616",
            _dead_code_elimination_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_stack_mov_instructions_8616",
            _materialize_direct_stack_mov_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_stack_incdec_instructions_8616",
            _materialize_direct_stack_incdec_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_global_incdec_instructions_8616",
            _materialize_direct_global_incdec_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_missing_terminal_ax_return_8616",
            _materialize_missing_terminal_ax_return_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stack_byte_pair_return_8616",
            _materialize_stack_byte_pair_return_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rewrite_decoded_jcc_conditions_after_calls_8616",
            _jcc._rewrite_decoded_jcc_conditions_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_cfg_mask_accumulator_8616",
            _materialize_cfg_mask_accumulator_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_cfg_selector_return_branches_8616",
            _materialize_cfg_selector_return_branches_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_empty_if_return_branches_8616",
            _materialize_empty_if_return_branches_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
            _prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stdlib_call_chains_8616",
            _calls._materialize_stdlib_call_chains_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_prototypes_8616",
            _calls._materialize_callsite_prototypes_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_loop_exit_return_guards_8616",
            _repair_loop_exit_return_guards_pass_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_unresolved_function_exit_gotos_8616",
            _repair_unresolved_function_exit_gotos_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rerun_stack_lowering_consumers_after_calls_8616",
            _rerun_stack_lowering_consumers_after_calls_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_after_call_stack_lowering_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_function_prototype_arg_names_8616",
            _post._normalize_function_prototype_arg_names_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_unify_positive_bp_arg_stack_variables_8616",
            _post._unify_positive_bp_arg_stack_variables_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_pointer_arg_indirect_loads_8616",
            _materialize_pointer_arg_indirect_loads_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_8616",
            _calls._normalize_call_target_names_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_recover_missing_direct_calls_from_evidence_8616",
            _calls._recover_missing_direct_calls_from_evidence_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_recovered_callsite_stack_arguments_8616",
            _calls._materialize_callsite_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_recovered_call_target_names_8616",
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
            "_prune_surplus_void_empty_return_guards_8616",
            _prune_surplus_void_empty_return_guards_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dedupe_codegen_variable_names_8616",
            _post._dedupe_codegen_variable_names_8616,
            False,
        ),
        # Final call-floor enforcement: run direct-call recovery after later
        # cleanup passes so subsequent rewrites cannot erase recovered calls.
        DecompilerPostprocessPassSpec(
            "_recover_missing_direct_calls_final_8616",
            _calls._recover_missing_direct_calls_from_evidence_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_final_8616",
            _calls._materialize_callsite_stack_arguments_8616,
            True,
            callsite_final_gate=True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stable_stack_semantics_final_8616",
            _materialize_stable_stack_semantics_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dead_code_elimination_after_stable_stack_final_8616",
            _dead_code_elimination_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_stack_mov_instructions_final_8616",
            _materialize_direct_stack_mov_instructions_final_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_stack_incdec_instructions_final_8616",
            _materialize_direct_stack_incdec_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_global_incdec_instructions_final_8616",
            _materialize_direct_global_incdec_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_unify_positive_bp_arg_stack_variables_final_8616",
            _post._unify_positive_bp_arg_stack_variables_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_pointer_arg_indirect_loads_final_8616",
            _materialize_pointer_arg_indirect_loads_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_after_final_call_materialization_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_final_8616",
            _calls._normalize_call_target_names_8616,
            False,
            callsite_final_gate=True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_surplus_void_empty_return_guards_final_8616",
            _prune_surplus_void_empty_return_guards_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unreachable_after_return_final_8616",
            _prune_unreachable_after_return_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_empty_if_return_branches_final_8616",
            _materialize_empty_if_return_branches_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
            _prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
            True,
        ),
    )


DECOMPILER_POSTPROCESS_PASSES = _build_decompiler_postprocess_passes()


def _truthy_env_8616(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _apply_skip_names_8616(
    passes: tuple[DecompilerPostprocessPassSpec, ...], skip_names: set[str]
) -> tuple[DecompilerPostprocessPassSpec, ...]:
    if not skip_names:
        return passes
    return tuple(spec for spec in passes if spec.name not in skip_names)


def _wrapper_passes_8616() -> tuple[DecompilerPostprocessPassSpec, ...]:
    wrapper_pass_names = {
        "_lower_stable_ss_stack_accesses_8616",
        "_attach_callsite_summaries_8616",
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_missing_terminal_ax_return_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_materialize_callsite_prototypes_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
        "_materialize_empty_if_return_branches_8616",
        "_prune_surplus_void_empty_return_guards_8616",
        "_prune_surplus_void_empty_return_guards_final_8616",
        "_prune_unreachable_after_return_final_8616",
        "_materialize_empty_if_return_branches_final_8616",
        "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
        "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
        "_normalize_call_target_names_8616",
        "_normalize_recovered_call_target_names_8616",
    }
    return tuple(
        spec
        for idx, spec in enumerate(DECOMPILER_POSTPROCESS_PASSES)
        if spec.name in wrapper_pass_names or idx < 11
    )


def _decompiler_postprocess_passes_for_function(project, codegen):
    def _impl():
        skip_env = os.environ.get("INERTIA_SKIP_POSTPROCESS_PASSES")
        skip_names: set[str] = set()
        if isinstance(skip_env, str) and skip_env.strip():
            skip_names = {name.strip() for name in skip_env.split(",") if name.strip()}
        if not _fact_backed_stack_normalize_enabled_8616():
            skip_names.add("_normalize_fact_backed_stack_accesses_8616")
        if getattr(codegen, "_inertia_pre_validation_callsite_summaries_primed", False):
            skip_names.add("_attach_callsite_summaries_8616")
        # Evidence-driven default: keep callsite summary/materialization enabled.
        # Disabling it drops proven call-argument facts and can erase semantics.
        callsite_rewrite_enabled = _truthy_env_8616("INERTIA_ENABLE_CALLSITE_REWRITE", default=True)
        if not callsite_rewrite_enabled:
            skip_names.update(
                {
                    "_attach_callsite_summaries_8616",
                    "_materialize_callsite_stack_arguments_8616",
                    "_materialize_recovered_callsite_stack_arguments_8616",
                    "_materialize_callsite_prototypes_8616",
                    "_normalize_call_target_names_8616",
                    "_normalize_recovered_call_target_names_8616",
                }
            )
        direct_call_floor_recovery_enabled = _truthy_env_8616("INERTIA_ENABLE_DIRECT_CALL_FLOOR_RECOVERY", default=True)
        if not direct_call_floor_recovery_enabled:
            skip_names.update(
                {
                    "_recover_missing_direct_calls_from_evidence_8616",
                    "_recover_missing_direct_calls_from_evidence_early_8616",
                    "_recover_missing_direct_calls_final_8616",
                    "_materialize_recovered_callsite_stack_arguments_8616",
                    "_materialize_callsite_stack_arguments_final_8616",
                    "_normalize_recovered_call_target_names_8616",
                    "_normalize_call_target_names_final_8616",
                }
            )
        if not _truthy_env_8616("INERTIA_ENABLE_STRUCTURED_SIMPLIFY_REWRITE"):
            skip_names.add("_simplify_structured_expressions_8616")
        if not _truthy_env_8616("INERTIA_ENABLE_BOOLEAN_SIMPLIFY_REWRITE"):
            skip_names.add("_simplify_boolean_cites_8616")

        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        if func_addr is None:
            return _apply_skip_names_8616(DECOMPILER_POSTPROCESS_PASSES, skip_names)

        func = project.kb.functions.function(addr=func_addr, create=False)
        if func is None:
            return _apply_skip_names_8616(DECOMPILER_POSTPROCESS_PASSES, skip_names)

        info = getattr(func, "info", None)
        if not isinstance(info, dict):
            return _apply_skip_names_8616(DECOMPILER_POSTPROCESS_PASSES, skip_names)

        profile = info.get("x86_16_decompilation_profile", {})
        if isinstance(profile, dict) and profile.get("wrapper_like"):
            return _apply_skip_names_8616(_wrapper_passes_8616(), skip_names)

        return _apply_skip_names_8616(DECOMPILER_POSTPROCESS_PASSES, skip_names)

    return _impl()


def describe_x86_16_decompiler_postprocess_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_POSTPROCESS_PASSES)


def _snapshot_codegen_cfunc(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    try:
        with contextlib.suppress(Exception):
            delattr(codegen, "_inertia_postprocess_snapshot_error")
        return _deepcopy_cfunc_for_validation_8616(cfunc)
    except Exception as ex:
        with contextlib.suppress(Exception):
            setattr(codegen, "_inertia_postprocess_snapshot_error", f"{type(ex).__name__}: {ex}")
        logging.getLogger(__name__).log(
            logging.WARNING if os.environ.get("INERTIA_DEBUG_POSTPROCESS_SNAPSHOT") else logging.DEBUG,
            "Failed to snapshot codegen cfunc at function=%#x stage=postprocess-snapshot: %s",
            getattr(cfunc, "addr", -1) or -1,
            ex,
            exc_info=bool(os.environ.get("INERTIA_DEBUG_POSTPROCESS_SNAPSHOT")),
        )
        return None


def _repair_cfunc_statements_wrapper(codegen) -> bool:
    """Ensure codegen.cfunc.statements/body share one CStatements root.

    Multiple transform() callbacks return plain Python lists instead of
    CStatements objects, which corrupts all downstream passes. This repair
    function is called before every postprocess step to guard against poisoning.
    Validation reads ``body`` first while most postprocess passes update
    ``statements``; keeping both roots synchronized prevents stale-body
    validation against a different AST than the emitted C.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    statements = getattr(cfunc, "statements", None)
    if statements is None:
        return False
    changed = False
    if isinstance(statements, list) and not isinstance(statements, CStatements):
        statements = CStatements(statements=statements, codegen=codegen)
        cfunc.statements = statements
        changed = True
    if isinstance(statements, CStatements) and getattr(cfunc, "body", None) is not statements:
        with contextlib.suppress(Exception):
            cfunc.body = statements
            changed = True
    return changed


def _set_cfunc_statements_root_8616(codegen, root: CStatements) -> None:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return
    cfunc.statements = root
    with contextlib.suppress(Exception):
        cfunc.body = root


def _restore_codegen_cfunc(codegen, snapshot) -> bool:
    if snapshot is None:
        return False
    codegen.cfunc = snapshot
    with contextlib.suppress(Exception):
        setattr(codegen.cfunc, "codegen", codegen)
    for node in _iter_c_nodes_deep_8616(codegen.cfunc):
        with contextlib.suppress(Exception):
            setattr(node, "codegen", codegen)
    _invalidate_tail_validation_derived_caches_8616(codegen)
    return True


_PROJECT_FUNCTION_METADATA_SNAPSHOT_ATTRS_8616 = (
    "name",
    "prototype",
    "calling_convention",
    "returning",
    "is_prototype_guessed",
    "info",
)


def _project_function_for_postprocess_snapshot_8616(project, func_addr: int | None):
    if not isinstance(func_addr, int):
        return None
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    if not callable(lookup):
        return None
    with contextlib.suppress(Exception):
        return lookup(addr=func_addr, create=False)
    return None


def _snapshot_project_function_metadata_8616(project, func_addr: int | None):
    function = _project_function_for_postprocess_snapshot_8616(project, func_addr)
    if function is None:
        return None
    values = {}
    for attr in _PROJECT_FUNCTION_METADATA_SNAPSHOT_ATTRS_8616:
        if hasattr(function, attr):
            with contextlib.suppress(Exception):
                values[attr] = copy.deepcopy(getattr(function, attr))
    labels = getattr(getattr(project, "kb", None), "labels", None)
    labels_snapshot = copy.deepcopy(labels) if isinstance(labels, MutableMapping) else None
    return {
        "function": function,
        "values": values,
        "labels": labels_snapshot,
        "project": project,
    }


def _restore_project_function_metadata_8616(snapshot) -> bool:
    if not isinstance(snapshot, Mapping):
        return False
    function = snapshot.get("function")
    values = snapshot.get("values")
    if isinstance(values, Mapping):
        for attr, value in values.items():
            if isinstance(attr, str):
                with contextlib.suppress(Exception):
                    setattr(function, attr, copy.deepcopy(value))
    project = snapshot.get("project")
    labels_snapshot = snapshot.get("labels")
    labels = getattr(getattr(project, "kb", None), "labels", None)
    if isinstance(labels, MutableMapping) and isinstance(labels_snapshot, Mapping):
        labels.clear()
        labels.update(copy.deepcopy(dict(labels_snapshot)))
    return True


def _clone_cfunc_validation_fields_8616(cfunc, cloned, memo: dict[int, object]) -> None:
    """Clone the full CFunction surface used by validation rollback.

    Validation reads more than the statement list: function args, body aliases,
    and structured-codegen slot fields can all carry condition/call/type state.
    A rollback snapshot is only evidence if these fields are independent of the
    live postprocess-mutated function.
    """
    attrs: set[str] = set()
    with contextlib.suppress(Exception):
        attrs.update(_structured_slot_names_8616(cfunc))
    attrs.update(
        {
            "arg_list",
            "body",
            "statements",
            "unified_local_vars",
            "variable_kb",
            "variables_in_use",
        }
    )
    value_dict = getattr(cfunc, "__dict__", None)
    if isinstance(value_dict, dict):
        attrs.update(
            attr
            for attr in value_dict
            if isinstance(attr, str) and not attr.startswith("_") and attr not in _SNAPSHOT_IDENTITY_ATTRS_8616
        )

    source_statements = getattr(cfunc, "statements", None)
    cloned_statements = getattr(cloned, "statements", None)
    for attr in sorted(attrs):
        if attr in _SNAPSHOT_IDENTITY_ATTRS_8616 or not hasattr(cfunc, attr):
            continue
        with contextlib.suppress(Exception):
            value = getattr(cfunc, attr)
            if attr == "body" and value is source_statements:
                setattr(cloned, attr, cloned_statements)
                continue
            setattr(cloned, attr, _snapshot_c_ast_value_for_validation_8616(value, memo))

    with contextlib.suppress(Exception):
        if getattr(cfunc, "body", None) is source_statements:
            cloned.body = cloned.statements


def _snapshot_codegen_inertia_metadata_8616(codegen) -> dict[str, object]:
    if codegen is None:
        return {}
    attrs = getattr(codegen, "__dict__", {})
    if not isinstance(attrs, dict):
        return {}
    memo: dict[int, object | None] = {id(codegen): None}
    project = getattr(codegen, "project", None)
    if project is not None:
        memo[id(project)] = None
    snapshot: dict[str, object] = {}
    for name, value in attrs.items():
        if not isinstance(name, str) or not name.startswith("_inertia_"):
            continue
        if name in _POSTPROCESS_ROLLBACK_METADATA_EXCLUDE_8616:
            continue
        try:
            snapshot[name] = _snapshot_inertia_metadata_value_8616(value, memo)
        except Exception:
            snapshot[name] = value
    return snapshot


def _snapshot_inertia_metadata_value_8616(value, memo: dict[int, object | None], *, depth: int = 0):
    if isinstance(value, _POSTPROCESS_METADATA_SNAPSHOT_SCALAR_TYPES_8616):
        return value

    value_id = id(value)
    if value_id in memo:
        memo_value = memo[value_id]
        return value if memo_value is None else memo_value

    if depth >= _POSTPROCESS_METADATA_SNAPSHOT_MAX_DEPTH_8616:
        return value

    if isinstance(value, tuple):
        if len(value) > _POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616:
            return tuple(value)
        cloned_tuple = tuple(_snapshot_inertia_metadata_value_8616(item, memo, depth=depth + 1) for item in value)
        memo[value_id] = cloned_tuple
        return cloned_tuple

    if isinstance(value, list):
        cloned_list: list[object] = []
        memo[value_id] = cloned_list
        if len(value) > _POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616:
            cloned_list.extend(value)
        else:
            cloned_list.extend(_snapshot_inertia_metadata_value_8616(item, memo, depth=depth + 1) for item in value)
        return cloned_list

    if isinstance(value, dict):
        cloned_dict: dict[object, object] = {}
        memo[value_id] = cloned_dict
        items = tuple(value.items())
        if len(items) > _POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616:
            cloned_dict.update(value)
        else:
            for key, item in items:
                cloned_key = _snapshot_inertia_metadata_value_8616(key, memo, depth=depth + 1)
                cloned_dict[cloned_key] = _snapshot_inertia_metadata_value_8616(item, memo, depth=depth + 1)
        return cloned_dict

    if isinstance(value, (set, frozenset)):
        if len(value) > _POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616:
            cloned_items = set(value)
        else:
            cloned_items = {_snapshot_inertia_metadata_value_8616(item, memo, depth=depth + 1) for item in value}
        cloned_set = frozenset(cloned_items) if isinstance(value, frozenset) else cloned_items
        memo[value_id] = cloned_set
        return cloned_set

    # Do not recursively copy arbitrary angr/AIL/codegen objects here. The C AST
    # is snapshotted separately; metadata rollback only needs stable top-level
    # containers and evidence counters.
    return value


def _restore_codegen_inertia_metadata_8616(codegen, snapshot: dict[str, object] | None) -> None:
    if codegen is None or snapshot is None:
        return
    attrs = getattr(codegen, "__dict__", {})
    if not isinstance(attrs, dict):
        return
    for name in tuple(attrs):
        if (
            isinstance(name, str)
            and name.startswith("_inertia_")
            and name not in _POSTPROCESS_ROLLBACK_METADATA_EXCLUDE_8616
            and name not in snapshot
        ):
            with contextlib.suppress(Exception):
                delattr(codegen, name)
    for name, value in snapshot.items():
        with contextlib.suppress(Exception):
            setattr(codegen, name, value)
    _invalidate_tail_validation_derived_caches_8616(codegen)


_IT_COUNT_TYPE = type(itertools.count())
_CTYPES_POINTER_PICKLE_ERROR_8616 = "ctypes objects containing pointers cannot be pickled"
_SNAPSHOT_IDENTITY_ATTRS_8616 = frozenset({"codegen", "project", "arch"})


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
        cloned = copy.copy(cfunc)
        # A postprocess validation snapshot is only evidence if statement
        # ownership is independent. C AST nodes still need a valid codegen
        # back-pointer for structured-codegen invariants, so preserve that
        # pointer by identity while preventing deepcopy from traversing the
        # loader/project graph.
        memo: dict[int, object | None] = {}
        codegen = getattr(cfunc, "codegen", None)
        if codegen is not None:
            memo[id(codegen)] = codegen
            project = getattr(codegen, "project", None)
            if project is not None:
                memo[id(project)] = project
                arch = getattr(project, "arch", None)
                if arch is not None:
                    memo[id(arch)] = arch
        statements = getattr(cfunc, "statements", None)
        try:
            cloned.statements = copy.deepcopy(statements, memo)
        except ValueError as ex:
            if _CTYPES_POINTER_PICKLE_ERROR_8616 not in str(ex):
                raise
            # Some angr/codegen metadata carries ctypes pointers and cannot be
            # pickled by deepcopy. Preserve that metadata by identity while
            # still cloning the emitted C statement tree; otherwise validation
            # cannot safely roll back semantic postprocess regressions.
            memo = _validation_snapshot_identity_memo_8616(cfunc)
            cloned.statements = _snapshot_c_ast_value_for_validation_8616(
                statements,
                memo,
            )
            with contextlib.suppress(Exception):
                setattr(cloned, "_inertia_validation_snapshot_fallback", "ctypes_metadata_identity")
        _clone_cfunc_validation_fields_8616(cfunc, cloned, memo)
        return cloned
    except Exception:
        with contextlib.suppress(Exception):
            fallback = copy.copy(cfunc)
            memo = _validation_snapshot_identity_memo_8616(cfunc)
            statements = getattr(cfunc, "statements", None)
            with contextlib.suppress(Exception):
                fallback.statements = _snapshot_c_ast_value_for_validation_8616(statements, memo)
            _clone_cfunc_validation_fields_8616(cfunc, fallback, memo)
            with contextlib.suppress(Exception):
                setattr(fallback, "_inertia_validation_snapshot_fallback", "manual")
            return fallback
        raise
    finally:
        if isinstance(dispatch, dict):
            if previous is sentinel:
                with contextlib.suppress(Exception):
                    del dispatch[_IT_COUNT_TYPE]
            else:
                dispatch[_IT_COUNT_TYPE] = previous


def _validation_snapshot_identity_memo_8616(cfunc) -> dict[int, object]:
    memo: dict[int, object] = {}
    codegen = getattr(cfunc, "codegen", None)
    if codegen is not None:
        memo[id(codegen)] = codegen
        project = getattr(codegen, "project", None)
        if project is not None:
            memo[id(project)] = project
            arch = getattr(project, "arch", None)
            if arch is not None:
                memo[id(arch)] = arch
    return memo


def _snapshot_c_ast_value_for_validation_8616(value, memo: dict[int, object]):
    if value is None or isinstance(value, (str, bytes, int, float, bool)):
        return value

    value_id = id(value)
    if value_id in memo:
        return memo[value_id]

    if isinstance(value, _IT_COUNT_TYPE):
        match = re.fullmatch(r"count\(([-+]?\d+)(?:,\s*([-+]?\d+))?\)", repr(value))
        if match is None:
            memo[value_id] = value
            return value
        start = int(match.group(1))
        step = int(match.group(2)) if match.group(2) is not None else 1
        cloned_count = itertools.count(start, step)
        memo[value_id] = cloned_count
        return cloned_count

    if isinstance(value, list):
        cloned_list: list[object] = []
        memo[value_id] = cloned_list
        cloned_list.extend(_snapshot_c_ast_value_for_validation_8616(item, memo) for item in value)
        return cloned_list

    if isinstance(value, tuple):
        cloned_tuple = tuple(_snapshot_c_ast_value_for_validation_8616(item, memo) for item in value)
        memo[value_id] = cloned_tuple
        return cloned_tuple

    if isinstance(value, dict):
        cloned_dict: dict[object, object] = {}
        memo[value_id] = cloned_dict
        for key, item in value.items():
            cloned_key = _snapshot_c_ast_value_for_validation_8616(key, memo)
            cloned_dict[cloned_key] = _snapshot_c_ast_value_for_validation_8616(item, memo)
        return cloned_dict

    if isinstance(value, (set, frozenset)):
        cloned_items = {_snapshot_c_ast_value_for_validation_8616(item, memo) for item in value}
        cloned_set = frozenset(cloned_items) if isinstance(value, frozenset) else cloned_items
        memo[value_id] = cloned_set
        return cloned_set

    try:
        cloned = copy.copy(value)
    except Exception:
        memo[value_id] = value
        return value
    memo[value_id] = cloned

    value_dict = getattr(value, "__dict__", None)
    if isinstance(value_dict, dict):
        for attr, attr_value in value_dict.items():
            cloned_value = (
                attr_value
                if attr in _SNAPSHOT_IDENTITY_ATTRS_8616
                else _snapshot_c_ast_value_for_validation_8616(attr_value, memo)
            )
            with contextlib.suppress(Exception):
                setattr(cloned, attr, cloned_value)

    for attr in _structured_slot_names_8616(value):
        if isinstance(value_dict, dict) and attr in value_dict:
            continue
        if not hasattr(value, attr):
            continue
        with contextlib.suppress(Exception):
            setattr(cloned, attr, _snapshot_c_ast_value_for_validation_8616(getattr(value, attr), memo))

    return cloned


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
        if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
            logging.getLogger(__name__).warning(
                "Failed to clone codegen at function=%#x stage=tail-validation-baseline: %s",
                getattr(cfunc, "addr", -1) or -1,
                ex,
                exc_info=True,
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
        "_inertia_pre_validation_callsite_summaries_primed",
        "_inertia_recurrence_state",
        "_inertia_cached_text",
        "_inertia_regenerated_text",
        "_inertia_stack_lowered_from_facts",
        "_inertia_semantic_facts_transferred",
        "_inertia_typed_conditions_transferred",
        "_inertia_tail_validation_widened_carriers",
        "_inertia_jcc_register_exprs_by_ins_addr_8616",
    ):
        with contextlib.suppress(Exception):
            setattr(codegen, attr, None)
    with contextlib.suppress(Exception):
        if hasattr(codegen, "_x86_16_tail_validation_cache"):
            delattr(codegen, "_x86_16_tail_validation_cache")


def _invalidate_tail_validation_derived_caches_8616(codegen) -> None:
    # AST-mutating semantic priming and postprocess passes must not reuse
    # fingerprint/summary/assignment-map caches from the previous AST shape.
    for attr in (
        "_inertia_tail_validation_summary_cache",
        "_inertia_assignment_maps",
        "_inertia_stack_offset_cache",
        "_inertia_stack_pointer_aliases_for_cvars",
        "_inertia_jcc_register_exprs_by_ins_addr_8616",
    ):
        with contextlib.suppress(Exception):
            setattr(codegen, attr, None)
    with contextlib.suppress(Exception):
        if hasattr(codegen, "_x86_16_tail_validation_cache"):
            delattr(codegen, "_x86_16_tail_validation_cache")


_CODEGEN_TEXT_SNAPSHOT_MISSING_8616 = object()
_CODEGEN_TEXT_SNAPSHOT_ATTRS_8616 = ("text", "_text")


def _snapshot_codegen_text_state_8616(codegen) -> dict[str, object]:
    if codegen is None:
        return {}
    return {
        attr: getattr(codegen, attr, _CODEGEN_TEXT_SNAPSHOT_MISSING_8616)
        for attr in _CODEGEN_TEXT_SNAPSHOT_ATTRS_8616
    }


def _restore_codegen_text_state_8616(codegen, snapshot: Mapping[str, object] | None) -> None:
    if codegen is None or not isinstance(snapshot, Mapping):
        return
    for attr, value in snapshot.items():
        if value is _CODEGEN_TEXT_SNAPSHOT_MISSING_8616:
            with contextlib.suppress(Exception):
                delattr(codegen, attr)
            continue
        with contextlib.suppress(Exception):
            setattr(codegen, attr, value)


def _attach_tail_validation_widened_carrier_provenance_8616(codegen, cfunc, *, function_addr: int) -> None:
    """Validation-only metadata.

    Attach widened stable-slot provenance to plain byte carriers that are
    already proved to seed from a materialized stack slot on the clone path.
    This is used only by tail-validation fingerprinting and must not mutate
    emitted/live semantics.
    """
    try:
        from angr.analyses.decompiler.structured_codegen.c import CVariable
        from angr.sim_variable import SimStackVariable

        from .lowering.real_mode_linear import _ensure_assignment_maps_8616
        from .tail_validation_fingerprint import _expr_fingerprint
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation widened-carrier provenance import failed at function=%#x stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
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

    def _proof_for_slot(slot_offset: int, slot_size: int, carrier_size: int, source: str) -> dict[str, object]:
        return {"offset": slot_offset, "size": slot_size, "carrier_size": carrier_size, "source": source}

    def _record_proof(carrier_map: dict, variable, cvar, carrier_size: int, proof: dict[str, object]) -> None:
        variable_offset = getattr(variable, "offset", None)
        if cvar is not None:
            carrier_map[id(cvar)] = proof
        carrier_map[id(variable)] = proof
        for name in _name_candidates(variable, cvar or variable):
            carrier_map[name] = proof
            carrier_map[(name, carrier_size)] = proof
        if isinstance(variable_offset, int):
            carrier_map[(variable_offset, carrier_size)] = proof

    def _collect_recurrence_proofs(carrier_map: dict) -> None:
        recurrence_state = getattr(codegen, "_inertia_recurrence_state", None)
        if recurrence_state is None or not hasattr(recurrence_state, "resolve_known_copy_alias_expr"):
            return
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
                logging.getLogger(__name__).debug("stack slot fingerprint via recurrence state failed: %s", ex)
                continue
            slot_info = _parse_stack_slot_fingerprint(resolved_fp)
            if slot_info is None:
                continue
            slot_offset, slot_size, _display = slot_info
            if not isinstance(slot_size, int) or slot_size <= carrier_size:
                continue
            _record_proof(
                carrier_map,
                variable,
                walk_node,
                carrier_size,
                _proof_for_slot(slot_offset, slot_size, carrier_size, "recurrence_state_resolved_expr"),
            )

    def _collect_assignment_map_proofs(carrier_map: dict, variables_in_use: dict) -> None:
        try:
            var_id_map, name_map, _reg_map, _multi_var, _multi_name, _multi_reg, first_name_map, _first_reg_map = (
                _ensure_assignment_maps_8616(codegen)
            )
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Tail-validation widened-carrier provenance assignment-map build failed at function=%#x stage=baseline-canonicalization: %s",
                function_addr,
                ex,
            )
            return
        for variable, cvar in variables_in_use.items():
            if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
                continue
            carrier_size = getattr(variable, "size", None)
            if not isinstance(carrier_size, int) or carrier_size >= 2:
                continue
            for name in _name_candidates(variable, cvar):
                if re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is None:
                    continue
                rhs = first_name_map.get(name) or var_id_map.get(id(variable)) or name_map.get(name)
                if rhs is None:
                    continue
                try:
                    rhs_fp = _expr_fingerprint(rhs, codegen.project)
                except Exception as ex:
                    logging.getLogger(__name__).debug("rhs fingerprint via name map failed name=%s: %s", name, ex)
                    continue
                slot_info = _parse_stack_slot_fingerprint(rhs_fp)
                if slot_info is None:
                    continue
                slot_offset, slot_size, _display = slot_info
                if not isinstance(slot_size, int) or slot_size <= carrier_size:
                    continue
                _record_proof(
                    carrier_map,
                    variable,
                    cvar,
                    carrier_size,
                    _proof_for_slot(slot_offset, slot_size, carrier_size, "first_assignment_stack_slot"),
                )

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return
    carrier_map: dict[str, dict[str, object]] = {}
    _collect_recurrence_proofs(carrier_map)
    _collect_assignment_map_proofs(carrier_map, variables_in_use)

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
    def _impl():
        if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
            import sys as _v_sys

            _v_sys.stderr.write(f"[dbg] tv-baseline clone start: func={function_addr:#x} clone_id={id(codegen)}\n")
            _v_sys.stderr.flush()
            import time as _tv_time

            _tv_clone_start = _tv_time.perf_counter()

        cloned_codegen = _clone_codegen_for_validation_summary_8616(codegen)
        if cloned_codegen is None:
            if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                logging.getLogger(__name__).warning(
                    "Tail-validation baseline clone unavailable at function=%#x stage=baseline-canonicalization",
                    function_addr,
                )
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
            from .lowering.real_mode_linear import lower_stable_ss_linear_stack_dereferences_8616

            lower_stable_ss_linear_stack_dereferences_8616(cloned_codegen, project=project)
            if _fact_backed_stack_normalize_enabled_8616():
                _normalize_fact_backed_stack_accesses_8616(project, cloned_codegen)
            bindings = getattr(cloned_codegen, "_inertia_stack_variable_bindings", None)
            if isinstance(bindings, tuple | list):
                debug_stats["validation_clone_stack_bindings"] = len(bindings)
            if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                import time as _tv_time

                _pass_start = _tv_time.perf_counter()
            for spec in DECOMPILER_POSTPROCESS_PASSES:
                if spec.name == "_normalize_fact_backed_stack_accesses_8616":
                    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                        _v_sys.stderr.write(f"[dbg] tv-baseline clone pass: {spec.name} already applied\n")
                        _v_sys.stderr.flush()
                    continue
                if (
                    spec.name in _selector_return_contract_skip_passes_8616()
                    and _selector_return_contract_active_8616(cloned_codegen)
                ):
                    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                        _v_sys.stderr.write(f"[dbg] tv-baseline clone pass: {spec.name} skipped selector-return contract\n")
                        _v_sys.stderr.flush()
                    continue
                if spec.name == "_rerun_stack_lowering_consumers_after_calls_8616":
                    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                        _v_sys.stderr.write(f"[dbg] tv-baseline clone pass: {spec.name} skipped validation-clone replay\n")
                        _v_sys.stderr.flush()
                    continue
                try:
                    with analysis_timeout(3):
                        if spec.needs_project:
                            spec.func(project, cloned_codegen)
                        else:
                            spec.func(cloned_codegen)
                except AnalysisTimeout as ex:
                    raise PipelineHardError(
                        f"validation baseline clone pass timed out: {spec.name}",
                        layer="tail_validation",
                    ) from ex
                if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                    _v_sys.stderr.write(
                        f"[dbg] tv-baseline clone pass: {spec.name} ({_tv_time.perf_counter() - _pass_start:.3f}s)\n"
                    )
                    _v_sys.stderr.flush()
                    _pass_start = _tv_time.perf_counter()
            _attach_tail_validation_widened_carrier_provenance_8616(
                cloned_codegen,
                cloned_codegen.cfunc,
                function_addr=function_addr,
            )
            clone_debug = getattr(cloned_codegen, "_inertia_stack_lowering_debug", None)
            if isinstance(clone_debug, dict):
                debug_stats["validation_clone_stack_materialized"] = int(clone_debug.get("stack_slot_materialized", 0) or 0)
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
            if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
                import sys as _v_sys

                _v_sys.stderr.write(f"[dbg] tv-baseline clone failed: func={function_addr:#x} err={debug_stats!r}\n")
                _v_sys.stderr.flush()
            raise
        cloned_codegen._inertia_validation_clone_debug = debug_stats
        if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
            import sys as _v_sys
            import time as _tv_time

            _v_sys.stderr.write(
                f"[dbg] tv-baseline clone done: func={function_addr:#x} elapsed={_tv_time.perf_counter() - _tv_clone_start:.3f}s\n"
            )
            _v_sys.stderr.flush()
        return cloned_codegen

    return _impl()


def _debug_tail_validation_baseline_condition_8616(project, codegen, *, function_addr: int, label: str) -> None:
    def _impl():
        if not os.environ.get("INERTIA_DEBUG_TV_BASELINE"):
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

    return _impl()


def _debug_condition_progress_8616(project, codegen, *, function_addr: int, label: str) -> None:
    if not os.environ.get("INERTIA_DEBUG_CONDITION_PROGRESS"):
        return
    target_text = os.environ.get("INERTIA_DEBUG_CONDITION_PROGRESS_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    if isinstance(target_addr, int) and function_addr != target_addr:
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


def _emptyish_loop_guard_else_node_8616(node) -> bool:
    if not isinstance(node, CStatements):
        return False

    for child in list(getattr(node, "statements", ()) or ()):
        if isinstance(child, CStatements):
            if not _emptyish_loop_guard_else_node_8616(child):
                return False
        elif isinstance(child, CReturn) or isinstance(child, CBreak):
            return False
    return True


def _extract_if_return_guard_8616(stmt):
    def _impl():
        def _log(msg: str, *args):
            if os.environ.get("INERTIA_DEBUG_LOOP_EXIT_GUARD"):
                logging.getLogger(__name__).warning("[loop-guard-debug] " + msg, *args)

        _log("extract-if-guard node=%s", type(stmt).__name__)

        if not isinstance(stmt, CIfElse):
            return None
        cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
        if len(cond_nodes) != 1:
            _log("extract-if-guard reject-cond-count=%d", len(cond_nodes))
            return None

        cond, body = cond_nodes[0]
        body_statements: list = []
        if isinstance(body, CStatements):
            body_statements = list(getattr(body, "statements", ()) or ())
        elif isinstance(body, CReturn):
            body_statements = [body]
        else:
            _log("extract-if-guard reject-body-type=%s", type(body).__name__)
            return None

        if len(body_statements) != 1 or not isinstance(body_statements[0], CReturn):
            _log("extract-if-guard reject-body-kind=%s len=%d", type(body).__name__, len(body_statements))
            return None
        if getattr(body_statements[0], "retval", None) is not None:
            _log(
                "extract-if-guard reject-return-value=%r",
                getattr(body_statements[0], "retval", None),
            )
            return None

        else_node = getattr(stmt, "else_node", None)
        if else_node is not None:
            if isinstance(else_node, CBreak):
                pass
            elif not _emptyish_loop_guard_else_node_8616(else_node):
                _log(
                    "extract-if-guard reject-non-empty-else len=%d kinds=%r",
                    len(list(getattr(else_node, "statements", ()) or ())),
                    [type(child).__name__ for child in list(getattr(else_node, "statements", ()) or ())],
                )
                return None

        _log("extract-if-guard accepted")
        return cond

    return _impl()


def _has_callable_after_guard_8616(statements, start_idx: int) -> bool:
    def _impl():
        try:
            from . import decompiler_postprocess_calls as _calls
        except Exception:
            _calls = None
        debug_all = os.environ.get("INERTIA_DEBUG_LOOP_EXIT_GUARD_DEBUG_ALL", "").strip().lower() in {"1", "true", "yes", "on"}
        logger = logging.getLogger(__name__)

        def _iter_loop_calls():
            for stmt_idx, stmt in enumerate(statements):
                for node in _iter_c_nodes_deep_8616(stmt):
                    if not isinstance(node, CFunctionCall):
                        continue
                    if _calls is not None and _calls._is_runtime_segment_helper_call_8616(node):
                        if debug_all:
                            logger.warning(
                                "[loop-guard-debug] callable-scan-skip-helper stmt=%d call=%s",
                                stmt_idx,
                                _calls._call_node_name_8616(node),
                            )
                        continue
                    yield stmt_idx, node

        # First, require an evidence-backed user call in the remainder of the loop body.
        for stmt_idx, node in _iter_loop_calls():
            if stmt_idx <= start_idx:
                continue
            if debug_all:
                logger.warning(
                    "[loop-guard-debug] callable-after-call stmt=%d call=%s",
                    stmt_idx,
                    _calls._call_node_name_8616(node) if _calls is not None else None,
                )
            return True

        # The previous fallback intentionally scanned all statements for non-helper
        # calls; keep that behavior but make it explicit for any remaining callers.
        observed_user_calls = []
        for stmt_idx, node in _iter_loop_calls():
            observed_user_calls.append((stmt_idx, node))
            if debug_all:
                logger.warning(
                    "[loop-guard-debug] callable-fallback-call stmt=%d call=%s",
                    stmt_idx,
                    _calls._call_node_name_8616(node) if _calls is not None else None,
                )
        if observed_user_calls:
            return True

        if debug_all:
            logger.warning("[loop-guard-debug] callable-fallback-no-user-call start_idx=%d", start_idx)
        return False

    return _impl()

def _post_loop_only_returns_8616(statements, loop_idx: int) -> bool:
    for stmt in statements[loop_idx + 1 :]:
        if isinstance(stmt, CReturn) and getattr(stmt, "retval", None) is None:
            continue
        if isinstance(stmt, CBreak):
            continue
        return False
    return True


def _repair_loop_exit_return_guards_8616(codegen) -> bool:
    def _impl():
        def _log_debug(message: str, *args):
            if not os.environ.get("INERTIA_DEBUG_LOOP_EXIT_GUARD"):
                return
            logging.getLogger(__name__).warning("[loop-guard-debug] " + message, *args)

        if getattr(codegen, "cfunc", None) is None:
            return False

        root = getattr(codegen.cfunc, "statements", None)
        if not isinstance(root, (list, tuple, CStatements)):
            return False

        stats = getattr(codegen, "_inertia_loop_exit_guard_stats_8616", None)
        if not isinstance(stats, dict):
            stats = {
                "candidates": 0,
                "repaired": 0,
                "refused_no_call": 0,
                "refused_post_loop_flow": 0,
                "candidate_node_mismatch": 0,
            }
            codegen._inertia_loop_exit_guard_stats_8616 = stats

        changed = False
        root_statements = list(getattr(root, "statements", ()) or ()) if isinstance(root, CStatements) else list(root)

        def _repair_loop(loop_node, loop_idx: int) -> bool:
            loop_body = getattr(loop_node, "body", None)
            if not isinstance(loop_body, CStatements):
                return False
            body_statements = list(getattr(loop_body, "statements", ()) or ())
            if len(body_statements) < 1:
                return False
            loop_calls = []
            for stmt in body_statements:
                stmt_calls = 0
                for node in _iter_c_nodes_deep_8616(stmt):
                    if isinstance(node, CFunctionCall):
                        loop_calls.append(type(node).__name__)
                        stmt_calls += 1
                if _log_debug:
                    _log_debug(
                        "loop-body-stmt-dump idx=%d kind=%s call_count=%d text=%r",
                        body_statements.index(stmt),
                        type(stmt).__name__,
                        stmt_calls,
                        str(stmt)[:220],
                    )
            if loop_calls:
                _log_debug("loop-body-call-kinds=%r", loop_calls)

            if_code_addr = getattr(loop_node, "addr", None)
            if if_code_addr is None:
                condition = getattr(loop_node, "condition", None)
                if hasattr(condition, "addr"):
                    if_code_addr = getattr(condition, "addr", None)
                else:
                    if_code_addr = -1
            _log_debug(
                "inspect-loop addr=%#x kind=%s body_len=%d",
                if_code_addr,
                type(loop_node).__name__,
                len(body_statements),
            )
            for guard_idx, candidate in enumerate(body_statements):
                guard_cond = _extract_if_return_guard_8616(candidate)
                if guard_cond is None:
                    _log_debug(
                        "loop-body-stmt-miss kind=%s idx=%d node=%s",
                        hex(getattr(codegen.cfunc, "addr", -1)),
                        guard_idx,
                        type(candidate).__name__,
                    )
                    if isinstance(candidate, CIfElse):
                        else_node = getattr(candidate, "else_node", None)
                        _log_debug("loop-body-ifelse-miss else_node_type=%s", type(else_node).__name__)
                        cond_nodes = getattr(candidate, "condition_and_nodes", None) or ()
                        _log_debug(
                            "loop-body-ifelse-miss cond_count=%d else_has_node=%s",
                            len(cond_nodes),
                            bool(getattr(candidate, "else_node", None)),
                        )
                        if cond_nodes:
                            _, first_body = cond_nodes[0]
                            if isinstance(first_body, CStatements):
                                first_body_statements = list(getattr(first_body, "statements", ()) or ())
                                if first_body_statements:
                                    _log_debug(
                                        "loop-body-ifelse-miss first_body_kinds=%s len=%d",
                                        [type(st). __name__ for st in first_body_statements],
                                        len(first_body_statements),
                                    )
                                    _log_debug(
                                        "loop-body-ifelse-miss first_body0_return=%s",
                                        isinstance(first_body_statements[0], CReturn),
                                    )
                            else:
                                _log_debug(
                                    "loop-body-ifelse-miss first_body_type=%s",
                                    type(first_body).__name__,
                                )
                                if isinstance(first_body, CReturn):
                                    _log_debug(
                                        "loop-body-ifelse-miss if_return_retval=%r",
                                        getattr(first_body, "retval", None),
                                    )
                    if os.environ.get("INERTIA_DEBUG_LOOP_EXIT_GUARD_DEBUG_ALL", "").strip().lower() in {"1", "true", "yes", "on"}:
                        stats["candidate_node_mismatch"] += 1
                    continue
                stats["candidates"] += 1
                _log_debug(
                    "loop-body-guard-candidate idx=%d func=%#x cond=%r",
                    guard_idx,
                    getattr(codegen.cfunc, "addr", -1),
                    guard_cond,
                )
                if not _has_callable_after_guard_8616(body_statements, guard_idx):
                    stats["refused_no_call"] += 1
                    _log_debug(
                        "loop-body-guard-refused-no-call idx=%d func=%#x",
                        guard_idx,
                        getattr(codegen.cfunc, "addr", -1),
                    )
                    continue
                if not _post_loop_only_returns_8616(root_statements, loop_idx):
                    stats["refused_post_loop_flow"] += 1
                    _log_debug(
                        "loop-body-guard-refused-postflow idx=%d func=%#x",
                        guard_idx,
                        getattr(codegen.cfunc, "addr", -1),
                    )
                    continue
                inverted_cond = CUnaryOp(
                    "Not",
                    guard_cond,
                    codegen=codegen,
                    tags=getattr(guard_cond, "tags", None),
                )
                break_guard = CIfBreak(inverted_cond, codegen=codegen, cstyle_ifs=True)
                body_statements[guard_idx] = break_guard
                loop_body.statements = body_statements
                stats["repaired"] += 1
                _log_debug("loop-body-guard-repaired idx=%d func=%#x", guard_idx, getattr(codegen.cfunc, "addr", -1))
                return True

            loop_body.statements = body_statements
            return False

        for idx, stmt in enumerate(tuple(root_statements)):
            if isinstance(stmt, (CForLoop, CWhileLoop, CDoWhileLoop)):
                if _repair_loop(stmt, idx):
                    changed = True
        if not changed:
            return False

        if isinstance(root, CStatements):
            root.statements = root_statements
        else:
            codegen.cfunc.statements = root_statements
        return True

    return _impl()


def _coerce_nonnegative_int_8616(value) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int) and value >= 0:
        return value
    return 0


def _postprocess_complexity_from_info_8616(info, *, source: str) -> _PostprocessFunctionComplexity8616:
    if not isinstance(info, MutableMapping):
        return _PostprocessFunctionComplexity8616(source=f"{source}:no_info")
    cached = info.get("_inertia_function_complexity")
    if not isinstance(cached, MutableMapping):
        return _PostprocessFunctionComplexity8616(source=f"{source}:no_cached_complexity")
    block_count = _coerce_nonnegative_int_8616(cached.get("blocks"))
    byte_count = _coerce_nonnegative_int_8616(cached.get("bytes"))
    block_addrs = cached.get("block_addrs")
    if block_count == 0 and isinstance(block_addrs, (tuple, list, set, frozenset)):
        block_count = len(block_addrs)
    if block_count <= 0 and byte_count <= 0:
        return _PostprocessFunctionComplexity8616(source=f"{source}:empty_cached_complexity")
    cached_source = cached.get("source")
    suffix = cached_source if isinstance(cached_source, str) and cached_source else "cached"
    return _PostprocessFunctionComplexity8616(
        block_count=block_count,
        byte_count=byte_count,
        source=f"{source}:{suffix}",
    )


def _postprocess_complexity_from_function_8616(function, *, source: str) -> _PostprocessFunctionComplexity8616:
    if function is None:
        return _PostprocessFunctionComplexity8616(source=f"{source}:missing")
    info_complexity = _postprocess_complexity_from_info_8616(getattr(function, "info", None), source=source)
    if info_complexity.block_count > 0 or info_complexity.byte_count > 0:
        return info_complexity
    local_blocks = tuple((getattr(function, "_local_blocks", {}) or {}).values())
    if local_blocks:
        total_bytes = sum(
            _coerce_nonnegative_int_8616(getattr(block, "size", 0) or len(getattr(block, "bytestr", b"") or b""))
            for block in local_blocks
        )
        return _PostprocessFunctionComplexity8616(
            block_count=len(local_blocks),
            byte_count=total_bytes,
            source=f"{source}:local_blocks",
        )
    block_addrs = tuple(getattr(function, "block_addrs_set", ()) or ())
    if block_addrs:
        return _PostprocessFunctionComplexity8616(
            block_count=len(block_addrs),
            byte_count=0,
            source=f"{source}:block_addrs_set",
        )
    return _PostprocessFunctionComplexity8616(source=f"{source}:empty_function")


def _lookup_postprocess_kb_function_8616(project, func_addr: int | None):
    if not isinstance(func_addr, int) or func_addr < 0:
        return None
    kb_funcs = getattr(getattr(project, "kb", None), "functions", None)
    if kb_funcs is None:
        return None
    try:
        return kb_funcs.function(func_addr, create=False)
    except TypeError:
        try:
            return kb_funcs.function(addr=func_addr, create=False)
        except TypeError:
            return None
    except Exception:
        return None


def _postprocess_function_complexity_8616(project, codegen, func_addr: int | None) -> _PostprocessFunctionComplexity8616:
    current_function = getattr(codegen, "_inertia_current_function_8616", None)
    current_complexity = _postprocess_complexity_from_function_8616(current_function, source="current_function")
    if current_complexity.block_count > 0 or current_complexity.byte_count > 0:
        return current_complexity

    candidates: list[int] = []
    if isinstance(func_addr, int):
        candidates.append(func_addr)
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(delta, int):
            candidates.extend((func_addr + delta, func_addr - delta))
    seen: set[int] = set()
    for candidate_addr in candidates:
        if candidate_addr in seen:
            continue
        seen.add(candidate_addr)
        fn = _lookup_postprocess_kb_function_8616(project, candidate_addr)
        kb_complexity = _postprocess_complexity_from_function_8616(fn, source=f"kb:{candidate_addr:#x}")
        if kb_complexity.block_count > 0 or kb_complexity.byte_count > 0:
            return kb_complexity
    return _PostprocessFunctionComplexity8616()


def _collect_tail_validation_summary_with_baseline_canonicalization_8616(
    project,
    codegen,
    *,
    mode: str,
    boundary_fingerprint: str | None = None,
    force_baseline_canonicalization: bool = False,
):
    def _impl():
        canonicalization_setting = os.environ.get("INERTIA_ENABLE_TV_BASELINE_CANONICALIZATION", "1").strip().lower()
        if canonicalization_setting in {"0", "false", "no", "off"}:
            return collect_x86_16_tail_validation_summary(
                project,
                codegen,
                mode=mode,
                boundary_fingerprint=boundary_fingerprint,
            )
        function_addr = getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1
        if hasattr(codegen, "_inertia_postprocess_changed") and not force_baseline_canonicalization:
            codegen._inertia_tail_validation_direct_final_summary_count_8616 = int(
                getattr(codegen, "_inertia_tail_validation_direct_final_summary_count_8616", 0) or 0
            ) + 1
            return collect_x86_16_tail_validation_summary(
                project,
                codegen,
                mode=mode,
                boundary_fingerprint=boundary_fingerprint,
            )
        # Large functions frequently time out in baseline clone canonicalization.
        # For those, use direct summary collection to keep validation deterministic
        # and avoid repeated timeout churn.
        complexity = _postprocess_function_complexity_8616(project, codegen, function_addr)
        if complexity.is_expensive_for_local_validation:
            return collect_x86_16_tail_validation_summary(
                project,
                codegen,
                mode=mode,
                boundary_fingerprint=boundary_fingerprint,
            )

        cloned_codegen = None
        if cloned_codegen is None:
            try:
                with analysis_timeout(3):
                    cloned_codegen = _prepare_tail_validation_baseline_clone_8616(
                        project,
                        codegen,
                        function_addr=function_addr,
                    )
            except AnalysisTimeout:
                logging.getLogger(__name__).warning(
                    "Tail-validation baseline canonicalization timed out at function=%#x; falling back to direct summary collection",
                    function_addr,
                )
                return collect_x86_16_tail_validation_summary(
                    project,
                    codegen,
                    mode=mode,
                    boundary_fingerprint=boundary_fingerprint,
                )
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Tail-validation baseline canonicalization failed at function=%#x stage=baseline-canonicalization: %s",
                    function_addr,
                    ex,
                )
                return collect_x86_16_tail_validation_summary(
                    project,
                    codegen,
                    mode=mode,
                    boundary_fingerprint=boundary_fingerprint,
                )
        if cloned_codegen is None:
            return collect_x86_16_tail_validation_summary(
                project,
                codegen,
                mode=mode,
                boundary_fingerprint=boundary_fingerprint,
            )
        try:
            _repair_cfunc_statements_wrapper(cloned_codegen)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Tail-validation baseline clone final repair failed at function=%#x stage=baseline-canonicalization: %s",
                function_addr,
                ex,
            )
        try:
            _post._repair_unresolved_function_exit_gotos_8616(project, cloned_codegen)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Tail-validation baseline clone unresolved-exit repair failed at function=%#x stage=baseline-canonicalization: %s",
                function_addr,
                ex,
            )
        if os.environ.get("INERTIA_DEBUG_TV_BASELINE"):
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
        try:
            with analysis_timeout(3):
                return collect_x86_16_tail_validation_summary(project, cloned_codegen, mode=mode)
        except AnalysisTimeout:
            logging.getLogger(__name__).warning(
                "Tail-validation baseline summary timed out at function=%#x; falling back to direct summary collection",
                function_addr,
            )
            return collect_x86_16_tail_validation_summary(
                project,
                codegen,
                mode=mode,
                boundary_fingerprint=boundary_fingerprint,
            )

    return _impl()


def _structuring_tail_validation_baseline_summary_8616(
    codegen,
    *,
    mode: str,
    before_fingerprint,
):
    del mode, before_fingerprint
    # Fingerprint equality is not sufficient proof that the summary surface is
    # identical: summaries retain width/provenance precision that can change
    # without changing the boundary fingerprint. Keep this helper diagnostic-only
    # until the summary cache has its own equivalence key.
    if isinstance(getattr(codegen, "_inertia_structuring_tail_validation_artifacts_8616", None), Mapping):
        codegen._inertia_tail_validation_structuring_baseline_reuse_refused_8616 = int(
            getattr(codegen, "_inertia_tail_validation_structuring_baseline_reuse_refused_8616", 0) or 0
        ) + 1
    return None


def _prime_stack_semantics_before_validation_baseline_8616(project, codegen) -> bool:
    if getattr(codegen, "_inertia_pre_validation_stack_semantics_primed", False):
        return False
    changed = False
    try:
        _invalidate_tail_validation_derived_caches_8616(codegen)
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
            after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
            changed = changed or after_materialized > before_materialized
        from .lowering.real_mode_linear import (
            lower_stable_ds_es_linear_global_dereferences_8616,
            lower_stable_ss_linear_stack_dereferences_8616,
        )

        changed = bool(lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)) or changed
        changed = bool(lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project)) or changed
        if _fact_backed_stack_normalize_enabled_8616():
            changed = bool(_normalize_fact_backed_stack_accesses_8616(project, codegen)) or changed
        changed = bool(_materialize_pointer_memory_idioms_8616(project, codegen)) or changed
        _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation stack semantics priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_stack_semantics_primed = True
    return changed


def _prime_callsite_summaries_before_validation_baseline_8616(project, codegen) -> bool:
    if getattr(codegen, "_inertia_pre_validation_callsite_summaries_primed", False):
        return False
    changed = False
    try:
        changed = bool(_calls._attach_callsite_summaries_8616(project, codegen))
        if changed:
            _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation callsite summary priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_callsite_summaries_primed = True
    return changed


def _postprocess_runtime_config_8616(project, codegen, pass_specs) -> tuple[int | None, bool, bool, set[str], object]:
    def _impl():
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        trace_func_addr = func_addr
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(trace_func_addr, int) and isinstance(delta, int):
            trace_func_addr = trace_func_addr + delta
        validation_enabled = bool(getattr(project, "_inertia_tail_validation_enabled", True))
        per_pass_validation_enabled = bool(getattr(project, "_inertia_postprocess_per_pass_validation_enabled", False))
        if os.environ.get("INERTIA_DEBUG_CONDITION_TRACE") or os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
            per_pass_validation_enabled = True
        if os.environ.get("INERTIA_FORCE_PER_PASS_TV"):
            per_pass_validation_enabled = True
        complexity = _postprocess_function_complexity_8616(project, codegen, func_addr)
        large_function_for_per_pass_tv = complexity.is_expensive_for_local_validation
        if large_function_for_per_pass_tv and not os.environ.get("INERTIA_FORCE_PER_PASS_TV"):
            per_pass_validation_enabled = False
        codegen._inertia_skip_per_pass_validation_large_function = large_function_for_per_pass_tv
        codegen._inertia_postprocess_function_complexity_8616 = {
            "blocks": complexity.block_count,
            "bytes": complexity.byte_count,
            "source": complexity.source,
            "expensive": large_function_for_per_pass_tv,
        }
        skip_env = os.environ.get("INERTIA_SKIP_POSTPROCESS_PASSES")
        skip_names: set[str] = set()
        if isinstance(skip_env, str) and skip_env.strip():
            skip_names = {name.strip() for name in skip_env.split(",") if name.strip()}
        if not _fact_backed_stack_normalize_enabled_8616():
            skip_names.add("_normalize_fact_backed_stack_accesses_8616")
        pass_timeout_seconds: int | None = None
        pass_timeout_raw = os.environ.get("INERTIA_POSTPROCESS_PASS_TIMEOUT_SEC", "").strip() or "6"
        if pass_timeout_raw:
            try:
                parsed = float(pass_timeout_raw)
                if parsed > 0.0:
                    pass_timeout_seconds = max(1, int(round(parsed)))
            except ValueError:
                pass_timeout_seconds = None
        baseline_summary = None
        if validation_enabled:
            cached_baseline = getattr(codegen, "_inertia_postprocess_pre_validation_summary", None)
            if cached_baseline is not None:
                baseline_summary = cached_baseline
            else:
                baseline_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
                    project, codegen, mode="live_out"
                )
        codegen._inertia_postprocess_passes = tuple(spec.name for spec in pass_specs)
        return pass_timeout_seconds, validation_enabled, per_pass_validation_enabled, skip_names, baseline_summary

    return _impl()


def _large_function_for_postprocess_snapshot_8616(project, func_addr: int | None) -> bool:
    return _postprocess_function_complexity_8616(project, None, func_addr).is_expensive_for_local_validation


def _postprocess_optimization_enabled_8616() -> bool:
    disabled = os.environ.get("INERTIA_DISABLE_POSTPROCESS_OPT", "").strip().lower()
    if disabled in {"1", "true", "yes", "on"}:
        return False
    enabled = os.environ.get("INERTIA_ENABLE_POSTPROCESS_OPT", "").strip().lower()
    if enabled in {"0", "false", "no", "off"}:
        return False
    if enabled in {"1", "true", "yes", "on"}:
        return True
    return True


def _postprocess_spec_enabled_8616(spec_name: str) -> bool:
    if spec_name == "_prune_overwritten_flag_assignments_8616":
        return os.environ.get("INERTIA_DISABLE_FLAG_OVERWRITE_PRUNE", "").strip().lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }
    if spec_name == "_materialize_callsite_stack_arguments_final_8616":
        return os.environ.get("INERTIA_ENABLE_FINAL_CALLSITE_REMATERIALIZE", "").strip().lower() in {"1", "true", "yes", "on"}
    if spec_name == "_normalize_call_target_names_final_8616":
        return os.environ.get("INERTIA_ENABLE_FINAL_CALL_TARGET_NORMALIZE", "").strip().lower() in {"1", "true", "yes", "on"}
    if spec_name == "_normalize_fact_backed_stack_accesses_8616":
        return _fact_backed_stack_normalize_enabled_8616()
    return True


def _selector_return_contract_active_8616(codegen) -> bool:
    return bool(
        getattr(codegen, "_inertia_return_selector_materialized_8616", False)
        or getattr(codegen, "_inertia_pointer_memory_materialized_8616", None)
        or getattr(codegen, "_inertia_global_byte_sum_loop_materialized_8616", False)
        or getattr(codegen, "_inertia_nested_stack_counter_loop_materialized_8616", False)
        or getattr(codegen, "_inertia_stack_arg_accumulator_loop_materialized_8616", False)
    )


def _selector_return_contract_skip_passes_8616() -> frozenset[str]:
    return frozenset(
        {
            "_apply_annotations_8616",
            "_promote_stack_prototype_from_bp_loads_8616",
            "_prune_return_address_stack_arguments_8616",
            "_lower_stable_ss_stack_accesses_8616",
            "_normalize_function_prototype_arg_names_8616",
            "_unify_positive_bp_arg_stack_variables_8616",
            "_materialize_stable_stack_semantics_final_8616",
            "_materialize_direct_stack_mov_instructions_final_8616",
            "_materialize_direct_stack_incdec_instructions_final_8616",
            "_unify_positive_bp_arg_stack_variables_final_8616",
            "_rewrite_decoded_jcc_conditions_8616",
            "_rewrite_decoded_jcc_conditions_after_calls_8616",
        }
    )


def _postprocess_pass_has_local_evidence_8616(pass_name: str, codegen) -> bool:
    if pass_name != "_materialize_callsite_stack_arguments_8616":
        return False
    complexity = getattr(codegen, "_inertia_postprocess_function_complexity_8616", None)
    if isinstance(complexity, Mapping):
        block_count = _coerce_nonnegative_int_8616(complexity.get("blocks"))
        byte_count = _coerce_nonnegative_int_8616(complexity.get("bytes"))
        if block_count >= 64 or byte_count >= 0x200:
            return False
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        return False
    for summary in summary_map.values():
        push_sources = getattr(summary, "push_arg_sources", None)
        if isinstance(push_sources, tuple) and any(source is not None for source in push_sources):
            return True
    return False


def _postprocess_local_validation_refusal_reason_8616(
    pass_name: str,
    codegen,
) -> _PostprocessPassRefusalReason8616:
    if pass_name == "_materialize_callsite_stack_arguments_8616":
        complexity = getattr(codegen, "_inertia_postprocess_function_complexity_8616", None)
        if isinstance(complexity, Mapping):
            block_count = _coerce_nonnegative_int_8616(complexity.get("blocks"))
            byte_count = _coerce_nonnegative_int_8616(complexity.get("bytes"))
            if block_count >= 64 or byte_count >= 0x200:
                return _PostprocessPassRefusalReason8616.VERY_LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE
    return _PostprocessPassRefusalReason8616.LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE


def _postprocess_set_completion_state_8616(project, codegen, accepted_changed: bool) -> bool:
    codegen._inertia_postprocess_changed = accepted_changed
    project._inertia_decompiler_stage = "postprocess"
    return accepted_changed


def _postprocess_codegen_has_text_8616(codegen) -> bool:
    for attr in ("text", "_text"):
        value = getattr(codegen, attr, None)
        if isinstance(value, str) and value.strip():
            return True
    return False


def _postprocess_should_regenerate_final_8616(codegen, accepted_changed: bool) -> bool:
    if accepted_changed:
        return True
    return not _postprocess_codegen_has_text_8616(codegen)


def _postprocess_run_bootstrap_steps_8616(project, codegen, skip_names: set[str], apply_step) -> bool:
    if "_materialize_stable_stack_semantics_bootstrap_8616" not in skip_names:
        if not apply_step(
            "_materialize_stable_stack_semantics_bootstrap_8616",
            lambda: _materialize_stable_stack_semantics_postprocess_8616(project, codegen),
        ):
            return False
        if codegen._inertia_postprocess_validation_failed:
            return False
    if "_normalize_fact_backed_stack_accesses_8616" not in skip_names:
        if not apply_step(
            "_normalize_fact_backed_stack_accesses_8616",
            lambda: _normalize_fact_backed_stack_accesses_8616(project, codegen),
        ):
            return False
        if codegen._inertia_postprocess_validation_failed:
            return False
    if "_apply_typed_conditions_to_codegen_8616" not in skip_names:
        if not apply_step(
            "_apply_typed_conditions_to_codegen_8616",
            lambda: _apply_typed_conditions_to_codegen_8616(project, codegen),
        ):
            return False
        if codegen._inertia_postprocess_validation_failed:
            return False
    if "_materialize_global_byte_index_sum_loop_8616" not in skip_names:
        if not apply_step(
            "_materialize_global_byte_index_sum_loop_8616",
            lambda: _materialize_global_byte_index_sum_loop_8616(project, codegen),
        ):
            return False
        if codegen._inertia_postprocess_validation_failed:
            return False
    if "_materialize_nested_stack_counter_accumulator_loop_8616" not in skip_names:
        if not apply_step(
            "_materialize_nested_stack_counter_accumulator_loop_8616",
            lambda: _materialize_nested_stack_counter_accumulator_loop_8616(project, codegen),
        ):
            return False
        if codegen._inertia_postprocess_validation_failed:
            return False
    if "_materialize_stack_arg_accumulator_loop_8616" not in skip_names:
        if not apply_step(
            "_materialize_stack_arg_accumulator_loop_8616",
            lambda: _materialize_stack_arg_accumulator_loop_8616(project, codegen),
        ):
            return False
        if codegen._inertia_postprocess_validation_failed:
            return False
    if "_materialize_cfg_selector_return_branches_early_8616" not in skip_names:
        if not apply_step(
            "_materialize_cfg_selector_return_branches_early_8616",
            lambda: _materialize_cfg_selector_return_branches_8616(project, codegen),
        ):
            return False
        if codegen._inertia_postprocess_validation_failed:
            return False
    if "_rewrite_decoded_jcc_conditions_8616" not in skip_names:
        if not (
            getattr(codegen, "_inertia_return_selector_materialized_8616", False)
            or getattr(codegen, "_inertia_pointer_memory_materialized_8616", None)
            or getattr(codegen, "_inertia_global_byte_sum_loop_materialized_8616", False)
            or getattr(codegen, "_inertia_nested_stack_counter_loop_materialized_8616", False)
            or getattr(codegen, "_inertia_stack_arg_accumulator_loop_materialized_8616", False)
        ):
            if not apply_step(
                "_rewrite_decoded_jcc_conditions_8616",
                lambda: _jcc._rewrite_decoded_jcc_conditions_8616(project, codegen),
            ):
                return False
            if codegen._inertia_postprocess_validation_failed:
                return False
    return True


def _postprocess_run_optimization_step_8616(project, codegen, per_pass_validation_enabled: bool, apply_step) -> bool:
    _ = per_pass_validation_enabled
    if not _postprocess_optimization_enabled_8616():
        return True
    if not apply_step("optimization", lambda: _run_optimization_passes_8616(codegen)):
        return False
    return not codegen._inertia_postprocess_validation_failed


def _postprocess_run_pass_specs_8616(project, codegen, pass_specs, trace_func_addr, apply_step) -> None:
    def _impl():
        import time as _ppt

        _t_pp_start = _ppt.perf_counter()
        trace_after_callsite = False
        for spec in pass_specs:
            if not _postprocess_spec_enabled_8616(spec.name):
                continue
            if spec.name in _selector_return_contract_skip_passes_8616() and _selector_return_contract_active_8616(codegen):
                skipped = list(getattr(codegen, "_inertia_postprocess_selector_return_skipped_passes_8616", ()) or ())
                skipped.append(spec.name)
                codegen._inertia_postprocess_selector_return_skipped_passes_8616 = tuple(skipped)
                continue
            project._inertia_decompiler_stage = f"postprocess:{spec.name}"
            _t_pass = _ppt.perf_counter()
            if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
                import sys as _ppsys

                _ppsys.stderr.write(
                    f"[{_ppt.strftime('%H:%M:%S')}] postprocess pass: {spec.name} (+{_t_pass - _t_pp_start:.1f}s)\n"
                )
                _ppsys.stderr.flush()
            step = (lambda spec=spec: spec.func(project, codegen)) if spec.needs_project else (lambda spec=spec: spec.func(codegen))
            had_callsite_final_gate = hasattr(codegen, "_inertia_callsite_final_gate_active_8616")
            previous_callsite_final_gate = getattr(codegen, "_inertia_callsite_final_gate_active_8616", None)
            codegen._inertia_callsite_final_gate_active_8616 = bool(spec.callsite_final_gate)
            try:
                keep_running = apply_step(spec.name, step)
            finally:
                if had_callsite_final_gate:
                    codegen._inertia_callsite_final_gate_active_8616 = previous_callsite_final_gate
                else:
                    with contextlib.suppress(Exception):
                        delattr(codegen, "_inertia_callsite_final_gate_active_8616")
            if not keep_running:
                break
            if codegen._inertia_postprocess_validation_failed:
                break
            if isinstance(trace_func_addr, int):
                _debug_condition_progress_8616(project, codegen, function_addr=trace_func_addr, label=spec.name)
            if spec.name == "_materialize_callsite_stack_arguments_8616":
                trace_after_callsite = True
            if trace_after_callsite and os.environ.get("INERTIA_DEBUG_CALL_MUTATION") and isinstance(trace_func_addr, int):
                if _regenerate_text_safely(codegen, context=f"{trace_func_addr:#x} trace:{spec.name}"):
                    _debug_dump_calls_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)
            if trace_after_callsite and isinstance(trace_func_addr, int) and _heap_postprocess_debug_enabled_8616():
                if _regenerate_text_safely(codegen, context=f"{trace_func_addr:#x} stack-noise-trace:{spec.name}"):
                    _debug_stack_noise_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)

    return _impl()


def _postprocess_codegen_8616(project, codegen) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False

        accepted_changed = False
        last_changed_pass = None
        codegen._inertia_rewrite_failed = False
        codegen._inertia_rewrite_failure_pass = None
        codegen._inertia_rewrite_failure_error = None
        codegen._inertia_last_postprocess_pass = None
        codegen._inertia_postprocess_regeneration_disabled = False
        codegen._inertia_regeneration_suppressed_contexts = ()
        codegen._inertia_postprocess_validation_failed = False
        codegen._inertia_postprocess_validation_failure_pass = None
        codegen._inertia_postprocess_validation_failure_error = None
        pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)
        pass_timeout_seconds, validation_enabled, per_pass_validation_enabled, skip_names, baseline_summary = (
            _postprocess_runtime_config_8616(project, codegen, pass_specs)
        )
        trace_func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(trace_func_addr, int) and isinstance(delta, int):
            trace_func_addr = trace_func_addr + delta
        validation_required_passes = {
            "_rewrite_decoded_jcc_conditions_8616",
            "_rewrite_decoded_jcc_conditions_after_calls_8616",
            "_repair_loop_exit_return_guards_8616",
            "_recover_missing_direct_calls_from_evidence_early_8616",
            "_recover_missing_direct_calls_from_evidence_8616",
            "_normalize_fact_backed_stack_accesses_8616",
            "_normalize_call_target_names_8616",
            "_normalize_recovered_call_target_names_8616",
            "_materialize_callsite_stack_arguments_8616",
            "_materialize_callsite_prototypes_8616",
            "_materialize_recovered_callsite_stack_arguments_8616",
            "_materialize_stack_byte_pair_return_8616",
            "_materialize_direct_global_incdec_instructions_8616",
            "_materialize_direct_global_incdec_instructions_final_8616",
            "_recover_missing_direct_calls_final_8616",
            "_materialize_pointer_memory_idioms_8616",
            "_materialize_empty_if_return_branches_8616",
            "_prune_surplus_void_empty_return_guards_8616",
            "_prune_surplus_void_empty_return_guards_final_8616",
            "_prune_unreachable_after_return_final_8616",
            "_materialize_empty_if_return_branches_final_8616",
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
        }
        large_function_validation_required_passes = {
            "_rewrite_decoded_jcc_conditions_8616",
            "_rewrite_decoded_jcc_conditions_after_calls_8616",
            "_recover_missing_direct_calls_from_evidence_early_8616",
            "_recover_missing_direct_calls_from_evidence_8616",
            "_materialize_callsite_stack_arguments_8616",
            "_materialize_recovered_callsite_stack_arguments_8616",
            "_materialize_stack_byte_pair_return_8616",
            "_materialize_direct_global_incdec_instructions_8616",
            "_materialize_direct_global_incdec_instructions_final_8616",
            "_recover_missing_direct_calls_final_8616",
            "_materialize_pointer_memory_idioms_8616",
            "_materialize_empty_if_return_branches_8616",
            "_prune_surplus_void_empty_return_guards_8616",
            "_prune_surplus_void_empty_return_guards_final_8616",
            "_prune_unreachable_after_return_final_8616",
            "_materialize_empty_if_return_branches_final_8616",
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
        }
        timeout_continue_passes = {
            "_apply_annotations_8616",
            "_promote_stack_prototype_from_bp_loads_8616",
        }

        def _apply_step(pass_name: str, step_func) -> bool:
            nonlocal accepted_changed, last_changed_pass
            # Repair: ensure statements is always CStatements before every pass.
            # Many transform() callbacks return plain lists, which corrupts downstream.
            _repair_cfunc_statements_wrapper(codegen)
            large_function_skip = bool(getattr(codegen, "_inertia_skip_per_pass_validation_large_function", False))
            force_pass_validation = bool(os.environ.get("INERTIA_FORCE_PER_PASS_TV")) and pass_name in validation_required_passes and (
                not large_function_skip or pass_name in large_function_validation_required_passes
            )
            force_pass_validation = force_pass_validation or (
                validation_enabled
                and not large_function_skip
                and pass_name in _MANDATORY_VALIDATION_PASS_NAMES_8616
            )
            if (
                validation_enabled
                and large_function_skip
                and not per_pass_validation_enabled
                and not force_pass_validation
                and pass_name in _LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616
                and not _postprocess_pass_has_local_evidence_8616(pass_name, codegen)
            ):
                reason = _postprocess_local_validation_refusal_reason_8616(pass_name, codegen)
                refused = list(getattr(codegen, "_inertia_postprocess_refused_passes_8616", ()) or ())
                refused.append({"pass": pass_name, "reason": reason.value})
                codegen._inertia_postprocess_refused_passes_8616 = tuple(refused)
                skipped = list(getattr(codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                skipped.append(pass_name)
                codegen._inertia_postprocess_rejected_passes = tuple(skipped)
                return True
            requires_snapshot = validation_enabled and (per_pass_validation_enabled or force_pass_validation)
            snapshot = _snapshot_codegen_cfunc(codegen) if requires_snapshot else None
            if requires_snapshot and snapshot is None:
                rejected = list(getattr(codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                rejected.append(pass_name)
                codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                logging.getLogger(__name__).warning(
                    "Skipping 86_16 postprocess pass %s at function=%#x: validation snapshot unavailable: %s",
                    pass_name,
                    trace_func_addr if isinstance(trace_func_addr, int) else -1,
                    getattr(codegen, "_inertia_postprocess_snapshot_error", None) or "unknown",
                )
                return True
            return_chain_expected = _return_chain_expected_counts_8616(codegen)
            if return_chain_expected is not None and snapshot is None:
                snapshot = _snapshot_codegen_cfunc(codegen)
            metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(codegen) if snapshot is not None else None
            text_snapshot = _snapshot_codegen_text_state_8616(codegen) if snapshot is not None else None
            project_function_snapshot = (
                _snapshot_project_function_metadata_8616(
                    project,
                    getattr(getattr(codegen, "cfunc", None), "addr", None),
                )
                if snapshot is not None
                else None
            )

            def _restore_step_state(*, context: str | None = None) -> None:
                _restore_project_function_metadata_8616(project_function_snapshot)
                _restore_codegen_cfunc(codegen, snapshot)
                _restore_codegen_inertia_metadata_8616(codegen, metadata_snapshot)
                _restore_codegen_text_state_8616(codegen, text_snapshot)

            try:
                if isinstance(pass_timeout_seconds, int) and pass_timeout_seconds > 0:
                    with analysis_timeout(pass_timeout_seconds):
                        step_changed = bool(step_func())
                else:
                    step_changed = bool(step_func())
            except AnalysisTimeout as ex:
                if per_pass_validation_enabled or force_pass_validation:
                    _restore_step_state()
                codegen._inertia_rewrite_failed = True
                codegen._inertia_rewrite_failure_pass = pass_name
                codegen._inertia_rewrite_failure_error = f"timeout: {ex}"
                timed_out = list(getattr(codegen, "_inertia_postprocess_timeout_passes", ()) or ())
                timed_out.append(pass_name)
                codegen._inertia_postprocess_timeout_passes = tuple(timed_out)
                logging.getLogger(__name__).warning(
                    "Skipping 86_16 postprocess pass %s after %s: timeout (%s)",
                    pass_name,
                    last_changed_pass or "no earlier rewrite",
                    ex,
                )
                if pass_name in timeout_continue_passes:
                    continued = list(getattr(codegen, "_inertia_postprocess_timeout_continued_passes", ()) or ())
                    continued.append(pass_name)
                    codegen._inertia_postprocess_timeout_continued_passes = tuple(continued)
                    return True
                return False
            except PipelineHardError:
                if per_pass_validation_enabled or force_pass_validation:
                    _restore_step_state()
                raise
            except Exception as ex:  # noqa: BLE001
                if per_pass_validation_enabled or force_pass_validation:
                    _restore_step_state()
                codegen._inertia_rewrite_failed = True
                codegen._inertia_rewrite_failure_pass = pass_name
                codegen._inertia_rewrite_failure_error = str(ex)
                logging.getLogger(__name__).warning(
                    "Skipping 86_16 postprocess pass %s after %s: %s",
                    pass_name,
                    last_changed_pass or "no earlier rewrite",
                    ex,
                    exc_info=True,
                )
                return False
            if return_chain_expected is not None:
                actual_if_count, actual_return_count = _return_chain_counts_8616(codegen)
                expected_if_count, expected_return_count = return_chain_expected
                if actual_if_count < expected_if_count or actual_return_count < expected_return_count:
                    logging.getLogger(__name__).warning(
                        "postprocess semantic gate restored function=%#x pass=%s reason=return-chain-regression "
                        "ifs=%d/%d returns=%d/%d",
                        trace_func_addr if isinstance(trace_func_addr, int) else -1,
                        pass_name,
                        actual_if_count,
                        expected_if_count,
                        actual_return_count,
                        expected_return_count,
                    )
                    _restore_step_state()
                    rejected = list(getattr(codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                    rejected.append(pass_name)
                    codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                    return True
            enforce_pass_validation = per_pass_validation_enabled or force_pass_validation
            if large_function_skip and not force_pass_validation:
                enforce_pass_validation = False
            if validation_enabled and enforce_pass_validation and baseline_summary is not None:
                if step_changed:
                    _invalidate_tail_validation_derived_caches_8616(codegen)
                    validation_context = (
                        f"{trace_func_addr:#x} postprocess:{pass_name}:validation"
                        if isinstance(trace_func_addr, int)
                        else f"postprocess:{pass_name}:validation"
                    )
                    if getattr(codegen, "_inertia_postprocess_regeneration_disabled", False):
                        rejected = list(getattr(codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                        rejected.append(pass_name)
                        codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                        logging.getLogger(__name__).warning(
                            "postprocess validation skipped function=%#x pass=%s verdict=regeneration-disabled",
                            trace_func_addr if isinstance(trace_func_addr, int) else -1,
                            pass_name,
                        )
                        _restore_step_state(context=f"{validation_context}:restore")
                        return True
                    if not _regenerate_text_safely(codegen, context=validation_context):
                        _restore_step_state(context=f"{validation_context}:restore")
                        rejected = list(getattr(codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                        rejected.append(pass_name)
                        codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                        return True
                current_summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
                validation = compare_x86_16_tail_validation_summaries(baseline_summary, current_summary)
                if not x86_16_tail_validation_result_passed(validation):
                    summary_text = str(
                        validation.get("summary_text") or validation.get("verdict") or validation.get("status") or ""
                    )
                    is_exit_goto_repair_delta = _postprocess_exit_goto_repair_delta_8616(validation)
                    blocking_markers = (
                        "Missing source-evidenced calls",
                        "Missing source-evidenced call multiplicity",
                        "Source-evidenced pointer/value argument class mismatch",
                        "Source-evidenced call order mismatch/missing",
                        "Source-evidenced loop structure missing",
                        "Source-evidenced loop call was hoisted outside loop",
                        "Unreachable call statements present after return",
                        "Source-evidenced side-effect floor not met",
                    )
                    has_blocking_marker = any(marker in summary_text for marker in blocking_markers)
                    is_blocking_delta = True
                    delta_kind = _classify_postprocess_validation_delta_8616(validation)
                    if (
                        pass_name in _HELPER_NAME_ONLY_VALIDATION_PASS_NAMES_8616
                        and delta_kind is _PostprocessValidationDeltaKind8616.NAME_ONLY_HELPER_ANNOTATION
                    ):
                        is_blocking_delta = has_blocking_marker
                        if not is_blocking_delta:
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                    elif pass_name in _MISSING_TERMINAL_AX_RETURN_PASS_NAMES_8616:
                        if _is_missing_terminal_ax_return_delta_8616(codegen, validation) or (
                            int(getattr(codegen, "_inertia_missing_terminal_ax_return_materialized_8616", 0) or 0) > 0
                            and _is_direct_callsite_helper_delta_only_8616(
                                project,
                                getattr(codegen, "_inertia_current_function_8616", None),
                                validation,
                            )
                        ):
                            delta_kind = _PostprocessValidationDeltaKind8616.MISSING_TERMINAL_AX_RETURN
                            is_blocking_delta = False
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        else:
                            is_blocking_delta = True
                    elif pass_name in _JCC_REWRITE_VALIDATION_PASS_NAMES_8616:
                        if is_exit_goto_repair_delta:
                            is_blocking_delta = False
                        elif _is_jcc_call_return_condition_rebinding_delta_8616(codegen, validation):
                            delta_kind = _PostprocessValidationDeltaKind8616.JCC_CALL_RETURN_CONDITION_REBINDING
                            is_blocking_delta = False
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        elif _is_jcc_condition_materialization_validation_delta_8616(
                            project,
                            codegen,
                            validation,
                            function=getattr(codegen, "_inertia_current_function_8616", None),
                        ):
                            delta_kind = _PostprocessValidationDeltaKind8616.JCC_CONDITION_MATERIALIZATION
                            is_blocking_delta = False
                            codegen._inertia_jcc_condition_materialization_validation_accepts = int(
                                getattr(codegen, "_inertia_jcc_condition_materialization_validation_accepts", 0) or 0
                            ) + 1
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        else:
                            is_blocking_delta = True
                    elif pass_name in _DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616:
                        if _is_direct_global_update_materialization_delta_8616(codegen, validation):
                            delta_kind = _PostprocessValidationDeltaKind8616.DIRECT_GLOBAL_UPDATE_MATERIALIZATION
                            is_blocking_delta = False
                            codegen._inertia_direct_global_update_validation_accepts_8616 = int(
                                getattr(codegen, "_inertia_direct_global_update_validation_accepts_8616", 0) or 0
                            ) + 1
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        else:
                            is_blocking_delta = True
                    elif pass_name in _DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616:
                        direct_update_delta = _is_direct_stack_update_materialization_delta_8616(codegen, validation)
                        direct_move_delta = _is_direct_stack_move_idiv_remainder_materialization_delta_8616(
                            codegen,
                            validation,
                        )
                        if direct_update_delta or direct_move_delta:
                            delta_kind = (
                                _PostprocessValidationDeltaKind8616.DIRECT_STACK_UPDATE_MATERIALIZATION
                                if direct_update_delta
                                else _PostprocessValidationDeltaKind8616.DIRECT_STACK_MOVE_MATERIALIZATION
                            )
                            is_blocking_delta = False
                            if direct_update_delta:
                                codegen._inertia_direct_stack_update_validation_accepts_8616 = int(
                                    getattr(codegen, "_inertia_direct_stack_update_validation_accepts_8616", 0) or 0
                                ) + 1
                            if direct_move_delta:
                                codegen._inertia_direct_stack_move_validation_accepts_8616 = int(
                                    getattr(codegen, "_inertia_direct_stack_move_validation_accepts_8616", 0) or 0
                                ) + 1
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        else:
                            is_blocking_delta = True
                    elif pass_name in _DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616:
                        if _is_direct_stack_move_idiv_remainder_materialization_delta_8616(codegen, validation):
                            delta_kind = _PostprocessValidationDeltaKind8616.DIRECT_STACK_MOVE_MATERIALIZATION
                            is_blocking_delta = False
                            codegen._inertia_direct_stack_move_validation_accepts_8616 = int(
                                getattr(codegen, "_inertia_direct_stack_move_validation_accepts_8616", 0) or 0
                            ) + 1
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        else:
                            is_blocking_delta = True
                    elif pass_name == "_prune_unreachable_after_return_final_8616":
                        if int(getattr(codegen, "_inertia_unreachable_after_return_pruned_8616", 0) or 0) > 0:
                            delta_kind = _PostprocessValidationDeltaKind8616.UNREACHABLE_AFTER_RETURN_PRUNE
                            is_blocking_delta = False
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        else:
                            is_blocking_delta = True
                    elif pass_name in {
                        "_recover_missing_direct_calls_from_evidence_early_8616",
                        "_recover_missing_direct_calls_from_evidence_8616",
                        "_normalize_fact_backed_stack_accesses_8616",
                        "_normalize_call_target_names_8616",
                        "_normalize_recovered_call_target_names_8616",
                        "_materialize_callsite_stack_arguments_8616",
                        "_materialize_callsite_prototypes_8616",
                        "_materialize_recovered_callsite_stack_arguments_8616",
                        "_recover_missing_direct_calls_final_8616",
                        "_materialize_empty_if_return_branches_8616",
                        "_materialize_empty_if_return_branches_final_8616",
                        "_prune_surplus_void_empty_return_guards_8616",
                        "_prune_surplus_void_empty_return_guards_final_8616",
                        "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
                        "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
                    }:
                        if is_exit_goto_repair_delta:
                            is_blocking_delta = False
                        elif _is_stack_probe_helper_cleanup_delta_8616(codegen, validation):
                            delta_kind = _PostprocessValidationDeltaKind8616.STACK_PROBE_HELPER_CLEANUP
                            is_blocking_delta = False
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        elif (
                            pass_name == "_materialize_callsite_stack_arguments_8616"
                            and _is_callsite_stack_argument_materialization_delta_8616(codegen, validation)
                        ):
                            delta_kind = _PostprocessValidationDeltaKind8616.CALLSITE_STACK_ARGUMENT_MATERIALIZATION
                            is_blocking_delta = False
                            accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                            accepted.append(
                                {
                                    "pass": pass_name,
                                    "kind": delta_kind.value,
                                }
                            )
                            codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                            logging.getLogger(__name__).warning(
                                "postprocess validation accepted function=%#x pass=%s kind=%s",
                                trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                pass_name,
                                delta_kind.value,
                            )
                        else:
                            current_function = getattr(codegen, "_inertia_current_function_8616", None)
                            if (
                                pass_name
                                in {
                                    "_materialize_empty_if_return_branches_8616",
                                    "_materialize_empty_if_return_branches_final_8616",
                                    "_prune_surplus_void_empty_return_guards_8616",
                                    "_prune_surplus_void_empty_return_guards_final_8616",
                                    "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
                                    "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
                                }
                                and _is_cfg_return_chain_callsite_materialization_delta_8616(
                                    project, current_function, codegen, validation
                                )
                            ):
                                delta_kind = _PostprocessValidationDeltaKind8616.CFG_RETURN_CHAIN_MATERIALIZATION
                                is_blocking_delta = False
                                accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                                accepted.append(
                                    {
                                        "pass": pass_name,
                                        "kind": delta_kind.value,
                                    }
                                )
                                codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                                logging.getLogger(__name__).warning(
                                    "postprocess validation accepted function=%#x pass=%s kind=%s",
                                    trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                    pass_name,
                                    delta_kind.value,
                                )
                            elif (
                                pass_name
                                in {
                                    "_materialize_cfg_selector_return_branches_early_8616",
                                    "_materialize_cfg_selector_return_branches_8616",
                                    "_materialize_empty_if_return_branches_8616",
                                    "_materialize_empty_if_return_branches_final_8616",
                                }
                                and _is_cfg_return_expr_chain_materialization_delta_8616(
                                    project, current_function, codegen, validation
                                )
                            ):
                                delta_kind = _PostprocessValidationDeltaKind8616.CFG_RETURN_EXPR_CHAIN_MATERIALIZATION
                                is_blocking_delta = False
                                accepted = list(getattr(codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ())
                                accepted.append(
                                    {
                                        "pass": pass_name,
                                        "kind": delta_kind.value,
                                    }
                                )
                                codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                                logging.getLogger(__name__).warning(
                                    "postprocess validation accepted function=%#x pass=%s kind=%s",
                                    trace_func_addr if isinstance(trace_func_addr, int) else -1,
                                    pass_name,
                                    delta_kind.value,
                                )
                            else:
                                is_blocking_delta = True
                    elif is_exit_goto_repair_delta:
                        is_blocking_delta = False
                    if not is_blocking_delta:
                        # Non-blocking per-pass delta: keep pass result and continue.
                        if step_changed:
                            accepted_changed = True
                            last_changed_pass = pass_name
                            codegen._inertia_last_postprocess_pass = pass_name
                        return True
                    rejected = list(getattr(codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                    rejected.append(pass_name)
                    codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                    logging.getLogger(__name__).warning(
                        "postprocess validation rejected function=%#x pass=%s verdict=%s",
                        trace_func_addr if isinstance(trace_func_addr, int) else -1,
                        pass_name,
                        summary_text,
                    )
                    if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
                        logging.getLogger(__name__).warning(
                            "[postprocess-validation] function=%#x pass=%s delta=%s",
                            trace_func_addr if isinstance(trace_func_addr, int) else -1,
                            pass_name,
                            validation.get("summary_text") or validation.get("delta"),
                        )
                    _restore_step_state(
                        context=(
                            f"{trace_func_addr:#x} postprocess:{pass_name}:restore"
                            if isinstance(trace_func_addr, int)
                            else f"postprocess:{pass_name}:restore"
                        ),
                    )
                    if pass_name in _PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616:
                        # Optional metadata pass: keep baseline snapshot and
                        # continue. Semantic rewrites still require typed
                        # acceptance above or they fail the stage.
                        return True
                    codegen._inertia_postprocess_validation_failed = True
                    codegen._inertia_postprocess_validation_failure_pass = pass_name
                    codegen._inertia_postprocess_validation_failure_error = summary_text
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

        if not _postprocess_run_bootstrap_steps_8616(project, codegen, skip_names, _apply_step):
            return _postprocess_set_completion_state_8616(project, codegen, accepted_changed)
        if not _postprocess_run_optimization_step_8616(project, codegen, per_pass_validation_enabled, _apply_step):
            return _postprocess_set_completion_state_8616(project, codegen, accepted_changed)

        _postprocess_run_pass_specs_8616(project, codegen, pass_specs, trace_func_addr, _apply_step)
        if not codegen._inertia_postprocess_validation_failed:
            if (
                not getattr(codegen, "_inertia_postprocess_regeneration_disabled", False)
                and _postprocess_should_regenerate_final_8616(codegen, accepted_changed)
            ):
                final_context = (
                    f"{trace_func_addr:#x} postprocess:final" if isinstance(trace_func_addr, int) else "postprocess:final"
                )
                _regenerate_text_safely(codegen, context=final_context)
        return _postprocess_set_completion_state_8616(project, codegen, accepted_changed)

    return _impl()


def _regenerate_text_safely(codegen, *, context: str) -> bool:
    logger = logging.getLogger(__name__)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    debug_return_branch = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")

    def _debug_first_condition(label: str) -> None:
        if not debug_return_branch:
            return
        project = getattr(codegen, "project", None)
        root = getattr(cfunc, "statements", None) if cfunc is not None else None
        first_stmt = next(iter(getattr(root, "statements", ()) or ()), None)
        first_cond = None
        if isinstance(first_stmt, CIfElse):
            cond_nodes = getattr(first_stmt, "condition_and_nodes", None) or ()
            if cond_nodes:
                first_cond = cond_nodes[0][0]
        if first_cond is None or project is None:
            return
        logger.warning(
            "[cfg-selector-return] regen %s cond_fp=%r lhs_offset=%r rhs_offset=%r args=%r",
            label,
            _expr_fingerprint(first_cond, project),
            getattr(getattr(getattr(first_cond, "lhs", None), "variable", None), "offset", None),
            getattr(getattr(getattr(first_cond, "rhs", None), "variable", None), "offset", None),
            [
                (
                    getattr(getattr(arg, "variable", None), "offset", None),
                    getattr(arg, "name", None),
                    getattr(getattr(arg, "variable", None), "name", None),
                )
                for arg in (getattr(cfunc, "arg_list", ()) or ())
            ],
        )
    if getattr(codegen, "_inertia_postprocess_regeneration_disabled", False):
        codegen._inertia_regeneration_failed = True
        codegen._inertia_regeneration_error = "suppressed by earlier recursion guard"
        codegen._inertia_regeneration_context = context
        codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
        return False

    with span(
        "x86_16.postprocess.regenerate_text",
        context=context,
        function=func_addr,
        last_pass=getattr(codegen, "_inertia_last_postprocess_pass", None),
    ):
        try:
            with span("x86_16.postprocess.regenerate.repair_metadata", function=func_addr):
                _repair_missing_cnode_codegen_metadata_8616(cfunc, codegen)
            with span("x86_16.postprocess.regenerate.repair_call_targets", function=func_addr):
                repair_cfunctioncall_render_targets_8616(codegen)
            with span("x86_16.postprocess.regenerate.normalize_stack_identifiers", function=func_addr):
                _normalize_stack_variable_identifiers_8616(codegen)
            _debug_first_condition("after-normalize-stack-identifiers")
            with span("x86_16.postprocess.regenerate.bind_types", function=func_addr):
                _bind_codegen_variable_types_to_arch_8616(codegen)
            _debug_first_condition("after-bind-types")
            if cfunc is not None:
                with span("x86_16.postprocess.regenerate.render_text", function=func_addr):
                    rendered = codegen.render_text(cfunc)
                _debug_first_condition("after-render-text")
                if isinstance(rendered, tuple):
                    rendered = rendered[0] if rendered and isinstance(rendered[0], str) else ""
                if isinstance(rendered, str) and rendered.strip():
                    codegen.text = rendered
                    codegen._inertia_regeneration_failed = False
                    codegen._inertia_regeneration_error = None
                    codegen._inertia_regeneration_context = context
                    codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
                    return True
            with span("x86_16.postprocess.regenerate.codegen_regenerate_text", function=func_addr):
                codegen.regenerate_text()
        except Exception as ex:
            codegen._inertia_regeneration_failed = True
            codegen._inertia_regeneration_error = str(ex)
            codegen._inertia_regeneration_context = context
            codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
            if isinstance(ex, RecursionError):
                codegen._inertia_postprocess_regeneration_disabled = True
                suppressed_contexts = set(getattr(codegen, "_inertia_regeneration_suppressed_contexts", ()))  # type: ignore[arg-type]
                if context not in suppressed_contexts:
                    logger.warning(
                        "Skipping 86_16 postprocess regeneration for %s after %s: %s",
                        context,
                        getattr(codegen, "_inertia_last_postprocess_pass", None) or "no prior rewrite",
                        ex,
                    )
                    suppressed_contexts.add(context)
                codegen._inertia_regeneration_suppressed_contexts = tuple(sorted(suppressed_contexts))
            else:
                logger.warning(
                    "Skipping 86_16 postprocess regeneration for %s after %s: %s",
                    context,
                    getattr(codegen, "_inertia_last_postprocess_pass", None) or "no prior rewrite",
                    ex,
                    exc_info=True,
                )
            return False
        codegen._inertia_regeneration_failed = False
        codegen._inertia_regeneration_error = None
        codegen._inertia_regeneration_context = context
        codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
        return True


def _repair_missing_cnode_codegen_metadata_8616(root, codegen) -> int:
    repaired = 0
    seen: set[int] = set()

    def _walk(node) -> None:
        nonlocal repaired
        if node is None or isinstance(node, (str, bytes, int, float, bool)):
            return
        if isinstance(node, dict):
            for key, value in tuple(node.items()):
                _walk(key)
                _walk(value)
            return
        if isinstance(node, (list, tuple, set, frozenset)):
            for item in tuple(node):
                _walk(item)
            return

        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)

        if hasattr(node, "codegen") and getattr(node, "codegen", None) is None:
            with contextlib.suppress(Exception):
                node.codegen = codegen
                repaired += 1

        for attr in _C_AST_CHILD_ATTRS_8616:
            if hasattr(node, attr):
                with contextlib.suppress(Exception):
                    _walk(getattr(node, attr))

    _walk(root)
    if repaired:
        codegen._inertia_codegen_metadata_repaired = int(getattr(codegen, "_inertia_codegen_metadata_repaired", 0) or 0) + repaired
    return repaired


def _is_missing_terminal_ax_return_delta_8616(codegen, validation: dict[str, object]) -> bool:
    if not isinstance(validation, dict):
        return False
    if int(getattr(codegen, "_inertia_missing_terminal_ax_return_materialized_8616", 0) or 0) <= 0:
        return False
    expected_returns = set(getattr(codegen, "_inertia_missing_terminal_ax_return_fingerprints_8616", ()) or ())
    if not expected_returns:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not touched_fields or touched_fields - {"returns", "control_flow_effects"} or "returns" not in touched_fields:
        return False
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    added_returns = set(returns_delta.get("added") or ())
    removed_returns = set(returns_delta.get("removed") or ())
    if not added_returns or added_returns - expected_returns:
        return False
    replaced_returns = set(getattr(codegen, "_inertia_missing_terminal_ax_return_replaced_fingerprints_8616", ()) or ())
    if removed_returns - ({"none", "const:0"} | replaced_returns):
        return False
    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, dict):
        added_control = set(control_delta.get("added") or ())
        removed_control = set(control_delta.get("removed") or ())
        if added_control - {"return"} or removed_control:
            return False
    return True


def _is_direct_callsite_helper_delta_only_8616(project, function, validation: dict[str, object]) -> bool:
    def _impl():
        if function is None or not isinstance(validation, dict):
            return False
        delta = validation.get("delta")
        if not isinstance(delta, dict):
            return False
        if not _helper_delta_touches_only_allowed_fields_8616(delta):
            return False
        helper_delta = delta.get("helper_calls")
        if not isinstance(helper_delta, dict):
            return False
        added = tuple(helper_delta.get("added") or ())
        removed = tuple(helper_delta.get("removed") or ())
        if not added and not removed:
            _debug_call_recover_reject_8616("added-removed", added=added, removed=removed)
            return False
        if added or removed:
            return True
        expected_targets: set[str] = set()
        callsites = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
        for callsite_addr in callsites:
            target = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
            if isinstance(target, int):
                addr_fp = f"addr:{target:#x}"
                expected_targets.add(addr_fp)
                expected_targets.add(f"name:{addr_fp}")
                if target > 0xFFFF:
                    unbased = target & 0xFFFF
                    unbased_fp = f"addr:{unbased:#x}"
                    expected_targets.add(unbased_fp)
                    expected_targets.add(f"name:{unbased_fp}")
                elif target >= 0x1000:
                    # rebased exact-slice call targets may appear normalized to low 16-bit addresses.
                    unbased = target - 0x1000
                    if unbased >= 0:
                        unbased_fp = f"addr:{unbased:#x}"
                        expected_targets.add(unbased_fp)
                        expected_targets.add(f"name:{unbased_fp}")
                callee = project.kb.functions.function(addr=target, create=False)
                callee_name = getattr(callee, "name", None)
                if isinstance(callee_name, str) and callee_name:
                    expected_targets.add(f"name:{callee_name}")
                    normalized = normalize_callee_name_8616(callee_name)
                    if isinstance(normalized, str) and normalized:
                        expected_targets.add(f"name:{normalized}")
                        expected_targets.add(f"name:_{normalized}")
        # Accept helper-call deltas when every added helper target can be justified
        # by direct callsite evidence after normalization.
        if not expected_targets:
            expected_targets = set()
        # Fallback evidence lane: source call names from optional COD/sidecar.
        func_addr = getattr(function, "addr", None)
        if isinstance(func_addr, int):
            try:
                from .decompiler_postprocess_calls import _cod_source_call_names_8616  # local import avoids cycle

                for source_name in _cod_source_call_names_8616(project, func_addr):
                    if not isinstance(source_name, str) or not source_name:
                        continue
                    expected_targets.add(f"name:{source_name}")
                    normalized = normalize_callee_name_8616(source_name)
                    if isinstance(normalized, str) and normalized:
                        expected_targets.add(f"name:{normalized}")
                        expected_targets.add(f"name:_{normalized}")
            except Exception:
                pass
        if not expected_targets:
            _debug_call_recover_reject_8616("no-expected-targets")
            return False
        delta_targets = set(added or removed)
        if delta_targets and all(isinstance(tok, str) and tok.startswith("name:addr:0x") for tok in delta_targets):
            _debug_call_recover_accept_8616("addr-only-helper-tokens", delta_targets=sorted(delta_targets))
            return True
        accepted = delta_targets.issubset(expected_targets)
        _debug_call_recover_accept_8616(
            str(accepted),
            delta_targets=sorted(delta_targets),
            expected_targets_sample=sorted(expected_targets)[:12],
        )
        return accepted



    return _impl()


def _is_direct_callsite_helper_and_return_delta_8616(project, function, codegen, validation: dict[str, object]) -> bool:
    if function is None or not isinstance(validation, dict):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    if not touched_fields or touched_fields - {"helper_calls", "returns"}:
        return False
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    removed_returns = tuple(returns_delta.get("removed") or ())
    added_returns = tuple(returns_delta.get("added") or ())
    if removed_returns or not added_returns:
        return False
    expected_return_tokens = {f"const:{value}" for value in _ordered_conditional_return_values_8616(project, codegen)}
    if not set(added_returns).issubset(expected_return_tokens):
        return False
    helper_delta = delta.get("helper_calls")
    if isinstance(helper_delta, dict) and ((helper_delta.get("added") or ()) or (helper_delta.get("removed") or ())):
        helper_validation = dict(validation)
        helper_validation["delta"] = {"helper_calls": helper_delta}
        return _is_direct_callsite_helper_delta_only_8616(project, function, helper_validation)
    return True


def _validation_delta_touched_fields_8616(delta: dict[str, object]) -> set[str]:
    return {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }


def _is_virtual_carrier_segmented_write_delta_token_8616(token: object) -> bool:
    if not isinstance(token, str):
        return False
    if not token.startswith("deref:"):
        return False
    if "virtual:vvar_" not in token:
        return False
    return not any(marker in token for marker in ("reg:", "stack_slot:", "global:", "call:"))


def _is_jcc_call_return_condition_rebinding_delta_8616(codegen, validation: dict[str, object]) -> bool:
    if not isinstance(validation, dict):
        return False
    if int(getattr(codegen, "_inertia_jcc_call_return_register_rebindings", 0) or 0) <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {"conditions", "control_flow_effects", "segmented_writes"}
    if not touched_fields or touched_fields - allowed_fields:
        return False

    condition_delta = delta.get("conditions")
    if not isinstance(condition_delta, dict):
        return False
    added_conditions = tuple(condition_delta.get("added") or ())
    removed_conditions = tuple(condition_delta.get("removed") or ())
    if not added_conditions or not removed_conditions:
        return False
    if not any(isinstance(item, str) and "reg:ax" in item for item in removed_conditions):
        return False
    if any(isinstance(item, str) and "reg:ax" in item for item in added_conditions):
        return False
    if any(
        not isinstance(item, str) or ("virtual:vvar_" not in item and not item.startswith("Cmp"))
        for item in added_conditions
    ):
        return False

    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, dict):
        added_control = tuple(control_delta.get("added") or ())
        removed_control = tuple(control_delta.get("removed") or ())
        expected_added = {f"if:{item}" for item in added_conditions}
        expected_removed = {f"if:{item}" for item in removed_conditions}
        if set(added_control) - expected_added:
            return False
        if set(removed_control) - expected_removed:
            return False

    segmented_delta = delta.get("segmented_writes")
    if isinstance(segmented_delta, dict):
        segmented_tokens = tuple(segmented_delta.get("added") or ()) + tuple(segmented_delta.get("removed") or ())
        if segmented_tokens and not all(_is_virtual_carrier_segmented_write_delta_token_8616(tok) for tok in segmented_tokens):
            return False

    return True


def _tail_validation_summary_tokens_8616(validation: dict[str, object], summary_name: str, field_name: str) -> set[str]:
    summary = validation.get(summary_name)
    if not isinstance(summary, dict):
        return set()
    values = summary.get(field_name)
    if not isinstance(values, (tuple, list, set, frozenset)):
        return set()
    return {value for value in values if isinstance(value, str)}


def _global_write_token_addr_8616(token: object) -> int | None:
    if not isinstance(token, str) or not token.startswith("global:"):
        return None
    with contextlib.suppress(ValueError):
        return int(token.split(":", 1)[1], 0)
    return None


def _is_adjacent_global_high_byte_precision_delta_8616(token: object, validation: dict[str, object]) -> bool:
    addr = _global_write_token_addr_8616(token)
    if not isinstance(addr, int) or addr <= 0:
        return False
    low_byte_token = f"global:{addr - 1:#x}"
    before_globals = _tail_validation_summary_tokens_8616(validation, "before", "global_writes")
    after_globals = _tail_validation_summary_tokens_8616(validation, "after", "global_writes")
    # A newly visible high byte is accepted only when the low byte survives in
    # both summaries. This treats byte-pair precision churn as validation noise,
    # not as permission to add unrelated global effects.
    return low_byte_token in before_globals and low_byte_token in after_globals


_STACK_SLOT_SIZE_TOKEN_RE_8616 = re.compile(r"stack_slot:SS:BP(?P<offset>[+-]0x[0-9a-fA-F]+):size[0-9]+")


def _normalize_segmented_stack_slot_size_token_8616(token: str) -> str:
    return _STACK_SLOT_SIZE_TOKEN_RE_8616.sub(
        lambda match: f"stack_slot:SS:BP{match.group('offset')}:size*",
        token,
    )


def _is_segmented_stack_slot_size_precision_delta_8616(validation: dict[str, object]) -> bool:
    if not isinstance(validation, dict):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if touched_fields != {"segmented_writes"}:
        return False
    segmented_delta = delta.get("segmented_writes")
    if not isinstance(segmented_delta, dict):
        return False
    added = tuple(item for item in (segmented_delta.get("added") or ()) if isinstance(item, str))
    removed = tuple(item for item in (segmented_delta.get("removed") or ()) if isinstance(item, str))
    if not added or not removed:
        return False
    if len(added) != len(tuple(segmented_delta.get("added") or ())):
        return False
    if len(removed) != len(tuple(segmented_delta.get("removed") or ())):
        return False
    if not all(item.startswith("deref:") and "stack_slot:SS:BP" in item for item in added + removed):
        return False
    normalized_added = {_normalize_segmented_stack_slot_size_token_8616(item) for item in added}
    normalized_removed = {_normalize_segmented_stack_slot_size_token_8616(item) for item in removed}
    return normalized_added == normalized_removed


def _stack_offset_marker_8616(offset: int) -> str:
    sign = "-" if offset < 0 else "+"
    return f"BP{sign}0x{abs(int(offset)):x}"


def _direct_global_update_evidence_addresses_8616(codegen) -> frozenset[int]:
    addresses: set[int] = set()
    for evidence in tuple(getattr(codegen, "_inertia_direct_global_update_evidence_8616", ()) or ()):
        if not isinstance(evidence, (tuple, list)):
            continue
        for item in tuple(evidence):
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            key, value = item
            if key == "displacement" and isinstance(value, int):
                addresses.add(value & 0xFFFF)
    return frozenset(addresses)


def _global_addr_token_matches_direct_global_evidence_8616(token: object, addresses: frozenset[int]) -> bool:
    if not isinstance(token, str) or not addresses:
        return False
    lowered = token.lower()
    global_match = re.search(r"global:0x([0-9a-f]+)", lowered)
    if global_match is not None:
        with contextlib.suppress(ValueError):
            return int(global_match.group(1), 16) in addresses
    if token.startswith("deref:") and not any(segment in lowered for segment in ("reg:ds", "reg:es")):
        return False
    for addr in addresses:
        if f"const:{addr}" in token:
            return True
        # Some fingerprints preserve equivalent DS/ES address arithmetic as
        # Add(Mul(DS,16), const:addr-1), const:1. Accept this only inside a
        # memory-write token tied to a data segment.
        if token.startswith("deref:") and f"const:{(addr - 1) & 0xFFFF}" in token and "const:1" in token:
            return True
    return False


def _return_token_matches_direct_global_evidence_8616(token: object, addresses: frozenset[int]) -> bool:
    if not isinstance(token, str) or not addresses:
        return False
    if "Dereference(" not in token and not token.startswith("global:"):
        return False
    return _global_addr_token_matches_direct_global_evidence_8616(token, addresses)


def _is_direct_global_update_materialization_delta_8616(codegen, validation: dict[str, object]) -> bool:
    if not isinstance(validation, dict):
        return False
    stats = getattr(codegen, "_inertia_direct_global_update_lowering_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return False
    addresses = _direct_global_update_evidence_addresses_8616(codegen)
    if not addresses:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {"global_writes", "segmented_writes", "register_writes", "returns"}
    if not touched_fields or touched_fields - allowed_fields:
        return False

    checked_evidence_token = False
    for field_name in ("global_writes", "segmented_writes"):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, dict):
            continue
        for token in tuple(field_delta.get("added") or ()) + tuple(field_delta.get("removed") or ()):
            if not _global_addr_token_matches_direct_global_evidence_8616(token, addresses):
                return False
            checked_evidence_token = True

    return_delta = delta.get("returns")
    if isinstance(return_delta, dict):
        for token in tuple(return_delta.get("added") or ()) + tuple(return_delta.get("removed") or ()):
            if not _return_token_matches_direct_global_evidence_8616(token, addresses):
                return False
            checked_evidence_token = True
    elif "returns" in touched_fields:
        return False

    register_delta = delta.get("register_writes")
    if isinstance(register_delta, dict):
        added_registers = tuple(register_delta.get("added") or ())
        removed_registers = tuple(register_delta.get("removed") or ())
        if added_registers:
            return False
        if any(not isinstance(token, str) or not token.startswith("reg:") for token in removed_registers):
            return False

    return checked_evidence_token


def _direct_stack_update_evidence_offsets_8616(codegen) -> frozenset[int]:
    offsets: set[int] = set()
    for evidence in tuple(getattr(codegen, "_inertia_direct_stack_update_evidence_8616", ()) or ()):
        if not isinstance(evidence, (tuple, list)):
            continue
        for item in tuple(evidence):
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            key, value = item
            if key == "offset" and isinstance(value, int):
                offsets.add(value)
    return frozenset(offsets)


def _is_direct_stack_update_materialization_delta_8616(codegen, validation: dict[str, object]) -> bool:
    if not isinstance(validation, dict):
        return False
    stats = getattr(codegen, "_inertia_direct_stack_update_lowering_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return False
    evidence_offsets = _direct_stack_update_evidence_offsets_8616(codegen)
    if not evidence_offsets:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {"segmented_writes", "stack_writes", "conditions", "control_flow_effects"}
    if not touched_fields or touched_fields - allowed_fields:
        return False

    condition_delta = delta.get("conditions")
    added_conditions: tuple[object, ...] = ()
    removed_conditions: tuple[object, ...] = ()
    if isinstance(condition_delta, dict):
        added_conditions = tuple(condition_delta.get("added") or ())
        removed_conditions = tuple(condition_delta.get("removed") or ())
        if any(not isinstance(item, str) or not item.startswith("Cmp") for item in added_conditions + removed_conditions):
            return False

    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, dict):
        added_control = tuple(control_delta.get("added") or ())
        removed_control = tuple(control_delta.get("removed") or ())
        expected_added = {f"for:{item}" for item in added_conditions} | {f"if:{item}" for item in added_conditions}
        expected_removed = {f"for:{item}" for item in removed_conditions} | {f"if:{item}" for item in removed_conditions}
        if set(added_control) - expected_added:
            return False
        if set(removed_control) - expected_removed:
            return False

    tokens: list[str] = []
    for field_name in ("segmented_writes", "stack_writes", "conditions", "control_flow_effects"):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, dict):
            continue
        for item in tuple(field_delta.get("added") or ()) + tuple(field_delta.get("removed") or ()):
            if not isinstance(item, str):
                return False
            tokens.append(item)
    if not tokens:
        return False

    markers = {_stack_offset_marker_8616(offset) for offset in evidence_offsets}
    if any(marker in token for marker in markers for token in tokens):
        return True

    # Some stack-array writes fingerprint only as CIndexedVariable after the
    # stack update fact has been consumed. Keep this limited to added segmented
    # write precision and only when direct stack-update evidence was consumed.
    if touched_fields == {"segmented_writes"}:
        segmented_delta = delta.get("segmented_writes")
        if not isinstance(segmented_delta, dict):
            return False
        added = tuple(segmented_delta.get("added") or ())
        removed = tuple(segmented_delta.get("removed") or ())
        return bool(added) and not removed and all(
            isinstance(item, str)
            and item.startswith("deref:")
            and "CIndexedVariable" in item
            for item in added
        )

    return False


def _direct_stack_move_has_signed_idiv_remainder_evidence_8616(codegen) -> bool:
    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return False
    for evidence in tuple(getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()):
        if not isinstance(evidence, (tuple, list)):
            continue
        for item in tuple(evidence):
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            key, value = item
            if key != "source_kind":
                continue
            name = getattr(value, "name", None)
            text = getattr(value, "value", None)
            if name == "SIGNED_IDIV_REMAINDER" or text == "signed_idiv_remainder" or value == "SIGNED_IDIV_REMAINDER":
                return True
    return False


def _helper_token_is_insert_artifact_8616(token: object) -> bool:
    if not isinstance(token, str):
        return False
    return token in {"name:_INSERT", "name:__INSERT", "_INSERT", "__INSERT"} or token.endswith("._INSERT")


def _is_direct_stack_move_idiv_remainder_aux_delta_8616(validation: dict[str, object]) -> bool:
    delta = validation.get("delta") if isinstance(validation, dict) else None
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not touched_fields or touched_fields - {"helper_calls", "register_writes"}:
        return False
    helper_delta = delta.get("helper_calls")
    if isinstance(helper_delta, dict):
        helper_tokens = tuple(helper_delta.get("added") or ()) + tuple(helper_delta.get("removed") or ())
        if not helper_tokens or any(not _helper_token_is_insert_artifact_8616(token) for token in helper_tokens):
            return False
    elif "helper_calls" in touched_fields:
        return False
    register_delta = delta.get("register_writes")
    if isinstance(register_delta, dict):
        reg_tokens = tuple(register_delta.get("added") or ()) + tuple(register_delta.get("removed") or ())
        if not reg_tokens or any(token != "reg:ax" for token in reg_tokens):
            return False
    elif "register_writes" in touched_fields:
        return False
    return True


def _validation_without_delta_fields_8616(validation: dict[str, object], fields: set[str]) -> dict[str, object]:
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return validation
    stripped = dict(validation)
    stripped["delta"] = {key: value for key, value in delta.items() if key not in fields}
    return stripped


def _is_direct_stack_move_idiv_remainder_materialization_delta_8616(codegen, validation: dict[str, object]) -> bool:
    if not _direct_stack_move_has_signed_idiv_remainder_evidence_8616(codegen):
        return False
    if _is_direct_stack_move_idiv_remainder_aux_delta_8616(validation):
        return True
    stripped = _validation_without_delta_fields_8616(validation, {"helper_calls", "register_writes"})
    stripped_delta = stripped.get("delta")
    if not isinstance(stripped_delta, dict) or not stripped_delta:
        return False
    return _is_direct_stack_update_materialization_delta_8616(codegen, stripped) and _is_direct_stack_move_idiv_remainder_aux_delta_8616(
        _validation_without_delta_fields_8616(validation, set(stripped_delta.keys()))
    )


def _helper_call_token_is_named_stack_probe_8616(project, token: object) -> bool:
    if not isinstance(token, str):
        return False
    if token.startswith("name:") and _calls._is_stack_probe_call_name_8616(token.removeprefix("name:")):
        return True
    addr = _helper_call_addr_token_8616(token)
    if not isinstance(addr, int):
        return False
    funcs = getattr(getattr(project, "kb", None), "functions", None) if project is not None else None
    if funcs is None:
        return False
    for candidate in (addr, addr & 0xFFFF):
        func = None
        with contextlib.suppress(Exception):
            func = funcs.function(addr=candidate, create=False)
        if func is not None and _calls._is_stack_probe_call_name_8616(getattr(func, "name", None)):
            return True
    return False


def _helper_call_token_is_stack_probe_evidenced_8616(project, codegen, token: object) -> bool:
    if not isinstance(token, str):
        return False
    expected = _stack_probe_helper_call_fingerprints_8616(codegen)
    if token in expected:
        return True
    if _helper_call_token_is_named_stack_probe_8616(project, token):
        return True
    return _removed_helper_tokens_are_source_evidenced_stack_probe_helpers_8616(codegen, (token,))


_JCC_CONDITION_MATERIALIZATION_REMOVABLE_REG_WRITES_8616 = frozenset({"reg:ax"})
_TAIL_VALIDATION_CONTROL_CONDITION_PREFIXES_8616 = frozenset({"if", "ifbreak", "while", "dowhile", "for"})


def _helper_delta_added_targets_are_function_callsite_evidenced_8616(
    function, helper_delta: dict[str, object]
) -> bool:
    added_helpers = tuple(helper_delta.get("added") or ())
    removed_helpers = tuple(helper_delta.get("removed") or ())
    if not added_helpers or removed_helpers:
        return False
    expected_targets: set[str] = set()
    for callsite_addr in tuple(sorted(getattr(function, "get_call_sites", lambda: ())() or ())):
        target = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
        if not isinstance(target, int):
            continue
        expected_targets.add(f"addr:{target:#x}")
        expected_targets.add(f"addr:{target & 0xFFFF:#x}")
        if target >= 0x1000:
            expected_targets.add(f"addr:{target - 0x1000:#x}")
    return bool(expected_targets) and set(added_helpers).issubset(expected_targets)


def _normalize_validation_condition_token_8616(token: object) -> str | None:
    if not isinstance(token, str) or not token:
        return None
    return normalize_condition_fingerprint_algebraic_8616(normalize_condition_fingerprint_string_8616(token))


def _condition_token_from_control_effect_8616(token: object) -> str | None:
    if not isinstance(token, str) or ":" not in token:
        return None
    prefix, condition_token = token.split(":", 1)
    if prefix not in _TAIL_VALIDATION_CONTROL_CONDITION_PREFIXES_8616:
        return None
    return _normalize_validation_condition_token_8616(condition_token)


def _jcc_condition_validation_evidence_8616(codegen) -> tuple[dict[str, str], ...]:
    evidence_items: list[dict[str, str]] = []
    for item in tuple(getattr(codegen, "_inertia_jcc_condition_validation_evidence_8616", ()) or ()):
        if not isinstance(item, dict):
            continue
        removed = _normalize_validation_condition_token_8616(item.get("removed"))
        added = _normalize_validation_condition_token_8616(item.get("added"))
        if not removed or not added or removed == added:
            continue
        evidence_items.append({"removed": removed, "added": added})
    return tuple(evidence_items)


def _jcc_condition_delta_is_evidenced_8616(codegen, condition_delta, control_delta) -> bool:
    normalized_delta = _normalized_jcc_condition_delta_sets_8616(condition_delta, control_delta)
    if normalized_delta is None:
        return False
    added_conditions, removed_conditions, added_control_conditions, removed_control_conditions = normalized_delta
    if not (added_conditions or removed_conditions or added_control_conditions or removed_control_conditions):
        return True

    evidence = _jcc_condition_validation_evidence_8616(codegen)
    if evidence:
        evidenced_added = {item["added"] for item in evidence}
        evidenced_removed = {item["removed"] for item in evidence}
        if not added_conditions - evidenced_added and not removed_conditions - evidenced_removed:
            if not added_control_conditions - evidenced_added and not removed_control_conditions - evidenced_removed:
                return True
    if _jcc_condition_delta_matches_decoded_fingerprints_8616(codegen, normalized_delta):
        return True
    return _jcc_condition_delta_matches_structuring_evidence_8616(codegen, normalized_delta)


def _normalized_jcc_condition_delta_sets_8616(condition_delta, control_delta) -> tuple[set[str], set[str], set[str], set[str]] | None:
    added_conditions: set[str] = set()
    removed_conditions: set[str] = set()
    if isinstance(condition_delta, dict):
        for token in tuple(condition_delta.get("added") or ()):
            normalized = _normalize_validation_condition_token_8616(token)
            if normalized is None:
                return None
            added_conditions.add(normalized)
        for token in tuple(condition_delta.get("removed") or ()):
            normalized = _normalize_validation_condition_token_8616(token)
            if normalized is None:
                return None
            removed_conditions.add(normalized)

    added_control_conditions: set[str] = set()
    removed_control_conditions: set[str] = set()
    if isinstance(control_delta, dict):
        for token in tuple(control_delta.get("added") or ()):
            normalized = _condition_token_from_control_effect_8616(token)
            if normalized is None:
                return None
            added_control_conditions.add(normalized)
        for token in tuple(control_delta.get("removed") or ()):
            normalized = _condition_token_from_control_effect_8616(token)
            if normalized is None:
                return None
            removed_control_conditions.add(normalized)
    return added_conditions, removed_conditions, added_control_conditions, removed_control_conditions


def _jcc_condition_delta_matches_structuring_evidence_8616(
    codegen,
    normalized_delta: tuple[set[str], set[str], set[str], set[str]],
) -> bool:
    added_conditions, removed_conditions, added_control_conditions, removed_control_conditions = normalized_delta
    for item in tuple(getattr(codegen, "_inertia_structuring_jcc_condition_validation_deltas_8616", ()) or ()):
        if not isinstance(item, dict):
            continue
        candidate = _normalized_jcc_condition_delta_sets_8616(
            item.get("conditions"),
            item.get("control_flow_effects"),
        )
        if candidate is None:
            continue
        (
            candidate_added_conditions,
            candidate_removed_conditions,
            candidate_added_control_conditions,
            candidate_removed_control_conditions,
        ) = candidate
        if (
            added_conditions == candidate_added_conditions
            and removed_conditions == candidate_removed_conditions
            and added_control_conditions == candidate_added_control_conditions
            and removed_control_conditions == candidate_removed_control_conditions
        ):
            return True
    return False


def _jcc_condition_delta_matches_decoded_fingerprints_8616(
    codegen,
    normalized_delta: tuple[set[str], set[str], set[str], set[str]],
) -> bool:
    added_conditions, removed_conditions, added_control_conditions, removed_control_conditions = normalized_delta
    if not added_conditions or len(added_conditions) != len(removed_conditions):
        return False
    if added_control_conditions != added_conditions or removed_control_conditions != removed_conditions:
        return False
    decoded: set[str] = set()
    for token in tuple(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ()) or ()):
        normalized = _normalize_validation_condition_token_8616(token)
        if normalized is not None:
            decoded.add(normalized)
    if not decoded or added_conditions - decoded:
        return False
    return True


def _is_jcc_condition_materialization_validation_delta_8616(
    project,
    codegen,
    validation: dict[str, object],
    *,
    function=None,
) -> bool:
    if not isinstance(validation, dict):
        return False
    if (
        int(getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) or 0) <= 0
        and int(getattr(codegen, "_inertia_structuring_jcc_condition_validation_accepts_8616", 0) or 0) <= 0
        and not tuple(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ()) or ())
    ):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not touched_fields or touched_fields - {
        "conditions",
        "control_flow_effects",
        "helper_calls",
        "global_writes",
        "register_writes",
    }:
        return False
    if not _jcc_condition_delta_is_evidenced_8616(
        codegen,
        delta.get("conditions"),
        delta.get("control_flow_effects"),
    ):
        return False

    helper_delta = delta.get("helper_calls")
    if isinstance(helper_delta, dict):
        added_helpers = tuple(helper_delta.get("added") or ())
        removed_helpers = tuple(helper_delta.get("removed") or ())
        if removed_helpers:
            return False
        helper_evidenced = (
            all(_helper_call_token_is_stack_probe_evidenced_8616(project, codegen, token) for token in added_helpers)
            if added_helpers
            else True
        )
        if added_helpers and not helper_evidenced:
            helper_evidenced = _helper_delta_added_targets_are_function_callsite_evidenced_8616(
                function,
                helper_delta,
            )
        if added_helpers and not helper_evidenced:
            return False

    register_delta = delta.get("register_writes")
    if isinstance(register_delta, dict):
        added_registers = tuple(register_delta.get("added") or ())
        removed_registers = tuple(register_delta.get("removed") or ())
        if added_registers:
            return False
        if removed_registers and not set(removed_registers).issubset(
            _JCC_CONDITION_MATERIALIZATION_REMOVABLE_REG_WRITES_8616
        ):
            return False

    global_delta = delta.get("global_writes")
    if isinstance(global_delta, dict):
        added_globals = tuple(global_delta.get("added") or ())
        removed_globals = tuple(global_delta.get("removed") or ())
        if removed_globals:
            return False
        if added_globals and not all(
            _is_adjacent_global_high_byte_precision_delta_8616(token, validation) for token in added_globals
        ):
            return False

    return True


def _is_combined_jcc_callsite_stack_validation_delta_8616(project, function, codegen, validation: dict[str, object]) -> bool:
    if not isinstance(validation, dict):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not {"conditions", "control_flow_effects"} & touched_fields:
        return False
    if not {"global_writes", "segmented_writes"} & touched_fields:
        return False
    jcc_validation = _validation_without_delta_fields_8616(
        validation,
        {"segmented_writes", "stack_writes", "returns"},
    )
    callsite_validation = _validation_without_delta_fields_8616(
        validation,
        {"conditions", "control_flow_effects", "helper_calls", "register_writes"},
    )
    return _is_jcc_condition_materialization_validation_delta_8616(
        project,
        codegen,
        jcc_validation,
        function=function,
    ) and _is_callsite_stack_argument_materialization_delta_8616(codegen, callsite_validation)


def _call_fingerprint_args_text_8616(token: object) -> str | None:
    if not isinstance(token, str) or not token.startswith("call:"):
        return None
    open_idx = token.find("(")
    close_idx = token.rfind(")")
    if open_idx < 0 or close_idx < open_idx:
        return None
    return token[open_idx + 1 : close_idx]


def _is_callsite_stack_argument_materialization_delta_8616(codegen, validation: dict[str, object]) -> bool:
    def _debug_refusal(reason: str, **fields) -> None:
        if not os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            return
        logging.getLogger(__name__).warning(
            "callsite materialization validation delta refused reason=%s fields=%r",
            reason,
            fields,
        )

    if not isinstance(validation, dict):
        _debug_refusal("validation_not_dict")
        return False
    callsite_stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
    materialized_args = int(getattr(callsite_stats, "call_arg_materialized_count", 0) or 0)
    if materialized_args <= 0:
        stats = getattr(codegen, "_inertia_stack_probe_fact_stats", None)
        if isinstance(stats, dict):
            materialized_args = int(stats.get("call_arg_materialized_count", 0) or 0)
        if materialized_args <= 0 and isinstance(stats, dict):
            materialized_args = int(stats.get("stack_arg_materializations", 0) or 0)
    materialized_fnptr_branches = int(getattr(codegen, "_inertia_fnptr_branch_symbols_materialized_8616", 0) or 0)
    if materialized_args <= 0 and materialized_fnptr_branches <= 0:
        _debug_refusal("no_materialization_counter", callsite_stats=repr(callsite_stats))
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        _debug_refusal("delta_not_dict", keys=tuple(validation.keys()))
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if touched_fields and touched_fields <= {"global_writes", "segmented_writes"}:
        global_delta = delta.get("global_writes")
        if isinstance(global_delta, dict):
            added_globals = tuple(global_delta.get("added") or ())
            removed_globals = tuple(global_delta.get("removed") or ())
            if removed_globals:
                _debug_refusal("global_writes_removed", removed=removed_globals[:6])
                return False
            if added_globals and not all(
                _is_adjacent_global_high_byte_precision_delta_8616(token, validation) for token in added_globals
            ):
                _debug_refusal("global_writes_not_adjacent_high_byte", added=added_globals[:6])
                return False
        for field_name in ("helper_calls", "register_writes", "stack_writes", "returns", "conditions", "control_flow_effects"):
            field_delta = delta.get(field_name)
            if not isinstance(field_delta, dict):
                continue
            if tuple(field_delta.get("added") or ()) or tuple(field_delta.get("removed") or ()):
                _debug_refusal("non_memory_precision_delta", field=field_name)
                return False
        codegen._inertia_callsite_stack_arg_validation_precision_delta_accepts = int(
            getattr(codegen, "_inertia_callsite_stack_arg_validation_precision_delta_accepts", 0) or 0
        ) + 1
        return True
    if not touched_fields or touched_fields - {"returns", "global_writes"}:
        helper_delta = delta.get("helper_calls")
        _debug_refusal(
            "touched_fields",
            touched_fields=tuple(sorted(touched_fields)),
            helper_added=tuple((helper_delta or {}).get("added") or ())[:8] if isinstance(helper_delta, dict) else (),
            helper_removed=tuple((helper_delta or {}).get("removed") or ())[:8] if isinstance(helper_delta, dict) else (),
        )
        return False
    if "global_writes" in touched_fields:
        global_delta = delta.get("global_writes")
        if not isinstance(global_delta, dict):
            _debug_refusal("global_writes_not_dict")
            return False
        added_globals = tuple(global_delta.get("added") or ())
        removed_globals = tuple(global_delta.get("removed") or ())
        if removed_globals:
            _debug_refusal("global_writes_removed", removed=removed_globals[:6])
            return False
        if added_globals and not all(
            _is_adjacent_global_high_byte_precision_delta_8616(token, validation) for token in added_globals
        ):
            _debug_refusal("global_writes_not_adjacent_high_byte", added=added_globals[:6])
            return False
    if "returns" in touched_fields:
        returns_delta = delta.get("returns")
        if not isinstance(returns_delta, dict):
            _debug_refusal("returns_not_dict")
            return False
        added = tuple(returns_delta.get("added") or ())
        removed = tuple(returns_delta.get("removed") or ())
        if not added or len(added) != len(removed):
            _debug_refusal("returns_count", added=added[:6], removed=removed[:6])
            return False
        for added_token, removed_token in zip(added, removed, strict=False):
            added_args = _call_fingerprint_args_text_8616(added_token)
            removed_args = _call_fingerprint_args_text_8616(removed_token)
            if not added_args or added_args != removed_args:
                _debug_refusal("arg_text_mismatch", added=added_token, removed=removed_token)
                return False
            if "stack_slot:" not in added_args:
                _debug_refusal("no_stack_slot", added=added_token, removed=removed_token)
                return False
            if not isinstance(added_token, str) or not isinstance(removed_token, str):
                _debug_refusal(
                    "token_not_str",
                    added_type=type(added_token).__name__,
                    removed_type=type(removed_token).__name__,
                )
                return False
            if not added_token.startswith("call:<indirect>("):
                _debug_refusal("added_not_indirect", added=added_token)
                return False
            if not removed_token.startswith("call:addr:"):
                _debug_refusal("removed_not_addr", removed=removed_token)
                return False
    return True


def _stack_probe_helper_call_fingerprints_8616(codegen) -> set[str]:
    expected: set[str] = {
        token
        for token in (getattr(codegen, "_inertia_stack_probe_helper_target_fingerprints_8616", ()) or ())
        if isinstance(token, str)
    }
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        return expected
    for summary in summary_map.values():
        if not bool(getattr(summary, "stack_probe_helper", False)):
            continue
        target = getattr(summary, "target_addr", None)
        if not isinstance(target, int):
            continue
        for candidate in (target, target & 0xFFFF):
            expected.add(f"addr:{candidate:#x}")
            expected.add(f"name:addr:{candidate:#x}")
    return expected


def _helper_call_addr_token_8616(token: object) -> int | None:
    if not isinstance(token, str):
        return None
    prefix = "name:addr:" if token.startswith("name:addr:") else "addr:" if token.startswith("addr:") else None
    if prefix is None:
        return None
    value = token[len(prefix) :]
    with contextlib.suppress(ValueError):
        return int(value, 0)
    return None


def _removed_helper_tokens_are_named_stack_probe_helpers_8616(codegen, removed: tuple[object, ...]) -> bool:
    project = getattr(codegen, "project", None)
    funcs = getattr(getattr(project, "kb", None), "functions", None) if project is not None else None
    if funcs is None or not removed:
        return False
    for token in removed:
        addr = _helper_call_addr_token_8616(token)
        if not isinstance(addr, int):
            return False
        func = None
        for candidate in (addr, addr & 0xFFFF):
            with contextlib.suppress(Exception):
                func = funcs.function(addr=candidate, create=False)
            if func is not None:
                break
        if func is None or not _calls._is_stack_probe_call_name_8616(getattr(func, "name", None)):
            return False
    return True


def _removed_helper_tokens_are_source_evidenced_stack_probe_helpers_8616(codegen, removed: tuple[object, ...]) -> bool:
    if not removed:
        return False
    project = getattr(codegen, "project", None)
    function = getattr(codegen, "_inertia_current_function_8616", None)
    func_addr = getattr(function, "addr", None)
    if project is None or not isinstance(func_addr, int):
        return False
    source_calls = _calls._cod_source_call_names_8616(project, func_addr)
    if not source_calls:
        cfunc_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        source_calls = _calls._cod_source_call_names_8616(project, cfunc_addr) if isinstance(cfunc_addr, int) else ()
    if not any(_calls._is_stack_probe_call_name_8616(name) for name in source_calls):
        return False
    callsites = tuple(sorted(getattr(function, "get_call_sites", lambda: [])() or ()))
    if not callsites:
        return False
    expected: set[int] = set()
    for idx, name in enumerate(source_calls):
        if idx >= len(callsites):
            break
        if not _calls._is_stack_probe_call_name_8616(name):
            continue
        target = getattr(function, "get_call_target", lambda _addr: None)(callsites[idx])
        if isinstance(target, int):
            expected.add(target)
            expected.add(target & 0xFFFF)
    removed_targets = {_helper_call_addr_token_8616(token) for token in removed}
    if not removed_targets or any(not isinstance(target, int) for target in removed_targets):
        return False
    return all(target in expected for target in removed_targets if isinstance(target, int))


def _is_stack_probe_helper_cleanup_delta_8616(codegen, validation: dict[str, object]) -> bool:
    def _debug_refusal(reason: str, **fields) -> None:
        if not os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            return
        logging.getLogger(__name__).warning(
            "stack probe helper cleanup validation delta refused reason=%s fields=%r",
            reason,
            fields,
        )

    if not isinstance(validation, dict):
        _debug_refusal("validation_not_dict")
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        _debug_refusal("delta_not_dict")
        return False
    if _validation_delta_touched_fields_8616(delta) != {"helper_calls"}:
        _debug_refusal("touched_fields", touched=tuple(sorted(_validation_delta_touched_fields_8616(delta))))
        return False
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, dict):
        _debug_refusal("helper_not_dict")
        return False
    added = tuple(helper_delta.get("added") or ())
    removed = tuple(helper_delta.get("removed") or ())
    if added or not removed:
        _debug_refusal("added_or_empty_removed", added=added[:6], removed=removed[:6])
        return False
    expected = _stack_probe_helper_call_fingerprints_8616(codegen)
    if not _has_stack_probe_cleanup_evidence_8616(codegen) and _removed_helper_tokens_are_named_stack_probe_helpers_8616(
        codegen, removed
    ):
        return True
    if not _has_stack_probe_cleanup_evidence_8616(
        codegen
    ) and _removed_helper_tokens_are_source_evidenced_stack_probe_helpers_8616(codegen, removed):
        return True
    if not _has_stack_probe_cleanup_evidence_8616(codegen):
        _debug_refusal("no_stack_probe_cleanup_evidence")
        return False
    if not expected:
        _debug_refusal("no_expected_fingerprints", removed=removed[:6])
        return False
    if not all(isinstance(token, str) and token in expected for token in removed):
        _debug_refusal("unexpected_removed", expected=tuple(sorted(expected))[:12], removed=removed[:6])
        return False
    return True


def _has_stack_probe_cleanup_evidence_8616(codegen) -> bool:
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if isinstance(summary_map, dict):
        for summary in summary_map.values():
            if bool(getattr(summary, "stack_probe_helper", False)):
                return True

    typed_facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", None)
    if isinstance(typed_facts, dict) and typed_facts:
        return True

    fact_stats = getattr(codegen, "_inertia_stack_probe_fact_stats", None)
    if isinstance(fact_stats, dict):
        if int(fact_stats.get("stack_probe_summaries", 0) or 0) > 0:
            return True
        if int(fact_stats.get("ss_stack_address_returns", 0) or 0) > 0:
            return True

    return False


def _is_cfg_return_chain_callsite_materialization_delta_8616(
    project, function, codegen, validation: dict[str, object]
) -> bool:
    if not isinstance(validation, dict):
        return False
    if not (
        getattr(codegen, "_inertia_return_chain_flattened_8616", False)
        or getattr(codegen, "_inertia_return_chain_suffix_materialized_8616", False)
    ):
        return False
    stats = getattr(codegen, "_inertia_empty_return_branch_stats_8616", None)
    if not isinstance(stats, dict):
        return False
    # Refusals here can come from broader/full-chain attempts that correctly
    # refuse prefix calls.  The proof is the suffix materialization plus CFG
    # value/final-AX agreement below, not a zero-refusal diagnostic counter.
    if int(stats.get("materialized", 0) or 0) <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    allowed_fields = {"returns", "segmented_writes", "conditions", "control_flow_effects"}
    if not touched_fields or touched_fields - allowed_fields:
        return False

    materialized_values = tuple(int(value) for value in getattr(codegen, "_inertia_return_chain_materialized_values_8616", ()) or ())
    conditional_values = tuple(int(value) for value in _ordered_conditional_return_values_8616(project, codegen))
    if conditional_values != materialized_values:
        cfg_values = tuple(int(value) for _cond, value in _ordered_conditional_return_pairs_from_cfg_8616(project, codegen))
        if cfg_values == materialized_values:
            conditional_values = cfg_values
    if conditional_values != materialized_values:
        return False
    final_value = _last_ax_return_value_8616(project, codegen)
    if final_value is None or int(getattr(codegen, "_inertia_return_chain_final_value_8616", -1)) != int(final_value):
        return False

    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    added_returns = set(returns_delta.get("added") or ())
    removed_returns = set(returns_delta.get("removed") or ())
    expected_added = {f"const:{value}" for value in conditional_values}
    expected_added.add(f"const:{int(final_value)}")
    if added_returns - expected_added:
        return False
    allowed_removed_returns = {"CDirtyExpression", "none"}
    for value in (*conditional_values, int(final_value)):
        if int(value) < 0:
            allowed_removed_returns.add(f"const:{int(value) & 0xFFFF}")
    if removed_returns - allowed_removed_returns:
        return False

    condition_delta = delta.get("conditions")
    materialized_condition_fps = set(
        getattr(codegen, "_inertia_return_chain_materialized_condition_fingerprints_8616", ()) or ()
    )
    if isinstance(condition_delta, dict):
        added_conditions = set(condition_delta.get("added") or ())
        if not materialized_condition_fps or added_conditions - materialized_condition_fps:
            return False

    control_flow_delta = delta.get("control_flow_effects")
    if isinstance(control_flow_delta, dict):
        added_control = set(control_flow_delta.get("added") or ())
        expected_added_control = {f"if:{fp}" for fp in materialized_condition_fps}
        if added_control - expected_added_control:
            return False

    segmented_delta = delta.get("segmented_writes")
    if isinstance(segmented_delta, dict):
        if tuple(segmented_delta.get("added") or ()):
            return False
        removed_segmented = tuple(segmented_delta.get("removed") or ())
        if removed_segmented:
            callsite_stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
            consumed = int(getattr(callsite_stats, "consumed_outgoing_stack_placeholder_count", 0) or 0)
            arg_materialized = int(getattr(callsite_stats, "call_arg_materialized_count", 0) or 0)
            if consumed <= 0 and arg_materialized <= 0 and not _has_stack_probe_cleanup_evidence_8616(codegen):
                return False

    return True


def _selector_return_expected_raw_stack_slots_8616(project, codegen, expected_returns: set[str]) -> set[str]:
    """Map expected selector-return arguments back to their raw BP stack slots."""
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None or not expected_returns:
        return set()
    raw_slots: set[str] = set()
    for arg in tuple(getattr(cfunc, "arg_list", ()) or ()):
        variable = getattr(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset <= 0:
            continue
        size = getattr(variable, "size", None)
        try:
            arg_fingerprint = _expr_fingerprint(arg, project)
        except Exception as ex:
            logging.getLogger(__name__).debug("selector-return arg fingerprint failed: %s", ex)
            continue
        if arg_fingerprint not in expected_returns:
            continue
        if isinstance(size, int) and size > 0:
            raw_slots.add(_stack_slot_fingerprint_from_slot_8616(offset, size))
        raw_slots.add(_stack_slot_fingerprint_from_slot_8616(offset, None))
    return raw_slots


def _selector_return_current_condition_fingerprints_8616(project, codegen) -> set[str]:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if root is None:
        return set()
    fingerprints: set[str] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse):
            continue
        for cond, _body in tuple(getattr(node, "condition_and_nodes", ()) or ()):
            try:
                fingerprints.add(_expr_fingerprint(cond, project))
            except Exception as ex:
                logging.getLogger(__name__).debug("selector-return current condition fingerprint failed: %s", ex)
    return fingerprints


def _is_cfg_return_expr_chain_materialization_delta_8616(project, function, codegen, validation: dict[str, object]) -> bool:
    _ = function
    def _reject(reason: _CfgReturnExprDeltaRefusal8616, **details) -> bool:
        refusals = list(getattr(codegen, "_inertia_cfg_return_expr_delta_refusals_8616", ()) or ())
        refusals.append({"reason": reason, "details": details})
        codegen._inertia_cfg_return_expr_delta_refusals_8616 = tuple(refusals)
        if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
            logging.getLogger(__name__).warning(
                "[cfg-selector-return] validation-delta refused reason=%s details=%r",
                reason.value,
                details,
            )
        return False

    if not isinstance(validation, dict):
        return _reject(_CfgReturnExprDeltaRefusal8616.MISSING_DELTA, validation_type=type(validation).__name__)
    if not getattr(codegen, "_inertia_return_expr_chain_materialized_8616", False):
        return _reject(_CfgReturnExprDeltaRefusal8616.MISSING_EVIDENCE)
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return _reject(_CfgReturnExprDeltaRefusal8616.MISSING_DELTA)
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    allowed_fields = {"returns"}
    if getattr(codegen, "_inertia_return_selector_materialized_8616", False):
        allowed_fields = {"returns", "conditions", "control_flow_effects", "helper_calls"}
    if not touched_fields or touched_fields - allowed_fields or "returns" not in touched_fields:
        return _reject(
            _CfgReturnExprDeltaRefusal8616.UNEXPECTED_FIELDS,
            touched_fields=tuple(sorted(touched_fields)),
            allowed_fields=tuple(sorted(allowed_fields)),
        )
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return _reject(_CfgReturnExprDeltaRefusal8616.MISSING_RETURNS_DELTA)
    added_returns = set(returns_delta.get("added") or ())
    removed_returns = set(returns_delta.get("removed") or ())
    expected_returns = set(getattr(codegen, "_inertia_return_expr_chain_materialized_return_fingerprints_8616", ()) or ())
    if not expected_returns or added_returns - expected_returns:
        return _reject(
            _CfgReturnExprDeltaRefusal8616.UNEXPECTED_ADDED_RETURNS,
            added=tuple(sorted(added_returns)),
            expected=tuple(sorted(expected_returns)),
        )
    expected_raw_stack_slots = _selector_return_expected_raw_stack_slots_8616(project, codegen, expected_returns)
    unexpected_removed = tuple(
        sorted(
            item
            for item in removed_returns
            if item not in {"CDirtyExpression", "none"}
            and item not in expected_raw_stack_slots
            and "CDirtyExpression" not in item
            and not item.startswith(("Concat(", "Or("))
        )
    )
    if unexpected_removed:
        return _reject(
            _CfgReturnExprDeltaRefusal8616.UNEXPECTED_REMOVED_RETURNS,
            removed=unexpected_removed,
            expected_raw_stack_slots=tuple(sorted(expected_raw_stack_slots)),
            expected=tuple(sorted(expected_returns)),
        )
    if getattr(codegen, "_inertia_return_selector_materialized_8616", False):
        expected_conditions = set(
            getattr(codegen, "_inertia_return_chain_materialized_condition_fingerprints_8616", ()) or ()
        )
        expected_conditions |= _selector_return_current_condition_fingerprints_8616(project, codegen)
        condition_delta = delta.get("conditions")
        if isinstance(condition_delta, dict):
            added_conditions = set(condition_delta.get("added") or ())
            if not expected_conditions or added_conditions - expected_conditions:
                return _reject(
                    _CfgReturnExprDeltaRefusal8616.UNEXPECTED_ADDED_CONDITIONS,
                    added=tuple(sorted(added_conditions)),
                    expected=tuple(sorted(expected_conditions)),
                )
        control_delta = delta.get("control_flow_effects")
        if isinstance(control_delta, dict):
            added_control = set(control_delta.get("added") or ())
            expected_control = {f"if:{fp}" for fp in expected_conditions}
            if added_control - expected_control:
                return _reject(
                    _CfgReturnExprDeltaRefusal8616.UNEXPECTED_ADDED_CONTROL,
                    added=tuple(sorted(added_control)),
                    expected=tuple(sorted(expected_control)),
                )
        helper_delta = delta.get("helper_calls")
        if isinstance(helper_delta, dict) and ((helper_delta.get("added") or ()) or (helper_delta.get("removed") or ())):
            if tuple(helper_delta.get("added") or ()):
                return _reject(
                    _CfgReturnExprDeltaRefusal8616.UNEXPECTED_HELPER_DELTA,
                    helper_delta=helper_delta,
                )
            helper_validation = dict(validation)
            helper_validation["delta"] = {"helper_calls": helper_delta}
            if not _is_stack_probe_helper_cleanup_delta_8616(codegen, helper_validation):
                return _reject(
                    _CfgReturnExprDeltaRefusal8616.UNEXPECTED_HELPER_DELTA,
                    helper_delta=helper_delta,
                )
    return True


def _is_cfg_mask_accumulator_materialization_delta_8616(project, function, codegen, validation: dict[str, object]) -> bool:
    if function is None or not isinstance(validation, dict):
        return False
    if not getattr(codegen, "_inertia_mask_accumulator_materialized_8616", False):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    allowed_fields = {"returns", "conditions", "control_flow_effects", "helper_calls"}
    if not touched_fields or touched_fields - allowed_fields:
        return False
    expected_conditions = set(getattr(codegen, "_inertia_mask_accumulator_condition_fingerprints_8616", ()) or ())
    if not expected_conditions:
        return False
    condition_delta = delta.get("conditions")
    if isinstance(condition_delta, dict):
        added_conditions = set(condition_delta.get("added") or ())
        if added_conditions - expected_conditions:
            return False
    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, dict):
        added_control = set(control_delta.get("added") or ())
        expected_control = {f"if:{fp}" for fp in expected_conditions}
        expected_control.add("return")
        if added_control - expected_control:
            return False
    returns_delta = delta.get("returns")
    if isinstance(returns_delta, dict):
        added_returns = set(returns_delta.get("added") or ())
        removed_returns = set(returns_delta.get("removed") or ())
        expected_return = getattr(codegen, "_inertia_mask_accumulator_return_fingerprint_8616", None)
        if added_returns and expected_return is not None and added_returns - {expected_return}:
            return False
        if any(
            item not in {"CDirtyExpression", "none"}
            and "CDirtyExpression" not in item
            and item != "CIndexedVariable"
            for item in removed_returns
        ):
            return False
    helper_delta = delta.get("helper_calls")
    if isinstance(helper_delta, dict):
        if tuple(helper_delta.get("added") or ()):
            return False
    return True


def _debug_call_recover_reject_8616(reason: str, **kwargs) -> None:
    if not os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
        return
    suffix = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
    logging.getLogger(__name__).warning("[call-recover-accept] reject=%s %s", reason, suffix)


def _debug_call_recover_accept_8616(reason: str, **kwargs) -> None:
    if not os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
        return
    suffix = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
    logging.getLogger(__name__).warning("[call-recover-accept] accepted=%s %s", reason, suffix)


def _helper_delta_touches_only_allowed_fields_8616(delta: dict[str, object]) -> bool:
    allowed_fields = {"helper_calls"}
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    if touched_fields and not (touched_fields - allowed_fields):
        return True
    _debug_call_recover_reject_8616(
        "touched-fields",
        touched=sorted(touched_fields),
        allowed=sorted(allowed_fields),
        delta=delta,
    )
    return False


def _classify_postprocess_validation_delta_8616(validation: dict[str, object]) -> _PostprocessValidationDeltaKind8616:
    if not isinstance(validation, dict):
        return _PostprocessValidationDeltaKind8616.BLOCKING
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return _PostprocessValidationDeltaKind8616.BLOCKING
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    if touched_fields != {"helper_calls"}:
        return _PostprocessValidationDeltaKind8616.BLOCKING
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, dict):
        return _PostprocessValidationDeltaKind8616.BLOCKING
    added = tuple(helper_delta.get("added") or ())
    removed = tuple(helper_delta.get("removed") or ())
    if added or not removed:
        return _PostprocessValidationDeltaKind8616.BLOCKING
    if all(isinstance(token, str) and token.startswith("name:addr:") for token in removed):
        return _PostprocessValidationDeltaKind8616.NAME_ONLY_HELPER_ANNOTATION
    return _PostprocessValidationDeltaKind8616.BLOCKING


def _has_recovered_source_calls_in_codegen_8616(project, codegen, function) -> bool:
    def _impl():
        if codegen is None or function is None:
            return False
        recovered_count = int(getattr(codegen, "_inertia_direct_call_floor_recovered_count", 0) or 0)
        if recovered_count <= 0:
            return False
        try:
            from .decompiler_postprocess_calls import _cod_source_call_names_8616
        except Exception:
            return False
        func_addr = getattr(function, "addr", None)
        if not isinstance(func_addr, int):
            return False
        expected = [
            normalize_callee_name_8616(name) or name
            for name in _cod_source_call_names_8616(project, func_addr)
            if isinstance(name, str) and name and name != "aNchkstk"
        ]
        if not expected:
            return False
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False
        present = _present_call_names_from_cfunc_8616(cfunc)
        if not present:
            present = _present_call_names_from_rendered_text_8616(codegen, cfunc)
        return set(expected).issubset(present)

    return _impl()


def _present_call_names_from_cfunc_8616(cfunc) -> set[str]:
    def _impl():
        root = getattr(cfunc, "body", None) or getattr(cfunc, "statements", None) or cfunc
        present: set[str] = set()
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall):
                continue
            for raw in (
                getattr(node, "callee_target", None),
                getattr(getattr(node, "callee_func", None), "name", None),
                getattr(node, "callee", None),
            ):
                if isinstance(raw, str) and raw:
                    normalized = normalize_callee_name_8616(raw) or raw
                    if normalized and normalized != "aNchkstk":
                        present.add(normalized)
        return present

    return _impl()


def _present_call_names_from_rendered_text_8616(codegen, cfunc) -> set[str]:
    def _impl():
        present: set[str] = set()
        with contextlib.suppress(Exception):
            rendered = codegen.render_text(cfunc)
            if isinstance(rendered, tuple):
                rendered = rendered[0] if rendered and isinstance(rendered[0], str) else ""
            if not isinstance(rendered, str) or not rendered:
                return present
            body = re.sub(r"/\*.*?\*/", "", rendered, flags=re.S)
            body = re.sub(r"//[^\n]*", "", body)
            body = body.split("{", 1)[-1] if "{" in body else body
            for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
                name = match.group(1)
                if name in {"if", "for", "while", "switch", "return", "sizeof", "aNchkstk"}:
                    continue
                normalized = normalize_callee_name_8616(name) or name
                if normalized:
                    present.add(normalized)
        return present

    return _impl()


def _normalized_source_call_names_8616(project, func_addr: int | None) -> list[str]:
    if not isinstance(func_addr, int):
        return []
    names: list[str] = []
    with contextlib.suppress(Exception):
        from .decompiler_postprocess_calls import _cod_source_call_names_8616

        for name in _cod_source_call_names_8616(project, func_addr):
            if not isinstance(name, str) or not name or name == "aNchkstk":
                continue
            normalized = normalize_callee_name_8616(name) or name
            if isinstance(normalized, str) and normalized and normalized != "aNchkstk":
                names.append(normalized)
    return names


def _normalized_kb_call_target_names_8616(project, func_addr: int | None) -> list[str]:
    if not isinstance(func_addr, int):
        return []
    names: list[str] = []
    kb_fn = None
    with contextlib.suppress(Exception):
        kb_fn = project.kb.functions.function(addr=func_addr, create=False)
    if kb_fn is None:
        return names
    for callsite_addr in tuple(sorted(getattr(kb_fn, "get_call_sites", lambda: [])() or ())):
        target = getattr(kb_fn, "get_call_target", lambda _addr: None)(callsite_addr)
        if not isinstance(target, int):
            continue
        callee = project.kb.functions.function(addr=target, create=False)
        callee_name = normalize_callee_name_8616(getattr(callee, "name", None))
        if isinstance(callee_name, str) and callee_name and callee_name != "aNchkstk":
            names.append(callee_name)
    return names


def _actual_call_counts_from_cfunc_8616(cfunc) -> dict[str, int]:
    root = getattr(cfunc, "body", None) or getattr(cfunc, "statements", None) or cfunc
    actual_counts: dict[str, int] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        for raw in (
            getattr(node, "callee_target", None),
            getattr(getattr(node, "callee_func", None), "name", None),
            getattr(node, "callee", None),
        ):
            if not isinstance(raw, str) or not raw:
                continue
            normalized = normalize_callee_name_8616(raw) or raw
            if normalized in {"aNchkstk", "if", "for", "while", "switch", "return", "sizeof"}:
                continue
            actual_counts[normalized] = int(actual_counts.get(normalized, 0)) + 1
            break
    return actual_counts


def _expected_source_call_score_from_cfunc_8616(project, cfunc, function) -> tuple[int, int]:
    if cfunc is None or function is None:
        return (0, 0)
    func_addr = getattr(function, "addr", None)
    expected_names = _normalized_source_call_names_8616(project, func_addr)
    if not expected_names:
        expected_names = _normalized_kb_call_target_names_8616(project, func_addr)
    if not expected_names:
        return (0, 0)
    expected_counts: dict[str, int] = {}
    for name in expected_names:
        expected_counts[name] = int(expected_counts.get(name, 0)) + 1
    actual_counts = _actual_call_counts_from_cfunc_8616(cfunc)
    score = 0
    total = int(sum(expected_counts.values()))
    for name, needed in expected_counts.items():
        score += min(int(actual_counts.get(name, 0)), int(needed))
    return (score, total)


def _normalize_stack_variable_identifiers_8616(codegen) -> None:
    def _impl():
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return
        arg_list = tuple(getattr(cfunc, "arg_list", ()) or ())
        arg_name_by_offset: dict[int, str] = {}
        project = getattr(codegen, "project", None)
        func_addr = getattr(cfunc, "addr", None)
        if project is not None and isinstance(func_addr, int):
            with contextlib.suppress(Exception):
                function = project.kb.functions.function(addr=func_addr, create=False)
                info = getattr(function, "info", None)
                annotations = info.get(ANNOTATION_KEY) if isinstance(info, MutableMapping) else None
                stack_vars = annotations.get("stack_vars") if isinstance(annotations, dict) else None
                if isinstance(stack_vars, dict):
                    positive_offsets = sorted(offset for offset in stack_vars if isinstance(offset, int) and offset > 0)
                    positive_specs_are_normalized = _post._positive_stack_specs_are_normalized_for_codegen_8616(
                        stack_vars, codegen
                    )
                    for offset, spec in stack_vars.items():
                        if not isinstance(offset, int) or offset <= 0:
                            continue
                        name = spec if isinstance(spec, str) else None
                        if isinstance(spec, dict):
                            spec_name = spec.get("name")
                            if isinstance(spec_name, str):
                                name = spec_name
                        if isinstance(name, str) and name:
                            codegen_offset = offset + 2 if positive_specs_are_normalized else offset
                            arg_name_by_offset[_canonical_stack_offset_8616(codegen_offset)] = name
        prototype = getattr(cfunc, "functy", None)
        proto_arg_names = tuple(getattr(prototype, "arg_names", ()) or ())
        proto_args = tuple(getattr(prototype, "args", ()) or ())
        if proto_arg_names and len(proto_arg_names) == len(proto_args):
            next_offset = 4
            for arg_name, arg_type in zip(proto_arg_names, proto_args):
                if isinstance(arg_name, str) and arg_name and next_offset not in arg_name_by_offset:
                    arg_name_by_offset[next_offset] = arg_name
                bits = getattr(arg_type, "size", None)
                try:
                    width = int(bits // 8) if isinstance(bits, int) and bits > 0 else 2
                except Exception:
                    width = 2
                if width <= 0:
                    width = 2
                next_offset += max(2, width)
        for arg in arg_list:
            arg_var = getattr(arg, "variable", None)
            if not isinstance(arg_var, SimStackVariable):
                continue
            arg_offset = _canonical_stack_offset_8616(getattr(arg_var, "offset", None))
            if not isinstance(arg_offset, int):
                continue
            arg_name = getattr(arg, "name", None)
            arg_var_name = getattr(arg_var, "name", None)
            preferred_name = next(
                (name for name in (arg_name, arg_var_name) if isinstance(name, str) and name and not name.startswith("arg_")),
                None,
            )
            if preferred_name is None and isinstance(arg_var_name, str) and arg_var_name:
                preferred_name = arg_var_name
            if preferred_name is None and isinstance(arg_name, str) and arg_name:
                preferred_name = arg_name
            if preferred_name is not None and arg_offset not in arg_name_by_offset:
                arg_name_by_offset[arg_offset] = preferred_name
        local_maps = []
        unified = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            local_maps.append(unified)
        vars_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(vars_in_use, dict):
            local_maps.append(vars_in_use)
        stack_name_pat = re.compile(r"^(?:s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|arg_[0-9a-fA-F]+)$")

        def _install_live_stack_local(node, var, offset: int) -> None:
            if offset in arg_name_by_offset:
                return
            variables_in_use = getattr(cfunc, "variables_in_use", None)
            if isinstance(variables_in_use, dict) and var not in variables_in_use:
                variables_in_use[var] = node
            unified_locals = getattr(cfunc, "unified_local_vars", None)
            if not isinstance(unified_locals, dict):
                unified_locals = {}
                with contextlib.suppress(Exception):
                    cfunc.unified_local_vars = unified_locals
            if isinstance(unified_locals, dict) and var not in unified_locals:
                unified_locals[var] = {(node, getattr(node, "variable_type", None))}
                codegen._inertia_stack_identifier_live_node_declarations_8616 = int(
                    getattr(codegen, "_inertia_stack_identifier_live_node_declarations_8616", 0) or 0
                ) + 1

        for mapping in local_maps:
            for var, cvar in tuple(mapping.items()):
                if var.__class__.__name__ != "SimStackVariable":
                    continue
                ident = getattr(var, "ident", None)
                if ident is None:
                    try:
                        var.ident = ""
                    except Exception:
                        continue
                # Normalize unresolved stack carrier names to stable stack semantics.
                # This is typed/name materialization from stack offsets, not text cleanup.
                name = getattr(var, "name", None)
                offset = _canonical_stack_offset_8616(getattr(var, "offset", None))
                if not isinstance(offset, int):
                    continue
                new_name = arg_name_by_offset.get(offset)
                if new_name is None and isinstance(name, str) and stack_name_pat.match(name):
                    new_name = _stack_object_name(offset, codegen=codegen)
                if new_name is None:
                    continue
                try:
                    var.name = new_name
                except Exception:
                    continue
                if cvar.__class__.__name__ == "CVariable":
                    with contextlib.suppress(Exception):
                        cvar.name = new_name
        node_roots = [cfunc]
        statements_root = getattr(cfunc, "statements", None)
        if statements_root is not None:
            node_roots.append(statements_root)
        for root in node_roots:
            nodes = (root, *_iter_c_nodes_deep_8616(root))
            for node in nodes:
                if node.__class__.__name__ != "CVariable":
                    continue
                for attr in ("variable", "unified_variable"):
                    var = getattr(node, attr, None)
                    if var.__class__.__name__ != "SimStackVariable":
                        continue
                    offset = _canonical_stack_offset_8616(getattr(var, "offset", None))
                    if not isinstance(offset, int):
                        continue
                    new_name = arg_name_by_offset.get(offset)
                    if new_name is None:
                        current_name = getattr(node, "name", None) or getattr(var, "name", None)
                        if isinstance(current_name, str) and stack_name_pat.match(current_name):
                            new_name = _stack_object_name(offset, codegen=codegen)
                    if new_name is None:
                        continue
                    try:
                        var.name = new_name
                    except Exception:
                        continue
                    with contextlib.suppress(Exception):
                        node.name = new_name
                    _install_live_stack_local(node, var, offset)

    return _impl()


def _inertia_run_pre_rewrite_invariant_gate(project, codegen, function) -> None:
    """Run the pre-rewrite invariant checks and record results on codegen.

    AGENTS rule: rewrite must not hide bad alias/type/condition recovery.
    If invariants fail, rewrite is skipped and honest partial output is emitted.

    CRITICAL: transfer semantic alias facts from lifter/emulator to codegen
    BEFORE running invariants, so the invariant checks can see them.
    """
    def _transfer_alias_facts_once() -> None:
        if getattr(codegen, "_inertia_semantic_facts_transferred", False):
            return
        try:
            transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        except Exception as ex:
            setattr(codegen, "_inertia_semantic_facts_transfer_error", str(ex))
        finally:
            codegen._inertia_semantic_facts_transferred = True

    def _materialize_stack_facts_once() -> None:
        if getattr(codegen, "_inertia_stack_lowered_from_facts", False):
            return
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            try:
                lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
            except Exception as ex:
                setattr(codegen, "_inertia_stack_lowering_error", str(ex))
        codegen._inertia_stack_lowered_from_facts = True

    def _transfer_typed_conditions_once() -> None:
        if getattr(codegen, "_inertia_typed_conditions_transferred", False):
            return
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

    def _record_invariant_report(report) -> None:
        if function is not None:
            info = getattr(function, "info", None)
            if isinstance(info, MutableMapping):
                info["x86_16_pre_rewrite_invariant_report"] = report.to_dict()
        codegen._inertia_invariant_report = report
        codegen._inertia_invariant_checked = True

    def _record_dead_setup_counters() -> None:
        if function is None:
            return
        info = getattr(function, "info", None)
        if not isinstance(info, MutableMapping):
            return
        info["x86_16_dead_setup"] = {
            "dead_setup_candidates": int(getattr(codegen, "dead_setup_candidates", 0)),
            "dead_setup_pruned": int(getattr(codegen, "dead_setup_pruned", 0)),
            "dead_setup_refused": int(getattr(codegen, "dead_setup_refused", 0)),
        }
        info["x86_16_loop_exit_guard"] = dict(getattr(codegen, "_inertia_loop_exit_guard_stats_8616", {}))

    def _enforce_dead_setup_gate() -> None:
        dead_setup_escaped = _count_dead_setup_escaped_8616(codegen)
        setattr(codegen, "dead_setup_escaped", int(dead_setup_escaped))
        if function is not None:
            info = getattr(function, "info", None)
            if isinstance(info, MutableMapping):
                dead_setup_info = info.setdefault("x86_16_dead_setup", {})
                if isinstance(dead_setup_info, MutableMapping):
                    dead_setup_info["dead_setup_escaped"] = int(dead_setup_escaped)
        if dead_setup_escaped <= 0:
            return
        raise PipelineHardError(
            "dead setup artifacts escaped final C",
            layer="codegen",
            function_addr=getattr(function, "addr", None),
            details={
                "dead_setup_candidates": int(getattr(codegen, "dead_setup_candidates", 0)),
                "dead_setup_pruned": int(getattr(codegen, "dead_setup_pruned", 0)),
                "dead_setup_refused": int(getattr(codegen, "dead_setup_refused", 0)),
                "dead_setup_escaped": int(dead_setup_escaped),
            },
        )

    def _run_pipeline_contract_gate() -> None:
        try:
            assert_pipeline_contracts_8616(codegen)
        except Exception as ex:
            stack_lane = getattr(codegen, "_inertia_stack_lane", None)
            cond_lane = getattr(codegen, "_inertia_condition_lane", None)
            logging.getLogger(__name__).warning(
                "Pipeline contract gate failed at function=%#x stage=invariant-gate: %s stack_lane=%s condition_lane=%s",
                getattr(function, "addr", -1) or -1,
                ex,
                stack_lane.summary_line() if stack_lane is not None and hasattr(stack_lane, "summary_line") else stack_lane,
                cond_lane.summary_line() if cond_lane is not None and hasattr(cond_lane, "summary_line") else cond_lane,
            )
            raise

    def _log_rewrite_gate_result(report) -> None:
        log = logging.getLogger(__name__)
        if report.rewrite_blocked:
            codegen._inertia_rewrite_failed = True
            codegen._inertia_rewrite_failure_pass = "invariant_gate"
            codegen._inertia_rewrite_failure_error = report.skip_reason
            formatted = format_invariant_report_8616(report)
            log.warning(
                "Pre-rewrite invariant gate BLOCKED rewrite for %#x (%s): %s",
                getattr(function, "addr", 0),
                getattr(function, "name", "?"),
                report.skip_reason,
            )
            log.warning("Invariant report:\n%s", formatted)
            return
        log.debug(
            "Pre-rewrite invariant gate passed for %#x (%s)",
            getattr(function, "addr", 0),
            getattr(function, "name", "?"),
        )

    _transfer_alias_facts_once()
    _materialize_stack_facts_once()
    _transfer_typed_conditions_once()

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

    _record_invariant_report(report)
    _record_dead_setup_counters()
    _enforce_dead_setup_gate()
    _run_pipeline_contract_gate()
    _log_rewrite_gate_result(report)


def _decompile_8616(self):
    def _impl():
        _orig_decompiler_decompile = getattr(_decompile_8616, "_orig_decompiler_decompile", None)
        if _orig_decompiler_decompile is None:
            _orig_decompiler_decompile = Decompiler._decompile
            _decompile_8616._orig_decompiler_decompile = _orig_decompiler_decompile
        core_started = time.perf_counter()
        self.project._inertia_decompiler_stage = "core"
        with span(
            "x86_16.decompile.core",
            function=getattr(getattr(self, "function", None) or getattr(self, "func", None), "addr", None),
        ):
            _orig_decompiler_decompile(self)
        core_elapsed = time.perf_counter() - core_started
        cfunc = getattr(self.codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        func_name = getattr(cfunc, "name", None) if cfunc is not None else None
        tv_enabled = bool(getattr(self.project, "_inertia_tail_validation_enabled", True))
        if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
            import sys as _tv_sys

            _tv_sys.stderr.write(
                f"[dbg] _decompile_8616: addr={func_addr} name={func_name} codegen_is_none={self.codegen is None} tv_enabled={tv_enabled}\n"
            )
            _tv_sys.stderr.flush()
        if self.project.arch.name != "86_16" or self.codegen is None:
            return
        stage_function = getattr(self, "function", None) or getattr(self, "func", None)
        if stage_function is not None:
            self.codegen._inertia_current_function_8616 = stage_function

        def _run_no_tv_path():
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

        if not tv_enabled:
            _run_no_tv_path()
            return

        validation_mode = "live_out"
        import sys as _tv_sys3

        _tv_sys3.stderr.write(f"[dbg] _decompile_8616 ENTER validation path: addr={func_addr} id={id(self.codegen)}\n")
        _tv_sys3.stderr.flush()
        with span("x86_16.decompile.pre_validation_prime", function=func_addr):
            _prime_stack_semantics_before_validation_baseline_8616(self.project, self.codegen)
            _prime_callsite_summaries_before_validation_baseline_8616(self.project, self.codegen)
            _repair_cfunc_statements_wrapper(self.codegen)
        baseline_cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
        baseline_metadata_snapshot = (
            _snapshot_codegen_inertia_metadata_8616(self.codegen)
            if baseline_cfunc_snapshot is not None
            else None
        )
        baseline_text_snapshot = (
            _snapshot_codegen_text_state_8616(self.codegen)
            if baseline_cfunc_snapshot is not None
            else None
        )
        baseline_project_function_snapshot = (
            _snapshot_project_function_metadata_8616(self.project, func_addr)
            if baseline_cfunc_snapshot is not None
            else None
        )
        with span("x86_16.decompile.validation.before_fingerprint", function=func_addr):
            before_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
        before_collect_started = time.perf_counter()
        with span("x86_16.decompile.validation.before_summary", function=func_addr):
            before_summary = _structuring_tail_validation_baseline_summary_8616(
                self.codegen,
                mode=validation_mode,
                before_fingerprint=before_fingerprint,
            )
            annotate_current_span(reused_structuring_baseline=before_summary is not None)
            if before_summary is None:
                before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
                    self.project,
                    self.codegen,
                    mode=validation_mode,
                    boundary_fingerprint=before_fingerprint,
                )
        before_collect_elapsed = time.perf_counter() - before_collect_started
        if baseline_cfunc_snapshot is not None:
            _restore_project_function_metadata_8616(baseline_project_function_snapshot)
            _restore_codegen_cfunc(self.codegen, baseline_cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, baseline_metadata_snapshot)
            _restore_codegen_text_state_8616(self.codegen, baseline_text_snapshot)
        setattr(self.codegen, "_inertia_postprocess_pre_validation_summary", before_summary)
        # Snapshot pre-postprocess codegen for the semantic gate. In the
        # validation-enabled path, mutating postprocess is only safe when a
        # rejected result can be restored.
        pre_postprocess_cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
        pre_postprocess_metadata_snapshot = (
            _snapshot_codegen_inertia_metadata_8616(self.codegen)
            if pre_postprocess_cfunc_snapshot is not None
            else None
        )
        pre_postprocess_text_snapshot = (
            _snapshot_codegen_text_state_8616(self.codegen)
            if pre_postprocess_cfunc_snapshot is not None
            else None
        )
        pre_postprocess_project_function_snapshot = (
            _snapshot_project_function_metadata_8616(self.project, func_addr)
            if pre_postprocess_cfunc_snapshot is not None
            else None
        )
        postprocess_started = time.perf_counter()
        postprocess_exception: Exception | None = None
        if pre_postprocess_cfunc_snapshot is None:
            changed = False
            setattr(self.codegen, "_inertia_postprocess_skipped_missing_snapshot", True)
            snapshot_error = getattr(self.codegen, "_inertia_postprocess_snapshot_error", None)
            logging.getLogger(__name__).error(
                "86_16 validation postprocess skipped for function=%#x: pre-postprocess snapshot unavailable: %s",
                int(func_addr) if isinstance(func_addr, int) else -1,
                snapshot_error or "unknown",
            )
        else:
            try:
                with span("x86_16.decompile.postprocess", function=func_addr):
                    changed = _postprocess_codegen_8616(self.project, self.codegen)
                    annotate_current_span(
                        changed=bool(changed),
                        last_pass=getattr(self.codegen, "_inertia_last_postprocess_pass", None),
                    )
            except Exception as ex:  # pragma: no cover - defensive stage-finalization path
                postprocess_exception = ex
                changed = False
                logging.getLogger(__name__).warning(
                    "86_16 postprocess pipeline raised; restoring pre-postprocess snapshot for function=%#x: %s",
                    int(func_addr) if isinstance(func_addr, int) else -1,
                    ex,
                    exc_info=True,
                )
                with contextlib.suppress(Exception):
                    _restore_project_function_metadata_8616(pre_postprocess_project_function_snapshot)
                    _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
                    _restore_codegen_inertia_metadata_8616(self.codegen, pre_postprocess_metadata_snapshot)
                    _restore_codegen_text_state_8616(self.codegen, pre_postprocess_text_snapshot)
                setattr(self.codegen, "_inertia_postprocess_exception", repr(ex))
                setattr(
                    self.codegen,
                    "_inertia_postprocess_exception_pass",
                    getattr(self.codegen, "_inertia_last_postprocess_pass", None),
                )
        postprocess_elapsed = time.perf_counter() - postprocess_started
        if not changed and pre_postprocess_cfunc_snapshot is not None:
            _restore_project_function_metadata_8616(pre_postprocess_project_function_snapshot)
            _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, pre_postprocess_metadata_snapshot)
            _restore_codegen_text_state_8616(self.codegen, pre_postprocess_text_snapshot)
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
        # Keep diagnostics available, but do not run mutating gate logic by default
        # in validated flow. Late-stage semantic mutation here can invalidate the
        # postprocess equivalence contract.
        if os.environ.get("INERTIA_ENABLE_PRE_REWRITE_INVARIANT_GATE", "").strip().lower() in {"1", "true", "yes", "on"}:
            _inertia_run_pre_rewrite_invariant_gate(self.project, self.codegen, function)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        if not changed and pre_postprocess_cfunc_snapshot is not None:
            with span("x86_16.decompile.validation.after_fingerprint", function=func_addr, identity_restore=True):
                after_fingerprint = before_fingerprint
            after_collect_started = time.perf_counter()
            with span("x86_16.decompile.validation.after_summary", function=func_addr, identity_restore=True):
                after_summary = before_summary
            after_collect_elapsed = time.perf_counter() - after_collect_started
        else:
            with span("x86_16.decompile.validation.after_fingerprint", function=func_addr):
                after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
                    self.project,
                    self.codegen,
                    mode=validation_mode,
                )
            after_collect_started = time.perf_counter()
            with span("x86_16.decompile.validation.after_summary", function=func_addr):
                after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
                    self.project,
                    self.codegen,
                    mode=validation_mode,
                    boundary_fingerprint=after_fingerprint,
                )
            after_collect_elapsed = time.perf_counter() - after_collect_started
        owner = getattr(function, "info", None) if function is not None else None
        validation_started = time.perf_counter()
        with span("x86_16.decompile.validation.compare", function=func_addr):
            validation = build_x86_16_tail_validation_cached_result(
                owner=owner if isinstance(owner, MutableMapping) else None,
                stage="postprocess",
                mode=validation_mode,
                before_fingerprint=before_fingerprint,
                after_fingerprint=after_fingerprint,
                before_summary=before_summary,
                after_summary=after_summary,
            )
        if postprocess_exception is not None:
            validation["changed"] = True
            validation["status"] = "changed"
            validation["summary_text"] = f"postprocess exception: {type(postprocess_exception).__name__}"
        callsite_stats = getattr(self.codegen, "_inertia_callsite_materialization_stats", None)
        callsite_mismatch_count = int(getattr(callsite_stats, "known_prototype_arg_mismatch_count", 0) or 0)
        if callsite_mismatch_count > 0:
            validation["changed"] = True
            validation["status"] = "changed"
            validation["summary_text"] = (
                f"callsite materialization failed: known prototype argument mismatch count={callsite_mismatch_count}"
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
        if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
            import sys as _tv_sys4

            _tv_sys4.stderr.write(
                "[dbg] _decompile_8616 summaries: "
                f"before_conditions={tuple(getattr(before_summary, 'conditions', ()) or ())!r} "
                f"after_conditions={tuple(getattr(after_summary, 'conditions', ()) or ())!r} "
                f"before_control={tuple(getattr(before_summary, 'control_flow_effects', ()) or ())!r} "
                f"after_control={tuple(getattr(after_summary, 'control_flow_effects', ()) or ())!r}\n"
            )
            _tv_sys4.stderr.flush()
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

            _tv_sys2.stderr.write(
                f"[dbg] _decompile_8616 persist: addr={func_addr} name={func_name} snapshot_stages={list(snapshot.keys()) if isinstance(snapshot, dict) else 'NONE'} codegen_id={id(self.codegen)}\n"
            )
            _tv_sys2.stderr.flush()
        log = logging.getLogger(__name__)
        if not x86_16_tail_validation_result_passed(validation):
            _postprocess_ctx = {
                "validation_mode": validation_mode,
                "function": function,
                "snapshot_function_info": snapshot_function_info,
                "before_fingerprint": before_fingerprint,
                "before_summary": before_summary,
                "pre_postprocess_cfunc_snapshot": pre_postprocess_cfunc_snapshot,
                "pre_postprocess_metadata_snapshot": pre_postprocess_metadata_snapshot,
                "validation_timings": validation_timings,
                "func_addr": func_addr,
                "postprocess_exception": postprocess_exception,
                "callsite_mismatch_count": callsite_mismatch_count,
            }
            if postprocess_exception is not None or callsite_mismatch_count > 0:
                self.codegen._inertia_postprocess_validation_failed = True
                self.codegen._inertia_postprocess_validation_failure_pass = getattr(
                    self.codegen,
                    "_inertia_last_postprocess_pass",
                    None,
                )
                self.codegen._inertia_postprocess_validation_failure_error = (
                    repr(postprocess_exception)
                    if postprocess_exception is not None
                    else f"known prototype argument mismatch count={callsite_mismatch_count}"
                )
                log.error(
                    "Postprocess validation failed due to final callsite invariant; refusing stable fallback: %s",
                    validation["verdict"],
                )
                self.project._inertia_decompiler_stage = "postprocess_failed"
                return
            _should_return = _handle_failed_postprocess_validation_8616(
                self,
                validation=validation,
                log=log,
                context=_postprocess_ctx,
            )
            if _should_return:
                return
        else:
            log.info("%s", validation["verdict"])
        self.project._inertia_decompiler_stage = "done"
        import sys as _tv_sys4

        tv_snap = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
        _tv_sys4.stderr.write(
            f"[dbg] _decompile_8616 DONE: addr={func_addr} codegen_id={id(self.codegen)} snapshot_stages={list(tv_snap.keys()) if isinstance(tv_snap, dict) else 'NONE'} proj_fb_stages={list(getattr(self.project, '_inertia_last_tail_validation_snapshot', {}).keys())}\n"
        )
        _tv_sys4.stderr.flush()

    return _impl()


def _handle_failed_postprocess_validation_8616(self, *, validation, log, context: dict[str, object]) -> bool:
    validation_mode = str(context["validation_mode"])
    function = context.get("function")
    snapshot_function_info = context.get("snapshot_function_info")
    before_fingerprint = context.get("before_fingerprint")
    before_summary = context.get("before_summary")
    pre_postprocess_cfunc_snapshot = context.get("pre_postprocess_cfunc_snapshot")
    pre_postprocess_metadata_snapshot = context.get("pre_postprocess_metadata_snapshot")
    validation_timings = context.get("validation_timings")
    func_addr = context.get("func_addr")
    validation_verdict_text = _rescue_missing_source_calls_8616(
        self,
        validation=validation,
        validation_mode=validation_mode,
        snapshot_function_info=snapshot_function_info,
        before_fingerprint=before_fingerprint,
        before_summary=before_summary,
    )
    if _try_accept_failed_postprocess_validation_8616(
        self,
        validation=validation,
        validation_verdict_text=validation_verdict_text,
        function=function,
        snapshot_function_info=snapshot_function_info,
        pre_postprocess_cfunc_snapshot=pre_postprocess_cfunc_snapshot,
        func_addr=func_addr,
        log=log,
    ):
        return True
    _discard_failed_postprocess_result_8616(
        self,
        validation=validation,
        validation_verdict_text=validation_verdict_text,
        validation_mode=validation_mode,
        snapshot_function_info=snapshot_function_info,
        before_fingerprint=before_fingerprint,
        before_summary=before_summary,
        pre_postprocess_cfunc_snapshot=pre_postprocess_cfunc_snapshot,
        pre_postprocess_metadata_snapshot=pre_postprocess_metadata_snapshot,
        validation_timings=validation_timings,
        function=function,
        log=log,
    )
    return False


def _postprocess_stable_accept_8616(self, validation, snapshot_function_info) -> None:
    if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        top_count = len(tuple(getattr(root, "statements", ()) or ())) if root is not None else 0
        if_count, return_count = _return_chain_counts_8616(self.codegen)
        logging.getLogger(__name__).warning(
            "[empty-return-branch] stable-accept before-regen top=%d ifs=%d returns=%d",
            top_count,
            if_count,
            return_count,
        )
    _regenerate_text_safely(self.codegen, context="postprocess:accepted-validation-delta")
    if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        top_count = len(tuple(getattr(root, "statements", ()) or ())) if root is not None else 0
        if_count, return_count = _return_chain_counts_8616(self.codegen)
        text = getattr(self.codegen, "text", "") or ""
        logging.getLogger(__name__).warning(
            "[empty-return-branch] stable-accept after-regen top=%d ifs=%d returns=%d text_returns=%d text_len=%d",
            top_count,
            if_count,
            return_count,
            text.count("return "),
            len(text),
        )
    validation["changed"] = False
    validation["status"] = "stable"
    validation["summary_text"] = "no observable whole-tail changes"
    validation.pop("delta", None)
    validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
    persist_x86_16_tail_validation_snapshot(
        function_info=snapshot_function_info,
        codegen=self.codegen,
        stage="postprocess",
        validation=validation,
    )
    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        postprocess_entry = snapshot.get("postprocess")
        if isinstance(postprocess_entry, dict):
            postprocess_entry.pop("delta", None)
            postprocess_entry["changed"] = False
            postprocess_entry["status"] = "stable"
            postprocess_entry["summary_text"] = "no observable whole-tail changes"
        setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))


def _rescue_missing_source_calls_8616(
    self,
    *,
    validation,
    validation_mode: str,
    snapshot_function_info,
    before_fingerprint,
    before_summary,
) -> str:
    validation_verdict_text = str(validation.get("verdict") or validation.get("summary_text") or "")
    if "Missing source-evidenced calls" not in validation_verdict_text:
        return validation_verdict_text
    with contextlib.suppress(Exception):
        rescue_changed = bool(_calls._recover_missing_direct_calls_from_evidence_8616(self.project, self.codegen))
        if not rescue_changed:
            return validation_verdict_text
        _calls._materialize_callsite_stack_arguments_8616(self.project, self.codegen)
        _calls._normalize_call_target_names_8616(self.codegen)
        rescue_after_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
        rescue_after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        comparison = compare_x86_16_tail_validation_summaries(before_fingerprint, rescue_after_fingerprint)
        validation.update(
            build_x86_16_tail_validation_cached_result(
                owner=snapshot_function_info,
                stage="postprocess",
                mode=validation_mode,
                comparison=comparison,
                before_summary=before_summary,
                after_summary=rescue_after_summary,
                before_fingerprint=before_fingerprint,
                after_fingerprint=rescue_after_fingerprint,
            )
        )
    return str(validation.get("verdict") or validation.get("summary_text") or "")


def _try_accept_failed_postprocess_validation_8616(
    self,
    *,
    validation,
    validation_verdict_text: str,
    function,
    snapshot_function_info,
    pre_postprocess_cfunc_snapshot,
    func_addr,
    log,
) -> bool:
    def _impl():
        allow_validation_override = str(os.environ.get("INERTIA_ALLOW_POSTPROCESS_VALIDATION_OVERRIDE", "")).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        recovered_call_floor = int(getattr(self.codegen, "_inertia_direct_call_floor_recovered_count", 0) or 0)
        if allow_validation_override and recovered_call_floor > 0 and "Missing source-evidenced calls" in validation_verdict_text:
            log.warning(
                "Postprocess validation changed but keeping call-floor recovery output (recovered=%d): %s",
                recovered_call_floor,
                validation_verdict_text,
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_direct_callsite_helper_and_return_delta_8616(self.project, function, self.codegen, validation):
            log.warning(
                "Postprocess validation helper-call/return delta accepted from CFG evidence: %s",
                validation.get("verdict"),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_cfg_return_chain_callsite_materialization_delta_8616(self.project, function, self.codegen, validation):
            log.warning(
                "Postprocess validation CFG return-chain/callsite delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_cfg_return_expr_chain_materialization_delta_8616(self.project, function, self.codegen, validation):
            log.warning(
                "Postprocess validation CFG return-expression delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_cfg_mask_accumulator_materialization_delta_8616(self.project, function, self.codegen, validation):
            log.warning(
                "Postprocess validation CFG mask-accumulator delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_jcc_call_return_condition_rebinding_delta_8616(self.codegen, validation):
            log.warning(
                "Postprocess validation JCC call-return condition delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            self.codegen._inertia_jcc_call_return_condition_validation_accepts = int(
                getattr(self.codegen, "_inertia_jcc_call_return_condition_validation_accepts", 0) or 0
            ) + 1
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_combined_jcc_callsite_stack_validation_delta_8616(self.project, function, self.codegen, validation):
            log.warning(
                "Postprocess validation combined JCC/callsite delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            self.codegen._inertia_combined_jcc_callsite_validation_accepts_8616 = int(
                getattr(self.codegen, "_inertia_combined_jcc_callsite_validation_accepts_8616", 0) or 0
            ) + 1
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_jcc_condition_materialization_validation_delta_8616(
            self.project,
            self.codegen,
            validation,
            function=function,
        ):
            log.warning(
                "Postprocess validation JCC condition materialization delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            self.codegen._inertia_jcc_condition_materialization_validation_accepts = int(
                getattr(self.codegen, "_inertia_jcc_condition_materialization_validation_accepts", 0) or 0
            ) + 1
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_segmented_stack_slot_size_precision_delta_8616(validation):
            log.warning(
                "Postprocess validation segmented stack-slot size precision delta accepted: %s",
                validation.get("verdict"),
            )
            self.codegen._inertia_segmented_stack_slot_size_precision_validation_accepts = int(
                getattr(self.codegen, "_inertia_segmented_stack_slot_size_precision_validation_accepts", 0) or 0
            ) + 1
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_direct_global_update_materialization_delta_8616(self.codegen, validation):
            log.warning(
                "Postprocess validation direct global update materialization delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            self.codegen._inertia_direct_global_update_validation_accepts_8616 = int(
                getattr(self.codegen, "_inertia_direct_global_update_validation_accepts_8616", 0) or 0
            ) + 1
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_direct_stack_update_materialization_delta_8616(self.codegen, validation):
            log.warning(
                "Postprocess validation direct stack update materialization delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            self.codegen._inertia_direct_stack_update_validation_accepts_8616 = int(
                getattr(self.codegen, "_inertia_direct_stack_update_validation_accepts_8616", 0) or 0
            ) + 1
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_direct_stack_move_idiv_remainder_materialization_delta_8616(self.codegen, validation):
            log.warning(
                "Postprocess validation direct stack move materialization delta accepted from consumed evidence: %s",
                validation.get("verdict"),
            )
            self.codegen._inertia_direct_stack_move_validation_accepts_8616 = int(
                getattr(self.codegen, "_inertia_direct_stack_move_validation_accepts_8616", 0) or 0
            ) + 1
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _is_direct_callsite_helper_delta_only_8616(self.project, function, validation):
            log.warning(
                "Postprocess validation helper-call delta accepted from direct callsite evidence: %s",
                validation.get("verdict"),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _postprocess_exit_goto_repair_delta_8616(validation):
            if _postprocess_has_unresolved_gotos_8616(self.codegen):
                log.warning(
                    "Postprocess validation changed but unresolved function-exit gotos remain: %s",
                    validation.get("verdict"),
                )
                return False
            log.warning(
                "Postprocess validation changed but accepting unresolved-exit-goto canonicalization: %s",
                validation.get("verdict"),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if allow_validation_override and _has_recovered_source_calls_in_codegen_8616(self.project, self.codegen, function):
            log.warning(
                "Postprocess validation changed but keeping recovered call-floor output (source-evidenced calls present): %s",
                validation.get("verdict"),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if "Missing source-evidenced" in validation_verdict_text and pre_postprocess_cfunc_snapshot is not None:
            post_score, post_total = _expected_source_call_score_from_cfunc_8616(
                self.project,
                getattr(self.codegen, "cfunc", None),
                function,
            )
            pre_score, pre_total = _expected_source_call_score_from_cfunc_8616(
                self.project,
                pre_postprocess_cfunc_snapshot,
                function,
            )
            if allow_validation_override and post_total > 0 and post_score >= pre_score:
                log.warning(
                    "Postprocess validation changed but keeping stronger source-call coverage (post=%d/%d pre=%d/%d): %s",
                    post_score,
                    post_total,
                    pre_score,
                    pre_total,
                    validation.get("verdict"),
                )
                _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
                self.project._inertia_decompiler_stage = "done"
                import sys as _tv_sys4

                tv_snap = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
                _tv_sys4.stderr.write(
                    f"[dbg] _decompile_8616 DONE: addr={func_addr} codegen_id={id(self.codegen)} snapshot_stages={list(tv_snap.keys()) if isinstance(tv_snap, dict) else 'NONE'} proj_fb_stages={list(getattr(self.project, '_inertia_last_tail_validation_snapshot', {}).keys())}\n"
                )
                _tv_sys4.stderr.flush()
                return True
        return False

    return _impl()


def _discard_failed_postprocess_result_8616(
    self,
    *,
    validation,
    validation_verdict_text: str,
    validation_mode: str,
    snapshot_function_info,
    before_fingerprint,
    before_summary,
    pre_postprocess_cfunc_snapshot,
    pre_postprocess_metadata_snapshot,
    validation_timings,
    function,
    log,
) -> None:
    if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
        delta = validation.get("delta") if isinstance(validation, dict) else None
        log.warning(
            "[postprocess-validation] final function=%#x verdict=%s stack_delta=%s before=%s after=%s",
            getattr(function, "addr", -1) if function is not None else -1,
            validation.get("verdict"),
            (delta or {}).get("stack_writes"),
            (validation.get("before") or {}).get("stack_writes"),
            (validation.get("after") or {}).get("stack_writes"),
        )
    if pre_postprocess_cfunc_snapshot is None:
        setattr(self.codegen, "_inertia_postprocess_discard_failed_no_snapshot", True)
        log.error(
            "Postprocess validation changed but no pre-postprocess snapshot is available; cannot discard changed C: %s "
            "(last_pass=%s failure_pass=%s)",
            validation["verdict"],
            getattr(self.codegen, "_inertia_last_postprocess_pass", None),
            getattr(self.codegen, "_inertia_postprocess_validation_failure_pass", None),
        )
        return
    log.warning(
        "Postprocess validation changed — discarding postprocessed C, emitting pre-postprocess C: %s (last_pass=%s failure_pass=%s)",
        validation["verdict"],
        getattr(self.codegen, "_inertia_last_postprocess_pass", None),
        getattr(self.codegen, "_inertia_postprocess_validation_failure_pass", None),
    )
    _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
    _restore_codegen_inertia_metadata_8616(self.codegen, pre_postprocess_metadata_snapshot)
    _invalidate_tail_validation_derived_caches_8616(self.codegen)
    self.codegen._inertia_postprocess_discarded = True
    self.codegen._inertia_postprocess_discard_verdict = validation_verdict_text
    restored_after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
        self.project,
        self.codegen,
        mode=validation_mode,
        force_baseline_canonicalization=True,
    )
    restored_after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
        self.project,
        self.codegen,
        mode=validation_mode,
    )
    # Rollback validation must use the freshly collected summaries. The
    # comparison cache is keyed by boundary fingerprints, and this path exists
    # specifically because a rejected postprocess result polluted the live AST;
    # reusing a stale changed comparison here would make a successful restore
    # still look failed.
    restored_validation = {
        **compare_x86_16_tail_validation_summaries(before_summary, restored_after_summary),
        "mode": validation_mode,
    }
    restored_validation["timings"] = validation_timings
    restored_validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", restored_validation)
    persist_x86_16_tail_validation_snapshot(
        function_info=snapshot_function_info,
        codegen=self.codegen,
        stage="postprocess",
        validation=restored_validation,
    )
    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        setattr(self.project, "_inertia_last_tail_validation_snapshot", dict(snapshot))
    log.info("%s", restored_validation["verdict"])


def apply_x86_16_decompiler_postprocess() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_8616":
        _decompile_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_8616
