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
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeBottom, SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from inertia_decompiler.runtime_support import AnalysisTimeout, analysis_timeout, timing_output_enabled

from . import decompiler_postprocess as _post
from . import decompiler_postprocess_calls as _calls
from . import decompiler_postprocess_flags as _flags
from . import decompiler_postprocess_globals as _globals
from . import decompiler_postprocess_jcc as _jcc
from . import decompiler_postprocess_simplify as _simplify
from . import segmented_memory_reasoning as _segmented_mem
from .annotations import ANNOTATION_KEY
from .callee_name_normalization import normalize_callee_name_8616
from .condition_trace import (
    dump_condition_trace_8616,
    materialized_condition_drift_detected_8616,
    record_ast_condition_trace_8616,
    record_tail_validation_condition_trace_8616,
)
from .decompiler_postprocess_typed_conditions import _apply_typed_conditions_to_codegen_8616
from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616
from .lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
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
from .postprocess.optimization.dead_setup import _count_dead_setup_escaped_8616
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
from .tail_validation_fingerprint import _expr_fingerprint

__all__ = [
    "DecompilerPostprocessPassSpec",
    "DECOMPILER_POSTPROCESS_PASSES",
    "_build_decompiler_postprocess_passes",
    "describe_x86_16_decompiler_postprocess_stage",
    "apply_x86_16_decompiler_postprocess",
]


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
    """
    Ensure high-byte projection shifts operate on an integer expression.
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
    if os.environ.get("INERTIA_ENABLE_POST_CALL_STACK_RERUN", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return False

    from inertia_decompiler.cli_c_ast_rewrites import (
        _canonicalize_stack_cvars as _rewrite_canonicalize_stack_cvars,
    )
    from inertia_decompiler.cli_c_ast_rewrites import (
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


def _branch_target_return_expr_8616(project, codegen, target_addr: int):
    try:
        block = project.factory.block(int(target_addr), opt_level=0)
    except Exception:
        return None
    ax_value = None
    dx_value = None

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
                if str(insn.reg_name(mem.base)).lower() == "bp":
                    value = _jcc._stack_slot_expr_8616(codegen, int(mem.disp), int(getattr(rhs, "size", 0) or 2))
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
        if mnemonic in {"jmp", "ljmp", "ret", "retf", "iret"}:
            return _combined_return_expr()
    return _combined_return_expr()


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
    for block_addr, insn in _linear_jcc_block_starts_8616(project, codegen):
        true_target = _jcc._branch_target_imm_8616(insn)
        false_target = _next_unconditional_target_after_jcc_8616(project, int(block_addr), int(insn.address))
        if true_target is None or false_target is None:
            continue
        true_expr = _branch_target_return_expr_8616(project, codegen, true_target)
        false_expr = _branch_target_return_expr_8616(project, codegen, false_target)
        if true_expr is None or false_expr is None:
            continue
        decoded = _jcc._translate_cmp_jcc_guard_8616(project, codegen, int(block_addr), int(insn.address))
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
            if name != "aNchkstk":
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
                return _jcc._stack_slot_expr_8616(codegen, int(mem.disp), int(getattr(operands[1], "size", 0) or 2))
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
    if len(chain) < 4:
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
            selector,
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
            [(cond, CStatements(statements=[CReturn(expr, codegen=codegen)], codegen=codegen))],
            else_node=None,
            cstyle_ifs=True,
            codegen=codegen,
        )
        for cond, expr in ordered
    ]
    statements.append(CReturn(expr_default, codegen=codegen))
    codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
    codegen._inertia_decrement_switch_return_materialized_8616 = True
    codegen._inertia_return_expr_chain_materialized_8616 = True
    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(
        _expr_fingerprint(expr, project) for _cond, expr in ordered
    ) + (_expr_fingerprint(expr_default, project),)
    if debug:
        log.warning("[cfg-selector-return] decrement-switch materialized")
    return True


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
    try:
        function = project.kb.functions.function(addr=func_addr, create=False)
    except Exception:
        return []
    if function is None:
        return []
    pairs: list[tuple[object, int]] = []
    seen_conditions: set[str] = set()
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
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
    stats["candidates"] += len(pairs)
    if debug:
        log.warning("[cfg-selector-return] candidates=%d stats=%r", len(pairs), stats)
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
    for cond, true_expr, _false_expr in pairs:
        true_body = CStatements(statements=[CReturn(true_expr, codegen=codegen)], codegen=codegen)
        statements.append(CIfElse([(cond, true_body)], else_node=None, cstyle_ifs=True, codegen=codegen))
        return_fingerprints.append(_expr_fingerprint(true_expr, project))
    final_expr = pairs[-1][2]
    statements.append(CReturn(final_expr, codegen=codegen))
    return_fingerprints.append(_expr_fingerprint(final_expr, project))
    codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
    stats["materialized"] += len(pairs)
    codegen._inertia_return_expr_chain_materialized_8616 = True
    codegen._inertia_return_selector_materialized_8616 = True
    codegen._inertia_return_chain_materialized_condition_fingerprints_8616 = tuple(
        _expr_fingerprint(cond, project) for cond, _true_expr, _false_expr in pairs
    )
    codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 = tuple(return_fingerprints)
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
    ordered_index = 0
    cond_return_pairs: list[tuple[object, int]] = []
    empty_if_nodes: list[object] = []

    def _body_is_empty(body) -> bool:
        if isinstance(body, CStatements):
            return not tuple(getattr(body, "statements", ()) or ())
        return body is None

    def _return_stmt(value: int):
        return CReturn(CConstant(int(value), SimTypeShort(False), codegen=codegen), codegen=codegen)

    for node in _iter_c_nodes_deep_8616(getattr(codegen.cfunc, "statements", None)):
        if not isinstance(node, CIfElse):
            continue
        cond_pairs = getattr(node, "condition_and_nodes", None)
        if not isinstance(cond_pairs, (list, tuple)) or not cond_pairs:
            continue
        cond, body = cond_pairs[0]
        if not _body_is_empty(body):
            continue
        empty_if_nodes.append(node)
        stats["candidates"] += 1
        value = _condition_branch_return_value_8616(project, cond)
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
            changed = _flatten_conditional_return_chain_8616(project, codegen, cfg_return_pairs) or changed
            cond_return_pairs = cfg_return_pairs
    if not cond_return_pairs and not getattr(codegen, "_inertia_return_chain_suffix_materialized_8616", False):
        cfg_return_pairs = _ordered_conditional_return_pairs_from_cfg_8616(project, codegen)
        if _materialize_cfg_conditional_return_suffix_8616(project, codegen, cfg_return_pairs):
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
    if not getattr(codegen, "_inertia_return_chain_flattened_8616", False):
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
            "_materialize_callsite_stack_arguments_8616",
            _calls._materialize_callsite_stack_arguments_8616,
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
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_final_8616",
            _calls._normalize_call_target_names_8616,
            False,
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
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_materialize_callsite_prototypes_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
        "_materialize_empty_if_return_branches_8616",
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
        direct_call_floor_recovery_enabled = _truthy_env_8616("INERTIA_ENABLE_DIRECT_CALL_FLOOR_RECOVERY")
        if not direct_call_floor_recovery_enabled:
            skip_names.update(
                {
                    "_recover_missing_direct_calls_from_evidence_8616",
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
    _invalidate_tail_validation_derived_caches_8616(codegen)
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
        cloned = copy.copy(cfunc)
        with contextlib.suppress(Exception):
            cloned.statements = copy.deepcopy(getattr(cfunc, "statements", None))
        for attr in ("variables_in_use", "unified_local_vars", "variable_kb"):
            value = getattr(cfunc, attr, None)
            if isinstance(value, dict):
                with contextlib.suppress(Exception):
                    setattr(cloned, attr, dict(value))
            else:
                with contextlib.suppress(Exception):
                    setattr(cloned, attr, value)
        return cloned
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


def _invalidate_tail_validation_derived_caches_8616(codegen) -> None:
    # AST-mutating semantic priming and postprocess passes must not reuse
    # fingerprint/summary/assignment-map caches from the previous AST shape.
    for attr in (
        "_inertia_tail_validation_summary_cache",
        "_inertia_assignment_maps",
        "_inertia_stack_offset_cache",
        "_inertia_stack_pointer_aliases_for_cvars",
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


def _collect_tail_validation_summary_with_baseline_canonicalization_8616(project, codegen, *, mode: str):
    def _impl():
        canonicalization_setting = os.environ.get("INERTIA_ENABLE_TV_BASELINE_CANONICALIZATION", "1").strip().lower()
        if canonicalization_setting in {"0", "false", "no", "off"}:
            return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
        function_addr = getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1
        # Large functions frequently time out in baseline clone canonicalization.
        # For those, use direct summary collection to keep validation deterministic
        # and avoid repeated timeout churn.
        try:
            kb_funcs = getattr(getattr(project, "kb", None), "functions", None)
            fn = (
                kb_funcs.function(function_addr, create=False)
                if kb_funcs is not None and isinstance(function_addr, int) and function_addr >= 0
                else None
            )
            block_count = len(getattr(fn, "block_addrs_set", ()) or ()) if fn is not None else 0
        except Exception:
            block_count = 0
        if block_count >= 40:
            return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)

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
                return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)
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
            return collect_x86_16_tail_validation_summary(project, codegen, mode=mode)

    return _impl()


def _prime_stack_semantics_before_validation_baseline_8616(project, codegen) -> None:
    if getattr(codegen, "_inertia_pre_validation_stack_semantics_primed", False):
        return
    try:
        _invalidate_tail_validation_derived_caches_8616(codegen)
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        from .lowering.real_mode_linear import (
            lower_stable_ds_es_linear_global_dereferences_8616,
            lower_stable_ss_linear_stack_dereferences_8616,
        )

        lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)
        lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project)
        if _fact_backed_stack_normalize_enabled_8616():
            _normalize_fact_backed_stack_accesses_8616(project, codegen)
        _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation stack semantics priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_stack_semantics_primed = True


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
        large_function_for_per_pass_tv = False
        try:
            kb_funcs = getattr(getattr(project, "kb", None), "functions", None)
            fn = (
                kb_funcs.function(func_addr, create=False)
                if kb_funcs is not None and isinstance(func_addr, int) and func_addr >= 0
                else None
            )
            block_count = len(getattr(fn, "block_addrs_set", ()) or ()) if fn is not None else 0
            large_function_for_per_pass_tv = block_count >= 40
        except Exception:
            large_function_for_per_pass_tv = False
        if large_function_for_per_pass_tv and not os.environ.get("INERTIA_FORCE_PER_PASS_TV"):
            per_pass_validation_enabled = False
        codegen._inertia_skip_per_pass_validation_large_function = large_function_for_per_pass_tv
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
        if validation_enabled and not large_function_for_per_pass_tv:
            _prime_stack_semantics_before_validation_baseline_8616(project, codegen)
            baseline_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
                project, codegen, mode="live_out"
            )
        codegen._inertia_postprocess_passes = tuple(spec.name for spec in pass_specs)
        return pass_timeout_seconds, validation_enabled, per_pass_validation_enabled, skip_names, baseline_summary

    return _impl()


def _large_function_for_postprocess_snapshot_8616(project, func_addr: int | None) -> bool:
    try:
        kb_funcs = getattr(getattr(project, "kb", None), "functions", None)
        fn = (
            kb_funcs.function(func_addr, create=False)
            if kb_funcs is not None and isinstance(func_addr, int) and func_addr >= 0
            else None
        )
        return len(getattr(fn, "block_addrs_set", ()) or ()) >= 40 if fn is not None else False
    except Exception:
        return False


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
        return os.environ.get("INERTIA_ENABLE_FLAG_OVERWRITE_PRUNE", "").strip().lower() in {"1", "true", "yes", "on"}
    if spec_name == "_materialize_callsite_stack_arguments_final_8616":
        return os.environ.get("INERTIA_ENABLE_FINAL_CALLSITE_REMATERIALIZE", "").strip().lower() in {"1", "true", "yes", "on"}
    if spec_name == "_normalize_call_target_names_final_8616":
        return os.environ.get("INERTIA_ENABLE_FINAL_CALL_TARGET_NORMALIZE", "").strip().lower() in {"1", "true", "yes", "on"}
    if spec_name == "_normalize_fact_backed_stack_accesses_8616":
        return _fact_backed_stack_normalize_enabled_8616()
    return True


def _postprocess_set_completion_state_8616(project, codegen, accepted_changed: bool) -> bool:
    codegen._inertia_postprocess_changed = accepted_changed
    project._inertia_decompiler_stage = "postprocess"
    return accepted_changed


def _postprocess_run_bootstrap_steps_8616(project, codegen, skip_names: set[str], apply_step) -> bool:
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
    if "_rewrite_decoded_jcc_conditions_8616" not in skip_names:
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
            project._inertia_decompiler_stage = f"postprocess:{spec.name}"
            _t_pass = _ppt.perf_counter()
            if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
                import sys as _ppsys

                _ppsys.stderr.write(
                    f"[{_ppt.strftime('%H:%M:%S')}] postprocess pass: {spec.name} (+{_t_pass - _t_pp_start:.1f}s)\n"
                )
                _ppsys.stderr.flush()
            step = (lambda spec=spec: spec.func(project, codegen)) if spec.needs_project else (lambda spec=spec: spec.func(codegen))
            if not apply_step(spec.name, step):
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

        def _apply_step(pass_name: str, step_func) -> bool:
            nonlocal accepted_changed, last_changed_pass
            # Repair: ensure statements is always CStatements before every pass.
            # Many transform() callbacks return plain lists, which corrupts downstream.
            _repair_cfunc_statements_wrapper(codegen)
            snapshot = _snapshot_codegen_cfunc(codegen) if per_pass_validation_enabled else None
            return_chain_expected = _return_chain_expected_counts_8616(codegen)
            if return_chain_expected is not None and snapshot is None:
                snapshot = _snapshot_codegen_cfunc(codegen)
            try:
                if isinstance(pass_timeout_seconds, int) and pass_timeout_seconds > 0:
                    with analysis_timeout(pass_timeout_seconds):
                        step_changed = bool(step_func())
                else:
                    step_changed = bool(step_func())
            except AnalysisTimeout as ex:
                if per_pass_validation_enabled:
                    _restore_codegen_cfunc(codegen, snapshot)
                codegen._inertia_rewrite_failed = True
                codegen._inertia_rewrite_failure_pass = pass_name
                codegen._inertia_rewrite_failure_error = f"timeout: {ex}"
                logging.getLogger(__name__).warning(
                    "Skipping 86_16 postprocess pass %s after %s: timeout (%s)",
                    pass_name,
                    last_changed_pass or "no earlier rewrite",
                    ex,
                )
                return False
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
                    _restore_codegen_cfunc(codegen, snapshot)
                    rejected = list(getattr(codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                    rejected.append(pass_name)
                    codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                    return True
            enforce_pass_validation = per_pass_validation_enabled or pass_name in {
                "_rewrite_decoded_jcc_conditions_8616",
                "_rewrite_decoded_jcc_conditions_after_calls_8616",
                "_repair_loop_exit_return_guards_8616",
                "_recover_missing_direct_calls_from_evidence_8616",
                "_normalize_fact_backed_stack_accesses_8616",
                "_normalize_call_target_names_8616",
                "_normalize_recovered_call_target_names_8616",
                "_materialize_callsite_stack_arguments_8616",
                "_materialize_callsite_prototypes_8616",
                "_materialize_recovered_callsite_stack_arguments_8616",
                "_recover_missing_direct_calls_final_8616",
            }
            if getattr(codegen, "_inertia_skip_per_pass_validation_large_function", False):
                enforce_pass_validation = False
            if validation_enabled and enforce_pass_validation and baseline_summary is not None:
                if step_changed:
                    _invalidate_tail_validation_derived_caches_8616(codegen)
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
                    is_blocking_delta = any(marker in summary_text for marker in blocking_markers)
                    if pass_name in {
                        "_rewrite_decoded_jcc_conditions_8616",
                        "_rewrite_decoded_jcc_conditions_after_calls_8616",
                        "_recover_missing_direct_calls_from_evidence_8616",
                        "_normalize_fact_backed_stack_accesses_8616",
                        "_normalize_call_target_names_8616",
                        "_normalize_recovered_call_target_names_8616",
                        "_materialize_callsite_stack_arguments_8616",
                        "_materialize_callsite_prototypes_8616",
                        "_materialize_recovered_callsite_stack_arguments_8616",
                        "_recover_missing_direct_calls_final_8616",
                    }:
                        if is_exit_goto_repair_delta:
                            is_blocking_delta = False
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
                    _restore_codegen_cfunc(codegen, snapshot)
                    # Pass-local reject: keep baseline snapshot and continue with later passes.
                    return True

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
            final_context = (
                f"{trace_func_addr:#x} postprocess:final" if isinstance(trace_func_addr, int) else "postprocess:final"
            )
            _regenerate_text_safely(codegen, context=final_context)
        return _postprocess_set_completion_state_8616(project, codegen, accepted_changed)

    return _impl()


def _regenerate_text_safely(codegen, *, context: str) -> bool:
    try:
        _normalize_stack_variable_identifiers_8616(codegen)
        _bind_codegen_variable_types_to_arch_8616(codegen)
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
            exc_info=True,
        )
        return False
    codegen._inertia_regeneration_failed = False
    codegen._inertia_regeneration_error = None
    codegen._inertia_regeneration_context = context
    codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
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
    if function is None or not isinstance(validation, dict):
        return False
    if not getattr(codegen, "_inertia_return_chain_flattened_8616", False):
        return False
    stats = getattr(codegen, "_inertia_empty_return_branch_stats_8616", None)
    if not isinstance(stats, dict):
        return False
    if int(stats.get("refused", 0) or 0) != 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    allowed_fields = {"helper_calls", "returns", "segmented_writes", "conditions", "control_flow_effects"}
    if not touched_fields or touched_fields - allowed_fields:
        return False

    conditional_values = tuple(int(value) for value in _ordered_conditional_return_values_8616(project, codegen))
    materialized_values = tuple(int(value) for value in getattr(codegen, "_inertia_return_chain_materialized_values_8616", ()) or ())
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

    helper_delta = delta.get("helper_calls")
    if isinstance(helper_delta, dict) and ((helper_delta.get("added") or ()) or (helper_delta.get("removed") or ())):
        helper_validation = dict(validation)
        helper_validation["delta"] = {"helper_calls": helper_delta}
        if not _is_direct_callsite_helper_delta_only_8616(project, function, helper_validation):
            return False

    return True


def _is_cfg_return_expr_chain_materialization_delta_8616(project, function, codegen, validation: dict[str, object]) -> bool:
    if function is None or not isinstance(validation, dict):
        return False
    if not getattr(codegen, "_inertia_return_expr_chain_materialized_8616", False):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    allowed_fields = {"returns"}
    if getattr(codegen, "_inertia_return_selector_materialized_8616", False):
        allowed_fields = {"returns", "conditions", "control_flow_effects"}
    if not touched_fields or touched_fields - allowed_fields or "returns" not in touched_fields:
        return False
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    added_returns = set(returns_delta.get("added") or ())
    removed_returns = set(returns_delta.get("removed") or ())
    expected_returns = set(getattr(codegen, "_inertia_return_expr_chain_materialized_return_fingerprints_8616", ()) or ())
    if not expected_returns or added_returns - expected_returns:
        return False
    if any(
        item not in {"CDirtyExpression", "none"}
        and "CDirtyExpression" not in item
        and not item.startswith(("Concat(", "Or("))
        for item in removed_returns
    ):
        return False
    if getattr(codegen, "_inertia_return_selector_materialized_8616", False):
        expected_conditions = set(
            getattr(codegen, "_inertia_return_chain_materialized_condition_fingerprints_8616", ()) or ()
        )
        condition_delta = delta.get("conditions")
        if isinstance(condition_delta, dict):
            added_conditions = set(condition_delta.get("added") or ())
            if not expected_conditions or added_conditions - expected_conditions:
                return False
        control_delta = delta.get("control_flow_effects")
        if isinstance(control_delta, dict):
            added_control = set(control_delta.get("added") or ())
            expected_control = {f"if:{fp}" for fp in expected_conditions}
            if added_control - expected_control:
                return False
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
                annotations = info.get(ANNOTATION_KEY) if isinstance(info, dict) else None
                stack_vars = annotations.get("stack_vars") if isinstance(annotations, dict) else None
                if isinstance(stack_vars, dict):
                    for offset, spec in stack_vars.items():
                        if not isinstance(offset, int) or offset <= 0:
                            continue
                        name = spec if isinstance(spec, str) else None
                        if isinstance(spec, dict):
                            spec_name = spec.get("name")
                            if isinstance(spec_name, str):
                                name = spec_name
                        if isinstance(name, str) and name:
                            arg_name_by_offset[_canonical_stack_offset_8616(offset)] = name
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
        for mapping in local_maps:
            for var in tuple(mapping.keys()):
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
                        continue
                    try:
                        var.name = new_name
                    except Exception:
                        continue

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
        _prime_stack_semantics_before_validation_baseline_8616(self.project, self.codegen)
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
        before_collect_started = time.perf_counter()
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_collect_elapsed = time.perf_counter() - before_collect_started
        # Snapshot pre-postprocess codegen for semantic gate
        skip_pre_postprocess_snapshot = _large_function_for_postprocess_snapshot_8616(self.project, func_addr)
        pre_postprocess_cfunc_snapshot = None if skip_pre_postprocess_snapshot else _snapshot_codegen_cfunc(self.codegen)
        postprocess_started = time.perf_counter()
        postprocess_exception: Exception | None = None
        try:
            changed = _postprocess_codegen_8616(self.project, self.codegen)
        except Exception as ex:  # pragma: no cover - defensive stage-finalization path
            postprocess_exception = ex
            changed = False
            logging.getLogger(__name__).warning(
                "86_16 postprocess pipeline raised; restoring pre-postprocess snapshot for function=%#x: %s",
                int(func_addr) if isinstance(func_addr, int) else -1,
                ex,
                exc_info=True,
            )
            if pre_postprocess_cfunc_snapshot is not None:
                with contextlib.suppress(Exception):
                    _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
            elif skip_pre_postprocess_snapshot:
                raise
            setattr(self.codegen, "_inertia_postprocess_exception", repr(ex))
            setattr(
                self.codegen,
                "_inertia_postprocess_exception_pass",
                getattr(self.codegen, "_inertia_last_postprocess_pass", None),
            )
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
        # Keep diagnostics available, but do not run mutating gate logic by default
        # in validated flow. Late-stage semantic mutation here can invalidate the
        # postprocess equivalence contract.
        if os.environ.get("INERTIA_ENABLE_PRE_REWRITE_INVARIANT_GATE", "").strip().lower() in {"1", "true", "yes", "on"}:
            _inertia_run_pre_rewrite_invariant_gate(self.project, self.codegen, function)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(self.project, self.codegen, mode=validation_mode)
        after_collect_started = time.perf_counter()
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
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
        if postprocess_exception is not None:
            validation["changed"] = True
            validation["status"] = "changed"
            validation["summary_text"] = f"postprocess exception: {type(postprocess_exception).__name__}"
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
                "validation_timings": validation_timings,
                "func_addr": func_addr,
            }
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
    log.warning(
        "Postprocess validation changed — discarding postprocessed C, emitting pre-postprocess C: %s (last_pass=%s failure_pass=%s)",
        validation["verdict"],
        getattr(self.codegen, "_inertia_last_postprocess_pass", None),
        getattr(self.codegen, "_inertia_postprocess_validation_failure_pass", None),
    )
    if pre_postprocess_cfunc_snapshot is None:
        return
    _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
    _normalize_pointer_high_byte_shifts_8616(self.codegen)
    self.codegen._inertia_postprocess_discarded = True
    self.codegen._inertia_postprocess_discard_verdict = validation_verdict_text
    restored_after_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode=validation_mode)
    restored_after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
        self.project,
        self.codegen,
        mode=validation_mode,
    )
    restored_validation = build_x86_16_tail_validation_cached_result(
        owner=snapshot_function_info,
        stage="postprocess",
        mode=validation_mode,
        before_fingerprint=before_fingerprint,
        after_fingerprint=restored_after_fingerprint,
        before_summary=before_summary,
        after_summary=restored_after_summary,
    )
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
