from __future__ import annotations

from dataclasses import dataclass
import logging
import os

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from .decompiler_postprocess_flags import _c_expr_uses_register_8616
from .decompiler_postprocess_utils import (
    _replace_c_children_8616,
    _iter_c_nodes_deep_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)
from .ir.condition_ir import JCC_TO_COND_8616
from .tail_validation_fingerprint import _expr_fingerprint
from .lowering.segmented_memory_lowering import lower_runtime_segment_access_8616

__all__ = ["_rewrite_decoded_jcc_conditions_8616"]

_COND_TO_CMP_OP_8616: dict[str, str] = {
    "eq": "CmpEQ",
    "ne": "CmpNE",
    "ult": "CmpLT",
    "ule": "CmpLE",
    "ugt": "CmpGT",
    "uge": "CmpGE",
    "slt": "CmpLT",
    "sle": "CmpLE",
    "sgt": "CmpGT",
    "sge": "CmpGE",
}

_JCC_COMPARE_OPS_8616: dict[str, str] = {
    mnemonic: _COND_TO_CMP_OP_8616[cond_op]
    for mnemonic, cond_op in JCC_TO_COND_8616.items()
    if cond_op in _COND_TO_CMP_OP_8616
}

_JCC_COMPARE_MASK_TESTS_8616: dict[str, tuple[int, bool]] = {
    "jo": (0x800, True),
    "jno": (0x800, False),
    "js": (0x80, True),
    "jns": (0x80, False),
    "jp": (0x4, True),
    "jpe": (0x4, True),
    "jnp": (0x4, False),
    "jpo": (0x4, False),
}

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _DecodedCmpGuard8616:
    lhs: object
    rhs: object
    op: str


def _condition_tags_8616(node) -> tuple[int, int] | None:
    seen: set[int] = set()

    def _walk(current) -> tuple[int, int] | None:
        if current is None:
            return None
        marker = id(current)
        if marker in seen:
            return None
        seen.add(marker)
        tags = getattr(current, "tags", None)
        if isinstance(tags, dict):
            ins_addr = tags.get("ins_addr")
            block_addr = tags.get("vex_block_addr")
            if isinstance(ins_addr, int) and isinstance(block_addr, int):
                return (ins_addr, block_addr)
        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond"):
            child = getattr(current, attr, None)
            found = _walk(child)
            if found is not None:
                return found
        return None

    return _walk(node)


def _reg_offset_8616(project, name: str) -> int | None:
    reg = project.arch.registers.get(name.lower())
    return None if reg is None else int(reg[0])


def _const_8616(value: int, codegen):
    return CConstant(int(value), SimTypeShort(False), codegen=codegen)


def _register_exprs_by_ins_addr_8616(codegen, project) -> dict[tuple[int, str, int], object]:
    reg_exprs: dict[tuple[int, str, int], object] = {}
    for node in _iter_c_nodes_deep_8616(getattr(codegen, "cfunc", None)):
        if not isinstance(node, CAssignment) or not isinstance(node.lhs, CVariable):
            continue
        tags = getattr(node, "tags", None)
        ins_addr = None if tags is None else tags.get("ins_addr")
        if not isinstance(ins_addr, int):
            continue
        variable = getattr(node.lhs, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            continue
        var_size = int(getattr(variable, "size", 0) or 0)
        for reg_name, (reg_offset, reg_size) in project.arch.registers.items():
            if int(reg_offset) != int(getattr(variable, "reg", -1)):
                continue
            if var_size and int(reg_size) != var_size:
                continue
            reg_exprs[(ins_addr, reg_name.lower(), int(reg_size))] = node.rhs
    return reg_exprs


def _lookup_register_expr_8616(reg_exprs: dict[tuple[int, str, int], object], ins_addr: int, reg_name: str, size: int):
    expr = reg_exprs.get((int(ins_addr), reg_name.lower(), int(size)))
    if expr is not None:
        return expr
    for (candidate_addr, candidate_name, _candidate_size), candidate_expr in reg_exprs.items():
        if int(candidate_addr) == int(ins_addr) and candidate_name == reg_name.lower():
            return candidate_expr
    return None


def _stack_slot_placeholder_name_8616(disp: int, size: int) -> str:
    sign = "m" if int(disp) < 0 else "p"
    return f"stack_bp_{sign}{abs(int(disp)):x}_b{int(size)}"


def _stack_slot_expr_8616(codegen, disp: int, size: int = 2):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None

    def _candidate_exprs():
        for arg in tuple(getattr(cfunc, "arg_list", ()) or ()):
            yield arg
        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            yield from variables_in_use.values()
        unified_locals = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for cvars in unified_locals.values():
                for item in cvars or ():
                    if isinstance(item, tuple) and item:
                        yield item[0]

    for expr in _candidate_exprs():
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable) and int(getattr(variable, "offset", 0) or 0) == int(disp):
            return expr
    region = getattr(cfunc, "addr", None)
    return CVariable(
        SimStackVariable(
            int(disp),
            int(size) or 2,
            base="bp",
            name=_stack_slot_placeholder_name_8616(disp, size),
            region=region,
        ),
        codegen=codegen,
    )


def _low_byte_expr_from_assignment_8616(expr):
    if isinstance(expr, CBinaryOp) and expr.op == "Or":
        if isinstance(expr.lhs, CBinaryOp) and expr.lhs.op == "And" and isinstance(expr.lhs.rhs, CConstant):
            if int(expr.lhs.rhs.value) == 0xFF00:
                return expr.rhs
        if isinstance(expr.rhs, CBinaryOp) and expr.rhs.op == "And" and isinstance(expr.rhs.rhs, CConstant):
            if int(expr.rhs.rhs.value) == 0xFF00:
                return expr.lhs
    return expr


def _stack_slot_key_8616(insn) -> tuple[int, int] | None:
    if len(insn.operands) < 2:
        return None
    mem = insn.operands[1].mem if insn.operands[1].type == 3 else insn.operands[0].mem if insn.operands[0].type == 3 else None
    if mem is None:
        return None
    base = insn.reg_name(mem.base) if mem.base else None
    if base != "bp":
        return None
    return int(mem.disp), int(getattr(insn.operands[0], "size", 0) or getattr(insn.operands[1], "size", 0) or 2)


def _memory_load_expr_8616(project, codegen, ds_var, base_expr, disp: int, size: int):
    if base_expr is None:
        return None
    addr_expr = CBinaryOp(
        "Add",
        CBinaryOp("Shl", ds_var, _const_8616(4, codegen), codegen=codegen),
        CBinaryOp("Add", base_expr, _const_8616(disp, codegen), codegen=codegen),
        codegen=codegen,
    )
    pointee = (SimTypeChar() if int(size) == 1 else SimTypeShort(False)).with_arch(project.arch)
    deref = CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False).with_arch(project.arch),
            SimTypePointer(pointee).with_arch(project.arch),
            addr_expr,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    lowered = lower_runtime_segment_access_8616(deref, target="portable-flat")
    return lowered if lowered is not None else deref


def _translate_cmp_jcc_guard_8616(project, codegen, block_addr: int, jcc_addr: int) -> _DecodedCmpGuard8616 | None:
    debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
    try:
        block = project.factory.block(block_addr, opt_level=0)
    except Exception:
        if debug_jcc:
            _log.warning("[jcc-rewrite] block decode failed block=%#x jcc=%#x", block_addr, jcc_addr)
        return None

    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    jcc_index = next((idx for idx, insn in enumerate(insns) if int(insn.address) == int(jcc_addr)), None)
    if jcc_index is None or jcc_index == 0:
        if debug_jcc:
            _log.warning("[jcc-rewrite] jcc index missing block=%#x jcc=%#x insn_count=%d", block_addr, jcc_addr, len(insns))
        return None
    jcc_insn = insns[jcc_index]
    cmp_insn = insns[jcc_index - 1]
    jcc_mnemonic = jcc_insn.mnemonic.lower()
    if jcc_mnemonic in _JCC_COMPARE_MASK_TESTS_8616:
        flags_offset = _reg_offset_8616(project, "flags")
        if flags_offset is None:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] flags register offset missing for compare-flags mnemonic=%s block=%#x jcc=%#x",
                    jcc_mnemonic,
                    block_addr,
                    jcc_addr,
                )
            return None
        bitmask, is_set = _JCC_COMPARE_MASK_TESTS_8616[jcc_mnemonic]
        return _DecodedCmpGuard8616(
            lhs=CBinaryOp(
                "And",
                CVariable(SimRegisterVariable(flags_offset, 2, name="flags"), codegen=codegen),
                _const_8616(bitmask, codegen),
                codegen=codegen,
            ),
            rhs=_const_8616(0, codegen),
            op=("CmpNE" if is_set else "CmpEQ"),
        )

    if jcc_mnemonic not in _JCC_COMPARE_OPS_8616:
        if debug_jcc:
            _log.warning("[jcc-rewrite] unsupported jcc mnemonic=%s block=%#x jcc=%#x", jcc_mnemonic, block_addr, jcc_addr)
        return None
    if cmp_insn.mnemonic != "cmp" or len(cmp_insn.operands) != 2:
        if debug_jcc:
            _log.warning("[jcc-rewrite] predecessor not cmp mnemonic=%s block=%#x jcc=%#x", cmp_insn.mnemonic, block_addr, jcc_addr)
        return None

    ds_offset = _reg_offset_8616(project, "ds")
    if ds_offset is None:
        if debug_jcc:
            _log.warning("[jcc-rewrite] ds reg missing block=%#x jcc=%#x", block_addr, jcc_addr)
        return None
    ds_var = CVariable(SimRegisterVariable(ds_offset, 2, name="ds"), codegen=codegen)
    reg_exprs = _register_exprs_by_ins_addr_8616(codegen, project)
    reg_state: dict[str, object] = {}
    stack_slots: dict[tuple[int, int], object] = {}

    for insn in insns[:jcc_index]:
        mnemonic = insn.mnemonic
        if mnemonic == "mov" and len(insn.operands) == 2 and insn.operands[0].type == 1 and insn.operands[1].type == 3:
            dst_reg = insn.reg_name(insn.operands[0].reg).lower()
            mem = insn.operands[1].mem
            key = None
            if insn.reg_name(mem.base) == "bp":
                key = (int(mem.disp), int(insn.operands[0].size))
            expr = None
            if key is not None:
                expr = _stack_slot_expr_8616(codegen, key[0], key[1])
                if expr is None:
                    expr = stack_slots.get(key)
            if expr is None:
                expr = _lookup_register_expr_8616(reg_exprs, int(insn.address), dst_reg, int(insn.operands[0].size))
            if dst_reg == "al" and expr is not None:
                expr = _low_byte_expr_from_assignment_8616(expr)
            elif expr is None and mem.base:
                expr = _memory_load_expr_8616(
                    project,
                    codegen,
                    ds_var,
                    reg_state.get(insn.reg_name(mem.base).lower()),
                    int(mem.disp),
                    int(insn.operands[0].size),
                )
            if expr is not None:
                reg_state[dst_reg] = expr
                if key is not None:
                    stack_slots.setdefault(key, expr)
            continue

        if mnemonic == "mov" and len(insn.operands) == 2 and insn.operands[0].type == 3 and insn.operands[1].type == 1:
            mem = insn.operands[0].mem
            if insn.reg_name(mem.base) != "bp":
                continue
            src_reg = insn.reg_name(insn.operands[1].reg).lower()
            size = int(insn.operands[1].size)
            slot_expr = _stack_slot_expr_8616(codegen, int(mem.disp), size)
            if slot_expr is not None:
                stack_slots[(int(mem.disp), size)] = slot_expr
            elif reg_state.get(src_reg) is not None:
                stack_slots[(int(mem.disp), size)] = reg_state[src_reg]
            continue

        if mnemonic == "shl" and len(insn.operands) == 2 and insn.operands[0].type == 1 and insn.operands[1].type == 2:
            reg_name = insn.reg_name(insn.operands[0].reg).lower()
            reg_expr = reg_state.get(reg_name)
            if reg_expr is not None:
                reg_state[reg_name] = CBinaryOp("Shl", reg_expr, _const_8616(int(insn.operands[1].imm), codegen), codegen=codegen)

    lhs = None
    rhs = None
    lhs_op = cmp_insn.operands[0]
    rhs_op = cmp_insn.operands[1]
    if lhs_op.type == 3 and lhs_op.mem.base:
        lhs = _memory_load_expr_8616(
            project,
            codegen,
            ds_var,
            reg_state.get(cmp_insn.reg_name(lhs_op.mem.base).lower()),
            int(lhs_op.mem.disp),
            int(lhs_op.size),
        )
    if rhs_op.type == 1:
        rhs = reg_state.get(cmp_insn.reg_name(rhs_op.reg).lower())
    elif rhs_op.type == 2:
        rhs = _const_8616(int(rhs_op.imm), codegen)

    if lhs is None or rhs is None:
        if debug_jcc:
            _log.warning(
                "[jcc-rewrite] operand recovery failed block=%#x jcc=%#x lhs=%r rhs=%r lhs_op_type=%s rhs_op_type=%s reg_state=%r stack_slots=%r",
                block_addr,
                jcc_addr,
                lhs,
                rhs,
                getattr(lhs_op, "type", None),
                getattr(rhs_op, "type", None),
                reg_state,
                stack_slots,
            )
        return None

    op = _JCC_COMPARE_OPS_8616.get(jcc_mnemonic)
    if op is None:
        if debug_jcc:
            _log.warning("[jcc-rewrite] op map missing mnemonic=%s block=%#x jcc=%#x", jcc_mnemonic, block_addr, jcc_addr)
        return None
    if debug_jcc:
        reg_state_fp = {}
        stack_slots_fp = {}
        for key, value in reg_state.items():
            try:
                reg_state_fp[key] = _expr_fingerprint(value, project)
            except Exception:
                reg_state_fp[key] = repr(value)
        for key, value in stack_slots.items():
            try:
                stack_slots_fp[key] = _expr_fingerprint(value, project)
            except Exception:
                stack_slots_fp[key] = repr(value)
        _log.warning(
            "[jcc-rewrite] decoded block=%#x jcc=%#x mnemonic=%s op=%s lhs=%r rhs=%r reg_state=%r stack_slots=%r reg_state_fp=%r stack_slots_fp=%r",
            block_addr,
            jcc_addr,
            jcc_mnemonic,
            op,
            lhs,
            rhs,
            reg_state,
            stack_slots,
            reg_state_fp,
            stack_slots_fp,
        )
    return _DecodedCmpGuard8616(lhs=lhs, rhs=rhs, op=op)


def _rewrite_decoded_jcc_conditions_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    flags_offset = _reg_offset_8616(project, "flags")
    if flags_offset is None:
        return False

    changed = False
    materialized_count = 0

    def _decoded_condition_replacement(cond):
        key = _condition_tags_8616(cond)
        ins_addr = None if key is None else key[0]
        block_addr = None if key is None else key[1]
        debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
        if debug_jcc:
            _log.warning(
                "[jcc-rewrite] candidate key=%r uses_flags=%s cond_type=%s cond_op=%s",
                key,
                _c_expr_uses_register_8616(cond, flags_offset) if isinstance(ins_addr, int) and isinstance(block_addr, int) else _c_expr_uses_register_8616(cond, flags_offset),
                type(cond).__name__ if cond is not None else None,
                getattr(cond, "op", None),
            )
        if not (
            isinstance(ins_addr, int)
            and isinstance(block_addr, int)
            and _c_expr_uses_register_8616(cond, flags_offset)
        ):
            return None
        decoded = _translate_cmp_jcc_guard_8616(project, codegen, block_addr, ins_addr)
        if decoded is None:
            return None
        same_expr = _same_c_expression_8616(decoded.lhs, decoded.rhs)
        lhs_fp = _expr_fingerprint(decoded.lhs, project)
        rhs_fp = _expr_fingerprint(decoded.rhs, project)
        if debug_jcc:
            _log.warning(
                "[jcc-rewrite] decoded candidate key=%r same_expr=%s lhs_fp=%r rhs_fp=%r",
                key,
                same_expr,
                lhs_fp,
                rhs_fp,
            )
        if same_expr or lhs_fp == rhs_fp:
            if debug_jcc:
                _log.warning("[jcc-rewrite] decoded candidate rejected key=%r", key)
            return None
        if debug_jcc:
            _log.warning("[jcc-rewrite] decoded candidate accepted key=%r", key)
        return CBinaryOp(
            decoded.op,
            decoded.lhs,
            decoded.rhs,
            codegen=codegen,
            tags=getattr(cond, "tags", None),
        )

    def _rewrite_condition(node):
        nonlocal changed, materialized_count
        replacement = _decoded_condition_replacement(node)
        if replacement is None:
            return node
        changed = True
        materialized_count += 1
        return replacement

    def _replace_tagged_condition(node):
        replacement = _rewrite_condition(node)
        if replacement is not None:
            return replacement
        if not _structured_codegen_node_8616(node):
            return node
        changed_in_place = _replace_c_children_8616(node, _replace_tagged_condition)
        if changed_in_place:
            changed = True
        return node

    for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
        cond_pairs = getattr(node, "condition_and_nodes", None)
        if isinstance(cond_pairs, (list, tuple)):
            pair_changed = False
            new_pairs = []
            for cond, body in cond_pairs:
                new_cond = _replace_tagged_condition(cond)
                pair_changed = pair_changed or (new_cond is not cond)
                new_pairs.append((new_cond, body))
                if new_cond is not cond:
                    changed = True
            if pair_changed:
                node.condition_and_nodes = type(cond_pairs)(new_pairs)
        if hasattr(node, "condition"):
            cond = getattr(node, "condition", None)
            if cond is not None:
                new_cond = _replace_tagged_condition(cond)
                if new_cond is not cond:
                    node.condition = new_cond
                    changed = True

    if changed:
        lane = getattr(codegen, "_inertia_condition_lane", None)
        if lane is not None:
            lane.materialized = max(int(getattr(lane, "materialized", 0) or 0), materialized_count)
        codegen._inertia_semantic_condition_materialized_count = max(
            int(getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) or 0),
            materialized_count,
        )

    return changed
