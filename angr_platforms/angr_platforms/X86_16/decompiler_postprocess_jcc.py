from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import MutableMapping
from dataclasses import dataclass
from enum import Enum

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CFunctionCall,
    CIfBreak,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from .annotations import ANNOTATION_KEY
from .decompiler_postprocess_flags import _c_expr_uses_register_8616
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _structured_codegen_node_8616,
)
from .ir.condition_ir import JCC_TO_COND_8616
from .lowering.real_mode_linear import RealModeLinearStackAccess8616, stack_cvar_for_stable_ss_linear_access_8616
from .lowering.segmented_memory_lowering import lower_runtime_segment_access_8616
from .tail_validation_fingerprint import _expr_fingerprint

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

_INVERT_CMP_OP_8616: dict[str, str] = {
    "CmpEQ": "CmpNE",
    "CmpNE": "CmpEQ",
    "CmpGT": "CmpLE",
    "CmpGE": "CmpLT",
    "CmpLT": "CmpGE",
    "CmpLE": "CmpGT",
}

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _DecodedCmpGuard8616:
    lhs: object
    rhs: object
    op: str
    expr: object | None = None


class _JccPolarityEvidence8616(Enum):
    UNKNOWN = "unknown"
    JCC_TARGET_BODY = "jcc_target_body"
    BREAK_CONDITION = "break_condition"
    LOOP_CONTINUATION = "loop_continuation"


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


def _condition_materialized_by_jcc_8616(node) -> bool:
    seen: set[int] = set()

    def _walk(current) -> bool:
        if current is None:
            return False
        marker = id(current)
        if marker in seen:
            return False
        seen.add(marker)
        tags = getattr(current, "tags", None)
        if isinstance(tags, dict) and tags.get("inertia_jcc_materialized_8616") is True:
            return True
        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond"):
            child = getattr(current, attr, None)
            if _walk(child):
                return True
        return False

    return _walk(node)


def _reg_offset_8616(project, name: str) -> int | None:
    registers = getattr(getattr(project, "arch", None), "registers", None)
    if not isinstance(registers, dict):
        return None
    reg = registers.get(name.lower())
    return None if reg is None else int(reg[0])


def _assignment_lhs_register_info_8616(project, lhs: object) -> tuple[int, int] | None:
    variable = getattr(lhs, "variable", None) if isinstance(lhs, CVariable) else None
    if isinstance(variable, SimRegisterVariable):
        return int(getattr(variable, "reg", -1)), int(getattr(variable, "size", 0) or 0)
    if type(lhs).__name__ != "CDirtyExpression":
        return None
    dirty = getattr(lhs, "dirty", None)
    reg_offset = None
    with contextlib.suppress(TypeError, AttributeError):
        reg_offset = getattr(dirty, "reg_offset", None)
    if not isinstance(reg_offset, int):
        return None
    bits = getattr(dirty, "bits", None)
    size = getattr(dirty, "size", None)
    size_bytes = int(bits // 8) if isinstance(bits, int) and bits > 0 else int(size or 0)
    if size_bytes <= 0:
        size_bytes = 2
    return int(reg_offset), int(size_bytes)


def _const_8616(value: int, codegen):
    return CConstant(int(value), SimTypeShort(False), codegen=codegen)


def _signed_const_8616(value: int, codegen):
    return CConstant(int(value), SimTypeShort(True), codegen=codegen)


def _type_with_project_arch_8616(project, sim_type):
    if sim_type is None:
        return None
    try:
        _ = sim_type.size
        return sim_type
    except ValueError:
        pass
    except Exception:
        return sim_type
    arch = getattr(project, "arch", None)
    if arch is None or not hasattr(sim_type, "with_arch"):
        return sim_type
    with contextlib.suppress(Exception):
        return sim_type.with_arch(arch)
    return sim_type


def _ensure_c_expr_type_has_arch_8616(project, expr):
    if expr is None:
        return None
    if isinstance(expr, CVariable):
        variable_type = getattr(expr, "variable_type", None)
        fixed_type = _type_with_project_arch_8616(project, variable_type)
        if fixed_type is not None and fixed_type is not variable_type:
            with contextlib.suppress(Exception):
                expr.variable_type = fixed_type
    elif isinstance(expr, CConstant):
        const_type = getattr(expr, "_type", None)
        fixed_type = _type_with_project_arch_8616(project, const_type)
        if fixed_type is not None and fixed_type is not const_type:
            with contextlib.suppress(Exception):
                expr._type = fixed_type
    return expr


def _register_exprs_by_ins_addr_8616(codegen, project) -> dict[tuple[int, str, int], object]:
    def _impl():
        cache = getattr(codegen, "_inertia_jcc_register_exprs_by_ins_addr_8616", None)
        if isinstance(cache, dict):
            return cache
        reg_exprs: dict[tuple[int, str, int], object] = {}
        for node in _iter_c_nodes_deep_8616(getattr(codegen, "cfunc", None)):
            if not isinstance(node, CAssignment):
                continue
            tags = getattr(node, "tags", None)
            ins_addr = None if tags is None else tags.get("ins_addr")
            if not isinstance(ins_addr, int):
                continue
            lhs_reg_info = _assignment_lhs_register_info_8616(project, node.lhs)
            if lhs_reg_info is None:
                continue
            lhs_reg_offset, var_size = lhs_reg_info
            for reg_name, (reg_offset, reg_size) in project.arch.registers.items():
                if int(reg_offset) != int(lhs_reg_offset):
                    continue
                if var_size and int(reg_size) != var_size:
                    continue
                rhs = getattr(node, "rhs", None)
                expr = node.lhs if any(isinstance(child, CFunctionCall) for child in _iter_c_nodes_deep_8616(rhs)) else rhs
                reg_exprs[(ins_addr, reg_name.lower(), int(reg_size))] = expr
        try:
            codegen._inertia_jcc_register_exprs_by_ins_addr_8616 = reg_exprs
        except Exception:
            pass
        return reg_exprs

    return _impl()


def _lookup_register_expr_8616(reg_exprs: dict[tuple[int, str, int], object], ins_addr: int, reg_name: str, size: int):
    expr = reg_exprs.get((int(ins_addr), reg_name.lower(), int(size)))
    if expr is not None:
        return expr
    for (candidate_addr, candidate_name, _candidate_size), candidate_expr in reg_exprs.items():
        if int(candidate_addr) == int(ins_addr) and candidate_name == reg_name.lower():
            return candidate_expr
    return None


def _lookup_register_expr_before_8616(reg_exprs: dict[tuple[int, str, int], object], ins_addr: int, reg_name: str, size: int):
    best_addr = None
    best_expr = None
    for (candidate_addr, candidate_name, candidate_size), candidate_expr in reg_exprs.items():
        if candidate_name != reg_name.lower():
            continue
        if int(size) and int(candidate_size) != int(size):
            continue
        if int(candidate_addr) >= int(ins_addr):
            continue
        if best_addr is None or int(candidate_addr) > best_addr:
            best_addr = int(candidate_addr)
            best_expr = candidate_expr
    return best_expr


def _lookup_prior_register_stack_load_8616(project, codegen, ins_addr: int, reg_name: str, size: int):
    for insn in sorted(
        _function_insns_for_codegen_8616(project, codegen),
        key=lambda item: int(getattr(item, "address", -1)),
        reverse=True,
    ):
        addr = int(getattr(insn, "address", -1))
        if addr >= int(ins_addr):
            continue
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic in {"jmp", "ljmp", "ret", "retf", "iret", "call", "lcall"} or mnemonic.startswith("j"):
            break
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if int(getattr(operands[0], "type", -1)) != 1 or int(getattr(operands[1], "type", -1)) != 3:
            continue
        if str(insn.reg_name(operands[0].reg)).lower() != reg_name.lower():
            continue
        if int(getattr(operands[0], "size", 0) or size) != int(size):
            continue
        mem = operands[1].mem
        if not mem.base or str(insn.reg_name(mem.base)).lower() != "bp":
            continue
        return _bp_operand_stack_expr_8616(codegen, int(mem.disp), int(getattr(operands[1], "size", 0) or size))
    return None


def _stack_slot_offset_8616(expr) -> int | None:
    if not isinstance(expr, CVariable):
        return None
    variable = getattr(expr, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return None
    offset = getattr(variable, "offset", None)
    return offset if isinstance(offset, int) else None


def _wide_stack_pair_expr_8616(codegen, hi_expr, lo_expr):
    hi_offset = _stack_slot_offset_8616(hi_expr)
    lo_offset = _stack_slot_offset_8616(lo_expr)
    if not (isinstance(hi_offset, int) and isinstance(lo_offset, int)):
        return None
    if hi_offset != lo_offset + 2:
        return None
    return _stack_slot_expr_8616(codegen, lo_offset, 4)


def _expr_is_register_8616(project, expr, reg_name: str) -> bool:
    node = expr
    while isinstance(node, CTypeCast):
        node = getattr(node, "expr", None)
    if not isinstance(node, CVariable):
        return False
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        return False
    expected = _reg_offset_8616(project, reg_name)
    return expected is not None and int(getattr(variable, "reg", -1)) == int(expected)


def _wide_call_return_pair_expr_8616(project, codegen, hi_expr, lo_expr, ins_addr: int):
    if not (_expr_is_register_8616(project, hi_expr, "dx") and _expr_is_register_8616(project, lo_expr, "ax")):
        return None
    debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
    if debug_jcc:
        _log.warning("[jcc-rewrite] wide-call-return candidate ins_addr=%#x hi=%r lo=%r", int(ins_addr), hi_expr, lo_expr)
    try:
        codegen._inertia_jcc_wide_call_return_pair_candidates_8616 = int(
            getattr(codegen, "_inertia_jcc_wide_call_return_pair_candidates_8616", 0) or 0
        ) + 1
    except Exception:
        pass
    call_expr = _call_return_expr_before_insn_8616(project, codegen, int(ins_addr))
    if call_expr is None:
        if debug_jcc:
            _log.warning("[jcc-rewrite] wide-call-return refused-no-call ins_addr=%#x", int(ins_addr))
        try:
            codegen._inertia_jcc_wide_call_return_pair_refused_8616 = int(
                getattr(codegen, "_inertia_jcc_wide_call_return_pair_refused_8616", 0) or 0
            ) + 1
        except Exception:
            pass
        return None
    try:
        codegen._inertia_jcc_wide_call_return_pair_materialized_8616 = int(
            getattr(codegen, "_inertia_jcc_wide_call_return_pair_materialized_8616", 0) or 0
        ) + 1
    except Exception:
        pass
    if debug_jcc:
        _log.warning("[jcc-rewrite] wide-call-return materialized ins_addr=%#x expr=%r", int(ins_addr), call_expr)
    return call_expr


def _wide_call_return_pair_operands_8616(project, codegen, hi_operand, lo_operand, hi_reg_name_fn, lo_reg_name_fn, ins_addr: int):
    if int(getattr(hi_operand, "type", -1)) != 1 or int(getattr(lo_operand, "type", -1)) != 1:
        return None
    if str(hi_reg_name_fn(hi_operand.reg)).lower() != "dx":
        return None
    if str(lo_reg_name_fn(lo_operand.reg)).lower() != "ax":
        return None
    dx_offset = _reg_offset_8616(project, "dx")
    ax_offset = _reg_offset_8616(project, "ax")
    if dx_offset is None or ax_offset is None:
        return None
    return _wide_call_return_pair_expr_8616(
        project,
        codegen,
        CVariable(SimRegisterVariable(dx_offset, int(getattr(hi_operand, "size", 0) or 2), name="dx"), codegen=codegen),
        CVariable(SimRegisterVariable(ax_offset, int(getattr(lo_operand, "size", 0) or 2), name="ax"), codegen=codegen),
        ins_addr,
    )


def _stack_slot_placeholder_name_8616(disp: int, size: int) -> str:
    sign = "m" if int(disp) < 0 else "p"
    return f"stack_bp_{sign}{abs(int(disp)):x}_b{int(size)}"


def _stack_arg_width_from_type_8616(arg_type) -> int:
    bits = getattr(arg_type, "size", None)
    with contextlib.suppress(Exception):
        if isinstance(bits, int) and bits > 0:
            return max(2, int(bits // 8))
    return 2


def _is_unstable_stack_arg_name_8616(name: object) -> bool:
    return isinstance(name, str) and (
        name.startswith("arg_")
        or name.startswith("local_")
        or name.startswith("stack_bp_")
        or name.startswith("s_")
    )


def _annotation_arg_name_for_stack_offset_8616(codegen, disp: int, *, project=None) -> str | None:
    def _name_from_spec(spec) -> str | None:
        name = spec if isinstance(spec, str) else None
        if isinstance(spec, dict):
            spec_name = spec.get("name")
            if isinstance(spec_name, str):
                name = spec_name
        if isinstance(name, str) and name and not _is_unstable_stack_arg_name_8616(name):
            return name
        return None

    cfunc = getattr(codegen, "cfunc", None)
    project = project if project is not None else getattr(codegen, "project", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    if project is None or not isinstance(func_addr, int) or int(disp) <= 2:
        return None
    with contextlib.suppress(Exception):
        function = project.kb.functions.function(addr=func_addr, create=False)
        info = getattr(function, "info", None)
        annotations = info.get(ANNOTATION_KEY) if isinstance(info, MutableMapping) else None
        stack_vars = annotations.get("stack_vars") if isinstance(annotations, dict) else None
        if not isinstance(stack_vars, dict):
            return None
        # COD/LST BP aliases are recorded as architectural BP displacements,
        # while function annotations normalize BP-relative slots by removing the
        # return-address word. Accept both forms so lowering can consume the
        # same evidence regardless of which layer is asking.
        candidates = (int(disp), int(disp) - 2)
        for candidate in candidates:
            name = _name_from_spec(stack_vars.get(candidate))
            if name is not None:
                return name
    return None


def _prototype_arg_name_for_stack_offset_8616(codegen, disp: int, *, project=None) -> str | None:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None or int(disp) <= 2:
        return None
    candidates = [
        getattr(cfunc, "functy", None),
        getattr(cfunc, "prototype", None),
    ]
    project = project if project is not None else getattr(codegen, "project", None)
    func_addr = getattr(cfunc, "addr", None)
    if project is not None and isinstance(func_addr, int):
        with contextlib.suppress(Exception):
            func = project.kb.functions.function(addr=func_addr, create=False)
            candidates.append(getattr(func, "prototype", None) if func is not None else None)
    for prototype in candidates:
        arg_names = tuple(getattr(prototype, "arg_names", ()) or ()) if prototype is not None else ()
        args = tuple(getattr(prototype, "args", ()) or ()) if prototype is not None else ()
        if not arg_names or len(arg_names) != len(args):
            continue
        cursor = 4
        for name, arg_type in zip(arg_names, args):
            if (
                cursor == int(disp)
                and isinstance(name, str)
                and name
                and not _is_unstable_stack_arg_name_8616(name)
            ):
                return name
            cursor += _stack_arg_width_from_type_8616(arg_type)
    return None


def _is_placeholder_stack_arg_name_8616(name: object) -> bool:
    return _is_unstable_stack_arg_name_8616(name)


def _sync_stack_arg_expr_name_from_prototype_8616(codegen, expr, disp: int, *, project=None):
    if int(disp) <= 2:
        return expr
    desired_name = _annotation_arg_name_for_stack_offset_8616(
        codegen,
        disp,
        project=project,
    ) or _prototype_arg_name_for_stack_offset_8616(codegen, disp, project=project)
    if not desired_name:
        return expr
    variable = getattr(expr, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return expr
    if int(getattr(variable, "offset", 0) or 0) != int(disp):
        return expr
    current_name = getattr(variable, "name", None)
    if current_name == desired_name:
        return expr
    if _is_placeholder_stack_arg_name_8616(current_name) or not current_name:
        with contextlib.suppress(Exception):
            variable.name = desired_name
        with contextlib.suppress(Exception):
            expr.name = desired_name
        unified = getattr(expr, "unified_variable", None)
        if unified is not None:
            with contextlib.suppress(Exception):
                unified.name = desired_name
    return expr


def _stack_slot_expr_8616(codegen, disp: int, size: int = 2, *, project=None):
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

    # Positive BP displacements are function arguments in near 16-bit C calls.
    # Reuse an existing canonical argument before stable stack lowering can
    # synthesize a placeholder such as arg_4 and diverge from the signature.
    if int(disp) > 2:
        for expr in tuple(getattr(cfunc, "arg_list", ()) or ()):
            variable = getattr(expr, "variable", None)
            if isinstance(variable, SimStackVariable) and int(getattr(variable, "offset", 0) or 0) == int(disp):
                return _sync_stack_arg_expr_name_from_prototype_8616(codegen, expr, disp, project=project)

    with contextlib.suppress(Exception):
        materialized = stack_cvar_for_stable_ss_linear_access_8616(
            codegen,
            RealModeLinearStackAccess8616(int(disp), int(size) or 2),
        )
        if materialized is not None:
            return _sync_stack_arg_expr_name_from_prototype_8616(codegen, materialized, disp, project=project)

    for expr in _candidate_exprs():
        variable = getattr(expr, "variable", None)
        if isinstance(variable, SimStackVariable) and int(getattr(variable, "offset", 0) or 0) == int(disp):
            return _sync_stack_arg_expr_name_from_prototype_8616(codegen, expr, disp, project=project)
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


def _bp_operand_stack_expr_8616(codegen, disp: int, size: int = 2):
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return _stack_slot_expr_8616(codegen, disp, size)
    requested_disp = int(disp)
    requested_size = int(size) or 2
    for arg in tuple(getattr(cfunc, "arg_list", ()) or ()):
        variable = getattr(arg, "variable", None)
        if not isinstance(arg, CVariable) or not isinstance(variable, SimStackVariable):
            continue
        offset = getattr(variable, "offset", None)
        if isinstance(offset, int) and int(offset) == requested_disp:
            return arg

    # x86-16 near C functions place the first stack argument at BP+4.
    # Prefer this instruction operand evidence over unstable recovered positive
    # BP aliases when the function prototype already proves an argument slot.
    expected_disp = 4
    for arg in tuple(getattr(cfunc, "arg_list", ()) or ()):
        variable = getattr(arg, "variable", None)
        if not isinstance(arg, CVariable):
            continue
        arg_type = getattr(arg, "variable_type", None)
        arg_size = max(2, int(getattr(variable, "size", 0) or requested_size))
        if requested_disp == expected_disp:
            project = getattr(codegen, "project", None)
            fallback_type = SimTypeShort(False)
            if getattr(project, "arch", None) is not None:
                fallback_type = fallback_type.with_arch(project.arch)
            return CVariable(
                SimStackVariable(
                    requested_disp,
                    requested_size,
                    base="bp",
                    name=f"arg_{requested_disp:x}",
                    region=getattr(cfunc, "addr", None),
                ),
                variable_type=arg_type if arg_type is not None else fallback_type,
                codegen=codegen,
            )
        expected_disp += arg_size
    return _stack_slot_expr_8616(codegen, disp, size)


def _low_byte_expr_from_assignment_8616(expr):
    def _impl():
        if isinstance(expr, CBinaryOp) and expr.op == "Or":
            if isinstance(expr.lhs, CBinaryOp) and expr.lhs.op == "And" and isinstance(expr.lhs.rhs, CConstant):
                if int(expr.lhs.rhs.value) == 0xFF00:
                    return expr.rhs
            if isinstance(expr.rhs, CBinaryOp) and expr.rhs.op == "And" and isinstance(expr.rhs.rhs, CConstant):
                if int(expr.rhs.rhs.value) == 0xFF00:
                    return expr.lhs
        return expr

    return _impl()


def _stack_slot_key_8616(insn) -> tuple[int, int] | None:
    if len(insn.operands) < 2:
        return None
    mem = (
        insn.operands[1].mem
        if insn.operands[1].type == 3
        else insn.operands[0].mem
        if insn.operands[0].type == 3
        else None
    )
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


_JCC_LOW_OP_8616: dict[str, str] = {
    "jb": "CmpLT",
    "jnae": "CmpLT",
    "jc": "CmpLT",
    "jbe": "CmpLE",
    "jna": "CmpLE",
    "ja": "CmpGT",
    "jnbe": "CmpGT",
    "jae": "CmpGE",
    "jnb": "CmpGE",
    "jnc": "CmpGE",
    "je": "CmpEQ",
    "jz": "CmpEQ",
    "jne": "CmpNE",
    "jnz": "CmpNE",
}


def _branch_target_imm_8616(insn) -> int | None:
    operands = tuple(getattr(insn, "operands", ()) or ())
    if not operands:
        return None
    op0 = operands[0]
    if int(getattr(op0, "type", -1)) != 2:
        return None
    return int(getattr(op0, "imm", 0))


def _function_insns_for_codegen_8616(project, codegen) -> tuple:
    cache = getattr(codegen, "_inertia_jcc_function_insns_8616", None)
    if isinstance(cache, tuple):
        return cache
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return ()
    try:
        function = project.kb.functions.function(addr=func_addr, create=False)
    except Exception:
        function = None
    if function is None:
        return ()
    insns: list[object] = []
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        insns.extend(tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()))
    func_size = int(getattr(function, "size", 0) or 0)
    linear_size = max(func_size, 0x400)
    if 0 < linear_size <= 0x4000:
        addr = int(func_addr)
        end_addr = int(func_addr) + int(linear_size)
        linear_insns = []
        while addr < end_addr:
            try:
                linear_block = project.factory.block(addr, num_inst=1, opt_level=0)
            except Exception:
                break
            decoded = tuple(getattr(getattr(linear_block, "capstone", None), "insns", ()) or ())
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
        insns.extend(tuple(linear_insns))
    by_addr = {}
    for insn in insns:
        by_addr.setdefault(int(getattr(insn, "address", 0) or 0), insn)
    result = tuple(sorted(by_addr.values(), key=lambda item: int(getattr(item, "address", 0) or 0)))
    try:
        codegen._inertia_jcc_function_insns_8616 = result
    except Exception:
        pass
    return result


def _merge_unique_insns_by_addr_8616(*groups: tuple) -> tuple:
    by_addr = {}
    for group in groups:
        for insn in tuple(group or ()):
            addr = int(getattr(insn, "address", 0) or 0)
            if addr:
                by_addr.setdefault(addr, insn)
    return tuple(sorted(by_addr.values(), key=lambda item: int(getattr(item, "address", 0) or 0)))


def _linear_insns_before_addr_8616(project, codegen, ins_addr: int, *, max_bytes: int = 0x800) -> tuple:
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    stop_addr = int(ins_addr)
    start_candidates: list[int] = []
    if isinstance(func_addr, int):
        start_candidates.append(int(func_addr))
    loader = getattr(project, "loader", None)
    for owner in (loader, getattr(loader, "main_object", None)):
        min_addr = getattr(owner, "min_addr", None)
        if isinstance(min_addr, int):
            start_candidates.append(int(min_addr))
    cache = getattr(codegen, "_inertia_jcc_function_insns_8616", None)
    if isinstance(cache, tuple):
        cached_addrs = sorted(
            {
                int(getattr(insn, "address", -1))
                for insn in cache
                if 0 <= int(getattr(insn, "address", -1)) < stop_addr
            }
        )
        if cached_addrs:
            start_candidates.append(cached_addrs[0])
    start_candidates = sorted({addr for addr in start_candidates if 0 <= addr < stop_addr})
    if not start_candidates:
        return ()
    start_addr = start_candidates[0]
    if stop_addr <= start_addr:
        return ()
    end_addr = min(stop_addr, start_addr + int(max_bytes))
    addr = start_addr
    insns: list[object] = []
    while addr < end_addr:
        try:
            block = project.factory.block(addr, num_inst=1, opt_level=0)
        except TypeError:
            try:
                block = project.factory.block(addr, opt_level=0)
            except Exception:
                break
        except Exception:
            break
        decoded = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not decoded:
            break
        insn = decoded[0]
        insn_addr = int(getattr(insn, "address", addr) or addr)
        if insn_addr >= stop_addr:
            break
        insns.append(insn)
        size = int(getattr(insn, "size", 0) or 0)
        if str(getattr(insn, "mnemonic", "")).lower() in {"ret", "retf", "iret"}:
            break
        if size <= 0:
            break
        next_addr = insn_addr + size
        if next_addr <= addr:
            break
        addr = next_addr
    return tuple(insns)


def _direct_call_target_8616(insn) -> int | None:
    mnemonic = str(getattr(insn, "mnemonic", "")).lower()
    if mnemonic not in {"call", "lcall"}:
        return None
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 1:
        return None
    op0 = operands[0]
    if int(getattr(op0, "type", -1)) != 2:
        return None
    return int(getattr(op0, "imm", 0))


def _callee_name_for_target_8616(project, target_addr: int) -> tuple[str, object | None]:
    callee_func = None
    with contextlib.suppress(Exception):
        callee_func = project.kb.functions.function(addr=int(target_addr), create=False)
    name = getattr(callee_func, "name", None)
    if not isinstance(name, str) or not name:
        name = f"sub_{int(target_addr):x}"
    if name.startswith("_") and len(name) > 1:
        name = name[1:]
    return name, callee_func


def _callee_prototype_arg_count_8616(callee_func, callee_name: str | None = None) -> int | None:
    prototype = getattr(callee_func, "prototype", None)
    args = getattr(prototype, "args", None)
    if isinstance(args, (list, tuple)):
        return len(args)
    if isinstance(callee_name, str) and callee_name in {"clock"}:
        return 0
    return None


def _const_from_push_imm_8616(value: int, codegen):
    return CConstant(int(value) & 0xFFFF, SimTypeShort(False), codegen=codegen)


def _call_args_from_push_setup_8616(
    project, codegen, insns: tuple, call_index: int, arg_count: int | None = None
) -> tuple[object, ...] | None:
    if arg_count == 0:
        return ()
    start = call_index
    lower_bound = max(0, call_index - 16)
    for idx in range(call_index - 1, lower_bound - 1, -1):
        mnemonic = str(getattr(insns[idx], "mnemonic", "")).lower()
        if mnemonic in {"push", "mov"}:
            start = idx
            continue
        break
    reg_values: dict[str, object] = {}
    pushed: list[object] = []
    for insn in insns[start:call_index]:
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = tuple(getattr(insn, "operands", ()) or ())
        if mnemonic == "mov" and len(operands) == 2 and int(getattr(operands[0], "type", -1)) == 1:
            reg_name = insn.reg_name(operands[0].reg).lower()
            if int(getattr(operands[1], "type", -1)) == 2:
                reg_values[reg_name] = _const_from_push_imm_8616(int(getattr(operands[1], "imm", 0)), codegen)
            else:
                reg_values.pop(reg_name, None)
            continue
        if mnemonic == "push" and len(operands) == 1:
            op0 = operands[0]
            op_type = int(getattr(op0, "type", -1))
            if op_type == 2:
                pushed.append(_const_from_push_imm_8616(int(getattr(op0, "imm", 0)), codegen))
                continue
            if op_type == 1:
                reg_name = insn.reg_name(op0.reg).lower()
                expr = reg_values.get(reg_name)
                if expr is None:
                    if isinstance(arg_count, int):
                        pushed.append(None)
                        continue
                    return None
                pushed.append(expr)
                continue
            return None
        return None
    if isinstance(arg_count, int):
        if arg_count < 0 or len(pushed) < arg_count:
            return None
        if arg_count == 0:
            pushed = []
        else:
            pushed = pushed[-arg_count:]
        if any(item is None for item in pushed):
            return None
    return tuple(reversed(pushed))


def _call_return_expr_before_insn_8616(project, codegen, ins_addr: int):
    debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
    insns = _function_insns_for_codegen_8616(project, codegen)
    linear_insns = _linear_insns_before_addr_8616(project, codegen, int(ins_addr))
    if linear_insns:
        insns = _merge_unique_insns_by_addr_8616(insns, linear_insns)
        try:
            codegen._inertia_jcc_function_insns_8616 = insns
        except Exception:
            pass
    if not insns:
        return None
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}
    start_idx = index_by_addr.get(int(ins_addr))
    if start_idx is None and linear_insns:
        start_idx = len(tuple(insn for insn in insns if int(getattr(insn, "address", -1)) < int(ins_addr)))
    if start_idx is None:
        return None
    lower_bound = max(0, start_idx - 8)
    arg_count = None
    for idx in range(start_idx - 1, lower_bound - 1, -1):
        insn = insns[idx]
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        target = _direct_call_target_8616(insn)
        if target is not None:
            name, callee_func = _callee_name_for_target_8616(project, target)
            if name == "aNchkstk":
                return None
            effective_arg_count = arg_count
            if effective_arg_count is None:
                effective_arg_count = _callee_prototype_arg_count_8616(callee_func, name)
            args = _call_args_from_push_setup_8616(project, codegen, insns, idx, effective_arg_count)
            if args is None:
                return None
            return CFunctionCall(name, callee_func, list(args), codegen=codegen)
        if (
            mnemonic == "add"
            and len(tuple(getattr(insn, "operands", ()) or ())) == 2
            and int(getattr(insn.operands[0], "type", -1)) == 1
            and str(insn.reg_name(insn.operands[0].reg)).lower() == "sp"
            and int(getattr(insn.operands[1], "type", -1)) == 2
        ):
            cleanup = int(getattr(insn.operands[1], "imm", 0) or 0)
            if cleanup >= 0 and cleanup % 2 == 0:
                arg_count = cleanup // 2
            continue
        if mnemonic in {"add", "sub", "nop"}:
            continue
        break
    if debug_jcc:
        seen = getattr(codegen, "_inertia_jcc_call_return_debug_logged_8616", None)
        if not isinstance(seen, set):
            seen = set()
            try:
                codegen._inertia_jcc_call_return_debug_logged_8616 = seen
            except Exception:
                pass
        key = int(ins_addr)
        if key not in seen:
            seen.add(key)
            window = []
            for insn in insns:
                addr = int(getattr(insn, "address", -1))
                if int(ins_addr) - 0x40 <= addr <= int(ins_addr):
                    window.append(f"{addr:#x}:{str(getattr(insn, 'mnemonic', '')).lower()}")
            cfunc = getattr(codegen, "cfunc", None)
            loader = getattr(project, "loader", None)
            _log.warning(
                "[jcc-rewrite] call-return no-call ins_addr=%#x cfunc_addr=%r loader_min=%r main_min=%r "
                "cache_count=%d linear_count=%d window=%s",
                int(ins_addr),
                getattr(cfunc, "addr", None),
                getattr(loader, "min_addr", None),
                getattr(getattr(loader, "main_object", None), "min_addr", None),
                len(tuple(insns or ())),
                len(tuple(linear_insns or ())),
                ",".join(window[-16:]),
            )
    return None


def _decode_cmp_jcc_32bit_chain_8616(project, codegen, cmp_insn, jcc_insn, reg_exprs, ds_var):
    def _impl():
        jcc1 = str(getattr(jcc_insn, "mnemonic", "")).lower()
        mid_addr = _branch_target_imm_8616(jcc_insn)
        if mid_addr is None:
            return None
        try:
            mid_block = project.factory.block(mid_addr, opt_level=0)
        except Exception:
            return None
        mid_insns = tuple(getattr(getattr(mid_block, "capstone", None), "insns", ()) or ())

        reg_state: dict[str, object] = {}
        stack_slots: dict[tuple[int, int], object] = {}
        for state_insn in sorted(
            _function_insns_for_codegen_8616(project, codegen),
            key=lambda item: int(getattr(item, "address", -1)),
        ):
            state_addr = int(getattr(state_insn, "address", -1))
            if state_addr >= int(cmp_insn.address):
                break
            _apply_cmp_state_update_8616(project, codegen, state_insn, reg_state, stack_slots, reg_exprs, ds_var)

        if jcc1 in {"je", "jz"}:
            cmp2_insn = next((ins for ins in mid_insns if str(getattr(ins, "mnemonic", "")).lower() == "cmp"), None)
            jcc2_insn = next(
                (
                    ins
                    for ins in mid_insns
                    if str(getattr(ins, "mnemonic", "")).lower() in {"je", "jz", "jne", "jnz"}
                ),
                None,
            )
            if cmp2_insn is not None and jcc2_insn is not None:
                lhs_lo = _resolve_cmp_operand_expr_8616(
                    project,
                    codegen,
                    cmp_insn.operands[0],
                    reg_state,
                    ds_var,
                    cmp_insn.reg_name,
                    reg_exprs,
                    int(cmp_insn.address),
                )
                rhs_lo = _resolve_cmp_operand_expr_8616(
                    project,
                    codegen,
                    cmp_insn.operands[1],
                    reg_state,
                    ds_var,
                    cmp_insn.reg_name,
                    reg_exprs,
                    int(cmp_insn.address),
                )
                lhs_hi = _resolve_cmp_operand_expr_8616(
                    project,
                    codegen,
                    cmp2_insn.operands[0],
                    reg_state,
                    ds_var,
                    cmp2_insn.reg_name,
                    reg_exprs,
                    int(cmp2_insn.address),
                )
                rhs_hi = _resolve_cmp_operand_expr_8616(
                    project,
                    codegen,
                    cmp2_insn.operands[1],
                    reg_state,
                    ds_var,
                    cmp2_insn.reg_name,
                    reg_exprs,
                    int(cmp2_insn.address),
                )
                lhs_wide = _wide_stack_pair_expr_8616(codegen, lhs_hi, lhs_lo)
                rhs_wide = _wide_stack_pair_expr_8616(codegen, rhs_hi, rhs_lo)
                if lhs_wide is None:
                    lhs_wide = _wide_call_return_pair_expr_8616(project, codegen, lhs_hi, lhs_lo, int(cmp_insn.address))
                if lhs_wide is None:
                    lhs_wide = _wide_call_return_pair_operands_8616(
                        project,
                        codegen,
                        cmp_insn.operands[0],
                        cmp2_insn.operands[0],
                        cmp_insn.reg_name,
                        cmp2_insn.reg_name,
                        int(cmp_insn.address),
                    )
                if rhs_wide is None:
                    rhs_wide = _wide_call_return_pair_expr_8616(project, codegen, rhs_hi, rhs_lo, int(cmp_insn.address))
                if rhs_wide is None:
                    rhs_wide = _wide_call_return_pair_operands_8616(
                        project,
                        codegen,
                        cmp_insn.operands[1],
                        cmp2_insn.operands[1],
                        cmp_insn.reg_name,
                        cmp2_insn.reg_name,
                        int(cmp_insn.address),
                    )
                if lhs_wide is not None and rhs_wide is not None:
                    jcc2_name = str(getattr(jcc2_insn, "mnemonic", "")).lower()
                    return _DecodedCmpGuard8616(
                        lhs=lhs_wide,
                        rhs=rhs_wide,
                        op="CmpNE" if jcc2_name in {"jne", "jnz"} else "CmpEQ",
                    )

        # Compilers often emit `jcc short; jmp far` in the middle block. Accept
        # both one-insn and two-insn forms and pick the first conditional jump.
        jcc2_insn = next(
            (
                ins
                for ins in mid_insns
                if str(getattr(ins, "mnemonic", "")).lower().startswith("j")
                and str(getattr(ins, "mnemonic", "")).lower() not in {"jmp", "ljmp"}
            ),
            None,
        )
        if jcc2_insn is None:
            return None
        jcc2 = str(getattr(jcc2_insn, "mnemonic", "")).lower()
        cmp2_addr = _branch_target_imm_8616(jcc2_insn)
        if cmp2_addr is None:
            return None
        try:
            low_block = project.factory.block(cmp2_addr, opt_level=0)
        except Exception:
            return None
        low_insns = tuple(getattr(getattr(low_block, "capstone", None), "insns", ()) or ())
        if len(low_insns) < 2:
            return None
        cmp2_insn = low_insns[0]
        jcc3_insn = low_insns[1]
        if str(getattr(cmp2_insn, "mnemonic", "")).lower() != "cmp":
            return None
        jcc3 = str(getattr(jcc3_insn, "mnemonic", "")).lower()
        low_op = _JCC_LOW_OP_8616.get(jcc3)
        if low_op is None:
            return None

        lhs_hi = _resolve_cmp_operand_expr_8616(
            project, codegen, cmp_insn.operands[0], reg_state, ds_var, cmp_insn.reg_name, reg_exprs, int(cmp_insn.address)
        )
        rhs_hi = _resolve_cmp_operand_expr_8616(
            project, codegen, cmp_insn.operands[1], reg_state, ds_var, cmp_insn.reg_name, reg_exprs, int(cmp_insn.address)
        )
        lhs_lo = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            cmp2_insn.operands[0],
            reg_state,
            ds_var,
            cmp2_insn.reg_name,
            reg_exprs,
            int(cmp2_insn.address),
        )
        rhs_lo = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            cmp2_insn.operands[1],
            reg_state,
            ds_var,
            cmp2_insn.reg_name,
            reg_exprs,
            int(cmp2_insn.address),
        )
        if lhs_hi is None or rhs_hi is None or lhs_lo is None or rhs_lo is None:
            return None

        lhs_hi = _ensure_c_expr_type_has_arch_8616(project, lhs_hi)
        rhs_hi = _ensure_c_expr_type_has_arch_8616(project, rhs_hi)
        lhs_lo = _ensure_c_expr_type_has_arch_8616(project, lhs_lo)
        rhs_lo = _ensure_c_expr_type_has_arch_8616(project, rhs_lo)

        hi_lt = CBinaryOp("CmpLT", lhs_hi, rhs_hi, codegen=codegen)
        hi_gt = CBinaryOp("CmpGT", lhs_hi, rhs_hi, codegen=codegen)
        hi_eq = CBinaryOp("CmpEQ", lhs_hi, rhs_hi, codegen=codegen)
        lo_rel = CBinaryOp(low_op, lhs_lo, rhs_lo, codegen=codegen)
        eq_expr = CBinaryOp("LogicalAnd", hi_eq, CBinaryOp("CmpEQ", lhs_lo, rhs_lo, codegen=codegen), codegen=codegen)
        lhs_wide = _wide_stack_pair_expr_8616(codegen, lhs_hi, lhs_lo)
        rhs_wide = _wide_stack_pair_expr_8616(codegen, rhs_hi, rhs_lo)
        if lhs_wide is None:
            lhs_wide = _wide_call_return_pair_expr_8616(project, codegen, lhs_hi, lhs_lo, int(cmp_insn.address))
        if lhs_wide is None:
            lhs_wide = _wide_call_return_pair_operands_8616(
                project,
                codegen,
                cmp_insn.operands[0],
                cmp2_insn.operands[0],
                cmp_insn.reg_name,
                cmp2_insn.reg_name,
                int(cmp_insn.address),
            )
        if rhs_wide is None:
            rhs_wide = _wide_call_return_pair_expr_8616(project, codegen, rhs_hi, rhs_lo, int(cmp_insn.address))
        if rhs_wide is None:
            rhs_wide = _wide_call_return_pair_operands_8616(
                project,
                codegen,
                cmp_insn.operands[1],
                cmp2_insn.operands[1],
                cmp_insn.reg_name,
                cmp2_insn.reg_name,
                int(cmp_insn.address),
            )

        if jcc1 in {"jl", "jnge", "jb", "jnae", "jc"} and jcc2 in {"jge", "jnl", "jae", "jnb", "jnc"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(lhs=lhs_wide, rhs=rhs_wide, op="CmpLT")
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op="CmpLT",
                expr=CBinaryOp(
                    "LogicalOr", hi_lt, CBinaryOp("LogicalAnd", hi_eq, lo_rel, codegen=codegen), codegen=codegen
                ),
            )
        if jcc1 in {"jle", "jng", "jbe", "jna"} and jcc2 in {"jge", "jnl", "jae", "jnb", "jnc"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(
                    lhs=lhs_wide,
                    rhs=rhs_wide,
                    op="CmpLT" if low_op == "CmpLT" else "CmpLE",
                )
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op="CmpLE",
                expr=CBinaryOp(
                    "LogicalOr", hi_lt, CBinaryOp("LogicalAnd", hi_eq, lo_rel, codegen=codegen), codegen=codegen
                ),
            )
        if jcc1 in {"jg", "jnle", "ja", "jnbe"} and jcc2 in {"jle", "jng", "jbe", "jna"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(lhs=lhs_wide, rhs=rhs_wide, op="CmpGT")
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op="CmpGT",
                expr=CBinaryOp(
                    "LogicalOr", hi_gt, CBinaryOp("LogicalAnd", hi_eq, lo_rel, codegen=codegen), codegen=codegen
                ),
            )
        if jcc1 in {"jge", "jnl", "jae", "jnb", "jnc"} and jcc2 in {"jle", "jng", "jbe", "jna"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(
                    lhs=lhs_wide,
                    rhs=rhs_wide,
                    op="CmpGT" if low_op == "CmpGT" else "CmpGE",
                )
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op="CmpGE",
                expr=CBinaryOp(
                    "LogicalOr", hi_gt, CBinaryOp("LogicalAnd", hi_eq, lo_rel, codegen=codegen), codegen=codegen
                ),
            )
        if jcc1 in {"je", "jz"} and jcc2 in {"je", "jz", "jne", "jnz"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(lhs=lhs_wide, rhs=rhs_wide, op="CmpEQ")
            return _DecodedCmpGuard8616(lhs=None, rhs=None, op="CmpEQ", expr=eq_expr)
        if jcc1 in {"jne", "jnz"} and jcc2 in {"je", "jz", "jne", "jnz"}:
            if lhs_wide is not None and rhs_wide is not None:
                return _DecodedCmpGuard8616(lhs=lhs_wide, rhs=rhs_wide, op="CmpNE")
            ne_expr = CBinaryOp(
                "LogicalOr",
                CBinaryOp("CmpNE", lhs_hi, rhs_hi, codegen=codegen),
                CBinaryOp("LogicalAnd", hi_eq, CBinaryOp("CmpNE", lhs_lo, rhs_lo, codegen=codegen), codegen=codegen),
                codegen=codegen,
            )
            return _DecodedCmpGuard8616(lhs=None, rhs=None, op="CmpNE", expr=ne_expr)
        return None

    return _impl()


def _resolve_cmp_operand_expr_8616(
    project,
    codegen,
    operand,
    reg_state: dict[str, object],
    ds_var,
    reg_name_fn,
    reg_exprs: dict[tuple[int, str, int], object],
    ins_addr: int,
):
    def _impl():
        op_type = int(getattr(operand, "type", -1))
        if op_type == 1:
            reg_name = reg_name_fn(operand.reg).lower()
            expr = reg_state.get(reg_name)
            if expr is not None:
                return expr
            expr = _lookup_register_expr_8616(reg_exprs, int(ins_addr), reg_name, int(getattr(operand, "size", 0) or 2))
            if expr is not None:
                return expr
            expr = _lookup_prior_register_stack_load_8616(
                project,
                codegen,
                int(ins_addr),
                reg_name,
                int(getattr(operand, "size", 0) or 2),
            )
            if expr is not None:
                return expr
            reg_offset = _reg_offset_8616(project, reg_name)
            reg_size = int(getattr(operand, "size", 0) or 2)
            if reg_offset is not None:
                return CVariable(SimRegisterVariable(reg_offset, reg_size, name=reg_name), codegen=codegen)
            return None
        if op_type == 2:
            return _const_8616(int(operand.imm), codegen)
        if op_type == 3 and getattr(operand, "mem", None) is not None:
            mem = operand.mem
            if mem.base:
                base_reg_name = reg_name_fn(mem.base).lower()
                if base_reg_name == "bp":
                    return _bp_operand_stack_expr_8616(codegen, int(mem.disp), int(getattr(operand, "size", 0) or 2))
                base_expr = reg_state.get(base_reg_name)
                return _memory_load_expr_8616(
                    project,
                    codegen,
                    ds_var,
                    base_expr,
                    int(mem.disp),
                    int(getattr(operand, "size", 0) or 2),
                )
        return None

    return _impl()


def _decode_block_and_jcc_index_8616(project, block_addr: int, jcc_addr: int, debug_jcc: bool):
    try:
        block = project.factory.block(block_addr, opt_level=0)
    except Exception:
        if debug_jcc:
            _log.warning("[jcc-rewrite] block decode failed block=%#x jcc=%#x", block_addr, jcc_addr)
        return None, None
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    jcc_index = next((idx for idx, insn in enumerate(insns) if int(insn.address) == int(jcc_addr)), None)
    if jcc_index is None or jcc_index == 0:
        if debug_jcc:
            _log.warning(
                "[jcc-rewrite] jcc index missing block=%#x jcc=%#x insn_count=%d", block_addr, jcc_addr, len(insns)
            )
        return None, None
    return insns, jcc_index


def _nearest_flag_producer_before_jcc_8616(insns: tuple, jcc_index: int):
    for idx in range(int(jcc_index) - 1, -1, -1):
        insn = insns[idx]
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic in {"cmp", "test", "inc", "dec", "add", "sub", "and", "or", "xor"}:
            return insn
        if mnemonic.startswith("j") or mnemonic in {"ret", "retf", "iret", "call", "lcall"}:
            break
    return None


def _decode_mask_test_guard_8616(project, codegen, jcc_mnemonic: str, block_addr: int, jcc_addr: int, debug_jcc: bool):
    if jcc_mnemonic not in _JCC_COMPARE_MASK_TESTS_8616:
        return None
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


_INC_DEC_JCC_BASELINE_8616: dict[tuple[str, str], tuple[str, int, bool]] = {
    ("inc", "je"): ("CmpEQ", -1, True),
    ("inc", "jz"): ("CmpEQ", -1, True),
    ("inc", "jne"): ("CmpNE", -1, True),
    ("inc", "jnz"): ("CmpNE", -1, True),
    ("inc", "jge"): ("CmpGE", -1, True),
    ("inc", "jnl"): ("CmpGE", -1, True),
    ("inc", "jg"): ("CmpGT", -1, True),
    ("inc", "jnle"): ("CmpGT", -1, True),
    ("inc", "jl"): ("CmpLT", -1, True),
    ("inc", "jnge"): ("CmpLT", -1, True),
    ("inc", "jle"): ("CmpLE", -1, True),
    ("inc", "jng"): ("CmpLE", -1, True),
    ("dec", "je"): ("CmpEQ", 1, False),
    ("dec", "jz"): ("CmpEQ", 1, False),
    ("dec", "jne"): ("CmpNE", 1, False),
    ("dec", "jnz"): ("CmpNE", 1, False),
    ("dec", "jge"): ("CmpGE", 1, False),
    ("dec", "jnl"): ("CmpGE", 1, False),
    ("dec", "jg"): ("CmpGT", 1, False),
    ("dec", "jnle"): ("CmpGT", 1, False),
    ("dec", "jl"): ("CmpLT", 1, False),
    ("dec", "jnge"): ("CmpLT", 1, False),
    ("dec", "jle"): ("CmpLE", 1, False),
    ("dec", "jng"): ("CmpLE", 1, False),
}


def _decode_linear_insns_range_8616(project, start_addr: int, stop_addr: int) -> tuple:
    insns: list[object] = []
    addr = int(start_addr)
    while addr < int(stop_addr):
        try:
            block = project.factory.block(addr, num_inst=1, opt_level=0)
        except Exception:
            break
        decoded = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not decoded:
            break
        insn = decoded[0]
        insn_addr = int(getattr(insn, "address", addr) or addr)
        if insn_addr >= int(stop_addr):
            break
        insns.append(insn)
        size = int(getattr(insn, "size", 0) or 0)
        if size <= 0:
            break
        addr = insn_addr + size
    return tuple(insns)


def _switch_dispatch_seed_expr_8616(project, codegen, ins_addr: int, reg_name: str, reg_size: int):
    insns = tuple(_function_insns_for_codegen_8616(project, codegen) or ())
    for idx, insn in enumerate(insns[:-1]):
        if int(getattr(insn, "address", -1)) >= int(ins_addr):
            break
        next_insn = insns[idx + 1]
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        next_mnemonic = str(getattr(next_insn, "mnemonic", "")).lower()
        if mnemonic != "mov" or next_mnemonic not in {"jmp", "ljmp"}:
            continue
        operands = tuple(getattr(insn, "operands", ()) or ())
        if len(operands) != 2 or int(getattr(operands[0], "type", -1)) != 1 or int(getattr(operands[1], "type", -1)) != 3:
            continue
        if str(insn.reg_name(operands[0].reg)).lower() != reg_name.lower():
            continue
        if int(getattr(operands[0], "size", 0) or reg_size) != int(reg_size):
            continue
        target = _branch_target_imm_8616(next_insn)
        if target is None or int(target) > int(ins_addr):
            continue
        mem = operands[1].mem
        if not mem.base or str(insn.reg_name(mem.base)).lower() != "bp":
            continue
        seed = _bp_operand_stack_expr_8616(codegen, int(mem.disp), int(getattr(operands[1], "size", 0) or reg_size))
        return seed, int(target)
    return None, None


def _stateful_register_expr_before_insn_8616(project, codegen, ins_addr: int, reg_name: str, reg_size: int, reg_exprs, ds_var):
    reg_state: dict[str, object] = {}
    stack_slots: dict[tuple[int, int], object] = {}
    seed_expr, replay_start = _switch_dispatch_seed_expr_8616(project, codegen, ins_addr, reg_name, reg_size)
    if seed_expr is not None and replay_start is not None:
        reg_state[reg_name.lower()] = seed_expr
        replay_insns = _decode_linear_insns_range_8616(project, replay_start, int(ins_addr))
    else:
        replay_insns = tuple(_function_insns_for_codegen_8616(project, codegen) or ())
    for insn in replay_insns:
        current_addr = int(getattr(insn, "address", -1))
        if current_addr >= int(ins_addr):
            break
        _apply_cmp_state_update_8616(project, codegen, insn, reg_state, stack_slots, reg_exprs, ds_var)
    return reg_state.get(reg_name.lower())


def _decode_inc_dec_jcc_guard_8616(project, codegen, arith_insn, jcc_mnemonic: str, reg_exprs, ds_var=None):
    def _impl():
        mnemonic = str(getattr(arith_insn, "mnemonic", "")).lower()
        if mnemonic not in {"inc", "dec"}:
            return None
        decision = _INC_DEC_JCC_BASELINE_8616.get((mnemonic, jcc_mnemonic))
        if decision is None:
            return None
        operands = tuple(getattr(arith_insn, "operands", ()) or ())
        if len(operands) != 1 or int(getattr(operands[0], "type", -1)) != 1:
            return None
        reg_name = arith_insn.reg_name(operands[0].reg).lower()
        reg_size = int(getattr(operands[0], "size", 0) or 2)
        lhs = None
        if reg_name in {"ax", "al", "ah"}:
            lhs = _call_return_expr_before_insn_8616(project, codegen, int(arith_insn.address))
        if lhs is None:
            lhs = _stateful_register_expr_before_insn_8616(
                project,
                codegen,
                int(arith_insn.address),
                reg_name,
                reg_size,
                reg_exprs,
                ds_var,
            )
        if lhs is None:
            lhs = _lookup_register_expr_before_8616(reg_exprs, int(arith_insn.address), reg_name, reg_size)
        if lhs is None:
            reg_offset = _reg_offset_8616(project, reg_name)
            if reg_offset is None:
                return None
            lhs = CVariable(SimRegisterVariable(reg_offset, reg_size, name=reg_name), codegen=codegen)
        op, rhs_value, rhs_signed = decision
        rhs = _signed_const_8616(rhs_value, codegen) if rhs_signed else _const_8616(rhs_value, codegen)
        return _DecodedCmpGuard8616(lhs=lhs, rhs=rhs, op=op)

    return _impl()


def _decode_test_jcc_guard_8616(project, codegen, test_insn, jcc_mnemonic: str, reg_exprs, ds_var):
    def _impl():
        mnemonic = str(getattr(test_insn, "mnemonic", "")).lower()
        if mnemonic not in {"test", "or", "and"}:
            return None
        if jcc_mnemonic not in {"je", "jz", "jne", "jnz"}:
            return None
        operands = tuple(getattr(test_insn, "operands", ()) or ())
        if len(operands) != 2:
            return None
        reg_state: dict[str, object] = {}
        stack_slots: dict[tuple[int, int], object] = {}
        lhs = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            operands[0],
            reg_state,
            ds_var,
            test_insn.reg_name,
            reg_exprs,
            int(test_insn.address),
        )
        rhs = _resolve_cmp_operand_expr_8616(
            project,
            codegen,
            operands[1],
            reg_state,
            ds_var,
            test_insn.reg_name,
            reg_exprs,
            int(test_insn.address),
        )
        if lhs is None or rhs is None:
            return None
        if mnemonic in {"or", "and"} and not _same_c_expression_8616(lhs, rhs):
            return None
        tested = lhs if _same_c_expression_8616(lhs, rhs) else CBinaryOp("And", lhs, rhs, codegen=codegen)
        return _DecodedCmpGuard8616(
            lhs=tested,
            rhs=_const_8616(0, codegen),
            op="CmpEQ" if jcc_mnemonic in {"je", "jz"} else "CmpNE",
        )

    return _impl()


def _apply_cmp_state_update_8616(project, codegen, insn, reg_state, stack_slots, reg_exprs, ds_var) -> None:
    def _impl():
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic == "mov" and len(insn.operands) == 2 and insn.operands[0].type == 1 and insn.operands[1].type == 3:
            dst_reg = insn.reg_name(insn.operands[0].reg).lower()
            mem = insn.operands[1].mem
            key = (int(mem.disp), int(insn.operands[0].size)) if insn.reg_name(mem.base) == "bp" else None
            expr = None
            if key is not None:
                expr = _bp_operand_stack_expr_8616(codegen, key[0], key[1]) or stack_slots.get(key)
            elif mem.base:
                base_reg_name = insn.reg_name(mem.base).lower()
                base_expr = reg_state.get(base_reg_name)
                if base_expr is not None:
                    expr = _memory_load_expr_8616(
                        project,
                        codegen,
                        ds_var,
                        base_expr,
                        int(mem.disp),
                        int(insn.operands[0].size),
                    )
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
            return

        if mnemonic == "mov" and len(insn.operands) == 2 and insn.operands[0].type == 3 and insn.operands[1].type == 1:
            mem = insn.operands[0].mem
            if insn.reg_name(mem.base) != "bp":
                return
            src_reg = insn.reg_name(insn.operands[1].reg).lower()
            size = int(insn.operands[1].size)
            slot_expr = _bp_operand_stack_expr_8616(codegen, int(mem.disp), size)
            if slot_expr is not None:
                stack_slots[(int(mem.disp), size)] = slot_expr
            elif reg_state.get(src_reg) is not None:
                stack_slots[(int(mem.disp), size)] = reg_state[src_reg]
            return

        if mnemonic in {"cbw", "cwde"}:
            al_expr = reg_state.get("al")
            if al_expr is None:
                reg_state.pop("ax", None)
                reg_state.pop("eax", None)
                return
            reg_state["ax"] = al_expr
            reg_state["eax"] = al_expr
            codegen._inertia_jcc_byte_extend_materialized_8616 = int(
                getattr(codegen, "_inertia_jcc_byte_extend_materialized_8616", 0) or 0
            ) + 1
            return

        if mnemonic in {"shl", "sal"} and len(insn.operands) == 2 and insn.operands[0].type == 1 and insn.operands[1].type == 2:
            reg_name = insn.reg_name(insn.operands[0].reg).lower()
            reg_expr = reg_state.get(reg_name)
            if reg_expr is not None:
                reg_state[reg_name] = CBinaryOp("Shl", reg_expr, _const_8616(int(insn.operands[1].imm), codegen), codegen=codegen)
            else:
                reg_state.pop(reg_name, None)
            return

        if mnemonic in {"inc", "dec"} and len(insn.operands) == 1 and insn.operands[0].type == 1:
            reg_name = insn.reg_name(insn.operands[0].reg).lower()
            reg_expr = reg_state.get(reg_name)
            if reg_expr is None:
                reg_state.pop(reg_name, None)
                return
            op = "Add" if mnemonic == "inc" else "Sub"
            reg_state[reg_name] = CBinaryOp(op, reg_expr, _const_8616(1, codegen), codegen=codegen)
            return

        if mnemonic in {"add", "sub"} and len(insn.operands) == 2 and insn.operands[0].type == 1:
            reg_name = insn.reg_name(insn.operands[0].reg).lower()
            reg_expr = reg_state.get(reg_name)
            if reg_expr is None:
                reg_state.pop(reg_name, None)
                return
            rhs = _resolve_cmp_operand_expr_8616(
                project,
                codegen,
                insn.operands[1],
                reg_state,
                ds_var,
                insn.reg_name,
                reg_exprs,
                int(insn.address),
            )
            if rhs is None:
                reg_state.pop(reg_name, None)
                return
            op = "Add" if mnemonic == "add" else "Sub"
            reg_state[reg_name] = CBinaryOp(op, reg_expr, rhs, codegen=codegen)
            return

    return _impl()


def _translate_cmp_jcc_guard_8616(project, codegen, block_addr: int, jcc_addr: int) -> _DecodedCmpGuard8616 | None:
    def _impl():
        debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
        insns, jcc_index = _decode_block_and_jcc_index_8616(project, block_addr, jcc_addr, debug_jcc)
        if insns is None or jcc_index is None:
            return None
        jcc_insn = insns[jcc_index]
        jcc_mnemonic = jcc_insn.mnemonic.lower()
        mask_decoded = _decode_mask_test_guard_8616(project, codegen, jcc_mnemonic, block_addr, jcc_addr, debug_jcc)
        if mask_decoded is not None:
            return mask_decoded

        cmp_insn = _nearest_flag_producer_before_jcc_8616(insns, jcc_index)
        if cmp_insn is None:
            if debug_jcc:
                _log.warning("[jcc-rewrite] no flag producer block=%#x jcc=%#x", block_addr, jcc_addr)
            return None

        if jcc_mnemonic not in _JCC_COMPARE_OPS_8616:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] unsupported jcc mnemonic=%s block=%#x jcc=%#x", jcc_mnemonic, block_addr, jcc_addr
                )
            return None
        reg_exprs = _register_exprs_by_ins_addr_8616(codegen, project)
        ds_offset = _reg_offset_8616(project, "ds")
        ds_var = (
            CVariable(SimRegisterVariable(ds_offset, 2, name="ds"), codegen=codegen)
            if ds_offset is not None
            else None
        )
        arith_decoded = _decode_inc_dec_jcc_guard_8616(project, codegen, cmp_insn, jcc_mnemonic, reg_exprs, ds_var)
        if arith_decoded is not None:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] decoded arithmetic-jcc block=%#x jcc=%#x mnemonic=%s predecessor=%s",
                    block_addr,
                    jcc_addr,
                    jcc_mnemonic,
                    cmp_insn.mnemonic,
                )
            return arith_decoded
        if ds_var is None:
            if debug_jcc:
                _log.warning("[jcc-rewrite] ds reg missing block=%#x jcc=%#x", block_addr, jcc_addr)
            return None
        test_decoded = _decode_test_jcc_guard_8616(project, codegen, cmp_insn, jcc_mnemonic, reg_exprs, ds_var)
        if test_decoded is not None:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] decoded test-jcc block=%#x jcc=%#x mnemonic=%s predecessor=%s",
                    block_addr,
                    jcc_addr,
                    jcc_mnemonic,
                    cmp_insn.mnemonic,
                )
            return test_decoded
        if cmp_insn.mnemonic != "cmp" or len(cmp_insn.operands) != 2:
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] predecessor not cmp mnemonic=%s block=%#x jcc=%#x",
                    cmp_insn.mnemonic,
                    block_addr,
                    jcc_addr,
            )
            return None

        chain_decoded = _decode_cmp_jcc_32bit_chain_8616(project, codegen, cmp_insn, jcc_insn, reg_exprs, ds_var)
        if chain_decoded is not None:
            return chain_decoded
        reg_state: dict[str, object] = {}
        stack_slots: dict[tuple[int, int], object] = {}

        for insn in insns[:jcc_index]:
            _apply_cmp_state_update_8616(project, codegen, insn, reg_state, stack_slots, reg_exprs, ds_var)

        lhs_op = cmp_insn.operands[0]
        rhs_op = cmp_insn.operands[1]
        lhs = _resolve_cmp_operand_expr_8616(
            project, codegen, lhs_op, reg_state, ds_var, cmp_insn.reg_name, reg_exprs, int(cmp_insn.address)
        )
        rhs = _resolve_cmp_operand_expr_8616(
            project, codegen, rhs_op, reg_state, ds_var, cmp_insn.reg_name, reg_exprs, int(cmp_insn.address)
        )
        call_return_expr = _call_return_expr_before_insn_8616(project, codegen, int(cmp_insn.address))
        if call_return_expr is not None:
            lhs_reg = (
                int(getattr(lhs_op, "type", -1)) == 1
                and str(cmp_insn.reg_name(lhs_op.reg)).lower() in {"ax", "al", "ah"}
            )
            rhs_reg = (
                int(getattr(rhs_op, "type", -1)) == 1
                and str(cmp_insn.reg_name(rhs_op.reg)).lower() in {"ax", "al", "ah"}
            )
            if lhs_reg:
                lhs = call_return_expr
            elif rhs_reg:
                rhs = call_return_expr

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
                _log.warning(
                    "[jcc-rewrite] op map missing mnemonic=%s block=%#x jcc=%#x", jcc_mnemonic, block_addr, jcc_addr
                )
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

    return _impl()


def _rewrite_decoded_jcc_conditions_8616(project, codegen) -> bool:
    def _impl():
        if getattr(codegen, "cfunc", None) is None:
            return False
        flags_offset = _reg_offset_8616(project, "flags")
        if flags_offset is None:
            return False

        changed = False
        materialized_count = 0
        key_signature_plan: dict[tuple[int, int], tuple] = {}
        key_decoded_plan: dict[tuple[int, int], _DecodedCmpGuard8616] = {}
        key_conflicts: set[tuple[int, int]] = set()
        unknown_polarity_refused_keys: set[tuple[int, int]] = set()
        raw_state_refused_keys: set[tuple[int, int]] = set()

        def _is_literal_condition_8616(expr) -> bool:
            node = expr
            while isinstance(node, CTypeCast):
                node = node.expr
            if isinstance(node, CConstant):
                return isinstance(getattr(node, "value", None), int)
            return False

        def _is_tagged_condition_carrier_8616(expr) -> bool:
            seen: set[int] = set()

            def _walk(node) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CITE):
                    return True
                if isinstance(node, CBinaryOp):
                    return _walk(getattr(node, "lhs", None)) or _walk(getattr(node, "rhs", None))
                if isinstance(node, CUnaryOp):
                    return _walk(getattr(node, "operand", None))
                if isinstance(node, CTypeCast):
                    return _walk(getattr(node, "expr", None))
                cond = getattr(node, "cond", None)
                if cond is not None and _walk(cond):
                    return True
                expr = getattr(node, "expr", None)
                if expr is not None and _walk(expr):
                    return True
                return False

            return _walk(expr)

        def _expr_uses_nonsegment_register_carrier_8616(expr) -> bool:
            seen: set[int] = set()
            segment_offsets = {
                offset
                for name, (offset, _size) in getattr(project.arch, "registers", {}).items()
                if name.lower() in {"cs", "ds", "es", "ss"}
            }

            def _walk(node) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CVariable):
                    variable = getattr(node, "variable", None)
                    if isinstance(variable, SimRegisterVariable):
                        return int(getattr(variable, "reg", -1)) not in segment_offsets
                if isinstance(node, CBinaryOp):
                    return _walk(getattr(node, "lhs", None)) or _walk(getattr(node, "rhs", None))
                if isinstance(node, CUnaryOp):
                    return _walk(getattr(node, "operand", None))
                if isinstance(node, CTypeCast):
                    return _walk(getattr(node, "expr", None))
                for attr in ("expr", "condition", "cond", "lhs", "rhs"):
                    child = getattr(node, attr, None)
                    if child is not None and _walk(child):
                        return True
                args = getattr(node, "args", None)
                if isinstance(args, (list, tuple)):
                    return any(_walk(arg) for arg in args)
                return False

            return _walk(expr)

        def _has_materialized_nonflag_cmp_8616(expr) -> bool:
            seen: set[int] = set()

            def _walk(node) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CBinaryOp):
                    op = getattr(node, "op", None)
                    if isinstance(op, str) and op.startswith("Cmp"):
                        if not _c_expr_uses_register_8616(node, flags_offset):
                            return not _expr_uses_nonsegment_register_carrier_8616(node)
                    return _walk(getattr(node, "lhs", None)) or _walk(getattr(node, "rhs", None))
                if isinstance(node, CUnaryOp):
                    return _walk(getattr(node, "operand", None))
                cond = getattr(node, "cond", None)
                if cond is not None:
                    return _walk(cond)
                return False

            return _walk(expr)

        def _arg_stack_offsets_8616() -> set[int]:
            cfunc = getattr(codegen, "cfunc", None)
            arg_offsets: set[int] = set()
            arg_list = tuple(getattr(cfunc, "arg_list", ()) or ())
            for arg in arg_list:
                variable = getattr(arg, "variable", None)
                if isinstance(variable, SimStackVariable):
                    arg_offsets.add(int(getattr(variable, "offset", 0) or 0))
            variables_in_use = getattr(cfunc, "variables_in_use", None)
            if isinstance(variables_in_use, dict):
                for variable, cvar in tuple(variables_in_use.items()):
                    if not isinstance(variable, SimStackVariable):
                        continue
                    offset = int(getattr(variable, "offset", 0) or 0)
                    if offset <= 0:
                        continue
                    cvar_name = getattr(cvar, "name", None)
                    var_name = getattr(variable, "name", None)
                    for name in (cvar_name, var_name):
                        if not isinstance(name, str):
                            continue
                        name = name.strip()
                        if not name or name.startswith(("tmp_", "vvar_", "ir_")):
                            break
                        arg_offsets.add(offset)
                        break
            unified_locals = getattr(cfunc, "unified_local_vars", None)
            if isinstance(unified_locals, dict):
                for cvars in unified_locals.values():
                    for item in tuple(cvars or ()):
                        if not isinstance(item, tuple) or not item:
                            continue
                        candidate = item[0]
                        variable = getattr(candidate, "variable", None)
                        if not isinstance(variable, SimStackVariable):
                            continue
                        offset = int(getattr(variable, "offset", 0) or 0)
                        if offset <= 0:
                            continue
                        name = getattr(variable, "name", None)
                        if not isinstance(name, str):
                            continue
                        name = name.strip()
                        if name.startswith(("tmp_", "vvar_", "ir_")):
                            continue
                        arg_offsets.add(offset)
            return arg_offsets

        _arg_stack_offsets = _arg_stack_offsets_8616()

        def _expr_uses_nonarg_bp_positive_stack_slot_8616(expr) -> bool:
            seen: set[int] = set()

            def _walk(node) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CVariable):
                    variable = getattr(node, "variable", None)
                    if isinstance(variable, SimStackVariable):
                        offset = int(getattr(variable, "offset", 0) or 0)
                        if offset >= 0 and offset not in _arg_stack_offsets:
                            return True
                if isinstance(node, CBinaryOp):
                    return _walk(getattr(node, "lhs", None)) or _walk(getattr(node, "rhs", None))
                if isinstance(node, CUnaryOp):
                    return _walk(getattr(node, "operand", None))
                if isinstance(node, CTypeCast):
                    return _walk(getattr(node, "expr", None))
                for attr in ("expr", "condition", "cond"):
                    child = getattr(node, attr, None)
                    if child is not None and _walk(child):
                        return True
                return False

            return _walk(expr)

        def _expr_uses_unstable_positive_stack_arg_placeholder_8616(expr) -> bool:
            seen: set[int] = set()

            def _walk(node) -> bool:
                if node is None:
                    return False
                marker = id(node)
                if marker in seen:
                    return False
                seen.add(marker)
                if isinstance(node, CVariable):
                    variable = getattr(node, "variable", None)
                    if isinstance(variable, SimStackVariable):
                        offset = int(getattr(variable, "offset", 0) or 0)
                        if offset >= 0:
                            names = (
                                getattr(node, "name", None),
                                getattr(variable, "name", None),
                                getattr(getattr(node, "unified_variable", None), "name", None),
                            )
                            if any(_is_unstable_stack_arg_name_8616(name) for name in names):
                                return True
                if isinstance(node, CBinaryOp):
                    return _walk(getattr(node, "lhs", None)) or _walk(getattr(node, "rhs", None))
                if isinstance(node, CUnaryOp):
                    return _walk(getattr(node, "operand", None))
                if isinstance(node, CTypeCast):
                    return _walk(getattr(node, "expr", None))
                for attr in ("expr", "condition", "cond"):
                    child = getattr(node, attr, None)
                    if child is not None and _walk(child):
                        return True
                return False

            return _walk(expr)

        def _safe_fingerprint_8616(expr) -> tuple[str, str]:
            try:
                value = _expr_fingerprint(expr, project)
            except Exception:  # pragma: no cover - platform-specific fingerprints
                value = repr(expr)
            return (str(type(expr).__name__), repr(value))

        def _validation_fingerprint_8616(expr) -> str:
            try:
                return str(_expr_fingerprint(expr, project))
            except Exception:  # pragma: no cover - platform-specific fingerprints
                return repr(expr)

        def _record_jcc_validation_evidence_8616(before_expr, after_expr) -> None:
            before_fp = _validation_fingerprint_8616(before_expr)
            after_fp = _validation_fingerprint_8616(after_expr)
            if not before_fp or not after_fp or before_fp == after_fp:
                return
            evidence = list(getattr(codegen, "_inertia_jcc_condition_validation_evidence_8616", ()) or ())
            evidence.append(
                {
                    "removed": before_fp,
                    "added": after_fp,
                }
            )
            codegen._inertia_jcc_condition_validation_evidence_8616 = tuple(evidence)

        def _record_jcc_decoded_condition_fingerprint_8616(expr) -> None:
            fingerprint = _validation_fingerprint_8616(expr)
            if not fingerprint:
                return
            existing = tuple(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ()) or ())
            if fingerprint not in existing:
                codegen._inertia_jcc_decoded_condition_fingerprint_evidence_count_8616 = int(
                    getattr(codegen, "_inertia_jcc_decoded_condition_fingerprint_evidence_count_8616", 0) or 0
                ) + 1
            codegen._inertia_jcc_decoded_condition_fingerprints_8616 = tuple(dict.fromkeys(existing + (fingerprint,)))

        def _record_decoded_guard_fingerprint_8616(decoded) -> None:
            expr = getattr(decoded, "expr", None)
            if expr is None:
                expr = CBinaryOp(
                    decoded.op,
                    decoded.lhs,
                    decoded.rhs,
                    codegen=codegen,
                )
            _record_jcc_decoded_condition_fingerprint_8616(expr)

        def _const_bool_value_8616(expr) -> int | None:
            node = expr
            while isinstance(node, CTypeCast):
                node = getattr(node, "expr", None)
            if isinstance(node, CConstant) and int(getattr(node, "value", -1)) in {0, 1}:
                return int(getattr(node, "value", -1))
            return None

        def _condition_inverts_decoded_guard_8616(expr) -> bool:
            if isinstance(expr, CUnaryOp) and getattr(expr, "op", None) == "Not":
                return not _condition_inverts_decoded_guard_8616(getattr(expr, "operand", None))
            if isinstance(expr, CITE):
                iftrue = _const_bool_value_8616(getattr(expr, "iftrue", None))
                iffalse = _const_bool_value_8616(getattr(expr, "iffalse", None))
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning(
                        "[jcc-rewrite] cite polarity iftrue=%r iffalse=%r inverts=%s",
                        iftrue,
                        iffalse,
                        (iftrue, iffalse) == (0, 1),
                    )
                if (iftrue, iffalse) == (0, 1):
                    return True
                if (iftrue, iffalse) == (1, 0):
                    return False
            return False

        def _condition_is_direct_inverting_cite_8616(expr) -> bool:
            if not isinstance(expr, CITE):
                return False
            iftrue = _const_bool_value_8616(getattr(expr, "iftrue", None))
            iffalse = _const_bool_value_8616(getattr(expr, "iffalse", None))
            return (iftrue, iffalse) == (0, 1)

        def _decoded_guard_contains_real_call_8616(decoded: _DecodedCmpGuard8616) -> bool:
            roots = (decoded.expr,) if getattr(decoded, "expr", None) is not None else (decoded.lhs, decoded.rhs)
            for root in roots:
                for child in _iter_c_nodes_deep_8616(root):
                    if not isinstance(child, CFunctionCall):
                        continue
                    callee = getattr(child, "callee_target", None)
                    if isinstance(callee, str) and callee in {"SEG_PTR", "MK_FP", "SEG_U8", "SEG_U16", "SEG_U32"}:
                        continue
                    return True
            return False

        def _decoded_guard_uses_raw_state_register_8616(decoded: _DecodedCmpGuard8616) -> bool:
            raw_register_names = {"flags", "eflags", "sp"}
            raw_register_offsets = {
                offset
                for offset in (
                    _reg_offset_8616(project, "flags"),
                    _reg_offset_8616(project, "eflags"),
                    _reg_offset_8616(project, "sp"),
                )
                if isinstance(offset, int)
            }
            roots = (decoded.expr,) if getattr(decoded, "expr", None) is not None else (decoded.lhs, decoded.rhs)
            for root in roots:
                for child in _iter_c_nodes_deep_8616(root):
                    if not isinstance(child, CVariable):
                        continue
                    variable = getattr(child, "variable", None)
                    names = {
                        str(name).lower()
                        for name in (
                            getattr(child, "name", None),
                            getattr(variable, "name", None),
                            getattr(getattr(child, "unified_variable", None), "name", None),
                        )
                        if isinstance(name, str) and name
                    }
                    if names & raw_register_names:
                        return True
                    if isinstance(variable, SimRegisterVariable):
                        reg = getattr(variable, "reg", None)
                        if isinstance(reg, int) and reg in raw_register_offsets:
                            return True
            return False

        def _invert_decoded_guard_8616(decoded: _DecodedCmpGuard8616, tags):
            if getattr(decoded, "expr", None) is not None:
                return _DecodedCmpGuard8616(
                    lhs=None,
                    rhs=None,
                    op=decoded.op,
                    expr=CUnaryOp("Not", decoded.expr, codegen=codegen, tags=tags),
                )
            inverted_op = _INVERT_CMP_OP_8616.get(decoded.op)
            if inverted_op is not None and not _decoded_guard_contains_real_call_8616(decoded):
                return _DecodedCmpGuard8616(lhs=decoded.lhs, rhs=decoded.rhs, op=inverted_op, expr=None)
            return _DecodedCmpGuard8616(
                lhs=None,
                rhs=None,
                op=decoded.op,
                expr=CUnaryOp(
                    "Not",
                    CBinaryOp(decoded.op, decoded.lhs, decoded.rhs, codegen=codegen, tags=tags),
                    codegen=codegen,
                    tags=tags,
                ),
            )

        def _jcc_target_for_key_8616(key: tuple[int, int] | None) -> int | None:
            if not isinstance(key, tuple) or len(key) != 2:
                return None
            ins_addr, block_addr = key
            if not (isinstance(ins_addr, int) and isinstance(block_addr, int)):
                return None
            decoded = _decode_block_and_jcc_index_8616(project, block_addr, ins_addr, False)
            insns, jcc_index = decoded
            if insns is None or jcc_index is None:
                return None
            if jcc_index < 0 or jcc_index >= len(insns):
                return None
            return _branch_target_imm_8616(insns[jcc_index])

        def _root_contains_ins_addr_8616(root, target_addr: int) -> bool:
            if root is None:
                return False
            pending = [root]
            seen: set[int] = set()
            while pending:
                current = pending.pop()
                if current is None:
                    continue
                if isinstance(current, (list, tuple)):
                    pending.extend(reversed(tuple(current)))
                    continue
                marker = id(current)
                if marker in seen:
                    continue
                seen.add(marker)
                tags = getattr(current, "tags", None)
                if isinstance(tags, dict) and tags.get("ins_addr") == target_addr:
                    return True
                stmts = getattr(current, "statements", None)
                if stmts is not None:
                    pending.extend(reversed(tuple(stmts or ())))
                    continue
                for attr in ("condition_and_nodes", "body", "else_node", "iftrue", "iffalse"):
                    child = getattr(current, attr, None)
                    if child is None:
                        continue
                    if attr == "condition_and_nodes" and isinstance(child, (list, tuple)):
                        for _cond, body in reversed(tuple(child)):
                            pending.append(body)
                    else:
                        pending.append(child)
            return False

        def _jcc_polarity_evidence_8616(key: tuple[int, int] | None, body) -> _JccPolarityEvidence8616:
            target = _jcc_target_for_key_8616(key)
            if isinstance(target, int) and _root_contains_ins_addr_8616(body, target):
                return _JccPolarityEvidence8616.JCC_TARGET_BODY
            return _JccPolarityEvidence8616.UNKNOWN

        def _body_is_break_only_8616(body) -> bool:
            if body is None:
                return False
            if isinstance(body, CBreak):
                return True
            statements = getattr(body, "statements", None)
            if statements is None:
                return False
            if type(statements).__name__ == "CStatements":
                statements = getattr(statements, "statements", None)
            items = tuple(statements or ())
            return len(items) == 1 and isinstance(items[0], CBreak)

        def _condition_exprs_from_stmt_8616(stmt):
            cond_pairs = getattr(stmt, "condition_and_nodes", None)
            if isinstance(cond_pairs, (list, tuple)):
                for cond, _body in tuple(cond_pairs):
                    if cond is not None:
                        yield cond
            cond = getattr(stmt, "condition", None)
            if cond is not None:
                yield cond

        def _child_statement_roots_8616(stmt):
            for attr in ("body", "else_node", "iftrue", "iffalse", "initializer", "iterator"):
                child = getattr(stmt, attr, None)
                if child is not None:
                    yield child
            cond_pairs = getattr(stmt, "condition_and_nodes", None)
            if isinstance(cond_pairs, (list, tuple)):
                for _cond, body in tuple(cond_pairs):
                    if body is not None:
                        yield body
            cases = getattr(stmt, "cases", None)
            if isinstance(cases, dict):
                yield from cases.values()
            default = getattr(stmt, "default", None)
            if default is not None:
                yield default

        def _statements_from_root_8616(root) -> tuple:
            if root is None:
                return ()
            stmts = getattr(root, "statements", None)
            if stmts is not None:
                if type(stmts).__name__ == "CStatements":
                    stmts = getattr(stmts, "statements", None)
                raw_stmts = tuple(stmts or ())
                flattened: list[object] = []
                for stmt in raw_stmts:
                    if type(stmt).__name__ == "CStatements":
                        nested = getattr(stmt, "statements", None)
                        if nested is not None:
                            flattened.extend(tuple(nested or ()))
                            continue
                    flattened.append(stmt)
                return tuple(flattened)
            if isinstance(root, (list, tuple)):
                flattened: list[object] = []
                for stmt in root:
                    if type(stmt).__name__ == "CStatements":
                        nested = getattr(stmt, "statements", None)
                        if nested is not None:
                            flattened.extend(tuple(nested or ()))
                            continue
                    flattened.append(stmt)
                return tuple(flattened)
            return ()

        def _assignment_rhs_has_real_call_8616(stmt) -> bool:
            if not isinstance(stmt, CAssignment):
                return False
            rhs = getattr(stmt, "rhs", None)
            if rhs is None:
                return False
            for child in _iter_c_nodes_deep_8616(rhs):
                if not isinstance(child, CFunctionCall):
                    continue
                callee = getattr(child, "callee_target", None)
                if isinstance(callee, str) and callee in {"SEG_PTR", "MK_FP", "SEG_U8", "SEG_U16", "SEG_U32"}:
                    continue
                return True
            return False

        def _call_return_guard_sources_by_key_8616() -> dict[tuple[int, int], object]:
            sources: dict[tuple[int, int], object] = {}
            conflicts: set[tuple[int, int]] = set()
            seen_roots: set[int] = set()
            debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
            debug_stats = {"blocks": 0, "stmts": 0, "assignments": 0, "callish": 0, "conditions_after_assign": 0}
            debug_stmt_types: dict[str, int] = {}

            def _record(cond, source) -> None:
                key = _condition_tags_8616(cond)
                if not isinstance(key, tuple) or key in conflicts:
                    return
                previous = sources.get(key)
                if previous is None:
                    sources[key] = source
                    return
                if _safe_fingerprint_8616(previous) != _safe_fingerprint_8616(source):
                    conflicts.add(key)
                    sources.pop(key, None)

            def _walk_block(root) -> None:
                root_id = id(root)
                if root_id in seen_roots:
                    return
                seen_roots.add(root_id)
                debug_stats["blocks"] += 1
                last_call_lhs = None
                for stmt in _statements_from_root_8616(root):
                    debug_stats["stmts"] += 1
                    stmt_type = type(stmt).__name__
                    debug_stmt_types[stmt_type] = debug_stmt_types.get(stmt_type, 0) + 1
                    if isinstance(stmt, CAssignment):
                        debug_stats["assignments"] += 1
                    if _assignment_rhs_has_real_call_8616(stmt):
                        debug_stats["callish"] += 1
                        lhs = getattr(stmt, "lhs", None)
                        last_call_lhs = lhs
                        continue
                    if last_call_lhs is not None:
                        for cond in _condition_exprs_from_stmt_8616(stmt):
                            debug_stats["conditions_after_assign"] += 1
                            _record(cond, last_call_lhs)
                    for child in _child_statement_roots_8616(stmt):
                        _walk_block(child)
                    last_call_lhs = None

            _walk_block(codegen.cfunc)
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] call-return guard sources=%d conflicts=%d stats=%r",
                    len(sources),
                    len(conflicts),
                    {**debug_stats, "types": debug_stmt_types},
                )
            return sources

        call_return_guard_sources = _call_return_guard_sources_by_key_8616()

        def _expr_is_return_register_8616(expr) -> bool:
            node = expr
            while isinstance(node, CTypeCast):
                node = getattr(node, "expr", None)
            if not isinstance(node, CVariable):
                return False
            variable = getattr(node, "variable", None)
            if not isinstance(variable, SimRegisterVariable):
                return False
            ax_offset = _reg_offset_8616(project, "ax")
            if ax_offset is None:
                return False
            return int(getattr(variable, "reg", -1)) == int(ax_offset)

        def _rebind_adjacent_call_return_register_conditions_8616() -> bool:
            local_changed = False
            local_count = 0
            seen_roots: set[int] = set()

            def _replace_return_register_reads_8616(cond, source):
                nonlocal local_changed, local_count
                if cond is None or source is None:
                    return cond
                if _expr_is_return_register_8616(cond):
                    local_changed = True
                    local_count += 1
                    return source
                if not _structured_codegen_node_8616(cond):
                    return cond

                def _replace_child(child):
                    nonlocal local_changed, local_count
                    if _expr_is_return_register_8616(child):
                        local_changed = True
                        local_count += 1
                        return source
                    return child

                if _replace_c_children_8616(cond, _replace_child):
                    local_changed = True
                return cond

            def _replace_stmt_conditions_8616(stmt, source) -> bool:
                before_count = local_count
                cond_pairs = getattr(stmt, "condition_and_nodes", None)
                if isinstance(cond_pairs, (list, tuple)):
                    pair_changed = False
                    new_pairs = []
                    for cond, body in tuple(cond_pairs):
                        new_cond = _replace_return_register_reads_8616(cond, source)
                        pair_changed = pair_changed or new_cond is not cond
                        new_pairs.append((new_cond, body))
                    if pair_changed:
                        stmt.condition_and_nodes = type(cond_pairs)(new_pairs)
                if hasattr(stmt, "condition"):
                    cond = getattr(stmt, "condition", None)
                    new_cond = _replace_return_register_reads_8616(cond, source)
                    if new_cond is not cond:
                        stmt.condition = new_cond
                return local_count != before_count

            def _walk_block(root) -> None:
                root_id = id(root)
                if root_id in seen_roots:
                    return
                seen_roots.add(root_id)
                last_call_lhs = None
                for stmt in _statements_from_root_8616(root):
                    if isinstance(stmt, CAssignment) and _assignment_rhs_has_real_call_8616(stmt):
                        last_call_lhs = getattr(stmt, "lhs", None)
                        continue
                    if last_call_lhs is not None:
                        _replace_stmt_conditions_8616(stmt, last_call_lhs)
                        last_call_lhs = None
                    for child in _child_statement_roots_8616(stmt):
                        _walk_block(child)

            _walk_block(codegen.cfunc)
            if local_count:
                try:
                    codegen._inertia_jcc_call_return_register_rebindings = int(
                        getattr(codegen, "_inertia_jcc_call_return_register_rebindings", 0) or 0
                    ) + local_count
                except Exception:
                    pass
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning("[jcc-rewrite] rebound adjacent call-return register reads count=%d", local_count)
            return local_changed

        def _expr_is_stale_literal_8616(expr) -> bool:
            node = expr
            while isinstance(node, CTypeCast):
                node = getattr(node, "expr", None)
            return isinstance(node, CConstant) and isinstance(getattr(node, "value", None), int)

        def _rebind_decoded_call_return_guard_8616(key, decoded):
            source = call_return_guard_sources.get(key)
            if source is None or getattr(decoded, "expr", None) is not None:
                return decoded
            lhs = decoded.lhs
            rhs = decoded.rhs
            rebound = False
            if _expr_is_return_register_8616(lhs) or _expr_is_stale_literal_8616(lhs):
                lhs = source
                rebound = True
            elif _expr_is_return_register_8616(rhs):
                rhs = source
                rebound = True
            if not rebound:
                return decoded
            try:
                codegen._inertia_jcc_call_return_rebindings = int(
                    getattr(codegen, "_inertia_jcc_call_return_rebindings", 0) or 0
                ) + 1
            except Exception:
                pass
            if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                _log.warning("[jcc-rewrite] rebound call-return guard key=%r source=%r", key, source)
            return _DecodedCmpGuard8616(lhs=lhs, rhs=rhs, op=decoded.op, expr=None)

        def _decoded_signature_8616(decoded: _DecodedCmpGuard8616):
            if getattr(decoded, "expr", None) is not None:
                return ("expr", decoded.op, *_safe_fingerprint_8616(decoded.expr))
            return ("cmp", decoded.op, *_safe_fingerprint_8616(decoded.lhs), *_safe_fingerprint_8616(decoded.rhs))

        def _collect_decoded_signature_8616(cond):
            key = _condition_tags_8616(cond)
            if not isinstance(key, tuple):
                return
            ins_addr = key[0]
            block_addr = key[1]
            if not (isinstance(ins_addr, int) and isinstance(block_addr, int)):
                return
            decoded = _decode_condition_from_tags_8616(cond, block_addr, ins_addr)
            if decoded is None:
                return
            signature = _decoded_signature_8616(decoded)
            previous = key_signature_plan.get(key)
            if previous is None:
                key_signature_plan[key] = signature
                key_decoded_plan[key] = decoded
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning("[jcc-rewrite] key plan set key=%r signature=%r", key, signature)
                return
            if previous != signature and key not in key_conflicts:
                key_conflicts.add(key)
                key_signature_plan.pop(key, None)
                key_decoded_plan.pop(key, None)
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning("[jcc-rewrite] key conflict key=%r signature_mismatch=%r prev=%r new=%r", key, key_signature_plan, previous, signature)

        def _iter_guard_conditions_8616():
            seen_conditions: set[int] = set()
            for stmt in _statements_from_root_8616(codegen.cfunc):
                for node in _iter_c_nodes_deep_8616(stmt):
                    cond_pairs = getattr(node, "condition_and_nodes", None)
                    if isinstance(cond_pairs, (list, tuple)):
                        for cond, _body in tuple(cond_pairs):
                            if cond is None:
                                continue
                            marker = id(cond)
                            if marker in seen_conditions:
                                continue
                            seen_conditions.add(marker)
                            yield cond
                    cond = getattr(node, "condition", None)
                    if cond is None:
                        continue
                    marker = id(cond)
                    if marker in seen_conditions:
                        continue
                    seen_conditions.add(marker)
                    yield cond

        def _decode_condition_from_tags_8616(cond, block_addr: int, ins_addr: int):
            # Primary lane: flags-backed conditions.
            # Recovery lane: conditions that already collapsed to a literal constant
            # but still carry insn/block tags for a decodable cmp+jcc origin.
            tagged_key = _condition_tags_8616(cond)
            debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
            has_carrier_evidence = (
                _c_expr_uses_register_8616(cond, flags_offset)
                or _is_literal_condition_8616(cond)
                or _is_tagged_condition_carrier_8616(cond)
                or _has_materialized_nonflag_cmp_8616(cond)
            )
            if not (
                has_carrier_evidence
            ):
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] decode skip no-evidence key=%r tagged_key=%r cond_type=%s",
                        (ins_addr, block_addr),
                        tagged_key,
                        type(cond).__name__,
                )
                return None

            decoded = _translate_cmp_jcc_guard_8616(project, codegen, block_addr, ins_addr)
            if decoded is None:
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip no-decoded key=%r", (ins_addr, block_addr))
                return None

            if getattr(decoded, "expr", None) is not None:
                return decoded

            same_expr = _same_c_expression_8616(decoded.lhs, decoded.rhs)
            lhs_fp = _safe_fingerprint_8616(decoded.lhs)
            rhs_fp = _safe_fingerprint_8616(decoded.rhs)
            if same_expr or lhs_fp == rhs_fp:
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] decode skip same-operands key=%r lhs_fp=%r rhs_fp=%r",
                        (ins_addr, block_addr),
                        lhs_fp,
                        rhs_fp,
                    )
                return None

            # Safety guard: avoid rewriting via decoded jcc when compare operands
            # depend on BP+positive stack slots (arg/return area). This pattern is
            # frequently ambiguous in 16-bit lifted state and can introduce false
            # loop predicates.
            if _expr_uses_nonarg_bp_positive_stack_slot_8616(decoded.lhs) or _expr_uses_nonarg_bp_positive_stack_slot_8616(
                decoded.rhs
            ):
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] decode skip positive-stack-slot key=%r lhs_fp=%r rhs_fp=%r",
                        (ins_addr, block_addr),
                        lhs_fp,
                        rhs_fp,
                )
                return None

            # Guardrail: once a condition is an explicit non-flag comparison,
            # treat it as materialized. Exception: a compare sourced from an
            # unstable positive BP placeholder is weaker evidence than a decoded
            # JCC guard whose operands are stable BP-local stack slots.
            if _has_materialized_nonflag_cmp_8616(cond):
                if not _expr_uses_unstable_positive_stack_arg_placeholder_8616(cond):
                    if not _decoded_guard_uses_raw_state_register_8616(decoded):
                        _record_decoded_guard_fingerprint_8616(decoded)
                        codegen._inertia_jcc_rewrite_kept_explicit_cmp_with_decoded_evidence_8616 = int(
                            getattr(
                                codegen,
                                "_inertia_jcc_rewrite_kept_explicit_cmp_with_decoded_evidence_8616",
                                0,
                            )
                            or 0
                        ) + 1
                    if debug_jcc:
                        _log.warning("[jcc-rewrite] decode skip explicit-cmp key=%r", (ins_addr, block_addr))
                    return None
                if debug_jcc:
                    _log.warning(
                        "[jcc-rewrite] replacing unstable explicit stack-arg cmp key=%r",
                        (ins_addr, block_addr),
                    )

            return decoded

        def _build_rewrite_8616(
            cond,
            decoded,
            key,
            *,
            polarity_evidence: _JccPolarityEvidence8616 = _JccPolarityEvidence8616.UNKNOWN,
        ):
            decoded = _rebind_decoded_call_return_guard_8616(key, decoded)
            tags = getattr(cond, "tags", None)
            if not isinstance(tags, dict) and isinstance(key, tuple) and len(key) == 2:
                ins_addr, block_addr = key
                if isinstance(ins_addr, int) and isinstance(block_addr, int):
                    tags = {"ins_addr": ins_addr, "vex_block_addr": block_addr}
            tags = dict(tags or {})
            tags["inertia_jcc_materialized_8616"] = True
            invert_guard = _condition_inverts_decoded_guard_8616(cond)
            if polarity_evidence is _JccPolarityEvidence8616.JCC_TARGET_BODY:
                invert_guard = False
            if invert_guard:
                if bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE")):
                    _log.warning(
                        "[jcc-rewrite] applying decoded guard polarity inversion key=%r op=%s evidence=%s",
                        key,
                        decoded.op,
                        polarity_evidence.value,
                    )
                decoded = _invert_decoded_guard_8616(decoded, tags)
            if getattr(decoded, "expr", None) is not None:
                with contextlib.suppress(Exception):
                    if not isinstance(getattr(decoded.expr, "tags", None), dict):
                        decoded.expr.tags = tags
                return decoded.expr
            return CBinaryOp(
                decoded.op,
                decoded.lhs,
                decoded.rhs,
                codegen=codegen,
                tags=tags,
            )

        def _decoded_condition_replacement(
            cond,
            *,
            body=None,
            polarity_evidence: _JccPolarityEvidence8616 | None = None,
        ):
            key = _condition_tags_8616(cond)
            ins_addr = None if key is None else key[0]
            block_addr = None if key is None else key[1]
            debug_jcc = bool(os.environ.get("INERTIA_DEBUG_JCC_REWRITE"))
            if debug_jcc:
                _log.warning(
                    "[jcc-rewrite] candidate key=%r uses_flags=%s cond_type=%s cond_op=%s",
                    key,
                    _c_expr_uses_register_8616(cond, flags_offset)
                    if isinstance(ins_addr, int) and isinstance(block_addr, int)
                    else _c_expr_uses_register_8616(cond, flags_offset),
                    type(cond).__name__ if cond is not None else None,
                    getattr(cond, "op", None),
                )
            if not (isinstance(ins_addr, int) and isinstance(block_addr, int)):
                return None
            if key in key_conflicts:
                if debug_jcc:
                    _log.warning("[jcc-rewrite] key conflict detected key=%r skip", key)
                return None
            decoded = key_decoded_plan.get(key)
            if decoded is None:
                decoded = _decode_condition_from_tags_8616(cond, block_addr, ins_addr)
            if decoded is None:
                return None
            planned_signature = key_signature_plan.get(key)
            if planned_signature is None:
                return None
            signature = _decoded_signature_8616(decoded)
            if signature != planned_signature:
                key_conflicts.add(key)
                key_signature_plan.pop(key, None)
                if debug_jcc:
                    _log.warning("[jcc-rewrite] signature mismatch key=%r signature=%r planned=%r", key, signature, planned_signature)
                return None
            if _decoded_guard_uses_raw_state_register_8616(decoded):
                should_count_refusal = True
                if isinstance(key, tuple):
                    should_count_refusal = key not in raw_state_refused_keys
                    raw_state_refused_keys.add(key)
                if should_count_refusal:
                    codegen._inertia_jcc_rewrite_refused_raw_state_guard_8616 = int(
                        getattr(codegen, "_inertia_jcc_rewrite_refused_raw_state_guard_8616", 0) or 0
                    ) + 1
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip raw-state guard key=%r", key)
                return None
            if bool(decoded.expr is not None):
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decoded candidate accepted (expr) key=%r", key)
            elif debug_jcc:
                _log.warning("[jcc-rewrite] decoded candidate accepted key=%r", key)
            if polarity_evidence is None:
                polarity_evidence = _jcc_polarity_evidence_8616(key, body)
            if (
                polarity_evidence is _JccPolarityEvidence8616.JCC_TARGET_BODY
                and _condition_is_direct_inverting_cite_8616(cond)
            ):
                codegen._inertia_jcc_rewrite_refused_target_body_inverted_cite_8616 = int(
                    getattr(codegen, "_inertia_jcc_rewrite_refused_target_body_inverted_cite_8616", 0) or 0
                ) + 1
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip target-body-inverted-cite key=%r", key)
                return None
            if (
                polarity_evidence is _JccPolarityEvidence8616.UNKNOWN
                and _condition_inverts_decoded_guard_8616(cond)
                and getattr(decoded, "expr", None) is None
                and not _decoded_guard_contains_real_call_8616(decoded)
            ):
                should_count_refusal = True
                if isinstance(key, tuple):
                    should_count_refusal = key not in unknown_polarity_refused_keys
                    unknown_polarity_refused_keys.add(key)
                if should_count_refusal:
                    codegen._inertia_jcc_rewrite_refused_unknown_polarity_8616 = int(
                        getattr(codegen, "_inertia_jcc_rewrite_refused_unknown_polarity_8616", 0) or 0
                    ) + 1
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip unknown-polarity-inversion key=%r", key)
                return None
            _record_decoded_guard_fingerprint_8616(decoded)
            replacement = _build_rewrite_8616(cond, decoded, key, polarity_evidence=polarity_evidence)
            _record_jcc_decoded_condition_fingerprint_8616(replacement)
            if _condition_materialized_by_jcc_8616(cond) and _validation_fingerprint_8616(
                cond
            ) == _validation_fingerprint_8616(replacement):
                if debug_jcc:
                    _log.warning("[jcc-rewrite] decode skip already-materialized key=%r", key)
                return None
            return replacement

        for cond in _iter_guard_conditions_8616():
            key = _condition_tags_8616(cond)
            if key is None:
                continue
            if key in key_conflicts:
                continue
            _collect_decoded_signature_8616(cond)

        if bool(os.environ.get("INERTIA_ENABLE_JCC_CALL_RETURN_REBIND")):
            if _rebind_adjacent_call_return_register_conditions_8616():
                changed = True

        def _rewrite_condition(
            node,
            *,
            body=None,
            polarity_evidence: _JccPolarityEvidence8616 | None = None,
        ):
            nonlocal changed, materialized_count
            replacement = _decoded_condition_replacement(node, body=body, polarity_evidence=polarity_evidence)
            if replacement is None:
                return None
            changed = True
            materialized_count += 1
            _record_jcc_validation_evidence_8616(node, replacement)
            return replacement

        def _replace_tagged_condition(
            node,
            *,
            body=None,
            polarity_evidence: _JccPolarityEvidence8616 | None = None,
        ):
            nonlocal changed
            replacement = _rewrite_condition(node, body=body, polarity_evidence=polarity_evidence)
            if replacement is not None:
                return replacement
            if not _structured_codegen_node_8616(node):
                return node
            key = _condition_tags_8616(node)
            if isinstance(key, tuple) and key in unknown_polarity_refused_keys:
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
                    polarity_evidence = (
                        _JccPolarityEvidence8616.BREAK_CONDITION
                        if _body_is_break_only_8616(body)
                        else _jcc_polarity_evidence_8616(_condition_tags_8616(cond), body)
                    )
                    new_cond = _replace_tagged_condition(cond, body=body, polarity_evidence=polarity_evidence)
                    pair_changed = pair_changed or (new_cond is not cond)
                    new_pairs.append((new_cond, body))
                    if new_cond is not cond:
                        changed = True
                if pair_changed:
                    node.condition_and_nodes = type(cond_pairs)(new_pairs)
                    # Keep primary condition in sync when the node-level condition
                    # has already collapsed (e.g. literal false), but a tagged
                    # branch-pair condition was successfully recovered.
                    primary = getattr(node, "condition", None)
                    if _is_literal_condition_8616(primary) and new_pairs:
                        first_cond = new_pairs[0][0]
                        if first_cond is not None:
                            node.condition = first_cond
                            changed = True
            if hasattr(node, "condition"):
                cond = getattr(node, "condition", None)
                if cond is not None:
                    condition_polarity_evidence = (
                        _JccPolarityEvidence8616.BREAK_CONDITION
                        if isinstance(node, CIfBreak)
                        else _JccPolarityEvidence8616.LOOP_CONTINUATION
                        if isinstance(node, CDoWhileLoop)
                        else _JccPolarityEvidence8616.UNKNOWN
                    )
                    new_cond = _replace_tagged_condition(cond, polarity_evidence=condition_polarity_evidence)
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

    return _impl()
