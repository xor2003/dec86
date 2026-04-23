from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable

from .decompiler_postprocess_flags import _c_expr_uses_register_8616
from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616, _structured_codegen_node_8616

__all__ = ["_rewrite_decoded_jcc_conditions_8616"]


@dataclass(frozen=True, slots=True)
class _DecodedCmpGuard8616:
    lhs: object
    rhs: object
    op: str


def _reg_offset_8616(project, name: str) -> int | None:
    reg = project.arch.registers.get(name.lower())
    return None if reg is None else int(reg[0])


def _const_8616(value: int, codegen):
    return CConstant(int(value), SimTypeShort(False), codegen=codegen)


def _register_exprs_by_ins_addr_8616(codegen, project) -> dict[tuple[int, str], object]:
    reg_exprs: dict[tuple[int, str], object] = {}
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
        for reg_name, (reg_offset, _reg_size) in project.arch.registers.items():
            if int(reg_offset) != int(getattr(variable, "reg", -1)):
                continue
            reg_exprs[(ins_addr, reg_name.lower())] = node.rhs
            break
    return reg_exprs


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
    return CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False).with_arch(project.arch),
            SimTypePointer(pointee).with_arch(project.arch),
            addr_expr,
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _translate_cmp_jcc_guard_8616(project, codegen, block_addr: int, jcc_addr: int) -> _DecodedCmpGuard8616 | None:
    try:
        block = project.factory.block(block_addr, opt_level=0)
    except Exception:
        return None

    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    jcc_index = next((idx for idx, insn in enumerate(insns) if int(insn.address) == int(jcc_addr)), None)
    if jcc_index is None or jcc_index == 0:
        return None
    jcc_insn = insns[jcc_index]
    cmp_insn = insns[jcc_index - 1]
    if jcc_insn.mnemonic not in {"jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "je", "jz", "jne", "jnz"}:
        return None
    if cmp_insn.mnemonic != "cmp" or len(cmp_insn.operands) != 2:
        return None

    ds_offset = _reg_offset_8616(project, "ds")
    if ds_offset is None:
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
            expr = reg_exprs.get((int(insn.address), dst_reg))
            if dst_reg == "al" and expr is not None:
                expr = _low_byte_expr_from_assignment_8616(expr)
            elif expr is None and key is not None:
                expr = stack_slots.get(key)
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
            src_expr = reg_state.get(src_reg)
            if src_expr is not None:
                stack_slots[(int(mem.disp), int(insn.operands[1].size))] = src_expr
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
        return None

    op = {
        "jg": "CmpGT",
        "jge": "CmpGE",
        "jl": "CmpLT",
        "jle": "CmpLE",
        "ja": "CmpGT",
        "jae": "CmpGE",
        "jb": "CmpLT",
        "jbe": "CmpLE",
        "je": "CmpEQ",
        "jz": "CmpEQ",
        "jne": "CmpNE",
        "jnz": "CmpNE",
    }.get(jcc_insn.mnemonic)
    if op is None:
        return None
    return _DecodedCmpGuard8616(lhs=lhs, rhs=rhs, op=op)


def _rewrite_decoded_jcc_conditions_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    flags_offset = _reg_offset_8616(project, "flags")
    if flags_offset is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed
        if not _structured_codegen_node_8616(node):
            return
        if hasattr(node, "condition_and_nodes") and isinstance(getattr(node, "condition_and_nodes", None), list):
            new_pairs = []
            pair_changed = False
            for cond, body in node.condition_and_nodes:
                tags = getattr(cond, "tags", None)
                ins_addr = None if tags is None else tags.get("ins_addr")
                block_addr = None if tags is None else tags.get("vex_block_addr")
                new_cond = cond
                if (
                    isinstance(ins_addr, int)
                    and isinstance(block_addr, int)
                    and _c_expr_uses_register_8616(cond, flags_offset)
                ):
                    decoded = _translate_cmp_jcc_guard_8616(project, codegen, block_addr, ins_addr)
                    if decoded is not None:
                        new_cond = CBinaryOp(
                            decoded.op,
                            decoded.lhs,
                            decoded.rhs,
                            codegen=codegen,
                            tags=getattr(cond, "tags", None),
                        )
                pair_changed = pair_changed or (new_cond is not cond)
                new_pairs.append((new_cond, body))
                visit(body)
            if pair_changed:
                node.condition_and_nodes = new_pairs
                changed = True
            return

        for attr in ("lhs", "rhs", "operand", "condition", "cond", "body", "iftrue", "iffalse", "else_node", "expr"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)
        for attr in ("statements", "args", "operands"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    visit(item)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            visit(subitem)

    visit(codegen.cfunc.statements)
    return changed
