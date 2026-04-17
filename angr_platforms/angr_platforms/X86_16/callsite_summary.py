from __future__ import annotations

from dataclasses import dataclass

from .analysis_helpers import collect_neighbor_call_targets

__all__ = ["CallsiteSummary8616", "summarize_x86_16_callsite"]


@dataclass(frozen=True, slots=True)
class CallsiteSummary8616:
    callsite_addr: int
    target_addr: int | None
    return_addr: int | None
    kind: str | None
    arg_count: int | None
    arg_widths: tuple[int, ...]
    stack_cleanup: int | None
    return_register: str | None
    return_used: bool | None


def _mnemonic(insn) -> str:
    return str(getattr(insn, "mnemonic", "") or "").strip().lower()


def _capstone_insn(insn):
    return getattr(insn, "insn", insn)


def _operand_reg_name(insn, operand) -> str | None:
    reg = getattr(operand, "reg", None)
    if not isinstance(reg, int):
        return None
    capstone_insn = _capstone_insn(insn)
    reg_name = getattr(capstone_insn, "reg_name", None)
    if callable(reg_name):
        try:
            value = reg_name(reg)
        except Exception:
            value = None
        if isinstance(value, str) and value:
            return value.lower()
    return None


def _operand_imm_value(operand) -> int | None:
    imm = getattr(operand, "imm", None)
    return imm if isinstance(imm, int) else None


def _operand_is_reg(insn, operand, names: set[str]) -> bool:
    reg_name = _operand_reg_name(insn, operand)
    return reg_name in names if reg_name is not None else False


def _instruction_operands(insn) -> tuple:
    return tuple(getattr(_capstone_insn(insn), "operands", ()) or ())


def _find_call_index(insns: tuple, callsite_addr: int) -> int | None:
    for idx, insn in enumerate(insns):
        if getattr(insn, "address", None) == callsite_addr:
            return idx
    return None


def _push_arg_width(insn) -> int:
    operands = _instruction_operands(insn)
    if operands:
        size = getattr(operands[0], "size", None)
        if isinstance(size, int) and size > 0:
            return size
    return 2


def _collect_push_args_before_call(insns: tuple, idx: int) -> tuple[int, ...]:
    widths: list[int] = []
    scan = idx - 1
    while scan >= 0:
        insn = insns[scan]
        if not _mnemonic(insn).startswith("push"):
            break
        widths.append(_push_arg_width(insn))
        scan -= 1
    widths.reverse()
    return tuple(widths)


def _stack_cleanup_after_call(insns: tuple, idx: int) -> int | None:
    if idx + 1 >= len(insns):
        return None
    insn = insns[idx + 1]
    if _mnemonic(insn) != "add":
        return None
    operands = _instruction_operands(insn)
    if len(operands) != 2:
        return None
    if not _operand_is_reg(insn, operands[0], {"sp", "esp"}):
        return None
    return _operand_imm_value(operands[1])


def _instruction_reads_return_reg(insn, reg_names: set[str]) -> bool:
    operands = _instruction_operands(insn)
    if not operands:
        return False
    for operand in operands:
        if _operand_is_reg(insn, operand, reg_names):
            return True
    return False


def _return_use_after_call(insns: tuple, idx: int) -> tuple[str | None, bool | None]:
    for insn in insns[idx + 1 : idx + 3]:
        if _instruction_reads_return_reg(insn, {"ax", "al", "ah"}):
            return "ax", True
    return None, False


def summarize_x86_16_callsite(function, callsite_addr: int) -> CallsiteSummary8616 | None:
    project = getattr(function, "project", None)
    if project is None or getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return None

    target_addr = None
    return_addr = None
    kind = None
    for seed in collect_neighbor_call_targets(function):
        if seed.callsite_addr != callsite_addr:
            continue
        target_addr = seed.target_addr
        return_addr = seed.return_addr
        kind = seed.kind
        break

    try:
        block = project.factory.block(callsite_addr, opt_level=0)
    except Exception:
        return CallsiteSummary8616(callsite_addr, target_addr, return_addr, kind, None, (), None, None, None)

    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    call_idx = _find_call_index(insns, callsite_addr)
    if call_idx is None:
        return CallsiteSummary8616(callsite_addr, target_addr, return_addr, kind, None, (), None, None, None)

    arg_widths = _collect_push_args_before_call(insns, call_idx)
    arg_count = len(arg_widths)
    cleanup = _stack_cleanup_after_call(insns, call_idx)
    return_register, return_used = _return_use_after_call(insns, call_idx)
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=return_addr,
        kind=kind,
        arg_count=arg_count,
        arg_widths=arg_widths,
        stack_cleanup=cleanup,
        return_register=return_register,
        return_used=return_used,
    )
