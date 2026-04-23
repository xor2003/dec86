from __future__ import annotations

from dataclasses import dataclass

from .analysis_helpers import collect_neighbor_call_targets
from .callee_name_normalization import normalize_callee_name_8616

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
    stack_probe_helper: bool = False
    helper_return_state: str = "none"
    helper_return_space: str | None = None


def _is_stack_probe_target_name_8616(name: str | None) -> bool:
    if not isinstance(name, str):
        return False
    normalized = normalize_callee_name_8616(name)
    if not isinstance(normalized, str):
        return False
    return normalized.lower() in {
        "anchkstk",
        "chkstk",
        "_chkstk",
        "__chkstk",
        "__aNchkstk".lower(),
    }


def _lookup_target_name_8616(function, target_addr: int | None) -> str | None:
    if not isinstance(target_addr, int):
        return None
    project = getattr(function, "project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    lookup_addrs = [target_addr]
    if isinstance(original_delta, int):
        lookup_addrs.append(target_addr + original_delta)
        rebased = target_addr - original_delta
        if rebased >= 0:
            lookup_addrs.append(rebased)
    deduped_addrs: list[int] = []
    for addr in lookup_addrs:
        if addr not in deduped_addrs:
            deduped_addrs.append(addr)

    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        kb_functions = getattr(getattr(candidate_project, "kb", None), "functions", None)
        lookup = getattr(kb_functions, "function", None)
        for candidate_addr in deduped_addrs:
            if callable(lookup):
                try:
                    callee = lookup(addr=candidate_addr, create=False)
                except Exception:
                    callee = None
                name = getattr(callee, "name", None)
                if isinstance(name, str) and name:
                    return name
            for labels in (
                getattr(getattr(candidate_project, "kb", None), "labels", None),
                getattr(getattr(candidate_project, "_inertia_lst_metadata", None), "code_labels", None),
            ):
                if labels is None:
                    continue
                try:
                    label = labels.get(candidate_addr)
                except Exception:
                    label = None
                if isinstance(label, str) and label:
                    return label
    return None


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


def _block_insns_for_callsite(function, callsite_addr: int) -> tuple:
    project = getattr(function, "project", None)
    if project is None:
        return ()

    candidate_addrs = [callsite_addr]
    for block_addr in tuple(sorted(getattr(function, "block_addrs_set", ()) or ())):
        if block_addr == callsite_addr:
            continue
        if block_addr > callsite_addr:
            break
        candidate_addrs.append(block_addr)

    for block_addr in reversed(candidate_addrs):
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if _find_call_index(insns, callsite_addr) is not None:
            return insns
    return ()


def _next_linear_block_insns(function, callsite_addr: int) -> tuple:
    project = getattr(function, "project", None)
    if project is None:
        return ()
    candidate_addrs = sorted(addr for addr in (getattr(function, "block_addrs_set", ()) or ()) if addr > callsite_addr)
    for block_addr in candidate_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if insns:
            return insns
    return ()


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


def _trim_push_args_to_stack_cleanup(arg_widths: tuple[int, ...], cleanup: int | None) -> tuple[int, ...]:
    if not isinstance(cleanup, int) or cleanup <= 0 or not arg_widths:
        return arg_widths
    total = 0
    kept: list[int] = []
    for width in reversed(arg_widths):
        if total + width > cleanup:
            break
        kept.append(width)
        total += width
        if total == cleanup:
            return tuple(reversed(kept))
    return arg_widths


def _stack_cleanup_after_call(function, insns: tuple, idx: int, callsite_addr: int) -> int | None:
    follow_insns = insns[idx + 1 :] if idx + 1 < len(insns) else ()
    if not follow_insns:
        follow_insns = _next_linear_block_insns(function, callsite_addr)
    if not follow_insns:
        return None
    insn = follow_insns[0]
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


def _return_use_after_call(function, insns: tuple, idx: int, callsite_addr: int) -> tuple[str | None, bool | None]:
    follow_insns = list(insns[idx + 1 : idx + 3])
    if len(follow_insns) < 2:
        follow_insns.extend(_next_linear_block_insns(function, callsite_addr)[: 2 - len(follow_insns)])
    for insn in follow_insns[:2]:
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

    insns = _block_insns_for_callsite(function, callsite_addr)
    stack_probe_helper = _is_stack_probe_target_name_8616(_lookup_target_name_8616(function, target_addr))
    if not insns:
        helper_return_state = "stack_address" if stack_probe_helper else "none"
        helper_return_space = "ss" if stack_probe_helper else None
        return CallsiteSummary8616(
            callsite_addr,
            target_addr,
            return_addr,
            kind,
            None,
            (),
            None,
            None,
            None,
            stack_probe_helper,
            helper_return_state=helper_return_state,
            helper_return_space=helper_return_space,
        )
    call_idx = _find_call_index(insns, callsite_addr)
    if call_idx is None:
        helper_return_state = "stack_address" if stack_probe_helper else "none"
        helper_return_space = "ss" if stack_probe_helper else None
        return CallsiteSummary8616(
            callsite_addr,
            target_addr,
            return_addr,
            kind,
            None,
            (),
            None,
            None,
            None,
            stack_probe_helper,
            helper_return_state=helper_return_state,
            helper_return_space=helper_return_space,
        )

    cleanup = _stack_cleanup_after_call(function, insns, call_idx, callsite_addr)
    arg_widths = _trim_push_args_to_stack_cleanup(_collect_push_args_before_call(insns, call_idx), cleanup)
    arg_count = len(arg_widths)
    return_register, return_used = _return_use_after_call(function, insns, call_idx, callsite_addr)
    helper_return_state = "none"
    helper_return_space = None
    if stack_probe_helper:
        if return_register not in {None, "ax"}:
            helper_return_state = "unknown"
        else:
            helper_return_state = "stack_address"
            helper_return_space = "ss"
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
        stack_probe_helper=stack_probe_helper,
        helper_return_state=helper_return_state,
        helper_return_space=helper_return_space,
    )
