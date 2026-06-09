from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from types import SimpleNamespace

from capstone.x86_const import X86_OP_IMM, X86_OP_MEM

from .analysis_helpers import collect_neighbor_call_targets, resolve_direct_call_target_from_block
from .callee_name_normalization import normalize_callee_name_8616
from .compiler_helpers import identify_x86_16_compiler_helper_at_8616, is_x86_16_stack_probe_name_8616

__all__ = ["CallsiteSummary8616", "summarize_x86_16_callsite"]

log = logging.getLogger(__name__)


class CallsiteReturnShape8616(Enum):
    AX = "ax"
    DX_AX = "dx_ax"


class CallsitePushSourceKind8616(Enum):
    BP_VALUE = "bp"
    BP_ADDRESS = "bp_addr"
    BP_INDEX_ADDRESS = "bp_index_addr"
    GLOBAL_VALUE = "global"
    GLOBAL_INDEX_VALUE = "global_index"
    IMMEDIATE = "imm"
    EXPR = "expr"
    RETURN_REGISTER = "ret_reg"
    SEGMENT = "seg"


class CallsitePushExprOp8616(Enum):
    ADD = "add"
    ADC = "adc"
    SUB = "sub"
    SBB = "sbb"
    SHL = "shl"
    SHR = "shr"
    MUL = "mul"


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
    helper_return_width: int | None = None
    helper_return_address_kind: str = "none"
    return_shape: str | None = None
    push_arg_sources: tuple[tuple | None, ...] = field(default=(), compare=False)
    return_store_destination: tuple[str, int] | None = None
    target_source: tuple | None = None

    def brief(self) -> str:
        return (
            f"callsite={self.callsite_addr:#x} "
            f"target={None if self.target_addr is None else hex(self.target_addr)} "
            f"args={self.arg_count} "
            f"return_shape={self.return_shape} "
            f"helper_return={self.helper_return_state} "
            f"helper_space={self.helper_return_space} "
            f"helper_width={self.helper_return_width} "
            f"helper_addr_kind={self.helper_return_address_kind}"
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _is_stack_probe_target_name_8616(name: str | None) -> bool:
    return is_x86_16_stack_probe_name_8616(name)


def _lookup_target_name_8616(function, target_addr: int | None) -> str | None:
    def _impl():
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
                evidence = identify_x86_16_compiler_helper_at_8616(candidate_project, candidate_addr)
                generic_name: str | None = None
                if callable(lookup):
                    try:
                        callee = lookup(addr=candidate_addr, create=False)
                    except Exception as ex:
                        log.debug(
                            "callsite target lookup failed project=%r addr=%#x: %s",
                            candidate_project,
                            candidate_addr,
                            ex,
                        )
                        callee = None
                    name = getattr(callee, "name", None)
                    if isinstance(name, str) and name:
                        normalized = normalize_callee_name_8616(name)
                        if evidence is not None and (
                            not isinstance(normalized, str)
                            or normalized.startswith("sub_")
                            or normalized.startswith("loc_")
                        ):
                            return evidence.name
                        if _is_stack_probe_target_name_8616(name):
                            return name
                        generic_name = name
                for labels in (
                    getattr(getattr(candidate_project, "kb", None), "labels", None),
                    getattr(getattr(candidate_project, "_inertia_lst_metadata", None), "code_labels", None),
                ):
                    if labels is None:
                        continue
                    try:
                        label = labels.get(candidate_addr)
                    except Exception as ex:
                        log.debug(
                            "callsite label lookup failed project=%r addr=%#x: %s",
                            candidate_project,
                            candidate_addr,
                            ex,
                        )
                        label = None
                    if isinstance(label, str) and label:
                        if evidence is not None:
                            normalized = normalize_callee_name_8616(label)
                            if (
                                not isinstance(normalized, str)
                                or normalized.startswith("sub_")
                                or normalized.startswith("loc_")
                            ):
                                return evidence.name
                        return label
                if evidence is not None:
                    return evidence.name
                if generic_name is not None:
                    return generic_name
        return None

    return _impl()


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
        except Exception as ex:
            log.debug("capstone reg_name lookup failed reg=%r: %s", reg, ex)
            value = None
        if isinstance(value, str) and value:
            return value.lower()
    return None


def _operand_imm_value(operand) -> int | None:
    operand_type = getattr(operand, "type", None)
    if isinstance(operand_type, int) and operand_type != X86_OP_IMM:
        return None
    imm = getattr(operand, "imm", None)
    return imm if isinstance(imm, int) else None


def _operand_mem_value_8616(operand):
    if getattr(operand, "type", None) != X86_OP_MEM:
        return None
    return getattr(operand, "mem", None)


def _operand_is_reg(insn, operand, names: set[str]) -> bool:
    reg_name = _operand_reg_name(insn, operand)
    return reg_name in names if reg_name is not None else False


def _instruction_operands(insn) -> tuple:
    return tuple(getattr(_capstone_insn(insn), "operands", ()) or ())


def _find_call_index(insns: tuple, callsite_addr: int) -> int | None:
    for idx, insn in enumerate(insns):
        insn_addr = getattr(insn, "address", None)
        if insn_addr == callsite_addr and _mnemonic(insn).startswith("call"):
            return idx
        insn_size = getattr(insn, "size", None)
        if (
            isinstance(insn_addr, int)
            and isinstance(insn_size, int)
            and insn_size > 0
            and insn_addr < callsite_addr < insn_addr + insn_size
            and _mnemonic(insn).startswith("call")
        ):
            return idx
    return None


def _block_insns_for_callsite(function, callsite_addr: int) -> tuple:
    def _impl():
        project = getattr(function, "project", None)
        if project is None:
            return ()

        debug = bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"))

        def _debug_insns(label: str, insns: tuple) -> None:
            if not debug:
                return
            rendered = ", ".join(
                f"{getattr(insn, 'address', None):#x}:{getattr(insn, 'mnemonic', '')} {getattr(insn, 'op_str', '')}"
                for insn in insns[:12]
            )
            log.warning("[callsite-window] callsite=%#x %s count=%d %s", callsite_addr, label, len(insns), rendered)

        def _decode_linear_window(start_addr: int) -> tuple:
            if not isinstance(start_addr, int) or start_addr > callsite_addr:
                return ()
            size = max(callsite_addr - start_addr + 16, 16)
            try:
                block = project.factory.block(
                    start_addr,
                    size=size,
                    num_inst=max(callsite_addr - start_addr + 8, 8),
                    strict_block_end=False,
                    opt_level=0,
                )
            except Exception as ex:
                log.debug("callsite linear-window decode failed start=%#x callsite=%#x: %s", start_addr, callsite_addr, ex)
                block = None
            insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()) if block is not None else ()
            _debug_insns(f"factory-window start={start_addr:#x}", insns)
            if _find_call_index(insns, callsite_addr) is not None:
                return insns
            capstone_engine = getattr(getattr(project, "arch", None), "capstone", None)
            memory = getattr(getattr(project, "loader", None), "memory", None)
            if capstone_engine is None or memory is None:
                return insns
            try:
                data = bytes(memory.load(start_addr, size))
                capstone_insns = tuple(capstone_engine.disasm(data, start_addr))
                _debug_insns(f"capstone-window start={start_addr:#x}", capstone_insns)
                return capstone_insns
            except Exception as ex:
                log.debug(
                    "callsite capstone-window decode failed start=%#x callsite=%#x: %s", start_addr, callsite_addr, ex
                )
                return insns

        candidate_addrs = [callsite_addr]
        func_addr = getattr(function, "addr", None)
        if isinstance(func_addr, int) and func_addr <= callsite_addr:
            candidate_addrs.append(func_addr)
        for block_addr in tuple(sorted(getattr(function, "block_addrs_set", ()) or ())):
            if block_addr == callsite_addr:
                continue
            if block_addr > callsite_addr:
                break
            candidate_addrs.append(block_addr)

        for block_addr in reversed(candidate_addrs):
            try:
                block = project.factory.block(block_addr, opt_level=0)
            except Exception as ex:
                log.debug("callsite block decode failed block=%#x: %s", block_addr, ex)
                continue
            insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
            _debug_insns(f"factory-block start={block_addr:#x}", insns)
            call_idx = _find_call_index(insns, callsite_addr)
            if call_idx is not None and call_idx > 0:
                return insns
            if call_idx is not None:
                for start_addr in reversed(candidate_addrs):
                    window_insns = _decode_linear_window(start_addr)
                    window_idx = _find_call_index(window_insns, callsite_addr)
                    if window_idx is not None and window_idx > 0:
                        return window_insns
                return insns
        return ()

    return _impl()


def _next_linear_block_insns(function, callsite_addr: int) -> tuple:
    project = getattr(function, "project", None)
    if project is None:
        return ()
    candidate_addrs = sorted(addr for addr in (getattr(function, "block_addrs_set", ()) or ()) if addr > callsite_addr)
    for block_addr in candidate_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception as ex:
            log.debug("callsite next block decode failed block=%#x: %s", block_addr, ex)
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


def _direct_call_target_for_insn_8616(function, insn) -> int | None:
    project = getattr(function, "project", None)
    callsite_addr = getattr(insn, "address", None)
    if project is None or not isinstance(callsite_addr, int):
        return None
    try:
        return resolve_direct_call_target_from_block(project, callsite_addr)
    except Exception:
        return None


def _callee_stack_cleanup_bytes_8616(function, insn) -> int | None:
    project = getattr(function, "project", None)
    target = _direct_call_target_for_insn_8616(function, insn)
    if project is None or not isinstance(target, int):
        return None
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    candidate_addrs = [target]
    if isinstance(original_delta, int):
        candidate_addrs.append(target + original_delta)
        if target >= original_delta:
            candidate_addrs.append(target - original_delta)
    deduped_addrs: list[int] = []
    for addr in candidate_addrs:
        if isinstance(addr, int) and addr >= 0 and addr not in deduped_addrs:
            deduped_addrs.append(addr)
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        if candidate_project is None:
            continue
        for candidate_addr in deduped_addrs:
            try:
                block = candidate_project.factory.block(candidate_addr, size=256, strict_block_end=False, opt_level=0)
                callee_insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
            except Exception as ex:
                log.debug("callee cleanup decode failed target=%#x: %s", candidate_addr, ex)
                continue
            for callee_insn in callee_insns:
                if not _mnemonic(callee_insn).startswith("ret"):
                    continue
                operands = _instruction_operands(callee_insn)
                if not operands:
                    return 0
                cleanup = _operand_imm_value(operands[0])
                if isinstance(cleanup, int) and 0 <= cleanup <= 128 and cleanup % 2 == 0:
                    return cleanup
                return None
    return None


def _is_segment_register_push_8616(insn) -> bool:
    if not _mnemonic(insn).startswith("push"):
        return False
    operands = _instruction_operands(insn)
    return len(operands) == 1 and _operand_reg_name(insn, operands[0]) in {"cs", "ds", "es", "ss"}


def _transparent_between_push_args_8616(insn) -> bool:
    mnemonic = _mnemonic(insn)
    if mnemonic in {"cbw", "cwd", "cwde", "nop"}:
        return True
    if mnemonic in {"mul", "imul"}:
        operands = _instruction_operands(insn)
        if len(operands) == 1:
            return True
        if len(operands) in {2, 3}:
            dest_name = _operand_reg_name(insn, operands[0])
            return dest_name not in {"sp", "bp", "ss", "ds", "es", "cs"} if dest_name is not None else False
        return False
    if mnemonic in {"mov", "lea"}:
        operands = _instruction_operands(insn)
        if len(operands) != 2:
            return False
        return _operand_reg_name(insn, operands[0]) not in {"sp", "bp", "ss", "ds", "es", "cs"}

    if mnemonic not in {"adc", "add", "sbb", "sub", "shl", "shr", "and", "or", "xor", "inc", "dec"}:
        return False
    operands = _instruction_operands(insn)
    if mnemonic in {"inc", "dec"}:
        if len(operands) != 1:
            return False
        dest_name = _operand_reg_name(insn, operands[0])
        return dest_name not in {"sp", "bp", "ss", "ds", "es", "cs"} if dest_name is not None else False

    if len(operands) != 2:
        return False
    dest_name = _operand_reg_name(insn, operands[0])
    if dest_name in {"sp", "bp", "ss", "ds", "es", "cs"}:
        return False
    return dest_name is not None


def _rewind_callee_clean_nested_call_args_8616(function, insns: tuple, call_idx: int) -> int | None:
    cleanup = _callee_stack_cleanup_bytes_8616(function, insns[call_idx])
    if not isinstance(cleanup, int) or cleanup <= 0:
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-window] nested-call rewind refused callsite=%#x cleanup=%r",
                getattr(insns[call_idx], "address", -1),
                cleanup,
            )
        return None
    scan = call_idx - 1
    skipped_transparents = 0
    total = 0
    while scan >= 0:
        insn = insns[scan]
        if _mnemonic(insn).startswith("push") and not _is_segment_register_push_8616(insn):
            total += _push_arg_width(insn)
            scan -= 1
            skipped_transparents = 0
            if total == cleanup:
                if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
                    log.warning(
                        "[callsite-window] nested-call rewind accepted callsite=%#x cleanup=%d rewound_to=%d",
                        getattr(insns[call_idx], "address", -1),
                        cleanup,
                        scan,
                    )
                return scan
            if total > cleanup:
                if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
                    log.warning(
                        "[callsite-window] nested-call rewind refused callsite=%#x reason=overshoot cleanup=%d total=%d",
                        getattr(insns[call_idx], "address", -1),
                        cleanup,
                        total,
                    )
                return None
            continue
        if skipped_transparents < 12 and _transparent_between_push_args_8616(insn):
            skipped_transparents += 1
            scan -= 1
            continue
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-window] nested-call rewind refused callsite=%#x reason=barrier cleanup=%d total=%d",
                getattr(insns[call_idx], "address", -1),
                cleanup,
                total,
            )
        return None
    return None


def _linear_window_insns_for_callsite_8616(function, callsite_addr: int) -> tuple:
    project = getattr(function, "project", None)
    if project is None:
        return ()
    start = getattr(function, "addr", None)
    block_addrs = tuple(sorted(getattr(function, "block_addrs_set", ()) or ()))
    if not isinstance(start, int) or start > callsite_addr:
        starts = [addr for addr in block_addrs if isinstance(addr, int) and addr <= callsite_addr]
        start = starts[0] if starts else None
    if not isinstance(start, int) or start > callsite_addr:
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-window] callsite=%#x cleanup-linear refused start=%r blocks=%r",
                callsite_addr,
                start,
                tuple(hex(addr) for addr in block_addrs[:12]),
            )
        return ()
    size = max(callsite_addr - start + 16, 16)
    try:
        block = project.factory.block(
            start,
            size=size,
            num_inst=max(callsite_addr - start + 8, 8),
            strict_block_end=False,
            opt_level=0,
        )
    except Exception as ex:
        log.debug("callsite cleanup linear-window decode failed start=%#x callsite=%#x: %s", start, callsite_addr, ex)
        return ()
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    call_idx = _find_call_index(insns, callsite_addr)
    if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
        log.warning(
            "[callsite-window] callsite=%#x cleanup-linear start=%#x count=%d call_idx=%r",
            callsite_addr,
            start,
            len(insns),
            call_idx,
        )
    if call_idx is None:
        return ()
    return insns


def _collect_push_args_before_call(
    function,
    insns: tuple,
    idx: int,
    cleanup: int | None = None,
) -> tuple[int, ...]:
    def _impl():
        widths: list[int] = []
        scan = idx - 1
        skipped_transparents = 0
        skipped_call_segment = False
        target_total = cleanup if isinstance(cleanup, int) and cleanup > 0 else None
        while scan >= 0:
            insn = insns[scan]
            if _mnemonic(insn).startswith("push"):
                if not widths and _is_segment_register_push_8616(insn):
                    skipped_call_segment = True
                    scan -= 1
                    continue
                widths.append(_push_arg_width(insn))
                scan -= 1
                if target_total is not None and sum(widths) >= target_total:
                    break
                continue
            if not widths and skipped_call_segment and _transparent_between_push_args_8616(insn):
                scan -= 1
                continue
            if widths and skipped_transparents < 8 and _transparent_between_push_args_8616(insn):
                skipped_transparents += 1
                scan -= 1
                continue
            if (
                widths
                and target_total is not None
                and sum(widths) < target_total
                and _mnemonic(insn).startswith("call")
            ):
                rewound = _rewind_callee_clean_nested_call_args_8616(function, insns, scan)
                if rewound is not None and rewound < scan:
                    scan = rewound
                    skipped_transparents = 0
                    continue
            break
        widths.reverse()
        return tuple(widths)

    return _impl()


def _push_arg_source(insn) -> tuple | None:
    operands = _instruction_operands(insn)
    if len(operands) != 1:
        return None
    operand = operands[0]
    reg_name = _operand_reg_name(insn, operand)
    if reg_name in {"cs", "ds", "es", "ss"}:
        return (CallsitePushSourceKind8616.SEGMENT.value, reg_name)
    mem = _operand_mem_value_8616(operand)
    if mem is not None:
        base = getattr(mem, "base", None)
        disp = getattr(mem, "disp", None)
        if isinstance(base, int) and isinstance(disp, int):
            base_name = _operand_reg_name(insn, type("_PushMemOperand", (), {"reg": base})())
            index = int(getattr(mem, "index", 0) or 0)
            if base_name == "bp" and int(getattr(mem, "index", 0) or 0) == 0:
                return (CallsitePushSourceKind8616.BP_VALUE.value, int(disp))
            if not base_name and index == 0:
                width = getattr(operand, "size", None)
                return (
                    CallsitePushSourceKind8616.GLOBAL_VALUE.value,
                    int(disp),
                    int(width) if isinstance(width, int) and width > 0 else 2,
                )
    imm = _operand_imm_value(operand)
    if isinstance(imm, int):
        return (CallsitePushSourceKind8616.IMMEDIATE.value, imm)
    return None


def _call_target_source_8616(insn) -> tuple | None:
    operands = _instruction_operands(insn)
    if len(operands) != 1:
        return None
    operand = operands[0]
    mem = _operand_mem_value_8616(operand)
    if mem is not None:
        base = getattr(mem, "base", None)
        disp = getattr(mem, "disp", None)
        if isinstance(base, int) and isinstance(disp, int):
            base_name = _operand_reg_name(insn, type("_CallMemOperand", (), {"reg": base})())
            if base_name == "bp" and int(getattr(mem, "index", 0) or 0) == 0:
                return ("bp", int(disp))
    reg_name = _operand_reg_name(insn, operand)
    if isinstance(reg_name, str) and reg_name:
        return ("reg", reg_name)
    imm = _operand_imm_value(operand)
    if isinstance(imm, int):
        return ("imm", imm)
    return None


def _source_from_bp_mem_operand_8616(insn, operand, *, address: bool) -> tuple | None:
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None
    base = getattr(mem, "base", None)
    disp = getattr(mem, "disp", None)
    if isinstance(base, int) and isinstance(disp, int):
        base_name = _operand_reg_name(insn, type("_SourceMemOperand", (), {"reg": base})())
        index = int(getattr(mem, "index", 0) or 0)
        if base_name == "bp" and index == 0:
            kind = (
                CallsitePushSourceKind8616.BP_ADDRESS
                if address
                else CallsitePushSourceKind8616.BP_VALUE
            )
            return (kind.value, int(disp))
        if base_name == "bp" and address and index != 0:
            index_name = _operand_reg_name(insn, type("_SourceMemOperand", (), {"reg": index})())
            scale = int(getattr(mem, "scale", 1) or 1)
            if isinstance(index_name, str) and index_name not in {"sp", "bp", "ss", "ds", "es", "cs"}:
                return (CallsitePushSourceKind8616.BP_INDEX_ADDRESS.value, int(disp), index_name, scale)
    return None


def _source_from_mov_operand(insn, operand) -> tuple | None:
    imm = _operand_imm_value(operand)
    if isinstance(imm, int):
        return (CallsitePushSourceKind8616.IMMEDIATE.value, imm)
    bp_source = _source_from_bp_mem_operand_8616(insn, operand, address=False)
    if bp_source is not None:
        return bp_source
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None
    base = getattr(mem, "base", None)
    disp = getattr(mem, "disp", None)
    index = int(getattr(mem, "index", 0) or 0)
    if isinstance(base, int) and isinstance(disp, int):
        base_name = _operand_reg_name(insn, type("_SourceGlobalMemOperand", (), {"reg": base})())
        if not base_name and index == 0:
            width = getattr(operand, "size", None)
            return (
                CallsitePushSourceKind8616.GLOBAL_VALUE.value,
                int(disp),
                int(width) if isinstance(width, int) and width > 0 else 2,
            )
    return None


def _ax_immediate_before_one_operand_mul_8616(insns: tuple, mul_idx: int) -> int | None:
    scan = mul_idx - 1
    skipped = 0
    while scan >= 0 and skipped < 4:
        insn = insns[scan]
        mnemonic = _mnemonic(insn)
        operands = _instruction_operands(insn)
        if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) == "ax":
            value = _operand_imm_value(operands[1])
            return int(value) if isinstance(value, int) else None
        if mnemonic in {"cwd", "nop"}:
            skipped += 1
            scan -= 1
            continue
        return None
    return None


def _source_from_lea_operand_8616(insn, operand) -> tuple | None:
    return _source_from_bp_mem_operand_8616(insn, operand, address=True)


def _indexed_global_source_from_mov_operand_8616(insns: tuple, mov_idx: int, insn, operand) -> tuple | None:
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None
    base = getattr(mem, "base", None)
    disp = getattr(mem, "disp", None)
    index = int(getattr(mem, "index", 0) or 0)
    if not (isinstance(base, int) and isinstance(disp, int) and index == 0):
        return None
    base_name = _operand_reg_name(insn, type("_IndexedGlobalMemOperand", (), {"reg": base})())
    if not isinstance(base_name, str) or not base_name or base_name in {"sp", "bp", "ss", "ds", "es", "cs"}:
        return None

    scan = mov_idx - 1
    skipped = 0
    ops: list[tuple[str, int]] = []
    while scan >= 0 and skipped < 8:
        prev = insns[scan]
        mnemonic = _mnemonic(prev)
        operands = _instruction_operands(prev)
        if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(prev, operands[0]) == base_name:
            base_source = _source_from_mov_operand(prev, operands[1])
            if base_source is None:
                return None
            width = getattr(operand, "size", None)
            return (
                CallsitePushSourceKind8616.GLOBAL_INDEX_VALUE.value,
                int(disp),
                int(width) if isinstance(width, int) and width > 0 else 2,
                base_source,
                tuple(reversed(ops)),
            )
        if (
            mnemonic in {"add", "sub", "shl", "shr"}
            and len(operands) == 2
            and _operand_reg_name(prev, operands[0]) == base_name
        ):
            value = _operand_imm_value(operands[1])
            if not isinstance(value, int):
                return None
            op = {
                "add": CallsitePushExprOp8616.ADD,
                "sub": CallsitePushExprOp8616.SUB,
                "shl": CallsitePushExprOp8616.SHL,
                "shr": CallsitePushExprOp8616.SHR,
            }[mnemonic]
            ops.append((op.value, value))
            scan -= 1
            skipped += 1
            continue
        if _mnemonic(prev).startswith(("call", "push", "pop", "ret", "jmp")):
            return None
        if not _transparent_between_push_args_8616(prev):
            return None
        skipped += 1
        scan -= 1
    return None


def _register_source_from_context_8616(insns: tuple, idx: int, reg_name: str, *, depth: int = 0) -> tuple | None:
    if depth > 4 or reg_name in {"sp", "bp", "ss", "ds", "es", "cs"}:
        return None
    scan = idx - 1
    skipped = 0
    ops: list[tuple[str, int]] = []
    source_regs = {reg_name}
    while scan >= 0 and skipped < 8:
        insn = insns[scan]
        operands = _instruction_operands(insn)
        mnemonic = _mnemonic(insn)
        if reg_name == "ax" and mnemonic in {"cbw", "cwde"}:
            source_regs.add("al")
            scan -= 1
            skipped += 1
            continue
        if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) in source_regs:
            rhs_reg = _operand_reg_name(insn, operands[1])
            if isinstance(rhs_reg, str) and rhs_reg and rhs_reg not in source_regs:
                base_source = _register_source_from_context_8616(insns, scan, rhs_reg, depth=depth + 1)
            else:
                base_source = _source_from_mov_operand(insn, operands[1])
                if base_source is None:
                    base_source = _indexed_global_source_from_mov_operand_8616(insns, scan, insn, operands[1])
            if base_source is None:
                return None
            if not ops:
                return base_source
            return (CallsitePushSourceKind8616.EXPR.value, base_source, tuple(reversed(ops)))
        if (
            mnemonic in {"add", "sub", "shl", "shr"}
            and len(operands) == 2
            and _operand_reg_name(insn, operands[0]) == reg_name
        ):
            value = _operand_imm_value(operands[1])
            if not isinstance(value, int):
                return None
            op = {
                "add": CallsitePushExprOp8616.ADD,
                "sub": CallsitePushExprOp8616.SUB,
                "shl": CallsitePushExprOp8616.SHL,
                "shr": CallsitePushExprOp8616.SHR,
            }[mnemonic]
            ops.append((op.value, value))
            scan -= 1
            skipped += 1
            continue
        if _mnemonic(insn).startswith(("call", "push", "pop", "ret", "jmp")):
            return None
        if not _transparent_between_push_args_8616(insn):
            return None
        skipped += 1
        scan -= 1
    return None


def _return_register_push_source_from_context_8616(function, insns: tuple, idx: int, pushed_reg: str) -> tuple | None:
    if pushed_reg not in {"ax", "dx"}:
        return None
    call_idx = idx - 1
    while call_idx >= 0:
        insn = insns[call_idx]
        if _mnemonic(insn).startswith("call"):
            break
        if not _mnemonic(insn).startswith("push"):
            return None
        operands = _instruction_operands(insn)
        if len(operands) != 1:
            return None
        sibling_reg = _operand_reg_name(insn, operands[0])
        if sibling_reg not in {"ax", "dx"}:
            return None
        call_idx -= 1
    if call_idx < 0 or not _mnemonic(insns[call_idx]).startswith("call"):
        return None

    observed_regs: set[str] = set()
    scan = call_idx + 1
    while scan < len(insns):
        insn = insns[scan]
        if not _mnemonic(insn).startswith("push"):
            break
        operands = _instruction_operands(insn)
        if len(operands) != 1:
            break
        reg_name = _operand_reg_name(insn, operands[0])
        if reg_name not in {"ax", "dx"}:
            break
        observed_regs.add(reg_name)
        if scan >= idx and {"ax", "dx"} <= observed_regs:
            break
        scan += 1

    callsite_addr = getattr(insns[call_idx], "address", None)
    if not isinstance(callsite_addr, int):
        return None
    return_shape = _return_shape_after_call(function, insns, call_idx, callsite_addr)
    if pushed_reg == "ax" and return_shape in {CallsiteReturnShape8616.AX, CallsiteReturnShape8616.DX_AX}:
        return (CallsitePushSourceKind8616.RETURN_REGISTER.value, callsite_addr, pushed_reg)
    if pushed_reg == "dx" and return_shape is CallsiteReturnShape8616.DX_AX:
        return (CallsitePushSourceKind8616.RETURN_REGISTER.value, callsite_addr, pushed_reg)
    if {"ax", "dx"} <= observed_regs and pushed_reg in observed_regs:
        return (CallsitePushSourceKind8616.RETURN_REGISTER.value, callsite_addr, pushed_reg)
    return None


def _push_arg_source_from_context(function, insns: tuple, idx: int) -> tuple | None:
    def _impl():
        source = _push_arg_source(insns[idx])
        if source is not None:
            return source
        operands = _instruction_operands(insns[idx])
        if len(operands) != 1:
            return None
        pushed_reg = _operand_reg_name(insns[idx], operands[0])
        if pushed_reg is None or pushed_reg in {"sp", "bp", "ss", "ds", "es", "cs"}:
            return None
        return_source = _return_register_push_source_from_context_8616(function, insns, idx, pushed_reg)
        if return_source is not None:
            return return_source
        scan = idx - 1
        skipped = 0
        ops: list[tuple[str, int]] = []
        source_regs = {pushed_reg}
        while scan >= 0 and skipped < 6:
            insn = insns[scan]
            operands = _instruction_operands(insn)
            mnemonic = _mnemonic(insn)
            if pushed_reg == "ax" and mnemonic in {"cbw", "cwde"}:
                source_regs.add("al")
                scan -= 1
                skipped += 1
                continue
            if mnemonic == "mov" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) in source_regs:
                base_source = _source_from_mov_operand(insn, operands[1])
                if base_source is None:
                    base_source = _indexed_global_source_from_mov_operand_8616(insns, scan, insn, operands[1])
                if base_source is None:
                    return None
                if not ops:
                    return base_source
                return (CallsitePushSourceKind8616.EXPR.value, base_source, tuple(reversed(ops)))
            if mnemonic == "lea" and len(operands) == 2 and _operand_reg_name(insn, operands[0]) == pushed_reg:
                base_source = _source_from_lea_operand_8616(insn, operands[1])
                if base_source is None:
                    return None
                if (
                    isinstance(base_source, tuple)
                    and len(base_source) >= 4
                    and base_source[0] == CallsitePushSourceKind8616.BP_INDEX_ADDRESS.value
                    and isinstance(base_source[2], str)
                ):
                    index_source = _register_source_from_context_8616(insns, scan, base_source[2])
                    if index_source is not None:
                        base_source = (*base_source, index_source)
                if not ops:
                    return base_source
                return (CallsitePushSourceKind8616.EXPR.value, base_source, tuple(reversed(ops)))
            if (
                mnemonic in {"adc", "add", "sbb", "sub", "shl", "shr"}
                and len(operands) == 2
                and _operand_reg_name(insn, operands[0]) == pushed_reg
            ):
                value = _operand_imm_value(operands[1])
                if not isinstance(value, int):
                    return None
                op = {
                    "adc": CallsitePushExprOp8616.ADC,
                    "add": CallsitePushExprOp8616.ADD,
                    "sbb": CallsitePushExprOp8616.SBB,
                    "sub": CallsitePushExprOp8616.SUB,
                    "shl": CallsitePushExprOp8616.SHL,
                    "shr": CallsitePushExprOp8616.SHR,
                }[mnemonic]
                ops.append((op.value, value))
                scan -= 1
                skipped += 1
                continue
            if mnemonic in {"inc", "dec"} and len(operands) == 1 and _operand_reg_name(insn, operands[0]) == pushed_reg:
                ops.append(
                    (
                        CallsitePushExprOp8616.ADD.value
                        if mnemonic == "inc"
                        else CallsitePushExprOp8616.SUB.value,
                        1,
                    )
                )
                scan -= 1
                skipped += 1
                continue
            if mnemonic in {"mul", "imul"}:
                if len(operands) == 1 and pushed_reg == "ax":
                    source = _source_from_mov_operand(insn, operands[0])
                    factor = _ax_immediate_before_one_operand_mul_8616(insns, scan)
                    if source is not None and isinstance(factor, int):
                        return (
                            CallsitePushSourceKind8616.EXPR.value,
                            source,
                            ((CallsitePushExprOp8616.MUL.value, factor), *tuple(reversed(ops))),
                        )
                    return None
                if pushed_reg in {"ax", "dx"}:
                    return None
                if len(operands) in {2, 3} and _operand_reg_name(insn, operands[0]) == pushed_reg:
                    return None
            if _mnemonic(insn).startswith("push"):
                operands = _instruction_operands(insn)
                sibling_reg = _operand_reg_name(insn, operands[0]) if len(operands) == 1 else None
                if _is_segment_register_push_8616(insn) or (
                    pushed_reg in {"ax", "dx"}
                    and sibling_reg in {"ax", "dx"}
                    and sibling_reg != pushed_reg
                ):
                    scan -= 1
                    skipped += 1
                    continue
                return None
            if _mnemonic(insn).startswith(("call", "pop", "ret", "jmp")):
                return None
            if not _transparent_between_push_args_8616(insn):
                return None
            skipped += 1
            scan -= 1
        return None

    return _impl()


def _collect_push_arg_sources_before_call(
    function,
    insns: tuple,
    idx: int,
    cleanup: int | None = None,
) -> tuple[tuple | None, ...]:
    def _impl():
        sources: list[tuple | None] = []
        scan = idx - 1
        skipped_transparents = 0
        skipped_call_segment = False
        total = 0
        target_total = cleanup if isinstance(cleanup, int) and cleanup > 0 else None
        while scan >= 0:
            insn = insns[scan]
            if _mnemonic(insn).startswith("push"):
                if not sources and _is_segment_register_push_8616(insn):
                    skipped_call_segment = True
                    scan -= 1
                    continue
                sources.append(_push_arg_source_from_context(function, insns, scan))
                total += _push_arg_width(insn)
                scan -= 1
                if target_total is not None and total >= target_total:
                    break
                continue
            if not sources and skipped_call_segment and _transparent_between_push_args_8616(insn):
                scan -= 1
                continue
            if sources and skipped_transparents < 8 and _transparent_between_push_args_8616(insn):
                skipped_transparents += 1
                scan -= 1
                continue
            if (
                sources
                and target_total is not None
                and total < target_total
                and _mnemonic(insn).startswith("call")
            ):
                rewound = _rewind_callee_clean_nested_call_args_8616(function, insns, scan)
                if rewound is not None and rewound < scan:
                    scan = rewound
                    skipped_transparents = 0
                    continue
            break
        sources.reverse()
        return tuple(sources)

    return _impl()


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


def _trim_push_arg_sources_to_stack_cleanup(
    arg_widths: tuple[int, ...],
    arg_sources: tuple[tuple | None, ...],
    cleanup: int | None,
) -> tuple[tuple | None, ...]:
    if not isinstance(cleanup, int) or cleanup <= 0 or not arg_widths or not arg_sources:
        return arg_sources
    if len(arg_widths) != len(arg_sources):
        return arg_sources
    total = 0
    kept: list[tuple | None] = []
    for width, source in reversed(tuple(zip(arg_widths, arg_sources))):
        if total + width > cleanup:
            break
        kept.append(source)
        total += width
        if total == cleanup:
            return tuple(reversed(kept))
    return arg_sources


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


def _instruction_writes_return_reg(insn, reg_names: set[str]) -> bool:
    operands = _instruction_operands(insn)
    if not operands:
        return False
    mnemonic = _mnemonic(insn)
    if mnemonic in {"cmp", "test"}:
        return False
    return _operand_is_reg(insn, operands[0], reg_names)


def _transparent_return_epilogue_insn_8616(insn) -> bool:
    mnemonic = _mnemonic(insn)
    operands = _instruction_operands(insn)
    if mnemonic == "add" and len(operands) == 2 and _operand_is_reg(insn, operands[0], {"sp", "esp"}):
        return True
    if mnemonic == "mov" and len(operands) == 2:
        return _operand_is_reg(insn, operands[0], {"sp", "esp"}) and _operand_is_reg(insn, operands[1], {"bp", "ebp"})
    if mnemonic == "pop" and len(operands) == 1:
        return True
    if mnemonic.startswith("j"):
        return True
    return False


def _direct_jump_target_8616(insn) -> int | None:
    mnemonic = _mnemonic(insn)
    if mnemonic not in {"jmp", "jmpw", "ljmp"}:
        return None
    operands = _instruction_operands(insn)
    if len(operands) != 1:
        return None
    return _operand_imm_value(operands[0])


def _extend_follow_insns_through_direct_jumps_8616(function, follow_insns: list, *, limit: int = 16) -> list:
    project = getattr(function, "project", None)
    if project is None:
        return follow_insns
    expanded = list(follow_insns)
    decoded_targets: set[int] = set()
    idx = 0
    while idx < len(expanded) and len(expanded) < limit:
        target = _direct_jump_target_8616(expanded[idx])
        idx += 1
        if not isinstance(target, int) or target in decoded_targets:
            continue
        decoded_targets.add(target)
        try:
            block = project.factory.block(target, opt_level=0)
        except Exception as ex:
            log.debug("return-use jump target decode failed target=%#x: %s", target, ex)
            continue
        target_insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        expanded.extend(target_insns[: max(0, limit - len(expanded))])
    return expanded


def _operand_mem_base_disp(insn, operand) -> tuple[str | None, int | None]:
    mem = _operand_mem_value_8616(operand)
    if mem is None:
        return None, None
    base = getattr(mem, "base", None)
    disp = getattr(mem, "disp", None)
    if not isinstance(base, int):
        return None, disp if isinstance(disp, int) else None
    capstone_insn = _capstone_insn(insn)
    reg_name = getattr(capstone_insn, "reg_name", None)
    if not callable(reg_name):
        return None, disp if isinstance(disp, int) else None
    try:
        name = reg_name(base)
    except Exception as ex:
        log.debug("capstone mem base lookup failed reg=%r: %s", base, ex)
        name = None
    return (name.lower() if isinstance(name, str) and name else None), disp if isinstance(disp, int) else None


def _return_store_after_call(function, insns: tuple, idx: int, callsite_addr: int) -> tuple[str, int] | None:
    follow_insns = list(insns[idx + 1 : idx + 4])
    if len(follow_insns) < 3:
        follow_insns.extend(_next_linear_block_insns(function, callsite_addr)[: 3 - len(follow_insns)])
    for insn in follow_insns[:3]:
        mnemonic = _mnemonic(insn)
        operands = _instruction_operands(insn)
        if mnemonic == "add" and len(operands) == 2 and _operand_is_reg(insn, operands[0], {"sp", "esp"}):
            continue
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if not _operand_is_reg(insn, operands[1], {"ax"}):
            continue
        base, disp = _operand_mem_base_disp(insn, operands[0])
        if base == "bp" and isinstance(disp, int):
            return "bp", disp
    return None


def _return_use_after_call(function, insns: tuple, idx: int, callsite_addr: int) -> tuple[str | None, bool | None]:
    follow_insns = list(insns[idx + 1 : idx + 8])
    if len(follow_insns) < 8:
        follow_insns.extend(_next_linear_block_insns(function, callsite_addr)[: 8 - len(follow_insns)])
    follow_insns = _extend_follow_insns_through_direct_jumps_8616(function, follow_insns, limit=16)
    for insn in follow_insns[:16]:
        if _instruction_reads_return_reg(insn, {"ax", "al", "ah"}):
            return "ax", True
        if _instruction_writes_return_reg(insn, {"ax", "al", "ah"}):
            return "ax", False
        if _mnemonic(insn) in {"ret", "retf", "retw", "iret"}:
            return "ax", True
        if _transparent_return_epilogue_insn_8616(insn):
            continue
        break
    return None, False


def _return_shape_after_call(function, insns: tuple, idx: int, callsite_addr: int) -> CallsiteReturnShape8616 | None:
    follow_insns = list(insns[idx + 1 : idx + 8])
    if len(follow_insns) < 8:
        follow_insns.extend(_next_linear_block_insns(function, callsite_addr)[: 8 - len(follow_insns)])
    follow_insns = _extend_follow_insns_through_direct_jumps_8616(function, follow_insns, limit=16)

    store_dx_offsets: set[int] = set()
    store_ax_offsets: set[int] = set()
    saw_ax = False
    saw_dx = False

    def _has_adjacent_word_pair_8616(ax_offsets: set[int], dx_offsets: set[int]) -> bool:
        for offset in dx_offsets:
            if (offset + 2 in ax_offsets) or (offset - 2 in ax_offsets):
                return True
        for offset in ax_offsets:
            if (offset + 2 in dx_offsets) or (offset - 2 in dx_offsets):
                return True
        return False

    for insn in follow_insns[:16]:
        if _mnemonic(insn) in {"ret", "retf", "retw", "iret"}:
            break

        if _mnemonic(insn) == "mov" and len(_instruction_operands(insn)) == 2:
            operands = _instruction_operands(insn)
            base, disp = _operand_mem_base_disp(insn, operands[0])
            if base == "bp" and isinstance(disp, int):
                if _operand_is_reg(insn, operands[1], {"dx", "dh", "dl"}):
                    store_dx_offsets.add(disp)
                    saw_dx = True
                if _operand_is_reg(insn, operands[1], {"ax", "al", "ah"}):
                    store_ax_offsets.add(disp)
                    saw_ax = True
            if _has_adjacent_word_pair_8616(store_ax_offsets, store_dx_offsets):
                return CallsiteReturnShape8616.DX_AX

        if _instruction_reads_return_reg(insn, {"ax", "al", "ah"}):
            saw_ax = True
        if _instruction_reads_return_reg(insn, {"dx", "dh", "dl"}):
            saw_dx = True
        if _instruction_writes_return_reg(insn, {"ax", "al", "ah"}):
            saw_ax = True
        if _instruction_writes_return_reg(insn, {"dx", "dh", "dl"}):
            saw_dx = True

        if _transparent_return_epilogue_insn_8616(insn):
            continue

    if any(off + 2 in store_ax_offsets for off in store_dx_offsets):
        return CallsiteReturnShape8616.DX_AX
    if any(off - 2 in store_ax_offsets for off in store_dx_offsets):
        return CallsiteReturnShape8616.DX_AX
    if saw_ax:
        return CallsiteReturnShape8616.AX
    return None


def summarize_x86_16_callsite(function: SimpleNamespace, callsite_addr: int) -> CallsiteSummary8616 | None:
    def _impl():
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
            helper_return_width = 2 if stack_probe_helper else None
            helper_return_address_kind = "stack" if stack_probe_helper else "none"
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
                helper_return_width=helper_return_width,
                helper_return_address_kind=helper_return_address_kind,
            )
        call_idx = _find_call_index(insns, callsite_addr)
        if call_idx is None:
            helper_return_state = "stack_address" if stack_probe_helper else "none"
            helper_return_space = "ss" if stack_probe_helper else None
            helper_return_width = 2 if stack_probe_helper else None
            helper_return_address_kind = "stack" if stack_probe_helper else "none"
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
                helper_return_width=helper_return_width,
                helper_return_address_kind=helper_return_address_kind,
            )

        if return_addr is None:
            call_insn = insns[call_idx]
            insn_addr = getattr(call_insn, "address", None)
            insn_size = getattr(call_insn, "size", None)
            if isinstance(insn_addr, int) and isinstance(insn_size, int) and insn_size > 0:
                return_addr = (insn_addr + insn_size) & 0xFFFF

        cleanup = _stack_cleanup_after_call(function, insns, call_idx, callsite_addr)
        target_source = _call_target_source_8616(insns[call_idx])
        raw_arg_widths = _collect_push_args_before_call(function, insns, call_idx, cleanup)
        raw_arg_sources = _collect_push_arg_sources_before_call(function, insns, call_idx, cleanup)
        if isinstance(cleanup, int) and cleanup > 0 and sum(raw_arg_widths) < cleanup:
            window_insns = _linear_window_insns_for_callsite_8616(function, callsite_addr)
            window_idx = _find_call_index(window_insns, callsite_addr) if window_insns else None
            if window_idx is not None:
                window_widths = _collect_push_args_before_call(function, window_insns, window_idx, cleanup)
                if sum(window_widths) > sum(raw_arg_widths):
                    raw_arg_widths = window_widths
                    raw_arg_sources = _collect_push_arg_sources_before_call(
                        function, window_insns, window_idx, cleanup
                    )
        arg_widths = _trim_push_args_to_stack_cleanup(raw_arg_widths, cleanup)
        push_arg_sources = _trim_push_arg_sources_to_stack_cleanup(raw_arg_widths, raw_arg_sources, cleanup)
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SUMMARY"):
            log.warning(
                "[callsite-summary] callsite=%#x call_idx=%s cleanup=%r target_source=%r raw_widths=%r raw_sources=%r widths=%r sources=%r",
                callsite_addr,
                call_idx,
                cleanup,
                target_source,
                raw_arg_widths,
                raw_arg_sources,
                arg_widths,
                push_arg_sources,
            )
        arg_count = len(arg_widths)
        follow_insns = list(insns[call_idx + 1 : call_idx + 3])
        if len(follow_insns) < 2:
            follow_insns.extend(_next_linear_block_insns(function, callsite_addr)[: 2 - len(follow_insns)])
        has_followup_insns = bool(follow_insns)
        return_register, return_used = _return_use_after_call(function, insns, call_idx, callsite_addr)
        return_shape = _return_shape_after_call(function, insns, call_idx, callsite_addr)
        return_store_destination = _return_store_after_call(function, insns, call_idx, callsite_addr)
        helper_return_state = "none"
        helper_return_space = None
        helper_return_width = None
        helper_return_address_kind = "none"
        if stack_probe_helper:
            if return_register not in {None, "ax"}:
                helper_return_state = "unknown"
                helper_return_address_kind = "unknown"
            elif return_used is True or not has_followup_insns:
                helper_return_state = "stack_address"
                helper_return_space = "ss"
                helper_return_width = 2
                helper_return_address_kind = "stack"
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
            helper_return_width=helper_return_width,
            helper_return_address_kind=helper_return_address_kind,
            return_shape=return_shape.value if isinstance(return_shape, CallsiteReturnShape8616) else None,
            push_arg_sources=push_arg_sources,
            return_store_destination=return_store_destination,
            target_source=target_source,
        )

    return _impl()
