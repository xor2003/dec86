"""Layer: Frontend/angr compatibility.

Responsibility: patch angr calling-convention behavior needed for 16-bit x86.
Forbidden: source/COD/text-backed signature recovery or rewrite-stage call repair.
Dynamic boundary: this module patches third-party angr calling-convention
analysis, project, function, IRSB, and capstone objects. Owned Inertia
contracts must use typed fields and dot access.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Protocol, cast

from angr.analyses.calling_convention import calling_convention as _cc_analysis
from angr.analyses.calling_convention import fact_collector as _cc_fact_collector
from angr.analyses.calling_convention import utils as _cc_utils
from angr.errors import SimTranslationError
from angr.sim_type import SimType, SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from pyvex.expr import Get
from pyvex.stmt import Put

from .simos_86_16 import SimCC8616MSCsmall

__all__ = [
    "apply_x86_16_calling_convention_compatibility",
    "apply_x86_16_stack_byte_prototype_evidence",
    "apply_x86_16_wide_stack_prototype_evidence",
    "apply_x86_16_wide_stack_prototype_evidence_at_address",
]


class _WideReturnEvidence8616(Enum):
    NONE = "none"
    DX_AX_TERMINAL_ARITH = "dx_ax_terminal_arith"


@dataclass(frozen=True)
class _WideStackArgumentEvidence8616:
    """Track carry-chain evidence for logical wide stack arguments."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_offsets: tuple[int, ...]
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def classified_fact_count(self) -> int:
        """Return the number of distinct proven wide argument offsets."""
        return len(self.classified_offsets)

    def with_materialized_count(self, count: int) -> _WideStackArgumentEvidence8616:
        """Return this evidence with its prototype materialization count."""
        return replace(self, materialized_count=count)


class _CapstoneMemory8616(Protocol):
    """Typed view of the capstone x86 memory operand fields used here."""

    base: int
    disp: int


class _CapstoneOperand8616(Protocol):
    """Typed view of the capstone operand fields used by ABI evidence."""

    type: int
    size: int
    reg: int
    mem: _CapstoneMemory8616


class _CapstoneInstruction8616(Protocol):
    """Typed view of a capstone instruction after wrapper normalization."""

    mnemonic: str
    operands: tuple[_CapstoneOperand8616, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return capstone's canonical register name."""
        ...


def _has_explicit_arg_names_8616(prototype: object) -> bool:
    arg_names = getattr(prototype, "arg_names", None) or ()
    for name in arg_names:
        if name is None:
            continue
        if not (isinstance(name, str) and len(name) > 1 and name[0] == "a" and name[1:].isdigit()):
            return True
    return False


def _irsb_reads_word_bp_8616(irsb: object, arch: object) -> bool:
    arch_dynamic = cast(Any, arch)
    irsb_dynamic = cast(Any, irsb)
    bp_offset = arch_dynamic.registers["bp"][0]
    for stmt in irsb_dynamic.statements:
        for expr in stmt.expressions:
            if isinstance(expr, Get) and expr.offset == bp_offset and expr.ty == "Ity_I16":
                return True
    return False


def _count_ax_dx_puts_8616(irsb: object, arch: object) -> int:
    arch_dynamic = cast(Any, arch)
    irsb_dynamic = cast(Any, irsb)
    count = 0
    for stmt in irsb_dynamic.statements:
        if not isinstance(stmt, Put):
            continue
        reg_name = arch_dynamic.translate_register_name(stmt.offset, size=arch_dynamic.bytes)
        if reg_name in {"ax", "dx"}:
            count += 1
    return count


def _iter_function_blocks_8616(project: object, function: object) -> Iterator[object]:
    project_dynamic = cast(Any, project)
    # Dynamic angr function compatibility boundary.
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            yield project_dynamic.factory.block(int(block_addr), opt_level=0)
        except SimTranslationError:
            continue


def _capstone_reg_name_8616(insn: object, reg_id: int) -> str:
    """Return a lower-case register name from a capstone or angr capstone wrapper."""
    try:
        return str(cast(Any, _capstone_instruction_8616(insn)).reg_name(reg_id)).lower()
    except Exception:
        return ""


def _capstone_instruction_8616(insn: object) -> object:
    """Return the underlying capstone instruction from an angr wrapper."""
    # Dynamic angr/capstone compatibility boundary.
    return getattr(insn, "insn", insn)


def _typed_capstone_instruction_8616(insn: object) -> _CapstoneInstruction8616:
    """Return a typed view over a normalized third-party instruction."""
    return cast(_CapstoneInstruction8616, _capstone_instruction_8616(insn))


def _bp_word_memory_offset_8616(insn: object, operand: _CapstoneOperand8616) -> int | None:
    """Return a positive BP-relative word offset from one memory operand."""
    if operand.type != 3 or operand.size != 2 or operand.mem.base == 0:
        return None
    if _capstone_reg_name_8616(insn, operand.mem.base) != "bp":
        return None
    displacement = operand.mem.disp
    if 0x8000 <= displacement <= 0xFFFF:
        displacement -= 0x10000
    return displacement if displacement >= 4 else None


def _binary_stack_operand_offset_8616(insn: object) -> int | None:
    """Return the BP word offset consumed by a two-operand instruction."""
    operands = _typed_capstone_instruction_8616(insn).operands
    if len(operands) != 2:
        return None
    return _bp_word_memory_offset_8616(insn, operands[1])


def _written_register_id_8616(insn: object) -> int | None:
    """Return the destination register id for a register-writing instruction."""
    operands = _typed_capstone_instruction_8616(insn).operands
    if not operands or operands[0].type != 1:
        return None
    return operands[0].reg


def _wide_stack_argument_evidence_from_insns_8616(
    instruction_groups: Iterator[tuple[object, ...]],
) -> _WideStackArgumentEvidence8616:
    """Classify carry-linked arithmetic from normalized instruction groups."""
    raw_fact_count = 0
    normalized_fact_count = 0
    failure_count = 0
    classified_offsets: set[int] = set()
    carry_mnemonic = {"add": "adc", "sub": "sbb"}
    for insns in instruction_groups:
        for low_insn, high_insn in zip(insns, insns[1:]):
            low_mnemonic = _typed_capstone_instruction_8616(low_insn).mnemonic.lower()
            if carry_mnemonic.get(low_mnemonic) != _typed_capstone_instruction_8616(high_insn).mnemonic.lower():
                continue
            raw_fact_count += 1
            low_offset = _binary_stack_operand_offset_8616(low_insn)
            high_offset = _binary_stack_operand_offset_8616(high_insn)
            if low_offset is None or high_offset is None:
                failure_count += 1
                continue
            normalized_fact_count += 1
            low_reg = _written_register_id_8616(low_insn)
            high_reg = _written_register_id_8616(high_insn)
            if high_offset != low_offset + 2 or low_reg is None or high_reg is None or low_reg == high_reg:
                failure_count += 1
                continue
            classified_offsets.add(low_offset)
    return _WideStackArgumentEvidence8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_offsets=tuple(sorted(classified_offsets)),
        failure_count=failure_count,
    )


def _function_instruction_groups_8616(project: object, function: object) -> Iterator[tuple[object, ...]]:
    """Yield capstone instruction groups for each known function block."""
    for block in _iter_function_blocks_8616(project, function):
        # Dynamic angr block compatibility boundary.
        yield tuple(cast(Any, block).capstone.insns or ())


def _wide_stack_argument_evidence_8616(project: object, function: object) -> _WideStackArgumentEvidence8616:
    """Classify carry-linked arithmetic over adjacent BP words as one value."""
    return _wide_stack_argument_evidence_from_insns_8616(_function_instruction_groups_8616(project, function))


def _instruction_writes_reg_8616(insn: object, reg_name: str) -> bool:
    inner = _capstone_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if not operands:
        return False
    first = operands[0]
    # Dynamic capstone compatibility boundary.
    if int(getattr(first, "type", -1)) != 1:
        return False
    # Dynamic capstone compatibility boundary.
    return _capstone_reg_name_8616(insn, int(getattr(first, "reg", 0) or 0)) == reg_name


def _instruction_reads_reg_8616(insn: object, reg_names: set[str]) -> bool:
    """Return whether an instruction reads one of the requested registers."""
    inner = _capstone_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    for operand in operands[1:]:
        # Dynamic capstone compatibility boundary.
        if int(getattr(operand, "type", -1)) != 1:
            continue
        # Dynamic capstone compatibility boundary.
        if _capstone_reg_name_8616(insn, int(getattr(operand, "reg", 0) or 0)) in reg_names:
            return True
    # Dynamic capstone compatibility boundary.
    mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
    if mnemonic in {"cmp", "test"} and operands:
        first = operands[0]
        # Dynamic capstone compatibility boundary.
        return int(getattr(first, "type", -1)) == 1 and _capstone_reg_name_8616(
            # Dynamic capstone compatibility boundary.
            insn, int(getattr(first, "reg", 0) or 0)
        ) in reg_names
    return False


def _bp_byte_load_offsets_from_instructions_8616(project: object, function: object) -> tuple[int, ...]:
    """Return positive BP stack offsets read through byte memory operands."""
    offsets: set[int] = set()
    for block in _iter_function_blocks_8616(project, function):
        # Dynamic angr/capstone compatibility boundary.
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            # Dynamic capstone compatibility boundary.
            for operand in tuple(getattr(insn, "operands", ()) or ()):
                # Dynamic capstone compatibility boundary.
                if int(getattr(operand, "type", -1)) != 3 or int(getattr(operand, "size", 0) or 0) != 1:
                    continue
                # Dynamic capstone compatibility boundary.
                mem = getattr(operand, "mem", None)
                # Dynamic capstone compatibility boundary.
                if mem is None or not getattr(mem, "base", None):
                    continue
                if _capstone_reg_name_8616(insn, int(mem.base)) != "bp":
                    continue
                # Dynamic capstone compatibility boundary.
                disp = int(getattr(mem, "disp", 0) or 0)
                if 0x8000 <= disp <= 0xFFFF:
                    disp -= 0x10000
                if disp >= 4:
                    offsets.add(disp)
    return tuple(sorted(offsets))


def _terminal_byte_return_evidence_8616(project: object, function: object) -> bool:
    """Detect terminal AL-family return production without source declarations."""
    for block in _iter_function_blocks_8616(project, function):
        last_return_write: str | None = None
        # Dynamic angr/capstone compatibility boundary.
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            if _instruction_writes_reg_8616(insn, "ax"):
                last_return_write = "ax"
            elif _instruction_writes_reg_8616(insn, "al"):
                last_return_write = "al"
            # Dynamic capstone compatibility boundary.
            mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
            if mnemonic in {"ret", "retf", "iret", "jmp", "ljmp"} and last_return_write == "al":
                return True
    return False


def _terminal_word_return_evidence_8616(project: object, function: object) -> bool:
    """Return whether a terminal path leaves a word result in AX."""
    if _terminal_wide_return_evidence_8616(project, function) is not _WideReturnEvidence8616.NONE:
        return False
    for block in _iter_function_blocks_8616(project, function):
        saw_ax_write = False
        for insn in tuple(cast(Any, block).capstone.insns or ()):
            if _instruction_writes_reg_8616(insn, "ax"):
                saw_ax_write = True
            mnemonic = str(cast(Any, insn).mnemonic or "").lower()
            if mnemonic in {"ret", "retf", "iret"} and saw_ax_write:
                return True
    return False


def _function_target_addrs_8616(function: object) -> set[int]:
    """Return address aliases that may identify a function in exact slices."""
    # Dynamic angr function compatibility boundary.
    target_addr = getattr(function, "addr", None)
    if not isinstance(target_addr, int):
        return set()
    targets = {target_addr}
    # Dynamic angr function compatibility boundary.
    original_delta = getattr(getattr(function, "project", None), "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int):
        targets.add(target_addr + original_delta)
    return targets


def _caller_sign_extends_byte_return_8616(project: object, function: object) -> bool | None:
    """Return whether callers prove signed or non-signed AL consumption."""
    try:
        from .analysis_helpers import collect_neighbor_call_targets
        from .callsite_summary import _block_insns_for_callsite, _find_call_index
    except Exception:
        return None
    target_addrs = _function_target_addrs_8616(function)
    if not target_addrs:
        return None
    # Dynamic angr project compatibility boundary.
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if functions is None:
        return None
    saw_matching_call = False
    try:
        callers = tuple(functions.values())
    except Exception:
        return False
    for caller in callers:
        try:
            seeds = tuple(collect_neighbor_call_targets(caller))
        except Exception:
            continue
        for seed in seeds:
            # CallTargetSeed is owned evidence, not part of the angr boundary.
            if seed.target_addr not in target_addrs:
                continue
            saw_matching_call = True
            callsite_addr = seed.callsite_addr
            insns = _block_insns_for_callsite(caller, callsite_addr)
            call_idx = _find_call_index(insns, callsite_addr) if insns else None
            if call_idx is None:
                continue
            for follow in insns[call_idx + 1 : call_idx + 5]:
                # Dynamic capstone compatibility boundary.
                mnemonic = str(getattr(follow, "mnemonic", "") or "").lower()
                if mnemonic == "cbw":
                    return True
                if _instruction_reads_reg_8616(follow, {"al"}) or _instruction_writes_reg_8616(follow, "ax"):
                    break
    return False if saw_matching_call else None


def _terminal_wide_return_evidence_8616(project: object, function: object) -> _WideReturnEvidence8616:
    """Detect a terminal DX:AX producer without relying on source names."""
    terminal_dx_ops = {"adc", "sbb", "mov"}
    for block in _iter_function_blocks_8616(project, function):
        # Dynamic angr/capstone compatibility boundary.
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not insns:
            continue
        last_ax_idx = None
        last_dx_idx = None
        last_dx_mnemonic = None
        for idx, insn in enumerate(insns):
            if _instruction_writes_reg_8616(insn, "ax"):
                last_ax_idx = idx
            if _instruction_writes_reg_8616(insn, "dx"):
                last_dx_idx = idx
                last_dx_mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        if last_ax_idx is None or last_dx_idx is None:
            continue
        if last_dx_idx <= last_ax_idx:
            continue
        if last_dx_mnemonic in terminal_dx_ops:
            if not _wide_return_suffix_is_terminal_8616(project, function, insns, last_dx_idx):
                continue
            return _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH
    return _WideReturnEvidence8616.NONE


def _wide_return_suffix_is_terminal_8616(
    project: object, function: object, insns: tuple[object, ...], producer_idx: int
) -> bool:
    """Return whether a DX:AX producer is followed only by epilogue instructions."""
    for insn in insns[producer_idx + 1 :]:
        # Dynamic capstone compatibility boundary.
        mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        if mnemonic in {"nop", "pop", "leave"}:
            continue
        if mnemonic in {"jmp", "ljmp"}:
            target = _direct_jump_target_8616(insn)
            return target is not None and _target_block_is_epilogue_only_8616(project, function, target)
        return mnemonic in {"ret", "retf", "iret"}
    return False


def _direct_jump_target_8616(insn: object) -> int | None:
    """Return a direct jump target from a capstone instruction, if present."""
    inner = _capstone_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if len(operands) != 1:
        return None
    operand = operands[0]
    # Dynamic capstone compatibility boundary.
    if int(getattr(operand, "type", -1)) != 2:
        return None
    # Dynamic capstone compatibility boundary.
    target = getattr(operand, "imm", None)
    return target if isinstance(target, int) else None


def _target_block_is_epilogue_only_8616(project: object, function: object, target_addr: int) -> bool:
    """Return whether a direct target block contains only stack teardown and return."""
    project_dynamic = cast(Any, project)
    # Dynamic angr function compatibility boundary.
    block_addrs = set(getattr(function, "block_addrs_set", ()) or ())
    if block_addrs and target_addr not in block_addrs:
        return False
    try:
        block = project_dynamic.factory.block(target_addr, opt_level=0)
    except SimTranslationError:
        return False
    # Dynamic angr/capstone compatibility boundary.
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    if not insns:
        return False
    for idx, insn in enumerate(insns):
        # Dynamic capstone compatibility boundary.
        mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        if mnemonic in {"nop", "pop", "leave"} or _instruction_is_mov_sp_bp_8616(insn):
            continue
        return idx == len(insns) - 1 and mnemonic in {"ret", "retf", "iret"}
    return False


def _instruction_is_mov_sp_bp_8616(insn: object) -> bool:
    """Return whether an instruction is the 16-bit epilogue form `mov sp, bp`."""
    # Dynamic capstone compatibility boundary.
    if str(getattr(insn, "mnemonic", "") or "").lower() != "mov":
        return False
    inner = _capstone_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if len(operands) != 2:
        return False
    lhs = operands[0]
    rhs = operands[1]
    # Dynamic capstone compatibility boundary.
    if int(getattr(lhs, "type", -1)) != 1 or int(getattr(rhs, "type", -1)) != 1:
        return False
    # Dynamic capstone compatibility boundary.
    lhs_reg = int(getattr(lhs, "reg", 0) or 0)
    # Dynamic capstone compatibility boundary.
    rhs_reg = int(getattr(rhs, "reg", 0) or 0)
    return _capstone_reg_name_8616(insn, lhs_reg) == "sp" and _capstone_reg_name_8616(insn, rhs_reg) == "bp"


def _bp_word_load_offsets_from_insns_8616(instruction_groups: Iterator[tuple[object, ...]]) -> tuple[int, ...]:
    """Return positive BP word offsets read by normalized instructions."""
    offsets: set[int] = set()
    for insns in instruction_groups:
        for insn in insns:
            for operand in _typed_capstone_instruction_8616(insn).operands:
                offset = _bp_word_memory_offset_8616(insn, operand)
                if offset is not None:
                    offsets.add(offset)
    return tuple(sorted(offsets))


def _bp_word_load_offsets_from_instructions_8616(project: object, function: object) -> tuple[int, ...]:
    """Return positive BP stack offsets read through word memory operands."""
    return _bp_word_load_offsets_from_insns_8616(_function_instruction_groups_8616(project, function))


def _wide_stack_arg_count_from_offsets_8616(offsets: tuple[int, ...]) -> int:
    remaining = set(offsets)
    count = 0
    offset = 4
    while offset in remaining and offset + 2 in remaining:
        count += 1
        offset += 4
    return count


def _sim_type_stack_width_8616(sim_type: object) -> int:
    """Return a 16-bit ABI stack width for an angr type."""
    try:
        bit_width = int(cast(Any, sim_type).size)
    except (AttributeError, TypeError, ValueError):
        return 2
    return max(2, (bit_width + 7) // 8)


def _wide_stack_arithmetic_prototype_from_evidence_8616(
    project: object,
    function: object,
    *,
    evidence: _WideStackArgumentEvidence8616,
    loaded_offsets: tuple[int, ...],
    signed: bool,
) -> tuple[object, object, _WideStackArgumentEvidence8616] | None:
    """Build a logical prototype from carry-linked adjacent stack words."""
    if evidence.classified_fact_count == 0:
        return None

    project_dynamic = cast(Any, project)
    function_dynamic = cast(Any, function)
    existing = function_dynamic.prototype
    if isinstance(existing, SimTypeFunction):
        physical_args: list[SimType] = list(cast(Iterable[SimType], existing.args or ()))
        return_type = existing.returnty
        variadic = existing.variadic
    else:
        physical_args = []
        return_type = SimTypeBottom(label="void").with_arch(project_dynamic.arch)
        variadic = False

    required_word_count = 0
    if loaded_offsets:
        required_word_count = ((max(loaded_offsets) - 4) // 2) + 1
    while len(physical_args) < required_word_count:
        physical_args.append(SimTypeShort(False).with_arch(project_dynamic.arch))

    logical_args: list[SimType] = []
    materialized_offsets: set[int] = set()
    physical_index = 0
    stack_offset = 4
    wide_offsets = set(evidence.classified_offsets)
    while physical_index < len(physical_args):
        arg_type = physical_args[physical_index]
        arg_width = _sim_type_stack_width_8616(arg_type)
        if stack_offset in wide_offsets:
            if arg_width >= 4:
                logical_args.append(arg_type)
                materialized_offsets.add(stack_offset)
                stack_offset += arg_width
                physical_index += 1
                continue
            if physical_index + 1 < len(physical_args):
                high_type = physical_args[physical_index + 1]
                if arg_width == 2 and _sim_type_stack_width_8616(high_type) == 2:
                    logical_args.append(SimTypeLong(signed=signed).with_arch(project_dynamic.arch))
                    materialized_offsets.add(stack_offset)
                    stack_offset += 4
                    physical_index += 2
                    continue
        logical_args.append(arg_type)
        stack_offset += arg_width
        physical_index += 1

    materialized_evidence = evidence.with_materialized_count(len(materialized_offsets))
    if materialized_evidence.materialized_count != materialized_evidence.classified_fact_count:
        return None
    prototype = SimTypeFunction(logical_args, return_type, variadic=variadic).with_arch(project_dynamic.arch)
    return SimCC8616MSCsmall(project_dynamic.arch), prototype, materialized_evidence


def _wide_stack_arithmetic_prototype_from_function_8616(
    project: object, function: object, *, signed: bool
) -> tuple[object, object, _WideStackArgumentEvidence8616] | None:
    """Build a logical prototype from one discovered function body."""
    return _wide_stack_arithmetic_prototype_from_evidence_8616(
        project,
        function,
        evidence=_wide_stack_argument_evidence_8616(project, function),
        loaded_offsets=_bp_word_load_offsets_from_instructions_8616(project, function),
        signed=signed,
    )


def _wide_stack_arg_prototype_from_function_8616(
    project: object, function: object, *, signed: bool = True
) -> tuple[object, object] | None:
    project_dynamic = cast(Any, project)
    arithmetic_inference = _wide_stack_arithmetic_prototype_from_function_8616(
        project,
        function,
        signed=signed,
    )
    if arithmetic_inference is not None:
        cc, prototype, _evidence = arithmetic_inference
        return cc, prototype
    evidence = _terminal_wide_return_evidence_8616(project, function)
    if evidence is _WideReturnEvidence8616.NONE:
        return None
    arg_count = _wide_stack_arg_count_from_offsets_8616(_bp_word_load_offsets_from_instructions_8616(project, function))
    if arg_count <= 0:
        return None
    wide_ty = SimTypeLong(signed=signed).with_arch(project_dynamic.arch)
    return SimCC8616MSCsmall(project_dynamic.arch), SimTypeFunction([wide_ty] * arg_count, wide_ty).with_arch(
        project_dynamic.arch
    )


def _stack_byte_prototype_from_function_8616(project: object, function: object) -> tuple[object, object] | None:
    """Infer a byte stack prototype from terminal AL and byte BP-load evidence."""
    project_dynamic = cast(Any, project)
    if not _terminal_byte_return_evidence_8616(project, function):
        return None
    arg_offsets = _bp_byte_load_offsets_from_instructions_8616(project, function)
    if not arg_offsets:
        return None
    signed_evidence = _caller_sign_extends_byte_return_8616(project, function)
    signed = True if signed_evidence is None else signed_evidence
    byte_ty = SimTypeChar(signed=signed).with_arch(project_dynamic.arch)
    return SimCC8616MSCsmall(project_dynamic.arch), SimTypeFunction([byte_ty] * len(arg_offsets), byte_ty).with_arch(
        project_dynamic.arch
    )


def _guess_retval_type_8616(self: object, cc: object, ret_val_size: object) -> object:
    self_dynamic = cast(Any, self)
    cc_dynamic = cast(Any, cc)

    def _impl() -> object:
        ret_type = cast(Any, _guess_retval_type_8616)._orig(self, cc, ret_val_size)
        if getattr(self_dynamic.project.arch, "name", None) != "86_16" or ret_type is None:
            return ret_type
        if not isinstance(ret_type, SimTypeShort):
            return ret_type
        if not getattr(cc_dynamic, "OVERFLOW_RETURN_VAL", None) or getattr(cc_dynamic, "RETURN_VAL", None) is None:
            return ret_type
        if getattr(self_dynamic._function, "_argument_registers", None) or getattr(
            self_dynamic._function, "_argument_stack_variables", None
        ):
            return ret_type

        for ret_block in getattr(self_dynamic._function, "ret_sites", ()):
            retval_updated, overflow_updated = False, False
            try:
                irsb = self_dynamic.project.factory.block(ret_block.addr, size=ret_block.size).vex
            except SimTranslationError:
                continue
            if _irsb_reads_word_bp_8616(irsb, self_dynamic.project.arch):
                continue
            for stmt in irsb.statements:
                if isinstance(stmt, Put):
                    reg_name = self_dynamic.project.arch.translate_register_name(
                        stmt.offset, size=self_dynamic.project.arch.bytes
                    )
                    if reg_name == cc_dynamic.RETURN_VAL.reg_name:
                        retval_updated = True
                    elif reg_name == cc_dynamic.OVERFLOW_RETURN_VAL.reg_name:
                        overflow_updated = True
            if retval_updated and overflow_updated:
                return SimTypeLong().with_arch(self_dynamic.project.arch)
        return ret_type

    return _impl()


def _promote_wide_stack_return_to_wide_arg_8616(self: object, prototype: object) -> object:
    self_dynamic = cast(Any, self)
    prototype_dynamic = cast(Any, prototype)

    def _impl() -> object:
        if getattr(self_dynamic.project.arch, "name", None) != "86_16" or prototype is None:
            return prototype
        wide_stack_proto = _wide_stack_arg_prototype_from_function_8616(self_dynamic.project, self_dynamic._function)
        if wide_stack_proto is not None:
            _cc, promoted = wide_stack_proto
            return promoted
        if len(prototype_dynamic.args) == 0 and isinstance(prototype_dynamic.returnty, SimTypeLong):
            block_addrs = sorted(getattr(self_dynamic._function, "block_addrs_set", ()) or ())
            if block_addrs:
                try:
                    irsb = self_dynamic.project.factory.block(block_addrs[0]).vex
                except SimTranslationError:
                    irsb = None
                if irsb is not None:
                    if _irsb_reads_word_bp_8616(irsb, self_dynamic.project.arch):
                        if _count_ax_dx_puts_8616(irsb, self_dynamic.project.arch) == 2:
                            wide_ty = SimTypeLong().with_arch(self_dynamic.project.arch)
                            return prototype_dynamic.__class__([wide_ty], wide_ty).with_arch(self_dynamic.project.arch)
        if len(prototype_dynamic.args) != 2:
            return prototype
        if not all(type(arg) is SimTypeShort for arg in prototype_dynamic.args):
            return prototype
        if type(prototype_dynamic.returnty) is not SimTypeShort:
            return prototype

        block_addrs = sorted(getattr(self_dynamic._function, "block_addrs_set", ()) or ())
        if not block_addrs:
            return prototype

        try:
            irsb = self_dynamic.project.factory.block(block_addrs[0]).vex
        except SimTranslationError:
            return prototype

        if not _irsb_reads_word_bp_8616(irsb, self_dynamic.project.arch):
            return prototype

        if _count_ax_dx_puts_8616(irsb, self_dynamic.project.arch) != 2:
            return prototype

        wide_ty = SimTypeLong().with_arch(self_dynamic.project.arch)
        return prototype_dynamic.__class__([wide_ty], wide_ty).with_arch(self_dynamic.project.arch)

    return _impl()


def _promote_terminal_word_return_8616(project: object, function: object, prototype: object) -> object:
    """Promote a guessed void prototype when terminal AX evidence proves a word return."""
    project_dynamic = cast(Any, project)
    prototype_dynamic = cast(Any, prototype)
    return_type = prototype_dynamic.returnty
    if not isinstance(return_type, SimTypeBottom):
        return prototype
    if not _terminal_word_return_evidence_8616(project, function):
        return prototype
    word_type = SimTypeShort().with_arch(project_dynamic.arch)
    return prototype_dynamic.__class__(list(prototype_dynamic.args), word_type).with_arch(project_dynamic.arch)


def _fallback_terminal_word_return_prototype_8616(self: object) -> tuple[object, object] | None:
    """Build a no-argument word-return prototype from terminal AX evidence."""
    self_dynamic = cast(Any, self)
    if not _terminal_word_return_evidence_8616(self_dynamic.project, self_dynamic._function):
        return None
    word_type = SimTypeShort().with_arch(self_dynamic.project.arch)
    return SimCC8616MSCsmall(self_dynamic.project.arch), SimTypeFunction([], word_type).with_arch(
        self_dynamic.project.arch
    )


def _fallback_wide_stack_return_prototype_8616(self: object) -> tuple[object, object] | None:
    self_dynamic = cast(Any, self)
    wide_stack_proto = _wide_stack_arg_prototype_from_function_8616(self_dynamic.project, self_dynamic._function)
    if wide_stack_proto is not None:
        return wide_stack_proto

    block_addrs = sorted(getattr(self_dynamic._function, "block_addrs_set", ()) or ())
    if not block_addrs:
        return None

    try:
        irsb = self_dynamic.project.factory.block(block_addrs[0]).vex
    except SimTranslationError:
        return None

    if not _irsb_reads_word_bp_8616(irsb, self_dynamic.project.arch) or irsb.jumpkind != "Ijk_Ret":
        return None

    if _count_ax_dx_puts_8616(irsb, self_dynamic.project.arch) != 2:
        return None

    wide_ty = SimTypeLong().with_arch(self_dynamic.project.arch)
    return SimCC8616MSCsmall(self_dynamic.project.arch), SimTypeFunction([wide_ty], wide_ty).with_arch(
        self_dynamic.project.arch
    )


def _set_function_prototype_8616(function: object, cc: object, prototype: object) -> tuple[object, object]:
    function_dynamic = cast(Any, function)
    # Dynamic angr function compatibility boundary.
    existing = getattr(function, "prototype", None)
    if existing is not None and (
        # Dynamic angr function compatibility boundary.
        _has_explicit_arg_names_8616(existing) or not bool(getattr(function, "is_prototype_guessed", True))
    ):
        return cc, existing
    # Dynamic angr SimType compatibility boundary.
    if prototype is not None and getattr(prototype, "_arch", None) is None:
        try:
            prototype = cast(Any, prototype).with_arch(function_dynamic.project.arch)
        except Exception:
            pass
    function_dynamic.prototype = prototype
    function_dynamic.is_prototype_guessed = False
    if cc is not None:
        try:
            function_dynamic.calling_convention = cc
        except Exception:
            pass
    return cc, prototype


def apply_x86_16_wide_stack_prototype_evidence(project: object, function: object) -> bool:
    """Promote guessed prototypes when binary evidence proves a wide stack ABI."""
    # Dynamic angr project compatibility boundary.
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return False
    # Dynamic angr function compatibility boundary.
    existing = getattr(function, "prototype", None)
    if existing is not None and (
        # Dynamic angr function compatibility boundary.
        _has_explicit_arg_names_8616(existing) or not bool(getattr(function, "is_prototype_guessed", True))
    ):
        return False
    inferred = _wide_stack_arg_prototype_from_function_8616(project, function)
    if inferred is None:
        return False
    cc, prototype = inferred
    _set_function_prototype_8616(function, cc, prototype)
    return True


def apply_x86_16_wide_stack_prototype_evidence_at_address(
    project: object,
    function: object,
    address: int,
    *,
    scan_size: int = 512,
) -> bool:
    """Promote a bodyless function stub from bounded binary instruction facts.

    Exact-region projects keep direct callees as bodyless stubs. This entrypoint
    reads a bounded window from the original project and refuses evidence unless
    a decoded return terminates the window.
    """
    project_dynamic = cast(Any, project)
    function_dynamic = cast(Any, function)
    if project_dynamic.arch.name != "86_16" or address < 0 or not 16 <= scan_size <= 4096:
        return False
    existing = function_dynamic.prototype
    if existing is not None and (
        _has_explicit_arg_names_8616(existing) or not bool(function_dynamic.is_prototype_guessed)
    ):
        return False
    try:
        block = project_dynamic.factory.block(address, size=scan_size, opt_level=0)
    except (KeyError, SimTranslationError, ValueError):
        return False
    instructions: list[object] = []
    for insn in tuple(cast(Any, block).capstone.insns or ()):
        instructions.append(insn)
        if _typed_capstone_instruction_8616(insn).mnemonic.lower() in {"ret", "retf", "iret"}:
            break
    if not instructions or _typed_capstone_instruction_8616(instructions[-1]).mnemonic.lower() not in {
        "ret",
        "retf",
        "iret",
    }:
        return False
    instruction_group = (tuple(instructions),)
    inferred = _wide_stack_arithmetic_prototype_from_evidence_8616(
        project,
        function,
        evidence=_wide_stack_argument_evidence_from_insns_8616(iter(instruction_group)),
        loaded_offsets=_bp_word_load_offsets_from_insns_8616(iter(instruction_group)),
        signed=True,
    )
    if inferred is None:
        return False
    cc, prototype, evidence = inferred
    if evidence.classified_fact_count > 0 and evidence.materialized_count == 0:
        raise RuntimeError("wide stack argument evidence was classified but not materialized")
    _set_function_prototype_8616(function, cc, prototype)
    return True


def apply_x86_16_stack_byte_prototype_evidence(project: object, function: object) -> bool:
    """Promote guessed prototypes when binary evidence proves byte stack values."""
    # Dynamic angr project compatibility boundary.
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return False
    # Dynamic angr function compatibility boundary.
    existing = getattr(function, "prototype", None)
    if existing is not None and (
        # Dynamic angr function compatibility boundary.
        _has_explicit_arg_names_8616(existing) or not bool(getattr(function, "is_prototype_guessed", True))
    ):
        return False
    inferred = _stack_byte_prototype_from_function_8616(project, function)
    if inferred is None:
        return False
    cc, prototype = inferred
    _set_function_prototype_8616(function, cc, prototype)
    return True


def apply_x86_16_calling_convention_compatibility() -> None:
    """Install x86-16 calling-convention compatibility patches once per process."""
    if getattr(_cc_utils.is_sane_register_variable, "__name__", "") != "_is_sane_register_variable_8616":
        _orig_is_sane_register_variable = _cc_utils.is_sane_register_variable

        def _is_sane_register_variable_8616(
            arch: object, reg_offset: object, reg_size: object, def_cc: object = None
        ) -> bool:
            arch_dynamic = cast(Any, arch)
            if arch_dynamic.name == "86_16":
                return True
            return cast(Any, _orig_is_sane_register_variable)(arch, reg_offset, reg_size, def_cc=def_cc)

        cast(Any, _cc_utils).is_sane_register_variable = _is_sane_register_variable_8616
        cast(Any, _cc_analysis).is_sane_register_variable = _is_sane_register_variable_8616
        cast(Any, _cc_fact_collector).is_sane_register_variable = _is_sane_register_variable_8616

    if getattr(_cc_analysis.CallingConventionAnalysis._analyze_function, "__name__", "") != "_analyze_function_8616":
        cast(Any, _guess_retval_type_8616)._orig = _cc_analysis.CallingConventionAnalysis._guess_retval_type
        _analyze_function_orig = _cc_analysis.CallingConventionAnalysis._analyze_function

        def _analyze_function_8616(self: object) -> object:
            self_dynamic = cast(Any, self)
            existing_prototype = getattr(self_dynamic._function, "prototype", None)
            had_explicit_prototype = existing_prototype is not None and not bool(
                getattr(self_dynamic._function, "is_prototype_guessed", True)
            )
            result = cast(Any, _analyze_function_orig)(self)
            if result is None:
                fallback = _fallback_wide_stack_return_prototype_8616(self)
                if fallback is None:
                    fallback = _fallback_terminal_word_return_prototype_8616(self)
                if fallback is None:
                    return result
                return _set_function_prototype_8616(self_dynamic._function, *fallback)
            cc, prototype = result
            if prototype is None:
                fallback = _fallback_wide_stack_return_prototype_8616(self)
                if fallback is None:
                    fallback = _fallback_terminal_word_return_prototype_8616(self)
                if fallback is not None:
                    return _set_function_prototype_8616(self_dynamic._function, *fallback)
            promoted = _promote_wide_stack_return_to_wide_arg_8616(self, prototype)
            if not had_explicit_prototype:
                promoted = _promote_terminal_word_return_8616(
                    self_dynamic.project,
                    self_dynamic._function,
                    promoted,
                )
            if (
                promoted is not prototype
                and not had_explicit_prototype
                and not _has_explicit_arg_names_8616(promoted)
            ):
                return _set_function_prototype_8616(self_dynamic._function, cc, promoted)
            return cc, promoted

        cast(Any, _cc_analysis.CallingConventionAnalysis)._analyze_function = _analyze_function_8616

    if getattr(_cc_analysis.CallingConventionAnalysis._guess_retval_type, "__name__", "") != "_guess_retval_type_8616":
        cast(Any, _guess_retval_type_8616)._orig = _cc_analysis.CallingConventionAnalysis._guess_retval_type
        cast(Any, _cc_analysis.CallingConventionAnalysis)._guess_retval_type = _guess_retval_type_8616
