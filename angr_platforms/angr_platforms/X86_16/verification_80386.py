"""Compare straight-line 80386 real-mode execution with hardware MOO states.

Layer: Frontend verification.
Responsibility: execute one modeled 80386 instruction and compare its register
and memory effects with hardware-captured before/after state.
"""

from __future__ import annotations

from typing import Any

import angr
import angr.sim_options as o

from .verification_80286 import (
    CaseMismatch,
    CaseResult,
    _concrete_byte,
    _make_project,
    _solver_eval_int_8616,
    _state_reg_expr_8616,
    _state_reg_set_8616,
    _step_with_lock_retry,
)

_UNMODELED_DEBUG_REGISTERS: frozenset[str] = frozenset({"dr6", "dr7"})
_DEFINED_REAL_MODE_EFLAGS_MASK = 0x00000FD5
_ARITHMETIC_FLAG_CF = 0x001
_ARITHMETIC_FLAG_PF = 0x004
_ARITHMETIC_FLAG_AF = 0x010
_ARITHMETIC_FLAG_ZF = 0x040
_ARITHMETIC_FLAG_SF = 0x080
_ARITHMETIC_FLAG_OF = 0x800
_UNDEFINED_BT_FLAGS = _ARITHMETIC_FLAG_PF | _ARITHMETIC_FLAG_AF | _ARITHMETIC_FLAG_ZF | _ARITHMETIC_FLAG_SF | _ARITHMETIC_FLAG_OF
_UNDEFINED_BSF_BSR_FLAGS = (
    _ARITHMETIC_FLAG_CF | _ARITHMETIC_FLAG_PF | _ARITHMETIC_FLAG_AF | _ARITHMETIC_FLAG_SF | _ARITHMETIC_FLAG_OF
)
_UNDEFINED_MUL_FLAGS = _ARITHMETIC_FLAG_PF | _ARITHMETIC_FLAG_AF | _ARITHMETIC_FLAG_ZF | _ARITHMETIC_FLAG_SF
_UNDEFINED_AAD_FLAGS = _ARITHMETIC_FLAG_CF | _ARITHMETIC_FLAG_AF | _ARITHMETIC_FLAG_OF


def _repeat_count_80386(case: dict[str, Any], instruction: bytes) -> int | None:
    """Return the address-size-selected count for a repeated string instruction."""
    prefix_end = 0
    has_repeat = False
    address_bits = 16
    prefix_bytes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
    while prefix_end < len(instruction) and instruction[prefix_end] in prefix_bytes:
        has_repeat |= instruction[prefix_end] in {0xF2, 0xF3}
        if instruction[prefix_end] == 0x67:
            address_bits = 32
        prefix_end += 1
    if not has_repeat or prefix_end >= len(instruction) or instruction[prefix_end] not in {
        0x6C,
        0x6D,
        0x6E,
        0x6F,
        0xA4,
        0xA5,
        0xA6,
        0xA7,
        0xAA,
        0xAB,
        0xAC,
        0xAD,
        0xAE,
        0xAF,
    }:
        return None
    ecx = int(case["initial"]["regs"]["ecx"])
    return ecx & (0xFFFFFFFF if address_bits == 32 else 0xFFFF)


def _shift_count_80386(case: dict[str, Any]) -> int | None:
    """Return the 80386-masked shift count encoded by one hardware case."""
    name = str(case["name"])
    if "," not in name:
        return None
    token = name.rsplit(",", maxsplit=1)[1].strip().lower()
    if token == "cl":
        return int(case["initial"]["regs"]["ecx"]) & 0x1F
    try:
        return int(token[:-1], 16) & 0x1F if token.endswith("h") else int(token, 0) & 0x1F
    except ValueError:
        return None


def _shift_width_80386(case: dict[str, Any]) -> int:
    """Infer the explicit hardware-test destination width from its decoded name."""
    destination = str(case["name"]).split(maxsplit=1)[1].split(",", maxsplit=1)[0].lower()
    if "dword" in destination or destination in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
        return 32
    if "byte" in destination or destination in {"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"}:
        return 8
    return 16


def _defined_eflags_mask_80386(case: dict[str, Any]) -> int:
    """Return the architectural EFLAGS comparison mask for one hardware case."""
    mnemonic = str(case["name"]).split(maxsplit=1)[0].lower()
    if mnemonic in {"bt", "btc", "btr", "bts"}:
        return _DEFINED_REAL_MODE_EFLAGS_MASK & ~_UNDEFINED_BT_FLAGS
    if mnemonic in {"bsf", "bsr"}:
        return _DEFINED_REAL_MODE_EFLAGS_MASK & ~_UNDEFINED_BSF_BSR_FLAGS
    if mnemonic in {"imul", "mul"}:
        return _DEFINED_REAL_MODE_EFLAGS_MASK & ~_UNDEFINED_MUL_FLAGS
    if mnemonic == "aad":
        return _DEFINED_REAL_MODE_EFLAGS_MASK & ~_UNDEFINED_AAD_FLAGS
    if mnemonic in {"div", "idiv"}:
        return 0
    count = _shift_count_80386(case)
    if count == 0:
        return _DEFINED_REAL_MODE_EFLAGS_MASK
    if mnemonic in {"rol", "ror"} and count is not None:
        effective_count = count % _shift_width_80386(case)
        return (
            _DEFINED_REAL_MODE_EFLAGS_MASK
            if effective_count == 1
            else _DEFINED_REAL_MODE_EFLAGS_MASK & ~_ARITHMETIC_FLAG_OF
        )
    if mnemonic in {"rcl", "rcr"} and count is not None:
        effective_count = count % (_shift_width_80386(case) + 1)
        return (
            _DEFINED_REAL_MODE_EFLAGS_MASK
            if effective_count == 1
            else _DEFINED_REAL_MODE_EFLAGS_MASK & ~_ARITHMETIC_FLAG_OF
        )
    if mnemonic in {"sal", "sar", "shl", "shr", "shld", "shrd"} and count is not None:
        undefined = _ARITHMETIC_FLAG_AF
        if count != 1:
            undefined |= _ARITHMETIC_FLAG_OF
        if mnemonic in {"sal", "shl", "shr"} and count >= _shift_width_80386(case):
            undefined |= _ARITHMETIC_FLAG_CF
        if mnemonic in {"shld", "shrd"} and count > _shift_width_80386(case):
            undefined |= (
                _ARITHMETIC_FLAG_CF
                | _ARITHMETIC_FLAG_PF
                | _ARITHMETIC_FLAG_ZF
                | _ARITHMETIC_FLAG_SF
            )
        return _DEFINED_REAL_MODE_EFLAGS_MASK & ~undefined
    return _DEFINED_REAL_MODE_EFLAGS_MASK


def _instruction_bytes_80386(case: dict[str, Any], project: angr.Project) -> bytes:
    """Return exactly the first hardware-test instruction, excluding its terminating HLT."""
    regs = case["initial"]["regs"]
    linear_ip = ((int(regs["cs"]) & 0xFFFF) << 4) + (int(regs["eip"]) & 0xFFFF)
    raw = bytes(case["bytes"])
    instructions = tuple(project.arch.capstone.disasm(raw, linear_ip, 1))
    if len(instructions) == 1 and instructions[0].size > 0:
        return raw[: instructions[0].size]
    prefix_bytes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
    prefix_end = 0
    while prefix_end < len(raw) and raw[prefix_end] in prefix_bytes:
        prefix_end += 1
    lock_count = raw[:prefix_end].count(0xF0)
    if lock_count:
        without_lock = bytes(byte for index, byte in enumerate(raw) if index >= prefix_end or byte != 0xF0)
        decoded = tuple(project.arch.capstone.disasm(without_lock, linear_ip, 1))
        if len(decoded) == 1 and decoded[0].size > 0:
            return raw[: decoded[0].size + lock_count]
    if prefix_end + 1 < len(raw) and raw[prefix_end] == 0x8F and ((raw[prefix_end + 1] >> 3) & 7) != 0:
        sanitized = bytearray(raw)
        sanitized[prefix_end + 1] &= 0xC7
        decoded = tuple(project.arch.capstone.disasm(bytes(sanitized), linear_ip, 1))
        if len(decoded) == 1 and decoded[0].size > 0:
            return raw[: decoded[0].size]
    raise ValueError("80386 hardware case does not decode exactly one instruction")


def _instruction_is_hlt_80386(instruction: bytes) -> bool:
    """Return whether the decoded test instruction itself is HLT."""
    prefix_bytes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
    opcode_index = 0
    while opcode_index < len(instruction) and instruction[opcode_index] in prefix_bytes:
        opcode_index += 1
    return opcode_index < len(instruction) and instruction[opcode_index] == 0xF4


def _verified_invalid_lock_fault_80386(
    case: dict[str, Any], instruction: bytes, project: angr.Project
) -> bool | None:
    """Verify an invalid LOCK encoding and its hardware vector-6 entry."""
    prefix_end = 0
    prefix_bytes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
    while prefix_end < len(instruction) and instruction[prefix_end] in prefix_bytes:
        prefix_end += 1
    invalid_pop_extension = (
        prefix_end + 1 < len(instruction)
        and instruction[prefix_end] == 0x8F
        and ((instruction[prefix_end + 1] >> 3) & 7) != 0
    )
    if 0xF0 not in instruction[:prefix_end] and not invalid_pop_extension:
        return None
    initial_regs = case["initial"]["regs"]
    linear_ip = ((int(initial_regs["cs"]) & 0xFFFF) << 4) + (int(initial_regs["eip"]) & 0xFFFF)
    if tuple(project.arch.capstone.disasm(instruction, linear_ip, 1)):
        return None

    final_regs = case["final"].get("regs", {})
    initial_ram = dict(case["initial"].get("ram", []))
    vector_base = 6 * 4
    if not all(vector_base + offset in initial_ram for offset in range(4)):
        return False
    vector_ip = initial_ram[vector_base] | initial_ram[vector_base + 1] << 8
    vector_cs = initial_ram[vector_base + 2] | initial_ram[vector_base + 3] << 8
    final_sp = int(final_regs.get("esp", -1)) & 0xFFFF
    stack_base = (int(initial_regs["ss"]) << 4) + final_sp
    frame_values = (
        int(initial_regs["eip"]) & 0xFFFF,
        int(initial_regs["cs"]) & 0xFFFF,
        int(initial_regs["eflags"]) & 0xFFFF,
    )
    expected_frame = [byte for value in frame_values for byte in value.to_bytes(2, "little")]
    final_ram = dict(case["final"].get("ram", []))
    return (
        ((int(final_regs.get("eip", -1)) - 1) & 0xFFFF) == vector_ip
        and int(final_regs.get("cs", -1)) == vector_cs
        and final_sp == ((int(initial_regs["esp"]) - 6) & 0xFFFF)
        and all(final_ram.get(stack_base + offset) == byte for offset, byte in enumerate(expected_frame))
    )


def _verified_register_divide_error_80386(case: dict[str, Any], instruction: bytes) -> bool | None:
    """Verify a hardware vector-0 witness for a register unsigned-DIV fault."""
    index = 0
    operand_bits = 16
    while index < len(instruction) and instruction[index] in {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0}:
        if instruction[index] == 0x66:
            operand_bits = 32
        index += 1
    if index + 1 >= len(instruction) or instruction[index] != 0xF7:
        return None
    modrm = instruction[index + 1]
    if (modrm >> 6) != 3 or ((modrm >> 3) & 7) != 6:
        return None

    registers = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
    mask = (1 << operand_bits) - 1
    initial_regs = case["initial"]["regs"]
    final_regs = case["final"].get("regs", {})
    divisor = int(initial_regs[registers[modrm & 7]]) & mask
    high_half = int(initial_regs["edx"]) & mask
    modeled_fault = divisor == 0 or high_half >= divisor

    initial_ram = dict(case["initial"].get("ram", []))
    if not all(address in initial_ram for address in range(4)):
        return False
    vector_ip = int(initial_ram[0]) | (int(initial_ram[1]) << 8)
    vector_cs = int(initial_ram[2]) | (int(initial_ram[3]) << 8)
    hardware_fault = (
        ((int(final_regs.get("eip", -1)) - 1) & 0xFFFFFFFF) == vector_ip
        and int(final_regs.get("cs", -1)) == vector_cs
        and (int(final_regs.get("esp", -1)) & 0xFFFF) == ((int(initial_regs["esp"]) - 6) & 0xFFFF)
        and int(final_regs.get("eax", initial_regs["eax"])) == int(initial_regs["eax"])
        and int(final_regs.get("edx", initial_regs["edx"])) == int(initial_regs["edx"])
    )
    return modeled_fault and hardware_fault


def _verified_real_mode_segment_limit_fault_80386(
    case: dict[str, Any], instruction: bytes, project: angr.Project
) -> bool | None:
    """Verify a hardware #SS/#GP witness for any explicit address32 memory operand."""
    prefix_index = 0
    address_bits = 16
    while prefix_index < len(instruction) and instruction[prefix_index] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0x67,
        0xF0,
        0xF2,
        0xF3,
    }:
        if instruction[prefix_index] == 0x67:
            address_bits = 32
        prefix_index += 1
    decoded = list(project.arch.capstone.disasm(instruction, int(case["initial"]["regs"]["eip"]) & 0xFFFF, 1))
    if len(decoded) != 1 or decoded[0].size != len(instruction):
        return None
    if decoded[0].mnemonic == "lea":
        return None
    initial_regs = case["initial"]["regs"]

    def address_register_value(name: str) -> int:
        """Read a Capstone address-register name from the hardware register state."""
        if name in initial_regs:
            return int(initial_regs[name])
        if name in {"ax", "bx", "cx", "dx", "si", "di", "bp", "sp"}:
            return int(initial_regs[f"e{name}"]) & 0xFFFF
        return 0

    modeled_fault = False
    for operand in decoded[0].operands:
        if operand.type != 3:
            continue
        memory = operand.mem
        base_name = decoded[0].reg_name(memory.base) if memory.base else ""
        index_name = decoded[0].reg_name(memory.index) if memory.index else ""
        base = address_register_value(base_name)
        index = address_register_value(index_name)
        address_mask = 0xFFFFFFFF if address_bits == 32 else 0xFFFF
        effective_offset = (base + index * int(memory.scale) + int(memory.disp)) & address_mask
        operand_bytes = max(int(operand.size), 1)
        modeled_fault |= effective_offset > 0x10000 - operand_bytes
    if not modeled_fault:
        return None

    initial_ram = dict(case["initial"].get("ram", []))
    final_regs = case["final"].get("regs", {})
    matching_vector = None
    for vector in (12, 13):
        vector_base = vector * 4
        if not all(vector_base + offset in initial_ram for offset in range(4)):
            continue
        vector_ip = initial_ram[vector_base] | initial_ram[vector_base + 1] << 8
        vector_cs = initial_ram[vector_base + 2] | initial_ram[vector_base + 3] << 8
        if (
            ((int(final_regs.get("eip", -1)) - 1) & 0xFFFF) == vector_ip
            and int(final_regs.get("cs", -1)) == vector_cs
        ):
            matching_vector = vector
            break
    if matching_vector is None:
        return False
    final_sp = int(final_regs.get("esp", -1)) & 0xFFFF
    stack_base = (int(initial_regs["ss"]) << 4) + final_sp
    frame_values = (
        int(initial_regs["eip"]) & 0xFFFF,
        int(initial_regs["cs"]) & 0xFFFF,
        int(initial_regs["eflags"]) & 0xFFFF,
    )
    expected_frame = [byte for value in frame_values for byte in value.to_bytes(2, "little")]
    final_ram = dict(case["final"].get("ram", []))
    hardware_fault = (
        final_sp == ((int(initial_regs["esp"]) - 6) & 0xFFFF)
        and int(final_regs.get("ss", initial_regs["ss"])) == int(initial_regs["ss"])
        and all(final_ram.get(stack_base + offset) == byte for offset, byte in enumerate(expected_frame))
    )
    return modeled_fault and hardware_fault


def _verified_bound_fault_80386(
    case: dict[str, Any], instruction: bytes, project: angr.Project, state: angr.SimState
) -> bool | None:
    """Verify a selected BOUND exit and its hardware vector-5 exception frame."""
    initial_regs = case["initial"]["regs"]
    linear_ip = ((int(initial_regs["cs"]) & 0xFFFF) << 4) + (int(initial_regs["eip"]) & 0xFFFF)
    decoded = tuple(project.arch.capstone.disasm(instruction, linear_ip, 1))
    if len(decoded) != 1 or decoded[0].mnemonic != "bound":
        return None

    initial_ram = dict(case["initial"].get("ram", []))
    final_ram = dict(case["final"].get("ram", []))
    final_regs = case["final"].get("regs", {})
    vector_base = 5 * 4
    if not all(vector_base + offset in initial_ram for offset in range(4)):
        return None
    vector_ip = initial_ram[vector_base] | initial_ram[vector_base + 1] << 8
    vector_cs = initial_ram[vector_base + 2] | initial_ram[vector_base + 3] << 8
    hardware_fault = (
        ((int(final_regs.get("eip", -1)) - 1) & 0xFFFF) == vector_ip
        and int(final_regs.get("cs", -1)) == vector_cs
    )
    if not hardware_fault:
        return None

    selected = _step_with_lock_retry(project, state, instruction, advance_ip_for_stripped_lock=True)
    modeled_fault = selected.addr == 0xF005 and selected.history.jumpkind == "Ijk_Call"
    final_sp = int(final_regs.get("esp", -1)) & 0xFFFF
    expected_sp = (int(initial_regs["esp"]) - 6) & 0xFFFF
    stack_base = (int(initial_regs["ss"]) << 4) + final_sp

    def frame_word(offset: int) -> int:
        """Read one captured little-endian exception-frame word."""
        low_addr = stack_base + offset
        high_addr = stack_base + offset + 1
        low = final_ram.get(low_addr, initial_ram.get(low_addr, -1))
        high = final_ram.get(high_addr, initial_ram.get(high_addr, -1))
        if low is None or high is None:
            return -1
        return int(low) | int(high) << 8

    frame_matches = (
        final_sp == expected_sp
        and frame_word(0) == (int(initial_regs["eip"]) & 0xFFFF)
        and frame_word(2) == (int(initial_regs["cs"]) & 0xFFFF)
        and frame_word(4) == (int(initial_regs["eflags"]) & 0xFFFF)
    )
    return modeled_fault and frame_matches


def _verified_software_interrupt_80386(
    case: dict[str, Any], instruction: bytes, project: angr.Project, state: angr.SimState
) -> bool | None:
    """Verify an INT/INT3 synthetic exit against its hardware IVT entry and frame."""
    prefix_index = 0
    prefix_bytes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
    while prefix_index < len(instruction) and instruction[prefix_index] in prefix_bytes:
        prefix_index += 1
    if prefix_index >= len(instruction) or instruction[prefix_index] not in {0xCC, 0xCD}:
        return None
    opcode = instruction[prefix_index]
    if opcode == 0xCD and prefix_index + 1 >= len(instruction):
        return False
    vector = 3 if opcode == 0xCC else instruction[prefix_index + 1]

    initial_regs = case["initial"]["regs"]
    initial_ram = dict(case["initial"].get("ram", []))
    final_ram = dict(case["final"].get("ram", []))
    final_regs = case["final"].get("regs", {})
    vector_base = vector * 4
    if not all(vector_base + offset in initial_ram for offset in range(4)):
        return False
    vector_ip = initial_ram[vector_base] | initial_ram[vector_base + 1] << 8
    vector_cs = initial_ram[vector_base + 2] | initial_ram[vector_base + 3] << 8
    hardware_entry = (
        ((int(final_regs.get("eip", -1)) - 1) & 0xFFFF) == vector_ip
        and int(final_regs.get("cs", -1)) == vector_cs
    )
    selected = _step_with_lock_retry(project, state, instruction, advance_ip_for_stripped_lock=True)
    modeled_entry = selected.addr == (0xF000 | vector) and selected.history.jumpkind == "Ijk_Call"
    final_sp = int(final_regs.get("esp", -1)) & 0xFFFF
    stack_base = (int(initial_regs["ss"]) << 4) + final_sp

    def frame_word(offset: int) -> int:
        """Read one captured little-endian software-interrupt frame word."""
        low_addr = stack_base + offset
        high_addr = stack_base + offset + 1
        low = final_ram.get(low_addr, initial_ram.get(low_addr, -1))
        high = final_ram.get(high_addr, initial_ram.get(high_addr, -1))
        if low is None or high is None:
            return -1
        return int(low) | int(high) << 8

    frame_matches = (
        final_sp == ((int(initial_regs["esp"]) - 6) & 0xFFFF)
        and frame_word(0) == ((int(initial_regs["eip"]) + len(instruction)) & 0xFFFF)
        and frame_word(2) == (int(initial_regs["cs"]) & 0xFFFF)
        and frame_word(4) == (int(initial_regs["eflags"]) & 0xFFFF)
    )
    return modeled_entry and hardware_entry and frame_matches


def verify_straightline_case_80386(
    case: dict[str, Any],
    *,
    opcode: str,
    project: angr.Project | None = None,
) -> CaseResult:
    """Verify one non-faulting, non-control-flow 80386 case against hardware state."""
    local_project = _make_project() if project is None else project
    result = CaseResult(opcode=opcode, idx=case["idx"], name=case["name"], hash=case.get("hash"), passed=False)
    try:
        initial_regs = case["initial"]["regs"]
        final_regs = case["final"].get("regs", {})
        state = local_project.factory.blank_state(
            addr=int(initial_regs["eip"]) & 0xFFFF,
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        for register, value in initial_regs.items():
            if register in local_project.arch.registers:
                _state_reg_set_8616(state, register, int(value))
        for address, byte in case["initial"].get("ram", []):
            state.memory.store(int(address), bytes([int(byte)]))

        instruction = _instruction_bytes_80386(case, local_project)
        invalid_lock_verified = _verified_invalid_lock_fault_80386(case, instruction, local_project)
        if invalid_lock_verified is not None:
            result.passed = invalid_lock_verified
            if not invalid_lock_verified:
                result.error = "Invalid LOCK fault did not match the hardware vector-6 witness"
            return result
        divide_error_verified = _verified_register_divide_error_80386(case, instruction)
        if divide_error_verified is not None:
            result.passed = divide_error_verified
            if not divide_error_verified:
                result.error = "Register DIV fault did not match the hardware vector-0 witness"
            return result
        segment_fault_verified = _verified_real_mode_segment_limit_fault_80386(case, instruction, local_project)
        if segment_fault_verified is not None:
            result.passed = segment_fault_verified
            if not segment_fault_verified:
                result.error = "Real-mode segment-limit fault did not match the hardware vector-13 witness"
            return result
        bound_fault_verified = _verified_bound_fault_80386(case, instruction, local_project, state)
        if bound_fault_verified is not None:
            result.passed = bound_fault_verified
            if not bound_fault_verified:
                result.error = "BOUND fault did not match the hardware vector-5 witness"
            return result
        interrupt_verified = _verified_software_interrupt_80386(case, instruction, local_project, state)
        if interrupt_verified is not None:
            result.passed = interrupt_verified
            if not interrupt_verified:
                result.error = "Software interrupt did not match its hardware IVT witness"
            return result
        start_addr = state.addr
        repeat_count = _repeat_count_80386(case, instruction)
        if repeat_count == 0:
            state.regs.ip = (_solver_eval_int_8616(state, state.regs.ip) + len(instruction)) & 0xFFFF
        else:
            state = _step_with_lock_retry(local_project, state, instruction, advance_ip_for_stripped_lock=True)
            iterations = 1
            while repeat_count is not None and state.addr == start_addr and iterations < repeat_count:
                state = _step_with_lock_retry(local_project, state, instruction, advance_ip_for_stripped_lock=True)
                iterations += 1
        eflags_mask = _defined_eflags_mask_80386(case)
        mismatches: list[CaseMismatch] = []
        for register, initial_value in initial_regs.items():
            if register in _UNMODELED_DEBUG_REGISTERS:
                if register in final_regs and int(final_regs[register]) != int(initial_value):
                    mismatches.append(
                        CaseMismatch("unsupported_reg", register, int(final_regs[register]), int(initial_value))
                    )
                continue
            if register not in local_project.arch.registers:
                mismatches.append(CaseMismatch("unsupported_reg", register, int(initial_value), 0))
                continue
            expected = int(final_regs.get(register, initial_value))
            if register == "eip" and register in final_regs and not _instruction_is_hlt_80386(instruction):
                expected = (expected - 1) & 0xFFFFFFFF
            actual = _solver_eval_int_8616(state, _state_reg_expr_8616(state, register))
            if register == "eflags":
                expected &= eflags_mask
                actual &= eflags_mask
            if actual != expected:
                mismatches.append(CaseMismatch("reg", register, expected, actual))

        initial_ram = dict(case["initial"].get("ram", []))
        final_ram = dict(case["final"].get("ram", []))
        for address in sorted(set(initial_ram) | set(final_ram)):
            expected = int(final_ram[address] if address in final_ram else initial_ram[address])
            actual = _concrete_byte(state, int(address))
            if actual != expected:
                mismatches.append(CaseMismatch("mem", f"{address:#x}", expected, actual, address=int(address)))
        result.mismatches = mismatches
        result.passed = not mismatches
    except Exception as ex:  # Third-party angr/pyvex execution boundary.
        result.error = f"{type(ex).__name__}: {ex}"
    return result
