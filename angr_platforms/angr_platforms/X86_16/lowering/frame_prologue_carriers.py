"""Classify exact canonical x86-16 frame-prologue C AST carriers.

Layer: Types/Lowering.
Responsibility: prove the paired ``SP -= 2`` and ``SS:SP = BP`` carriers of a
decoded ``push bp`` before Lowering consumes compiler frame scaffolding.
Consumes alias, widening, and typed facts plus exact physical register views.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimStackVariable
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_SP,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .physical_registers import physical_register_offset_8616, physical_register_view_8616


class _ArchitectureRegisters8616(Protocol):
    """Architecture register contracts required by frame classification."""

    registers: Mapping[str, tuple[int, int]]


class _ProjectRegisters8616(Protocol):
    """Project surface required by frame classification."""

    arch: _ArchitectureRegisters8616


class _CapstoneOperand8616(Protocol):
    """Capstone register operand fields consumed by frame classification."""

    type: int
    reg: int


class _CapstoneInstruction8616(Protocol):
    """Capstone instruction fields consumed by frame classification."""

    address: int
    id: int
    operands: Sequence[_CapstoneOperand8616]
    size: int


class _CapstoneWrapper8616(Protocol):
    """angr wrapper field exposing the underlying Capstone instruction."""

    insn: _CapstoneInstruction8616


def _unwrap_casts_8616(value: object) -> object:
    """Remove type-only wrappers from one structured expression."""
    while isinstance(value, CTypeCast):
        value = value.expr
    return value


def _constant_8616(value: object) -> int | None:
    """Return one explicit structured integer constant."""
    value = _unwrap_casts_8616(value)
    return value.value if isinstance(value, CConstant) and isinstance(value.value, int) else None


def _matches_register_8616(
    value: object,
    project: _ProjectRegisters8616,
    register_name: str,
) -> bool:
    """Return whether one carrier exactly covers the named physical register."""
    expected = project.arch.registers.get(register_name)
    view = physical_register_view_8616(_unwrap_casts_8616(value))
    return view is not None and expected is not None and (view.reg_offset, view.width) == expected


def _statement_addr_8616(statement: CAssignment) -> int | None:
    """Return the exact machine instruction tag on one structured assignment."""
    value = statement.tags.get("ins_addr")
    return value if isinstance(value, int) else None


def _is_entry_sp_decrement_8616(
    statement: object,
    project: _ProjectRegisters8616,
    function_addr: int,
) -> bool:
    """Match the exact ``SP = SP - 2`` carrier emitted for ``push bp``."""
    if not isinstance(statement, CAssignment) or _statement_addr_8616(statement) != function_addr:
        return False
    rhs = _unwrap_casts_8616(statement.rhs)
    return (
        _matches_register_8616(statement.lhs, project, "sp")
        and isinstance(rhs, CBinaryOp)
        and rhs.op == "Sub"
        and _matches_register_8616(rhs.lhs, project, "sp")
        and _constant_8616(rhs.rhs) == 2
    )


def _entry_ss_sp_displacement_8616(
    value: object,
    project: _ProjectRegisters8616,
) -> int | None:
    """Return displacement for an exact ``SS:SP+constant`` dereference."""
    value = _unwrap_casts_8616(value)
    if not isinstance(value, CUnaryOp) or value.op != "Dereference":
        return None

    def flatten(term: object, sign: int = 1) -> list[tuple[object, int]]:
        """Flatten structured addition and subtraction without rendering text."""
        term = _unwrap_casts_8616(term)
        if isinstance(term, CBinaryOp) and term.op == "Add":
            return flatten(term.lhs, sign) + flatten(term.rhs, sign)
        if isinstance(term, CBinaryOp) and term.op == "Sub":
            return flatten(term.lhs, sign) + flatten(term.rhs, -sign)
        return [(term, sign)]

    displacement = 0
    ss_terms = 0
    sp_terms = 0
    for term, sign in flatten(value.operand):
        constant = _constant_8616(term)
        if constant is not None:
            displacement += sign * constant
            continue
        term = _unwrap_casts_8616(term)
        if isinstance(term, CBinaryOp) and term.op in {"Mul", "Shl"} and sign == 1:
            scale = 16 if term.op == "Mul" else 4
            if (
                _matches_register_8616(term.lhs, project, "ss")
                and _constant_8616(term.rhs) == scale
            ) or (
                _matches_register_8616(term.rhs, project, "ss")
                and _constant_8616(term.lhs) == scale
            ):
                ss_terms += 1
                continue
        if sign == 1 and _matches_register_8616(term, project, "sp"):
            sp_terms += 1
            continue
        return None
    return displacement if ss_terms == 1 and sp_terms == 1 else None


def is_exact_push_bp_store_carrier_8616(
    statement: object,
    root: object,
    project: _ProjectRegisters8616,
    function_addr: int,
) -> bool:
    """Prove one saved-BP store using its exact paired SP decrement carrier."""
    if not isinstance(statement, CAssignment) or _statement_addr_8616(statement) != function_addr:
        return False
    if not _matches_register_8616(statement.rhs, project, "bp"):
        return False
    if _entry_ss_sp_displacement_8616(statement.lhs, project) != -2:
        return False
    return any(
        _is_entry_sp_decrement_8616(node, project, function_addr)
        for node in _iter_c_nodes_deep_8616(root)
    )


def is_exact_push_bp_carrier_8616(
    statement: object,
    root: object,
    project: _ProjectRegisters8616,
    function_addr: int,
) -> bool:
    """Prove one stack-update or saved-BP carrier of the entry ``push bp``."""
    if _is_entry_sp_decrement_8616(
        statement,
        project,
        function_addr,
    ) or is_exact_push_bp_store_carrier_8616(
        statement,
        root,
        project,
        function_addr,
    ):
        return True
    if not isinstance(statement, CAssignment) or _statement_addr_8616(statement) != function_addr:
        return False
    lhs = statement.lhs
    if not (
        isinstance(lhs, CVariable)
        and isinstance(lhs.variable, SimStackVariable)
        and lhs.variable.base == "bp"
    ):
        return False
    rhs = statement.rhs
    if isinstance(rhs, CDirtyExpression):
        expected_bp = project.arch.registers.get("bp")
        if (
            expected_bp is not None
            and lhs.variable.size == expected_bp[1]
            and physical_register_offset_8616(rhs) == expected_bp[0]
        ):
            return True
    if not isinstance(rhs, CUnaryOp) or rhs.op not in {"Reference", "AddressOf"}:
        return False
    anchor = rhs.operand
    return (
        isinstance(anchor, CVariable)
        and isinstance(anchor.variable, SimStackVariable)
        and anchor.variable.base == "bp"
        and anchor.variable.offset == 0
    )


def _instruction_8616(value: object) -> _CapstoneInstruction8616:
    """Unwrap one angr Capstone wrapper at the third-party boundary."""
    wrapper = cast(_CapstoneWrapper8616, value)
    try:
        return wrapper.insn
    except AttributeError:
        return cast(_CapstoneInstruction8616, value)


def _instruction_registers_8616(value: object) -> tuple[int, ...] | None:
    """Return exact register operands for one decoded instruction."""
    instruction = _instruction_8616(value)
    try:
        operands = tuple(instruction.operands)
    except (AttributeError, TypeError):
        return None
    if any(operand.type != X86_OP_REG for operand in operands):
        return None
    return tuple(int(operand.reg) for operand in operands)


def _instruction_end_8616(value: object) -> int | None:
    """Return the exclusive address of one decoded instruction."""
    instruction = _instruction_8616(value)
    try:
        address = instruction.address
        size = instruction.size
    except AttributeError:
        return None
    return address + size if isinstance(address, int) and isinstance(size, int) and size > 0 else None


def canonical_frame_instruction_addresses_8616(
    instructions_by_addr: Mapping[int, object],
    function_addr: int,
) -> frozenset[int]:
    """Return exact decoded entry and teardown addresses for a BP frame.

    The entry pair is mandatory. Teardown addresses are admitted only as a
    contiguous ``mov sp, bp; pop bp; ret`` sequence. This function classifies
    binary instruction ownership; callers must separately prove that the C AST
    contains a matching ``push bp`` carrier before consuming assignments.
    """
    push = _instruction_8616(instructions_by_addr.get(function_addr))
    try:
        push_id = push.id
    except AttributeError:
        return frozenset()
    push_end = _instruction_end_8616(push)
    if (
        push_id != X86_INS_PUSH
        or _instruction_registers_8616(push) != (X86_REG_BP,)
        or push_end is None
    ):
        return frozenset()
    frame_setup = _instruction_8616(instructions_by_addr.get(push_end))
    try:
        setup_id = frame_setup.id
    except AttributeError:
        return frozenset()
    if setup_id != X86_INS_MOV or _instruction_registers_8616(frame_setup) != (
        X86_REG_BP,
        X86_REG_SP,
    ):
        return frozenset()

    addresses = {function_addr, push_end}
    for address, raw_instruction in instructions_by_addr.items():
        instruction = _instruction_8616(raw_instruction)
        try:
            instruction_id = instruction.id
        except AttributeError:
            continue
        if instruction_id != X86_INS_MOV or _instruction_registers_8616(instruction) != (
            X86_REG_SP,
            X86_REG_BP,
        ):
            continue
        pop_addr = _instruction_end_8616(instruction)
        if pop_addr is None:
            continue
        pop = _instruction_8616(instructions_by_addr.get(pop_addr))
        try:
            pop_id = pop.id
        except AttributeError:
            continue
        if pop_id != X86_INS_POP or _instruction_registers_8616(pop) != (X86_REG_BP,):
            continue
        ret_addr = _instruction_end_8616(pop)
        if ret_addr is None:
            continue
        ret = _instruction_8616(instructions_by_addr.get(ret_addr))
        try:
            ret_id = ret.id
        except AttributeError:
            continue
        if ret_id == X86_INS_RET:
            addresses.update((address, pop_addr, ret_addr))
    return frozenset(addresses)


__all__ = [
    "canonical_frame_instruction_addresses_8616",
    "is_exact_push_bp_carrier_8616",
    "is_exact_push_bp_store_carrier_8616",
]
