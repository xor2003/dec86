"""Rebind exact balanced PUSH/POP transfers across caller-neutral calls.

Layer: Types/Lowering.
Responsibility: consume decoded memory-save instruction identity and rebind a
post-call POP projection to the exact value written by its paired PUSH. Memory
save pairs retain one stack object; immediate/register pairs materialize one
coherent architectural GP write. This pass refuses branching, mismatched
operands, and ambiguous C projections.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.

Dynamic boundary: decoded instructions, Capstone operands, and angr project,
function, and codegen objects expose third-party compatibility attributes.
"""

from __future__ import annotations

import copy
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.errors import SimEngineError
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from capstone.x86_const import (
    X86_GRP_JUMP,
    X86_GRP_RET,
    X86_INS_CALL,
    X86_INS_LCALL,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from .gp_register_state import (
    runtime_gp_live_in_name_8616,
    runtime_gp_name_for_variable_8616,
    runtime_gp_state_assignment_8616,
    runtime_gp_state_expr_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_word_recomposition import recognize_stack_word_recomposition_8616

__all__ = [
    "BalancedImmediateRegisterRestoreStats8616",
    "BalancedMemoryStackRestoreStats8616",
    "materialize_balanced_immediate_register_restores_8616",
    "rebind_balanced_memory_stack_restores_8616",
]

type _DynamicValue8616 = Any
type _MemoryOperandKey8616 = tuple[int, int, int, int, int, int]

log: logging.Logger = logging.getLogger(__name__)


class _CFunctionSurface8616(Protocol):
    """Structured function fields consumed by balanced restore lowering."""

    addr: int
    statements: object


class _CodegenSurface8616(Protocol):
    """Owned codegen extension used by balanced restore lowering."""

    cfunc: _CFunctionSurface8616 | None
    _inertia_balanced_immediate_register_restore_stats_8616: BalancedImmediateRegisterRestoreStats8616
    _inertia_balanced_memory_stack_restore_stats_8616: BalancedMemoryStackRestoreStats8616


@dataclass(frozen=True, slots=True)
class BalancedMemoryStackRestoreStats8616:
    """Closed evidence census for exact memory PUSH/POP stack rebinding."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class BalancedImmediateRegisterRestoreStats8616:
    """Closed evidence census for exact immediate PUSH/register POP transfers."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class _ImmediateRegisterTransfer8616:
    """One decoded caller-neutral immediate PUSH/register POP transfer."""

    push_addr: int
    pop_addr: int
    value: int
    register_name: str
    width: int


def _instruction_stream_8616(function: object) -> tuple[_DynamicValue8616, ...]:
    """Return one deterministic instruction stream, refusing duplicate addresses."""
    instructions: dict[int, _DynamicValue8616] = {}
    try:
        blocks = tuple(cast(_DynamicValue8616, function).blocks or ())
    except (AttributeError, TypeError):
        return ()
    for block in blocks:
        try:
            wrappers = tuple(cast(_DynamicValue8616, block).capstone.insns or ())
        except (AttributeError, TypeError):
            return ()
        for wrapper in wrappers:
            instruction = getattr(wrapper, "insn", wrapper)
            address = getattr(instruction, "address", None)
            if not isinstance(address, int) or isinstance(address, bool):
                return ()
            prior = instructions.get(address)
            if prior is not None:
                if getattr(prior, "id", None) != getattr(instruction, "id", None):
                    return ()
                continue
            instructions[address] = instruction
    return tuple(instructions[address] for address in sorted(instructions))


def _memory_operand_key_8616(instruction: object) -> _MemoryOperandKey8616 | None:
    """Return an exact one-operand x86 memory identity and width."""
    try:
        operands = tuple(cast(_DynamicValue8616, instruction).operands or ())
    except (AttributeError, TypeError):
        return None
    if len(operands) != 1 or getattr(operands[0], "type", None) != X86_OP_MEM:
        return None
    operand = operands[0]
    memory = getattr(operand, "mem", None)
    size = getattr(operand, "size", None)
    values = (
        getattr(memory, "segment", None),
        getattr(memory, "base", None),
        getattr(memory, "index", None),
        getattr(memory, "scale", None),
        getattr(memory, "disp", None),
        size,
    )
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in values):
        return None
    return cast(_MemoryOperandKey8616, values)


def _register_operand_width_8616(instruction: object) -> int | None:
    """Return the exact width of one register-only stack operand."""
    try:
        operands = tuple(cast(_DynamicValue8616, instruction).operands or ())
    except (AttributeError, TypeError):
        return None
    if len(operands) != 1 or getattr(operands[0], "type", None) != X86_OP_REG:
        return None
    width = getattr(operands[0], "size", None)
    return width if isinstance(width, int) and not isinstance(width, bool) and width in {2, 4} else None


def _balanced_pairs_8616(
    instructions: Iterable[object],
) -> tuple[tuple[int, int, int | None], ...]:
    """Pair exact LIFO memory saves and register transfers across calls."""
    stack: list[tuple[int, _MemoryOperandKey8616 | None, int | None]] = []
    pairs: list[tuple[int, int, int | None]] = []
    for instruction in instructions:
        instruction_id = getattr(instruction, "id", None)
        address = getattr(instruction, "address", None)
        if not isinstance(address, int):
            return ()
        if instruction_id in {X86_INS_CALL, X86_INS_LCALL}:
            continue
        if instruction_id == X86_INS_PUSH:
            stack.append(
                (
                    address,
                    _memory_operand_key_8616(instruction),
                    _register_operand_width_8616(instruction),
                )
            )
            continue
        if instruction_id != X86_INS_POP:
            groups = frozenset(getattr(instruction, "groups", ()) or ())
            if groups & {X86_GRP_JUMP, X86_GRP_RET}:
                # End only the current straight-line pairing window. Later
                # address-ordered windows may still contain exact local pairs.
                stack.clear()
            continue
        if not stack:
            return ()
        push_addr, push_key, push_register_width = stack.pop()
        pop_key = _memory_operand_key_8616(instruction)
        if push_key is not None and push_key == pop_key:
            pairs.append((push_addr, address, push_key[-1]))
            continue
        pop_register_width = _register_operand_width_8616(instruction)
        if push_register_width is not None and push_register_width == pop_register_width:
            pairs.append((push_addr, address, push_register_width))
    return tuple(pairs)


def _balanced_immediate_register_transfers_8616(
    instructions: Iterable[object],
) -> tuple[_ImmediateRegisterTransfer8616, ...]:
    """Pair exact LIFO immediate/register transfers in straight-line windows."""
    stack: list[tuple[int, int | None, int | None]] = []
    transfers: list[_ImmediateRegisterTransfer8616] = []
    for instruction in instructions:
        instruction_id = getattr(instruction, "id", None)
        address = getattr(instruction, "address", None)
        if not isinstance(address, int):
            return ()
        try:
            operands = tuple(cast(_DynamicValue8616, instruction).operands or ())
        except (AttributeError, TypeError):
            return ()
        if instruction_id in {X86_INS_CALL, X86_INS_LCALL}:
            continue
        if instruction_id == X86_INS_PUSH:
            if len(operands) == 1 and getattr(operands[0], "type", None) == X86_OP_IMM:
                immediate = getattr(operands[0], "imm", None)
                width = getattr(operands[0], "size", None)
                stack.append(
                    (
                        address,
                        immediate if isinstance(immediate, int) else None,
                        width if isinstance(width, int) and width > 0 else None,
                    )
                )
            else:
                stack.append((address, None, None))
            continue
        if instruction_id == X86_INS_POP:
            if not stack:
                return ()
            push_addr, immediate, immediate_width = stack.pop()
            if len(operands) != 1 or getattr(operands[0], "type", None) != X86_OP_REG:
                continue
            register_id = getattr(operands[0], "reg", None)
            width = getattr(operands[0], "size", None)
            if (
                immediate is None
                or immediate_width is None
                or not isinstance(register_id, int)
                or not isinstance(width, int)
                or width not in {2, 4}
                or immediate_width > width
            ):
                continue
            try:
                register_name = str(cast(_DynamicValue8616, instruction).reg_name(register_id)).lower()
            except (AttributeError, TypeError, ValueError):
                continue
            if runtime_gp_live_in_name_8616(register_name) is None:
                continue
            immediate_mask = (1 << (immediate_width * 8)) - 1
            normalized = immediate & immediate_mask
            if immediate_width < width and normalized & (1 << (immediate_width * 8 - 1)):
                normalized -= 1 << (immediate_width * 8)
            transfers.append(
                _ImmediateRegisterTransfer8616(
                    push_addr=push_addr,
                    pop_addr=address,
                    value=normalized & ((1 << (width * 8)) - 1),
                    register_name=register_name,
                    width=width,
                )
            )
            continue
        groups = frozenset(getattr(instruction, "groups", ()) or ())
        if groups & {X86_GRP_JUMP, X86_GRP_RET}:
            stack.clear()
    return tuple(transfers)


def _register_cvar_matches_8616(
    node: object,
    *,
    register_offset: int,
    width: int,
) -> bool:
    """Return whether one C variable is the exact decoded register view."""
    return (
        isinstance(node, structured_c.CVariable)
        and isinstance(node.variable, SimRegisterVariable)
        and node.variable.reg == register_offset
        and node.variable.size == width
    )


def _assignment_writes_stack_pointer_8616(
    statement: object,
    registers: dict[str, tuple[int, int]],
) -> bool:
    """Return whether one assignment owns the decoded POP stack increment."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    lhs = statement.lhs
    if not isinstance(lhs, structured_c.CVariable):
        return False
    if runtime_gp_name_for_variable_8616(lhs.variable) == "esp":
        return True
    if not isinstance(lhs.variable, SimRegisterVariable):
        return False
    shapes = {
        shape
        for name, shape in registers.items()
        if name.lower() in {"sp", "esp"} and isinstance(shape, tuple) and len(shape) >= 2
    }
    return (lhs.variable.reg, lhs.variable.size) in shapes


def materialize_balanced_immediate_register_restores_8616(
    codegen: object,
    function: object | None,
    *,
    project: object | None = None,
) -> bool:
    """Materialize exact immediate PUSH/register POP transfers into GP state."""
    surface = cast(_CodegenSurface8616, codegen)
    cfunc = surface.cfunc
    empty = BalancedImmediateRegisterRestoreStats8616(0, 0, 0, 0, 0)
    if cfunc is None or function is None or not isinstance(cfunc.statements, structured_c.CStatements):
        surface._inertia_balanced_immediate_register_restore_stats_8616 = empty
        return False
    if project is None:
        project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    registers = getattr(arch, "registers", None)
    if not isinstance(registers, dict):
        surface._inertia_balanced_immediate_register_restore_stats_8616 = empty
        return False
    transfers = _balanced_immediate_register_transfers_8616(_instruction_stream_8616(function))
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-register-restore] function=%#x transfers=%s",
            cfunc.addr,
            transfers,
        )
    classified = 0
    materialized = 0
    changed = False
    containers = tuple(
        {
            id(node): node
            for node in (cfunc.statements, *_iter_c_nodes_deep_8616(cfunc.statements))
            if isinstance(node, structured_c.CStatements)
        }.values()
    )
    for transfer in transfers:
        shape = registers.get(transfer.register_name)
        if not isinstance(shape, tuple) or len(shape) < 2 or shape[1] != transfer.width:
            continue
        register_offset = shape[0]
        if not isinstance(register_offset, int):
            continue
        matches: list[tuple[structured_c.CStatements, int]] = []
        for container in containers:
            for index, statement in enumerate(tuple(container.statements)):
                addresses = (
                    _statement_instruction_addrs_8616(statement)
                    if isinstance(statement, structured_c.CAssignment)
                    else instruction_addrs_from_node_8616(statement)
                )
                if transfer.pop_addr in addresses and _assignment_writes_stack_pointer_8616(
                    statement,
                    registers,
                ):
                    matches.append((container, index))
        if len(matches) != 1:
            if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
                log.warning(
                    "[balanced-register-restore] pop=%#x matches=%d",
                    transfer.pop_addr,
                    len(matches),
                )
            continue
        classified += 1
        container, marker_index = matches[0]
        existing = next(
            (
                statement
                for statement in container.statements
                if isinstance(statement, structured_c.CAssignment)
                and statement.tags.get("inertia_x86_16_balanced_immediate_pop") == transfer.pop_addr
            ),
            None,
        )
        if existing is None:
            value = structured_c.CConstant(
                transfer.value,
                SimTypeShort(False).with_arch(arch),
                codegen=codegen,
            )
            assignment = runtime_gp_state_assignment_8616(
                transfer.register_name,
                value,
                codegen=codegen,
                function_addr=cfunc.addr,
            )
            if assignment is None:
                continue
            assignment.tags.update(
                {
                    "ins_addr": transfer.pop_addr,
                    "inertia_x86_16_balanced_immediate_pop": transfer.pop_addr,
                    "inertia_source_instruction_addrs": (
                        transfer.push_addr,
                        transfer.pop_addr,
                    ),
                }
            )
            container.statements.insert(marker_index, assignment)
            marker_index += 1
            changed = True
        materialized += 1

        def replace_read(
            node: object,
            *,
            active_register_offset: int = register_offset,
            active_width: int = transfer.width,
            active_register_name: str = transfer.register_name,
        ) -> object:
            """Project one post-POP register read from coherent runtime state."""
            if not _register_cvar_matches_8616(
                node,
                register_offset=active_register_offset,
                width=active_width,
            ):
                return node
            replacement = runtime_gp_state_expr_8616(
                active_register_name,
                codegen=codegen,
                function_addr=cfunc.addr,
            )
            return replacement if replacement is not None else node

        for statement in tuple(container.statements[marker_index + 1 :]):
            if (
                isinstance(statement, structured_c.CAssignment)
                and _register_cvar_matches_8616(
                    statement.lhs,
                    register_offset=register_offset,
                    width=transfer.width,
                )
            ):
                break
            if _replace_c_children_8616(statement, replace_read):
                changed = True
    raw_count = len(transfers)
    surface._inertia_balanced_immediate_register_restore_stats_8616 = (
        BalancedImmediateRegisterRestoreStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=classified,
            materialized_count=materialized,
            failure_count=max(raw_count - classified, 0) + max(classified - materialized, 0),
        )
    )
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-register-restore] function=%#x raw=%d classified=%d materialized=%d changed=%s",
            cfunc.addr,
            raw_count,
            classified,
            materialized,
            changed,
        )
    return changed


def _decode_instruction_8616(project: object, address: int) -> object | None:
    """Decode one exact tagged instruction from immutable project bytes."""
    try:
        wrappers = tuple(
            cast(_DynamicValue8616, project).factory.block(
                address,
                num_inst=1,
                opt_level=0,
            ).capstone.insns
            or ()
        )
    except (AttributeError, KeyError, SimEngineError, TypeError, ValueError):
        return None
    if len(wrappers) != 1:
        return None
    return cast(object, getattr(wrappers[0], "insn", wrappers[0]))


def _decode_stack_instruction_8616(
    project: object,
    function: object,
    address: int,
) -> object | None:
    """Decode one PUSH/POP across normalized and original linear projections."""
    candidates = [address]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and not isinstance(delta, bool) and delta:
        candidates.extend((address - delta, address + delta))
    inventory = getattr(function, "_inertia_instruction_by_addr_map_8616", None)
    for candidate in dict.fromkeys(candidates):
        if candidate < 0:
            continue
        instruction = inventory.get(candidate) if isinstance(inventory, dict) else None
        if instruction is None:
            instruction = _decode_instruction_8616(project, candidate)
        if (
            getattr(instruction, "id", None) in {X86_INS_PUSH, X86_INS_POP}
            and _memory_operand_key_8616(instruction) is not None
        ):
            return instruction
    return None


def _structured_pairs_8616(
    project: object,
    function: object,
    root: structured_c.CStatements,
) -> tuple[tuple[int, int], ...]:
    """Pair exact tagged memory saves inside one flat structured sequence."""
    pairs: set[tuple[int, int]] = set()
    for container in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(container, structured_c.CStatements):
            continue
        stack: list[tuple[int, _MemoryOperandKey8616 | None]] = []
        seen_addresses: set[int] = set()
        for statement in tuple(container.statements):
            if not isinstance(statement, (structured_c.CAssignment, structured_c.CFunctionCall)):
                stack.clear()
                continue
            if not isinstance(statement, structured_c.CAssignment) or not _stack_variables_8616(statement):
                continue
            addresses = _statement_instruction_addrs_8616(statement)
            if len(addresses) != 1:
                stack.clear()
                continue
            address = next(iter(addresses))
            if address in seen_addresses:
                continue
            seen_addresses.add(address)
            instruction = _decode_stack_instruction_8616(project, function, address)
            instruction_id = getattr(instruction, "id", None)
            if instruction_id == X86_INS_PUSH:
                stack.append((address, _memory_operand_key_8616(instruction)))
                continue
            if instruction_id != X86_INS_POP:
                continue
            if not stack:
                continue
            push_addr, push_key = stack.pop()
            pop_key = _memory_operand_key_8616(instruction)
            if push_key is not None and push_key == pop_key:
                pairs.add((push_addr, address))
    candidates_by_key: dict[_MemoryOperandKey8616, list[tuple[int, int, int]]] = {}
    ordered_addresses: list[int] = []
    for statement in _iter_c_nodes_deep_8616(root):
        if not isinstance(statement, structured_c.CAssignment) or not _stack_variables_8616(statement):
            continue
        addresses = _statement_instruction_addrs_8616(statement)
        if len(addresses) != 1:
            continue
        address = next(iter(addresses))
        if address in ordered_addresses:
            continue
        instruction = _decode_stack_instruction_8616(project, function, address)
        instruction_id = getattr(instruction, "id", None)
        memory_key = _memory_operand_key_8616(instruction)
        if instruction_id not in {X86_INS_PUSH, X86_INS_POP} or memory_key is None:
            continue
        ordered_addresses.append(address)
        candidates_by_key.setdefault(memory_key, []).append(
            (len(ordered_addresses) - 1, address, cast(int, instruction_id))
        )
    for candidates in candidates_by_key.values():
        pushes = tuple(item for item in candidates if item[2] == X86_INS_PUSH)
        pops = tuple(item for item in candidates if item[2] == X86_INS_POP)
        if len(pushes) == len(pops) == 1 and pushes[0][0] < pops[0][0]:
            pairs.add((pushes[0][1], pops[0][1]))
    return tuple(sorted(pairs))


def _stack_variables_8616(root: object) -> dict[tuple[int, int], structured_c.CVariable]:
    """Return unambiguous BP-relative stack variables in one C subtree."""
    result: dict[tuple[int, int], structured_c.CVariable] = {}
    roots = root if isinstance(root, tuple) else (root,)
    for owner in roots:
        for node in _iter_c_nodes_deep_8616(owner):
            if not isinstance(node, structured_c.CVariable) or not isinstance(node.variable, SimStackVariable):
                continue
            variable = node.variable
            if variable.base != "bp" or not isinstance(variable.offset, int) or not isinstance(variable.size, int):
                continue
            result.setdefault((variable.offset, variable.size), node)
    return result


def _statement_instruction_addrs_8616(statement: structured_c.CAssignment) -> frozenset[int]:
    """Return owner and descendant instruction provenance for one assignment."""
    addresses = set(instruction_addrs_from_node_8616(statement))
    owner = statement.tags.get("ins_addr")
    if isinstance(owner, int) and not isinstance(owner, bool):
        addresses.add(owner)
    return frozenset(addresses)


def _remove_statements_8616(root: object, removed: frozenset[int]) -> bool:
    """Remove exact assignment objects from every structured statement owner."""
    changed = False
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, structured_c.CStatements):
            continue
        retained = [statement for statement in node.statements if id(statement) not in removed]
        if len(retained) != len(node.statements):
            node.statements[:] = retained
            changed = True
    return changed


def rebind_balanced_memory_stack_restores_8616(
    codegen: object,
    function: object | None,
    *,
    project: object | None = None,
) -> bool:
    """Rebind exact memory POP reads to their paired PUSH stack object."""
    surface = cast(_CodegenSurface8616, codegen)
    cfunc = surface.cfunc
    empty = BalancedMemoryStackRestoreStats8616(0, 0, 0, 0, 0)
    if cfunc is None or function is None or not isinstance(cfunc.statements, structured_c.CStatements):
        surface._inertia_balanced_memory_stack_restore_stats_8616 = empty
        surface._inertia_balanced_immediate_register_restore_stats_8616 = (
            BalancedImmediateRegisterRestoreStats8616(0, 0, 0, 0, 0)
        )
        return False
    if project is None:
        project = getattr(codegen, "project", None)
    register_changed = materialize_balanced_immediate_register_restores_8616(
        codegen,
        function,
        project=project,
    )
    structured_pairs = (
        _structured_pairs_8616(project, function, cfunc.statements)
        if project is not None
        else ()
    )
    pairs = tuple(
        sorted(
            set(_balanced_pairs_8616(_instruction_stream_8616(function)))
            | {(push_addr, pop_addr, None) for push_addr, pop_addr in structured_pairs}
        )
    )
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-memory-restore] function=%#x pairs=%s",
            cfunc.addr,
            pairs,
        )
    raw_count = len(pairs)
    classified = 0
    materialized = 0
    statements = tuple(
        node
        for node in _iter_c_nodes_deep_8616(cfunc.statements)
        if isinstance(node, structured_c.CAssignment)
    )
    for push_addr, pop_addr, pair_width in pairs:
        push_statements = tuple(
            statement for statement in statements if push_addr in _statement_instruction_addrs_8616(statement)
        )
        pop_statements = tuple(
            statement for statement in statements if pop_addr in _statement_instruction_addrs_8616(statement)
        )
        push_variables = _stack_variables_8616(push_statements)
        pop_variables = _stack_variables_8616(pop_statements)
        if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
            log.warning(
                "[balanced-memory-restore] pair=%#x->%#x push_statements=%d pop_statements=%d push_variables=%s pop_variables=%s",
                push_addr,
                pop_addr,
                len(push_statements),
                len(pop_statements),
                tuple(sorted(push_variables)),
                tuple(sorted(pop_variables)),
            )
        push_instruction = (
            _decode_stack_instruction_8616(project, function, push_addr)
            if project is not None
            else None
        )
        push_memory_key = _memory_operand_key_8616(push_instruction)
        word_pair = pair_width == 2 or (push_memory_key is not None and push_memory_key[-1] == 2)
        if len(pop_variables) != 1:
            continue
        if len(push_variables) == 1:
            (push_identity, exemplar), = push_variables.items()
        elif word_pair and len(push_variables) == 2 and all(
            identity[1] == 1 for identity in push_variables
        ):
            push_identity = min(push_variables, key=lambda identity: identity[0])
            exemplar = push_variables[push_identity]
        else:
            continue
        (pop_identity, _pop_exemplar), = pop_variables.items()
        if push_identity[1] != pop_identity[1] and not (
            word_pair and {push_identity[1], pop_identity[1]} <= {1, 2}
        ):
            continue
        classified += 1
        if word_pair:
            exemplar.variable.size = 2
            exemplar.variable_type = SimTypeShort(False).with_arch(exemplar.codegen.project.arch)

        def transform(
            node: object,
            *,
            target_identity: tuple[int, int] = pop_identity,
            push_exemplar: structured_c.CVariable = exemplar,
            word_mode: bool = word_pair,
        ) -> object:
            recomposition = recognize_stack_word_recomposition_8616(node) if word_mode else None
            if recomposition is not None:
                recomposed_variables = _stack_variables_8616((recomposition.low, recomposition.high))
                if target_identity in recomposed_variables:
                    replacement = copy.copy(push_exemplar)
                    replacement.variable_type = SimTypeShort(False).with_arch(
                        push_exemplar.codegen.project.arch
                    )
                    return replacement
            if not isinstance(node, structured_c.CVariable) or not isinstance(node.variable, SimStackVariable):
                return node
            variable = node.variable
            if (variable.offset, variable.size) != target_identity:
                return node
            replacement = copy.copy(push_exemplar)
            replacement.variable_type = (
                SimTypeShort(False).with_arch(push_exemplar.codegen.project.arch)
                if word_mode
                else node.variable_type
            )
            return replacement

        changed_pair = False
        for statement in pop_statements:
            if _replace_c_children_8616(statement, transform):
                changed_pair = True
        if word_pair:
            primary_push = next(
                (
                    statement
                    for statement in push_statements
                    if isinstance(statement.lhs, structured_c.CVariable)
                    and isinstance(statement.lhs.variable, SimStackVariable)
                    and (statement.lhs.variable.offset, statement.lhs.variable.size)
                    in {push_identity, (push_identity[0], 2)}
                ),
                None,
            )
            if primary_push is not None:
                primary_push.lhs = copy.copy(exemplar)
                primary_push.lhs.variable_type = SimTypeShort(False).with_arch(
                    exemplar.codegen.project.arch
                )
                redundant = frozenset(
                    id(statement)
                    for statement in push_statements
                    if statement is not primary_push
                )
                changed_pair = _remove_statements_8616(cfunc.statements, redundant) or changed_pair
        materialized += int(changed_pair)
    surface._inertia_balanced_memory_stack_restore_stats_8616 = BalancedMemoryStackRestoreStats8616(
        raw_count,
        raw_count,
        classified,
        materialized,
        max(raw_count - classified, 0) + max(classified - materialized, 0),
    )
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-memory-restore] function=%#x raw=%d classified=%d materialized=%d",
            cfunc.addr,
            raw_count,
            classified,
            materialized,
        )
    return materialized > 0 or register_changed
