"""Recover exact register sources at decoded instruction boundaries.

Layer: Recovery metadata.
Responsibility: collect decoded register-transfer facts and delegate cross-CFG
source identity to the Alias owner. Callsite recovery is a compatibility
consumer of the generic instruction-boundary proof.
Forbidden: source/COD/rendered-C inference or semantic materialization.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, cast

from angr.errors import SimEngineError

from .alias.register_reaching_source import (
    RegisterBlockTransfer8616,
    RegisterBlockTransferKind8616,
    RegisterReachingSourceResult8616,
    callsite_source_reads_memory_8616,
    resolve_register_reaching_source_8616,
)
from .analysis_helpers import resolve_direct_call_target_from_instruction_8616
from .callsite_register_instruction_facts import (
    instruction_writes_memory_8616,
    instruction_writes_register_8616,
    register_replacement_source_8616,
    register_storage_snapshot_source_8616,
)
from .frontend_instruction_kinds import is_x86_16_call_mnemonic_8616
from .frontend_instruction_reachability import decoded_block_instructions_8616
from .register_source_block_inventory import (
    collect_register_source_block_inventory_8616,
)
from .semantics.call_register_effects import (
    SyntheticCallRegisterEffectVerdict8616,
    classify_synthetic_call_register_effect_8616,
)
from .semantics.register_value_preservation import (
    decoded_instruction_preserves_register_value_8616,
)
from .synthetic_call_stub_evidence import is_synthetic_call_stub_8616

__all__ = (
    "recover_callsite_register_source_8616",
    "recover_register_source_before_instruction_8616",
)


class _MemoryOperand8616(Protocol):
    """Capstone memory fields at the third-party instruction boundary."""

    base: int
    index: int
    segment: int
    disp: int


class _Operand8616(Protocol):
    """Capstone operand fields consumed through instruction-fact helpers."""

    type: int
    reg: int
    imm: int
    size: int
    access: int
    mem: _MemoryOperand8616


class _DecodedInstruction8616(Protocol):
    """Capstone detail fields consumed through instruction-fact helpers."""

    operands: Sequence[_Operand8616]

    def reg_name(self, reg_id: int) -> str:
        """Return one backend register name."""

    def regs_access(self) -> tuple[Sequence[int], Sequence[int]]:
        """Return registers read and written by this instruction."""


class _Instruction8616(Protocol):
    """angr Capstone wrapper fields used by this collector."""

    address: int
    mnemonic: str
    insn: _DecodedInstruction8616


class _FunctionManager8616(Protocol):
    """Exact function lookup used for direct-callee proofs."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function at ``addr``."""


class _KnowledgeBase8616(Protocol):
    """angr knowledge-base fields used by direct-callee proofs."""

    functions: _FunctionManager8616


class _Project8616(Protocol):
    """angr project fields consumed by register transfer collection."""

    kb: _KnowledgeBase8616


class _Function8616(Protocol):
    """angr function fields consumed by exact register-source recovery."""

    addr: int
    project: _Project8616


class _CalleeFunction8616(Protocol):
    """Direct-callee function block ownership used by leaf proofs."""

    block_addrs_set: set[int]


def _direct_leaf_call_preserves_register_8616(
    project: _Project8616,
    target: int | None,
    register: str,
) -> bool:
    """Prove a direct one-block leaf callee does not write ``register``.

    A direct target remains machine evidence when CFG function discovery omits
    its leaf stub. In that case decode the exact target as one basic block and
    retain the same terminal-return and no-write requirements.
    """
    if not isinstance(target, int):
        return False
    if is_synthetic_call_stub_8616(project, target):
        return False
    try:
        callee = project.kb.functions.function(addr=target, create=False)
    except (AttributeError, TypeError):
        callee = None
    block_addrs: tuple[int, ...]
    if callee is None:
        block_addrs = (target,)
    else:
        try:
            block_addrs = tuple(sorted(cast(_CalleeFunction8616, callee).block_addrs_set))
        except (AttributeError, TypeError):
            return False
        if not block_addrs:
            block_addrs = (target,)
    if len(block_addrs) != 1:
        return False
    try:
        instructions = decoded_block_instructions_8616(
            project,
            block_addrs[0],
            opt_level=0,
        )
    except (AttributeError, SimEngineError, TypeError, ValueError):
        return False
    if not instructions or instructions[-1].mnemonic.lower() not in {"ret", "retf", "retw"}:
        return False
    for candidate in instructions[:-1]:
        mnemonic = candidate.mnemonic.lower()
        if is_x86_16_call_mnemonic_8616(mnemonic) or mnemonic.startswith(("j", "loop")):
            return False
        if instruction_writes_register_8616(candidate, register):
            return False
    return True


def _synthetic_call_preserves_register_8616(
    project: _Project8616,
    callsite_addr: int,
    target: int | None,
    register: str,
) -> bool:
    """Consume the registered MS C ABI only for an exact synthetic target."""
    effect = classify_synthetic_call_register_effect_8616(
        project,
        callsite_addr=callsite_addr,
        target_addr=target,
        register=register,
    )
    return (
        effect.closes_evidence
        and effect.verdict is SyntheticCallRegisterEffectVerdict8616.PRESERVED
    )


def _block_transfer_8616(
    project: _Project8616,
    instructions: tuple[_Instruction8616, ...],
    register: str,
) -> tuple[RegisterBlockTransferKind8616, tuple[object, ...] | None, bool]:
    """Collect one ordered block-prefix transfer from decoded instructions."""
    kind = RegisterBlockTransferKind8616.PRESERVE
    source: tuple[object, ...] | None = None
    clobbers_memory_sources = False
    for instruction in instructions:
        mnemonic = instruction.mnemonic.lower()
        writes_memory = instruction_writes_memory_8616(instruction) or is_x86_16_call_mnemonic_8616(mnemonic)
        if writes_memory:
            if kind is RegisterBlockTransferKind8616.REPLACE and callsite_source_reads_memory_8616(source):
                kind = RegisterBlockTransferKind8616.KILL
                source = None
            elif kind is RegisterBlockTransferKind8616.PRESERVE:
                clobbers_memory_sources = True
        storage_source = register_storage_snapshot_source_8616(instruction, register)
        if storage_source is not None:
            kind = RegisterBlockTransferKind8616.REPLACE
            source = storage_source
            clobbers_memory_sources = False
            continue
        if is_x86_16_call_mnemonic_8616(mnemonic):
            target = resolve_direct_call_target_from_instruction_8616(
                project,
                instruction,
            )
            if not (
                _direct_leaf_call_preserves_register_8616(
                    project,
                    target,
                    register,
                )
                or _synthetic_call_preserves_register_8616(
                    project,
                    instruction.address,
                    target,
                    register,
                )
            ):
                kind = RegisterBlockTransferKind8616.KILL
                source = None
                clobbers_memory_sources = False
            continue
        if not instruction_writes_register_8616(instruction, register):
            continue
        if decoded_instruction_preserves_register_value_8616(instruction, register):
            continue
        replacement = register_replacement_source_8616(instruction, register)
        if replacement is None:
            kind = RegisterBlockTransferKind8616.KILL
            source = None
            clobbers_memory_sources = False
        else:
            kind = RegisterBlockTransferKind8616.REPLACE
            source = replacement
            clobbers_memory_sources = False
    return kind, source, clobbers_memory_sources


def recover_register_source_before_instruction_8616(
    function: object,
    *,
    instruction_addr: int,
    register: str,
) -> RegisterReachingSourceResult8616:
    """Prove one register source reaches an exact instruction on every path."""
    boundary = cast(_Function8616, function)
    try:
        project = boundary.project
        entry_addr = boundary.addr
    except (AttributeError, TypeError):
        return resolve_register_reaching_source_8616((), entry_addr=0, sink_addr=0)
    inventory = collect_register_source_block_inventory_8616(function)
    if not inventory.complete or inventory.function_addr != entry_addr:
        return resolve_register_reaching_source_8616(
            (),
            entry_addr=entry_addr,
            sink_addr=0,
        )
    transfers: list[RegisterBlockTransfer8616] = []
    sink_addr: int | None = None
    for block in inventory.blocks:
        prefix: list[_Instruction8616] = []
        for instruction in cast(tuple[_Instruction8616, ...], block.instructions):
            if instruction.address == instruction_addr:
                if sink_addr is not None:
                    return resolve_register_reaching_source_8616(
                        (),
                        entry_addr=entry_addr,
                        sink_addr=0,
                    )
                sink_addr = block.block_addr
                break
            prefix.append(instruction)
        kind, source, clobbers_memory_sources = _block_transfer_8616(
            project,
            tuple(prefix),
            register,
        )
        transfers.append(
            RegisterBlockTransfer8616(
                block.block_addr,
                block.predecessors,
                kind,
                source,
                clobbers_memory_sources,
            )
        )
    if sink_addr is None:
        return resolve_register_reaching_source_8616((), entry_addr=entry_addr, sink_addr=0)
    return resolve_register_reaching_source_8616(
        tuple(transfers),
        entry_addr=entry_addr,
        sink_addr=sink_addr,
    )


def recover_callsite_register_source_8616(
    function: object,
    *,
    push_instruction_addr: int,
    register: str,
) -> RegisterReachingSourceResult8616:
    """Prove one register source reaches an exact argument PUSH on every path."""
    return recover_register_source_before_instruction_8616(
        function,
        instruction_addr=push_instruction_addr,
        register=register,
    )
