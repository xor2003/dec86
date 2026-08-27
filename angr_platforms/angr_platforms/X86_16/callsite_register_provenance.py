"""Recover exact register sources at decoded instruction boundaries.

Layer: Recovery metadata.
Responsibility: collect decoded register-transfer facts and delegate cross-CFG
source identity to the Alias owner. Callsite recovery is a compatibility
consumer of the generic instruction-boundary proof.
Forbidden: source/COD/rendered-C inference or semantic materialization.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, cast

from angr.errors import SimEngineError

from .alias.register_reaching_source import (
    RegisterBlockTransfer8616,
    RegisterBlockTransferKind8616,
    RegisterReachingSourceResult8616,
    callsite_source_reads_memory_8616,
    resolve_register_reaching_source_8616,
)
from .analysis_helpers import resolve_direct_call_target_from_block
from .callsite_register_instruction_facts import (
    DecodedInstructionFactSurface8616,
    instruction_writes_memory_8616,
    instruction_writes_register_8616,
    register_replacement_source_8616,
    register_storage_snapshot_source_8616,
)
from .frontend_instruction_kinds import is_x86_16_call_mnemonic_8616
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


class _Instruction8616(DecodedInstructionFactSurface8616, Protocol):
    """angr Capstone wrapper fields used by this collector."""

    address: int


class _CapstoneBlock8616(Protocol):
    """Decoded instruction container exposed by an angr block."""

    insns: Sequence[_Instruction8616]


class _Block8616(Protocol):
    """angr block surface used by transfer collection."""

    capstone: _CapstoneBlock8616


class _Factory8616(Protocol):
    """angr block factory boundary."""

    def block(self, addr: int, *, size: int | None = None, opt_level: int) -> _Block8616:
        """Decode one block at ``addr``."""


class _FunctionManager8616(Protocol):
    """Exact function lookup used for direct-callee proofs."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function at ``addr``."""


class _KnowledgeBase8616(Protocol):
    """angr knowledge-base fields used by direct-callee proofs."""

    functions: _FunctionManager8616


class _Project8616(Protocol):
    """angr project fields consumed by register transfer collection."""

    factory: _Factory8616
    kb: _KnowledgeBase8616


class _GraphNode8616(Protocol):
    """Function graph node bounds used by transfer collection."""

    addr: int
    size: int


class _Graph8616(Protocol):
    """Directed function graph surface used by the Alias input collector."""

    nodes: Iterable[_GraphNode8616]

    def predecessors(self, node: _GraphNode8616) -> Iterable[_GraphNode8616]:
        """Return direct in-function predecessors of ``node``."""


class _Function8616(Protocol):
    """angr function fields consumed by exact register-source recovery."""

    addr: int
    project: _Project8616
    graph: _Graph8616
    block_addrs_set: set[int]


def _graph_node_addr_8616(node: object) -> int | None:
    """Return an address from an angr node or a NetworkX integer node."""
    if isinstance(node, int):
        return node
    try:
        address = cast(_GraphNode8616, node).addr
    except AttributeError:
        return None
    return address if isinstance(address, int) else None


def _direct_leaf_call_preserves_register_8616(
    project: _Project8616,
    instruction: _Instruction8616,
    register: str,
) -> bool:
    """Prove a direct one-block leaf callee does not write ``register``.

    A direct target remains machine evidence when CFG function discovery omits
    its leaf stub. In that case decode the exact target as one basic block and
    retain the same terminal-return and no-write requirements.
    """
    target = resolve_direct_call_target_from_block(project, instruction.address)
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
            block_addrs = tuple(sorted(cast(_Function8616, callee).block_addrs_set))
        except (AttributeError, TypeError):
            return False
        if not block_addrs:
            block_addrs = (target,)
    if len(block_addrs) != 1:
        return False
    try:
        instructions = tuple(project.factory.block(block_addrs[0], opt_level=0).capstone.insns)
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
    instruction: _Instruction8616,
    register: str,
) -> bool:
    """Consume the registered MS C ABI only for an exact synthetic target."""
    target = resolve_direct_call_target_from_block(project, instruction.address)
    effect = classify_synthetic_call_register_effect_8616(
        project,
        callsite_addr=instruction.address,
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
            if not (
                _direct_leaf_call_preserves_register_8616(
                    project,
                    instruction,
                    register,
                )
                or _synthetic_call_preserves_register_8616(
                    project,
                    instruction,
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
        block_addrs = tuple(sorted(boundary.block_addrs_set))
        graph = boundary.graph
        graph_nodes = tuple(graph.nodes)
    except (AttributeError, TypeError):
        return resolve_register_reaching_source_8616((), entry_addr=0, sink_addr=0)
    node_by_addr: dict[int, _GraphNode8616] = {}
    for node in graph_nodes:
        node_addr = _graph_node_addr_8616(node)
        if node_addr is not None:
            node_by_addr[node_addr] = node
    transfers: list[RegisterBlockTransfer8616] = []
    sink_addr: int | None = None
    for block_addr in block_addrs:
        graph_node = node_by_addr.get(block_addr)
        if graph_node is None:
            return resolve_register_reaching_source_8616((), entry_addr=entry_addr, sink_addr=0)
        try:
            block_size = int(graph_node.size)
            if block_size <= 0:
                return resolve_register_reaching_source_8616((), entry_addr=entry_addr, sink_addr=0)
            instructions = tuple(
                project.factory.block(block_addr, size=block_size, opt_level=0).capstone.insns
            )
            predecessor_addrs = tuple(
                address
                for predecessor in graph.predecessors(graph_node)
                if (address := _graph_node_addr_8616(predecessor)) is not None
            )
            predecessors = tuple(sorted(predecessor_addrs))
        except (AttributeError, TypeError, ValueError):
            return resolve_register_reaching_source_8616((), entry_addr=entry_addr, sink_addr=0)
        prefix: list[_Instruction8616] = []
        for instruction in instructions:
            if instruction.address == instruction_addr:
                if sink_addr is not None:
                    return resolve_register_reaching_source_8616(
                        (),
                        entry_addr=entry_addr,
                        sink_addr=0,
                    )
                sink_addr = block_addr
                break
            prefix.append(instruction)
        kind, source, clobbers_memory_sources = _block_transfer_8616(
            project,
            tuple(prefix),
            register,
        )
        transfers.append(
            RegisterBlockTransfer8616(
                block_addr,
                predecessors,
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
