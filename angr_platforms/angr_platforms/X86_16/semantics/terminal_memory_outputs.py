"""Classify exact direct segmented storage reaching every function return.

Layer: Semantics.
Responsibility: prove whether each stable direct DS/ES store is definitely
written on every entry-reachable return path while retaining all store sites.
Consumes typed function SSA and structured instruction decoding. This module
does not create Alias identities, choose C types, mutate prototypes, or render C.
Indirect, indexed, overlapping, or incompletely connected memory effects remain
explicitly outside this first direct-storage proof and cannot validate a
conflicting direct output.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Any, cast

from angr.errors import SimEngineError, SimTranslationError

from ..frontend_instruction_reachability import decoded_block_instructions_8616
from ..ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace
from ..ir.ssa_function import SSAFunctionArtifact
from .terminal_memory_output_contracts import (
    MemoryOutputKey8616,
    TerminalMemoryOutputDisposition8616,
    TerminalMemoryOutputEvidence8616,
    TerminalMemoryOutputFact8616,
    TerminalMemoryOutputFailure8616,
    TerminalMemoryOutputStats8616,
    TerminalMemoryStoreSite8616,
)


def _direct_store_8616(
    block_addr: int,
    instr_index: int,
    instruction: IRInstr,
) -> tuple[MemoryOutputKey8616, IRAddress, TerminalMemoryStoreSite8616] | None:
    """Return one width-coherent stable direct DS/ES STORE."""
    if instruction.op != "STORE" or len(instruction.args) < 2:
        return None
    address, value = instruction.args[:2]
    if (
        not isinstance(address, IRAddress)
        or not isinstance(value, IRValue)
        or address.space not in {MemSpace.DS, MemSpace.ES}
        or address.base
        or address.status is not AddressStatus.STABLE
        or address.size <= 0
        or address.size != instruction.size
        or address.size != value.size
        or instruction.addr is None
    ):
        return None
    key = (address.space, address.offset, address.size)
    return key, address, TerminalMemoryStoreSite8616(block_addr, instr_index, instruction.addr)


def _ranges_overlap_8616(left: MemoryOutputKey8616, right: MemoryOutputKey8616) -> bool:
    """Return whether two ranges overlap within one segmented address space."""
    return left[0] is right[0] and left[1] < right[1] + right[2] and right[1] < left[1] + left[2]


def _terminal_is_return_8616(project: object, block_addr: int) -> bool:
    """Prove a terminal block ends in a structured machine return."""
    try:
        instructions = decoded_block_instructions_8616(cast(Any, project), block_addr, opt_level=0)
    except (KeyError, SimEngineError, SimTranslationError, ValueError):
        return False
    if not instructions:
        return False
    # Dynamic angr/Capstone boundary: decoded objects may retain an angr wrapper.
    decoded = cast(Any, instructions[-1])
    try:
        mnemonic = str(decoded.insn.mnemonic or "").lower()
    except AttributeError:
        try:
            mnemonic = str(decoded.mnemonic or "").lower()
        except AttributeError:
            return False
    return mnemonic in {"iret", "ret", "retf", "retw"}


def _refused_8616(
    artifact: SSAFunctionArtifact,
    failure: TerminalMemoryOutputFailure8616,
    raw_count: int,
    normalized_count: int = 0,
) -> TerminalMemoryOutputEvidence8616:
    """Build one atomic refusal without publishing partial output facts."""
    return TerminalMemoryOutputEvidence8616(
        function_addr=artifact.function_addr,
        facts=(),
        failure=failure,
        stats=TerminalMemoryOutputStats8616(
            raw_fact_count=max(1, raw_count),
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
    )


def _reachable_blocks_8616(
    artifact: SSAFunctionArtifact,
) -> tuple[
    set[int] | None,
    dict[int, frozenset[int]] | None,
    TerminalMemoryOutputFailure8616 | None,
]:
    """Return the closed entry-reachable SSA block set."""
    blocks = {block.addr: block for block in artifact.blocks}
    if artifact.function_addr not in blocks:
        return None, None, TerminalMemoryOutputFailure8616.ENTRY_BLOCK_MISSING
    if set(artifact.predecessor_map) != set(blocks):
        return None, None, TerminalMemoryOutputFailure8616.CFG_INCOMPLETE
    successors: dict[int, set[int]] = {address: set() for address in blocks}
    for successor, predecessors in artifact.predecessor_map.items():
        if any(predecessor not in blocks for predecessor in predecessors):
            return None, None, TerminalMemoryOutputFailure8616.CFG_INCOMPLETE
        for predecessor in predecessors:
            successors[predecessor].add(successor)
    reachable: set[int] = set()
    pending = [artifact.function_addr]
    while pending:
        block_addr = pending.pop()
        if block_addr in reachable:
            continue
        reachable.add(block_addr)
        pending.extend(successors[block_addr])
    return reachable, {address: frozenset(values) for address, values in successors.items()}, None


def _must_write_keys_8616(
    artifact: SSAFunctionArtifact,
    reachable: set[int],
    successors: dict[int, frozenset[int]],
    candidate_keys: frozenset[MemoryOutputKey8616],
) -> tuple[frozenset[MemoryOutputKey8616], tuple[int, ...]] | None:
    """Solve definite direct stores to every terminal over the exact SSA CFG."""
    blocks = {block.addr: block for block in artifact.blocks if block.addr in reachable}
    predecessors = {
        address: set(predecessor for predecessor in artifact.predecessor_map[address] if predecessor in reachable)
        for address in reachable
    }
    terminals = tuple(sorted(address for address in reachable if not successors[address]))
    if not terminals:
        return None
    can_reach_terminal = set(terminals)
    pending = list(terminals)
    while pending:
        address = pending.pop()
        for predecessor in predecessors[address]:
            if predecessor not in can_reach_terminal:
                can_reach_terminal.add(predecessor)
                pending.append(predecessor)
    if can_reach_terminal != reachable:
        return None
    local = {
        block.addr: frozenset(
            direct[0]
            for index, instruction in enumerate(block.instrs)
            if (direct := _direct_store_8616(block.addr, index, instruction)) is not None
        )
        for block in blocks.values()
    }
    incoming = {address: candidate_keys for address in reachable}
    outgoing = {address: candidate_keys for address in reachable}
    incoming[artifact.function_addr] = frozenset()
    changed = True
    while changed:
        changed = False
        for address in sorted(reachable):
            if address == artifact.function_addr:
                new_in: frozenset[MemoryOutputKey8616] = frozenset()
            else:
                pred_sets = tuple(outgoing[pred] for pred in sorted(predecessors[address]))
                new_in = frozenset.intersection(*pred_sets) if pred_sets else frozenset()
            new_out = new_in | local[address]
            if new_in != incoming[address] or new_out != outgoing[address]:
                incoming[address], outgoing[address], changed = new_in, new_out, True
    terminal_sets = tuple(outgoing[address] for address in terminals)
    return frozenset.intersection(*terminal_sets), terminals


def _store_may_alias_candidates_8616(
    instruction: IRInstr,
    candidate_keys: tuple[MemoryOutputKey8616, ...],
) -> bool:
    """Return whether an unsupported STORE may overlap a direct candidate."""
    address = instruction.args[0] if instruction.args else None
    if not isinstance(address, IRAddress):
        return True
    if address.space is MemSpace.SS:
        return False
    same_space = tuple(key for key in candidate_keys if key[0] is address.space)
    if not same_space:
        return address.space not in {MemSpace.DS, MemSpace.ES}
    if address.base or address.status is not AddressStatus.STABLE or address.size <= 0:
        return True
    store_key = (address.space, address.offset, address.size)
    return any(_ranges_overlap_8616(store_key, candidate) for candidate in same_space)


def collect_terminal_memory_output_evidence_8616(
    project: object,
    artifact: SSAFunctionArtifact,
) -> TerminalMemoryOutputEvidence8616:
    """Classify stable direct DS/ES ranges over every exact return path."""
    all_direct: list[tuple[int, int, IRInstr]] = []
    for block in artifact.blocks:
        all_direct.extend(
            (block.addr, instr_index, instruction)
            for instr_index, instruction in enumerate(block.instrs)
            if _direct_store_8616(block.addr, instr_index, instruction) is not None
        )
    if not all_direct:
        return TerminalMemoryOutputEvidence8616(
            artifact.function_addr, (), None, TerminalMemoryOutputStats8616()
        )
    reachable, successors, failure = _reachable_blocks_8616(artifact)
    if reachable is None or successors is None:
        if failure is None:
            raise RuntimeError("incomplete memory-output CFG refusal")
        return _refused_8616(artifact, failure, len(all_direct))

    grouped: dict[MemoryOutputKey8616, tuple[IRAddress, list[TerminalMemoryStoreSite8616]]] = {}
    all_stores: list[tuple[int, int, IRInstr]] = []
    direct_sites: set[tuple[int, int]] = set()
    for block in artifact.blocks:
        if block.addr not in reachable:
            continue
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.op != "STORE":
                continue
            all_stores.append((block.addr, instr_index, instruction))
            direct = _direct_store_8616(block.addr, instr_index, instruction)
            if direct is None:
                continue
            direct_sites.add((block.addr, instr_index))
            key, address, site = direct
            stored = grouped.setdefault(key, (address, []))
            stored[1].append(site)
    if not grouped:
        return TerminalMemoryOutputEvidence8616(
            artifact.function_addr, (), None, TerminalMemoryOutputStats8616()
        )
    keys = tuple(sorted(grouped, key=lambda item: (item[0].value, item[1], item[2])))
    if any(_ranges_overlap_8616(left, right) for index, left in enumerate(keys) for right in keys[index + 1 :]):
        return _refused_8616(
            artifact, TerminalMemoryOutputFailure8616.OVERLAPPING_STORAGE, len(keys), len(keys)
        )
    for block_addr, instr_index, instruction in all_stores:
        if (block_addr, instr_index) in direct_sites:
            continue
        if _store_may_alias_candidates_8616(instruction, keys):
            return _refused_8616(
                artifact, TerminalMemoryOutputFailure8616.ALIAS_CONFLICT, len(keys), len(keys)
            )
    solved = _must_write_keys_8616(artifact, reachable, successors, frozenset(keys))
    if solved is None:
        return _refused_8616(
            artifact, TerminalMemoryOutputFailure8616.CFG_INCOMPLETE, len(keys), len(keys)
        )
    must_write, terminals = solved
    if any(not _terminal_is_return_8616(project, address) for address in terminals):
        return _refused_8616(
            artifact, TerminalMemoryOutputFailure8616.TERMINAL_NOT_RETURN, len(keys), len(keys)
        )
    facts = tuple(
        TerminalMemoryOutputFact8616(
            address=grouped[key][0],
            disposition=(
                TerminalMemoryOutputDisposition8616.MUST_WRITE
                if key in must_write
                else TerminalMemoryOutputDisposition8616.CONDITIONAL
            ),
            store_sites=tuple(sorted(grouped[key][1], key=lambda site: (site.block_addr, site.instr_index))),
            terminal_block_addrs=terminals,
        )
        for key in keys
    )
    count = len(facts)
    return TerminalMemoryOutputEvidence8616(
        artifact.function_addr,
        facts,
        None,
        TerminalMemoryOutputStats8616(count, count, count, count),
    )
