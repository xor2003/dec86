"""Build function-level SSA for exact segmented stack-memory ranges.

Layer: IR.
Responsibility: version proven `SS:BP+offset` loads/stores and create memory
phi inputs without naming locals or inferring C types.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .core import AddressStatus, IRAddress, IRAtom, IRCondition, IRInstr, IRRefusal, MemSpace
from .ssa import SSABlock
from .ssa_memory_contracts import (
    MemoryRangeKey8616,
    SSAFunctionMemoryResult8616,
    SSAMemoryBinding8616,
    SSAMemoryIncomingValue8616,
    SSAMemoryOverlap8616,
    SSAMemoryOverlapRelation8616,
    SSAMemoryPhiNode8616,
    SSAMemoryStats8616,
)

__all__ = [
    "build_x86_16_function_memory_ssa",
]


def _memory_key_8616(address: IRAddress) -> MemoryRangeKey8616 | None:
    """Return one versionable exact SS:BP range identity."""
    if (
        address.space is not MemSpace.SS
        or address.status is not AddressStatus.STABLE
        or address.base != ("bp",)
        or address.size <= 0
    ):
        return None
    return (address.space.value, address.base, address.offset, address.size)


def _versioned_address_8616(address: IRAddress, version: int) -> IRAddress:
    """Preserve all address evidence while assigning an SSA version."""
    return IRAddress(
        space=address.space,
        base=address.base,
        offset=address.offset,
        size=address.size,
        status=address.status,
        segment_origin=address.segment_origin,
        expr=address.expr,
        version=version,
    )


def _stack_access_8616(instr: IRInstr) -> IRAddress | None:
    """Return the memory operand for one typed stack LOAD or STORE."""
    if instr.op not in {"LOAD", "STORE"} or not instr.args:
        return None
    address = instr.args[0]
    return address if isinstance(address, IRAddress) and address.space is MemSpace.SS else None


def _overlap_8616(left: IRAddress, right: IRAddress) -> SSAMemoryOverlap8616 | None:
    """Return the exact intersection of two canonical non-identical ranges."""
    if left.space is not right.space or left.base != right.base:
        return None
    start = max(left.offset, right.offset)
    end = min(left.offset + left.size, right.offset + right.size)
    if start >= end:
        return None
    left_contains = left.offset <= right.offset and right.offset + right.size <= left.offset + left.size
    right_contains = right.offset <= left.offset and left.offset + left.size <= right.offset + right.size
    if left_contains:
        relation = SSAMemoryOverlapRelation8616.LEFT_CONTAINS_RIGHT
    elif right_contains:
        relation = SSAMemoryOverlapRelation8616.RIGHT_CONTAINS_LEFT
    else:
        relation = SSAMemoryOverlapRelation8616.PARTIAL
    intersection = IRAddress(
        left.space,
        left.base,
        start,
        end - start,
        left.status,
        left.segment_origin,
    )
    return SSAMemoryOverlap8616(left, right, intersection, relation)


def _rewrite_atom_8616(
    atom: IRAtom,
    versions: dict[MemoryRangeKey8616, int],
    refused_keys: frozenset[MemoryRangeKey8616],
) -> IRAtom:
    """Rewrite exact memory atoms to their reaching version."""
    if isinstance(atom, IRCondition):
        return IRCondition(
            op=atom.op,
            args=tuple(_rewrite_atom_8616(item, versions, refused_keys) for item in atom.args),
            expr=atom.expr,
            width_bits=atom.width_bits,
        )
    if not isinstance(atom, IRAddress):
        return atom
    key = _memory_key_8616(atom)
    if key is None or key in refused_keys:
        return atom
    return _versioned_address_8616(atom, versions.get(key, 0))


def _collect_accesses_8616(
    blocks: tuple[SSABlock, ...],
) -> tuple[tuple[int, int, IRAddress], ...]:
    """Collect stack accesses in deterministic instruction order."""
    return tuple(
        (block.addr, index, address)
        for block in sorted(blocks, key=lambda item: item.addr)
        for index, instr in enumerate(block.instrs)
        if (address := _stack_access_8616(instr)) is not None
    )


def build_x86_16_function_memory_ssa(
    function_addr: int,
    blocks: tuple[SSABlock, ...],
    predecessor_map: dict[int, tuple[int, ...]],
) -> SSAFunctionMemoryResult8616:
    """Version exact stack ranges and join reaching definitions to a fixed point."""
    accesses = _collect_accesses_8616(blocks)
    valid_keys = tuple(
        key for _block, _index, address in accesses if (key := _memory_key_8616(address)) is not None
    )
    unique_keys = tuple(sorted(set(valid_keys)))
    address_by_key = {
        key: address
        for _block, _index, address in accesses
        if (key := _memory_key_8616(address)) is not None
    }
    overlaps = tuple(
        overlap
        for index, left_key in enumerate(unique_keys)
        for right_key in unique_keys[index + 1 :]
        if (overlap := _overlap_8616(address_by_key[left_key], address_by_key[right_key]))
        is not None
    )
    overlapping_keys = frozenset(
        key
        for overlap in overlaps
        for address in (overlap.left, overlap.right)
        if (key := _memory_key_8616(address)) is not None
    )
    call_refused_keys = frozenset(
        key
        for key in unique_keys
        if any(
            instr.op == "CALL"
            and (
                instr.call_stack_effect is None
                or not instr.call_stack_effect.preserves(address_by_key[key])
            )
            for block in blocks
            for instr in block.instrs
        )
    )
    refused_keys = overlapping_keys | call_refused_keys
    refusals = tuple(
        IRRefusal(
            kind=(
                "overlapping_stack_range"
                if _memory_key_8616(address) in overlapping_keys
                else "unknown_call_stack_effect"
                if _memory_key_8616(address) in call_refused_keys
                else "unproven_stack_range"
            ),
            detail=f"refused SS range base={address.base!r} offset={address.offset} size={address.size}",
            block_addr=block_addr,
        )
        for block_addr, _index, address in accesses
        if _memory_key_8616(address) is None or _memory_key_8616(address) in refused_keys
    )
    accepted_keys = tuple(key for key in unique_keys if key not in refused_keys)
    store_versions: dict[tuple[int, int, MemoryRangeKey8616], int] = {}
    next_version = 1
    for block in sorted(blocks, key=lambda item: item.addr):
        for index, instr in enumerate(block.instrs):
            address = _stack_access_8616(instr)
            key = _memory_key_8616(address) if address is not None else None
            if instr.op == "STORE" and key in accepted_keys:
                store_versions[(block.addr, index, key)] = next_version
                next_version += 1

    join_keys = tuple(
        (block_addr, key)
        for block_addr, predecessors in sorted(predecessor_map.items())
        if len(predecessors) > 1
        for key in accepted_keys
    )
    phi_versions = {item: next_version + index for index, item in enumerate(join_keys)}
    entry_versions = {(block.addr, key): 0 for block in blocks for key in accepted_keys}
    exit_versions = dict(entry_versions)
    last_store = {
        (block.addr, key): max(
            (
                version
                for (store_block, _index, store_key), version in store_versions.items()
                if store_block == block.addr and store_key == key
            ),
            default=0,
        )
        for block in blocks
        for key in accepted_keys
    }
    iteration_limit = max(1, len(blocks) * max(1, len(accepted_keys)) + 1)
    for _iteration in range(iteration_limit):
        changed = False
        for block in sorted(blocks, key=lambda item: item.addr):
            for key in accepted_keys:
                predecessor_versions = {
                    exit_versions[(predecessor, key)]
                    for predecessor in predecessor_map.get(block.addr, ())
                    if (predecessor, key) in exit_versions
                }
                entry = (
                    0
                    if not predecessor_versions
                    else next(iter(predecessor_versions))
                    if len(predecessor_versions) == 1
                    else phi_versions[(block.addr, key)]
                )
                exit_version = last_store[(block.addr, key)] or entry
                if entry_versions[(block.addr, key)] != entry or exit_versions[(block.addr, key)] != exit_version:
                    entry_versions[(block.addr, key)] = entry
                    exit_versions[(block.addr, key)] = exit_version
                    changed = True
        if not changed:
            break
    else:
        iteration_refusals = tuple(
            IRRefusal(
                kind="stack_memory_ssa_iteration_limit",
                detail=(
                    "stack-memory SSA did not reach its deterministic fixed point; "
                    f"refused SS range base={address.base!r} offset={address.offset} size={address.size}"
                ),
                block_addr=block_addr,
            )
            for block_addr, _index, address in accesses
            if _memory_key_8616(address) not in refused_keys
        )
        return SSAFunctionMemoryResult8616(
            blocks=blocks,
            bindings=(),
            phi_nodes=(),
            refusals=refusals + iteration_refusals,
            stats=SSAMemoryStats8616(
                raw_fact_count=len(accesses) + len(overlaps),
                normalized_fact_count=len(overlaps),
                classified_fact_count=len(overlaps),
                materialized_count=len(overlaps),
                failure_count=len(accesses),
            ),
            overlaps=overlaps,
        )

    bindings: list[SSAMemoryBinding8616] = []
    rewritten_blocks: list[SSABlock] = []
    materialized_count = len(overlaps)
    for block in sorted(blocks, key=lambda item: item.addr):
        current = {key: entry_versions[(block.addr, key)] for key in accepted_keys}
        rewritten_instrs: list[IRInstr] = []
        for index, instr in enumerate(block.instrs):
            args = tuple(_rewrite_atom_8616(atom, current, refused_keys) for atom in instr.args)
            address = _stack_access_8616(instr)
            key = _memory_key_8616(address) if address is not None else None
            if key is not None and address is not None and key in accepted_keys:
                materialized_count += 1
                if instr.op == "STORE":
                    version = store_versions[(block.addr, index, key)]
                    current[key] = version
                    versioned_address = _versioned_address_8616(address, version)
                    args = (versioned_address, *args[1:])
                    bindings.append(SSAMemoryBinding8616(block.addr, index, versioned_address))
            rewritten_instrs.append(
                IRInstr(instr.op, instr.dst, args, instr.size, instr.addr, instr.call_stack_effect)
            )
        rewritten_blocks.append(
            SSABlock(
                addr=block.addr,
                instrs=tuple(rewritten_instrs),
                bindings=block.bindings,
                refusals=block.refusals,
            )
        )

    phi_nodes = tuple(
        SSAMemoryPhiNode8616(
            block_addr=block_addr,
            key=key,
            target=_versioned_address_8616(address_by_key[key], phi_versions[(block_addr, key)]),
            incoming=tuple(
                SSAMemoryIncomingValue8616(
                    predecessor,
                    _versioned_address_8616(address_by_key[key], exit_versions[(predecessor, key)]),
                )
                for predecessor in predecessor_map[block_addr]
            ),
        )
        for block_addr, key in join_keys
        if len({exit_versions[(predecessor, key)] for predecessor in predecessor_map[block_addr]}) > 1
    )
    failure_count = len(refusals)
    return SSAFunctionMemoryResult8616(
        blocks=tuple(rewritten_blocks),
        bindings=tuple(bindings),
        phi_nodes=phi_nodes,
        refusals=refusals,
        stats=SSAMemoryStats8616(
            raw_fact_count=len(accesses) + len(overlaps),
            normalized_fact_count=materialized_count,
            classified_fact_count=materialized_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
        ),
        overlaps=overlaps,
    )
