"""Project versioned stack-memory accesses into canonical Alias identities.

Layer: Alias.
Responsibility: classify one IR stack address or composed byte-view access
without inferring C objects, types, widening, control flow, or rendered text.
Owns storage identity only. Do not perform lowering, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..ir.core import IRAddress
from ..ir.ssa_memory_contracts import SSAMemoryAccess8616, SSAMemoryAccessKind8616
from .alias_model_impl import AliasFailure, AliasStorageFacts, alias_facts_for_ir_address_8616
from .stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemoryAliasRefusal8616,
    StackMemoryAliasRefusalKind8616,
    StackMemorySSAAliasAccess8616,
    StackMemorySSAAliasAccessSlice8616,
    StackMemorySSAAliasFact8616,
)


def alias_stack_memory_storage_8616(
    address: IRAddress,
) -> AliasStorageFacts | tuple[StackMemoryAliasRefusalKind8616, str]:
    """Classify one typed address through the canonical Alias entry point."""
    result = alias_facts_for_ir_address_8616(address)
    if isinstance(result, AliasStorageFacts):
        return result
    if isinstance(result, AliasFailure):
        return (StackMemoryAliasRefusalKind8616.ALIAS_FAILURE, result.reason)
    return (
        StackMemoryAliasRefusalKind8616.UNCLASSIFIABLE_ADDRESS,
        "canonical Alias model did not classify the versioned stack address",
    )


def project_stack_memory_access_8616(
    access: SSAMemoryAccess8616,
) -> StackMemorySSAAliasFact8616 | StackMemorySSAAliasAccess8616 | StackMemoryAliasRefusal8616:
    """Project one complete IR access as an exact fact or composed Alias view."""
    if not access.complete:
        return StackMemoryAliasRefusal8616(
            StackMemoryAliasRefusalKind8616.INCOMPLETE_ACCESS_SLICES,
            access.block_addr,
            access.instr_index,
            "memory-SSA slices do not exactly cover the original stack access",
            access.address,
        )
    storage = alias_stack_memory_storage_8616(access.address)
    if isinstance(storage, tuple):
        return StackMemoryAliasRefusal8616(
            storage[0], access.block_addr, access.instr_index, storage[1], access.address
        )
    projected_slices: list[StackMemorySSAAliasAccessSlice8616] = []
    for item in access.slices:
        slice_storage = alias_stack_memory_storage_8616(item.address)
        if isinstance(slice_storage, tuple):
            return StackMemoryAliasRefusal8616(
                slice_storage[0],
                access.block_addr,
                access.instr_index,
                slice_storage[1],
                item.address,
            )
        if not storage.contains(slice_storage):
            return StackMemoryAliasRefusal8616(
                StackMemoryAliasRefusalKind8616.INCONSISTENT_ACCESS_STORAGE,
                access.block_addr,
                access.instr_index,
                "composed memory slice is not contained by the original Alias storage",
                item.address,
            )
        projected_slices.append(StackMemorySSAAliasAccessSlice8616(item, slice_storage))
    if len(projected_slices) == 1:
        projected_slice = projected_slices[0]
        return StackMemorySSAAliasFact8616(
            StackMemoryAliasFactKind8616.STORE
            if access.kind is SSAMemoryAccessKind8616.STORE
            else StackMemoryAliasFactKind8616.LOAD,
            access.block_addr,
            access.instr_index,
            projected_slice.source.address,
            projected_slice.storage,
        )
    return StackMemorySSAAliasAccess8616(access, storage, tuple(projected_slices))


__all__ = ["alias_stack_memory_storage_8616", "project_stack_memory_access_8616"]
