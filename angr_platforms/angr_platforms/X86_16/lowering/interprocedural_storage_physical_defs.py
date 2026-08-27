"""Prove logical call sources from byte-executed outgoing stack stores.

Layer: Types/Lowering.
Responsibility: trace exact SSA values through physical byte stores and bind
them to one structured logical call-argument source. This module consumes IR
and callsite evidence; it does not infer signatures, classify C types, or
mutate code generation.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..callsite_summary import CallsitePushSourceKind8616
from ..ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
)
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    PhysicalCallArgumentPiece8616,
    SSAInstructionSite8616,
)

__all__ = [
    "reaching_definition_width_8616",
    "resolve_physical_store_definitions_8616",
]


def reaching_definition_width_8616(
    definition: StorageReachingDefinition8616,
) -> int:
    """Return one exact source-piece width from the owned definition contract."""
    source_storage = definition.source_storage
    if source_storage is not None:
        source_width = source_storage.width
        return source_width if isinstance(source_width, int) else 0
    value_width = definition.value.size
    return value_width if isinstance(value_width, int) else 0


def _prior_value_definition_8616(
    site: SSAInstructionSite8616,
    value: IRValue,
) -> IRInstr | None:
    """Return one prior instruction defining an exact SSA value or VEX tmp."""
    candidates = tuple(
        instr
        for instr in site.block.instrs[: site.instr_index]
        if instr.dst is not None
        and (
            (
                isinstance(value.source_tmp, int)
                and instr.dst.source_tmp == value.source_tmp
            )
            or (
                value.source_tmp is None
                and instr.dst.space is value.space
                and instr.dst.name == value.name
                and instr.dst.version == value.version
                and instr.dst.size == value.size
            )
        )
    )
    return candidates[0] if len(candidates) == 1 else None


def _logical_source_slice_8616(
    site: SSAInstructionSite8616,
    value: IRValue,
    logical_width: int,
    seen: frozenset[tuple[object, ...]] = frozenset(),
) -> tuple[IRValue, int] | None:
    """Trace one physical store value to its logical source and byte offset."""
    key = (value.space, value.name, value.version, value.source_tmp, value.size)
    if key in seen:
        return None
    if value.const is not None or (
        value.space is MemSpace.REG and value.size >= logical_width
    ):
        return value, 0
    definition = _prior_value_definition_8616(site, value)
    if definition is None:
        return None
    if definition.op == "MOV" and len(definition.args) == 1:
        source = definition.args[0]
        return (
            _logical_source_slice_8616(
                site,
                source,
                logical_width,
                seen | {key},
            )
            if isinstance(source, IRValue)
            else None
        )
    if definition.op.startswith("Iop_Shr") and len(definition.args) == 2:
        source, shift = definition.args
        if (
            isinstance(source, IRValue)
            and isinstance(shift, IRValue)
            and isinstance(shift.const, int)
            and shift.const % 8 == 0
        ):
            traced = _logical_source_slice_8616(
                site,
                source,
                logical_width,
                seen | {key},
            )
            return None if traced is None else (traced[0], traced[1] + shift.const // 8)
    return None


def _bp_affine_8616(
    site: SSAInstructionSite8616,
    value: IRValue,
    seen: frozenset[tuple[object, ...]] = frozenset(),
) -> tuple[int, int] | None:
    """Resolve one structured SSA value to ``BP * coefficient + offset``."""
    if value.space is MemSpace.REG and value.name == "bp":
        return 1, value.offset
    if isinstance(value.const, int):
        return 0, value.const
    key = (value.space, value.name, value.version, value.source_tmp, value.size)
    if key in seen:
        return None
    definition = _prior_value_definition_8616(site, value)
    if definition is None:
        return None
    if definition.op == "MOV" and len(definition.args) == 1:
        source = definition.args[0]
        return (
            _bp_affine_8616(site, source, seen | {key})
            if isinstance(source, IRValue)
            else None
        )
    if definition.op in {"Iop_Add16", "Iop_Sub16"} and len(definition.args) == 2:
        left, right = definition.args
        if not isinstance(left, IRValue) or not isinstance(right, IRValue):
            return None
        left_affine = _bp_affine_8616(site, left, seen | {key})
        right_affine = _bp_affine_8616(site, right, seen | {key})
        if left_affine is None or right_affine is None:
            return None
        sign = 1 if definition.op == "Iop_Add16" else -1
        return (
            left_affine[0] + sign * right_affine[0],
            left_affine[1] + sign * right_affine[1],
        )
    return None


def resolve_physical_store_definitions_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    piece: PhysicalCallArgumentPiece8616,
) -> tuple[
    tuple[StorageReachingDefinition8616, ...] | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Bind one logical pushed value to its exact outgoing stack-store pieces."""
    candidates = tuple(
        (site, site.instr.args[0], site.instr.args[1])
        for site in sites
        if site.instr.op == "STORE"
        and site.instr.addr == piece.push_addr
        and len(site.instr.args) == 2
        and isinstance(site.instr.args[0], IRAddress)
        and site.instr.args[0].space is MemSpace.SS
        and site.instr.args[0].base == ("sp",)
        and site.instr.args[0].status is AddressStatus.STABLE
        and site.instr.args[0].segment_origin is SegmentOrigin.PROVEN
        and isinstance(site.instr.args[1], IRValue)
        and site.instr.args[0].size == site.instr.args[1].size
    )
    if not candidates:
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    ordered = tuple(sorted(candidates, key=lambda item: item[1].offset))
    first_address = ordered[0][1]
    cursor = first_address.offset
    for _site, address, _value in ordered:
        if address.offset != cursor or address.base_values != first_address.base_values:
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
        cursor += address.size
    if sum(address.size for _site, address, _value in ordered) != piece.width:
        return None, CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT
    traces = tuple(
        _logical_source_slice_8616(site, value, piece.width)
        for site, _address, value in ordered
    )
    expected_offsets: list[int] = []
    source_offset = 0
    for _site, address, _value in ordered:
        expected_offsets.append(source_offset)
        source_offset += address.size
    if any(trace is None for trace in traces) or tuple(
        trace[1] for trace in traces if trace is not None
    ) != tuple(expected_offsets):
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    roots = tuple(trace[0] for trace in traces if trace is not None)
    source = piece.source
    kind = source[0] if source else None
    source_storages: tuple[StorageIdentity8616 | None, ...]
    if kind in {
        CallsitePushSourceKind8616.IMMEDIATE,
        CallsitePushSourceKind8616.IMMEDIATE.value,
    }:
        if len(source) != 2 or not isinstance(source[1], int):
            return None, CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT
        mask = (1 << (piece.width * 8)) - 1
        if any(
            root.const is None or root.const & mask != source[1] & mask
            for root in roots
        ):
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
        source_storages = (None,) * len(ordered)
    elif kind in {
        CallsitePushSourceKind8616.BP_ADDRESS,
        CallsitePushSourceKind8616.BP_ADDRESS.value,
    }:
        if (
            len(source) != 2
            or not isinstance(source[1], int)
            or any(root != roots[0] for root in roots)
        ):
            return None, CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT
        affine = _bp_affine_8616(ordered[0][0], roots[0])
        if (
            affine is None
            or affine[0] != 1
            or affine[1] & 0xFFFF != source[1] & 0xFFFF
        ):
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
        source_storages = tuple(
            StorageIdentity8616(
                kind=StorageIdentityKind8616.STACK,
                width=address.size,
                address=IRAddress(
                    space=MemSpace.SS,
                    base=("bp",),
                    offset=source[1] + offset,
                    size=address.size,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
            )
            for (_site, address, _value), offset in zip(
                ordered,
                expected_offsets,
                strict=True,
            )
        )
    else:
        return None, CallArgumentDefinitionFailure8616.UNSUPPORTED_SOURCE_KIND
    definitions = tuple(
        StorageReachingDefinition8616(
            value=value,
            block_addr=site.block.addr,
            instr_index=site.instr_index,
            instr_addr=piece.push_addr,
            source_storage=source_storage,
        )
        for (site, _address, value), source_storage in zip(
            ordered,
            source_storages,
            strict=True,
        )
    )
    if any(not definition.is_complete for definition in definitions):
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    return definitions, None
