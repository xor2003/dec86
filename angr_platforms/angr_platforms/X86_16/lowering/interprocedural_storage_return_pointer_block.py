"""Transfer returned pointer carriers through one typed caller SSA block.

Layer: Types/Lowering.
Responsibility: carry exact full-word register identities through semantic MOV
aliases and recognize stable segmented LOAD or STORE address use in one block.
Consumes alias, widening, and typed facts.
Consumes Alias-owned register domains and typed IR/SSA facts. This module does
not traverse CFG edges, join phi inputs, infer arithmetic aliases, mutate
codegen, or inspect Structuring output.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from ..alias.domains import (
    AX,
    FULL16,
    DomainKey,
    register_domain_for_name,
    register_view_for_name,
)
from ..caller_return_use_contracts import CallerReturnUseFact8616
from ..ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from ..ir.ssa import SSABlock
from .interprocedural_storage_return_type_contracts import (
    ReturnPointerAliasStep8616,
    ReturnPointerCfgEdge8616,
    ReturnPointerPhiEvidence8616,
    ReturnPointerUseEvidence8616,
)

__all__ = [
    "PointerBlockScan8616",
    "PointerCarrier8616",
    "append_unique_pointer_proofs_8616",
    "full_word_pointer_domain_8616",
    "pointer_witness_seed_values_8616",
    "scan_pointer_carriers_in_block_8616",
]

_ProofT = TypeVar("_ProofT")
_ValueKey8616 = tuple[MemSpace, str | None, int, int, int | None]


@dataclass(frozen=True, slots=True)
class PointerCarrier8616:
    """One exact call-output-derived register carrier and its proof path."""

    value: IRValue
    aliases: tuple[ReturnPointerAliasStep8616, ...] = ()
    cfg_edges: tuple[ReturnPointerCfgEdge8616, ...] = ()
    phis: tuple[ReturnPointerPhiEvidence8616, ...] = ()


@dataclass(slots=True)
class PointerBlockScan8616:
    """Output carriers and refusal observations from one block scan."""

    carriers: dict[DomainKey, PointerCarrier8616]
    evidence: ReturnPointerUseEvidence8616 | None = None
    saw_unknown_address: bool = False
    saw_ambiguous_address: bool = False
    saw_alias_clobber: bool = False


def append_unique_pointer_proofs_8616(
    values: tuple[_ProofT, ...],
    additions: tuple[_ProofT, ...],
) -> tuple[_ProofT, ...]:
    """Append equal proof records once while preserving deterministic order."""
    merged = list(values)
    for addition in additions:
        if addition not in merged:
            merged.append(addition)
    return tuple(merged)


def full_word_pointer_domain_8616(value: IRValue) -> DomainKey | None:
    """Return Alias-owned full-word register identity for a typed value."""
    if value.space is not MemSpace.REG or value.size != 2:
        return None
    if register_view_for_name(value.name) != FULL16:
        return None
    return register_domain_for_name(value.name)


def pointer_witness_seed_values_8616(
    block: SSABlock,
    witness: int,
) -> tuple[IRValue, ...]:
    """Return exact AX-domain reads performed by one witnessed instruction."""
    values: list[IRValue] = []
    for instruction in block.instrs:
        if instruction.addr != witness:
            continue
        for argument in instruction.args:
            if (
                isinstance(argument, IRValue)
                and full_word_pointer_domain_8616(argument) == AX
                and isinstance(argument.version, int)
                and argument not in values
            ):
                values.append(argument)
    return tuple(values)


def _value_key_8616(value: IRValue) -> _ValueKey8616:
    """Return exact block-local SSA identity for one typed value."""
    return (value.space, value.name, value.offset, value.size, value.version)


def _copy_source_8616(
    instruction: IRInstr,
    tainted: dict[_ValueKey8616, PointerCarrier8616],
    live: dict[DomainKey, PointerCarrier8616],
    entry_domains: set[DomainKey],
) -> tuple[IRValue, PointerCarrier8616] | None:
    """Resolve one exact tainted source of an equal-width semantic MOV."""
    destination = instruction.dst
    if (
        instruction.op != "MOV"
        or destination is None
        or len(instruction.args) != 1
        or not isinstance(instruction.args[0], IRValue)
    ):
        return None
    source = instruction.args[0]
    if source.expr is not None or source.size != 2 or destination.size != source.size:
        return None
    carrier = tainted.get(_value_key_8616(source))
    source_domain = full_word_pointer_domain_8616(source)
    if carrier is None and source.version == 0 and source_domain in entry_domains:
        carrier = live.get(source_domain)
    return None if carrier is None else (source, carrier)


def _address_uses_8616(instruction: IRInstr) -> tuple[IRAddress, ...]:
    """Return typed memory addresses consumed by a LOAD or STORE."""
    if instruction.op not in {"LOAD", "STORE"}:
        return ()
    return tuple(argument for argument in instruction.args if isinstance(argument, IRAddress))


def _address_carrier_8616(
    address: IRAddress,
    live: dict[DomainKey, PointerCarrier8616],
) -> tuple[PointerCarrier8616 | None, str | None, bool, bool]:
    """Classify exact, ambiguous, and unknown use of a live pointer carrier."""
    live_names = tuple(
        name for name in address.base if (domain := register_domain_for_name(name)) is not None and domain in live
    )
    if not live_names:
        return None, None, False, False
    if len(address.base) != 1 or len(live_names) != 1:
        return None, None, True, False
    if (
        address.status is not AddressStatus.STABLE
        or address.segment_origin is not SegmentOrigin.PROVEN
        or address.space not in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        or address.size <= 0
    ):
        return None, None, False, True
    name = live_names[0]
    domain = register_domain_for_name(name)
    if domain is None:
        return None, None, False, True
    return live[domain], name, False, False


def scan_pointer_carriers_in_block_8616(
    block: SSABlock,
    fact: CallerReturnUseFact8616,
    entry_carriers: dict[DomainKey, PointerCarrier8616],
    start_index: int,
    witness: int,
) -> PointerBlockScan8616:
    """Propagate exact carriers through one block from a proven entry state."""
    live = dict(entry_carriers)
    entry_domains = set(live)
    tainted = {_value_key_8616(carrier.value): carrier for carrier in live.values()}
    saw_unknown = False
    saw_ambiguous = False
    saw_clobber = False

    for instr_index in range(start_index, len(block.instrs)):
        instruction = block.instrs[instr_index]
        instr_addr = instruction.addr
        if isinstance(instr_addr, int):
            for address in _address_uses_8616(instruction):
                carrier, name, ambiguous, unknown = _address_carrier_8616(address, live)
                saw_ambiguous = saw_ambiguous or ambiguous
                saw_unknown = saw_unknown or unknown
                if carrier is not None and name is not None:
                    evidence = ReturnPointerUseEvidence8616(
                        caller_addr=fact.caller_addr,
                        callsite_addr=fact.callsite_addr,
                        witness_instruction_addr=witness,
                        dereference_instruction_addr=instr_addr,
                        carrier_register=name,
                        address=address,
                        aliases=carrier.aliases,
                        cfg_edges=carrier.cfg_edges,
                        phis=carrier.phis,
                    )
                    if evidence.complete:
                        return PointerBlockScan8616(carriers=live, evidence=evidence)
                    saw_unknown = True

        destination = instruction.dst
        copy = None if not isinstance(instr_addr, int) else _copy_source_8616(instruction, tainted, live, entry_domains)
        destination_domain = None if destination is None else full_word_pointer_domain_8616(destination)
        if destination_domain is not None:
            entry_domains.discard(destination_domain)
            if destination_domain in live and copy is None:
                saw_clobber = True
            live.pop(destination_domain, None)
        if destination is None or copy is None or not isinstance(destination.version, int):
            continue
        source, source_carrier = copy
        alias = ReturnPointerAliasStep8616(
            block_addr=block.addr,
            instr_index=instr_index,
            instr_addr=instr_addr,
            source=source,
            target=destination,
        )
        carrier = PointerCarrier8616(
            value=destination,
            aliases=append_unique_pointer_proofs_8616(source_carrier.aliases, (alias,)),
            cfg_edges=source_carrier.cfg_edges,
            phis=source_carrier.phis,
        )
        tainted[_value_key_8616(destination)] = carrier
        if destination_domain is not None:
            live[destination_domain] = carrier
    return PointerBlockScan8616(
        carriers=live,
        saw_unknown_address=saw_unknown,
        saw_ambiguous_address=saw_ambiguous,
        saw_alias_clobber=saw_clobber,
    )
