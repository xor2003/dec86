"""Core typed IR objects for values, addresses, conditions, and instructions.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias

__all__ = [
    "AddressStatus",
    "SegmentOrigin",
    "IRAddress",
    "IRBinaryValue",
    "is_stack_address_8616",
    "IRAtom",
    "IRBlock",
    "IRCondition",
    "IRFunctionArtifact",
    "IRInstr",
    "IRRefusal",
    "IRValue",
    "MemSpace",
]


class MemSpace(Enum):
    """Segmented storage space for typed IR values and addresses."""

    REG = "reg"
    DS = "ds"
    ES = "es"
    SS = "ss"
    CONST = "const"
    TMP = "tmp"
    UNKNOWN = "unknown"


class AddressStatus(Enum):
    """Confidence status for a recovered typed IR address."""

    STABLE = "stable"
    PROVISIONAL = "provisional"
    UNKNOWN = "unknown"


class SegmentOrigin(Enum):
    """Evidence source for an address segment choice."""

    PROVEN = "proven"
    DEFAULTED = "defaulted"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class IRValue:
    """Typed scalar value or storage value in the IR layer."""

    space: MemSpace
    name: str | None = None
    offset: int = 0
    const: int | None = None
    size: int = 0
    version: int | None = None
    expr: tuple[str, ...] | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR value for diagnostics and artifacts."""
        return {
            "kind": "value",
            "space": self.space.value,
            "name": self.name,
            "offset": self.offset,
            "const": self.const,
            "size": self.size,
            "version": self.version,
            "expr": self.expr,
        }


@dataclass(frozen=True, slots=True)
class IRBinaryValue:
    """Typed binary value expression whose operands retain storage identity."""

    op: str
    lhs: IRValue
    rhs: IRValue
    size: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed value expression for diagnostics and artifacts."""
        return {
            "kind": "binary_value",
            "op": self.op,
            "lhs": self.lhs.to_dict(),
            "rhs": self.rhs.to_dict(),
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class IRAddress:
    """Typed segmented memory address recovered from instruction evidence."""

    space: MemSpace
    base: tuple[str, ...] = ()
    offset: int = 0
    size: int = 0
    status: AddressStatus = AddressStatus.UNKNOWN
    segment_origin: SegmentOrigin = SegmentOrigin.UNKNOWN
    expr: tuple[str, ...] | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR address for diagnostics and artifacts."""
        return {
            "kind": "address",
            "space": self.space.value,
            "base": list(self.base),
            "offset": self.offset,
            "size": self.size,
            "status": self.status.value,
            "segment_origin": self.segment_origin.value,
            "expr": self.expr,
        }


def is_stack_address_8616(addr: IRAddress) -> bool:
    """Return whether an address is a proven or likely SS:BP/SP stack slot."""

    def _impl() -> bool:
        """Classify stack addresses without lowering them.

        AGENTS rule: SS:BP+offset MUST become a stack slot, never fallback to memory.
        """
        if addr.space != MemSpace.SS:
            return False
        # Proven segment origin: explicit SS segment instruction
        if addr.segment_origin == SegmentOrigin.PROVEN:
            base_set = set(addr.base)
            if {"ss"} & base_set or {"bp"} & base_set or {"sp"} & base_set:
                return True
        # Expression-based: BP or SP appears in the expression tuple
        if addr.expr:
            expr_set = set(addr.expr)
            if {"bp", "sp", "ss"} & expr_set:
                return True
        # Defaulted segment with BP base hint
        if addr.segment_origin == SegmentOrigin.DEFAULTED and addr.space == MemSpace.SS:
            base_set = set(addr.base)
            if {"bp"} & base_set:
                return True
        return False

    return _impl()


@dataclass(frozen=True, slots=True)
class IRCondition:
    """Typed branch or predicate condition in the IR layer."""

    op: str
    args: tuple["IRAtom", ...]
    expr: tuple[str, ...] | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR condition for diagnostics and artifacts."""
        return {
            "kind": "condition",
            "op": self.op,
            "args": [_atom_to_dict(arg) for arg in self.args],
            "expr": self.expr,
        }


IRAtom: TypeAlias = IRValue | IRBinaryValue | IRAddress | IRCondition


def _atom_to_dict(atom: IRAtom) -> dict[str, object]:
    return atom.to_dict()


@dataclass(frozen=True, slots=True)
class IRInstr:
    """Typed instruction fact with destination, arguments, size, and address."""

    op: str
    dst: IRValue | None
    args: tuple[IRAtom, ...]
    size: int = 0
    addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR instruction for diagnostics and artifacts."""
        return {
            "op": self.op,
            "dst": None if self.dst is None else self.dst.to_dict(),
            "args": [_atom_to_dict(arg) for arg in self.args],
            "size": self.size,
            "addr": self.addr,
        }


@dataclass(frozen=True, slots=True)
class IRRefusal:
    """Structured reason why an IR fact could not be recovered."""

    kind: str
    detail: str
    block_addr: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this IR refusal for diagnostics and artifacts."""
        return {
            "kind": self.kind,
            "detail": self.detail,
            "block_addr": self.block_addr,
        }


@dataclass(frozen=True, slots=True)
class IRBlock:
    """Typed IR block with instructions, refusals, and successor addresses."""

    addr: int
    instrs: tuple[IRInstr, ...] = ()
    refusals: tuple[IRRefusal, ...] = ()
    successor_addrs: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize this typed IR block for diagnostics and artifacts."""
        return {
            "addr": self.addr,
            "instrs": [instr.to_dict() for instr in self.instrs],
            "refusals": [item.to_dict() for item in self.refusals],
            "successor_addrs": list(self.successor_addrs),
        }


@dataclass(frozen=True, slots=True)
class IRFunctionArtifact:
    """Typed IR artifact for one recovered function."""

    function_addr: int
    blocks: tuple[IRBlock, ...] = ()
    refusals: tuple[IRRefusal, ...] = ()
    summary: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize this function-level typed IR artifact."""
        return {
            "function_addr": self.function_addr,
            "blocks": [block.to_dict() for block in self.blocks],
            "refusals": [item.to_dict() for item in self.refusals],
            "summary": dict(self.summary),
        }
