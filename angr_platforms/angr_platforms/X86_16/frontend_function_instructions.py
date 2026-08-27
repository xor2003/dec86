"""Collect exact per-function instruction inventories from the angr CFG.

Layer: Frontend.
Responsibility: bind decoded Capstone instructions to one explicit function
entry and its CFG-owned block addresses without assigning semantic effects.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from .frontend_instruction_reachability import decoded_block_instructions_8616

__all__ = [
    "FunctionInstructionInventory8616",
    "FunctionInstructionInventoryStatus8616",
    "collect_function_instruction_inventory_8616",
]


class _FunctionBoundary8616(Protocol):
    """angr function fields consumed at the Frontend boundary."""

    block_addrs_set: Iterable[int]


class _InstructionBoundary8616(Protocol):
    """Capstone instruction identity consumed at the Frontend boundary."""

    address: int


class _FunctionManagerBoundary8616(Protocol):
    """Narrow angr knowledge-base function lookup boundary."""

    def function(
        self,
        *,
        addr: int,
        create: bool = False,
    ) -> _FunctionBoundary8616 | None:
        """Return the function whose entry is ``addr``."""


class _KnowledgeBaseBoundary8616(Protocol):
    """Narrow angr knowledge-base boundary."""

    functions: _FunctionManagerBoundary8616


class _ProjectBoundary8616(Protocol):
    """Narrow angr project boundary used for function instruction lookup."""

    kb: _KnowledgeBaseBoundary8616


class FunctionInstructionInventoryStatus8616(Enum):
    """Typed result of binding decoded instructions to one CFG function."""

    COMPLETE = "complete"
    MISSING_ENTRY = "missing_entry"
    MISSING_FUNCTION = "missing_function"
    MISSING_BLOCKS = "missing_blocks"
    DECODE_REFUSED = "decode_refused"


@dataclass(frozen=True, slots=True)
class FunctionInstructionInventory8616:
    """Instruction evidence owned by one exact CFG function entry."""

    function_entry: int | None
    block_addrs: tuple[int, ...]
    instructions: tuple[object, ...]
    status: FunctionInstructionInventoryStatus8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every CFG block produced instruction evidence."""
        return (
            self.status is FunctionInstructionInventoryStatus8616.COMPLETE
            and self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count
            == self.materialized_count + self.failure_count
            and self.failure_count == 0
            and bool(self.instructions)
        )


def _refused_inventory_8616(
    function_entry: int | None,
    status: FunctionInstructionInventoryStatus8616,
) -> FunctionInstructionInventory8616:
    """Build a closed one-fact refusal for missing function identity evidence."""
    return FunctionInstructionInventory8616(
        function_entry=function_entry,
        block_addrs=(),
        instructions=(),
        status=status,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=1,
    )


def collect_function_instruction_inventory_8616(
    project: object,
    *,
    function_entry: int | None,
) -> FunctionInstructionInventory8616:
    """Decode only blocks owned by the exact current CFG function."""
    if not isinstance(function_entry, int):
        return _refused_inventory_8616(
            None,
            FunctionInstructionInventoryStatus8616.MISSING_ENTRY,
        )

    boundary = cast(_ProjectBoundary8616, project)
    try:
        function = boundary.kb.functions.function(
            addr=int(function_entry),
            create=False,
        )
    except Exception:
        function = None
    if function is None:
        return _refused_inventory_8616(
            int(function_entry),
            FunctionInstructionInventoryStatus8616.MISSING_FUNCTION,
        )

    try:
        block_addrs = tuple(sorted({int(addr) for addr in function.block_addrs_set}))
    except (AttributeError, TypeError, ValueError):
        block_addrs = ()
    if not block_addrs:
        return _refused_inventory_8616(
            int(function_entry),
            FunctionInstructionInventoryStatus8616.MISSING_BLOCKS,
        )

    by_addr: dict[int, object] = {}
    materialized_count = 0
    failure_count = 0
    for block_addr in block_addrs:
        try:
            decoded = decoded_block_instructions_8616(
                project,
                block_addr,
                opt_level=0,
            )
        except Exception:
            decoded = ()
        if not decoded or int(cast(_InstructionBoundary8616, decoded[0]).address) != block_addr:
            failure_count += 1
            continue
        materialized_count += 1
        for instruction in decoded:
            address = int(cast(_InstructionBoundary8616, instruction).address)
            if address >= 0:
                by_addr.setdefault(address, instruction)

    status = (
        FunctionInstructionInventoryStatus8616.COMPLETE
        if failure_count == 0 and by_addr
        else FunctionInstructionInventoryStatus8616.DECODE_REFUSED
    )
    fact_count = len(block_addrs)
    return FunctionInstructionInventory8616(
        function_entry=int(function_entry),
        block_addrs=block_addrs,
        instructions=tuple(by_addr[address] for address in sorted(by_addr)),
        status=status,
        raw_fact_count=fact_count,
        normalized_fact_count=fact_count,
        classified_fact_count=fact_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
