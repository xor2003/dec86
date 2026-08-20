"""Recover callee stack cleanup from complete binary terminal paths.

Layer: Semantics.
Responsibility: classify immediate stack cleanup performed by every reachable
return without choosing or mutating a C calling convention.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Forbidden: source/COD/name evidence, rendered-text recovery, or prototype repair.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.errors import SimEngineError, SimTranslationError

from ..frontend_instruction_reachability import decoded_block_instructions_8616

__all__ = [
    "TerminalStackCleanupEvidence8616",
    "collect_terminal_stack_cleanup_evidence_8616",
    "terminal_stack_cleanup_at_address_8616",
]


class _FunctionSurface8616(Protocol):
    """angr function fields consumed by terminal cleanup semantics."""

    addr: int
    block_addrs_set: set[int]


@dataclass(frozen=True, slots=True)
class TerminalStackCleanupEvidence8616:
    """Closed accounting for cleanup amounts on reachable return paths."""

    cleanup_amounts: frozenset[int]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every terminal path has a valid cleanup amount."""
        return (
            self.raw_fact_count > 0
            and self.normalized_fact_count == self.raw_fact_count
            and self.classified_fact_count == self.raw_fact_count
            and self.materialized_count == self.classified_fact_count
            and self.failure_count == 0
        )

    @property
    def consistent_cleanup(self) -> int | None:
        """Return the one cleanup amount proven on every terminal path."""
        if not self.complete or len(self.cleanup_amounts) != 1:
            return None
        return next(iter(self.cleanup_amounts))


def _inner_instruction_8616(insn: object) -> object:
    """Return a dynamic Capstone instruction beneath an optional angr wrapper."""
    try:
        return cast(Any, insn).insn
    except AttributeError:
        return cast(Any, insn)


def _mnemonic_8616(insn: object) -> str:
    """Return a normalized mnemonic across the dynamic Capstone boundary."""
    try:
        return str(cast(Any, insn).mnemonic or "").lower()
    except AttributeError:
        try:
            return str(cast(Any, _inner_instruction_8616(insn)).mnemonic or "").lower()
        except AttributeError:
            return ""


def _fallthrough_8616(insn: object) -> int | None:
    """Return the next instruction address across the Capstone boundary."""
    try:
        address, size = cast(Any, insn).address, cast(Any, insn).size
    except AttributeError:
        inner = cast(Any, _inner_instruction_8616(insn))
        try:
            address, size = inner.address, inner.size
        except AttributeError:
            return None
    return address + size if isinstance(address, int) and isinstance(size, int) and size > 0 else None


def _direct_target_8616(insn: object) -> int | None:
    """Return one direct branch target across the Capstone boundary."""
    inner = cast(Any, _inner_instruction_8616(insn))
    try:
        operands = tuple(inner.operands or ())
    except AttributeError:
        return None
    if len(operands) != 1:
        return None
    operand = cast(Any, operands[0])
    return operand.imm if operand.type == 2 and isinstance(operand.imm, int) else None


def _return_cleanup_8616(insn: object) -> int | None:
    """Return a valid even near/far return immediate, including plain zero."""
    inner = cast(Any, _inner_instruction_8616(insn))
    try:
        operands = tuple(inner.operands or ())
    except AttributeError:
        return None
    if not operands:
        return 0
    if len(operands) != 1:
        return None
    operand = cast(Any, operands[0])
    cleanup = operand.imm if operand.type == 2 else None
    return cleanup if isinstance(cleanup, int) and 0 <= cleanup <= 128 and cleanup % 2 == 0 else None


def _is_conditional_branch_8616(mnemonic: str) -> bool:
    """Return whether a decoded mnemonic has two control-flow successors."""
    return (mnemonic.startswith("j") and mnemonic not in {"jmp", "jmpw"}) or mnemonic.startswith("loop")


def collect_terminal_stack_cleanup_evidence_8616(
    project: object,
    function: object,
) -> TerminalStackCleanupEvidence8616:
    """Collect cleanup amounts along all bounded entry-reachable returns."""
    function_surface = cast(_FunctionSurface8616, function)
    try:
        block_addrs = frozenset(int(addr) for addr in function_surface.block_addrs_set)
        entry_addr = function_surface.addr
    except AttributeError:
        block_addrs, entry_addr = frozenset(), None
    if not isinstance(entry_addr, int) or entry_addr not in block_addrs:
        return TerminalStackCleanupEvidence8616(frozenset(), 1, 0, 0, 0, 1)
    amounts: set[int] = set()
    counts = [0, 0, 0, 0, 0]

    def record_cleanup(cleanup: int) -> None:
        """Record one classified terminal cleanup fact."""
        for index in range(4):
            counts[index] += 1
        amounts.add(cleanup)

    def record_failure() -> None:
        """Record one terminal/control fact that cannot be classified."""
        counts[0] += 1
        counts[4] += 1

    def scan(block_addr: int, path: frozenset[int]) -> None:
        """Follow one bounded control-flow path to a return."""
        if block_addr in path:
            return
        try:
            insns = decoded_block_instructions_8616(cast(Any, project), block_addr, opt_level=0)
        except (KeyError, SimEngineError, SimTranslationError, ValueError):
            record_failure()
            return
        if not insns:
            record_failure()
            return
        for insn in insns:
            mnemonic = _mnemonic_8616(insn)
            if mnemonic.startswith("ret") or mnemonic == "iret":
                cleanup = _return_cleanup_8616(insn)
                if isinstance(cleanup, int):
                    record_cleanup(cleanup)
                else:
                    record_failure()
                return
            if mnemonic in {"jmp", "jmpw", "ljmp"}:
                target = _direct_target_8616(insn)
                if target in block_addrs:
                    scan(target, path | {block_addr})
                else:
                    record_failure()
                return
            if _is_conditional_branch_8616(mnemonic):
                for successor in dict.fromkeys((_direct_target_8616(insn), _fallthrough_8616(insn))):
                    if successor in block_addrs:
                        scan(successor, path | {block_addr})
                    else:
                        record_failure()
                return
        fallthrough = _fallthrough_8616(insns[-1])
        if fallthrough in block_addrs:
            scan(fallthrough, path | {block_addr})
        else:
            record_failure()

    scan(entry_addr, frozenset())
    return TerminalStackCleanupEvidence8616(frozenset(amounts), *counts)


def terminal_stack_cleanup_at_address_8616(
    project: object,
    address: int,
) -> TerminalStackCleanupEvidence8616:
    """Collect a known function or a direct one-block bodyless cleanup contract."""
    try:
        function = cast(Any, project).kb.functions.function(addr=address, create=False)
    except (AttributeError, KeyError):
        function = None
    if function is not None:
        return collect_terminal_stack_cleanup_evidence_8616(project, function)
    try:
        insns = decoded_block_instructions_8616(cast(Any, project), address, opt_level=0)
    except (KeyError, SimEngineError, SimTranslationError, ValueError):
        insns = ()
    if not insns or any(
        _is_conditional_branch_8616(_mnemonic_8616(insn))
        or _mnemonic_8616(insn) in {"jmp", "jmpw", "ljmp"}
        for insn in insns
    ):
        return TerminalStackCleanupEvidence8616(frozenset(), 1, 0, 0, 0, 1)
    terminal = insns[-1]
    cleanup = _return_cleanup_8616(terminal) if _mnemonic_8616(terminal).startswith("ret") else None
    if not isinstance(cleanup, int):
        return TerminalStackCleanupEvidence8616(frozenset(), 1, 0, 0, 0, 1)
    return TerminalStackCleanupEvidence8616(frozenset({cleanup}), 1, 1, 1, 1, 0)
