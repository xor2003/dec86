"""Import terminal VEX control flow into typed x86-16 IR instructions.

Layer: IR.
Responsibility: preserve explicit call targets and instruction addresses from
the third-party VEX block boundary. This module does not classify call
semantics or materialize C.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Any, Protocol, cast

from .core import IRInstr, IRValue, MemSpace

__all__ = ["terminal_control_flow_instr_8616"]


class _VexConstant8616(Protocol):
    """Minimal third-party VEX constant contract."""

    value: object


class _VexConstantExpression8616(Protocol):
    """Minimal third-party VEX constant-expression contract."""

    con: _VexConstant8616


class _VexBlock8616(Protocol):
    """Minimal third-party VEX terminal control-flow contract."""

    jumpkind: object
    next: object


def _constant_target_8616(expr: object) -> int | None:
    """Return an exact integer target from a VEX constant expression."""
    try:
        value = cast(_VexConstantExpression8616, expr).con.value
        return int(cast(Any, value))
    except (AttributeError, TypeError, ValueError):
        return None


def terminal_control_flow_instr_8616(
    vex: object,
    instruction_addr: int | None,
) -> IRInstr | None:
    """Return a typed terminal call when VEX proves one exact call target."""
    try:
        boundary = cast(_VexBlock8616, vex)
        jumpkind = str(boundary.jumpkind)
        target = _constant_target_8616(boundary.next)
    except AttributeError:
        return None
    if jumpkind != "Ijk_Call" or target is None:
        return None
    return IRInstr(
        op="CALL",
        dst=None,
        args=(IRValue(MemSpace.CONST, const=target, size=4),),
        addr=instruction_addr,
    )
