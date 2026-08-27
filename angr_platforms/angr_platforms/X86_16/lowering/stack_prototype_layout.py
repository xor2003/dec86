"""Project typed function prototypes onto the 16-bit BP stack ABI.

Layer: Types/Lowering.
Responsibility: derive exact contiguous stack slots from already-owned argument
types so contained word views do not become duplicate function arguments.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: assembly, source, symbol-name, or rendered-C inference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from angr.sim_type import SimType, SimTypeFunction
from archinfo import Arch

__all__ = ["StackPrototypeArgument8616", "stack_prototype_argument_layout_8616"]


@dataclass(frozen=True, slots=True)
class StackPrototypeArgument8616:
    """One typed argument's exact storage slot in a near-call BP frame."""

    offset: int
    storage_width: int
    argument_type: SimType


def stack_prototype_argument_layout_8616(
    prototype: object,
    arch: Arch,
) -> tuple[StackPrototypeArgument8616, ...]:
    """Return a contiguous BP+4 layout, or no layout when a type lacks size evidence."""
    if not isinstance(prototype, SimTypeFunction):
        return ()
    byte_width = arch.byte_width
    if not isinstance(byte_width, int) or byte_width <= 0:
        return ()
    cursor = 4
    layout: list[StackPrototypeArgument8616] = []
    for raw_type in prototype.args or ():
        if not isinstance(raw_type, SimType):
            return ()
        argument_type = raw_type
        try:
            if argument_type._arch is None:  # third-party SimType boundary
                argument_type = cast(SimType, argument_type.with_arch(arch))
            size_bits = argument_type.size
        except (AttributeError, TypeError, ValueError):
            return ()
        if not isinstance(size_bits, int) or size_bits <= 0 or size_bits % byte_width != 0:
            return ()
        value_width = size_bits // byte_width
        storage_width = max(2, (value_width + 1) & ~1)
        layout.append(StackPrototypeArgument8616(cursor, storage_width, argument_type))
        cursor += storage_width
    return tuple(layout)
