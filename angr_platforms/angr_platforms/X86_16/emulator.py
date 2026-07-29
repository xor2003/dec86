"""Layer: Frontend/runtime.

Responsibility: bridge processor, interrupt, stack, and VEX value operations for the lifter.
Forbidden: decompiler semantic recovery, source/COD-backed behavior, or validation gating.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, cast

from pyvex.expr import Const, RdTmp
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import IRSBCustomizer, Type

from .interrupt import Interrupt
from .processor import Processor
from .stack_helpers import StackEmulator
from .stack_helpers import pop16 as stack_pop16
from .stack_helpers import push16 as stack_push16

__all__ = ("Emulator",)


class _ArchRegister(Protocol):
    """Register metadata required from the frontend architecture."""

    name: str
    vex_offset: int


class _EmulatorArch(Protocol):
    """Architecture contract consumed by the emulator bridge."""

    register_list: Iterable[_ArchRegister]


class _LifterWithIrsb(Protocol):
    """Lifter contract needed during emulator construction."""

    irsb: object


class _LifterInstruction(Protocol):
    """Active VEX lifter instruction surface used to wrap expressions."""

    def _settmp(self, value: object) -> RdTmp | Const:
        """Materialize a VEX temporary for an expression."""
        ...


class _RuntimeHooks(Protocol):
    """Processor/DataAccess hooks supplied by the runtime inheritance stack."""

    lifter_instruction: _LifterInstruction | None

    def constant(self, value: int, _type: object = Type.int_8) -> object:
        """Build a typed frontend constant."""
        ...

    def read_mem16_seg(self, seg: object, addr: object) -> object:
        """Read a segmented 16-bit value through DataAccess."""
        ...

    def write_mem16_seg(self, seg: object, addr: object, val: object) -> None:
        """Write a segmented 16-bit value through DataAccess."""
        ...


class Emulator(Interrupt):
    """Bridge processor state, stack helpers, interrupts, and VEX values."""

    def __init__(self, arch: _EmulatorArch, lifter: _LifterWithIrsb | None = None) -> None:
        """Initialize frontend runtime state for one architecture instance."""
        Processor.__init__(self)
        Interrupt.__init__(self)
        self.arch = arch
        self.lifter = lifter
        self.irsb = lifter.irsb if lifter else None
        self.vex_offsets: dict[str, int] = {register.name.lower(): register.vex_offset for register in arch.register_list}
        self.regs: dict[str, object] = {}

    def chk_ring(self, _dpl: int) -> bool:
        """Return whether the current real-mode frontend permits a ring-sensitive instruction."""
        # The current x86-16 lifter only models real-mode execution, where ring checks
        # should not block instructions like HLT inside the verification harness.
        return True

    def _vv(self, value: object, ty: object | None = None) -> object:
        """Wrap Python constants or VEX expressions as VexValue objects."""
        if isinstance(value, VexValue):
            return value
        hooks = cast(_RuntimeHooks, self)
        if isinstance(value, int):
            if ty is None:
                raise ValueError("type is required to wrap an integer into a VEX value")
            return hooks.constant(value, ty)
        if hooks.lifter_instruction is None:
            raise ValueError("cannot wrap a non-constant VEX expression without an active lifter instruction")
        lifter_instruction = hooks.lifter_instruction
        return VexValue(cast(IRSBCustomizer, lifter_instruction), lifter_instruction._settmp(value))

    def push16(self, val: object) -> None:
        """Push a 16-bit value through the shared stack helper."""
        hooks = cast(_RuntimeHooks, self)
        if isinstance(val, VexValue) and hooks.lifter_instruction is not None:
            # Snapshot register-backed values like PUSH SP before we mutate SP itself.
            val = self._vv(val.rdt)
        if isinstance(val, int):
            val = hooks.constant(val, Type.int_16)
        stack_push16(cast(StackEmulator, self), val)

    def pop16(self) -> object:
        """Pop a 16-bit value through the shared stack helper."""
        return stack_pop16(cast(StackEmulator, self))

    def get_data16(self, seg: object, addr: object) -> object:
        """Read segmented 16-bit data through the frontend memory bridge."""
        return cast(_RuntimeHooks, self).read_mem16_seg(seg, addr)

    def put_data16(self, seg: object, addr: object, val: object) -> None:
        """Write segmented 16-bit data through the frontend memory bridge."""
        cast(_RuntimeHooks, self).write_mem16_seg(seg, addr, val)
