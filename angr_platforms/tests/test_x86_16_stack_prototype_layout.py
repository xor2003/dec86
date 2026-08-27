"""Tests for typed 16-bit stack-prototype layout projection."""

from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.stack_prototype_layout import stack_prototype_argument_layout_8616


def test_stack_prototype_layout_keeps_two_word_scalar_as_one_argument() -> None:
    """A 32-bit argument owns both adjacent 16-bit stack views."""
    arch = Arch86_16()
    prototype = SimTypeFunction([SimTypeLong()], SimTypeLong()).with_arch(arch)

    layout = stack_prototype_argument_layout_8616(prototype, arch)

    assert [(argument.offset, argument.storage_width) for argument in layout] == [(4, 4)]


def test_stack_prototype_layout_places_pointer_and_word_contiguously() -> None:
    """A near pointer and word occupy distinct two-byte ABI slots."""
    arch = Arch86_16()
    prototype = SimTypeFunction(
        [SimTypePointer(SimTypeChar()), SimTypeShort()],
        SimTypeShort(),
    ).with_arch(arch)

    layout = stack_prototype_argument_layout_8616(prototype, arch)

    assert [(argument.offset, argument.storage_width) for argument in layout] == [(4, 2), (6, 2)]
