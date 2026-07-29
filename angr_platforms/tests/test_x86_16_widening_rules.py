from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.widening.widening_rules import collect_bp_stack_access_widths_from_instructions_8616


def test_collect_bp_stack_access_widths_uses_linear_summaries_without_block_metadata():
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            # mov word ptr [bp-2], ax
            return b"\x89\x46\xfe"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=None),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, size=3, name="store_tmp"),
    )

    widths = collect_bp_stack_access_widths_from_instructions_8616(project, codegen)

    assert widths == {-2: 2}


def test_collect_bp_stack_access_widths_excludes_lea_address_width():
    class _Memory:
        def load(self, addr, size):
            assert addr == 0x4010
            # lea ax, [bp-82]; mov byte ptr [bp-82], 0
            return b"\x8d\x46\xae\xc6\x46\xae\x00"[:size]

    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=None),
        loader=SimpleNamespace(memory=_Memory()),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010, size=7, name="addressed_byte_array"),
    )

    widths = collect_bp_stack_access_widths_from_instructions_8616(project, codegen)

    assert widths == {-82: 1}
