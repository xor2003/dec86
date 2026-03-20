from __future__ import annotations

import angr
from angr import options as o
from archinfo import ArchX86

from angr_platforms.X86_16.arch_86_16 import Arch86_16


def _run_one_instruction(arch, code: bytes, ax: int = 0x125A, di: int = 0x200):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ax = ax
    state.regs.es = 0
    try:
        state.regs.di = di
    except AttributeError:
        pass
    try:
        state.regs.edi = di
    except AttributeError:
        pass

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _assert_same_store_effect(code16: bytes, code32: bytes, width: int, ax: int):
    state32 = _run_one_instruction(ArchX86(), code32, ax=ax)
    state16 = _run_one_instruction(Arch86_16(), code16, ax=ax)

    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)
    assert state32.solver.eval(state32.memory.load(0x200, width, endness=state32.arch.memory_endness)) == (
        state16.solver.eval(state16.memory.load(0x200, width, endness=state16.arch.memory_endness))
    )


def test_stosb_matches_upstream_x86_vex_effect():
    _assert_same_store_effect(b"\xAA", b"\xAA", 1, ax=0x125A)


def test_stosw_matches_upstream_x86_vex_effect():
    _assert_same_store_effect(b"\xAB", b"\x66\xAB", 2, ax=0x3456)
