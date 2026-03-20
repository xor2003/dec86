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


def _assert_same_load_effect(code16: bytes, code32: bytes, mem: bytes):
    state32 = _run_load_instruction(ArchX86(), code32, mem)
    state16 = _run_load_instruction(Arch86_16(), code16, mem)

    assert state32.solver.eval(state32.regs.ax) == state16.solver.eval(state16.regs.ax)
    assert state32.solver.eval(state32.regs.si) == state16.solver.eval(state16.regs.si)


def _run_load_instruction(arch, code: bytes, mem: bytes, si: int = 0x220):
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
    state.regs.ds = 0
    try:
        state.regs.si = si
    except AttributeError:
        pass
    try:
        state.regs.esi = si
    except AttributeError:
        pass
    state.memory.store(si, mem)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _assert_same_scan_effect(code16: bytes, code32: bytes, width: int, ax: int, mem: bytes):
    state32 = _run_scan_instruction(ArchX86(), code32, ax=ax, mem=mem)
    state16 = _run_scan_instruction(Arch86_16(), code16, ax=ax, mem=mem)

    assert state32.solver.eval(state32.regs.di) == state16.solver.eval(state16.regs.di)
    for bit in (0, 6, 7, 11):
        assert state32.solver.eval(state32.regs.flags[bit]) == state16.solver.eval(state16.regs.flags[bit])


def _run_scan_instruction(arch, code: bytes, ax: int, mem: bytes, di: int = 0x200):
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
    state.memory.store(di, mem)

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def _run_far_load_instruction(code: bytes, si: int = 0x220):
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.si = si
    state.regs.ds = 0
    state.memory.store(si, b"\x34\x12\x78\x56")

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def test_stosb_matches_upstream_x86_vex_effect():
    _assert_same_store_effect(b"\xAA", b"\xAA", 1, ax=0x125A)


def test_stosw_matches_upstream_x86_vex_effect():
    _assert_same_store_effect(b"\xAB", b"\x66\xAB", 2, ax=0x3456)


def test_lodsb_matches_upstream_x86_vex_effect():
    _assert_same_load_effect(b"\xAC", b"\x67\xAC", b"\x78")


def test_lodsw_matches_upstream_x86_vex_effect():
    _assert_same_load_effect(b"\xAD", b"\x66\x67\xAD", b"\x78\x56")


def test_scasb_matches_upstream_x86_vex_effect():
    _assert_same_scan_effect(b"\xAE", b"\x67\xAE", 1, ax=0x1278, mem=b"\x78")


def test_scasw_matches_upstream_x86_vex_effect():
    _assert_same_scan_effect(b"\xAF", b"\x66\x67\xAF", 2, ax=0x5678, mem=b"\x78\x56")


def test_les_loads_far_pointer_into_register_and_es():
    state = _run_far_load_instruction(b"\xC4\x04")

    assert state.solver.eval(state.regs.ax) == 0x1234
    assert state.solver.eval(state.regs.es) == 0x5678


def test_lds_loads_far_pointer_into_register_and_ds():
    state = _run_far_load_instruction(b"\xC5\x04")

    assert state.solver.eval(state.regs.ax) == 0x1234
    assert state.solver.eval(state.regs.ds) == 0x5678
