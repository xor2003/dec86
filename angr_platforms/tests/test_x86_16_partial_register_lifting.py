from __future__ import annotations

import pyvex
from angr import options as o
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from pyvex.expr import Get
from pyvex.stmt import Put

import decompile


def test_mov_cl_immediate_lifts_as_byte_view_without_reading_cx() -> None:
    arch = Arch86_16()
    irsb = pyvex.lift(bytes.fromhex("b105"), 0x1000, arch)

    puts = [statement for statement in irsb.statements if isinstance(statement, Put)]
    full_cx_reads = [
        expr
        for expr in irsb.expressions
        if isinstance(expr, Get)
        and expr.offset == arch.registers["cx"][0]
        and expr.result_size(irsb.tyenv) == 16
    ]

    assert len(puts) == 1
    assert puts[0].offset == arch.registers["cl"][0]
    assert puts[0].data.result_size(irsb.tyenv) == 8
    assert full_cx_reads == []


def test_partial_cl_write_preserves_high_byte_for_later_full_cx_read() -> None:
    code = bytes.fromhex("b10589c8")  # mov cl, 5; mov ax, cx
    project = decompile._build_project_from_bytes(code, base_addr=0x1000, entry_point=0x1000)
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.cx = 0xABCD

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=2, insn_bytes=code)

    assert len(simgr.active) == 1
    successor = simgr.active[0]
    assert successor.solver.eval(successor.regs.cx) == 0xAB05
    assert successor.solver.eval(successor.regs.ax) == 0xAB05
