"""Focused tests for collecting decoded real-mode interrupt calls.

Layer: frontend analysis
Responsibility: prove that interrupt opcode forms become typed interrupt-call facts.
"""

from types import SimpleNamespace

import angr
from angr_platforms.X86_16.analysis_helpers import collect_interrupt_calls


def test_collect_interrupt_calls_recognizes_single_byte_int3() -> None:
    """Map opcode CC's operand-free mnemonic to interrupt vector 3."""
    project = angr.load_shellcode(
        b"\xcc\xc3",
        arch="X86_16",
        load_address=0x1000,
        simos="DOS",
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1000})

    calls = collect_interrupt_calls(function)

    assert len(calls) == 1
    assert calls[0].vector == 3
    assert calls[0].insn_addr == 0x1000
