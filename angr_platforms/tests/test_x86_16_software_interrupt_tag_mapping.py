"""Regression tests for software-interrupt callsite tag boundaries."""

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.rustylib.ailment import Tags
from angr_platforms.X86_16.lowering.software_interrupt_calls import (
    _callsite_addr_8616 as lowering_callsite_addr_8616,
)
from angr_platforms.X86_16.structuring.software_interrupt_returns import (
    _callsite_addr_8616 as structuring_callsite_addr_8616,
)
from angr_platforms.X86_16.validation_interrupt_calls import (
    _callsite_addr_8616 as validation_callsite_addr_8616,
)


class _Codegen:
    def next_idx(self) -> int:
        return 1

    def next_node_idx(self) -> int:
        return 1

    def next_ident(self, _node_type: str) -> str:
        return "node_1"


def test_software_interrupt_callsite_accepts_current_angr_tags() -> None:
    call = structured_c.CFunctionCall(
        "interrupt_int33",
        None,
        [],
        tags=Tags({"ins_addr": 0x1020}),
        codegen=_Codegen(),
    )

    assert lowering_callsite_addr_8616(call) == 0x1020
    assert structuring_callsite_addr_8616(call) == 0x1020
    assert validation_callsite_addr_8616(call) == 0x1020
