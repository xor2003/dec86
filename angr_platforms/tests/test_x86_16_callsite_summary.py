from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.analysis_helpers import CallTargetSeed
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616, summarize_x86_16_callsite


class _Operand:
    def __init__(self, *, reg: int | None = None, imm: int | None = None, size: int | None = None):
        self.reg = reg
        self.imm = imm
        self.size = size


class _Insn:
    def __init__(self, address: int, mnemonic: str, operands: list[_Operand] | None = None, reg_names: dict[int, str] | None = None):
        self.address = address
        self.mnemonic = mnemonic
        self.insn = SimpleNamespace(operands=tuple(operands or ()), reg_name=lambda reg: (reg_names or {}).get(reg, ""))


def _function_with_block(insns):
    block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    return SimpleNamespace(project=project)


def test_callsite_summary_reports_push_args_cleanup_and_return_use(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=1, size=2)]),
            _Insn(0x1001, "push", [_Operand(imm=2, size=2)]),
            _Insn(0x1002, "call"),
            _Insn(0x1005, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
            _Insn(0x1008, "test", [_Operand(reg=2), _Operand(reg=2)], reg_names={2: "ax"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1002,
        target_addr=0x1544,
        return_addr=0x1005,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
    )


def test_callsite_summary_returns_empty_shape_when_block_has_no_neighbors(monkeypatch):
    function = _function_with_block([_Insn(0x1002, "call")])
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1002,
        target_addr=None,
        return_addr=None,
        kind=None,
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register=None,
        return_used=False,
    )
