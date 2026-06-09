from __future__ import annotations

from types import SimpleNamespace

from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from angr_platforms.X86_16.analysis_helpers import CallTargetSeed, resolve_direct_call_target_from_block
from angr_platforms.X86_16.callsite_summary import (
    CallsitePushExprOp8616,
    CallsiteReturnShape8616,
    CallsiteSummary8616,
    summarize_x86_16_callsite,
    _return_shape_after_call,
)


MSC_ANCHKSTK_BYTES = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")


class _Operand:
    def __init__(
        self,
        *,
        reg: int | None = None,
        imm: int | None = None,
        size: int | None = None,
        mem: object | None = None,
        operand_type: int | None = None,
    ):
        self.reg = reg
        self.imm = imm
        self.size = size
        self.mem = mem
        if isinstance(operand_type, int):
            self.type = operand_type


class _Insn:
    def __init__(
        self,
        address: int,
        mnemonic: str,
        operands: list[_Operand] | None = None,
        reg_names: dict[int, str] | None = None,
    ):
        self.address = address
        self.mnemonic = mnemonic
        for operand in operands or ():
            if not hasattr(operand, "type"):
                if getattr(operand, "mem", None) is not None:
                    operand.type = X86_OP_MEM
                elif isinstance(getattr(operand, "reg", None), int):
                    operand.type = X86_OP_REG
                elif isinstance(getattr(operand, "imm", None), int):
                    operand.type = X86_OP_IMM
                else:
                    operand.type = None
        self.insn = SimpleNamespace(operands=tuple(operands or ()), reg_name=lambda reg: (reg_names or {}).get(reg, ""))


def _function_with_block(insns):
    block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    return SimpleNamespace(project=project)


def _project_with_call_insn(insn, *, linked_base: int = 0x10000, max_addr: int = 0x1000):
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(insn,)))
    return SimpleNamespace(
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=linked_base, max_addr=max_addr)),
    )


def test_direct_call_target_preserves_project_linear_near_immediate():
    project = _project_with_call_insn(_Insn(0x10016, "call", [_Operand(imm=0x105D2)]))

    assert resolve_direct_call_target_from_block(project, 0x10016) == 0x105D2


def test_direct_call_target_rebases_unbased_near_immediate_with_image_evidence():
    project = _project_with_call_insn(_Insn(0x10016, "call", [_Operand(imm=0x05D2)]))

    assert resolve_direct_call_target_from_block(project, 0x10016) == 0x105D2


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
        return_shape=CallsiteReturnShape8616.AX.value,
        stack_probe_helper=False,
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
        stack_probe_helper=False,
    )


def test_callsite_summary_uses_containing_block_for_push_args_before_call(monkeypatch):
    insns = (
        _Insn(0x1009, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
        _Insn(0x100A, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
        _Insn(0x100B, "push", [_Operand(imm=4, size=2)]),
        _Insn(0x100E, "call"),
        _Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1009})
    monkeypatch.setattr(
        function,
        "get_call_sites",
        lambda: [0x100E],
        raising=False,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x100E,
        target_addr=0x1544,
        return_addr=0x1011,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_counts_pushes_separated_by_register_setup(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=1, size=2)]),
            _Insn(0x1001, "mov", [_Operand(reg=2), _Operand(imm=0x61)], reg_names={2: "ax"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1005, "call"),
            _Insn(0x1008, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1005, 0x1544, 0x1008, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1005)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1005,
        target_addr=0x1544,
        return_addr=0x1008,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_counts_pushes_separated_by_register_arithmetic_chain(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "mov", [_Operand(reg=2), _Operand(imm=3)], reg_names={2: "ax"}),
            _Insn(0x1003, "shl", [_Operand(reg=2), _Operand(imm=1)], reg_names={2: "ax"}),
            _Insn(0x1005, "add", [_Operand(reg=2), _Operand(imm=0x0B4C)], reg_names={2: "ax"}),
            _Insn(0x1008, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1009, "mov", [_Operand(reg=2), _Operand(imm=5)], reg_names={2: "ax"}),
            _Insn(0x100C, "shl", [_Operand(reg=2), _Operand(imm=1)], reg_names={2: "ax"}),
            _Insn(0x100E, "add", [_Operand(reg=2), _Operand(imm=0x0B4C)], reg_names={2: "ax"}),
            _Insn(0x1011, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1012, "call"),
            _Insn(0x1015, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1012, 0x1544, 0x1015, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1012)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1012,
        target_addr=0x1544,
        return_addr=0x1015,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_records_proven_imul_ax_memory_push_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "mov", [_Operand(reg=2), _Operand(imm=75)], reg_names={2: "ax"}),
            _Insn(0x1003, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "mov", [_Operand(reg=2), _Operand(imm=60)], reg_names={2: "ax"}),
            _Insn(
                0x1007,
                "imul",
                [_Operand(mem=SimpleNamespace(base=5, index=0, disp=4), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x100A, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x100B, "call"),
            _Insn(0x100E, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100B, 0x1544, 0x100E, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100B)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.stack_cleanup == 4
    assert summary.push_arg_sources == (
        ("imm", 75),
        ("expr", ("bp", 4), ((CallsitePushExprOp8616.MUL.value, 60),)),
    )


def test_callsite_summary_records_absolute_memory_push_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "push",
                [_Operand(mem=SimpleNamespace(base=0, index=0, disp=0x1234), size=2)],
                reg_names={1: "sp"},
            ),
            _Insn(0x1003, "call"),
            _Insn(0x1006, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1003, 0x1544, 0x1006, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1003)

    assert summary.arg_count == 1
    assert summary.arg_widths == (2,)
    assert summary.push_arg_sources == (("global", 0x1234, 2),)


def test_callsite_summary_records_ax_byte_indexed_global_push_source(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "bx", 5: "bp", 6: "al"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=5, index=0, disp=4), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1003, "shl", [_Operand(reg=3), _Operand(imm=1)], reg_names=reg_names),
            _Insn(
                0x1005,
                "mov",
                [_Operand(reg=6), _Operand(mem=SimpleNamespace(base=3, index=0, disp=0x0B4C), size=1)],
                reg_names=reg_names,
            ),
            _Insn(0x1009, "cwde"),
            _Insn(0x100A, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100B, "call"),
            _Insn(0x100E, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100B, 0x1544, 0x100E, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100B)

    assert summary.arg_count == 1
    assert summary.arg_widths == (2,)
    assert summary.push_arg_sources == (
        ("global_index", 0x0B4C, 1, ("bp", 4), ((CallsitePushExprOp8616.SHL.value, 1),)),
    )


def test_callsite_summary_records_dx_ax_global_sub_borrow_push_sources(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "dx"}
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x132), size=2)],
                reg_names=reg_names,
            ),
            _Insn(
                0x1003,
                "mov",
                [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x134), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x1006, "sub", [_Operand(reg=2), _Operand(imm=75)], reg_names=reg_names),
            _Insn(0x1009, "sbb", [_Operand(reg=3), _Operand(imm=0)], reg_names=reg_names),
            _Insn(0x100C, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
            _Insn(0x100D, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100E, "call"),
            _Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (
        ("expr", ("global", 0x134, 2), ((CallsitePushExprOp8616.SBB.value, 0),)),
        ("expr", ("global", 0x132, 2), ((CallsitePushExprOp8616.SUB.value, 75),)),
    )


def test_callsite_summary_does_not_treat_register_union_mem_as_global(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "mov", [_Operand(reg=2), _Operand(imm=15)], reg_names={1: "sp", 2: "ax"}),
            _Insn(
                0x1003,
                "push",
                [
                    _Operand(
                        reg=2,
                        size=2,
                        mem=SimpleNamespace(base=0, index=0, disp=0),
                        operand_type=X86_OP_REG,
                    )
                ],
                reg_names={1: "sp", 2: "ax"},
            ),
            _Insn(0x1004, "call"),
            _Insn(0x1007, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1004, 0x1544, 0x1007, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1004)

    assert summary.arg_count == 1
    assert summary.arg_widths == (2,)
    assert summary.push_arg_sources == (("imm", 15),)


def test_callsite_summary_records_forwarded_dx_ax_return_push_sources(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "dx", 5: "bp"}
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=0x1111, size=2)], reg_names=reg_names),
            _Insn(0x1002, "push", [_Operand(imm=0x2222, size=2)], reg_names=reg_names),
            _Insn(0x1004, "call", [_Operand(imm=0x2000)], reg_names=reg_names),
            _Insn(0x1007, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
            _Insn(0x1008, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x1009, "push", [_Operand(imm=0x17D, size=2)], reg_names=reg_names),
            _Insn(
                0x100B,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-80), size=2)],
                reg_names=reg_names,
            ),
            _Insn(0x100E, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
            _Insn(0x100F, "call", [_Operand(imm=0x3000)], reg_names=reg_names),
            _Insn(0x1012, "add", [_Operand(reg=1), _Operand(imm=8)], reg_names=reg_names),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100F, 0x3000, 0x1012, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100F)

    assert summary.arg_count == 4
    assert summary.arg_widths == (2, 2, 2, 2)
    assert summary.push_arg_sources == (
        ("ret_reg", 0x1004, "dx"),
        ("ret_reg", 0x1004, "ax"),
        ("imm", 0x17D),
        ("bp_addr", -80),
    )


def test_callsite_summary_keeps_outer_pushes_across_nested_callee_clean_call(monkeypatch):
    reg_names = {1: "sp", 2: "ax", 3: "dx", 5: "bp"}
    insns = [
        _Insn(0x1000, "push", [_Operand(imm=0x1111, size=2)], reg_names=reg_names),
        _Insn(0x1002, "push", [_Operand(imm=0x2222, size=2)], reg_names=reg_names),
        _Insn(0x1004, "mov", [_Operand(reg=2), _Operand(imm=0x03E8)], reg_names=reg_names),
        _Insn(0x1007, "mov", [_Operand(reg=3), _Operand(imm=0)], reg_names=reg_names),
        _Insn(0x100A, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x100B, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x100C, "mov", [_Operand(reg=2), _Operand(imm=0x3333)], reg_names=reg_names),
        _Insn(0x100F, "mov", [_Operand(reg=3), _Operand(imm=0x4444)], reg_names=reg_names),
        _Insn(0x1010, "sub", [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x10))], reg_names=reg_names),
        _Insn(0x1011, "sbb", [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x12))], reg_names=reg_names),
        _Insn(0x1012, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1013, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x1014, "call", [_Operand(imm=0x2000)], reg_names=reg_names),
        _Insn(0x1017, "push", [_Operand(reg=3, size=2)], reg_names=reg_names),
        _Insn(0x1018, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x1019, "push", [_Operand(imm=0x17D, size=2)], reg_names=reg_names),
        _Insn(
            0x101B,
            "lea",
            [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-80), size=2)],
            reg_names=reg_names,
        ),
        _Insn(0x101E, "push", [_Operand(reg=2, size=2)], reg_names=reg_names),
        _Insn(0x101F, "call", [_Operand(imm=0x3000)], reg_names=reg_names),
        _Insn(0x1022, "add", [_Operand(reg=1), _Operand(imm=12)], reg_names=reg_names),
    ]
    main_block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))
    callee_block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_Insn(0x2000, "ret", [_Operand(imm=8)], reg_names=reg_names),))
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, **_kwargs: callee_block if addr == 0x2000 else main_block),
    )
    function = SimpleNamespace(project=project, addr=0x5000, block_addrs_set={0x1000})
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x101F, 0x3000, 0x1022, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x101F)

    assert summary.arg_count == 6
    assert summary.arg_widths == (2, 2, 2, 2, 2, 2)
    assert summary.stack_cleanup == 12
    assert summary.push_arg_sources == (
        ("imm", 0x1111),
        ("imm", 0x2222),
        ("ret_reg", 0x1014, "dx"),
        ("ret_reg", 0x1014, "ax"),
        ("imm", 0x17D),
        ("bp_addr", -80),
    )


def test_callsite_summary_records_register_dec_push_expr_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-2), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x1003, "dec", [_Operand(reg=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1005, "call"),
            _Insn(0x1008, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1005, 0x1544, 0x1008, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1005)

    assert summary.arg_count == 1
    assert summary.push_arg_sources == (("expr", ("bp", -2), (("sub", 1),)),)


def test_callsite_summary_records_global_add_push_expr_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "mov",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=0, index=0, disp=0x0BAC), size=2)],
                reg_names={1: "sp", 2: "ax"},
            ),
            _Insn(0x1003, "add", [_Operand(reg=2), _Operand(imm=7)], reg_names={1: "sp", 2: "ax"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={1: "sp", 2: "ax"}),
            _Insn(0x1005, "push", [_Operand(imm=59, size=2)], reg_names={1: "sp", 2: "ax"}),
            _Insn(0x1006, "call"),
            _Insn(0x1009, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp", 2: "ax"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1006, 0x1544, 0x1009, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1006)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (("expr", ("global", 0x0BAC, 2), (("add", 7),)), ("imm", 59))


def test_callsite_summary_records_lea_bp_push_address_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-44), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x1003, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "call"),
            _Insn(0x1007, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1004, 0x1544, 0x1007, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1004)

    assert summary.arg_count == 1
    assert summary.push_arg_sources == (("bp_addr", -44),)


def test_callsite_summary_records_lea_bp_index_push_address_source(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=6, scale=1, disp=-44), size=2)],
                reg_names={2: "ax", 5: "bp", 6: "si"},
            ),
            _Insn(0x1003, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1004, "call"),
            _Insn(0x1007, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1004, 0x1544, 0x1007, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1004)

    assert summary.arg_count == 1
    assert summary.push_arg_sources == (("bp_index_addr", -44, "si", 1),)


def test_callsite_summary_keeps_prior_pushes_before_indexed_lea_setup(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(mem=SimpleNamespace(base=5, index=0, disp=-46), size=2)], reg_names={5: "bp"}),
            _Insn(0x1003, "mov", [_Operand(reg=2), _Operand(imm=32)], reg_names={2: "ax"}),
            _Insn(0x1006, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1007, "mov", [_Operand(reg=3), _Operand(mem=SimpleNamespace(base=5, index=0, disp=4))], reg_names={3: "bx", 5: "bp"}),
            _Insn(0x100A, "shl", [_Operand(reg=3), _Operand(imm=1)], reg_names={3: "bx"}),
            _Insn(0x100C, "mov", [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=3, index=0, disp=0xB4C))], reg_names={2: "ax", 3: "bx"}),
            _Insn(0x100F, "cwde", []),
            _Insn(0x1010, "mov", [_Operand(reg=6), _Operand(reg=2)], reg_names={2: "ax", 6: "si"}),
            _Insn(
                0x1012,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=6, scale=1, disp=-44), size=2)],
                reg_names={2: "ax", 5: "bp", 6: "si"},
            ),
            _Insn(0x1015, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1016, "call"),
            _Insn(0x1019, "add", [_Operand(reg=1), _Operand(imm=6)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1016, 0x1544, 0x1019, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1016)

    assert summary.arg_count == 3
    assert summary.arg_widths == (2, 2, 2)
    assert summary.push_arg_sources == (
        ("bp", -46),
        ("imm", 32),
        ("bp_index_addr", -44, "si", 1, ("global_index", 0xB4C, 2, ("bp", 4), (("shl", 1),))),
    )


def test_callsite_summary_keeps_segment_pointer_arg_before_call_return_segment(monkeypatch):
    function = _function_with_block(
        [
            _Insn(
                0x1000,
                "lea",
                [_Operand(reg=2), _Operand(mem=SimpleNamespace(base=5, index=0, disp=-44), size=2)],
                reg_names={2: "ax", 5: "bp"},
            ),
            _Insn(0x1003, "push", [_Operand(reg=8, size=2)], reg_names={8: "ss"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1005, "nop"),
            _Insn(0x1006, "push", [_Operand(reg=9, size=2)], reg_names={9: "cs"}),
            _Insn(0x1007, "call"),
            _Insn(0x100A, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1007, 0x1544, 0x100A, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1007)

    assert summary.arg_count == 2
    assert summary.arg_widths == (2, 2)
    assert summary.push_arg_sources == (("seg", "ss"), ("bp_addr", -44))


def test_callsite_summary_uses_fallthrough_cleanup_block_after_call(monkeypatch):
    call_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x1009, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
                _Insn(0x100A, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
                _Insn(0x100B, "push", [_Operand(imm=4, size=2)]),
                _Insn(0x100E, "call"),
            )
        )
    )
    cleanup_block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),))
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: call_block if addr == 0x1009 else cleanup_block),
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1009, 0x1011})
    monkeypatch.setattr(
        function,
        "get_call_sites",
        lambda: [0x100E],
        raising=False,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x100E,
        target_addr=0x1544,
        return_addr=0x1011,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_marks_known_stack_probe_helpers(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)
        ),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_state == "stack_address"
    assert summary.helper_return_space == "ss"
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_marks_binary_signature_stack_probe_without_sidecars(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))

    def _load(addr: int, size: int):
        if addr != 0x1544:
            raise KeyError(addr)
        return MSC_ANCHKSTK_BYTES[:size]

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        loader=SimpleNamespace(memory=SimpleNamespace(load=_load)),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: None), labels={}),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_helper_signature_overrides_generic_stub_name(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))

    def _load(addr: int, size: int):
        if addr != 0x1544:
            raise KeyError(addr)
        return MSC_ANCHKSTK_BYTES[:size]

    generic_stub = SimpleNamespace(addr=0x1544, name="sub_1544")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        loader=SimpleNamespace(memory=SimpleNamespace(load=_load)),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: generic_stub), labels={}),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_state == "stack_address"


def test_callsite_summary_marks_rebased_exact_slice_stack_probe_helper_from_original_project(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    original_project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: (
                    SimpleNamespace(addr=addr, name="aNchkstk") if addr == 0x11222 else None
                )
            ),
            labels={0x11222: "aNchkstk"},
        ),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x11222: "aNchkstk"}),
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0x10222,
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1000, 0x1005, "direct_far")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_marks_stack_probe_returned_stack_address_when_ax_is_consumed(monkeypatch):
    insns = (
        _Insn(0x1002, "call"),
        _Insn(0x1005, "mov", [_Operand(reg=3), _Operand(reg=2)], reg_names={2: "ax", 3: "bx"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)
        ),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.return_register == "ax"
    assert summary.return_used is True
    assert summary.helper_return_state == "stack_address"
    assert summary.helper_return_space == "ss"
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_detects_dx_ax_return_shape(monkeypatch):
    bp_base = 7
    insns = (
        _Insn(0x1002, "call"),
        _Insn(
            0x1005,
            "mov",
            [
                _Operand(mem=SimpleNamespace(base=bp_base, disp=-4), size=2),
                _Operand(reg=2),
            ],
            reg_names={bp_base: "bp", 2: "ax"},
        ),
        _Insn(
            0x1007,
            "mov",
            [
                _Operand(mem=SimpleNamespace(base=bp_base, disp=-2), size=2),
                _Operand(reg=3),
            ],
            reg_names={bp_base: "bp", 3: "dx"},
        ),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1500, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.return_shape == CallsiteReturnShape8616.DX_AX.value


def test_callsite_summary_uses_ax_shape_without_paired_dx_ax_stores(monkeypatch):
    insns = (
        _Insn(0x1002, "call"),
        _Insn(
            0x1005,
            "cmp",
            [_Operand(reg=2), _Operand(reg=3)],
            reg_names={2: "ax", 3: "dx"},
        ),
    )
    function = SimpleNamespace()

    shape = _return_shape_after_call(function, insns, 0, 0x1002)

    assert shape == CallsiteReturnShape8616.AX


def test_callsite_summary_does_not_claim_stack_address_when_probe_return_is_not_consumed(monkeypatch):
    insns = (
        _Insn(0x1002, "call"),
        _Insn(0x1005, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
        _Insn(0x1006, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)
        ),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.return_register is None
    assert summary.return_used is False
    assert summary.helper_return_state == "none"
    assert summary.helper_return_space is None
    assert summary.helper_return_width is None
    assert summary.helper_return_address_kind == "none"
