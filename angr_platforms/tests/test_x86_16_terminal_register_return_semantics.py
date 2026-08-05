from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.semantics import terminal_register_returns
from angr_platforms.X86_16.semantics.branch_target_return import TerminalAxReturnEffectKind8616
from angr_platforms.X86_16.semantics.terminal_register_returns import (
    TerminalAxReturnLane8616,
    terminal_ax_return_lane_states_8616,
)


class _Factory:
    def __init__(self, blocks: dict[int, object]) -> None:
        self.blocks = blocks

    def block(self, address: int, *, opt_level: int) -> object:
        assert opt_level == 0
        return self.blocks[address]


def _insn(address: int, mnemonic: str, *, size: int = 1, target: int | None = None) -> object:
    operands = () if target is None else (SimpleNamespace(type=2, imm=target),)
    return SimpleNamespace(address=address, size=size, mnemonic=mnemonic, operands=operands)


def test_terminal_ax_paths_start_at_function_entry_and_follow_call_fallthrough(monkeypatch) -> None:
    entry = _insn(0x1000, "call", size=5)
    write_ax = _insn(0x1005, "mov")
    jump = _insn(0x1006, "jmp", target=0x1010)
    terminal = _insn(0x1010, "ret")
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(entry,))),
        0x1005: SimpleNamespace(capstone=SimpleNamespace(insns=(write_ax, jump))),
        0x1010: SimpleNamespace(capstone=SimpleNamespace(insns=(terminal,))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    def _effect(insn: object) -> object:
        if insn is entry:
            return SimpleNamespace(kind=TerminalAxReturnEffectKind8616.CALL_CLOBBER, dst_reg=None)
        return SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg="ax" if insn is write_ax else None,
        )

    monkeypatch.setattr(terminal_register_returns, "terminal_ax_return_effect_8616", _effect)

    states = terminal_ax_return_lane_states_8616(project, function)

    assert states == frozenset({TerminalAxReturnLane8616.WORD})
