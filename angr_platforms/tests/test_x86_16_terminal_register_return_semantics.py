from __future__ import annotations

from types import SimpleNamespace

from angr.errors import SimEngineError
from angr_platforms.X86_16.semantics import terminal_register_returns
from angr_platforms.X86_16.semantics.branch_target_return import TerminalAxReturnEffectKind8616
from angr_platforms.X86_16.semantics.terminal_register_returns import (
    TerminalAxReturnEvidence8616,
    TerminalAxReturnLane8616,
    TerminalReturnStorageState8616,
    collect_terminal_ax_return_evidence_8616,
    terminal_ax_return_lane_states_8616,
)
from angr_platforms.X86_16.semantics.terminal_return_storage import (
    TerminalReturnStorage8616,
    consistent_terminal_return_storage_8616,
)


class _Factory:
    def __init__(self, blocks: dict[int, object]) -> None:
        self.blocks = blocks
        self.calls: list[int] = []

    def block(self, address: int, *, opt_level: int) -> object:
        assert opt_level == 0
        self.calls.append(address)
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


def test_terminal_ax_evidence_closes_mixed_defined_and_undefined_return_paths(monkeypatch) -> None:
    branch = _insn(0x1000, "je", size=2, target=0x1010)
    write_ax = _insn(0x1002, "mov")
    value_jump = _insn(0x1003, "jmp", target=0x1020)
    empty_jump = _insn(0x1010, "jmp", target=0x1020)
    terminal = _insn(0x1020, "ret")
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(branch,))),
        0x1002: SimpleNamespace(capstone=SimpleNamespace(insns=(write_ax, value_jump))),
        0x1010: SimpleNamespace(capstone=SimpleNamespace(insns=(empty_jump,))),
        0x1020: SimpleNamespace(capstone=SimpleNamespace(insns=(terminal,))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_return_effect_8616",
        lambda insn: SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg="ax" if insn is write_ax else None,
        ),
    )

    evidence = collect_terminal_ax_return_evidence_8616(project, function)

    assert evidence.states == frozenset({TerminalAxReturnLane8616.NONE, TerminalAxReturnLane8616.WORD})
    assert evidence.raw_fact_count == 2
    assert evidence.normalized_fact_count == 2
    assert evidence.classified_fact_count == 2
    assert evidence.materialized_count == 2
    assert evidence.failure_count == 0
    assert evidence.proves_missing_value_path is True

    repeated = collect_terminal_ax_return_evidence_8616(project, function)

    assert repeated == evidence
    assert len(project.factory.calls) == len(blocks)
    assert set(project.factory.calls) == set(blocks)


def test_terminal_storage_refuses_mixed_call_output_and_explicit_ax_paths(monkeypatch) -> None:
    branch = _insn(0x1000, "je", size=2, target=0x1010)
    write_ax = _insn(0x1002, "mov")
    value_ret = _insn(0x1003, "ret")
    call = _insn(0x1010, "call")
    call_ret = _insn(0x1011, "ret")
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(branch,))),
        0x1002: SimpleNamespace(capstone=SimpleNamespace(insns=(write_ax, value_ret))),
        0x1010: SimpleNamespace(capstone=SimpleNamespace(insns=(call, call_ret))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    def _effect(insn: object) -> object:
        if insn is call:
            return SimpleNamespace(kind=TerminalAxReturnEffectKind8616.CALL_CLOBBER, dst_reg=None)
        return SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg="ax" if insn is write_ax else None,
        )

    monkeypatch.setattr(terminal_register_returns, "terminal_ax_return_effect_8616", _effect)

    evidence = collect_terminal_ax_return_evidence_8616(project, function)

    assert evidence.complete is True
    assert {state.call_output_only for state in evidence.storage_states} == {False, True}
    assert consistent_terminal_return_storage_8616(evidence) is None


def test_terminal_storage_classifies_only_call_output_paths() -> None:
    evidence = TerminalAxReturnEvidence8616(
        frozenset(
            {
                TerminalReturnStorageState8616(
                    TerminalAxReturnLane8616.WORD,
                    False,
                    TerminalAxReturnLane8616.WORD,
                )
            }
        ),
        1,
        1,
        1,
        1,
        0,
    )

    assert (
        consistent_terminal_return_storage_8616(evidence)
        is TerminalReturnStorage8616.CALL_OUTPUT
    )


def test_terminal_storage_excludes_call_derived_high_lane_after_al_write(monkeypatch) -> None:
    call = _insn(0x1000, "call")
    write_al = _insn(0x1001, "mov")
    terminal = _insn(0x1002, "ret")
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(call, write_al, terminal))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    def _effect(insn: object) -> object:
        if insn is call:
            return SimpleNamespace(kind=TerminalAxReturnEffectKind8616.CALL_CLOBBER, dst_reg=None)
        return SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg="al" if insn is write_al else None,
        )

    monkeypatch.setattr(terminal_register_returns, "terminal_ax_return_effect_8616", _effect)

    evidence = collect_terminal_ax_return_evidence_8616(project, function)
    state = next(iter(evidence.storage_states))

    assert state.ax_lanes is TerminalAxReturnLane8616.WORD
    assert state.call_output_lanes is TerminalAxReturnLane8616.HIGH
    assert state.explicit_ax_lanes is TerminalAxReturnLane8616.LOW
    assert consistent_terminal_return_storage_8616(evidence) is TerminalReturnStorage8616.AL


def test_balanced_entry_push_and_epilogue_pop_preserve_ax_return_storage(monkeypatch) -> None:
    register_ax = 1

    def _register_insn(address: int, mnemonic: str) -> object:
        return SimpleNamespace(
            address=address,
            size=1,
            mnemonic=mnemonic,
            operands=(SimpleNamespace(type=1, reg=register_ax),),
            reg_name=lambda reg: "ax" if reg == register_ax else "",
        )

    push_ax = _register_insn(0x1000, "push")
    write_ax = _register_insn(0x1001, "mov")
    pop_ax = _register_insn(0x1002, "pop")
    terminal = _insn(0x1003, "ret")
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(push_ax, write_ax, pop_ax, terminal))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))
    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_return_effect_8616",
        lambda insn: SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg="ax" if insn is write_ax or insn is pop_ax else None,
        ),
    )

    evidence = collect_terminal_ax_return_evidence_8616(project, function)

    assert evidence.states == frozenset({TerminalAxReturnLane8616.NONE})
    assert consistent_terminal_return_storage_8616(evidence) is TerminalReturnStorage8616.NONE


def test_terminal_wide_return_requires_every_terminal_path(monkeypatch) -> None:
    branch = _insn(0x1000, "je", size=2, target=0x1010)
    wide_ax = _insn(0x1002, "mov")
    wide_dx = _insn(0x1003, "mov")
    wide_ret = _insn(0x1004, "ret")
    word_ax = _insn(0x1010, "mov")
    word_ret = _insn(0x1011, "ret")
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(branch,))),
        0x1002: SimpleNamespace(capstone=SimpleNamespace(insns=(wide_ax, wide_dx, wide_ret))),
        0x1010: SimpleNamespace(capstone=SimpleNamespace(insns=(word_ax, word_ret))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_return_effect_8616",
        lambda insn: SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg="dx"
            if insn is wide_dx
            else "ax"
            if insn is wide_ax or insn is word_ax
            else None,
        ),
    )

    evidence = collect_terminal_ax_return_evidence_8616(project, function)

    assert evidence.complete is True
    assert evidence.proves_wide_return is False
    assert {state.dx_ax_pair_proven for state in evidence.storage_states} == {False, True}


def test_terminal_lane_projection_refuses_incomplete_successor_census(monkeypatch) -> None:
    branch = _insn(0x1000, "je", size=2, target=0x1010)
    write_ax = _insn(0x1002, "mov")
    terminal = _insn(0x1003, "ret")
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(branch,))),
        0x1002: SimpleNamespace(capstone=SimpleNamespace(insns=(write_ax, terminal))),
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))
    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_return_effect_8616",
        lambda insn: SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg="ax" if insn is write_ax else None,
        ),
    )

    evidence = collect_terminal_ax_return_evidence_8616(project, function)

    assert evidence.complete is False
    assert evidence.states == frozenset({TerminalAxReturnLane8616.WORD})
    assert terminal_ax_return_lane_states_8616(project, function) == frozenset()


def test_terminal_register_return_refuses_inaccessible_decode() -> None:
    class _MissingFactory:
        def block(self, _address: int, *, opt_level: int) -> object:
            assert opt_level == 0
            raise SimEngineError("No bytes in memory")

    evidence = collect_terminal_ax_return_evidence_8616(
        SimpleNamespace(factory=_MissingFactory()),
        SimpleNamespace(addr=0x11222, block_addrs_set={0x11222}),
    )

    assert evidence.complete is False
    assert evidence.raw_fact_count == evidence.failure_count == 1


def test_exact_terminal_storage_distinguishes_ax_from_dx_ax() -> None:
    word = TerminalAxReturnEvidence8616(
        frozenset({TerminalReturnStorageState8616(TerminalAxReturnLane8616.WORD, False)}),
        1,
        1,
        1,
        1,
        0,
    )
    wide = TerminalAxReturnEvidence8616(
        frozenset({TerminalReturnStorageState8616(TerminalAxReturnLane8616.WORD, True)}),
        1,
        1,
        1,
        1,
        0,
    )

    assert consistent_terminal_return_storage_8616(word) is TerminalReturnStorage8616.AX
    assert consistent_terminal_return_storage_8616(wide) is TerminalReturnStorage8616.DX_AX


def test_exact_terminal_storage_refuses_mixed_or_incomplete_paths() -> None:
    mixed = TerminalAxReturnEvidence8616(
        frozenset(
            {
                TerminalReturnStorageState8616(TerminalAxReturnLane8616.LOW, False),
                TerminalReturnStorageState8616(TerminalAxReturnLane8616.WORD, False),
            }
        ),
        2,
        2,
        2,
        2,
        0,
    )
    incomplete = TerminalAxReturnEvidence8616(
        frozenset({TerminalReturnStorageState8616(TerminalAxReturnLane8616.WORD, False)}),
        2,
        1,
        1,
        1,
        1,
    )

    assert consistent_terminal_return_storage_8616(mixed) is None
    assert consistent_terminal_return_storage_8616(incomplete) is None
