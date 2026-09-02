"""Regression coverage for path-specific terminal return values."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.semantics.branch_target_return import (
    TerminalAxReturnEffect8616,
    TerminalAxReturnEffectKind8616,
)
from angr_platforms.X86_16.structuring.return_chains import (
    TerminalAxInstructionAction8616,
    TerminalAxScanCallbacks8616,
    linear_terminal_ax_return_scan_8616,
)
from angr_platforms.X86_16.structuring.tagged_terminal_return_values import (
    materialize_tagged_terminal_return_values_8616,
)


@dataclass(frozen=True, slots=True)
class _Operand:
    """Minimal decoded operand used by terminal-return tests."""

    type: int
    reg: int = 0
    imm: int = 0


class _Insn:
    """Minimal decoded instruction used by terminal-return tests."""

    def __init__(
        self,
        mnemonic: str,
        operands: tuple[_Operand, ...] = (),
        *,
        address: int = 0,
    ) -> None:
        self.mnemonic = mnemonic
        self.operands = operands
        self.address = address

    @staticmethod
    def reg_name(register: int) -> str:
        """Return the single register name needed by this fixture."""
        return {1: "ax"}.get(register, "")


def _block(*instructions: _Insn) -> SimpleNamespace:
    """Build one minimal decoded block."""
    return SimpleNamespace(capstone=SimpleNamespace(insns=instructions))


def _target(instruction: _Insn) -> int | None:
    """Return one direct branch target from the fixture instruction."""
    if len(instruction.operands) != 1 or instruction.operands[0].type != 2:
        return None
    return instruction.operands[0].imm


def test_linear_terminal_scan_refuses_multiple_value_predecessors() -> None:
    """A linear proof must not select the first of several return paths."""
    blocks = {
        0x1000: _block(
            _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=1))),
            _Insn("jmp", (_Operand(2, imm=0x1100),)),
        ),
        0x1010: _block(
            _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=0))),
            _Insn("jmp", (_Operand(2, imm=0x1100),)),
        ),
        0x1100: _block(_Insn("ret")),
    }
    terminal_value: list[int | None] = [None]

    def process(
        _instruction: object,
        effect: TerminalAxReturnEffect8616,
    ) -> TerminalAxInstructionAction8616:
        """Track the fixture's exact AX immediate effect."""
        if effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_IMM:
            terminal_value[0] = effect.imm
            return TerminalAxInstructionAction8616(classified=True)
        return TerminalAxInstructionAction8616(abort=True)

    result = linear_terminal_ax_return_scan_8616(
        blocks,
        blocks.get,
        _target,
        TerminalAxScanCallbacks8616(
            combined_return_expr=lambda: terminal_value[0],
            process_instruction=process,
        ),
    )

    assert result.expr is None
    assert result.terminal_value_block_count == 2


def test_tagged_terminal_return_uses_its_own_cfg_predecessor() -> None:
    """Replace a stale AX self-subtract with the tagged path's proven zero."""
    codegen = SimpleNamespace(
        next_idx=lambda _kind: 0,
        next_node_idx=lambda: 0,
        next_ident=lambda name: name,
        cstyle_null_cmp=False,
        project=SimpleNamespace(arch=Arch86_16()),
    )
    short_type = SimTypeShort(False)
    tags = {"ins_addr": 0x1000, "vex_block_addr": 0x1000}
    ax = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=short_type,
        codegen=codegen,
        tags=tags,
    )
    stale = CBinaryOp(
        "Add",
        ax,
        CUnaryOp("Neg", ax, codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    terminal_return = CReturn(stale, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([terminal_return], codegen=codegen)
    )
    blocks = {
        0x1000: _block(
            _Insn(
                "sub",
                (_Operand(1, reg=1), _Operand(1, reg=1)),
                address=0x1000,
            ),
            _Insn("jmp", (_Operand(2, imm=0x1100),), address=0x1002),
        ),
        0x1100: _block(_Insn("ret", address=0x1100)),
    }
    project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda addr, *, opt_level=0: blocks[addr])
    )
    function = SimpleNamespace(block_addrs_set=frozenset(blocks))

    result = materialize_tagged_terminal_return_values_8616(
        project,
        codegen,
        function,
        expressions_equivalent=lambda lhs, rhs: (
            isinstance(lhs, CConstant)
            and isinstance(rhs, CConstant)
            and lhs.value == rhs.value
        ),
    )

    assert result.changed
    assert (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
        result.replacement_count,
    ) == (1, 1, 1, 1, 0, 1)
    assert isinstance(terminal_return.retval, CConstant)
    assert terminal_return.retval.value == 0
