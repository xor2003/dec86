from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.calling_convention_compat import (
    _promote_terminal_word_return_8616,
    _set_function_prototype_8616,
    _terminal_wide_return_evidence_8616,
    _terminal_word_return_evidence_8616,
    _wide_stack_argument_evidence_8616,
    _WideReturnEvidence8616,
    apply_x86_16_wide_stack_prototype_evidence,
    apply_x86_16_wide_stack_prototype_evidence_at_address,
)


class _FakeRegOperand:
    def __init__(self, reg: int) -> None:
        self.type = 1
        self.reg = reg


class _FakeMemory:
    def __init__(self, base: int, disp: int) -> None:
        self.base = base
        self.disp = disp


class _FakeMemOperand:
    def __init__(self, *, base: int, disp: int, size: int = 2) -> None:
        self.type = 3
        self.size = size
        self.mem = _FakeMemory(base, disp)


class _FakeImmOperand:
    def __init__(self, imm: int) -> None:
        self.type = 2
        self.imm = imm


class _FakeInsn:
    def __init__(
        self,
        mnemonic: str,
        *,
        writes: str | None = None,
        target: int | None = None,
        source_bp_offset: int | None = None,
    ) -> None:
        self.mnemonic = mnemonic
        operands = []
        if writes is not None:
            operands.append(_FakeRegOperand({"ax": 1, "dx": 2}[writes]))
        if source_bp_offset is not None:
            operands.append(_FakeMemOperand(base=6, disp=source_bp_offset))
        if target is not None:
            operands.append(_FakeImmOperand(target))
        self.operands = tuple(operands)

    def reg_name(self, reg_id: int) -> str:
        return {1: "ax", 2: "dx", 6: "bp"}.get(reg_id, "")


class _FakeMovSpBpInsn:
    mnemonic = "mov"

    def __init__(self) -> None:
        self.operands = (_FakeRegOperand(47), _FakeRegOperand(6))

    def reg_name(self, reg_id: int) -> str:
        return {47: "sp", 6: "bp"}.get(reg_id, "")


class _FakeBlock:
    def __init__(self, insns: tuple[_FakeInsn | object, ...]) -> None:
        self.capstone = SimpleNamespace(insns=insns)


class _FakeFactory:
    def __init__(self, blocks: dict[int, _FakeBlock]) -> None:
        self._blocks = blocks

    def block(self, addr: int, opt_level: int = 0, size: int | None = None) -> _FakeBlock:
        return self._blocks[addr]


class _FakeProject:
    def __init__(
        self,
        insns: tuple[_FakeInsn | object, ...],
        *,
        extra_blocks: dict[int, tuple[_FakeInsn | object, ...]] | None = None,
    ) -> None:
        blocks = {0x1000: _FakeBlock(insns)}
        blocks.update({addr: _FakeBlock(block_insns) for addr, block_insns in (extra_blocks or {}).items()})
        self.factory = _FakeFactory(blocks)


def test_terminal_wide_return_evidence_requires_terminal_suffix() -> None:
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("adc", writes="dx"),
            _FakeInsn("mov"),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.NONE


def test_terminal_wide_return_evidence_accepts_epilogue_suffix() -> None:
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("adc", writes="dx"),
            _FakeInsn("pop"),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH


def test_terminal_wide_return_evidence_accepts_direct_jump_to_shared_epilogue() -> None:
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("sbb", writes="dx"),
            _FakeInsn("jmp", target=0x1010),
        ),
        extra_blocks={0x1010: (_FakeInsn("pop"), _FakeInsn("ret"))},
    )
    function = SimpleNamespace(block_addrs_set={0x1000, 0x1010})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH


def test_terminal_wide_return_evidence_accepts_mov_sp_bp_shared_epilogue() -> None:
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("sbb", writes="dx"),
            _FakeInsn("jmp", target=0x1010),
        ),
        extra_blocks={0x1010: (_FakeInsn("pop"), _FakeMovSpBpInsn(), _FakeInsn("pop"), _FakeInsn("ret"))},
    )
    function = SimpleNamespace(block_addrs_set={0x1000, 0x1010})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH


def test_terminal_wide_return_evidence_reads_register_names_from_angr_capstone_wrappers() -> None:
    project = _FakeProject(
        (
            SimpleNamespace(insn=_FakeInsn("mov", writes="ax"), mnemonic="mov"),
            SimpleNamespace(insn=_FakeInsn("sbb", writes="dx"), mnemonic="sbb"),
            _FakeInsn("jmp", target=0x1010),
        ),
        extra_blocks={0x1010: (_FakeInsn("pop"), _FakeInsn("ret"))},
    )
    function = SimpleNamespace(block_addrs_set={0x1000, 0x1010})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH


def test_terminal_word_return_evidence_accepts_ax_before_return() -> None:
    project = _FakeProject((_FakeInsn("mov", writes="ax"), _FakeInsn("ret")))
    function = SimpleNamespace(block_addrs_set={0x1000})

    assert _terminal_word_return_evidence_8616(project, function)


def test_terminal_word_return_promotion_preserves_explicit_nonvoid_return() -> None:
    arch = archinfo.ArchX86()
    project = _FakeProject((_FakeInsn("mov", writes="ax"), _FakeInsn("ret")))
    project.arch = arch
    function = SimpleNamespace(block_addrs_set={0x1000})
    prototype = SimTypeFunction([], SimTypeLong()).with_arch(arch)

    assert _promote_terminal_word_return_8616(project, function, prototype) is prototype


def test_terminal_word_return_promotion_replaces_guessed_void_return() -> None:
    arch = archinfo.ArchX86()
    project = _FakeProject((_FakeInsn("mov", writes="ax"), _FakeInsn("ret")))
    project.arch = arch
    function = SimpleNamespace(block_addrs_set={0x1000})
    prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)

    promoted = _promote_terminal_word_return_8616(project, function, prototype)

    assert isinstance(promoted.returnty, SimTypeShort)


def test_wide_stack_prototype_evidence_preserves_non_guessed_source_prototype():
    arch = archinfo.ArchX86()
    source_proto = SimTypeFunction([SimTypeLong(False)], SimTypeBottom(label="void")).with_arch(arch)
    wide_proto = SimTypeFunction([SimTypeLong(False)], SimTypeLong(False)).with_arch(arch)
    function = SimpleNamespace(
        prototype=source_proto,
        is_prototype_guessed=False,
        project=SimpleNamespace(arch=arch),
    )

    _cc, selected = _set_function_prototype_8616(function, "wide-cc", wide_proto)

    assert selected is source_proto
    assert function.prototype is source_proto
    assert not hasattr(function, "calling_convention")


def test_apply_wide_stack_prototype_evidence_refuses_non_guessed_existing_prototype():
    arch = SimpleNamespace(name="86_16")
    source_proto = SimTypeFunction([SimTypeLong(False)], SimTypeBottom(label="void"))
    function = SimpleNamespace(prototype=source_proto, is_prototype_guessed=False)
    project = SimpleNamespace(arch=arch)

    changed = apply_x86_16_wide_stack_prototype_evidence(project, function)

    assert changed is False
    assert function.prototype is source_proto


def test_wide_stack_argument_evidence_classifies_adjacent_add_adc_bp_words() -> None:
    project = _FakeProject(
        (
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=6),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    evidence = _wide_stack_argument_evidence_8616(project, function)

    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_offsets == (4,)
    assert evidence.failure_count == 0


def test_wide_stack_argument_evidence_refuses_nonadjacent_carry_source() -> None:
    project = _FakeProject(
        (
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=8),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    evidence = _wide_stack_argument_evidence_8616(project, function)

    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_offsets == ()
    assert evidence.failure_count == 1


def test_apply_wide_stack_prototype_evidence_merges_physical_words_for_void_callee() -> None:
    arch = Arch86_16()
    project = _FakeProject(
        (
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=6),
            _FakeInsn("ret"),
        )
    )
    project.arch = arch
    function = SimpleNamespace(
        block_addrs_set={0x1000},
        prototype=SimTypeFunction(
            [SimTypeShort(False), SimTypeShort(False)],
            SimTypeBottom(label="void"),
        ).with_arch(arch),
        is_prototype_guessed=True,
        project=project,
    )

    changed = apply_x86_16_wide_stack_prototype_evidence(project, function)

    assert changed
    assert len(function.prototype.args) == 1
    assert isinstance(function.prototype.args[0], SimTypeLong)
    assert isinstance(function.prototype.returnty, SimTypeBottom)


def test_address_wide_stack_evidence_materializes_bodyless_stub_from_bounded_body() -> None:
    arch = Arch86_16()
    project = _FakeProject(
        (
            _FakeInsn("call"),
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=6),
            _FakeInsn("ret"),
            _FakeInsn("add", writes="ax", source_bp_offset=8),
            _FakeInsn("adc", writes="dx", source_bp_offset=10),
        )
    )
    project.arch = arch
    function = SimpleNamespace(
        prototype=SimTypeFunction(
            [SimTypeShort(False), SimTypeShort(False)],
            SimTypeBottom(label="void"),
        ).with_arch(arch),
        is_prototype_guessed=True,
        project=project,
    )

    changed = apply_x86_16_wide_stack_prototype_evidence_at_address(project, function, 0x1000, scan_size=64)

    assert changed
    assert len(function.prototype.args) == 1
    assert isinstance(function.prototype.args[0], SimTypeLong)


def test_address_wide_stack_evidence_refuses_window_without_return() -> None:
    arch = Arch86_16()
    project = _FakeProject(
        (
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=6),
        )
    )
    project.arch = arch
    prototype = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)],
        SimTypeBottom(label="void"),
    ).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, project=project)

    changed = apply_x86_16_wide_stack_prototype_evidence_at_address(project, function, 0x1000, scan_size=64)

    assert not changed
    assert function.prototype is prototype
