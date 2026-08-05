from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.real_mode_linear import (
    prune_frame_prologue_stack_assignments_8616,
)
from angr_platforms.X86_16.validation_dataflow import validate_structured_def_use_8616
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_SP,
)


class _Codegen:
    """Minimal dynamic angr codegen boundary used by the focused regression."""

    def __init__(self, project: object) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return a deterministic structured-C node index."""
        self._idx += 1
        return self._idx


def _register_operand(register: int) -> SimpleNamespace:
    """Build one minimal Capstone register operand boundary."""
    return SimpleNamespace(type=X86_OP_REG, size=2, reg=register)


def _instruction(
    address: int,
    size: int,
    instruction_id: int,
    *registers: int,
) -> SimpleNamespace:
    """Build one minimal decoded instruction boundary."""
    return SimpleNamespace(
        address=address,
        size=size,
        id=instruction_id,
        operands=tuple(_register_operand(register) for register in registers),
    )


def test_canonical_bp_frame_prunes_entry_and_epilogue_carriers() -> None:
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    word_type = SimTypeShort(False)

    def register(name: str) -> CVariable:
        """Build one typed physical-register C variable."""
        offset = project.arch.registers[name][0]
        variable = SimRegisterVariable(offset, 2, name=name)
        return CVariable(variable, variable_type=word_type, codegen=codegen)

    sp = register("sp")
    bp = register("bp")
    ax = register("ax")
    two = CConstant(2, word_type, codegen=codegen)
    one = CConstant(1, word_type, codegen=codegen)
    push_carrier = CAssignment(
        sp,
        CBinaryOp("Sub", sp, two, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1000},
    )
    setup_carrier = CAssignment(bp, sp, codegen=codegen, tags={"ins_addr": 0x1001})
    body_assignment = CAssignment(ax, one, codegen=codegen, tags={"ins_addr": 0x1010})
    teardown_carrier = CAssignment(sp, bp, codegen=codegen, tags={"ins_addr": 0x1020})
    pop_carrier = CAssignment(bp, sp, codegen=codegen, tags={"ins_addr": 0x1022})
    return_carrier = CAssignment(
        sp,
        CBinaryOp("Add", sp, two, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1023},
    )
    root = CStatements(
        [
            push_carrier,
            setup_carrier,
            body_assignment,
            teardown_carrier,
            pop_carrier,
            return_carrier,
        ],
        addr=0x1000,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        arg_list=[],
        variables_in_use={},
        unified_local_vars={},
    )
    instructions = (
        _instruction(0x1000, 1, X86_INS_PUSH, X86_REG_BP),
        _instruction(0x1001, 2, X86_INS_MOV, X86_REG_BP, X86_REG_SP),
        _instruction(0x1020, 2, X86_INS_MOV, X86_REG_SP, X86_REG_BP),
        _instruction(0x1022, 1, X86_INS_POP, X86_REG_BP),
        _instruction(0x1023, 1, X86_INS_RET),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1000,
                capstone=SimpleNamespace(insns=instructions),
            ),
        ),
    )

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is True
    assert root.statements == [body_assignment]
    stats = codegen._inertia_frame_prologue_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (5, 5, 5, 5, 0)
    assert validate_structured_def_use_8616(root).issues == ()
