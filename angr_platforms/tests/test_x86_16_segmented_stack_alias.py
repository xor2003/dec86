from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import decompile
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements, CUnaryOp, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.alias_model import _stack_storage_facts_for_segmented_address_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.segmented_memory_reasoning import (
    SegmentAssignment,
    SegmentRegister,
    apply_x86_16_segmented_memory_reasoning,
)
from angr_platforms.X86_16.decompiler_postprocess_utils import _match_bp_stack_dereference_8616
from angr_platforms.X86_16.lowering.stack_lowering import run_stack_lowering_pass_8616
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(statements):
    project = _project()
    codegen = _DummyCodegen(project)
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
    )
    return project, codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _stack(offset: int, codegen, *, name: str = "local"):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name, region=0x4010), codegen=codegen)


def _ds_deref(project, linear: int, codegen):
    ds = _reg(project, "ds", codegen)
    return CUnaryOp(
        "Dereference",
        CBinaryOp("Add", CBinaryOp("Mul", ds, _const(16, codegen), codegen=codegen), _const(linear, codegen), codegen=codegen),
        codegen=codegen,
    )


def _ss_stack_deref(project, stack_offset: int, addend: int, codegen):
    ss = _reg(project, "ss", codegen)
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", _stack(stack_offset, codegen), codegen=codegen),
                _const(addend, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def test_stack_storage_facts_for_ss_segmented_address_lower_to_stack_identity():
    facts = _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010)

    assert facts is not None
    assert facts.domain.space == "stack"
    assert facts.domain.stack_slot is not None
    assert facts.domain.stack_slot.offset == 4
    assert facts.identity == ("stack", facts.domain.stack_slot)


def test_segmented_memory_reasoning_lowers_stable_ss_stack_dereference():
    project, before_codegen = _codegen([])
    before_codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ss_stack_deref(project, -2, 2, before_codegen),
                _const(7, before_codegen),
                codegen=before_codegen,
            )
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    after_codegen = deepcopy(before_codegen)

    changed = apply_x86_16_segmented_memory_reasoning(after_codegen)

    assert changed is True
    lhs = after_codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimStackVariable)
    assert lhs.variable.offset == 0
    assert lhs.variable.base == "bp"

    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen, mode="coarse")
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen, mode="coarse")
    diff = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    assert diff["changed"] is False


def test_segmented_memory_reasoning_does_not_lower_ds_access_to_stack():
    project, codegen = _codegen([])
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ds_deref(project, 0x20, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_segmented_memory_reasoning(codegen)

    assert changed is False
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CUnaryOp)
    assert lhs.op == "Dereference"


def test_segmented_memory_reasoning_refuses_over_associated_ss_lowering():
    project, codegen = _codegen([])
    codegen._inertia_segment_assignments = (
        SegmentAssignment(SegmentRegister.SS, 0x1000, "literal", "f1", 0.9),
        SegmentAssignment(SegmentRegister.SS, 0x2000, "literal", "f2", 0.9),
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ss_stack_deref(project, -2, 2, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_segmented_memory_reasoning(codegen)

    assert changed is False
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CUnaryOp)
    assert lhs.op == "Dereference"


def test_match_bp_stack_dereference_resolves_single_assignment_vvar_chain():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    stack_ref = CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp("Add", stack_ref, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(
                _ss_stack_deref(project, -10, 2, codegen),
                _const(7, codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", temp, _const(-2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_segmented_memory_reasoning_lowers_ss_dereference_backed_by_vvar_chain():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    stack_ref = CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", temp, _const(-2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp("Add", stack_ref, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(deref, _const(7, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_segmented_memory_reasoning(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[1].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimStackVariable)
    assert lhs.variable.offset == -10


def test_match_bp_stack_dereference_handles_sub_form_for_vvar_chain():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp(
                    "Add",
                    CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen),
                    _const(2, codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Sub",
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
                temp,
                codegen=codegen,
            ),
            _const(2, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_match_bp_stack_dereference_follows_stack_local_pointer_carrier_assignment():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    carrier = _stack(-2, codegen, name="s_2")
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp(
                    "Add",
                    CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen),
                    _const(2, codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                carrier,
                temp,
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
            CBinaryOp(
                "Sub",
                carrier,
                _const(2, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_match_bp_stack_dereference_handles_nested_add_sub_chain_from_vvar_base():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_16"
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CUnaryOp("Reference", _stack(-6, codegen, name="s_6"), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Sub",
            CBinaryOp(
                "Add",
                CBinaryOp(
                    "Sub",
                    CBinaryOp(
                        "Sub",
                        CBinaryOp(
                            "Add",
                            CBinaryOp("Shl", _reg(project, "ss", codegen), _const(4, codegen), codegen=codegen),
                            temp,
                            codegen=codegen,
                        ),
                        _const(2, codegen),
                        codegen=codegen,
                    ),
                    _const(2, codegen),
                    codegen=codegen,
                ),
                _const(2, codegen),
                codegen=codegen,
            ),
            _const(2, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_rewrite_ss_stack_byte_offsets_resolves_pointer_alias_by_variable_name():
    project, codegen = _codegen([])
    cfunc = codegen.cfunc
    cfunc.project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(binary_basename="SORTDEMO.EXE"))
    )
    cfunc.arg_list = []
    cfunc.unified_local_vars = {}
    cfunc.sort_local_vars = lambda: None

    ss = _reg(project, "ss", codegen)
    alias_var = SimRegisterVariable(0, 2, name="vvar_16")
    alias_cvar = CVariable(alias_var, codegen=codegen)
    alias_use_var = SimRegisterVariable(0, 2, name=None)
    alias_use_cvar = CVariable(alias_use_var, codegen=codegen)
    base_var = SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010)
    base_cvar = CVariable(base_var, codegen=codegen)
    target_var = SimStackVariable(-8, 2, base="bp", name="local_8", region=0x4010)
    target_cvar = CVariable(target_var, codegen=codegen)
    cfunc.variables_in_use = {
        alias_var: alias_cvar,
        alias_use_var: alias_use_cvar,
        base_var: base_cvar,
        target_var: target_cvar,
        ss.variable: ss,
    }

    addr_expr = CBinaryOp("Add", alias_use_cvar, _const(-2, codegen), codegen=codegen)
    store = CAssignment(
        CUnaryOp(
            "Dereference",
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
                addr_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        _const(7, codegen),
        codegen=codegen,
    )
    cfunc.statements = CStatements(
        [
            CAssignment(alias_cvar, CUnaryOp("Reference", base_cvar, codegen=codegen), codegen=codegen),
            store,
        ],
        addr=0x4010,
        codegen=codegen,
    )
    cfunc.body = cfunc.statements

    changed = decompile._rewrite_ss_stack_byte_offsets(project, codegen)

    assert changed is True
    lowered_lhs = cfunc.statements.statements[1].lhs
    assert isinstance(lowered_lhs, CVariable)
    assert lowered_lhs.variable is target_var


def test_stack_lowering_entrypoint_runs_typed_ss_lowering_before_cli_cleanup():
    calls: list[str] = []

    def lower_stable_ss_stack_accesses() -> bool:
        calls.append("typed-ss")
        return True

    def rewrite_ss_stack_byte_offsets() -> bool:
        calls.append("rewrite")
        return False

    def canonicalize_stack_cvars() -> bool:
        calls.append("canonicalize")
        return False

    changed = run_stack_lowering_pass_8616(
        lower_stable_ss_stack_accesses=lower_stable_ss_stack_accesses,
        rewrite_ss_stack_byte_offsets=rewrite_ss_stack_byte_offsets,
        canonicalize_stack_cvars=canonicalize_stack_cvars,
        max_rounds=1,
    )

    assert changed is True
    assert calls == ["typed-ss", "rewrite", "canonicalize"]
