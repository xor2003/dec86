"""Exercise real-image proof consumption without rendered-C pattern recovery."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeChar, SimTypeFixedSizeArray, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.consumed_stack_address_setup import prune_consumed_stack_address_setup_8616
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    StackVariableCoordinateProjection8616,
    StackVariableCoordinateRegistry8616,
)
from angr_platforms.X86_16.synthetic_call_stub_evidence import record_synthetic_call_stubs_8616

from inertia_decompiler.project_loading import _build_project_from_bytes


class Codegen:
    def __init__(self, project):
        self.project = project
        self._idx = 0
        self.cstyle_null_cmp = False

    def next_node_idx(self):
        self._idx += 1
        return self._idx

    def next_idx(self, _name):
        return self.next_node_idx()

    def next_ident(self, name):
        return name


def setup_fixture(callee="31 c0 c3"):
    # LEA AX,[BP-16]; PUSH SS; PUSH AX; PUSH CS; CALL 1020h.
    caller = bytes.fromhex("8d 46 f0 16 50 0e e8 17 00")
    binary = caller + bytes(0x20 - len(caller)) + bytes.fromhex(callee)
    project = _build_project_from_bytes(binary, base_addr=0x1000, entry_point=0x1000)
    codegen = Codegen(project)
    word, dword = SimTypeShort(False), SimTypeLong(False)
    variable = SimStackVariable(-18, 22, base="bp", name="buffer")
    stack = c.CVariable(variable, variable_type=word, codegen=codegen)
    reference = c.CUnaryOp("Reference", stack, codegen=codegen)
    codegen._inertia_stack_variable_coordinate_registry_8616 = StackVariableCoordinateRegistry8616((
        StackVariableCoordinateProjection8616(variable, stack, -16, -18, 22),
    ))
    parent = c.CVariable(SimMemoryVariable(
        0x10000, 4, name="inertia_eax", category="inertia_gp_register_state",
    ), variable_type=dword, codegen=codegen)
    assignment = c.CAssignment(parent, c.CBinaryOp("Or",
        c.CBinaryOp("And", parent, c.CConstant(0xFFFF0000, dword, codegen=codegen), codegen=codegen),
        c.CBinaryOp("And", reference, c.CConstant(0xFFFF, dword, codegen=codegen), codegen=codegen),
        codegen=codegen), codegen=codegen, tags={"ins_addr": 0x1000},
    )
    call = c.CFunctionCall("sub_1020", SimpleNamespace(name="sub_1020"),
        [reference, c.CConstant(0, word, codegen=codegen)], codegen=codegen,
        tags={"ins_addr": 0x1006, "inertia_target_addr_8616": 0x1020},
    )
    root = c.CStatements([assignment, c.CExpressionStatement(call, codegen=codegen)], addr=0x1000, codegen=codegen)
    summary = CallsiteSummary8616(
        callsite_addr=0x1006, target_addr=0x1020, return_addr=0x1009, kind="direct_near",
        arg_count=2, arg_widths=(2, 2), stack_cleanup=4, return_register=None, return_used=False,
        push_arg_sources=(("seg", "ss"), ("bp_addr", -16)), push_arg_instruction_addrs=(0x1003, 0x1004),
    )
    return project, codegen, root, summary, call


def test_proven_setup_is_deleted_without_changing_the_call():
    project, codegen, root, summary, call = setup_fixture()
    arguments = tuple(call.args)
    assert prune_consumed_stack_address_setup_8616(project, codegen, root, {0x1006: summary})
    assert len(root.statements) == 1
    assert root.statements[0].expr is call
    assert tuple(call.args) == arguments
    census = codegen._inertia_consumed_stack_setup_census_8616
    assert census.raw_fact_count == census.normalized_fact_count == census.classified_fact_count == census.materialized_count == 1
    assert census.failure_count == 0
    assert not prune_consumed_stack_address_setup_8616(project, codegen, root, {0x1006: summary})


@pytest.mark.parametrize("array_argument,byte_mask", [(True, False), (False, True), (True, True)])
def test_typed_array_decay_and_pure_byte_masks_keep_the_same_proof(array_argument, byte_mask):
    project, codegen, root, summary, call = setup_fixture()
    assignment = root.statements[0]
    if array_argument:
        array = call.args[0].operand
        array.variable_type = SimTypeFixedSizeArray(SimTypeChar(), 22)
        call.args[0] = array
    if byte_mask:
        inserted = assignment.rhs.rhs
        inserted.lhs = c.CBinaryOp(
            "And", inserted.lhs, c.CConstant(0xFF, SimTypeLong(False), codegen=codegen), codegen=codegen,
        )
    assert prune_consumed_stack_address_setup_8616(project, codegen, root, {0x1006: summary})
    assert root.statements[0].expr is call


def test_scalar_stack_value_is_not_an_array_address():
    project, codegen, root, summary, call = setup_fixture()
    call.args[0] = call.args[0].operand
    assert not prune_consumed_stack_address_setup_8616(project, codegen, root, {0x1006: summary})
    assert len(root.statements) == 2


@pytest.mark.parametrize("failure", [
    "input", "synthetic", "storage", "offset", "push", "mask", "extra_use", "dirty", "target",
    "argument_use", "missing_arguments", "outside_image",
])
def test_unproven_or_unmatched_setup_is_kept(failure):
    project, codegen, root, summary, call = setup_fixture("89 c3 31 c0 c3" if failure == "input" else "31 c0 c3")
    assignment = root.statements[0]
    if failure == "synthetic":
        record_synthetic_call_stubs_8616(project, frozenset({0x1020}))
    elif failure == "storage":
        codegen._inertia_stack_variable_coordinate_registry_8616 = StackVariableCoordinateRegistry8616()
    elif failure == "offset":
        summary = replace(summary, push_arg_sources=(("seg", "ss"), ("bp_addr", -14)))
    elif failure == "push":
        summary = replace(summary, push_arg_instruction_addrs=(0x1003, 0x1005))
    elif failure == "mask":
        assignment.rhs.lhs.rhs.value = 0
    elif failure == "extra_use":
        root.statements.insert(1, c.CAssignment(assignment.lhs, assignment.lhs, codegen=codegen))
    elif failure == "dirty":
        assignment.rhs.rhs.lhs = c.CDirtyExpression(object(), codegen=codegen)
    elif failure == "target":
        call.tags["inertia_target_addr_8616"] = 0x1021
    elif failure == "argument_use":
        call.args[1] = assignment.lhs
    elif failure == "missing_arguments":
        call.args = None
    elif failure == "outside_image":
        call.tags["inertia_target_addr_8616"] = 0x5000
        summary = replace(summary, target_addr=0x5000)
    before = tuple(root.statements)
    assert not prune_consumed_stack_address_setup_8616(project, codegen, root, {0x1006: summary})
    assert tuple(root.statements) == before
    assert codegen._inertia_consumed_stack_setup_census_8616.materialized_count == 0
