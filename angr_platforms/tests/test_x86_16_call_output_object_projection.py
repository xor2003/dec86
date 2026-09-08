"""Call-output fields must retain their binary-proven machine-BP coordinates."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunction, CVariable, CVariableField
from angr.sim_type import SimStruct, SimTypeBottom, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.call_output_object_projection import publish_call_output_object_projection_8616
from angr_platforms.X86_16.lowering.call_output_stack_object_replay import reapply_call_output_stack_object_types_8616
from angr_platforms.X86_16.lowering.call_output_stack_objects import (
    lower_call_output_stack_fields_in_condition_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_variable_coordinate_registry_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from test_x86_16_call_output_stack_objects import _condition, _fixture, _VariableManager


def test_call_output_publishes_missing_projection_before_field_materialization():
    codegen, condition, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    call = codegen.cfunc.statements.statements[0].expr
    old_base = call.args[0].operand
    registry = stack_variable_coordinate_registry_8616(codegen)
    codegen._inertia_stack_variable_coordinate_registry_8616 = replace(
        registry, projections=tuple(item for item in registry.projections if item.variable is not old_base.variable)
    )
    codegen.cfunc.variables_in_use.pop(old_base.variable)
    narrow = SimStackVariable(-114, 1, base="bp", name="config", region=0x1000)
    base = CVariable(narrow, variable_type=SimTypeBottom(), codegen=codegen)
    call.args[0].operand = base
    codegen.cfunc.variables_in_use[narrow] = base
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))

    result = lower_call_output_stack_fields_in_condition_8616(codegen, condition, conditions)

    assert result.stats.materialized_count == 2
    field = result.expression.lhs.lhs
    assert isinstance(field, CVariableField)
    bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, field.variable.variable)
    assert bp_offset == -112
    assert bp_offset + field.field.offset == -94
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(narrow)
    assert projection is not None
    assert (projection.bp_offset, projection.entry_sp_offset, projection.size) == (-112, -114, 22)
    assert narrow.size == 1


@pytest.mark.parametrize("byte_size,bp_offset", [(0, -112), (-1, -112), (22, -110)])
def test_call_output_projection_refuses_invalid_or_conflicting_facts(byte_size, bp_offset):
    codegen, _condition_expr, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    base = codegen.cfunc.statements.statements[0].expr.args[0].operand
    previous = stack_variable_coordinate_registry_8616(codegen)

    with pytest.raises(PipelineHardError):
        publish_call_output_object_projection_8616(codegen, base, bp_offset=bp_offset, byte_size=byte_size)

    assert stack_variable_coordinate_registry_8616(codegen) is previous


@pytest.mark.parametrize("bias", [0, -2])
def test_call_output_projection_replay_preserves_existing_aliases(bias):
    codegen, _condition_expr, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=bias)
    base = codegen.cfunc.statements.statements[0].expr.args[0].operand
    first = publish_call_output_object_projection_8616(codegen, base, bp_offset=-112, byte_size=22)
    alias_variable = SimStackVariable(-112 + bias, 1, base="bp", name="config_alias", region=0x1000)
    alias = CVariable(alias_variable, variable_type=base.variable_type, codegen=codegen)

    rebound = publish_call_output_object_projection_8616(codegen, alias, bp_offset=-112, byte_size=22)
    replayed = publish_call_output_object_projection_8616(codegen, base, bp_offset=-112, byte_size=22)

    assert rebound.variable is first.variable
    assert replayed.variable is first.variable
    assert alias_variable in replayed.equivalent_variables
    assert replayed.size == 22
    assert base.variable.size == 112
    assert alias_variable.size == 1
    assert machine_bp_offset_for_stack_variable_8616(codegen, alias_variable) == -112


@pytest.mark.parametrize("stale_ast", [False, True])
def test_call_output_replay_refreshes_real_cfunction_declaration_types(stale_ast):
    class VariableManager(_VariableManager):
        def unified_variable(self, _variable):
            return None

        def get_variable_type(self, variable):
            return self.variable_types.get(variable)

    codegen, condition, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    previous = codegen.cfunc
    manager = VariableManager()
    codegen.cfunc = CFunction(
        previous.addr, "example", SimTypeFunction([], SimTypeBottom(label="void")), [],
        previous.statements, previous.variables_in_use, manager, codegen=codegen,
    )
    result = lower_call_output_stack_fields_in_condition_8616(
        codegen, condition, (_condition(-94, 0x103F), _condition(-98, 0x1048)),
    )
    base = result.facts[0].base_cvar
    if stale_ast:
        base.variable_type = SimTypeShort(False)
    manager.set_variable_type(base.variable, SimTypeShort(False))
    codegen.cfunc.refresh()
    assert all(isinstance(type_, SimTypeShort) for _, type_ in codegen.cfunc.unified_local_vars[base.variable])
    unrelated = {variable: entries for variable, entries in codegen.cfunc.unified_local_vars.items()
                 if variable is not base.variable}

    assert reapply_call_output_stack_object_types_8616(codegen)

    assert isinstance(base.variable_type, SimStruct)
    assert isinstance(manager.get_variable_type(base.variable), SimStruct)
    assert all(isinstance(type_, SimStruct) for _, type_ in codegen.cfunc.unified_local_vars[base.variable])
    assert all(codegen.cfunc.unified_local_vars[variable] is entries for variable, entries in unrelated.items())
    assert not reapply_call_output_stack_object_types_8616(codegen)
