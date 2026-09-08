"""A later machine reload must not overwrite an earlier register consumer."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.real_mode_linear import (
    materialize_direct_stack_mov_instructions_8616,
)
from capstone.x86 import X86_INS_MOV, X86_REG_AX
from test_x86_16_segmented_runtime_lowering import (
    _bp_mem_operand,
    _imm_operand,
    _project,
    _reg,
    _reg_operand,
)


@pytest.mark.parametrize("origin", [0x4020, 0x4024, None])
def test_reload_placement_preserves_earlier_register_consumer(origin):
    project, codegen = _project()
    local = SimStackVariable(-2, 2, base="bp", name="counter", region=0x4010)
    local_expr = CVariable(local, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[local] = local_expr
    register = _reg(project, "ax", codegen)
    earlier = CExpressionStatement(
        CFunctionCall("sub_2000", None, [register], codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    later = CExpressionStatement(
        CFunctionCall("sub_3000", None, [register], codegen=codegen),
        codegen=codegen,
        tags={} if origin is None else {"ins_addr": origin},
    )
    store = CAssignment(
        local_expr, CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen, tags={"ins_addr": 0x4018},
    )
    statements = codegen.cfunc.statements.statements
    statements.extend([earlier, store, later])
    instructions = (
        SimpleNamespace(address=0x4018, id=X86_INS_MOV,
                        operands=(_bp_mem_operand(-2), _imm_operand(7))),
        SimpleNamespace(address=0x4020, id=X86_INS_MOV,
                        operands=(_reg_operand(X86_REG_AX), _bp_mem_operand(-2))),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=instructions)),),
    )

    materialize_direct_stack_mov_instructions_8616(codegen, project=project, function=function)

    assert statements[0] is earlier
    assert statements[-1] is later
    if origin != 0x4020:
        assert statements == [earlier, store, later]
        return
    reload = statements[-2]
    assert isinstance(reload, CAssignment)
    assert reload.lhs.variable is register.variable
    assert isinstance(reload.rhs, CConstant)
    assert reload.rhs.value == 7
