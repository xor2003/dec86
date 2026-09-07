"""Pointer-store projection folding must preserve segments and live carriers."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.near_pointer_argument import NearPointerArgumentFact8616
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    _lower_typed_pointer_register_carrier_stores_8616,
)


def _word_store(*, segment="ds", carrier_value=False, later_use=False):
    arch = Arch86_16()
    word = SimTypeShort(False).with_arch(arch)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
        cstyle_null_cmp=False,
    )

    def register(name):
        return c.CVariable(
            SimRegisterVariable(*arch.registers[name], name=name),
            variable_type=word,
            codegen=codegen,
        )

    def constant(value):
        return c.CConstant(value, word, codegen=codegen)

    pointer = c.CVariable(
        SimStackVariable(6, 2, base="bp", name="output", region=0x4010),
        variable_type=SimTypePointer(word).with_arch(arch),
        codegen=codegen,
    )
    carrier = register("bx")
    value = carrier if carrier_value else register("ax")
    tags = {"inertia_source_instruction_addrs": (0x4018,)}
    low = c.CAssignment(
        c.CIndexedVariable(pointer, constant(0), codegen=codegen, tags=tags),
        value,
        codegen=codegen,
    )
    high = c.CAssignment(
        c.CFunctionCall(
            "SEG_U16", None,
            [register(segment), c.CBinaryOp("Add", carrier, constant(1), codegen=codegen)],
            codegen=codegen,
            tags={**tags, "inertia_x86_16_runtime_segment_helper": "SEG_U16"},
        ),
        c.CBinaryOp("Shr", value, constant(8), codegen=codegen),
        codegen=codegen,
    )
    statements = [c.CAssignment(carrier, pointer, codegen=codegen), low, high]
    if later_use:
        statements.append(c.CAssignment(register("cx"), carrier, codegen=codegen))
    root = c.CStatements(statements, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010, statements=root, body=root, arg_list=[pointer],
        functy=SimTypeFunction([pointer.variable_type], word).with_arch(arch),
    )
    codegen._inertia_near_pointer_argument_facts_8616 = (
        NearPointerArgumentFact8616(6, 0x4014, 0x4018, 2),
    )
    return codegen, low, value


def test_word_store_fold_preserves_exact_value():
    codegen, low, value = _word_store()
    assert _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert codegen.cfunc.statements.statements == [low]
    assert low.rhs is value


@pytest.mark.parametrize("options", [
    {"segment": "es"},
    {"segment": "ss"},
    {"carrier_value": True},
    {"later_use": True},
])
def test_word_store_fold_refuses_conflicting_segment_or_live_carrier(options):
    codegen, low, value = _word_store(**options)
    original = tuple(codegen.cfunc.statements.statements)
    assert not _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert tuple(codegen.cfunc.statements.statements) == original
    assert low.rhs is value
