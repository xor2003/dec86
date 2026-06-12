from __future__ import annotations

from types import SimpleNamespace

from angr.sim_type import SimTypeFunction, SimTypeShort
from angr_platforms.X86_16.annotations import ANNOTATION_KEY
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)


class _DummyCodegen(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _codegen_with_stack_specs(stack_specs):
    return _DummyCodegen(
        _func=SimpleNamespace(info={ANNOTATION_KEY: {"stack_vars": stack_specs}}),
        project=SimpleNamespace(arch=Arch86_16()),
        cfunc=SimpleNamespace(
            addr=0x1000,
            arg_list=[],
            variables_in_use={},
            unified_local_vars={},
        ),
    )


def test_stable_stack_names_use_single_object_bias_for_positive_args():
    codegen = _codegen_with_stack_specs(
        {
            2: {"name": "value"},
            4: {"name": "limit"},
        }
    )

    value = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(4, 2))
    limit = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(6, 2))

    assert value.name == "value"
    assert value.variable.offset == 4
    assert limit.name == "limit"
    assert limit.variable.offset == 6
    assert [arg.name for arg in codegen.cfunc.arg_list] == ["value", "limit"]
    assert not codegen.cfunc.unified_local_vars


def test_stable_stack_names_use_exact_positive_arg_specs_without_bias():
    codegen = _codegen_with_stack_specs(
        {
            4: {"name": "value"},
            6: {"name": "limit"},
        }
    )

    value = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(4, 2))
    limit = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(6, 2))

    assert value.name == "value"
    assert value.variable.offset == 4
    assert limit.name == "limit"
    assert limit.variable.offset == 6
    assert [arg.name for arg in codegen.cfunc.arg_list] == ["value", "limit"]
    assert not codegen.cfunc.unified_local_vars


def test_stable_stack_arg_types_use_source_prototype_by_bp_offset():
    arch = Arch86_16()
    signed_word = SimTypeShort(True).with_arch(arch)
    codegen = _codegen_with_stack_specs(
        {
            2: {"name": "value"},
            4: {"name": "limit"},
        }
    )
    source_proto = SimTypeFunction(
        [signed_word, signed_word],
        signed_word,
        arg_names=("value", "limit"),
    ).with_arch(arch)
    codegen._func = SimpleNamespace(prototype=source_proto, is_prototype_guessed=False)
    codegen.cfunc.functy = source_proto

    value = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(4, 2))
    limit = stack_cvar_for_stable_ss_linear_access_8616(codegen, RealModeLinearStackAccess8616(6, 2))

    assert getattr(value.variable_type, "signed", None) is True
    assert getattr(limit.variable_type, "signed", None) is True
    assert [getattr(arg_type, "signed", None) for arg_type in codegen.cfunc.functy.args] == [True, True]
    assert codegen._inertia_stack_arg_source_prototype_type_materialized_8616 == 2
