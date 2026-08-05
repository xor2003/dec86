from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    reconcile_exact_stack_argument_prototype_8616,
)


def test_reconcile_refuses_wrapped_negative_local_byte_carriers_as_arguments() -> None:
    arch = Arch86_16()
    char_type = SimTypeChar().with_arch(arch)
    prototype = SimTypeFunction(
        [char_type, char_type],
        SimTypeShort(False),
        arg_names=("carrier_lo", "carrier_hi"),
    ).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create=False: function if addr == 0x1000 else None,
            )
        ),
    )
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=project)
    carriers = [
        structured_c.CVariable(
            SimStackVariable(offset, 1, base="bp", name=name, region=0x1000),
            variable_type=char_type,
            codegen=c_codegen,
        )
        for offset, name in ((0xFFF8, "carrier_lo"), (0xFFF9, "carrier_hi"))
    ]
    cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=carriers,
        functy=prototype,
        unified_local_vars={},
    )
    codegen = SimpleNamespace(cfunc=cfunc, _inertia_callsite_summaries={})

    changed = reconcile_exact_stack_argument_prototype_8616(project, codegen)

    assert changed is False
    assert not hasattr(codegen, "_inertia_function_parameter_width_facts_8616")
    assert tuple(cfunc.functy.args) == (char_type, char_type)
