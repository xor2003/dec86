from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.stack_argument_identity import (
    unify_positive_bp_argument_identity_8616,
)
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    reconcile_exact_stack_argument_prototype_8616,
)


def test_unify_positive_bp_argument_identity_propagates_pointer_type() -> None:
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
    )
    pointer_type = SimTypePointer(SimTypeShort(False)).with_arch(arch)
    scalar_type = SimTypeShort(False).with_arch(arch)
    argument = CVariable(
        SimStackVariable(6, 2, base="bp", name="argv", region=0x1000),
        variable_type=pointer_type,
        codegen=codegen,
    )
    duplicate = CVariable(
        SimStackVariable(6, 2, base="bp", name="local_6", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    indexed = CIndexedVariable(duplicate, index, codegen=codegen)
    call = CFunctionCall("consume", None, [indexed], codegen=codegen)
    statements = CStatements([call], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[argument],
        statements=statements,
        variables_in_use={
            argument.variable: argument,
            duplicate.variable: duplicate,
        },
        unified_local_vars={
            duplicate.variable: {(duplicate, duplicate.variable_type)},
        },
    )

    changed = unify_positive_bp_argument_identity_8616(codegen)

    assert changed is True
    rewritten = call.args[0]
    assert isinstance(rewritten, CIndexedVariable)
    assert rewritten.variable.variable is argument.variable
    assert rewritten.variable.variable_type is pointer_type
    assert list(codegen.cfunc.variables_in_use.values()) == [argument]
    assert codegen.cfunc.unified_local_vars == {}
    stats = codegen._inertia_arg_stack_identity_stats_8616
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0


def test_unify_positive_bp_argument_identity_refuses_ambiguous_header() -> None:
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
    )
    scalar_type = SimTypeShort(False).with_arch(arch)
    arguments = [
        CVariable(
            SimStackVariable(6, 2, base="bp", name=name, region=0x1000),
            variable_type=scalar_type,
            codegen=codegen,
        )
        for name in ("first", "second")
    ]
    duplicate = CVariable(
        SimStackVariable(6, 2, base="bp", name="body", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=arguments,
        statements=CStatements([duplicate], codegen=codegen),
        variables_in_use={duplicate.variable: duplicate},
        unified_local_vars={},
    )

    assert unify_positive_bp_argument_identity_8616(codegen) is False
    assert codegen._inertia_arg_stack_identity_stats_8616.failure_count == 0


def test_reconcile_renames_provisional_local_positive_bp_argument() -> None:
    arch = Arch86_16()
    scalar_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction(
        [scalar_type],
        scalar_type,
        arg_names=["local"],
    ).with_arch(arch)
    function = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: (
                    function if addr == 0x1000 else None
                )
            )
        ),
    )
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
    )
    argument = CVariable(
        SimStackVariable(6, 2, base="bp", name="local_6", region=0x1000),
        variable_type=scalar_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[argument],
        functy=prototype,
        variables_in_use={argument.variable: argument},
        unified_local_vars={},
    )
    codegen._inertia_callsite_summaries = {
        0x1010: SimpleNamespace(
            arg_widths=(2,),
            push_arg_sources=(("bp", 6),),
        )
    }

    assert reconcile_exact_stack_argument_prototype_8616(project, codegen) is True
    assert argument.variable.name == "arg_6"
    assert tuple(codegen.cfunc.functy.arg_names or ()) == ("arg_6",)
