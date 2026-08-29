from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _ensure_pointer_stack_arg_expr_8616,
)
from angr_platforms.X86_16.lowering.pointer_memory_idioms import (
    splice_proven_pointer_swap_statements_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


def test_pointer_memory_arguments_reuse_exact_machine_bp_projections() -> None:
    """Keep distinct BP arguments when their entry-SP offsets collide numerically."""
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    pointer_type = SimTypePointer(word_type).with_arch(arch)
    prototype = SimTypeFunction(
        [pointer_type, pointer_type],
        word_type,
        arg_names=("bar1", "bar2"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=prototype,
        is_prototype_guessed=False,
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create: (
                    function if addr == function.addr and not create else None
                )
            )
        ),
    )
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=project,
    )
    left_storage = SimStackVariable(2, 2, base="bp", name="bar1")
    right_storage = SimStackVariable(4, 2, base="bp", name="bar2")
    left = CVariable(left_storage, variable_type=pointer_type, codegen=codegen)
    right = CVariable(right_storage, variable_type=pointer_type, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=function.addr,
        arg_list=[left, right],
        functy=prototype,
        prototype=prototype,
        statements=CStatements([], codegen=codegen),
        unified_local_vars={},
        variables_in_use={left_storage: left, right_storage: right},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=left_storage,
        cvar=left,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
        display_name="bar1",
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=right_storage,
        cvar=right,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
        display_name="bar2",
    )

    selected_left = _ensure_pointer_stack_arg_expr_8616(
        project,
        codegen,
        4,
        pointee_size=2,
        fallback_name="left",
    )
    selected_right = _ensure_pointer_stack_arg_expr_8616(
        project,
        codegen,
        6,
        pointee_size=2,
        fallback_name="right",
    )

    assert selected_left is left
    assert selected_right is right
    assert selected_left.variable is not selected_right.variable
    assert codegen.cfunc.arg_list == [left, right]


def test_pointer_swap_refuses_collapsed_argument_storage_identity() -> None:
    """Refuse a swap whose two pointer expressions own the same stack slot."""
    arch = Arch86_16()
    word_type = SimTypeShort(False).with_arch(arch)
    pointer_type = SimTypePointer(word_type).with_arch(arch)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
    )
    shared_storage = SimStackVariable(4, 2, base="bp", name="shared")
    left = CVariable(shared_storage, variable_type=pointer_type, codegen=codegen)
    right = CVariable(shared_storage, variable_type=pointer_type, codegen=codegen)
    temporary = CVariable(
        SimStackVariable(-2, 2, base="bp", name="temporary"),
        variable_type=word_type,
        codegen=codegen,
    )
    zero = CConstant(0, word_type, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements(
            [
                CAssignment(
                    temporary,
                    CIndexedVariable(left, zero, variable_type=word_type, codegen=codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    CIndexedVariable(left, zero, variable_type=word_type, codegen=codegen),
                    CIndexedVariable(right, zero, variable_type=word_type, codegen=codegen),
                    codegen=codegen,
                ),
                CAssignment(
                    CIndexedVariable(right, zero, variable_type=word_type, codegen=codegen),
                    temporary,
                    codegen=codegen,
                ),
            ],
            codegen=codegen,
        )
    )

    assert not splice_proven_pointer_swap_statements_8616(
        codegen,
        left,
        right,
        temporary,
        frozenset({0x1010, 0x1012, 0x1014, 0x1016}),
        frozenset({0x1014, 0x1016}),
    )
    stats = codegen._inertia_pointer_swap_splice_stats_8616
    assert stats.failure_count == 1
    assert stats.materialized_count == 0
    assert stats.idempotent_count == 0
