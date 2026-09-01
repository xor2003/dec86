from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.tail_validation import (
    refresh_x86_16_final_semantic_validation_8616,
)
from angr_platforms.X86_16.validation.entry_stack_ranges import (
    entry_stack_ranges_from_codegen_8616,
)
from angr_platforms.X86_16.validation_dataflow import (
    DefUseEntryStackRange8616,
    validate_structured_def_use_8616,
)
from archinfo import ArchX86


def _codegen() -> SimpleNamespace:
    """Return the minimal third-party codegen surface needed by C nodes."""
    return SimpleNamespace(
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=ArchX86()),
    )


def _cvar(
    codegen: SimpleNamespace,
    offset: int,
    width: int = 2,
    name: str = "arg",
) -> CVariable:
    """Build one BP-relative structured variable for focused validation."""
    return CVariable(
        SimStackVariable(offset, width, base="bp", name=name, ident=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_explicit_entry_range_accepts_exact_read_and_refuses_overlap() -> None:
    codegen = _codegen()
    entry_range = (DefUseEntryStackRange8616(base_offset=4, width=2),)

    exact = validate_structured_def_use_8616(
        CStatements([_cvar(codegen, 4)], codegen=codegen),
        entry_defined_stack_ranges=entry_range,
    )
    overlapping = validate_structured_def_use_8616(
        CStatements([_cvar(codegen, 5)], codegen=codegen),
        entry_defined_stack_ranges=entry_range,
    )

    assert exact.passed
    assert exact.materialized_count == 1
    assert overlapping.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP+0x5:size2:root.stmt0",
    )


def test_codegen_collector_projects_entry_sp_argument_to_machine_bp() -> None:
    codegen = _codegen()
    argument = _cvar(codegen, 2)
    codegen.cfunc = SimpleNamespace(arg_list=[argument])
    storage = argument.variable
    assert isinstance(storage, SimStackVariable)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=storage,
        cvar=argument,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )

    collection = entry_stack_ranges_from_codegen_8616(codegen)

    assert collection.ranges == (
        DefUseEntryStackRange8616(base_offset=4, width=2),
    )
    assert collection.stats.raw_fact_count == 1
    assert collection.stats.normalized_fact_count == 1
    assert collection.stats.classified_fact_count == 1
    assert collection.stats.materialized_count == 1
    assert collection.stats.failure_count == 0
    assert collection.stats.complete is True


def test_final_tail_validation_refuses_read_overlapping_argument_boundary() -> None:
    codegen = _codegen()
    argument = _cvar(codegen, 2)
    storage = argument.variable
    assert isinstance(storage, SimStackVariable)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=storage,
        cvar=argument,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[argument],
        statements=CStatements([_cvar(codegen, 5)], codegen=codegen),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
        persist_failures=False,
    )

    assert report.def_use.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP+0x5:size2:root.stmt0",
    )
