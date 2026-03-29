from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable

from angr_platforms.X86_16.decompiler_postprocess_globals import (
    WordGlobalStoreCandidate,
    _coalesce_word_global_constant_stores_8616,
    describe_word_global_constant_store_candidates_8616,
)


def _make_codegen(statements):
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=archinfo.ArchX86()),
        cfunc=SimpleNamespace(addr=0x1000),
    )
    codegen.cfunc.statements = structured_c.CStatements(statements, codegen=codegen)
    return codegen


def _global_var(addr: int, codegen):
    return structured_c.CVariable(
        SimMemoryVariable(addr, 1, name=f"g_{addr:x}", region=0x1000),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_word_global_store_candidate_extraction_detects_adjacent_constants():
    codegen = _make_codegen([])
    stmt0 = structured_c.CAssignment(
        _global_var(0x2000, codegen),
        structured_c.CConstant(0x12, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    stmt1 = structured_c.CAssignment(
        _global_var(0x2001, codegen),
        structured_c.CConstant(0x34, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([stmt0, stmt1], codegen=codegen)
    project = SimpleNamespace(arch=SimpleNamespace())

    candidates = describe_word_global_constant_store_candidates_8616(project, codegen)

    assert candidates == (WordGlobalStoreCandidate(0x2000, 0x2001, "constant"),)


def test_word_global_store_coalescer_promotes_constant_pairs():
    codegen = _make_codegen([])
    stmt0 = structured_c.CAssignment(
        _global_var(0x2000, codegen),
        structured_c.CConstant(0x12, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    stmt1 = structured_c.CAssignment(
        _global_var(0x2001, codegen),
        structured_c.CConstant(0x34, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([stmt0, stmt1], codegen=codegen)
    project = SimpleNamespace(arch=SimpleNamespace())

    changed = _coalesce_word_global_constant_stores_8616(project, codegen)

    assert 0x2000 in changed
    assert len(codegen.cfunc.statements.statements) == 1
