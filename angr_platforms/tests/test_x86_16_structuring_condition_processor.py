from __future__ import annotations

from types import SimpleNamespace

import archinfo
import claripy
from angr import ailment
from angr.ailment.manager import Manager
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr_platforms.X86_16.decompiler_structuring_stage import (
    _guard_condition_processor_multibit_bool_predicates_8616,
)


def test_condition_processor_multibit_must_bool_becomes_nonzero_bool_predicate():
    project = SimpleNamespace()
    arch = archinfo.ArchX86()
    reg = ailment.Expr.Register(None, 0, 16)

    with _guard_condition_processor_multibit_bool_predicates_8616(project):
        processor = ConditionProcessor(arch, Manager(arch=arch))
        predicate = processor.claripy_ast_from_ail_condition(reg, must_bool=True, ins_addr=0x4010)

    assert isinstance(predicate, claripy.ast.Bool)
    assert getattr(project, "_inertia_condition_predicate_multibit_bool_normalized", 0) == 1
    assert getattr(project, "_inertia_condition_predicate_multibit_bool_refused", 0) == 0
