from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CConstant, CIfElse, CReturn, CStatements
from angr.sim_type import SimTypeShort

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _if_return(cond_value: int, return_value: int, codegen):
    body = CStatements(
        statements=[CReturn(_const(return_value, codegen), codegen=codegen)],
        codegen=codegen,
    )
    return CIfElse([(_const(cond_value, codegen), body)], else_node=None, cstyle_ifs=True, codegen=codegen)


def test_prune_duplicate_empty_return_accepts_single_statement_wrapper_before_cfg_suffix():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    wrapped_empty_return = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    root = CStatements(
        statements=[
            wrapped_empty_return,
            _if_return(1, -1, codegen),
            _if_return(2, 0, codegen),
            _if_return(3, 1, codegen),
            CReturn(_const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_return_chain_suffix_materialized_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = (-1, 0, 1)

    changed = _prune_duplicate_empty_return_guard_before_cfg_suffix_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_return_chain_empty_prefix_pruned_8616 is True
    assert codegen.cfunc.statements.statements[0] is not wrapped_empty_return
