from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CIfElse, CReturn, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.structuring.return_chains import (
    ReturnSelectorCallbacks8616,
    ensure_return_chain_codegen_state_8616,
    materialize_cfg_selector_return_branches_8616,
)
from angr_platforms.X86_16.structuring.selector_return_projection import (
    SelectorReturnProjectionVerdict8616,
    assess_selector_return_projection_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.cfunc = SimpleNamespace(addr=0x4010, statements=CStatements(statements=[], codegen=self))

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_ident(self, name: str) -> str:
        return name

    def next_node_idx(self) -> int:
        return self.next_idx("")


def _constant(value: int, codegen: _Codegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _fingerprint(expr: object, _project: object) -> str:
    if isinstance(expr, CConstant):
        return f"const:{expr.value}"
    if isinstance(expr, CBinaryOp):
        return f"{expr.op}({_fingerprint(expr.lhs, _project)},{_fingerprint(expr.rhs, _project)})"
    return type(expr).__name__


def _set_root(codegen: _Codegen, root: CStatements) -> None:
    codegen.cfunc.statements = root


def _callbacks(
    pairs: list[tuple[CConstant | CBinaryOp, CConstant, CConstant]],
) -> ReturnSelectorCallbacks8616:
    return ReturnSelectorCallbacks8616(
        materialize_decrement_switch_return_chain=lambda _project, _codegen: False,
        ordered_32bit_selector_return_expr_pairs=lambda _project, _codegen: list(pairs),
        ordered_conditional_return_expr_pairs=lambda _project, _codegen: [],
        selector_condition_call_addrs=lambda _pairs: frozenset(),
        selector_condition_call_addrs_from_cfg=lambda _project, _codegen: frozenset(),
        selector_function_has_unsafe_effects=lambda _project, _codegen, _allowed: False,
        clone_c_value_for_codegen_tree=lambda expr: expr,
        set_cfunc_statements_root=_set_root,
        expr_fingerprint=_fingerprint,
    )


def _condition(codegen: _Codegen, value: int) -> CBinaryOp:
    return CBinaryOp(
        "CmpEQ",
        _constant(7, codegen),
        _constant(value, codegen),
        codegen=codegen,
    )


def test_selector_return_replays_stale_projection_with_live_marker() -> None:
    project = object()
    codegen = _Codegen()
    ensure_return_chain_codegen_state_8616(codegen)
    expected_condition = _condition(codegen, 0)
    true_return = _constant(10, codegen)
    final_return = _constant(5, codegen)
    callbacks = _callbacks([(expected_condition, true_return, final_return)])

    assert materialize_cfg_selector_return_branches_8616(project, codegen, callbacks)
    stale_condition = _condition(codegen, 5)
    codegen.cfunc.statements = CStatements(
        statements=[
            CIfElse(
                [(stale_condition, CStatements(statements=[CReturn(true_return, codegen=codegen)], codegen=codegen))],
                else_node=None,
                codegen=codegen,
            ),
            CReturn(final_return, codegen=codegen),
        ],
        codegen=codegen,
    )
    stale = assess_selector_return_projection_8616(codegen, project, _fingerprint)
    assert stale.verdict is SelectorReturnProjectionVerdict8616.STALE_FINGERPRINTS

    assert materialize_cfg_selector_return_branches_8616(project, codegen, callbacks)
    repaired = assess_selector_return_projection_8616(codegen, project, _fingerprint)
    assert repaired.verdict is SelectorReturnProjectionVerdict8616.PASSED
    assert repaired.classified_fact_count == repaired.materialized_count == 1


def test_selector_return_stale_projection_hard_fails_when_evidence_cannot_replay() -> None:
    project = object()
    codegen = _Codegen()
    ensure_return_chain_codegen_state_8616(codegen)
    expected_condition = _condition(codegen, 0)
    callbacks = _callbacks([(expected_condition, _constant(10, codegen), _constant(5, codegen))])
    assert materialize_cfg_selector_return_branches_8616(project, codegen, callbacks)
    codegen.cfunc.statements = CStatements(statements=[CReturn(_constant(5, codegen), codegen=codegen)], codegen=codegen)

    with pytest.raises(PipelineHardError, match="lost CFG-proven selector-return projection"):
        materialize_cfg_selector_return_branches_8616(project, codegen, _callbacks([]))
