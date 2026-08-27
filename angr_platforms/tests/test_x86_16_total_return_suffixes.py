from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CIfElse,
    CLabel,
    CReturn,
    CStatements,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.structuring.total_return_suffixes import (
    prune_unreachable_total_return_suffixes_8616,
)
from archinfo import ArchX86


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _return_body(codegen: _Codegen, value: int) -> CStatements:
    expression = CConstant(value, SimTypeShort(False), codegen=codegen)
    return CStatements([CReturn(expression, codegen=codegen)], codegen=codegen)


def _total_return_chain(codegen: _Codegen) -> CIfElse:
    conditions = [
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(2, SimTypeShort(False), codegen=codegen),
    ]
    for condition in conditions:
        condition.tags[
            "inertia_structuring_multi_arm_return_chain_materialized_8616"
        ] = True
    return CIfElse(
        [
            (conditions[0], _return_body(codegen, 10)),
            (conditions[1], _return_body(codegen, 20)),
        ],
        else_node=_return_body(codegen, 30),
        cstyle_ifs=True,
        codegen=codegen,
    )


def test_total_return_suffix_prunes_unreachable_register_return() -> None:
    codegen = _Codegen()
    chain = _total_return_chain(codegen)
    unreachable = CReturn(
        CConstant(99, SimTypeShort(False), codegen=codegen), codegen=codegen
    )
    root = CStatements([chain, unreachable], codegen=codegen)

    result = prune_unreachable_total_return_suffixes_8616(root)

    assert root.statements == [chain]
    assert result.removed_statement_count == 1
    assert result.stats.raw_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_total_return_suffix_refuses_labeled_entry() -> None:
    codegen = _Codegen()
    chain = _total_return_chain(codegen)
    label = CLabel("reachable_target", codegen=codegen)
    root = CStatements([chain, label], codegen=codegen)

    result = prune_unreachable_total_return_suffixes_8616(root)

    assert root.statements == [chain, label]
    assert result.removed_statement_count == 0
    assert result.stats.failure_count == 1
