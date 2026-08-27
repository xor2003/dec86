from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import MemSpace
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    DirectSegmentedGlobalLoadEvidence8616,
    _make_direct_segmented_global_load_expr_8616,
    _unambiguous_anonymous_direct_scalar_evidence_8616,
)
from angr_platforms.X86_16.widening.segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_identity_8616,
)


class _Codegen:
    def __init__(self, project: object) -> None:
        self.cfunc = SimpleNamespace(addr=0x10970)
        self.project = project
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_direct_segmented_global_load_retains_evidence_instruction() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    evidence = DirectSegmentedGlobalLoadEvidence8616(
        offset=0x0BA2,
        width=2,
        space=MemSpace.DS,
        ins_addr=0x1099E,
    )

    expression = _make_direct_segmented_global_load_expr_8616(
        project,
        codegen,
        evidence,
    )

    assert expression is not None
    assert segmented_load_identity_8616(expression) == SegmentedLoadIdentity8616(
        space=MemSpace.DS,
        offset=0x0BA2,
        width=2,
        region=0x10970,
    )
    assert expression.tags["inertia_source_instruction_addrs"] == (0x1099E,)


def test_anonymous_direct_scalar_identity_refuses_overlapping_widths() -> None:
    word = DirectSegmentedGlobalLoadEvidence8616(0x0BA2, 2, MemSpace.DS, 0x1099E)
    byte = DirectSegmentedGlobalLoadEvidence8616(0x0BA3, 1, MemSpace.DS, 0x109A0)

    assert _unambiguous_anonymous_direct_scalar_evidence_8616(
        {(0x0BA2, 2): word},
        0x0BA2,
        2,
    ) == word
    assert _unambiguous_anonymous_direct_scalar_evidence_8616(
        {(0x0BA2, 2): word, (0x0BA3, 1): byte},
        0x0BA2,
        2,
    ) is None
