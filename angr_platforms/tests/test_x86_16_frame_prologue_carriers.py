"""Regress exact typed frame-prologue carrier classification."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.frame_prologue_carriers import (
    is_exact_push_bp_carrier_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from archinfo import ArchX86


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def test_push_bp_carrier_accepts_semantic_cast_storage_view() -> None:
    """A typed byte view must retain the tagged frame-store identity."""
    codegen = _Codegen()
    project = codegen.project
    saved_frame = CVariable(
        SimStackVariable(-4, 2, base="bp", name="fn"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    frame_anchor = CVariable(
        SimStackVariable(0, 1, base="bp", name="local_0"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    destination = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeChar(False),
        saved_frame,
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        CUnaryOp("Reference", frame_anchor, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    root = CStatements([assignment], codegen=codegen)

    assert is_exact_push_bp_carrier_8616(
        assignment,
        root,
        project,
        0x4010,
        canonical_frame_proven=True,
    )
