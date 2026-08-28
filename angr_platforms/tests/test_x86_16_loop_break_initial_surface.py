"""Focused tests for the pre-mutation loop-break AST surface."""

from collections.abc import Iterator
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CBreak,
    CConstant,
    CIfBreak,
    CStatements,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.structuring import loop_break_jcc


class _Codegen:
    """Minimal structured-codegen boundary for the loop fixture."""

    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return one deterministic node index."""
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        """Return one deterministic AST node index."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Return the stable fixture identifier."""
        return name


def _condition(
    codegen: _Codegen,
    *,
    ins_addr: int,
    block_addr: int,
    typed_loop: bool = False,
) -> CBinaryOp:
    """Build one tagged condition expression."""
    return CBinaryOp(
        "CmpNE",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": ins_addr,
            "vex_block_addr": block_addr,
            "inertia_typed_loop_condition_bound_8616": typed_loop,
        },
    )


def test_loop_break_initial_surface_collects_all_projections_in_one_walk(
    monkeypatch,
) -> None:
    """One pre-mutation walk must publish every initial query projection."""
    codegen = _Codegen()
    loop_condition = _condition(
        codegen,
        ins_addr=0x1002,
        block_addr=0x1000,
        typed_loop=True,
    )
    guard_condition = _condition(
        codegen,
        ins_addr=0x1012,
        block_addr=0x1010,
    )
    guard = CIfBreak(guard_condition, codegen=codegen, cstyle_ifs=True)
    loop = CWhileLoop(
        loop_condition,
        CStatements([guard, CBreak(codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    original = loop_break_jcc._iter_c_nodes_deep_8616
    walk_count = 0

    def counted_walk(node: object) -> Iterator[object]:
        nonlocal walk_count
        walk_count += 1
        yield from original(node)

    monkeypatch.setattr(loop_break_jcc, "_iter_c_nodes_deep_8616", counted_walk)

    surface = loop_break_jcc._collect_loop_break_initial_surface_8616(root)

    assert walk_count == 1
    assert surface.condition_keys == frozenset({(0x1002, 0x1000), (0x1012, 0x1010)})
    assert surface.loop_header_jcc_addrs == frozenset({0x1002})
    assert surface.typed_loop_condition_jcc_addrs == frozenset({0x1002})
    assert dict(surface.break_nodes_by_key) == {(0x1012, 0x1010): (guard,)}
