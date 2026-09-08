"""Tests for immutable Frontend function-boundary inventory reuse."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16 import frontend_function_boundary_index as index_module
from angr_platforms.X86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
)
from angr_platforms.X86_16.frontend_function_boundary_index import (
    exact_function_entry_boundary_8616,
    exact_function_range_inventory_8616,
)


def _boundary(project: object, start: int, end: int) -> ExactFunctionRangeBoundary8616:
    """Build one minimal complete boundary fixture."""
    return ExactFunctionRangeBoundary8616(
        project=project,
        addr=start,
        size=end - start,
        block_addrs_set=frozenset({start}),
        reachable_instruction_addrs=frozenset({start}),
        successor_edges=(),
    )


def test_exact_function_range_inventory_reuses_boundaries(monkeypatch) -> None:
    project = SimpleNamespace()
    calls: list[tuple[int, int]] = []

    def collect(project_arg: object, start: int, end: int) -> ExactFunctionRangeBoundary8616:
        calls.append((start, end))
        return _boundary(project_arg, start, end)

    monkeypatch.setattr(index_module, "exact_function_range_boundary_8616", collect)
    ranges = ((0x100, 0x120), (0x200, 0x230))

    first = exact_function_range_inventory_8616(project, ranges)
    second = exact_function_range_inventory_8616(project, ranges)

    assert second is first
    assert calls == list(ranges)
    assert tuple(boundary.addr for boundary in first.boundaries) == (0x100, 0x200)


def test_exact_function_range_inventory_keys_distinct_ranges(monkeypatch) -> None:
    project = SimpleNamespace()
    calls: list[tuple[int, int]] = []

    def collect(project_arg: object, start: int, end: int) -> ExactFunctionRangeBoundary8616:
        calls.append((start, end))
        return _boundary(project_arg, start, end)

    monkeypatch.setattr(index_module, "exact_function_range_boundary_8616", collect)

    exact_function_range_inventory_8616(project, ((0x100, 0x120),))
    exact_function_range_inventory_8616(project, ((0x100, 0x130),))

    assert calls == [(0x100, 0x120), (0x100, 0x130)]


def test_exact_function_range_inventory_keeps_failed_ranges_closed(monkeypatch) -> None:
    project = SimpleNamespace()
    monkeypatch.setattr(
        index_module,
        "exact_function_range_boundary_8616",
        lambda _project, _start, _end: None,
    )

    inventory = exact_function_range_inventory_8616(project, ((0x100, 0x120),))

    assert inventory.ranges == ((0x100, 0x120),)
    assert inventory.boundaries == ()


@pytest.mark.parametrize("start,end,accepted", [
    (0x1000, 0x1020, True), (0x1000, 0x1100, True),
    (0xFFF, 0x1020, False), (0x1000, 0x1101, False), (0x1000, 0x1000, False),
])
def test_exact_function_range_inventory_refuses_ranges_outside_rebased_image(monkeypatch, start, end, accepted) -> None:
    project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(min_addr=0x1000, max_addr=0x10FF))
    )
    calls: list[tuple[int, int]] = []

    def collect(project_arg: object, start: int, end: int) -> ExactFunctionRangeBoundary8616:
        calls.append((start, end))
        return _boundary(project_arg, start, end)

    monkeypatch.setattr(index_module, "exact_function_range_boundary_8616", collect)

    inventory = exact_function_range_inventory_8616(
        project,
        ((start, end), (0x10000, 0x10020)),
    )

    assert calls == ([(start, end)] if accepted else [])
    assert tuple(boundary.addr for boundary in inventory.boundaries) == ((start,) if accepted else ())


def test_exact_function_entry_boundary_accepts_only_padding_to_prologue(monkeypatch) -> None:
    boundary = _boundary(object(), 0x100, 0x120)
    image = b"\x90" * 7 + b"\x55\x8b\xec" + b"\x90" * 22

    class Memory:
        def load(self, addr: int, size: int) -> bytes:
            offset = addr - 0x100
            return image[offset : offset + size]

    project = SimpleNamespace(loader=SimpleNamespace(memory=Memory()))
    monkeypatch.setattr(
        index_module,
        "exact_function_range_inventory_8616",
        lambda _project, ranges: SimpleNamespace(ranges=ranges, boundaries=(boundary,)),
    )

    assert exact_function_entry_boundary_8616(project, 0x107, ((0x100, 0x120),)) is boundary
    assert exact_function_entry_boundary_8616(project, 0x108, ((0x100, 0x120),)) is None
