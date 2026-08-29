"""Tests for projecting status-flag evidence across rebased exact slices."""

from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir import status_flag_cfg_projection
from angr_platforms.X86_16.ir.status_flag_binary_cfg import (
    BinaryStatusFlagReadSummary8616,
)
from angr_platforms.X86_16.semantics.status_flag_contracts import StatusFlag8616


def _project(start: int, end: int) -> SimpleNamespace:
    return SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(min_addr=start, max_addr=end - 1),
        ),
    )


def test_rebased_slice_summarizes_out_of_slice_callee_in_original_image(
    monkeypatch,
) -> None:
    original = _project(0x10000, 0x20000)
    rebased = _project(0x1000, 0x1100)
    rebased._inertia_original_project = original
    rebased._inertia_original_linear_delta = 0xF000
    seen: list[tuple[object, int]] = []

    def summarize(project: object, *, entry_address: int, **_kwargs):
        seen.append((project, entry_address))
        return BinaryStatusFlagReadSummary8616(
            StatusFlag8616.NONE,
            1,
            1,
            1,
            1,
            0,
        )

    monkeypatch.setattr(
        status_flag_cfg_projection,
        "summarize_binary_status_flag_entry_reads_8616",
        summarize,
    )

    resolver = status_flag_cfg_projection._StatusFlagFunctionSummaryResolver8616(rebased)
    effect = resolver.effect_for_address(0x900)

    assert effect is not None
    assert effect.reads is StatusFlag8616.NONE
    assert seen == [(original, 0xF900)]


def test_rebased_slice_keeps_in_slice_callee_in_slice(monkeypatch) -> None:
    original = _project(0x10000, 0x20000)
    rebased = _project(0x1000, 0x1100)
    rebased._inertia_original_project = original
    rebased._inertia_original_linear_delta = 0xF000
    seen: list[tuple[object, int]] = []

    def summarize(project: object, *, entry_address: int, **_kwargs):
        seen.append((project, entry_address))
        return BinaryStatusFlagReadSummary8616(
            StatusFlag8616.NONE,
            1,
            1,
            1,
            1,
            0,
        )

    monkeypatch.setattr(
        status_flag_cfg_projection,
        "summarize_binary_status_flag_entry_reads_8616",
        summarize,
    )

    resolver = status_flag_cfg_projection._StatusFlagFunctionSummaryResolver8616(rebased)
    assert resolver.effect_for_address(0x1004) is not None
    assert seen == [(rebased, 0x1004)]
