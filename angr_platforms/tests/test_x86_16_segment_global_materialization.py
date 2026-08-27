"""Ordering regressions for the segmented-global Lowering coordinator."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from angr_platforms.X86_16.lowering import segment_global_materialization as materialization


def test_runtime_segment_projection_runs_after_typed_materializers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    state = {"indexed": False, "widened": False}

    def record(name: str, *, changed: bool = False) -> Any:
        def run(*_args: object, **_kwargs: object) -> bool:
            calls.append(name)
            return changed

        return run

    def indexed(*_args: object, **_kwargs: object) -> bool:
        calls.append("indexed")
        state["indexed"] = True
        return True

    def widening(*_args: object, **_kwargs: object) -> bool:
        calls.append("widening")
        assert state["indexed"] is True
        state["widened"] = True
        return True

    def runtime(*_args: object, **_kwargs: object) -> bool:
        calls.append("runtime")
        assert state == {"indexed": True, "widened": True}
        return True

    monkeypatch.setattr(materialization, "materialize_named_segmented_global_loads_8616", record("named"))
    monkeypatch.setattr(materialization, "materialize_compare_register_global_carriers_8616", record("compare"))
    monkeypatch.setattr(materialization, "materialize_indexed_segmented_global_loads_8616", indexed)
    monkeypatch.setattr(materialization, "materialize_direct_global_symbol_stores_8616", record("direct"))
    monkeypatch.setattr(materialization, "materialize_dos_interrupt_aggregate_globals_8616", record("dos"))
    monkeypatch.setattr(materialization, "apply_segmented_load_widening_8616", widening)
    monkeypatch.setattr(materialization, "apply_runtime_segment_lowering_8616", runtime)

    result = materialization.run_segment_global_materialization_8616(
        SimpleNamespace(_inertia_c_target="portable-flat"),
        SimpleNamespace(cfunc=SimpleNamespace(statements=object())),
        synthetic_globals=None,
        include_runtime_segment=True,
    )

    assert calls == ["named", "compare", "indexed", "direct", "dos", "widening", "runtime"]
    assert result.indexed_global_changed is True
    assert result.segmented_load_widening_changed is True
    assert result.runtime_segment_changed is True
    assert result.changed is True
