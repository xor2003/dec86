from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)

from inertia_decompiler import indexed_alias_program_context as indexed_context


def test_complete_source_collection_runs_only_in_whole_file_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = SimpleNamespace()
    ranges = SimpleNamespace()
    layout = GlobalObjectLayoutEvidence8616((), 0, 0, 0, 0)
    function = SimpleNamespace(addr=0x1000)
    parent_project = SimpleNamespace()
    worker_project = SimpleNamespace()
    collections: list[object] = []
    monkeypatch.setattr(
        indexed_context,
        "build_indexed_alias_program_evidence_8616",
        lambda _project, _selections: program,
    )
    monkeypatch.setattr(
        indexed_context,
        "recover_global_object_layout_evidence_8616",
        lambda _program: layout,
    )
    monkeypatch.setattr(
        indexed_context,
        "recover_program_bounded_global_object_ranges_8616",
        lambda _program, _layout: ranges,
    )
    monkeypatch.setattr(
        indexed_context,
        "collect_complete_project_global_object_sources_8616",
        lambda project, _functions, _layout: collections.append(project),
    )

    indexed_context.publish_discovered_indexed_alias_program_8616(
        parent_project,
        (function,),
        target_project=worker_project,
    )
    assert collections == []

    indexed_context.publish_discovered_indexed_alias_program_8616(
        parent_project,
        (function,),
    )
    assert collections == [parent_project]
