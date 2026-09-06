from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import angr
import angr_platforms.X86_16.ir.function_ssa_registry as function_ssa_registry
import networkx as nx
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16

import inertia_decompiler.cache as cache_module
from inertia_decompiler.direct_indexed_alias_local_cache import (
    build_cached_direct_indexed_alias_local_evidence_8616,
)

_INDEXED_FUNCTION = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 01 00 "
    "8b 5e fe d1 e3 88 87 00 02 "
    "8b 5e fe d1 e3 88 a7 01 02 "
    "8b 5e fe d1 e3 88 87 00 03 "
    "8b 5e fe d1 e3 88 a7 01 03 c9 c3"
)


@dataclass(frozen=True, slots=True)
class _BlockNode:
    addr: int
    size: int


def _project() -> angr.Project:
    return angr.Project(
        io.BytesIO(_INDEXED_FUNCTION),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )


def _function() -> object:
    graph = nx.DiGraph()
    graph.add_node(_BlockNode(0x1000, len(_INDEXED_FUNCTION)))
    return SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        graph=graph,
        info={},
    )


def test_fresh_direct_project_hydrates_ir_ssa_before_local_alias_build(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "0")
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    original_builder = function_ssa_registry.build_x86_16_ir_function_artifact
    raw_build_projects: list[object] = []

    def counted_builder(project: object, function: object) -> object:
        raw_build_projects.append(project)
        return original_builder(project, function)

    monkeypatch.setattr(
        function_ssa_registry,
        "build_x86_16_ir_function_artifact",
        counted_builder,
    )
    first_project = _project()
    first = build_cached_direct_indexed_alias_local_evidence_8616(
        first_project,
        _function(),
    )
    second_project = _project()
    second = build_cached_direct_indexed_alias_local_evidence_8616(
        second_project,
        _function(),
    )

    assert first.closed
    assert second.closed
    assert raw_build_projects == [first_project]
    assert second_project not in raw_build_projects

