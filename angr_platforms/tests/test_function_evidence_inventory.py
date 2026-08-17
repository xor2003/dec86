from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16 import function_evidence_inventory
from angr_platforms.X86_16.function_evidence_inventory import (
    FunctionEvidenceKind8616,
    collect_function_binary_evidence_8616,
)


def test_addressable_functions_do_not_alias_when_object_ids_are_reused(monkeypatch) -> None:
    project = SimpleNamespace()
    collected: list[int] = []

    def builder(_project: object | None, function: object) -> tuple[int]:
        address = function.addr
        collected.append(address)
        return (address,)

    monkeypatch.setattr(function_evidence_inventory, "id", lambda _value: 7, raising=False)
    first = SimpleNamespace(addr=0x100, size=8, blocks=())
    second = SimpleNamespace(addr=0x200, size=8, blocks=())

    assert collect_function_binary_evidence_8616(
        project,
        first,
        kind=FunctionEvidenceKind8616.INDEXED_GLOBAL_LOAD_SITES,
        builder=builder,
    ) == (0x100,)
    assert collect_function_binary_evidence_8616(
        project,
        second,
        kind=FunctionEvidenceKind8616.INDEXED_GLOBAL_LOAD_SITES,
        builder=builder,
    ) == (0x200,)
    assert collected == [0x100, 0x200]


def test_recreated_function_range_reuses_binary_evidence() -> None:
    project = SimpleNamespace()
    build_count = 0

    def builder(_project: object | None, function: object) -> tuple[int]:
        nonlocal build_count
        build_count += 1
        return (function.addr,)

    for _iteration in range(2):
        function = SimpleNamespace(addr=0x1234, size=12, blocks=())
        assert collect_function_binary_evidence_8616(
            project,
            function,
            kind=FunctionEvidenceKind8616.INDEXED_GLOBAL_STORES,
            builder=builder,
        ) == (0x1234,)

    assert build_count == 1


def test_changed_binary_surface_invalidates_address_cache() -> None:
    project = SimpleNamespace()
    build_count = 0

    def builder(_project: object | None, function: object) -> tuple[int]:
        nonlocal build_count
        build_count += 1
        return (function.size,)

    first = SimpleNamespace(addr=0x1234, size=12, blocks=())
    changed = SimpleNamespace(addr=0x1234, size=14, blocks=())

    assert collect_function_binary_evidence_8616(
        project,
        first,
        kind=FunctionEvidenceKind8616.NEAR_POINTER_ARGUMENTS,
        builder=builder,
    ) == (12,)
    assert collect_function_binary_evidence_8616(
        project,
        changed,
        kind=FunctionEvidenceKind8616.NEAR_POINTER_ARGUMENTS,
        builder=builder,
    ) == (14,)
    assert build_count == 2


def test_opaque_function_cache_retains_and_checks_owner(monkeypatch) -> None:
    project = SimpleNamespace()
    build_count = 0

    def builder(_project: object | None, function: object) -> tuple[object]:
        nonlocal build_count
        build_count += 1
        return (function,)

    monkeypatch.setattr(function_evidence_inventory, "id", lambda _value: 7, raising=False)
    first = object()
    second = object()

    assert collect_function_binary_evidence_8616(
        project,
        first,
        kind=FunctionEvidenceKind8616.INSTRUCTION_SUMMARIES,
        builder=builder,
    ) == (first,)
    assert collect_function_binary_evidence_8616(
        project,
        first,
        kind=FunctionEvidenceKind8616.INSTRUCTION_SUMMARIES,
        builder=builder,
    ) == (first,)
    assert collect_function_binary_evidence_8616(
        project,
        second,
        kind=FunctionEvidenceKind8616.INSTRUCTION_SUMMARIES,
        builder=builder,
    ) == (second,)
    assert build_count == 2
