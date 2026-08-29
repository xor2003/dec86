"""Tests for cycle-safe tail-validation generation atom reuse."""

from __future__ import annotations

from angr_platforms.X86_16.tail_validation_generation_atoms import (
    build_validation_generation_atom_8616,
)


class _SharedSurface:
    """Third-party-like semantic surface with observable field reads."""

    def __init__(self, name: str) -> None:
        self._name = name
        self.name_reads = 0

    @property
    def name(self) -> str:
        """Return the semantic name while counting normalization work."""
        self.name_reads += 1
        return self._name


def test_generation_atom_reuses_shared_cycle_free_surface() -> None:
    """One build must expand a repeated acyclic object only once."""
    shared = _SharedSurface("value")

    atom = build_validation_generation_atom_8616((shared, shared, shared))

    assert shared.name_reads == 1
    assert atom[2][0] == atom[2][1] == atom[2][2]


def test_generation_atom_preserves_path_sensitive_cycle_marker() -> None:
    """Cyclic objects must retain an ancestor-identity refusal marker."""
    cycle: list[object] = []
    cycle.append(cycle)

    atom = build_validation_generation_atom_8616(cycle)

    assert atom == (
        "sequence",
        "builtins.list",
        (("cycle", "builtins.list", id(cycle)),),
    )


def test_generation_atom_does_not_reuse_across_top_level_requests() -> None:
    """A later build must observe mutations to previously normalized evidence."""
    shared = _SharedSurface("before")
    before = build_validation_generation_atom_8616(shared)
    shared._name = "after"

    after = build_validation_generation_atom_8616(shared)

    assert before != after
    assert shared.name_reads == 2
