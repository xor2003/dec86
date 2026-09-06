"""Mypyc build and import-artifact ownership for developer tooling.

Layer: Tooling/gates.
Responsibility: reconcile mypyc schema and module-cohort changes, and isolate
only native artifacts that can participate in project imports.
"""

from __future__ import annotations

import importlib.machinery
import os
import shutil
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class MypycBuildCacheLayout:
    """Describe the isolated mypyc cache paths and compatibility schema."""

    repo_root: Path
    cache_dir: Path
    lib_dir: Path
    cgen_dir: Path
    schema: str

    def __post_init__(self) -> None:
        """Refuse cleanup roots outside the configured cache tree."""
        cache_root = self.cache_root.resolve()
        for owned_dir in (self.lib_dir, self.cgen_dir):
            if not (self.repo_root / owned_dir).resolve().is_relative_to(cache_root):
                raise ValueError(f"mypyc artifact directory escapes cache root: {owned_dir}")

    @property
    def cache_root(self) -> Path:
        """Return the absolute cache root."""
        return self.repo_root / self.cache_dir


def iter_importable_project_extensions(repo_root: Path) -> tuple[Path, ...]:
    """List project extensions reachable through normal source-package imports."""
    search_roots = (
        repo_root / "inertia_decompiler",
        repo_root / "angr_platforms" / "angr_platforms",
    )
    candidates = set(repo_root.glob("*.so"))
    for search_root in search_roots:
        if search_root.is_dir():
            candidates.update(search_root.rglob("*.so"))
    suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    return tuple(sorted(path for path in candidates if path.name.endswith(suffixes)))


@contextmanager
def disable_importable_project_extensions(repo_root: Path) -> Iterator[None]:
    """Temporarily park importable project extensions and restore every file."""
    modules = iter_importable_project_extensions(repo_root)
    moved: list[tuple[Path, Path]] = []
    try:
        for index, path in enumerate(modules):
            parked = path.with_name(f".{path.name}.pure-python-{os.getpid()}-{index}")
            if parked.exists():
                raise FileExistsError(f"pure-Python extension parking path exists: {parked}")
            path.replace(parked)
            moved.append((parked, path))
        yield
    finally:
        conflicts: list[Path] = []
        for parked, original in reversed(moved):
            if not parked.exists():
                continue
            if original.exists():
                conflicts.append(original)
                continue
            parked.replace(original)
        if conflicts:
            paths = ", ".join(str(path) for path in sorted(conflicts))
            raise FileExistsError(f"cannot restore parked Python extensions: {paths}")


def _read_lines(path: Path) -> tuple[str, ...]:
    """Read a small cache contract file, refusing missing or unreadable state."""
    try:
        return tuple(line for line in path.read_text(encoding="utf-8").splitlines() if line)
    except OSError:
        return ()


def _remove_module_artifacts(
    layout: MypycBuildCacheLayout,
    module: str,
    module_to_path: Callable[[str], str],
) -> None:
    """Remove one retired module's importable artifacts and generated sources."""
    module_parts = module.split(".")
    if not module_parts or any(not part.isidentifier() for part in module_parts):
        raise ValueError(f"invalid mypyc module name: {module!r}")
    cache_root = layout.cache_root.resolve()
    stem = module_parts[-1]
    target_dir = layout.repo_root / layout.lib_dir / Path(*module_parts[:-1])
    generated_dir = layout.repo_root / layout.cgen_dir / Path(*module_parts[:-1])
    if any(not owned_dir.resolve().is_relative_to(cache_root) for owned_dir in (target_dir, generated_dir)):
        raise ValueError(f"mypyc module artifact directory escapes cache root: {module!r}")
    for artifact_stem in (stem, f"{stem}__mypyc"):
        for suffix in importlib.machinery.EXTENSION_SUFFIXES:
            (target_dir / f"{artifact_stem}{suffix}").unlink(missing_ok=True)

    source_path = Path(module_to_path(module))
    marker_name = str(source_path).replace("/", "__") + ".stamp"
    (layout.cache_root / marker_name).unlink(missing_ok=True)

    for generated_name in (
        f"{stem}.c",
        f"{stem}.h",
        f"__native_{stem}.c",
        f"__native_{stem}.h",
    ):
        (generated_dir / generated_name).unlink(missing_ok=True)


def reconcile_mypyc_build_cache(
    layout: MypycBuildCacheLayout,
    modules: Iterable[str],
    module_to_path: Callable[[str], str],
) -> None:
    """Reconcile schema and cohort state while preserving unrelated artifacts."""
    requested_modules = tuple(sorted(set(modules)))
    cache_root = layout.cache_root
    schema_path = cache_root / "build-schema.txt"
    cohort_path = cache_root / "module-cohort.txt"
    schema_lines = _read_lines(schema_path)
    current_schema = schema_lines[0] if schema_lines else ""

    if current_schema != layout.schema:
        shutil.rmtree(cache_root, ignore_errors=True)
        cache_root.mkdir(parents=True, exist_ok=True)
        previous_modules: tuple[str, ...] = ()
    else:
        cache_root.mkdir(parents=True, exist_ok=True)
        cohort_lines = _read_lines(cohort_path)
        # Read the old combined schema/cohort format during one-way migration.
        previous_modules = cohort_lines or schema_lines[1:]

    requested = frozenset(requested_modules)
    for retired_module in sorted(set(previous_modules) - requested):
        _remove_module_artifacts(layout, retired_module, module_to_path)

    schema_path.write_text(f"{layout.schema}\n", encoding="utf-8")
    cohort_path.write_text("".join(f"{module}\n" for module in requested_modules), encoding="utf-8")
