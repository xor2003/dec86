#!/usr/bin/env python3
"""Build optional mypyc acceleration artifacts for local developer runs.

Layer: Tooling/gates.
Responsibility: run optional local mypyc builds without owning decompiler semantics.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TARGET_MODULES = [
    "inertia_decompiler.decompile_file_summary",
]
MYPYC_CACHE_DIR = Path(".cache") / "mypyc"


@dataclass(frozen=True)
class ModuleState:
    """Track one mypyc module source and cache marker."""

    module: str
    source_path: Path
    marker_path: Path


def _module_source_path(value: str) -> Path:
    """Resolve a module spec (dotted or file path) to a Python source file."""
    if value.endswith(".py"):
        return Path(value)
    return Path(*value.split(".")).with_suffix(".py")


def _module_artifact_candidates(module_state: ModuleState) -> list[Path]:
    target_dir = module_state.source_path.parent
    stem = module_state.source_path.stem
    return sorted(target_dir.glob(f"{stem}__mypyc*.so"))


def _module_marker(module_state: ModuleState) -> Path:
    return module_state.marker_path


def _setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build optional mypyc-compiled modules.")
    parser.add_argument(
        "setup_args",
        nargs="*",
        help="Arguments forwarded to setuptools (e.g. 'build_ext --inplace').",
    )
    parser.add_argument(
        "--module",
        action="append",
        default=[],
        help="Extra modules to compile (append dotted module names).",
    )
    return parser


def _module_to_path(value: str) -> str:
    """Convert dotted module names to source file paths for mypyc CLI compatibility."""
    if value.endswith(".py"):
        return value
    return str(Path(*value.split("."))).replace("\\", "/") + ".py"


def _collect_module_states(modules: Iterable[str]) -> list[ModuleState]:
    module_path = (REPO_ROOT / "scripts" / "build_mypyc.py").resolve()
    cache_root = REPO_ROOT / MYPYC_CACHE_DIR
    cache_root.mkdir(parents=True, exist_ok=True)
    states: list[ModuleState] = []
    for module in modules:
        source_path = (REPO_ROOT / _module_to_path(module)).resolve()
        marker_path = cache_root / (str(source_path.relative_to(REPO_ROOT)).replace("/", "__") + ".stamp")
        states.append(
            ModuleState(
                module=module,
                source_path=source_path,
                marker_path=marker_path,
            )
        )
    return states


def _build_stale(module_states: list[ModuleState]) -> list[ModuleState]:
    stale: list[ModuleState] = []
    control_inputs = [REPO_ROOT / "pyproject.toml", REPO_ROOT / "scripts" / "build_mypyc.py"]
    for module_state in module_states:
        source_mtime = module_state.source_path.stat().st_mtime if module_state.source_path.exists() else 0
        control_mtime = max(item.stat().st_mtime for item in control_inputs if item.exists())
        marker = _module_marker(module_state)
        artifacts = _module_artifact_candidates(module_state)
        if not artifacts:
            stale.append(module_state)
            continue
        latest_artifact_mtime = max(artifact.stat().st_mtime for artifact in artifacts)
        if marker.exists() and marker.stat().st_mtime >= max(source_mtime, control_mtime, latest_artifact_mtime):
            continue
        stale.append(module_state)
    return stale


def _refresh_markers(module_states: list[ModuleState]) -> None:
    marker_time = max((int(state.source_path.stat().st_mtime) for state in module_states), default=0)
    marker_epoch = marker_time if marker_time else 0
    for module_state in module_states:
        module_state.marker_path.write_text(f"{module_state.source_path} {marker_epoch}\n")


def main(argv: list[str] | None = None) -> int:
    parser = _setup_parser()
    parsed, setup_args = parser.parse_known_args(argv)

    try:
        modules = [module for module in (TARGET_MODULES + list(parsed.module))]
        modules = [module for module in modules if module]
        if not modules:
            return 0

        module_states = _collect_module_states(modules)
        stale_module_states = _build_stale(module_states)
        if not stale_module_states:
            print("mypyc: up-to-date; skipping build")
            return 0

        from mypyc.build import mypycify
        from setuptools import setup
    except Exception as exc:  # pragma: no cover
        print("mypy/mypyc is required for this build path. Install with: pip install .[mypyc]")
        print(f"Original error: {exc}")
        return 1

    stale_modules = [stale_state.module for stale_state in stale_module_states]
    module_paths = [_module_to_path(module) for module in stale_modules]
    if not module_paths:
        print("mypyc: no stale modules to compile")
        return 0

    setup(
        name="vextest-x86-16-mypyc",
        version="0.1",
        package_dir={"": "."},
        packages=["inertia_decompiler"],
        ext_modules=mypycify(module_paths),
        script_name=sys.argv[0],
        script_args=["build_ext", "--inplace"] if not setup_args else setup_args,
    )
    _refresh_markers(stale_module_states)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
