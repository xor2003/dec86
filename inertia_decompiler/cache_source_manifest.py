"""Own source-component scopes for persistent decompiler caches.

Layer: CLI/fallback/reporting.
Responsibility: identify implementation files that can change discovery-only
artifacts separately from files that can change final generated C.
Forbidden: weakening final decompilation cache invalidation or classifying
semantic output as discovery-only.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

_DISCOVERY_INERTIA_NAMES_8616 = frozenset(
    {
        "cache.py",
        "cache_io.py",
        "cache_lock.py",
        "cache_runtime_contract.py",
        "cache_source_manifest.py",
        "cli.py",
        "cli_arg_parser.py",
        "cli_core.py",
        "cli_function_discovery.py",
        "disassembly_helpers.py",
        "discovery_cache_contract.py",
        "discovery_evidence_project.py",
        "project_loading.py",
        "rizin_discovery.py",
        "rizin_evidence.py",
        "runtime_support.py",
        "sidecar_cache.py",
        "sidecar_metadata.py",
        "sidecar_parsers.py",
        "sidecar_policy.py",
        "slice_recovery.py",
        "source_sidecar.py",
        "work_items.py",
        "x86_16_exact_slice.py",
    }
)

_DISCOVERY_X86_16_ROOT_EXCLUDED_PREFIXES_8616 = (
    "alias_",
    "decompiler_",
    "postprocess_",
    "recompilable_",
    "structuring_",
    "tail_validation",
    "type_",
    "validation_",
    "widening_",
)

_DISCOVERY_X86_16_DEPENDENCY_DIRS_8616 = (
    "ir",
    "semantics",
)

_RECOVERY_PIPELINE_DEPENDENCY_NAMES_8616 = (
    "contracts.py",
    "errors.py",
)

_INDEXED_ALIAS_PROGRAM_INERTIA_NAMES_8616 = (
    *_DISCOVERY_INERTIA_NAMES_8616,
    "indexed_alias_program_context.py",
    "indexed_alias_program_parallel.py",
    "project_evidence_transport.py",
)

_INDEXED_ALIAS_PROGRAM_X86_16_DEPENDENCY_DIRS_8616 = (
    *_DISCOVERY_X86_16_DEPENDENCY_DIRS_8616,
    "alias",
    "widening",
)

_PROGRAM_CALLSITE_INERTIA_NAMES_8616 = (
    *_DISCOVERY_INERTIA_NAMES_8616,
    "indexed_alias_program_context.py",
    "indexed_alias_program_parallel.py",
    "program_callsite_cache.py",
)

_PROGRAM_CALLSITE_LOWERING_NAMES_8616 = (
    "callee_callsite_codec.py",
    "callee_callsite_contracts.py",
    "callee_range_callsite_facts.py",
    "project_callee_callsite_collection.py",
)


class RecoveryCacheSourceScope8616(StrEnum):
    """Implementation surface that owns one recovery-cache artifact."""

    FULL_DECOMPILATION = "full-decompilation"
    FUNCTION_DISCOVERY = "function-discovery"
    INDEXED_ALIAS_PROGRAM = "indexed-alias-program"
    PROGRAM_CALLSITE = "program-callsite"


def _function_discovery_cache_source_files_8616() -> tuple[Path, ...]:
    """Return the conservative frontend/discovery implementation surface."""
    inertia_root = _ROOT / "inertia_decompiler"
    x86_root = _ROOT / "angr_platforms" / "angr_platforms" / "X86_16"
    discovered = {
        inertia_root / name
        for name in _DISCOVERY_INERTIA_NAMES_8616
    }
    discovered.update(
        path
        for path in x86_root.glob("*.py")
        if not path.name.startswith(
            _DISCOVERY_X86_16_ROOT_EXCLUDED_PREFIXES_8616
        )
    )
    discovered.update(
        path
        for directory_name in _DISCOVERY_X86_16_DEPENDENCY_DIRS_8616
        for path in (x86_root / directory_name).rglob("*.py")
    )
    discovered.update(
        x86_root / "pipeline" / name
        for name in _RECOVERY_PIPELINE_DEPENDENCY_NAMES_8616
    )
    discovered.update(
        {
            _ROOT / "omf_pat.py",
            _ROOT / "signature_catalog.py",
        }
    )
    return tuple(sorted(path for path in discovered if path.is_file()))


FUNCTION_DISCOVERY_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _function_discovery_cache_source_files_8616()
)


def _indexed_alias_program_cache_source_files_8616() -> tuple[Path, ...]:
    """Return discovery plus the Alias/Widening program implementation surface."""
    inertia_root = _ROOT / "inertia_decompiler"
    x86_root = _ROOT / "angr_platforms" / "angr_platforms" / "X86_16"
    discovered = {
        inertia_root / name
        for name in _INDEXED_ALIAS_PROGRAM_INERTIA_NAMES_8616
    }
    discovered.update(
        path
        for path in FUNCTION_DISCOVERY_CACHE_SOURCE_FILES
    )
    discovered.update(
        path
        for directory_name in _INDEXED_ALIAS_PROGRAM_X86_16_DEPENDENCY_DIRS_8616
        for path in (x86_root / directory_name).rglob("*.py")
    )
    return tuple(sorted(path for path in discovered if path.is_file()))


INDEXED_ALIAS_PROGRAM_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _indexed_alias_program_cache_source_files_8616()
)


def _program_callsite_cache_source_files_8616() -> tuple[Path, ...]:
    """Return exact discovery and callsite-summary artifact owners."""
    inertia_root = _ROOT / "inertia_decompiler"
    x86_root = _ROOT / "angr_platforms" / "angr_platforms" / "X86_16"
    discovered = {
        inertia_root / name
        for name in _PROGRAM_CALLSITE_INERTIA_NAMES_8616
    }
    discovered.update(FUNCTION_DISCOVERY_CACHE_SOURCE_FILES)
    discovered.update((x86_root / "alias").rglob("*.py"))
    discovered.update(
        x86_root / "lowering" / name
        for name in _PROGRAM_CALLSITE_LOWERING_NAMES_8616
    )
    return tuple(sorted(path for path in discovered if path.is_file()))


PROGRAM_CALLSITE_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _program_callsite_cache_source_files_8616()
)
