"""Content-addressed cache keys for decompiler recovery artifacts.

Layer: CLI/fallback/reporting.
Responsibility: derive cache keys from binary, sidecar, and implementation fingerprints only.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

DECOMPILATION_CACHE_SCHEMA: int = 5
DECOMPILATION_CACHE_DIR: Path = _ROOT / ".inertia_decomp_cache"
BASE_RECOVERY_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _ROOT / "decompile.py",
    _ROOT / "inertia_decompiler" / "cli.py",
    _ROOT / "inertia_decompiler" / "cli_core.py",
    _ROOT / "inertia_decompiler" / "cli_decompilation.py",
    _ROOT / "inertia_decompiler" / "cli_function_discovery.py",
    _ROOT / "inertia_decompiler" / "cache.py",
    _ROOT / "inertia_decompiler" / "decompilation_quality.py",
    _ROOT / "inertia_decompiler" / "disassembly_helpers.py",
    _ROOT / "inertia_decompiler" / "non_optimized_fallback.py",
    _ROOT / "inertia_decompiler" / "project_loading.py",
    _ROOT / "inertia_decompiler" / "source_sidecar.py",
    _ROOT / "inertia_decompiler" / "sidecar_policy.py",
    _ROOT / "inertia_decompiler" / "sidecar_parsers.py",
    _ROOT / "inertia_decompiler" / "sidecar_metadata.py",
    _ROOT / "inertia_decompiler" / "slice_recovery.py",
    _ROOT / "inertia_decompiler" / "rizin_discovery.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "analysis_helpers.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_mz.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_ne.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lift_86_16.py",
)
SIDECAR_METADATA_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _ROOT / "inertia_decompiler" / "cache.py",
    _ROOT / "inertia_decompiler" / "sidecar_parsers.py",
    _ROOT / "inertia_decompiler" / "sidecar_metadata.py",
    _ROOT / "omf_pat.py",
    _ROOT / "signature_catalog.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "cod_extract.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "codeview_nb00.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "codeview_nb02_nb04.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "flair_extract.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_mz.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_ne.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lst_extract.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "turbo_debug_tdinfo.py",
)
BASE_DECOMPILATION_CACHE_SOURCE_FILES: tuple[Path, ...] = (
    _ROOT / "decompile.py",
    _ROOT / "inertia_decompiler" / "cli.py",
    _ROOT / "inertia_decompiler" / "cli_decompilation.py",
    _ROOT / "inertia_decompiler" / "cli_core.py",
    _ROOT / "inertia_decompiler" / "cli_c_ast_rewrites.py",
    _ROOT / "inertia_decompiler" / "cli_dead_local_prune.py",
    _ROOT / "inertia_decompiler" / "cli_c_text_postprocess.py",
    _ROOT / "inertia_decompiler" / "cache.py",
    _ROOT / "inertia_decompiler" / "decompilation_quality.py",
    _ROOT / "inertia_decompiler" / "disassembly_helpers.py",
    _ROOT / "inertia_decompiler" / "recompile_check.py",
    _ROOT / "inertia_decompiler" / "non_optimized_fallback.py",
    _ROOT / "inertia_decompiler" / "project_loading.py",
    _ROOT / "inertia_decompiler" / "source_sidecar.py",
    _ROOT / "inertia_decompiler" / "sidecar_policy.py",
    _ROOT / "inertia_decompiler" / "sidecar_parsers.py",
    _ROOT / "inertia_decompiler" / "sidecar_metadata.py",
    _ROOT / "inertia_decompiler" / "slice_recovery.py",
    _ROOT / "inertia_decompiler" / "tail_validation.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "analysis_helpers.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "postprocess" / "optimization" / "dead_setup.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "postprocess" / "optimization" / "const_prop.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "postprocess" / "optimization" / "dce.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "postprocess" / "optimization" / "pass_driver.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "condition_ir.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_flags.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_calls.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_jcc.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_stage.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_simplify.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_typed_conditions.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_postprocess_utils.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "segmented_memory_reasoning.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lowering" / "real_mode_linear.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lowering" / "segmented_global_loads.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "callsite_stack_metadata.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "decompiler_structuring_stage.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "lift_86_16.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_mz.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "load_dos_ne.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation_condition_context.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation_fingerprint.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "tail_validation_routing.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "type_array_matching.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "cod_comment_emitter.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "cod_extract.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "ir" / "core.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "pipeline" / "invariants.py",
    _ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / "validation_summary.py",
    _ROOT / "inertia_decompiler" / "cli_access_object_hints.py",
    _ROOT / "inertia_decompiler" / "cli_access_profiles.py",
    _ROOT / "inertia_decompiler" / "cli_access_traits.py",
)


def _production_decompiler_source_files() -> tuple[Path, ...]:
    """Return every production Python module that can affect decompilation."""
    package_roots = (
        _ROOT / "inertia_decompiler",
        _ROOT / "angr_platforms" / "angr_platforms" / "X86_16",
    )
    discovered = {
        path
        for package_root in package_roots
        for path in package_root.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    discovered.add(_ROOT / "decompile.py")
    return tuple(sorted(discovered))


_PRODUCTION_DECOMPILER_SOURCE_FILES: tuple[Path, ...] = _production_decompiler_source_files()
RECOVERY_CACHE_SOURCE_FILES: tuple[Path, ...] = tuple(
    sorted(set((*BASE_RECOVERY_CACHE_SOURCE_FILES, *_PRODUCTION_DECOMPILER_SOURCE_FILES)))
)
DECOMPILATION_CACHE_SOURCE_FILES: tuple[Path, ...] = tuple(
    sorted(set((*BASE_DECOMPILATION_CACHE_SOURCE_FILES, *_PRODUCTION_DECOMPILER_SOURCE_FILES)))
)


def _cache_sha256_file(path: Path) -> str:
    """Return a streamed content digest for one cache input file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_file_fingerprint(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    try:
        resolved = path.resolve()
        stat = resolved.stat()
        content_sha256 = _cache_sha256_file(resolved)
    except OSError:
        return None
    return {
        "path": str(resolved),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": content_sha256,
    }


def _cache_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@lru_cache(maxsize=8)
def _cache_source_digest(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        try:
            resolved = path.resolve()
            data = resolved.read_bytes()
        except OSError:
            continue
        digest.update(str(resolved).encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _case_insensitive_sibling_path(binary_path: Path, suffix: str) -> Path | None:
    direct = binary_path.with_suffix(suffix)
    if direct.exists():
        return direct
    parent = binary_path.parent
    try:
        siblings = sorted(parent.iterdir(), key=lambda path: path.name.lower())
    except OSError:
        return None
    wanted_stem = binary_path.stem.lower()
    wanted_suffix = suffix.lower()
    for sibling in siblings:
        if sibling.stem.lower() == wanted_stem and sibling.suffix.lower() == wanted_suffix:
            return sibling
    return None


def _cache_sidecar_fingerprints(binary_path: Path | None) -> dict[str, dict[str, object]]:
    if binary_path is None:
        return {}
    sidecars: dict[str, dict[str, object]] = {}
    for suffix in (".lst", ".map", ".cod", ".idc", ".inc"):
        sidecar_path = _case_insensitive_sibling_path(binary_path, suffix)
        fingerprint = _cache_file_fingerprint(sidecar_path)
        if fingerprint is not None:
            sidecars[suffix] = fingerprint
    return sidecars


def _cache_json_path(namespace: str, key: dict[str, object]) -> Path:
    encoded = json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return DECOMPILATION_CACHE_DIR / namespace / f"{_cache_sha256_bytes(encoded)}.json"


def _load_cache_json(namespace: str, key: dict[str, object]) -> dict[str, object] | None:
    path = _cache_json_path(namespace, key)
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _store_cache_json(namespace: str, key: dict[str, object], payload: dict[str, object]) -> dict[str, object] | None:
    path = _cache_json_path(namespace, key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True))
    except OSError:
        return None
    return None


def _function_decompilation_cache_key(
    *,
    binary_path: Path | None,
    function_addr: int,
    function_name: str | None,
    api_style: str,
    enable_structured_simplify: bool,
    enable_postprocess: bool,
) -> dict[str, object] | None:
    binary_fingerprint = _cache_file_fingerprint(binary_path)
    if binary_fingerprint is None:
        return None
    return {
        "schema": DECOMPILATION_CACHE_SCHEMA,
        "kind": "function_decompile",
        "binary": binary_fingerprint,
        "sidecars": _cache_sidecar_fingerprints(binary_path),
        "components": _cache_source_digest(DECOMPILATION_CACHE_SOURCE_FILES),
        "addr": function_addr,
        "function_name": function_name,
        "api_style": api_style,
        "structured_simplify": enable_structured_simplify,
        "postprocess": enable_postprocess,
    }


def _recovery_cache_key(
    *,
    binary_path: Path | None,
    kind: str,
    extra: dict[str, object] | None = None,
) -> dict[str, object] | None:
    binary_fingerprint = _cache_file_fingerprint(binary_path)
    if binary_fingerprint is None:
        return None
    payload = {
        "schema": DECOMPILATION_CACHE_SCHEMA,
        "kind": kind,
        "binary": binary_fingerprint,
        "sidecars": _cache_sidecar_fingerprints(binary_path),
        "components": _cache_source_digest(RECOVERY_CACHE_SOURCE_FILES),
    }
    if extra:
        payload.update(extra)
    return payload


def _sidecar_metadata_cache_key(
    *,
    binary_path: Path | None,
    kind: str,
    extra: dict[str, object] | None = None,
) -> dict[str, object] | None:
    binary_fingerprint = _cache_file_fingerprint(binary_path)
    if binary_fingerprint is None:
        return None
    payload = {
        "schema": DECOMPILATION_CACHE_SCHEMA,
        "kind": kind,
        "binary": binary_fingerprint,
        "sidecars": _cache_sidecar_fingerprints(binary_path),
        "components": _cache_source_digest(SIDECAR_METADATA_CACHE_SOURCE_FILES),
    }
    if extra:
        payload.update(extra)
    return payload
