"""Cache complete MS C runtime-gate artifacts without caching test verdicts.

Layer: Tooling/gates.
Responsibility: reuse source-bound decompile/recompile/run evidence after
verifying every persisted artifact, while leaving acceptance to test assertions.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator, Protocol, TypeAlias

from scripts.pytest_source_state import source_tree_snapshot

_CACHE_SCHEMA = 1
_SEMANTIC_ENV_PREFIX = "INERTIA_"
_NON_SEMANTIC_ENV_NAMES = frozenset({"INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS"})


class _Digest(Protocol):
    """Minimal hash interface used by deterministic cache-key builders."""

    def update(self, data: bytes) -> None:
        """Consume bytes in cache-key order."""

    def hexdigest(self) -> str:
        """Return the completed lowercase hexadecimal digest."""


GateProcessResult: TypeAlias = subprocess.CompletedProcess[str] | subprocess.TimeoutExpired | None


@dataclass(frozen=True, slots=True)
class MSC6RuntimeGateInputs:
    """Exact tools, examples, and policy needed by one complete runtime gate."""

    repo_root: Path
    cache_root: Path
    fallback_output_root: Path
    runtime_gate_path: Path
    kvikdos_path: Path
    msc6_root: Path
    examples: tuple[tuple[str, Path], ...]
    expected_exit_code: int = 255
    timeout_seconds: int = 60


@dataclass(frozen=True, slots=True)
class MSC6RuntimeGateArtifacts:
    """Current assertions' process facts and immutable artifact directory."""

    results: dict[str, GateProcessResult]
    output_root: Path
    cache_hit: bool


def _digest_field(digest: _Digest, label: str, value: str) -> None:
    """Append one unambiguous labeled field to a cache-key digest."""
    digest.update(label.encode("utf-8"))
    digest.update(b"\0")
    digest.update(value.encode("utf-8"))
    digest.update(b"\0")


def _digest_path(digest: _Digest, label: str, path: Path) -> None:
    """Append one file or recursive directory tree by path and content."""
    _digest_field(digest, f"{label}:path", str(path.resolve(strict=False)))
    if not path.exists():
        _digest_field(digest, f"{label}:state", "missing")
        return
    files = (path,) if path.is_file() else tuple(item for item in sorted(path.rglob("*")) if item.is_file())
    for item in files:
        relative = item.name if path.is_file() else item.relative_to(path).as_posix()
        _digest_field(digest, f"{label}:file", relative)
        digest.update(item.read_bytes())
        digest.update(b"\0")


def _cache_key(inputs: MSC6RuntimeGateInputs) -> str | None:
    """Return an exact stable key, or refuse caching during source mutation."""
    source = source_tree_snapshot(inputs.repo_root)
    if source.unstable_paths:
        return None
    digest = hashlib.sha256()
    _digest_field(digest, "schema", str(_CACHE_SCHEMA))
    _digest_field(digest, "source", source.sha256)
    _digest_field(digest, "python", sys.version)
    _digest_field(digest, "expected_exit", str(inputs.expected_exit_code))
    _digest_path(digest, "runtime_gate", inputs.runtime_gate_path)
    _digest_path(digest, "kvikdos", inputs.kvikdos_path)
    _digest_path(digest, "msc6", inputs.msc6_root)
    for name, executable in inputs.examples:
        _digest_field(digest, "example", name)
        for suffix in (".EXE", ".COD", ".MAP", ".C"):
            _digest_path(digest, f"example:{name}:{suffix}", executable.with_suffix(suffix))
    semantic_environment = {
        name: value
        for name, value in os.environ.items()
        if name.startswith(_SEMANTIC_ENV_PREFIX) and name not in _NON_SEMANTIC_ENV_NAMES
    }
    for name, value in sorted(semantic_environment.items()):
        _digest_field(digest, f"env:{name}", value)
    return digest.hexdigest()


@contextmanager
def _cache_lock(path: Path) -> Iterator[None]:
    """Serialize producers with a crash-released advisory file lock."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        typed_stream: IO[bytes] = stream
        fcntl.flock(typed_stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(typed_stream.fileno(), fcntl.LOCK_UN)


def _artifact_hashes(output_root: Path) -> dict[str, str]:
    """Hash every persisted gate artifact except the cache manifest itself."""
    return {
        path.relative_to(output_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(output_root.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }


def _result_is_accepted(result: GateProcessResult, expected_exit_code: int) -> bool:
    """Return whether process facts are eligible for persistence."""
    if not isinstance(result, subprocess.CompletedProcess) or result.returncode != 0:
        return False
    combined = f"{result.stderr}\n{result.stdout}"
    return "status=passed" in combined and f"run_exit={expected_exit_code}" in combined


def _load_cache(
    output_root: Path,
    cache_key: str,
    example_names: tuple[str, ...],
    expected_exit_code: int,
) -> MSC6RuntimeGateArtifacts | None:
    """Load one cache entry only after schema, result, and content verification."""
    manifest_path = output_root / "manifest.json"
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != _CACHE_SCHEMA or payload.get("key") != cache_key:
        return None
    raw_results = payload.get("results")
    raw_hashes = payload.get("artifact_sha256")
    if not isinstance(raw_results, dict) or set(raw_results) != set(example_names):
        return None
    if not isinstance(raw_hashes, dict) or not raw_hashes:
        return None
    if not all(isinstance(path, str) and isinstance(value, str) for path, value in raw_hashes.items()):
        return None
    for relative_path, expected_hash in raw_hashes.items():
        artifact_path = output_root / relative_path
        try:
            actual_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        except OSError:
            return None
        if actual_hash != expected_hash:
            return None
    results: dict[str, GateProcessResult] = {}
    for name in example_names:
        record = raw_results.get(name)
        if not isinstance(record, dict):
            return None
        arguments = record.get("args")
        returncode = record.get("returncode")
        stdout = record.get("stdout")
        stderr = record.get("stderr")
        if not isinstance(arguments, list) or not all(isinstance(value, str) for value in arguments):
            return None
        if not isinstance(returncode, int) or not isinstance(stdout, str) or not isinstance(stderr, str):
            return None
        result = subprocess.CompletedProcess(arguments, returncode, stdout, stderr)
        if not _result_is_accepted(result, expected_exit_code):
            return None
        results[name] = result
    return MSC6RuntimeGateArtifacts(results=results, output_root=output_root, cache_hit=True)


def _run_example(
    item: tuple[str, Path],
    inputs: MSC6RuntimeGateInputs,
    output_root: Path,
) -> tuple[str, GateProcessResult]:
    """Run one complete example gate in its own controller subprocess."""
    example_name, executable = item
    if not executable.is_file():
        return example_name, None
    command = [
        sys.executable,
        str(inputs.runtime_gate_path),
        "--example",
        example_name,
        "--expected-exit-code",
        str(inputs.expected_exit_code),
        "--timeout",
        str(inputs.timeout_seconds),
        "--out-dir",
        str(output_root / f"{example_name}_runtime_gate"),
        "--clean",
    ]
    try:
        result: GateProcessResult = subprocess.run(
            command,
            cwd=inputs.repo_root,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        result = exc
    return example_name, result


def _run_all(inputs: MSC6RuntimeGateInputs, output_root: Path) -> dict[str, GateProcessResult]:
    """Run all examples with the established two-controller memory bound."""
    with ThreadPoolExecutor(max_workers=2) as executor:
        return dict(executor.map(lambda item: _run_example(item, inputs, output_root), inputs.examples))


def _store_manifest(
    output_root: Path,
    cache_key: str,
    results: dict[str, GateProcessResult],
) -> None:
    """Publish accepted process facts after every output artifact is durable."""
    serialized_results: dict[str, object] = {}
    for name, result in sorted(results.items()):
        if not isinstance(result, subprocess.CompletedProcess):
            raise ValueError(f"cannot cache incomplete runtime-gate result: {name}")
        serialized_results[name] = {
            "args": [str(value) for value in result.args],
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    payload: dict[str, object] = {
        "schema": _CACHE_SCHEMA,
        "key": cache_key,
        "results": serialized_results,
        "artifact_sha256": _artifact_hashes(output_root),
    }
    manifest_path = output_root / "manifest.json"
    temporary_path = output_root / f"manifest.json.tmp-{os.getpid()}"
    temporary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary_path.replace(manifest_path)


def load_or_run_msc6_runtime_gate(inputs: MSC6RuntimeGateInputs) -> MSC6RuntimeGateArtifacts:
    """Reuse verified evidence or produce one complete source-bound gate entry."""
    cache_key = _cache_key(inputs)
    if cache_key is None:
        shutil.rmtree(inputs.fallback_output_root, ignore_errors=True)
        inputs.fallback_output_root.mkdir(parents=True)
        results = _run_all(inputs, inputs.fallback_output_root)
        return MSC6RuntimeGateArtifacts(results, inputs.fallback_output_root, False)

    output_root = inputs.cache_root / cache_key
    with _cache_lock(inputs.cache_root / f"{cache_key}.lock"):
        cached = _load_cache(
            output_root,
            cache_key,
            tuple(name for name, _executable in inputs.examples),
            inputs.expected_exit_code,
        )
        if cached is not None:
            return cached
        shutil.rmtree(output_root, ignore_errors=True)
        output_root.mkdir(parents=True)
        results = _run_all(inputs, output_root)
        if all(_result_is_accepted(result, inputs.expected_exit_code) for result in results.values()):
            _store_manifest(output_root, cache_key, results)
        return MSC6RuntimeGateArtifacts(results, output_root, False)
