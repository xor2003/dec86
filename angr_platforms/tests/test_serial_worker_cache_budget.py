"""Tests for monotonic serial clean-worker analysis-budget reuse."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import inertia_decompiler.cache as cache_module
import inertia_decompiler.serial_worker_cache as worker_cache
from inertia_decompiler.cache_runtime_contract import timing_diagnostics_requested_8616


def _inputs(binary: Path, *, timeout: int) -> worker_cache.SerialWorkerCacheInputs8616:
    return worker_cache.SerialWorkerCacheInputs8616(
        binary_path=binary,
        requested_addr=0x1000,
        recovery_addr=0x1000,
        timeout=timeout,
        window=0x200,
        base_addr=0x1000,
        entry_point=0x1000,
        c_target="portable-flat",
        api_style="modern",
        pat_backend="hyperscan",
        blob=False,
        signature_catalog=None,
        evidence_sha256="evidence",
        semantic_environment=(),
        result_schema=4,
    )


def _redirect_cache(monkeypatch, cache_dir: Path) -> None:
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", cache_dir)
    monkeypatch.setattr(worker_cache, "DECOMPILATION_CACHE_DIR", cache_dir)


def test_serial_worker_cache_key_excludes_analysis_budget(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    inputs = _inputs(binary, timeout=60)

    assert worker_cache.build_serial_worker_cache_key_8616(inputs) == (
        worker_cache.build_serial_worker_cache_key_8616(replace(inputs, timeout=240))
    )


def test_timing_diagnostics_disable_serial_worker_result_reuse(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """A timing request must execute the clean worker instead of cached C."""
    monkeypatch.setenv("INERTIA_DEBUG_TIMING", "true")

    result = worker_cache.load_serial_worker_cache_8616(
        _inputs(tmp_path / "timing.exe", timeout=60),
        enabled=True,
    )

    assert result.verdict is worker_cache.SerialWorkerCacheVerdict8616.DISABLED
    assert result.reason is worker_cache.SerialWorkerCacheReason8616.DIAGNOSTICS
    assert result.key is None


def test_disabled_timing_values_preserve_cache_reuse(monkeypatch) -> None:
    """Explicit false values must not request live timing diagnostics."""
    for value in ("", "0", "false", "FALSE", "no", "off", " Off "):
        monkeypatch.setenv("INERTIA_DEBUG_TIMING", value)
        assert not timing_diagnostics_requested_8616()


def test_serial_worker_cache_budget_reuse_is_monotonic(monkeypatch, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _redirect_cache(monkeypatch, cache_dir)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(
        worker_cache,
        "_validated_result_record_8616",
        lambda record, **_kwargs: dict(record),
    )
    inputs = _inputs(binary, timeout=60)
    miss = worker_cache.load_serial_worker_cache_8616(inputs, enabled=True)

    assert worker_cache.store_serial_worker_cache_8616(miss, {"payload": "medium"}, result_schema=4)
    weaker = worker_cache.load_serial_worker_cache_8616(replace(inputs, timeout=30), enabled=True)
    stronger = worker_cache.load_serial_worker_cache_8616(replace(inputs, timeout=120), enabled=True)

    assert weaker.verdict is worker_cache.SerialWorkerCacheVerdict8616.HIT
    assert weaker.record == {"payload": "medium"}
    assert stronger.verdict is worker_cache.SerialWorkerCacheVerdict8616.MISS
    assert stronger.reason is worker_cache.SerialWorkerCacheReason8616.INSUFFICIENT_ANALYSIS_BUDGET


def test_stronger_serial_worker_result_cannot_be_downgraded(monkeypatch, tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    _redirect_cache(monkeypatch, cache_dir)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(
        worker_cache,
        "_validated_result_record_8616",
        lambda record, **_kwargs: dict(record),
    )
    inputs = _inputs(binary, timeout=60)
    initial = worker_cache.load_serial_worker_cache_8616(inputs, enabled=True)
    assert worker_cache.store_serial_worker_cache_8616(initial, {"payload": "medium"}, result_schema=4)

    stronger_inputs = replace(inputs, timeout=120)
    stronger = worker_cache.load_serial_worker_cache_8616(stronger_inputs, enabled=True)
    assert worker_cache.store_serial_worker_cache_8616(stronger, {"payload": "strong"}, result_schema=4)

    weaker_lookup = worker_cache.SerialWorkerCacheLookup8616(
        worker_cache.SerialWorkerCacheVerdict8616.MISS,
        stronger.key,
        None,
        worker_cache.SerialWorkerCacheReason8616.NOT_FOUND,
        30,
    )
    assert worker_cache.store_serial_worker_cache_8616(weaker_lookup, {"payload": "weak"}, result_schema=4)
    key = worker_cache.build_serial_worker_cache_key_8616(inputs)
    assert key is not None
    stored_path = cache_module._cache_json_path(worker_cache.SERIAL_WORKER_CACHE_NAMESPACE_8616, key)
    stored = json.loads(stored_path.read_text(encoding="utf-8"))

    assert stored["payload"] == "strong"
    assert stored[worker_cache.SERIAL_WORKER_CACHE_ANALYSIS_TIMEOUT_FIELD_8616] == 120
