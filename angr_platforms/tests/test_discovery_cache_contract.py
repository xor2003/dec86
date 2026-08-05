from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    caller_return_use_evidence_by_addr_8616,
    record_caller_return_use_evidence_8616,
)

import inertia_decompiler.cache as recovery_cache
from inertia_decompiler.cli_function_discovery import (
    DisplayCatalogCachePolicy8616,
    SourceRegionCatalogEvidence8616,
    _configure_display_catalog_cache_policy_8616,
    _load_catalog_address_cache,
    _source_region_catalog_evidence_8616,
    _store_catalog_address_cache,
)
from inertia_decompiler.discovery_cache_contract import (
    caller_return_use_evidence_record_8616,
    display_catalog_cache_payload_from_record_8616,
    display_catalog_cache_record_8616,
)


def _cache_policy() -> DisplayCatalogCachePolicy8616:
    return DisplayCatalogCachePolicy8616.from_runtime(
        ignore_local_sidecar_hints=False,
        include_library_functions=False,
        function_discovery_backend="auto",
        pat_backend="auto",
        max_functions=0,
        timeout=8,
        window=0x400,
        rizin_timeout=8,
        low_memory=False,
        auto_rizin_policy="default",
        signature_catalog=None,
    )


def _return_use_evidence() -> CallerReturnUseEvidence8616:
    return CallerReturnUseEvidence8616(
        target_addr=0x10560,
        verdict=CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x1010, 0x1040),
        excluded_callsite_count=1,
    )


def _evidence_digest(project: object) -> str:
    records = [
        {
            "function_addr": addr,
            "evidence": caller_return_use_evidence_record_8616(evidence),
        }
        for addr, evidence in sorted(caller_return_use_evidence_by_addr_8616(project).items())
    ]
    return hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()


def test_display_catalog_cache_restores_exact_discovery_evidence(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    destination_project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    pair = (SimpleNamespace(), SimpleNamespace(addr=0x10560))
    source_region = SourceRegionCatalogEvidence8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        failed_addrs=(),
    )
    evidence = _return_use_evidence()
    record_caller_return_use_evidence_8616(source_project, evidence.target_addr, evidence)
    source_project._inertia_source_region_catalog_evidence = source_region
    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "discovery-digest")
    _configure_display_catalog_cache_policy_8616(source_project, _cache_policy())
    _configure_display_catalog_cache_policy_8616(destination_project, _cache_policy())

    _store_catalog_address_cache(source_project, binary, [pair])

    assert _load_catalog_address_cache(destination_project, binary) == [0x10560]
    assert caller_return_use_evidence_by_addr_8616(destination_project) == {0x10560: evidence}
    assert _source_region_catalog_evidence_8616(destination_project) == source_region
    assert _evidence_digest(destination_project) == _evidence_digest(source_project)


def test_display_catalog_cache_refuses_legacy_address_only_payload(monkeypatch, tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(entry=0x1100, arch=SimpleNamespace(name="86_16"))
    monkeypatch.setattr(recovery_cache, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(recovery_cache, "_cache_source_digest", lambda _paths: "discovery-digest")
    _configure_display_catalog_cache_policy_8616(project, _cache_policy())
    from inertia_decompiler.cli_function_discovery import _catalog_address_cache_key_8616

    cache_key = _catalog_address_cache_key_8616(project, binary)
    assert cache_key is not None
    recovery_cache._store_cache_json("recovery", cache_key, {"addrs": [0x10560]})

    assert _load_catalog_address_cache(project, binary) == []
    assert caller_return_use_evidence_by_addr_8616(project) == {}


def test_display_catalog_cache_refuses_unclosed_caller_evidence():
    evidence = _return_use_evidence()
    record = display_catalog_cache_record_8616((0x10560,), {0x10560: evidence}, None)
    caller_records = record["caller_return_use"]
    assert isinstance(caller_records, list)
    evidence_record = caller_records[0]["evidence"]
    assert isinstance(evidence_record, dict)
    evidence_record["unused_callsite_count"] = 0

    with pytest.raises(ValueError, match="classifications do not close"):
        display_catalog_cache_payload_from_record_8616(record)


def test_display_catalog_cache_refuses_unmaterialized_classified_evidence():
    evidence = _return_use_evidence()
    record = display_catalog_cache_record_8616((0x10560,), {0x10560: evidence}, None)
    caller_records = record["caller_return_use"]
    assert isinstance(caller_records, list)
    evidence_record = caller_records[0]["evidence"]
    assert isinstance(evidence_record, dict)
    evidence_record["materialized_count"] = 0

    with pytest.raises(ValueError, match="materialized facts do not close"):
        display_catalog_cache_payload_from_record_8616(record)
