from __future__ import annotations

from types import SimpleNamespace

import pytest

import decompile
import inertia_decompiler.cli_core as cli_core
import inertia_decompiler.cli_function_discovery as discovery
from inertia_decompiler.cli_arg_parser import parse_cli_arguments
from inertia_decompiler.cli_function_discovery import DisplayCatalogCachePolicy8616


def _policy(**overrides):
    fields = dict(
        ignore_local_sidecar_hints=False,
        include_library_functions=False,
        function_discovery_backend="auto",
        pat_backend="auto",
        max_functions=0,
        timeout=60,
        window=0x200,
        rizin_timeout=8,
        low_memory=False,
        auto_rizin_policy="default",
        signature_catalog=None,
    )
    fields.update(overrides)
    return DisplayCatalogCachePolicy8616.from_runtime(**fields)


def test_catalog_timeout_option_parses_from_flag_and_environment(monkeypatch):
    monkeypatch.delenv("INERTIA_CATALOG_TIMEOUT", raising=False)
    assert parse_cli_arguments(["x.exe"]).catalog_timeout is None
    assert parse_cli_arguments(["x.exe", "--catalog-timeout", "120"]).catalog_timeout == 120

    monkeypatch.setenv("INERTIA_CATALOG_TIMEOUT", "45")
    assert parse_cli_arguments(["x.exe"]).catalog_timeout == 45
    assert parse_cli_arguments(["x.exe", "--catalog-timeout", "9"]).catalog_timeout == 9

    monkeypatch.setenv("INERTIA_CATALOG_TIMEOUT", "soon")
    assert parse_cli_arguments(["x.exe"]).catalog_timeout is None


def test_catalog_budget_keeps_the_legacy_auto_rule_when_unset(monkeypatch):
    monkeypatch.delenv("INERTIA_CATALOG_TIMEOUT", raising=False)
    auto_default = parse_cli_arguments(["x.exe"])
    auto_short = parse_cli_arguments(["x.exe", "--timeout", "6"])
    explicit = parse_cli_arguments(["x.exe", "--timeout", "6", "--catalog-timeout", "300"])

    assert cli_core._catalog_budget_seconds_8616(auto_default) == 8
    assert cli_core._catalog_budget_seconds_8616(auto_short) == 6
    assert cli_core._catalog_guard_seconds_8616(auto_short) == 8
    assert cli_core._catalog_supplement_seconds_8616(auto_default) == 8

    assert cli_core._catalog_budget_seconds_8616(explicit) == 300
    assert cli_core._catalog_guard_seconds_8616(explicit) == 302
    assert cli_core._catalog_supplement_seconds_8616(explicit) == 300


def test_display_catalog_cache_key_isolates_explicit_catalog_budgets():
    default_policy = _policy()
    explicit_policy = _policy(catalog_timeout=300)

    assert default_policy.cache_fields()["schema"] == 3
    assert default_policy.cache_fields()["catalog_timeout"] is None
    assert explicit_policy.cache_fields()["catalog_timeout"] == 300
    assert default_policy.cache_fields() != explicit_policy.cache_fields()
    assert _policy(catalog_timeout=0).catalog_timeout == 1


def test_fast_exe_catalog_forwards_the_explicit_budget_to_seed_recovery(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), entry=0x10000)
    seen: dict[str, int] = {}

    monkeypatch.setattr(discovery, "_rank_pre_entry_source_function_seeds_8616", lambda _project: [])
    monkeypatch.setattr(discovery, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: None)

    def _fake_seeds(_project, *, timeout, limit):
        seen["timeout"] = timeout
        seen["limit"] = limit
        return []

    monkeypatch.setattr(discovery, "_recover_fast_seed_functions", _fake_seeds)

    discovery._recover_fast_exe_catalog(project, timeout=60, window=0x200, low_memory=False, limit=None)
    assert seen == {"timeout": 8, "limit": None}

    discovery._recover_fast_exe_catalog(project, timeout=60, window=0x200, low_memory=False, limit=None, catalog_timeout=300)
    assert seen == {"timeout": 300, "limit": None}


def _fake_ok_result(item):
    return decompile.FunctionWorkResult(
        index=item.index,
        status="ok",
        payload=f"int {item.function.name}(void) {{ return 0; }}",
        debug_output="",
        byte_count=1,
        elapsed=0.01,
        function=item.function,
        function_cfg=item.function_cfg,
        tail_validation={
            "structuring": {"status": "stable", "changed": False},
            "postprocess": {"status": "stable", "changed": False},
        },
    )


@pytest.mark.parametrize("catalog_args", [(), ("--catalog-timeout", "12")])
def test_main_reports_a_truncated_quick_catalog_honestly(monkeypatch, tmp_path, capsys, catalog_args):
    monkeypatch.setenv("INERTIA_ENABLE_SERIAL_FORK_PER_FUNCTION", "0")
    monkeypatch.setenv("INERTIA_MSC_DOS_CHECK", "optional")
    monkeypatch.delenv("INERTIA_CATALOG_TIMEOUT", raising=False)
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(
        entry=0x10000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=binary, linked_base=0x10000, max_addr=0x400)),
    )
    candidates = [0x10010 + index * 0x10 for index in range(5)]  # none equal to linked_base, which the CLI drops
    recovered_pairs = [
        (SimpleNamespace(), SimpleNamespace(addr=addr, name=f"sub_{addr:x}", project=project)) for addr in candidates[:2]
    ]
    seen_budgets: list[int] = []

    def _fake_catalog(_project, *, timeout, window, low_memory, limit, catalog_timeout=None):
        seen_budgets.append(timeout if catalog_timeout is None else catalog_timeout)
        return list(recovered_pairs)

    monkeypatch.setattr(decompile, "_build_project", lambda *_args, **_kwargs: project)
    monkeypatch.setattr(decompile, "_load_lst_metadata", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_apply_binary_specific_annotations", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_prefer_low_memory_path", lambda: False)
    monkeypatch.setattr(decompile, "_discover_ranked_binary_offsets", lambda _project, *, args: list(candidates))
    monkeypatch.setattr(decompile, "_load_catalog_address_cache", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "_recover_fast_exe_catalog", _fake_catalog)
    monkeypatch.setattr(decompile, "_store_catalog_address_cache", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "_choose_function_parallelism", lambda _count: 1)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_fork", lambda fn, *, timeout: fn())
    monkeypatch.setattr(decompile, "_run_function_work_item", lambda item, **_kwargs: _fake_ok_result(item))

    rc = decompile.main([str(binary), "--timeout", "4", *catalog_args])
    out = capsys.readouterr().out

    expected_budget = 12 if catalog_args else 4
    assert rc == 0, out
    assert seen_budgets == [expected_budget]
    assert "/* functions queued for decompilation: 5 */" in out
    assert (
        f"/* quick catalog covered 2 of 5 direct-binary function candidates within its {expected_budget}s budget; "
        "the remaining candidates are not queued. Raise --catalog-timeout (INERTIA_CATALOG_TIMEOUT) to recover more. */"
    ) in out
    assert "/* info: selected 2 function(s) for decompilation */" in out
    assert "summary: decompiled 2/2 selected functions" in out
