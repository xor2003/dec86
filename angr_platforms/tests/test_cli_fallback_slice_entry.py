from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler import cli_fallback_decompilation
from inertia_decompiler.x86_16_exact_slice import function_original_addr


def test_sidecar_slice_rebases_proven_entry_inside_padded_region(monkeypatch) -> None:
    region_start = 0x102CC
    semantic_entry = 0x102E0
    region_end = 0x10491
    code = b"\x90" * (semantic_entry - region_start) + b"\x55" * (region_end - semantic_entry)
    observed: dict[str, object] = {}

    def load(addr: int, size: int) -> bytes:
        observed["load"] = (addr, size)
        return code

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=load)),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={semantic_entry: "RunMenu"},
        code_ranges={region_start: (region_start, region_end)},
        absolute_addrs=True,
        source_format="cod_listing",
    )
    slice_project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(addr=0x1014, name="sub_1014", info={}, project=slice_project)

    def build_slice_project(
        slice_code: bytes,
        *,
        base_addr: int,
        entry_point: int,
    ) -> SimpleNamespace:
        observed["build"] = (len(slice_code), base_addr, entry_point)
        return slice_project

    def pick_lean(
        _slice_project: object,
        addr: int,
        *,
        regions: list[tuple[int, int]],
        **_kwargs: object,
    ) -> tuple[object, object]:
        observed["recover"] = (addr, regions)
        return SimpleNamespace(), function

    monkeypatch.setattr(cli_fallback_decompilation, "_build_project_from_bytes", build_slice_project)
    monkeypatch.setattr(cli_fallback_decompilation, "_pick_function_lean", pick_lean)
    monkeypatch.setattr(
        cli_fallback_decompilation,
        "_call_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "void RunMenu(void)\n{\n}\n", None, 1, 1, 0.01),
    )
    monkeypatch.setattr(
        cli_fallback_decompilation,
        "assess_decompiled_c_text",
        lambda _payload: SimpleNamespace(reject_as_decompiled=False),
    )
    monkeypatch.setattr(
        cli_fallback_decompilation,
        "_tail_validation_snapshot_for_function_run",
        lambda *_args: {},
    )
    monkeypatch.setattr(cli_fallback_decompilation, "_inherit_tail_validation_runtime_policy", lambda *_args: None)
    monkeypatch.setattr(cli_fallback_decompilation, "transfer_project_evidence_8616", lambda *_args: None)
    monkeypatch.setattr(
        cli_fallback_decompilation,
        "_run_with_timeout_in_daemon_thread",
        lambda job, **_kwargs: job(),
    )

    result = cli_fallback_decompilation._try_decompile_sidecar_slice(
        project,
        metadata,
        semantic_entry,
        "RunMenu",
        timeout=6,
        api_style="default",
        binary_path=None,
    )

    assert result is not None
    assert result.status == "ok"
    assert observed["load"] == (region_start, region_end - region_start)
    assert observed["build"] == (region_end - region_start, 0x1000, 0x1014)
    assert observed["recover"] == (0x1014, [(0x1000, 0x11C5)])
    assert slice_project._inertia_original_linear_delta == region_start - 0x1000
    assert function_original_addr(function) == semantic_entry
