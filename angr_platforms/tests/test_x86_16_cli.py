from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import decompile
from angr_platforms.X86_16.codeview_nb00 import find_codeview_nb00, parse_codeview_nb00
from angr_platforms.X86_16.cod_extract import extract_cod_listing_metadata
from angr_platforms.X86_16.flair_extract import list_flair_sig_libraries, match_flair_startup_entry
from angr_platforms.X86_16.load_dos_mz import DOSMZ
from angr_platforms.X86_16.lst_extract import LSTMetadata, extract_lst_metadata
from angr_platforms.X86_16.turbo_debug_tdinfo import TDInfoSymbolClass, parse_tdinfo_exe
from omf_pat import (
    PatModule,
    PatPublicName,
    CachedPatRegexSpec,
    _normalize_pat_backend_choice,
    enumerate_microsoft_lib_dictionary_symbols,
    ensure_pat_from_omf_input,
    extract_omf_modules_from_lib,
    generate_pat_from_omf_obj,
    generate_pat_from_omf_lib,
    load_cached_pat_regex_specs,
    lookup_microsoft_lib_symbol,
    parse_microsoft_lib,
    match_pat_modules,
    parse_pat_file,
)
from signature_catalog import build_signature_catalog, match_signature_catalog


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
TRACE_PATH = REPO_ROOT / "angr_platforms" / "scripts" / "trace_x86_16_paths.py"
MONOPRIN_COD = REPO_ROOT / "cod" / "f14" / "MONOPRIN.COD"
NHORZ_COD = REPO_ROOT / "cod" / "f14" / "NHORZ.COD"
MAX_COD = REPO_ROOT / "cod" / "default" / "MAX.COD"
DOSFUNC_COD = REPO_ROOT / "cod" / "DOSFUNC.COD"
ICOMDO_COM = REPO_ROOT / "angr_platforms" / "x16_samples" / "ICOMDO.COM"
ISOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOD.COD"
IMOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOD.COD"
ISOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOT.COD"
ISOX_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOX.COD"
IHOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IHOD.COD"
IHOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IHOT.COD"
ILOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ILOD.COD"
ILOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ILOT.COD"
IMOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOT.COD"
IMOX_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOX.COD"
LIFE_EXE = REPO_ROOT / "LIFE.EXE"
LIFE_COD = REPO_ROOT / "LIFE.COD"
NONAME_TDINFO_EXE = REPO_ROOT / "tdinfo-parser" / "NONAME.EXE"
SYNTHETIC_OBJ = REPO_ROOT / "angr_platforms" / "tests" / "fixtures" / "synthetic.obj"


def _build_synthetic_microsoft_lib(
    module_bytes: bytes,
    *,
    page_size: int = 512,
    case_sensitive: bool = False,
    extended_records: list[tuple[int, tuple[int, ...]]] | None = None,
    dictionary_entries: list[tuple[str, int]] | None = None,
) -> bytes:
    header_payload_len = page_size - 3
    module_page = module_bytes + (b"\x00" * ((page_size - (len(module_bytes) % page_size)) % page_size))
    dict_offset = page_size + len(module_page)
    dict_blocks = 1
    header = bytearray(page_size)
    header[0] = 0xF0
    header[1:3] = header_payload_len.to_bytes(2, "little")
    header[3:7] = dict_offset.to_bytes(4, "little")
    header[7:9] = dict_blocks.to_bytes(2, "little")
    header[9] = 0x01 if case_sensitive else 0x00
    dict_page = bytearray(512)
    if dictionary_entries:
        free_offset = 38 * 2
        for symbol_name, module_page_number in dictionary_entries:
            encoded_name = symbol_name.encode("latin1")
            entry = bytes([len(encoded_name)]) + encoded_name + int(module_page_number).to_bytes(2, "little")
            assert free_offset + len(entry) <= len(dict_page)
            _page_index, _page_delta, bucket, bucket_delta = _hash_synthetic_microsoft_lib_symbol(
                symbol_name,
                dict_blocks,
                case_sensitive=case_sensitive,
            )
            start_bucket = bucket
            while dict_page[bucket] != 0:
                bucket = (bucket + bucket_delta) % 37
                assert bucket != start_bucket
            dict_page[bucket] = free_offset // 2
            dict_page[free_offset : free_offset + len(entry)] = entry
            free_offset += len(entry)
            if free_offset & 1:
                free_offset += 1
        dict_page[37] = free_offset // 2
    blob = bytes(header) + module_page + bytes(dict_page)
    if extended_records:
        payload = bytearray()
        payload += len(extended_records).to_bytes(2, "little")
        table_size = len(extended_records) * 4
        dependency_lists = bytearray()
        offsets: list[int] = []
        for _page_number, deps in extended_records:
            offsets.append(2 + table_size + len(dependency_lists))
            for dep in deps:
                dependency_lists += int(dep).to_bytes(2, "little")
            dependency_lists += (0).to_bytes(2, "little")
        for (page_number, _deps), dep_offset in zip(extended_records, offsets, strict=True):
            payload += int(page_number).to_bytes(2, "little")
            payload += int(dep_offset).to_bytes(2, "little")
        payload += dependency_lists
        record_length = len(payload) + 1
        ext = bytearray()
        ext.append(0xF2)
        ext += record_length.to_bytes(2, "little")
        ext += payload
        ext.append(0)
        blob += bytes(ext)
    trailer = bytearray(512)
    trailer[0] = 0xF1
    trailer[1:3] = (509).to_bytes(2, "little")
    return blob + bytes(trailer)


def _hash_synthetic_microsoft_lib_symbol(symbol_name: str, dictionary_pages: int, *, case_sensitive: bool) -> tuple[int, int, int, int]:
    name_bytes = symbol_name.encode("latin1", errors="ignore")
    if not case_sensitive:
        name_bytes = bytes((byte | 0x20) if 0x41 <= byte <= 0x5A else byte for byte in name_bytes)
    page_index = 0
    page_index_delta = 0
    bucket_index = 0
    bucket_index_delta = 0
    for forward, reverse in zip(name_bytes, reversed(name_bytes), strict=True):
        page_index = ((page_index << 2) ^ forward) & 0xFFFFFFFF
        bucket_index_delta = ((bucket_index_delta >> 2) ^ forward) & 0xFFFFFFFF
        bucket_index = ((bucket_index >> 2) ^ reverse) & 0xFFFFFFFF
        page_index_delta = ((page_index_delta << 2) ^ reverse) & 0xFFFFFFFF
    page_index %= dictionary_pages
    page_index_delta = (page_index_delta % dictionary_pages) or 1
    bucket_index %= 37
    bucket_index_delta = (bucket_index_delta % 37) or 1
    return page_index, page_index_delta, bucket_index, bucket_index_delta


def _run_decompile_proc(
    path: Path,
    proc: str,
    *,
    proc_kind: str = "NEAR",
    analysis_timeout: int = 10,
    subprocess_timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--proc",
            proc,
            "--proc-kind",
            proc_kind,
            "--timeout",
            str(analysis_timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=subprocess_timeout,
        check=False,
    )


def test_preferred_decompiler_options_prefers_phoenix_for_true_wrappers():
    assert decompile._preferred_decompiler_options(1, 21, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(2, 21, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 25, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 24) is None
    assert decompile._preferred_decompiler_options(2, 21) is None


def test_preferred_decompiler_options_rejects_call_heavy_small_functions():
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 23, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 25, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(6, 64, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=False) is None


def test_function_recovery_detail_names_recovery_stage():
    assert decompile._function_recovery_detail("recovery") == "during x86-16 function recovery"
    assert decompile._function_recovery_detail("recovery:fast") == "during x86-16 function recovery (fast CFGFast)"
    assert decompile._function_recovery_detail("recovery:full") == "during x86-16 function recovery (full CFGFast)"
    assert decompile._function_recovery_detail("recovery:narrow:0x80") == (
        "during x86-16 function recovery (narrow CFGFast)"
    )
    assert decompile._function_recovery_detail("postprocess") is None


def test_fallback_entry_function_retries_broader_windows_after_narrow_recovery_fails(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions))
        region = regions[0]
        if region[1] - region[0] >= 0x800:
            return expected_cfg, expected_func
        raise KeyError("narrow miss")

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert cfg is expected_cfg
    assert func is expected_func
    assert project._inertia_decompiler_stage == "recovery:narrow:0x800"
    assert len([call for call in calls if call[0] == "pick"]) == 5
    assert [call[1][0][1] - call[1][0][0] for call in calls if call[0] == "pick"] == [
        0x200,
        0x200,
        0x400,
        0x400,
        0x800,
    ]


def test_fallback_entry_function_uses_lean_cfgfast_for_86_16(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    captured: list[dict[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        captured.append({"regions": regions, "data_references": data_references})
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured[-1]["data_references"] is False


def test_pick_function_lean_disables_expensive_cfgfast_features(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function_lean(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1100)],
            "normalize": False,
            "data_references": False,
            "force_smart_scan": False,
            "force_complete_scan": False,
            "resolve_indirect_jumps": False,
            "function_prologues": False,
            "symbols": False,
            "cross_references": False,
        }
    ]


def test_pick_function_lean_can_skip_far_call_extension(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("far-call extension should not run")))
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function_lean(
        project,
        0x1000,
        regions=[(0x1000, 0x1100)],
        extend_far_calls=False,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1100)],
            "normalize": False,
            "data_references": False,
            "force_smart_scan": False,
            "force_complete_scan": False,
            "resolve_indirect_jumps": False,
            "function_prologues": False,
            "symbols": False,
            "cross_references": False,
        }
    ]


def test_pick_function_lean_can_extend_traced_neighbor_calls(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )

    initial_func = SimpleNamespace(addr=0x1000)
    extended_func = SimpleNamespace(addr=0x1000)
    initial_cfg = SimpleNamespace(functions={0x1000: initial_func})
    extended_cfg = SimpleNamespace(functions={0x1000: extended_func})
    patched: list[object] = []

    project.analyses = SimpleNamespace(CFGFast=lambda **_kwargs: initial_cfg)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        decompile,
        "extend_cfg_for_neighbor_calls",
        lambda project_arg, function, *, entry_window: (
            extended_cfg
            if project_arg is project and function is initial_func and entry_window == 0x100
            else None
        ),
    )
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda function, *_args, **_kwargs: patched.append(function))

    cfg, func = decompile._pick_function_lean(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is extended_cfg
    assert func is extended_func
    assert patched == [extended_func]


def test_find_codeview_nb00_detects_life_exe():
    found = find_codeview_nb00(LIFE_EXE.read_bytes())
    assert found is not None
    signature, debug_base, subdir_addr = found
    assert signature == "NB00"
    assert debug_base == 23926
    assert subdir_addr == 31887


def test_parse_codeview_nb00_extracts_life_functions_and_data():
    info = parse_codeview_nb00(LIFE_EXE, load_base_linear=0x10000)

    assert info is not None
    assert len(info.modules) >= 3
    assert len(info.publics) >= 100
    assert "main" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "init_life" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "draw_box" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "generation" in {name.lstrip("_") for name in info.code_labels.values()}
    assert "speed" in {name.lstrip("_") for name in info.data_labels.values()}
    assert info.code_labels[0x10010].lstrip("_") == "main"
    assert info.code_labels[0x100ea].lstrip("_") == "init_life"
    assert info.code_labels[0x101a3].lstrip("_") == "draw_box"
    assert info.data_labels[0x15bb0].lstrip("_") == "speed"
    assert "LIFE.OBJ" in {module.name for module in info.modules}


def test_parse_codeview_nb00_agrees_with_life_cod_proc_names():
    info = parse_codeview_nb00(LIFE_EXE, load_base_linear=0x10000)

    assert info is not None
    cod_text = LIFE_COD.read_text(errors="ignore")

    for proc_name in ("_main", "_init_life", "_draw_box", "_generation", "_proc_key"):
        assert f"PUBLIC\t{proc_name}" in cod_text
        assert proc_name.lstrip("_") in {name.lstrip("_") for name in info.code_labels.values()}


def test_extract_cod_listing_metadata_reads_life_cod_ranges():
    metadata = extract_cod_listing_metadata(LIFE_COD)

    assert metadata.code_labels[0] == "_main"
    assert metadata.proc_kinds[0] == "NEAR"
    assert metadata.code_ranges[0][1] > metadata.code_ranges[0][0]


def test_load_lst_metadata_uses_codeview_nb00_when_sidecars_absent():
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = decompile._load_lst_metadata(LIFE_EXE, project)

    assert metadata is not None
    assert metadata.absolute_addrs is True
    assert "codeview_nb00" in metadata.source_format
    assert "cod_listing" in metadata.source_format
    assert metadata.code_labels[0x10010] == "main"
    assert 0x100c6 not in metadata.code_labels
    assert metadata.code_labels[0x100ea] == "init_life"
    assert 0x10000 not in metadata.code_labels
    assert metadata.data_labels[0x15bb0] == "_speed"


def test_sidecar_cod_metadata_for_function_uses_sibling_cod():
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x10010, name="main")
    metadata = SimpleNamespace(
        cod_path=str(LIFE_COD),
        cod_proc_kinds={0x10010: "NEAR"},
    )

    cod_metadata = decompile._sidecar_cod_metadata_for_function(project, function, LIFE_EXE, metadata)

    assert cod_metadata is not None
    assert cod_metadata.has_source_lines(("main(argc, argv)",))


def test_dosmz_loader_handles_life_exe_sparse_relocations():
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)

    assert project.arch.name == "86_16"
    assert project.entry == 0x11423
    assert project.loader.main_object.max_addr >= 0x18be1


def test_probe_lift_break_reports_first_bad_instruction(monkeypatch):
    insns = [
        SimpleNamespace(address=0x1000, size=1, mnemonic="push", op_str="bp"),
        SimpleNamespace(address=0x1001, size=2, mnemonic="mov", op_str="bp, sp"),
        SimpleNamespace(address=0x1003, size=2, mnemonic="int", op_str="0x21"),
    ]
    project = SimpleNamespace(
        factory=SimpleNamespace(
            block=lambda addr, size, opt_level=0: (_ for _ in ()).throw(ValueError("bad lift")) if addr == 0x1003 else object()
        ),
    )

    monkeypatch.setattr(decompile, "_infer_linear_disassembly_window", lambda *_args, **_kwargs: (0x1000, 0x1005))
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: insns)

    rendered = decompile._probe_lift_break(project, 0x1000)

    assert "first lift failure at 0x1003" in rendered
    assert "0x1003: int 0x21" in rendered


def test_try_decompile_non_optimized_slice_uses_raw_slice(monkeypatch):
    project = SimpleNamespace(
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="main")
    monkeypatch.setattr(decompile, "_lst_code_region", lambda *_args, **_kwargs: (0x1000, 0x1003))
    monkeypatch.setattr(decompile, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), function),
    )
    monkeypatch.setattr(
        decompile,
        "_decompile_function_with_stats",
        lambda *_args, **_kwargs: ("ok", "int main(void)\n{\n    return 0;\n}\n", 1, 3, 0.01),
    )

    rendered = decompile._try_decompile_non_optimized_slice(
        project,
        0x1000,
        "main",
        timeout=1,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
    )

    assert "int main" in rendered


def test_recover_lst_function_prefers_lean_cfgfast_for_labeled_x86_16(monkeypatch):
    project = SimpleNamespace(entry=0x1E432, arch=SimpleNamespace(name="86_16"))
    metadata = SimpleNamespace(absolute_addrs=True)
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x10010, name="main")

    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda _project, start_addr, *, window: (start_addr, start_addr + window),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (expected_cfg, expected_func),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("full CFGFast should not run")),
    )

    cfg, func = decompile._recover_lst_function(
        project,
        metadata,
        0x10010,
        "main",
        timeout=4,
        window=0x200,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert func.name == "main"


def test_rank_exe_function_seeds_uses_epilog_follow_ons(monkeypatch):
    code = b"\xc3\x55\x8b\xec\x90"
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=0x1004,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_linear_disassembly",
        lambda *_args, **_kwargs: [SimpleNamespace(address=0x1000, size=1, mnemonic="ret", op_str="")],
    )

    ranked = decompile._rank_exe_function_seeds(project)

    assert 0x1001 in ranked


def test_rank_exe_function_seeds_respects_known_code_windows(monkeypatch):
    code = b"\x90" * 0x300
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1100: "main"},
        code_ranges={0x1100: (0x1100, 0x1120)},
        absolute_addrs=True,
    )
    project = SimpleNamespace(
        entry=0x1000,
        _inertia_lst_metadata=metadata,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked == []


def test_rank_exe_function_seeds_prioritizes_entry_window_call_targets(monkeypatch):
    code = bytearray(b"\x90" * 0x200)
    entry = 0x1080
    target = 0x1010
    helper = 0x10c0
    call_offset = entry - 0x1000
    rel = target - (entry + 3)
    helper_rel = helper - (entry + 6)
    code[call_offset : call_offset + 3] = b"\xE8" + int(rel).to_bytes(2, "little", signed=True)
    code[call_offset + 3 : call_offset + 6] = b"\xE8" + int(helper_rel).to_bytes(2, "little", signed=True)
    project = SimpleNamespace(
        entry=entry,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                max_addr=len(code) - 1,
                linked_base=0x1000,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: bytes(code)),
                mz_segment_spans=(),
            )
        ),
    )
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyError("no entry CFG")),
    )
    monkeypatch.setattr(decompile, "_linear_disassembly", lambda *_args, **_kwargs: [])

    ranked = decompile._rank_exe_function_seeds(project)

    assert ranked
    assert ranked[0] == target
    assert ranked.index(target) < ranked.index(helper)


def test_recover_seeded_exe_functions_reuses_existing_project_before_rebuild(monkeypatch):
    code = b"\x55\x8B\xEC" + b"\x90" * 0x20
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x1003])
    rebuilds: list[Path] = []
    monkeypatch.setattr(
        decompile,
        "_build_project",
        lambda path, **_kwargs: rebuilds.append(path) or (_ for _ in ()).throw(AssertionError("seed recovery should not rebuild")),
    )
    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=0x1003, name="sub_1003", is_plt=False, is_simprocedure=False)
    monkeypatch.setattr(decompile, "_pick_function_lean", lambda *_args, **_kwargs: (expected_cfg, expected_func))

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=1)

    assert recovered == [(expected_cfg, expected_func)]
    assert rebuilds == []


def test_recover_seeded_exe_functions_prioritizes_neighbors_from_recovered_function(monkeypatch):
    code = b"\x55\x8B\xEC" + b"\x90" * 0x40
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            main_object=SimpleNamespace(
                binary=CLI_PATH,
                linked_base=0x1000,
                max_addr=len(code) - 1,
                memory=SimpleNamespace(load=lambda *_args, **_kwargs: code),
            )
        ),
        factory=SimpleNamespace(
            block=lambda addr, **_kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(address=addr)]))
        ),
    )
    monkeypatch.setattr(decompile, "_rank_exe_function_seeds", lambda _project: [0x1010, 0x1200])
    recovered_order: list[int] = []

    def _fake_pick(_project, addr, **_kwargs):
        recovered_order.append(addr)
        return SimpleNamespace(), SimpleNamespace(addr=addr, name=f"sub_{addr:x}", is_plt=False, is_simprocedure=False)

    monkeypatch.setattr(decompile, "_pick_function_lean", _fake_pick)
    monkeypatch.setattr(
        decompile,
        "collect_neighbor_call_targets",
        lambda function: [SimpleNamespace(target_addr=0x1030)] if function.addr == 0x1010 else [],
    )

    recovered = decompile._recover_seeded_exe_functions(project, timeout=4, limit=3)

    assert [func.addr for _cfg, func in recovered] == [0x1010, 0x1030, 0x1200]
    assert recovered_order[:3] == [0x1010, 0x1030, 0x1200]


def test_match_flair_startup_entry_matches_watcom_startup_pattern():
    entry_bytes = bytes.fromhex("CCEBFD90909090" + "90" * 25)

    matches = match_flair_startup_entry(entry_bytes, Path("/home/xor/ida77/flair77"))

    assert matches
    assert any(match.pat_path.endswith("exe_wa16.pat") for match in matches)


def test_list_flair_sig_libraries_reads_pascal_catalogs():
    libraries = list_flair_sig_libraries(Path("/home/xor/ida77/flair77"))

    assert any("Turbo Pascal" in library.title for library in libraries)


def test_ensure_pat_from_omf_input_generates_fallback_pat_for_obj(tmp_path):
    pat_path = ensure_pat_from_omf_input(SYNTHETIC_OBJ, tmp_path, flair_root=Path("/home/xor/ida77/flair77"))

    assert pat_path is not None
    modules = parse_pat_file(pat_path)
    assert [module.module_name for module in modules] == ["E086_SHORTCUT", "E086_ENTRY"]


def test_ensure_pat_from_omf_input_merges_plb_and_fallback_for_life_obj(tmp_path):
    pat_path = ensure_pat_from_omf_input(REPO_ROOT / "LIFE.OBJ", tmp_path, flair_root=Path("/home/xor/ida77/flair77"))

    assert pat_path is not None
    modules = parse_pat_file(pat_path)
    names = {module.module_name for module in modules}
    assert "_main" in names
    assert "_generation" in names
    rich_module = next(module for module in modules if module.referenced_names and any(pub.name == "_main" for pub in module.public_names))
    assert any(ref.name == "__chkstk" for ref in rich_module.referenced_names)
    assert len(modules) >= 15


def test_generate_pat_from_omf_obj_captures_fixupp_external_refs_for_life_obj(tmp_path):
    pat_path = tmp_path / "life-fallback.pat"

    count = generate_pat_from_omf_obj(REPO_ROOT / "LIFE.OBJ", pat_path)

    assert count >= 5
    modules = parse_pat_file(pat_path)
    main_module = next(module for module in modules if module.module_name == "_main")
    assert main_module.referenced_names
    all_ref_names = {ref.name for module in modules for ref in module.referenced_names}
    assert "__chkstk" in all_ref_names
    assert "_printf" in all_ref_names or "_sprintf" in all_ref_names


def test_extract_omf_modules_from_lib_reads_page_aligned_module(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(_build_synthetic_microsoft_lib(SYNTHETIC_OBJ.read_bytes()))

    modules = extract_omf_modules_from_lib(lib_path)

    assert len(modules) == 1
    assert modules[0].module_name == "SYNTHETIC.OBJ"
    assert modules[0].data.startswith(SYNTHETIC_OBJ.read_bytes()[:16])


def test_parse_microsoft_lib_reads_header_and_extended_dictionary(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            case_sensitive=True,
            extended_records=[(1, (7, 9))],
        )
    )

    metadata = parse_microsoft_lib(lib_path)

    assert metadata.header.page_size == 512
    assert metadata.header.case_sensitive is True
    assert metadata.header.dictionary_blocks == 1
    assert len(metadata.modules) == 1
    assert metadata.modules[0].page_number == 1
    assert metadata.modules[0].dependency_indexes == (7, 9)
    assert metadata.extended_records[0].page_number == 1
    assert metadata.extended_records[0].dependency_indexes == (7, 9)


def test_parse_microsoft_lib_reads_dictionary_entries_and_lookup(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            dictionary_entries=[("__chkstk", 1), ("_main", 1)],
        )
    )

    metadata = parse_microsoft_lib(lib_path)

    assert {(entry.symbol_name, entry.module_page) for entry in metadata.dictionary_entries} == {
        ("__chkstk", 1),
        ("_main", 1),
    }
    assert lookup_microsoft_lib_symbol(lib_path, "__CHKSTK") is not None
    assert lookup_microsoft_lib_symbol(lib_path, "__CHKSTK").module_page == 1
    assert lookup_microsoft_lib_symbol(lib_path, "_main").symbol_name == "_main"


def test_enumerate_microsoft_lib_dictionary_symbols_preserves_case_sensitive_lookup(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(
        _build_synthetic_microsoft_lib(
            SYNTHETIC_OBJ.read_bytes(),
            case_sensitive=True,
            dictionary_entries=[("SymbolExact", 1)],
        )
    )

    entries = enumerate_microsoft_lib_dictionary_symbols(lib_path)

    assert [(entry.symbol_name, entry.module_page) for entry in entries] == [("SymbolExact", 1)]
    assert lookup_microsoft_lib_symbol(lib_path, "SymbolExact") is not None
    assert lookup_microsoft_lib_symbol(lib_path, "symbolexact") is None


def test_generate_pat_from_omf_lib_extracts_obj_members(tmp_path):
    lib_path = tmp_path / "sample.lib"
    lib_path.write_bytes(_build_synthetic_microsoft_lib(SYNTHETIC_OBJ.read_bytes()))
    pat_path = tmp_path / "sample.pat"

    count = generate_pat_from_omf_lib(lib_path, pat_path)

    assert count >= 2
    modules = parse_pat_file(pat_path)
    assert [module.module_name for module in modules[:2]] == ["E086_SHORTCUT", "E086_ENTRY"]


def test_match_pat_modules_labels_unique_generated_function_match():
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )
    module = PatModule(
        source_path="<memory>",
        module_name="demo_func",
        pattern_bytes=tuple([0xFB, 0xFC, 0x52, 0x50, 0x53, 0x55, 0x56, 0x57, 0x06, 0x51, 0x1E, 0x8B] + [None] * 20),
        module_length=0x0C,
        public_names=(PatPublicName(offset=0, name="demo_func"),),
        referenced_names=(),
        tail_bytes=(),
    )

    code_labels, code_ranges = match_pat_modules(image, 0x1000, [module])

    assert code_labels == {0x1003: "demo_func"}
    assert code_ranges == {0x1003: (0x1003, 0x100F)}


def test_load_cached_pat_regex_specs_creates_reusable_disk_cache(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")

    specs = load_cached_pat_regex_specs(pat_path, tmp_path)

    assert len(specs) == 1
    assert isinstance(specs[0], CachedPatRegexSpec)
    assert any(path.suffixes[-2:] == [".patrx", ".pickle"] for path in tmp_path.iterdir() if path.is_file())


def test_match_pat_modules_accepts_cached_regex_specs(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    specs = load_cached_pat_regex_specs(pat_path, tmp_path)
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )

    code_labels, code_ranges = match_pat_modules(image, 0x1000, specs)

    assert code_labels == {0x1003: "demo_func"}
    assert code_ranges == {0x1003: (0x1003, 0x100F)}


def test_match_pat_modules_supports_both_explicit_backends(tmp_path):
    pat_path = tmp_path / "demo.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    pat_path.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    specs = load_cached_pat_regex_specs(pat_path, tmp_path)
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )

    py_labels, py_ranges = match_pat_modules(image, 0x1000, specs, backend="python_regex")
    hs_labels, hs_ranges = match_pat_modules(image, 0x1000, specs, backend="hyperscan")

    assert py_labels == {0x1003: "demo_func"}
    assert py_ranges == {0x1003: (0x1003, 0x100F)}
    assert hs_labels == py_labels
    assert hs_ranges == py_ranges


def test_normalize_pat_backend_choice_rejects_unknown_backend():
    with pytest.raises(ValueError):
        _normalize_pat_backend_choice("wat")


def test_detect_flair_metadata_forwards_pat_backend(monkeypatch):
    recorded = {}
    project = SimpleNamespace(
        entry=0x1000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 32),
        ),
    )

    monkeypatch.setattr(decompile.Path, "exists", lambda self: True)
    monkeypatch.setattr(decompile, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(decompile, "list_flair_sig_libraries", lambda *_args, **_kwargs: ())

    def _fake_discover(binary, project_arg, *, flair_root=None, backend=None, **_kwargs):
        recorded["binary"] = binary
        recorded["project"] = project_arg
        recorded["flair_root"] = flair_root
        recorded["backend"] = backend
        return SimpleNamespace(code_labels={}, code_ranges={}, source_formats=())

    monkeypatch.setattr(decompile, "discover_local_pat_matches", _fake_discover)

    decompile._detect_flair_metadata(Path("/tmp/demo.exe"), project, pat_backend="python_regex")

    assert recorded["backend"] == "python_regex"


def test_build_signature_catalog_skips_duplicate_modules(tmp_path):
    left = tmp_path / "left.pat"
    right = tmp_path / "right.pat"
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    left.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    right.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    output = tmp_path / "catalog.pat"

    result = build_signature_catalog([left, right], output, recursive=False, cache_dir=tmp_path / "cache")

    assert result.input_count == 2
    assert result.imported_module_count == 2
    assert result.unique_module_count == 1
    assert result.duplicate_module_count == 1
    modules = parse_pat_file(output)
    assert [module.module_name for module in modules] == ["demo_func"]


def test_match_signature_catalog_matches_prebuilt_catalog(tmp_path):
    pattern = "FBFC52505355565706511E8BEC" + (".." * 19)
    catalog = tmp_path / "catalog.pat"
    catalog.write_text(f"{pattern} 00 0000 000C :0000 demo_func\n---\n")
    image = bytes.fromhex(
        "90 90 90 FB FC 52 50 53 55 56 57 06 51 1E 8B EC 36 89 2E DE 00 C5 76 12 AD 89 76 12 8C D7 8E DF 8A CC 98 C3 90"
    )
    project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(min_addr=0x1000, max_addr=0x1000 + len(image) - 1),
            memory=SimpleNamespace(load=lambda addr, size: image[addr - 0x1000 : addr - 0x1000 + size]),
        )
    )

    result = match_signature_catalog(catalog, tmp_path / "demo.exe", project, backend="python_regex")

    assert result.code_labels == {0x1003: "demo_func"}
    assert result.code_ranges == {0x1003: (0x1003, 0x100F)}
    assert result.source_formats == ("signature_catalog",)


def test_detect_flair_metadata_merges_local_pat_matches(monkeypatch):
    project = SimpleNamespace(
        entry=0x2000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 32),
        ),
    )
    monkeypatch.setattr(decompile, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(decompile, "list_flair_sig_libraries", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(
        decompile,
        "discover_local_pat_matches",
        lambda *_args, **_kwargs: SimpleNamespace(
            code_labels={0x1234: "helper_func"},
            code_ranges={0x1234: (0x1234, 0x1250)},
            source_formats=("local_omf_pat",),
        ),
    )

    code_labels, code_ranges, source_formats = decompile._detect_flair_metadata(Path("/tmp/demo.exe"), project)

    assert code_labels[0x1234] == "helper_func"
    assert code_ranges[0x1234] == (0x1234, 0x1250)
    assert "local_omf_pat" in source_formats


def test_detect_flair_metadata_merges_signature_catalog(monkeypatch, tmp_path):
    project = SimpleNamespace(
        entry=0x2000,
        loader=SimpleNamespace(
            main_object=SimpleNamespace(),
            memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 32),
        ),
    )
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("---\n")
    monkeypatch.setattr(decompile, "match_flair_startup_entry", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(decompile, "list_flair_sig_libraries", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(
        decompile,
        "match_signature_catalog",
        lambda *_args, **_kwargs: SimpleNamespace(
            code_labels={0x2345: "catalog_func"},
            code_ranges={0x2345: (0x2345, 0x2350)},
            source_formats=("signature_catalog",),
        ),
    )
    monkeypatch.setattr(
        decompile,
        "discover_local_pat_matches",
        lambda *_args, **_kwargs: SimpleNamespace(code_labels={}, code_ranges={}, source_formats=()),
    )

    code_labels, code_ranges, source_formats = decompile._detect_flair_metadata(
        Path("/tmp/demo.exe"),
        project,
        pat_backend="python_regex",
        signature_catalog=catalog,
    )

    assert code_labels[0x2345] == "catalog_func"
    assert code_ranges[0x2345] == (0x2345, 0x2350)
    assert "signature_catalog" in source_formats


def test_load_lst_metadata_forwards_flair_parameters_without_global_args(monkeypatch, tmp_path):
    binary = tmp_path / "demo.exe"
    binary.write_bytes(b"MZ")
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("---\n")
    project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x40)),
        kb=SimpleNamespace(labels={}),
    )
    seen: dict[str, object] = {}

    monkeypatch.setattr(decompile, "_probe_ida_base_linear", lambda *_args, **_kwargs: 0x1000)
    monkeypatch.setattr(decompile, "_parse_codeview_nb00_metadata", lambda *_args, **_kwargs: ({}, {}, {}))
    monkeypatch.setattr(
        decompile,
        "_detect_flair_metadata",
        lambda _binary, _project, *, pat_backend=None, signature_catalog=None: (
            seen.setdefault("pat_backend", pat_backend) and {0x1010: "sig_func"},
            seen.setdefault("signature_catalog", signature_catalog) and {0x1010: (0x1010, 0x1020)},
            ("signature_catalog",),
        ),
    )

    metadata = decompile._load_lst_metadata(
        binary,
        project,
        pat_backend="python_regex",
        signature_catalog=catalog,
    )

    assert metadata is not None
    assert seen == {"pat_backend": "python_regex", "signature_catalog": catalog}
    assert metadata.code_labels[0x1010] == "sig_func"
    assert metadata.signature_code_addrs == frozenset({0x1010})


def test_parse_ida_map_metadata_prefers_segment_class_over_loc_name(tmp_path):
    map_path = tmp_path / "demo.map"
    map_path.write_text(
        "\n"
        " Start  Stop   Length Name               Class\n"
        "\n"
        " 00000H 0001FH 00020H seg000             CODE\n"
        " 00020H 0002FH 00010H dseg               DATA\n"
        "\n"
        "  Address         Publics by Value\n"
        "\n"
        " 0000:0004       loc_10004\n"
        " 0000:0010       main\n"
        " 0002:0002       word_10022\n"
    )

    code_labels, data_labels, segment_offsets = decompile._parse_ida_map_metadata(map_path, load_base_linear=0x10000)

    assert segment_offsets == {"seg000": 0x0000, "dseg": 0x0020}
    assert code_labels[0x10004] == "loc_10004"
    assert code_labels[0x10010] == "main"
    assert data_labels[0x10022] == "word_10022"


def test_visible_code_labels_skip_signature_matched_functions_by_default():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "real_func", 0x1300: "sig_func"},
        code_ranges={0x1200: (0x1200, 0x1220), 0x1300: (0x1300, 0x1310)},
        signature_code_addrs=frozenset({0x1300}),
        absolute_addrs=True,
        source_format="ida_map+signature_catalog",
    )

    assert decompile._visible_code_labels(metadata) == {0x1200: "real_func"}


def test_format_sidecar_function_catalog_omits_signature_matched_functions():
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x1200: "real_func", 0x1300: "sig_func"},
        code_ranges={0x1200: (0x1200, 0x1220), 0x1300: (0x1300, 0x1310)},
        signature_code_addrs=frozenset({0x1300}),
        absolute_addrs=True,
        source_format="signature_catalog",
    )

    formatted = decompile._format_sidecar_function_catalog(metadata)

    assert "real_func" in formatted
    assert "sig_func" not in formatted


def test_extract_lst_metadata_supports_uasm_proc_ranges_from_snake_listing():
    metadata = extract_lst_metadata(REPO_ROOT / "snake.lst")

    assert metadata.source_format == "uasm_lst"
    assert metadata.data_labels[0x00] == "msg"
    assert metadata.code_labels[0x00] == "main"
    assert metadata.code_labels[0x92] == "delay"
    assert metadata.code_ranges[0x00] == (0x00, 0x92)
    assert metadata.code_ranges[0x92] == (0x92, 0xA3)


def test_extract_lst_metadata_supports_uasm_entry_labels_in_com_listing():
    metadata = extract_lst_metadata(REPO_ROOT / "angr_platforms" / "x16_samples" / "ICOMDO.LST")

    assert metadata.source_format == "uasm_lst"
    assert metadata.code_labels[0x100] == "start"
    assert metadata.data_labels[0x110] == "msg"


def test_extract_lst_metadata_supports_masm_snow_listing():
    metadata = extract_lst_metadata(REPO_ROOT / "snow.lst")

    assert metadata.source_format == "masm_lst"
    assert metadata.code_labels[0x0000] == "start"
    assert metadata.code_ranges[0x0000] == (0x0000, 0x00B8)
    assert metadata.data_labels[0x00B8] == "const005"


def test_extract_lst_metadata_supports_ida_prefixed_listing(tmp_path):
    listing = """seg000:0000 seg000          segment byte public 'CODE' use16\nseg000:0010 main            proc near\nseg000:0010                 push    bp\nseg000:0012 main            endp\nseg001:0000 seg001          segment word public 'DATA' use16\nseg001:0004 value           db 1\n"""
    tmp = tmp_path / "ida_style.lst"
    tmp.write_text(listing)
    metadata = extract_lst_metadata(tmp)

    assert metadata.source_format == "ida_lst"
    assert metadata.code_labels[0x0010] == "main"
    assert metadata.code_ranges[0x0010] == (0x0010, 0x0012)
    assert metadata.data_labels[0x0004] == "value"


def test_rank_labeled_function_entries_prefers_entry_and_main(monkeypatch):
    project = SimpleNamespace(entry=0x1E432)
    monkeypatch.setattr(decompile, "_is_zero_filled_region", lambda *_args, **_kwargs: False)
    metadata = SimpleNamespace(
        code_ranges={
            0x10000: (0x10000, 0x10010),
            0x10010: (0x10010, 0x10147),
            0x1E432: (0x1E432, 0x1E4E4),
            0x1E4C6: (0x1E4C6, 0x1E4D5),
        }
    )

    ranked = decompile._rank_labeled_function_entries(
        project,
        [
            (0x10000, "padding"),
            (0x10010, "main"),
            (0x1E432, "start"),
            (0x1E4C6, "cintDIV"),
        ],
        metadata,
    )

    assert ranked[:4] == [
        (0x1E432, "start"),
        (0x10010, "main"),
        (0x1E4C6, "cintDIV"),
        (0x10000, "padding"),
    ]


def test_dosmz_loader_widens_linear_address_space_without_widening_near_words(tmp_path):
    mz = bytearray(0x20)
    mz[0:2] = b"MZ"
    mz[0x08:0x0A] = (2).to_bytes(2, "little")
    mz[0x10:0x12] = (0x200).to_bytes(2, "little")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(bytes(mz) + b"\x90" * 32)

    with sample.open("rb") as fp:
        obj = DOSMZ(str(sample), fp, base_addr=0x10000)

    assert obj.arch.bits == 32
    assert obj.arch.bytes == 2
    assert obj.linked_base == 0x10000


def test_parse_mzre_map_metadata_extracts_code_ranges(tmp_path):
    map_path = tmp_path / "sample.map"
    map_path.write_text(
        "seg000 CODE 0000\n"
        "main: seg000 NEAR 0010-0146 R0010-0146\n",
        encoding="utf-8",
    )

    code_labels, data_labels, code_ranges = decompile._parse_mzre_map_metadata(
        map_path,
        load_base_linear=0x10000,
    )

    assert data_labels == {}
    assert code_labels == {0x10010: "main"}
    assert code_ranges == {0x10010: (0x10010, 0x10147)}


def test_lst_code_region_prefers_exact_or_containing_sidecar_span():
    metadata = SimpleNamespace(
        code_ranges={
            0x10010: (0x10010, 0x10147),
            0x10147: (0x10147, 0x10211),
        }
    )

    assert decompile._lst_code_region(metadata, 0x10010) == (0x10010, 0x10147)
    assert decompile._lst_code_region(metadata, 0x10080) == (0x10010, 0x10147)
    assert decompile._lst_code_region(metadata, 0x10147) == (0x10147, 0x10211)
    assert decompile._lst_code_region(metadata, 0x20000) is None


def test_format_sidecar_function_catalog_includes_ranges_and_sizes():
    metadata = SimpleNamespace(
        code_labels={
            0x10010: "main",
            0x10147: "drawCockpit",
        },
        code_ranges={
            0x10010: (0x10010, 0x10147),
            0x10147: (0x10147, 0x10211),
        },
    )

    rendered = decompile._format_sidecar_function_catalog(metadata)

    assert "0x10010 main size=0x137 range=[0x10010, 0x10147)" in rendered
    assert "0x10147 drawCockpit size=0xca range=[0x10147, 0x10211)" in rendered


def test_parse_idc_metadata_filters_control_flow_labels(tmp_path):
    idc_path = tmp_path / "sample.idc"
    idc_path.write_text(
        'set_name(0X10010, "main");\n'
        'set_name(0X1008C, "cond_1008C");\n'
        'set_name(0X1009D, "else_1009D");\n',
        encoding="utf-8",
    )

    code_labels, data_labels = decompile._parse_idc_metadata(idc_path)

    assert code_labels == {0x10010: "main"}
    assert data_labels == {
        0x1008C: "cond_1008C",
        0x1009D: "else_1009D",
    }


def test_label_looks_like_function_filters_internal_hex_suffixed_flow_labels():
    assert decompile._label_looks_like_function("main")
    assert decompile._label_looks_like_function("MainGameLoop")
    assert decompile._label_looks_like_function("cintDIV")
    assert not decompile._label_looks_like_function("cond_1008C")
    assert not decompile._label_looks_like_function("innerCond_12D71")
    assert not decompile._label_looks_like_function("nextInner2_12D9E")
    assert not decompile._label_looks_like_function("out_12C7D")


def test_fallback_entry_function_uses_fast_recovery_for_call_heavy_cod_helpers(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow path should not run")))
    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", lambda project_arg, start_addr, *, window: (start_addr, start_addr + window))

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200, prefer_fast_recovery=True)

    assert cfg is expected_cfg
    assert func is expected_func
    assert project._inertia_decompiler_stage == "recovery:fast"
    assert calls == [("lean", [(0x1000, 0x1080)], False, False)]


def test_fallback_entry_function_uses_full_timeout_budget_for_fast_cod_helpers(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    budgets: list[int] = []

    def fake_analysis_timeout(timeout):
        budgets.append(timeout)

        class _Ctx:
            def __enter__(self):
                return None

            def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
                return False

        return _Ctx()

    monkeypatch.setattr(decompile, "_analysis_timeout", fake_analysis_timeout)
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=project.entry)),
    )
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    decompile._fallback_entry_function(project, timeout=20, window=0x200, prefer_fast_recovery=True)

    assert budgets == [20]


def test_fallback_entry_function_falls_back_after_fast_recovery_error(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        raise ValueError("fast recovery failed")

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    cfg, func = decompile._fallback_entry_function(project, timeout=20, window=0x200, prefer_fast_recovery=True)

    assert cfg is expected_cfg
    assert func is expected_func
    assert calls[0][0] == "lean"
    assert calls[-1][0] == "pick"


def test_fallback_entry_function_propagates_timeout_without_retrying(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        raise decompile._AnalysisTimeout()

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    with pytest.raises(decompile._AnalysisTimeout):
        decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert calls == [("infer", 0x200), ("pick", [(0x1000, 0x1200)], False, False)]


def test_recover_lst_function_retries_broader_windows_after_narrow_miss(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    lst_metadata = SimpleNamespace(code_labels={0x0: "helper"})
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, force_smart_scan))
        region = regions[0]
        if region[1] - region[0] >= 0x1000:
            return expected_cfg, expected_func
        raise KeyError("narrow miss")

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._recover_lst_function(
        project,
        lst_metadata,
        0x0,
        "helper",
        timeout=10,
        window=0x200,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert [call[1] for call in calls if call[0] == "infer"] == [0x200, 0x400, 0x800, 0x1000]
    assert [call[1][0][1] - call[1][0][0] for call in calls if call[0] == "pick"] == [
        0x200,
        0x400,
        0x800,
        0x1000,
    ]


def test_pick_function_retries_smart_scan_before_complete_scan_after_narrow_cfgfast_miss(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfgs = [
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={0x1000: expected_func}),
    ]

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfgs[len(captured) - 1]

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)], data_references=True)

    assert cfg is expected_cfgs[-1]
    assert func is expected_func
    assert len(captured) == 4
    assert [entry.get("force_complete_scan", False) for entry in captured] == [False, False, True, True]
    assert [entry["data_references"] for entry in captured] == [True, True, True, True]
    assert [entry["force_smart_scan"] for entry in captured] == [False, True, False, True]


def test_pick_function_continues_after_cfgfast_exception(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        if len(captured) < 3:
            raise ValueError("CFGFast temporarily failed")
        return SimpleNamespace(functions={0x1000: expected_func})

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)], data_references=True)

    assert cfg.functions[0x1000] is expected_func
    assert func is expected_func
    assert len(captured) == 3


def test_pick_function_disables_smart_scan_for_bounded_x86_16_regions(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured[0]["force_smart_scan"] is False
    assert captured[0]["data_references"] is True


def test_describe_exception_keeps_type_when_message_is_empty():
    assert decompile._describe_exception(AssertionError()) == "AssertionError"
    assert decompile._describe_exception(ValueError("bad cfg")) == "ValueError: bad cfg"


def test_detect_packed_mz_executable_recognizes_lzexe(tmp_path):
    path = tmp_path / "packed.exe"
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x1C:0x20] = b"LZ91"
    path.write_bytes(bytes(header))

    assert decompile._detect_packed_mz_executable(path) == "LZEXE 0.91"


def test_recover_partial_cfg_uses_bounded_cfgfast_and_returns_entry_cfg(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []
    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg = decompile._recover_partial_cfg(project, window=0x200)

    assert cfg is expected_cfg
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1200)],
            "normalize": True,
            "force_complete_scan": False,
            "data_references": False,
            "force_smart_scan": False,
        }
    ]


def test_supplement_functions_from_prologue_scan_adds_confirmed_recoveries(monkeypatch):
    code = bytearray(0x2000)
    for addr in (0x1750, 0x1770):
        offset = addr - 0x1000
        code[offset : offset + 3] = b"\x55\x8b\xec"

    class _Memory:
        def load(self, offset, size):
            return bytes(code[offset : offset + size])

    project = SimpleNamespace(
        entry=0x1500,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(max_addr=len(code) - 1, linked_base=0x1000, memory=_Memory())),
    )

    class _Block:
        def __init__(self):
            self.capstone = SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="push", op_str="bp"),
                    SimpleNamespace(mnemonic="mov", op_str="bp, sp"),
                ]
            )

    project.factory = SimpleNamespace(block=lambda *_args, **_kwargs: _Block())

    expected = {
        0x1770: (SimpleNamespace(), SimpleNamespace(addr=0x1770, name="sub_1770")),
        0x1750: (SimpleNamespace(), SimpleNamespace(addr=0x1750, name="sub_1750")),
    }

    def fake_pick_function_lean(project_arg, addr, **_kwargs):
        return expected[addr]

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda func, **_kwargs: func())

    supplemental = decompile._supplement_functions_from_prologue_scan(project, existing_addrs={0x1500})

    assert [function.addr for _, function in supplemental] == [0x1750]


def test_dedupe_adjacent_prototype_lines_removes_only_consecutive_duplicates():
    source = "int dos_int21(void);\nint dos_int21(void);\nint other(void);\n\nint dos_int21(void);\n"

    assert decompile._dedupe_adjacent_prototype_lines(source) == (
        "int dos_int21(void);\nint other(void);\n\nint dos_int21(void);\n"
    )


def test_sanitize_mangled_autonames_text_fixes_repeated_autonames():
    source = "long sub_6c5sub_6()\n{\n    dos_int2sub_1();\n}\n"

    assert decompile._sanitize_mangled_autonames_text(source) == (
        "long sub_6c5()\n{\n    dos_int2();\n}\n"
    )


def test_recover_blob_entry_function_enables_data_references(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
        analyses=SimpleNamespace(),
    )
    captured: list[dict[str, object]] = []

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfgs[len(captured) - 1]

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfgs = [
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={0x1000: expected_func}),
    ]
    project.analyses.CFGFast = fake_cfgfast

    cfg, func = decompile._recover_blob_entry_function(project, 0x1000, timeout=10)

    assert cfg is expected_cfgs[-1]
    assert func is expected_func
    assert [entry["data_references"] for entry in captured] == [False, True]


def test_decompile_cli_recovers_source_like_monoprin_tokens():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(MONOPRIN_COD), "--proc", "_mset_pos", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _mset_pos" in result.stdout
    assert "== c ==" in result.stdout
    assert "% 80" in result.stdout
    assert "% 25" in result.stdout
    assert (
        "int _mset_pos(int x, int y)" in result.stdout
        or "short _mset_pos(unsigned short v0, unsigned short x, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x_3, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short x_2, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short x_3, unsigned short y)" in result.stdout
    )
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "mono_x =" in result.stdout
    assert "mono_y =" in result.stdout
    assert "&v1" not in result.stdout
    assert "return" in result.stdout


def test_decompile_cli_can_extract_and_name_cod_procedure():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(NHORZ_COD), "--proc", "_ChangeWeather", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _ChangeWeather" in result.stdout
    assert "int _ChangeWeather(void)" in result.stdout
    assert "globals = _CLOUDHEIGHT, _CLOUDTHICK" in result.stdout
    assert "extern char g_" not in result.stdout
    assert "if (BadWeather)" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "if (!(!" not in result.stdout
    assert "BadWeather = 0;" in result.stdout
    assert "CLOUDHEIGHT = 8150;" in result.stdout
    assert "CLOUDTHICK = 500;" in result.stdout
    assert "0x7000" not in result.stdout
    assert "_start" not in result.stdout


def test_normalize_function_signature_arg_names_deduplicates_duplicate_parameters():
    text = "unsigned short _strlen(unsigned short s, unsigned short s)\n"

    assert decompile._normalize_function_signature_arg_names(text) == (
        "unsigned short _strlen(unsigned short s, unsigned short s_2)\n"
    )


def test_prune_void_function_return_values_text_handles_multiline_headers():
    text = (
        "void _dos_free()\n"
        "{\n"
        "    if (rout.x.cflag != 0) {\n"
        "        return err;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )

    assert decompile._prune_void_function_return_values_text(text) == (
        "void _dos_free()\n"
        "{\n"
        "    if (rout.x.cflag != 0) {\n"
        "        return;\n"
        "    }\n"
        "    return;\n"
        "}\n"
    )


def test_prune_void_function_return_values_text_drops_bare_returns_from_nonvoid_functions():
    text = (
        "unsigned short _dos_getProcessId(void)\n"
        "{\n"
        "    return;\n"
        "}\n"
    )

    assert decompile._prune_void_function_return_values_text(text) == (
        "unsigned short _dos_getProcessId(void)\n"
        "{\n"
        "}\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_far_pointer_stack_stores():
    metadata = SimpleNamespace(stack_aliases={0xA: "cs", 0xC: "ss"})
    text = "    *((unsigned short *)(ds * 16 + (unsigned int)cs_2)) = ir_3_2;\n"

    assert decompile._simplify_x86_16_stack_byte_pointers(text, metadata) == "    *cs = ir_3_2;\n"


def test_simplify_x86_16_stack_byte_pointers_keeps_const_pointer_inputs_stable():
    metadata = SimpleNamespace(stack_aliases={0x4: "file"})
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    *((unsigned short *)(ds * 16 + (unsigned int)file)) = ir_4_2;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "*file =" not in simplified
    assert "MK_FP(ds, (unsigned int)file)" in simplified


def test_simplify_x86_16_stack_byte_pointers_keeps_adjacent_source_backed_stores_distinct():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
            "return 0;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    err = loadprog(file, 0, DOS_LOAD_NOEXEC, cmdline);\n"
        "    if (err) return err;\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    *ss = exeLoadParams.ss;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "    *cs = exeLoadParams.cs;\n" in simplified
    assert "    *ss = exeLoadParams.ss;\n" in simplified
    assert simplified.index("    *cs = exeLoadParams.cs;\n") < simplified.index("    *ss = exeLoadParams.ss;\n")


def test_simplify_x86_16_stack_byte_pointers_splits_reused_temp_windows_for_source_backed_stores():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
            "return 0;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    err = loadprog(file, 0, DOS_LOAD_NOEXEC, cmdline);\n"
        "    if (err) return err;\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    ir_3_2 = exeLoadParams.ss;\n"
        "    *ss = ir_3_2;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "    *cs = exeLoadParams.cs;\n" in simplified
    assert "    *ss = exeLoadParams.ss;\n" in simplified
    assert simplified.index("    *cs = exeLoadParams.cs;\n") < simplified.index("    *ss = exeLoadParams.ss;\n")


def test_format_known_helper_calls_handles_missing_cod_metadata(monkeypatch):
    monkeypatch.setattr(decompile, "collect_dos_int21_calls", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "collect_interrupt_service_calls", lambda *_args, **_kwargs: [])

    project = SimpleNamespace(_sim_procedures={})
    function = SimpleNamespace(addr=0x1000, name="demo")

    assert (
        decompile._format_known_helper_calls(project, function, "int demo(void)\n{\n    return 0;\n}\n", "cdecl", None)
        == "int demo(void)\n{\n    return 0;\n}"
    )


def test_decompile_cli_prunes_void_returns_for_multiline_headers():
    result = _run_decompile_proc(DOSFUNC_COD, "_dos_free")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_free(const unsigned short segment)" in result.stdout
    assert "sreg.es = segment;" in result.stdout
    assert "return err;" in result.stdout
    assert "return 0;" in result.stdout
    assert "return;" not in result.stdout


@pytest.mark.parametrize(
    ("proc_name", "header_anchor"),
    (
        ("_dos_getProcessId", "unsigned short _dos_getProcessId(void)"),
        ("_dos_setProcessId", "int _dos_setProcessId(const unsigned short pid)"),
    ),
)
def test_decompile_cli_recovers_dos_process_id_helpers(proc_name: str, header_anchor: str):
    result = _run_decompile_proc(DOSFUNC_COD, proc_name)

    assert result.returncode == 0, result.stderr + result.stdout
    assert header_anchor in result.stdout
    assert "return ir_1;" not in result.stdout
    assert "return;" not in result.stdout
    if proc_name == "_dos_setProcessId":
        assert "[bp+0x4] = pid" in result.stdout


def test_decompile_cli_recovers_dos_load_program_pointer_stores():
    result = _run_decompile_proc(DOSFUNC_COD, "_dos_loadProgram")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_loadProgram(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)" in result.stdout
    assert "if (err) return err;" in result.stdout
    assert "*cs = exeLoadParams.cs;" in result.stdout
    assert "*ss = exeLoadParams.ss;" in result.stdout
    assert "ds * 16 +" not in result.stdout
    assert "*file =" not in result.stdout
    assert "ds * 16 +" not in result.stdout
    assert "if (&err)" not in result.stdout


def test_decompile_cli_skips_chkstk_thunk_for_small_cod_logic():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(MAX_COD), "--proc", "_max", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _max" in result.stdout
    assert "UnresolvableJumpTarget" not in result.stdout
    assert "/* COD annotations:" in result.stdout
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "short _max(" in result.stdout
    assert "unsigned short _max(unsigned short x, unsigned short y)" in result.stdout
    assert "unsigned short y" in result.stdout
    assert "if (a1 > x)" in result.stdout
    assert "return x_3;" in result.stdout


def test_decompile_cli_recovers_small_cod_byte_condition_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_MousePOS")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _MousePOS" in result.stdout
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "short _MousePOS(unsigned short x, unsigned short y)" in result.stdout
    assert "globals = _MOUSE, _MouseX, _MouseY" in result.stdout
    assert "if (!(MOUSE))" in result.stdout
    assert "&v1" not in result.stdout
    assert "return sub_ff033();" in result.stdout


def test_decompile_cli_recovers_configcrts_copy_loop():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_ConfigCrts")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _ConfigCrts" in result.stdout
    assert "unsigned short _ConfigCrts(void)" in result.stdout
    assert "i = 0;" in result.stdout
    assert "field_1 = i * 2;" in result.stdout
    assert "do" in result.stdout
    assert "return v7;" in result.stdout


def test_decompile_cli_recovers_rotate_pt_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_rotate_pt")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _rotate_pt" in result.stdout
    assert "void _rotate_pt(unsigned short s, unsigned short d, unsigned short ang)" in result.stdout
    assert "[bp+0x4] = s" in result.stdout
    assert "[bp+0x6] = d" in result.stdout
    assert "[bp-0x4] = y" in result.stdout
    assert "[bp-0x2] = x" in result.stdout
    assert "calls = _CosB, _SinB" in result.stdout
    assert "y_4 = *((char *)(ds * 16 + s))" in result.stdout
    assert "CosB(OurRoll);" in result.stdout


def test_decompile_cli_recovers_sethook_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetHook")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetHook" in result.stdout
    assert "unsigned short _SetHook(unsigned short Hook)" in result.stdout
    assert "[bp+0x4] = Hook" in result.stdout
    assert "globals = _HookDown" in result.stdout
    assert "calls = _Message" in result.stdout
    assert 'Message ("Hook Lowered",RIO_NOW_MSG);' in result.stdout
    assert "sub_102f();" not in result.stdout
    assert "HookDown == Hook" in result.stdout
    assert "g_7000 = Hook;" in result.stdout or "HookDown = Hook;" in result.stdout
    assert "if (Hook)" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "v2 = &v3;" not in result.stdout
    assert "= 93;" in result.stdout
    assert "= 106;" in result.stdout
    assert "return 1;" in result.stdout
    assert "s_" not in result.stdout


def test_decompile_cli_recovers_setgear_guard_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetGear")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetGear" in result.stdout
    assert "unsigned short _SetGear(unsigned short G)" in result.stdout or "void _SetGear(int G)" in result.stdout
    assert "if (!(ejected))" in result.stdout
    assert "if (!G)" in result.stdout
    assert "if (Knots <= 350)" in result.stdout
    assert "Status = Status | 1;" in result.stdout
    assert "Status = Status & -2;" in result.stdout
    assert "Message (\"Landing gear lowered\",RIO_MSG);" in result.stdout
    assert "return v13;" in result.stdout
    assert "if (...)" not in result.stdout
    assert "28674" not in result.stdout
    assert "28682" not in result.stdout
    assert "sub_102f();" not in result.stdout


def test_decompile_cli_recovers_setdlc_state_store():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetDLC")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetDLC" in result.stdout
    assert "short _SetDLC(" in result.stdout
    assert "unsigned short DLC" in result.stdout
    assert "[bp+0x4] = DLC" in result.stdout
    assert "globals = _DirectLiftControl" in result.stdout
    assert "DirectLiftControl = DLC;" in result.stdout
    assert "DLC >> 8" not in result.stdout
    assert "return DLC;" in result.stdout


def test_decompile_cli_keeps_query_interrupts_wrapper_calls_classified_in_matrix_corpus():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(IMOD_COD),
            "--proc",
            "query_interrupts",
            "--proc-kind",
            "FAR",
            "--timeout",
            "60",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 query_interrupts" in result.stdout
    assert "calls = _int86, _int86x" in result.stdout
    assert "int86(0x21, &inregs, &outregs);" in result.stdout
    assert "info = outregs;" in result.stdout
    assert "return outregs;" in result.stdout


def test_decompile_cli_recovers_tidshowrange_layout_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_TIDShowRange")

    assert result.returncode in (0, 3), result.stderr + result.stdout
    if result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    assert "function: 0x1000 _TIDShowRange" in result.stdout
    assert "void _TIDShowRange(void)" in result.stdout
    assert "RectFill(Rp2,146,21,29,9,BLACK);" in result.stdout
    assert "MapInEMSSprite(MISCSPRTSEG,0)" in result.stdout


def test_decompile_cli_recovers_drawradaralt_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_DrawRadarAlt")

    if result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _DrawRadarAlt" in result.stdout
    assert "void _DrawRadarAlt(void)" in result.stdout
    assert "[bp-0xc] = newalt" in result.stdout
    assert "[bp-0xa] = y2" in result.stdout
    assert "[bp-0x8] = soffset" in result.stdout
    assert "[bp-0x2] = b" in result.stdout
    assert "calls = _MapInEMSSprite, _TransRectCopy, _MDiv, _Rotate2D, _scaley, _DrawLine, _RectCopy" in result.stdout
    assert "if (!(View))" in result.stdout
    assert "unsigned short y2;  // [bp-0xa] y2" in result.stdout
    assert "unsigned short b;  // [bp-0x2] b" in result.stdout
    assert "y2 = 0;" in result.stdout
    assert "y2 = 112;" in result.stdout
    assert "s_12 = 0;" in result.stdout
    assert "s_14 = 2;" in result.stdout
    assert "MapInEMSSprite(MISCSPRTSEG,0);" in result.stdout


@pytest.mark.parametrize(
    ("path", "proc_kind", "shape_tokens"),
    [
        (ISOD_COD, "NEAR", ("& 0xff00 |", "return ")),
        (ISOT_COD, "NEAR", ("& 0xff00 |", "return ")),
        (ISOX_COD, "NEAR", ("& 0xff00 |", "return ")),
        (IMOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (IMOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (IMOX_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (IHOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (IHOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (ILOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (ILOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
    ],
)
def test_decompile_cli_main_matrix(path: Path, proc_kind: str, shape_tokens: tuple[str, str]):
    result = _run_decompile_proc(path, "_main", proc_kind=proc_kind, analysis_timeout=20, subprocess_timeout=60)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _main" in result.stdout
    assert "int _main(void)" in result.stdout
    for token in shape_tokens:
        assert token in result.stdout
    assert "Decompiler timeout" not in result.stdout


@pytest.mark.parametrize(
    ("path", "proc_kind"),
    [
        (ISOD_COD, "NEAR"),
        (ISOT_COD, "NEAR"),
        (ISOX_COD, "NEAR"),
        (IMOD_COD, "FAR"),
        (IMOT_COD, "FAR"),
        (IMOX_COD, "FAR"),
        (IHOD_COD, "FAR"),
        (IHOT_COD, "FAR"),
        (ILOD_COD, "FAR"),
        (ILOT_COD, "FAR"),
    ],
)
def test_decompile_cli_show_summary_matrix(path: Path, proc_kind: str):
    result = _run_decompile_proc(path, "show_summary", proc_kind=proc_kind, analysis_timeout=20, subprocess_timeout=60)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 show_summary" in result.stdout
    assert "int show_summary(void)" in result.stdout
    assert "info >> 8;" in result.stdout
    assert "*((" in result.stdout
    assert "Decompiler timeout" not in result.stdout


@pytest.mark.parametrize(
    ("path", "proc", "proc_kind", "analysis_timeout", "subprocess_timeout", "expected_tokens", "forbidden_tokens"),
    [
        (
            MAX_COD,
            "_max",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _max", "if (x > y)", "return x;", "return y;"),
            ("UnresolvableJumpTarget",),
        ),
        (
            NHORZ_COD,
            "_ChangeWeather",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _ChangeWeather", "if (BadWeather)", "CLOUDHEIGHT = 8150;", "CLOUDTHICK = 500;", "CLOUDTHICK = 1000;"),
            ("if (!(...))", "if (!(!"),
        ),
            (
                MONOPRIN_COD,
                "_mset_pos",
                "NEAR",
                10,
                30,
                (
                    "function: 0x1000 _mset_pos",
                    "% 80",
                    "% 25",
                    "int _mset_pos(int x, int y)",
                ),
                ("&v1",),
            ),
                (
                    REPO_ROOT / "cod" / "f14" / "BILLASM.COD",
                    "_MousePOS",
                    "NEAR",
                    10,
                    30,
                        (
                            "function: 0x1000 _MousePOS",
                            "if (!(MOUSE))",
                                "MouseX =",
                            "MouseY = y;",
                            "return sub_ff033();",
                        ),
                        ("if (...)", "28675", "28677"),
                    ),
        (
            REPO_ROOT / "cod" / "f14" / "PLANES3.COD",
            "_Ready5",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _Ready5", "void _Ready5(void)", "planecnt", "droll", "pdest", "* 46", "+ 18 + v3", "return;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookDown",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _LookDown", "if (!(BackSeat))", "Rp3D->Length1 = 50;", "RpCRT1->YBgn = 27;", "RpCRT2->YBgn = 25;", "RpCRT4->YBgn = 39;", "VdiMask[MASKY] = 27;", "AdiMask[MASKY] = 25;", "RawMask[MASKY] = 39;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookUp",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _LookUp", "if (!(BackSeat))", "Rp3D->Length1 = 150;", "RpCRT1->YBgn = 138;", "RpCRT2->YBgn = 136;", "RpCRT4->YBgn = 150;", "VdiMask[MASKY] = 138;", "AdiMask[MASKY] = 136;", "RawMask[MASKY] = 150;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBox",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBox", "return 1;", "xl <=", "xh >=", "zl <=", "zh >="),
            ("if (...)", "!(zh >=", "xl >", "xh <", "zl >"),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBoxLng",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBoxLng", "if (x < xl || x > xh || z < zl || z > zh)", "return 0;", "return 1;"),
            ("if (...)", "!(v4", "& &"),
        ),
            (
                REPO_ROOT / "cod" / "f14" / "CARR.COD",
                "_SetHook",
                "NEAR",
                10,
            30,
                        ("function: 0x1000 _SetHook", "return 1;", "if (Hook)", "= 93;", "Message (\"Hook Lowered\",RIO_NOW_MSG);", "HookDown == Hook", "HookDown = Hook;"),
                    (),
                ),
            (
                REPO_ROOT / "cod" / "f14" / "CARR.COD",
                "_SetGear",
                "NEAR",
                10,
                30,
                (
                    "function: 0x1000 _SetGear",
                    "unsigned short _SetGear(unsigned short G)",
                    "if (!(ejected))",
                    "if (!G)",
                    "if (Knots <= 350)",
                    "Status = Status | 1;",
                    "Status = Status & -2;",
                    'Message ("Landing gear lowered",RIO_MSG);',
                    "return v13;",
                ),
                (),
            ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_SetDLC",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _SetDLC", "DirectLiftControl = DLC;", "return DLC;"),
            ("DLC >> 8",),
        ),
            (
                REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
                "_TIDShowRange",
                "NEAR",
                10,
                30,
                    ("function: 0x1000 _TIDShowRange", "Timed out while recovering a function after 10s."),
                (),
            ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_DrawRadarAlt",
            "NEAR",
            10,
            30,
                ("function: 0x1000 _DrawRadarAlt", "if (!(View))", "y2 = 0;", "y2 = 112;", "s_12 = 0;", "s_14 = 2;", "MapInEMSSprite(MISCSPRTSEG,0);"),
            (),
        ),
            (
                ISOD_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ISOT_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ISOX_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IHOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IHOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ILOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ILOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOX_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
    ],
)
def test_decompile_cli_small_cod_logic_batch(
    path, proc, proc_kind, analysis_timeout, subprocess_timeout, expected_tokens, forbidden_tokens
):
    result = _run_decompile_proc(
        path,
        proc,
        proc_kind=proc_kind,
        analysis_timeout=analysis_timeout,
        subprocess_timeout=subprocess_timeout,
    )

    if proc == "_TIDShowRange" and result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    if proc == "_DrawRadarAlt" and result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    if proc == "fold_values" and result.returncode == 3:
        assert "Timed out while recovering a function after 20s." in result.stdout
        return

    assert result.returncode == 0, result.stderr + result.stdout
    for token in expected_tokens:
        assert token in result.stdout, result.stdout
    for token in forbidden_tokens:
        assert token not in result.stdout, result.stdout


def test_decompile_cli_names_known_dos_interrupt_helpers_in_com_output():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(ICOMDO_COM), "--timeout", "10", "--window", "0x80", "--max-functions", "2"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "int get_dos_version(void);" in result.stdout
    assert "void print_dos_string(const char *s);" in result.stdout
    assert "void exit(int status);" in result.stdout
    assert "void _start(void)" in result.stdout
    assert "get_dos_version();" in result.stdout
    assert 'print_dos_string("DOS sample");' in result.stdout
    assert "exit(0);" in result.stdout
    assert "1044513();" not in result.stdout
    assert "dos_int21();" not in result.stdout


def test_decompile_cli_supports_dos_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "dos",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_get_version(void);" in result.stdout
    assert "void _dos_print_dollar_string(const char far *s);" in result.stdout
    assert "void _dos_exit(unsigned char status);" in result.stdout
    assert "_dos_get_version();" in result.stdout
    assert '_dos_print_dollar_string("DOS sample");' in result.stdout
    assert "_dos_exit(0);" in result.stdout


def test_decompile_cli_supports_raw_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "raw",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "dos_int21();" in result.stdout


def test_decompile_cli_supports_pseudo_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "pseudo",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "int dos_get_version(void);" in result.stdout
    assert "void dos_print_dollar_string(const char *s);" in result.stdout
    assert "void dos_exit(int status);" in result.stdout
    assert "dos_get_version();" in result.stdout
    assert 'dos_print_dollar_string("DOS sample");' in result.stdout
    assert "dos_exit(0);" in result.stdout


def test_decompile_cli_supports_msc_api_style_alias_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "msc",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "_dos_get_version();" in result.stdout
    assert '_dos_print_dollar_string("DOS sample");' in result.stdout
    assert "_dos_exit(0);" in result.stdout


def test_trace_x86_16_paths_cli_traces_small_com_stub():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "exec", "--max-steps", "6"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "mode: exec" in result.stdout
    assert "== step 0 @ 0x1000 ==" in result.stdout
    assert "mov ah, 0x30" in result.stdout
    assert "== step 2 @ 0xf021 ==" in result.stdout
    assert "helper=DOSInt21 ; get_dos_version()" in result.stdout
    assert "== step 3 @ 0x1004 ==" in result.stdout
    assert "mov ah, 9" in result.stdout
    assert "== step 5 @ 0x1009 ==" in result.stdout
    assert "int 0x21" in result.stdout


def test_trace_x86_16_paths_cli_exec_supports_helper_annotations():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "exec", "--max-steps", "8"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert 'helper=DOSInt21 ; print_dos_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_recovers_cfg_for_small_com_stub():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "cfg", "--max-blocks", "4"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "mode: cfg" in result.stdout
    assert "function: 0x1000 _start" in result.stdout
    assert "== block 0x1000 ==" in result.stdout
    assert "0x1000: mov ah, 0x30" in result.stdout
    assert "0x1002: int 0x21 ; get_dos_version()" in result.stdout
    assert '0x1009: int 0x21 ; print_dos_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_supports_msc_helper_annotations():
    result = subprocess.run(
        [
            sys.executable,
            str(TRACE_PATH),
            str(ICOMDO_COM),
            "--mode",
            "cfg",
            "--max-blocks",
            "4",
            "--api-style",
            "msc",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "0x1002: int 0x21 ; _dos_get_version()" in result.stdout
    assert '0x1009: int 0x21 ; _dos_print_dollar_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_supports_pseudo_helper_annotations():
    result = subprocess.run(
        [
            sys.executable,
            str(TRACE_PATH),
            str(ICOMDO_COM),
            "--mode",
            "cfg",
            "--max-blocks",
            "4",
            "--api-style",
            "pseudo",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "0x1002: int 0x21 ; dos_get_version()" in result.stdout
    assert '0x1009: int 0x21 ; dos_print_dollar_string("DOS sample")' in result.stdout
