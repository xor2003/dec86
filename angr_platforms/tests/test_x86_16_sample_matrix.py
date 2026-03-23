from __future__ import annotations

import json
import logging
from pathlib import Path
import sys

import angr
import pytest

from angr_platforms.X86_16.analysis_helpers import (
    collect_direct_far_call_targets,
    collect_dos_int21_calls,
    extend_cfg_for_far_calls,
    infer_com_region,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.load_dos_mz import DOSMZ  # noqa: F401


MATRIX_DIR = Path(__file__).resolve().parents[1] / "x16_samples"
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import decompile

MANIFEST_PATH = MATRIX_DIR / "matrix_manifest.json"
EXPECTED_EXE_VARIANTS = {
    ("ISOD", "small", "/Od"),
    ("ISOT", "small", "/Ot"),
    ("ISOX", "small", "/Ox"),
    ("IMOD", "medium", "/Od"),
    ("IMOT", "medium", "/Ot"),
    ("IMOX", "medium", "/Ox"),
    ("ILOD", "large", "/Od"),
    ("ILOT", "large", "/Ot"),
    ("IHOD", "huge", "/Od"),
    ("IHOT", "huge", "/Ot"),
}
EXPECTED_COM_VARIANTS = {
    ("ICOMDO", "tiny", "n/a"),
    ("ICOMBI", "tiny", "n/a"),
}


def _load_manifest():
    return json.loads(MANIFEST_PATH.read_text())


def _decompile_entry_function(binary_name: str, window: int = 0x200):
    path = MATRIX_DIR / binary_name
    if binary_name.lower().endswith(".com"):
        project = angr.Project(
            path,
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": 0x1000,
                "entry_point": 0x1000,
            },
            simos="DOS",
        )
        regions = [infer_com_region(path, base_addr=0x1000, window=window, arch=project.arch)]
    else:
        project = angr.Project(path)
        regions = [(project.entry, project.entry + window)]

    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    if project.arch.name == "86_16":
        extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=window)
        if extended_cfg is not None and project.entry in extended_cfg.functions:
            cfg = extended_cfg

    function = cfg.functions[project.entry]
    dec = project.analyses.Decompiler(function, cfg=cfg)
    return dec.codegen.text if dec.codegen is not None else None


@pytest.mark.skipif(not MANIFEST_PATH.exists(), reason="sample matrix manifest is not available")
def test_sample_matrix_manifest_has_expected_variant_mix():
    entries = _load_manifest()
    exe_entries = [entry for entry in entries if entry["format"] == "exe"]
    com_entries = [entry for entry in entries if entry["format"] == "com"]
    exe_variants = {(entry["id"], entry["memory_model"], entry["optimization"]) for entry in exe_entries}
    com_variants = {(entry["id"], entry["memory_model"], entry["optimization"]) for entry in com_entries}

    assert len(exe_entries) == 10
    assert len(com_entries) == 2
    assert exe_variants == EXPECTED_EXE_VARIANTS
    assert com_variants == EXPECTED_COM_VARIANTS

    for entry in exe_entries:
        assert (MATRIX_DIR / entry["binary"]).exists()
        assert (MATRIX_DIR / entry["object"]).exists()
        assert (MATRIX_DIR / entry["cod"]).exists()
        assert (MATRIX_DIR / entry["map"]).exists()
        assert entry["source"] == "IDEMO.C"
        assert entry["compiler"] == "msc510"

    for entry in com_entries:
        assert (MATRIX_DIR / entry["binary"]).exists()
        assert (MATRIX_DIR / entry["listing"]).exists()
        assert entry["compiler"] == "uasm"


@pytest.mark.skipif(not MANIFEST_PATH.exists(), reason="sample matrix manifest is not available")
def test_msc_exe_variants_load_with_dos_mz_backend():
    entries = _load_manifest()

    for entry in entries:
        if entry["format"] != "exe":
            continue

        project = angr.Project(MATRIX_DIR / entry["binary"])
        cod_text = (MATRIX_DIR / entry["cod"]).read_text(errors="ignore")
        block = project.factory.block(project.entry, size=16)
        asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

        assert isinstance(project.loader.main_object, DOSMZ)
        assert project.arch.name == "86_16"
        assert "_main" in cod_text.lower()
        assert "idemo.c" in cod_text.lower()
        assert any(name in cod_text.lower() for name in ("_int86", "_int86x", "int86", "int86x"))
        assert "int 0x21" in asm


@pytest.mark.skipif(not MANIFEST_PATH.exists(), reason="sample matrix manifest is not available")
def test_com_variants_disassemble_as_real_mode_blobs():
    entries = _load_manifest()

    for entry in entries:
        if entry["format"] != "com":
            continue

        project = angr.Project(
            MATRIX_DIR / entry["binary"],
            main_opts={
                "backend": "blob",
                "arch": Arch86_16(),
                "base_addr": 0x1000,
                "entry_point": 0x1000,
            },
            simos="DOS",
        )
        block = project.factory.block(0x1000, size=16)
        asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

        assert project.arch.name == "86_16"
        assert "int " in asm


def test_small_model_rep_cmps_block_lifts():
    project = angr.Project(MATRIX_DIR / "ISOD.EXE")

    block = project.factory.block(0x1267, size=8, opt_level=0)
    asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

    assert "cmpsb" in asm
    assert block.vex.jumpkind == "Ijk_Boring"


def test_medium_model_global_add_block_lifts():
    project = angr.Project(MATRIX_DIR / "IMOD.EXE")

    block = project.factory.block(0x1682, size=4, opt_level=0)
    vex_text = block.vex._pp_str()

    assert "add word ptr [0x62], dx" in "\n".join(
        f"{insn.mnemonic} {insn.op_str}".strip().lower() for insn in block.capstone.insns
    )
    assert "Add16" in vex_text
    assert block.vex.jumpkind == "Ijk_Boring"


def test_medium_model_entry_far_call_targets_are_discoverable():
    project = angr.Project(MATRIX_DIR / "IMOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )

    far_targets = collect_direct_far_call_targets(cfg.functions[project.entry])

    assert len(far_targets) >= 12
    assert {target.target_addr for target in far_targets} >= {0x111A, 0x121E, 0x12E2, 0x1380, 0x13F4, 0x1586, 0x161F}


def test_medium_model_entry_far_call_sites_are_patched():
    project = angr.Project(MATRIX_DIR / "IMOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )
    extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=0x200)

    assert extended_cfg is not None
    function = extended_cfg.functions[project.entry]
    assert function.get_call_target(0x117E) == 0x1380
    assert function.get_call_target(0x1185) == 0x161F
    assert function.get_call_target(0x11CE) == 0x121E
    assert function.get_call_target(0x11D5) == 0x1586
    assert function.get_call_target(0x11DC) == 0x13F4
    assert function.get_call_target(0x11E1) == 0x111A
    assert function.get_call_target(0x11F4) == 0x12E2
    assert function.get_call_target(0x11FA) == 0x1380
    assert function.get_call_target(0x1209) == 0x1380
    assert function.get_call_target(0x120F) == 0x161F
    assert function.get_call_target(0x1214) == 0x12E2


def test_small_model_entry_function_decompiles_in_bounded_window():
    recovered_c = _decompile_entry_function("ISOD.EXE")

    assert recovered_c is not None
    assert "520" in recovered_c


def test_small_model_entry_dos_int21_calls_are_recoverable():
    project = angr.Project(MATRIX_DIR / "ISOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1146],
        regions=[(0x1146, 0x1146 + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1146]

    calls = collect_dos_int21_calls(function, MATRIX_DIR / "ISOD.EXE")

    assert [call.insn_addr for call in calls] == [0x1148, 0x117A, 0x11A2]
    assert [call.ah for call in calls] == [0x30, 0x4C, 0x4A]


def test_small_model_entry_dos_int21_calls_map_to_named_helpers():
    project = angr.Project(MATRIX_DIR / "ISOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1146],
        regions=[(0x1146, 0x1146 + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1146]

    replacements = decompile._int21_call_replacements(project, function, "modern", MATRIX_DIR / "ISOD.EXE")

    assert replacements == ["get_dos_version()", "exit(255)", "resize_dos_memory_block()"]


def test_medium_model_entry_function_decompiles_in_bounded_window():
    recovered_c = _decompile_entry_function("IMOD.EXE")

    assert recovered_c is not None
    assert "526" in recovered_c
    assert "sub_1380()" in recovered_c
    assert "sub_161f()" in recovered_c


def test_com_entry_function_decompiles_without_trailing_data_junk():
    recovered_c = _decompile_entry_function("ICOMDO.COM", window=0x80)

    assert recovered_c is not None
    assert "field_61" not in recovered_c
    assert "insw" not in recovered_c


def test_medium_model_far_call_sites_stop_logging_unknown_cc(caplog):
    project = angr.Project(MATRIX_DIR / "IMOD.EXE")
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + 0x200)],
        normalize=True,
        force_complete_scan=False,
    )
    extended_cfg = extend_cfg_for_far_calls(project, cfg.functions[project.entry], entry_window=0x200)
    assert extended_cfg is not None

    with caplog.at_level(logging.WARNING):
        function = extended_cfg.functions[project.entry]
        project.analyses.Decompiler(function, cfg=extended_cfg)

    warning_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "Call site 0x117e" not in warning_text
    assert "Call site 0x1185" not in warning_text
    assert "Call site 0x11ce" not in warning_text
    assert "Call site 0x11d5" not in warning_text
    assert "Call site 0x11dc" not in warning_text
    assert "Call site 0x11e1" not in warning_text
    assert "Call site 0x11f4" not in warning_text
    assert "Call site 0x11fa" not in warning_text
    assert "Call site 0x1209" not in warning_text
    assert "Call site 0x1214" not in warning_text


def test_synthetic_com_dos_file_services_map_to_named_helpers(tmp_path):
    code = bytearray(
        [
            0xB4,
            0x3D,  # mov ah, 3Dh
            0xB0,
            0x01,  # mov al, 1
            0xBA,
            0x30,
            0x01,  # mov dx, 130h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x3C,  # mov ah, 3Ch
            0xB9,
            0x20,
            0x00,  # mov cx, 20h
            0xBA,
            0x40,
            0x01,  # mov dx, 140h
            0xCD,
            0x21,  # int 21h
            0xB4,
            0x3E,  # mov ah, 3Eh
            0xBB,
            0x42,
            0x00,  # mov bx, 42h
            0xCD,
            0x21,  # int 21h
            0xB8,
            0x00,
            0x4C,  # mov ax, 4C00h
            0xCD,
            0x21,  # int 21h
        ]
    )
    while len(code) < 0x30:
        code.append(0)
    code.extend(b"INPUT.TXT\x00")
    while len(code) < 0x40:
        code.append(0)
    code.extend(b"OUTPUT.BIN\x00")

    binary_path = tmp_path / "dos_file_calls.com"
    binary_path.write_bytes(bytes(code))

    project = angr.Project(
        binary_path,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        simos="DOS",
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1020)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function, binary_path)
    modern = decompile._int21_call_replacements(project, function, "modern", binary_path)
    dos = decompile._int21_call_replacements(project, function, "dos", binary_path)
    modern_decls = decompile._dos_helper_declarations(function, "modern", binary_path)
    dos_decls = decompile._dos_helper_declarations(function, "dos", binary_path)

    assert [call.ah for call in calls] == [0x3D, 0x3C, 0x3E, 0x4C]
    assert modern == [
        'open("INPUT.TXT", 1)',
        'creat("OUTPUT.BIN", 0x20)',
        "close(0x42)",
        "exit(0)",
    ]
    assert dos == [
        '_dos_open("INPUT.TXT", 1)',
        '_dos_creat("OUTPUT.BIN", 0x20)',
        "_dos_close(0x42)",
        "_dos_exit(0)",
    ]
    assert "int open(const char *path, int oflag);" in modern_decls
    assert "int creat(const char *path, int attrs);" in modern_decls
    assert "int close(int fd);" in modern_decls
    assert "int _dos_open(const char far *path, unsigned char mode);" in dos_decls
    assert "int _dos_creat(const char far *path, unsigned short attrs);" in dos_decls
    assert "int _dos_close(unsigned short handle);" in dos_decls


def test_synthetic_bp_based_dos_open_call_recovers_argument_shapes(tmp_path):
    code = bytes(
        [
            0x55,  # push bp
            0x89,
            0xE5,  # mov bp, sp
            0xB4,
            0x3D,  # mov ah, 3Dh
            0x8A,
            0x46,
            0x06,  # mov al, [bp+6]
            0x8B,
            0x56,
            0x04,  # mov dx, [bp+4]
            0xCD,
            0x21,  # int 21h
            0xC3,  # ret
        ]
    )
    binary_path = tmp_path / "bp_open.bin"
    binary_path.write_bytes(code)

    project = angr.Project(
        binary_path,
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1010)],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[0x1000]

    calls = collect_dos_int21_calls(function)
    modern = decompile._int21_call_replacements(project, function, "modern", None)
    dos = decompile._int21_call_replacements(project, function, "dos", None)

    assert len(calls) == 1
    assert calls[0].ah == 0x3D
    assert calls[0].al_expr == "[bp+6]"
    assert calls[0].dx_expr == "[bp+4]"
    assert modern == ["open((const char *)[bp+4], [bp+6])"]
    assert dos == ["_dos_open((const char far *)[bp+4], [bp+6])"]
