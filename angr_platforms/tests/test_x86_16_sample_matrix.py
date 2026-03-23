from __future__ import annotations

import json
import logging
from pathlib import Path

import angr
import pytest

from angr_platforms.X86_16.analysis_helpers import collect_direct_far_call_targets, extend_cfg_for_far_calls
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.load_dos_mz import DOSMZ  # noqa: F401


MATRIX_DIR = Path(__file__).resolve().parents[1] / "x16_samples"
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
    project = angr.Project(MATRIX_DIR / binary_name)
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + window)],
        normalize=True,
        force_complete_scan=False,
    )
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

    assert len(far_targets) >= 11
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
    assert function.get_call_target(0x120F) == 0x161F


def test_small_model_entry_function_decompiles_in_bounded_window():
    recovered_c = _decompile_entry_function("ISOD.EXE")

    assert recovered_c is not None
    assert "520" in recovered_c


def test_medium_model_entry_function_decompiles_in_bounded_window():
    recovered_c = _decompile_entry_function("IMOD.EXE")

    assert recovered_c is not None
    assert "526" in recovered_c
    assert "sub_1380()" in recovered_c
    assert "sub_161f()" in recovered_c


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
    assert "Call site 0x1209" not in warning_text
