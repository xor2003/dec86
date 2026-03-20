from __future__ import annotations

import json
from pathlib import Path

import angr
import pytest

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
