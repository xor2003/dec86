from __future__ import annotations

from pathlib import Path

import angr
import pytest
import pyvex

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.load_dos_mz import DOSMZ  # noqa: F401
from angr_platforms.X86_16.simos_86_16 import DOS_INT21_ADDR, DOSInt21


T_EXE_PATH = Path("/home/xor/games/f15se2-re/T.EXE")
T_COD_PATH = Path("/home/xor/games/f15se2-re/T.COD")


def _read_mz_header(path: Path) -> dict[str, int]:
    data = path.read_bytes()[:0x40]
    return {
        "header_paragraphs": int.from_bytes(data[0x08:0x0A], "little"),
        "ss": int.from_bytes(data[0x0E:0x10], "little"),
        "sp": int.from_bytes(data[0x10:0x12], "little"),
        "ip": int.from_bytes(data[0x14:0x16], "little"),
        "cs": int.from_bytes(data[0x16:0x18], "little"),
    }


@pytest.mark.skipif(not T_EXE_PATH.exists(), reason="f15se2-re test executable is not available")
def test_dos_mz_backend_loads_real_executable():
    header = _read_mz_header(T_EXE_PATH)
    project = angr.Project(T_EXE_PATH)
    load_segment = project.loader.main_object.mz_load_segment

    assert isinstance(project.loader.main_object, DOSMZ)
    assert isinstance(project.arch, Arch86_16)
    assert project.loader.main_object.os == "DOS"
    assert project.loader.main_object.mz_image_offset == header["header_paragraphs"] * 0x10
    assert project.loader.main_object.initial_register_values == {
        "cs": header["cs"] + load_segment,
        "ip": header["ip"],
        "ss": header["ss"] + load_segment,
        "sp": header["sp"],
    }
    assert project.entry == project.loader.main_object.linked_base + (header["cs"] << 4) + header["ip"]


@pytest.mark.skipif(not T_EXE_PATH.exists(), reason="f15se2-re test executable is not available")
def test_dos_mz_entry_block_lifts_under_x86_16():
    project = angr.Project(T_EXE_PATH)

    block = project.factory.block(project.entry, size=8)
    asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

    assert "mov ah, 0x30" in asm
    assert "int 0x21" in asm


@pytest.mark.skipif(not T_EXE_PATH.exists(), reason="f15se2-re test executable is not available")
def test_dos_mz_entry_block_routes_int21_to_synthetic_call():
    project = angr.Project(T_EXE_PATH)

    block = project.factory.block(project.entry, size=8, opt_level=0)

    assert block.vex.jumpkind == "Ijk_Call"
    assert isinstance(block.vex.next, pyvex.expr.Const)
    assert block.vex.next.con.value == 0xFF021


@pytest.mark.skipif(not T_EXE_PATH.exists(), reason="f15se2-re test executable is not available")
def test_dos_mz_project_hooks_int21_target_as_dos_helper():
    project = angr.Project(T_EXE_PATH)

    assert project.simos.name == "DOS"
    assert project.is_hooked(DOS_INT21_ADDR)
    assert isinstance(project.hooked_by(DOS_INT21_ADDR), DOSInt21)


@pytest.mark.skipif(
    not T_EXE_PATH.exists() or not T_COD_PATH.exists(),
    reason="f15se2-re executable/COD pair is not available",
)
def test_real_executable_has_matching_cod_sidecar():
    cod_text = T_COD_PATH.read_text(errors="ignore")
    project = angr.Project(T_EXE_PATH)

    assert ";|*** int add(int a, int b)" in cod_text
    assert "_add\tPROC NEAR" in cod_text
    assert project.loader.main_object.binary_basename == "T.EXE"
