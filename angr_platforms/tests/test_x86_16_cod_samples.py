import io
import re
import signal
import sys
from pathlib import Path

import angr
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401


_ROOT = Path(__file__).resolve().parents[2]
_COD_DIR = _ROOT / "cod"
_F14_COD_DIR = _COD_DIR / "f14"
_X16_SAMPLES_DIR = Path(__file__).resolve().parents[1] / "x16_samples"
BDA_KEYBOARD_FLAGS_LINEAR = 0x417  # 0x40:0x17 in the BIOS Data Area.


def _project_from_bytes(code: bytes):
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def _extract_cod_function(cod_name: str, proc_name: str, cod_dir: Path | None = None, proc_kind: str = "NEAR"):
    base_dir = _COD_DIR if cod_dir is None else cod_dir
    lines = (base_dir / cod_name).read_text(errors="ignore").splitlines()
    start_marker = f"{proc_name}\tPROC {proc_kind}"
    end_marker = f"{proc_name}\tENDP"

    collect = False
    entries = []
    for line in lines:
        if start_marker in line:
            collect = True
            continue
        if collect and end_marker in line:
            break
        if not collect:
            continue

        match = re.search(r"\*\*\*\s+([0-9A-Fa-f]+)\s+((?:[0-9A-Fa-f]{2}\s+)+)(.*)$", line)
        if not match:
            continue

        entries.append(
            {
                "offset": int(match.group(1), 16),
                "bytes": bytes.fromhex("".join(match.group(2).split())),
                "text": match.group(3).strip(),
            }
        )

    assert entries, f"did not find {proc_name} in {cod_name}"
    return entries


def _join_entries(entries, start_offset=None, end_offset=None):
    return b"".join(
        entry["bytes"]
        for entry in entries
        if (start_offset is None or start_offset <= entry["offset"])
        and (end_offset is None or entry["offset"] < end_offset)
    )


class _TimeoutExpired(Exception):
    pass


def _raise_timeout(_signum, _frame):
    raise _TimeoutExpired("timed out while analyzing BIOS .COD sample")


def test_cod_extractor_identifies_relocation_free_and_relocated_samples():
    bios_entries = _extract_cod_function("BIOSFUNC.COD", "_bios_clearkeyflags")
    bios_bytes = _join_entries(bios_entries)

    compiler_entries = _extract_cod_function("output_Od_Gs.COD", "_compiler_idiom_test_suite")
    compiler_bytes = _join_entries(compiler_entries)

    assert bios_bytes.hex() == "558bec83ec04c746fc1704c746fe00002bdb8ec3bb1704268c078be55dc3"
    assert b"\xe8\x00\x00" not in bios_bytes
    assert compiler_bytes.find(b"\xe8\x00\x00") == 0x160


def test_bios_cod_sample_decompilation():
    bios_entries = _extract_cod_function("BIOSFUNC.COD", "_bios_clearkeyflags")
    project = _project_from_bytes(_join_entries(bios_entries))

    old_handler = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(5)
    try:
        cfg = project.analyses.CFGFast(normalize=True)
        dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    assert dec.codegen is not None
    assert any(token in dec.codegen.text for token in ("g_417", str(BDA_KEYBOARD_FLAGS_LINEAR)))
    assert "return" in dec.codegen.text


def test_compiler_idiom_prefix_lifts_from_cod_bytes():
    compiler_entries = _extract_cod_function("output_Od_Gs.COD", "_compiler_idiom_test_suite")
    # This relocation-free prefix covers `result = param_int * 2; temp_val = 10;`.
    prefix = _join_entries(compiler_entries, start_offset=0x9, end_offset=0x16)
    project = _project_from_bytes(prefix)

    irsb = project.factory.block(0x1000, len(prefix)).vex

    assert "Shl16" in irsb._pp_str()


def test_sample_matrix_fold_values_decompilation_from_cod_bytes():
    fold_entries = _extract_cod_function("ISOD.COD", "fold_values", cod_dir=_X16_SAMPLES_DIR)
    project = _project_from_bytes(_join_entries(fold_entries))

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert dec.codegen is not None
    assert "123" in dec.codegen.text
    assert "return" in dec.codegen.text


def test_far_sample_matrix_fold_values_decompilation_from_cod_bytes():
    fold_entries = _extract_cod_function("IMOD.COD", "fold_values", cod_dir=_X16_SAMPLES_DIR, proc_kind="FAR")
    project = _project_from_bytes(_join_entries(fold_entries))

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert dec.codegen is not None
    assert "123" in dec.codegen.text
    assert "return" in dec.codegen.text


def test_f14_overlay_loader_block_lifts_from_cod_bytes():
    overlay_entries = _extract_cod_function("OVL.COD", "_dig_load_overlay", cod_dir=_F14_COD_DIR)
    project = _project_from_bytes(_join_entries(overlay_entries))

    # This real F-14 overlay loader block used to fail on opcode 0x15 (`adc ax, imm16`).
    block = project.factory.block(0x1030)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "PUT(ax) = 0x0000" in irsb_text
    assert "PUT(flags)" in irsb_text
    assert "PUT(ip) = 0x1043" in irsb_text


def test_f14_mono_set_pos_decompilation_from_cod_bytes():
    entries = _extract_cod_function("MONOPRIN.COD", "_mset_pos", cod_dir=_F14_COD_DIR)
    project = _project_from_bytes(_join_entries(entries))

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert dec.codegen is not None
    assert "% 80" in dec.codegen.text
    assert "% 25" in dec.codegen.text
    assert "return" in dec.codegen.text


def test_f14_change_weather_decompilation_from_cod_bytes():
    entries = _extract_cod_function("NHORZ.COD", "_ChangeWeather", cod_dir=_F14_COD_DIR)
    project = _project_from_bytes(_join_entries(entries))

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert dec.codegen is not None
    for token in ("8150", "500", "125", "1000"):
        assert token in dec.codegen.text


def test_f14_ready5_decompilation_from_cod_bytes():
    entries = _extract_cod_function("PLANES3.COD", "_Ready5", cod_dir=_F14_COD_DIR)
    project = _project_from_bytes(_join_entries(entries))

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert dec.codegen is not None
    for token in ("46", "18", "return"):
        assert token in dec.codegen.text


def test_f14_config_crts_loop_block_lifts_from_cod_bytes():
    entries = _extract_cod_function("COCKPIT.COD", "_ConfigCrts", cod_dir=_F14_COD_DIR)
    project = _project_from_bytes(_join_entries(entries))

    block = project.factory.block(0x100B)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    assert "Shl16" in irsb_text
    assert "0x0222" in irsb_text
    assert "LDle:I16" in irsb_text
    assert "STle" in irsb_text
    assert "0x0008" in irsb_text


def test_f14_lookdown_decompilation_from_cod_bytes():
    entries = _extract_cod_function("COCKPIT.COD", "_LookDown", cod_dir=_F14_COD_DIR)
    project = _project_from_bytes(_join_entries(entries))

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert dec.codegen is not None
    for token in ("50", "27", "25", "39"):
        assert token in dec.codegen.text
