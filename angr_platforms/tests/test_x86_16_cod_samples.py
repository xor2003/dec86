import io
import re
import signal
import sys
from dataclasses import dataclass
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


@dataclass(frozen=True)
class DecompCase:
    name: str
    cod_name: str
    proc_name: str
    original_c: str
    expected_tokens: tuple[str, ...]
    cod_dir: Path | None = None
    proc_kind: str = "NEAR"


@dataclass(frozen=True)
class BlockLiftCase:
    name: str
    cod_name: str
    proc_name: str
    block_addr: int
    original_c: str
    expected_tokens: tuple[str, ...]
    cod_dir: Path | None = None
    proc_kind: str = "NEAR"


DECOMP_CASES = (
    DecompCase(
        name="isod_fold_values",
        cod_name="ISOD.COD",
        proc_name="fold_values",
        cod_dir=_X16_SAMPLES_DIR,
        original_c="return value + 123;",
        expected_tokens=("123", "return"),
    ),
    DecompCase(
        name="imod_fold_values",
        cod_name="IMOD.COD",
        proc_name="fold_values",
        cod_dir=_X16_SAMPLES_DIR,
        proc_kind="FAR",
        original_c="return value + 123;",
        expected_tokens=("123", "return"),
    ),
    DecompCase(
        name="f14_mset_pos",
        cod_name="MONOPRIN.COD",
        proc_name="_mset_pos",
        cod_dir=_F14_COD_DIR,
        original_c="_mono_x = x % 80; _mono_y = y % 25; return 0;",
        expected_tokens=("% 80", "% 25", "return"),
    ),
    DecompCase(
        name="f14_change_weather",
        cod_name="NHORZ.COD",
        proc_name="_ChangeWeather",
        cod_dir=_F14_COD_DIR,
        original_c=(
            "if (BadWeather) { CLOUDHEIGHT=8150; CLOUDTHICK=500; } "
            "else { CLOUDHEIGHT=125; CLOUDTHICK=1000; }"
        ),
        expected_tokens=("8150", "500", "125", "1000"),
    ),
    DecompCase(
        name="f14_ready5",
        cod_name="PLANES3.COD",
        proc_name="_Ready5",
        cod_dir=_F14_COD_DIR,
        original_c="bv[planecnt].basespeed = 0; /* struct stride 46, field offset 18 */ return 0;",
        expected_tokens=("46", "18", "return"),
    ),
    DecompCase(
        name="f14_lookdown",
        cod_name="COCKPIT.COD",
        proc_name="_LookDown",
        cod_dir=_F14_COD_DIR,
        original_c="Rp3D->Length1 = 50; RpCRT1->YBgn = 27; RpCRT2->YBgn = 25; RpCRT4->YBgn = 39;",
        expected_tokens=("50", "27", "25", "39"),
    ),
    DecompCase(
        name="f14_lookup",
        cod_name="COCKPIT.COD",
        proc_name="_LookUp",
        cod_dir=_F14_COD_DIR,
        original_c=(
            "Rp3D->Length1 = 150; RpCRT1->YBgn = 138; RpCRT2->YBgn = 136; "
            "RpCRT4->YBgn = 150; else Rp3D->Length1 = 139;"
        ),
        expected_tokens=("150", "138", "136", "139"),
    ),
    DecompCase(
        name="f14_mousepos",
        cod_name="BILLASM.COD",
        proc_name="_MousePOS",
        cod_dir=_F14_COD_DIR,
        original_c="if (!MOUSE) return 0; MouseX = x << 1; MouseY = y; int 33h;",
        expected_tokens=("* 2", "return"),
    ),
)


BLOCK_LIFT_CASES = (
    BlockLiftCase(
        name="f14_overlay_loader_block",
        cod_name="OVL.COD",
        proc_name="_dig_load_overlay",
        cod_dir=_F14_COD_DIR,
        block_addr=0x1030,
        original_c="ax = 0; adc ax, 0; err = ax; if (err == 0) goto success;",
        expected_tokens=("PUT(ax) = 0x0000", "PUT(flags)", "PUT(ip) = 0x1043"),
    ),
    BlockLiftCase(
        name="f14_config_crts_loop",
        cod_name="COCKPIT.COD",
        proc_name="_ConfigCrts",
        cod_dir=_F14_COD_DIR,
        block_addr=0x100B,
        original_c="for (i = 0; i < 8; i++) { CrtDisplays[i] = CrtConfig[i]; }",
        expected_tokens=("Shl16", "0x0222", "LDle:I16", "STle", "0x0008"),
    ),
)


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


def _decompile_blob(code: bytes):
    project = _project_from_bytes(code)
    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    return dec.codegen.text


def _assert_text_contains(text: str, expected_tokens: tuple[str, ...], original_c: str):
    missing = [token for token in expected_tokens if token not in text]
    assert not missing, (
        "Recovered C no longer reflects the original source intent.\n"
        f"Original C fragment:\n{original_c}\n\n"
        f"Missing expected tokens: {missing}\n\n"
        f"Recovered C:\n{text}"
    )


def _assert_irsb_contains(irsb_text: str, expected_tokens: tuple[str, ...], original_c: str):
    missing = [token for token in expected_tokens if token not in irsb_text]
    assert not missing, (
        "Lifted VEX no longer reflects the intended source-level operation.\n"
        f"Original C fragment:\n{original_c}\n\n"
        f"Missing expected IR anchors: {missing}\n\n"
        f"Recovered IRSB:\n{irsb_text}"
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

    _assert_text_contains(
        dec.codegen.text,
        ("return",),
        "uint16 FAR *bios_keyflags = MK_FP(0x40, 0x17); *bios_keyflags = 0;",
    )
    assert any(token in dec.codegen.text for token in ("g_417", str(BDA_KEYBOARD_FLAGS_LINEAR)))


def test_compiler_idiom_prefix_lifts_from_cod_bytes():
    compiler_entries = _extract_cod_function("output_Od_Gs.COD", "_compiler_idiom_test_suite")
    # This relocation-free prefix covers `result = param_int * 2; temp_val = 10;`.
    prefix = _join_entries(compiler_entries, start_offset=0x9, end_offset=0x16)
    project = _project_from_bytes(prefix)

    irsb = project.factory.block(0x1000, len(prefix)).vex

    assert "Shl16" in irsb._pp_str()


@pytest.mark.parametrize("case", DECOMP_CASES, ids=lambda case: case.name)
def test_cod_decompilation_cases(case: DecompCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=case.cod_dir, proc_kind=case.proc_kind)
    text = _decompile_blob(_join_entries(entries))
    _assert_text_contains(text, case.expected_tokens, case.original_c)


@pytest.mark.parametrize("case", BLOCK_LIFT_CASES, ids=lambda case: case.name)
def test_cod_block_lift_cases(case: BlockLiftCase):
    entries = _extract_cod_function(case.cod_name, case.proc_name, cod_dir=case.cod_dir, proc_kind=case.proc_kind)
    project = _project_from_bytes(_join_entries(entries))
    block = project.factory.block(case.block_addr)
    irsb_text = block.vex._pp_str()

    assert block.vex.jumpkind == "Ijk_Boring"
    _assert_irsb_contains(irsb_text, case.expected_tokens, case.original_c)
