from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
TRACE_PATH = REPO_ROOT / "angr_platforms" / "scripts" / "trace_x86_16_paths.py"
MONOPRIN_COD = REPO_ROOT / "cod" / "f14" / "MONOPRIN.COD"
NHORZ_COD = REPO_ROOT / "cod" / "f14" / "NHORZ.COD"
MAX_COD = REPO_ROOT / "cod" / "default" / "MAX.COD"
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
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "unsigned short x;  // [bp+0x4] x" in result.stdout
    assert "unsigned short y;  // [bp+0x6] y" in result.stdout
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
    assert "int _ChangeWeather" in result.stdout
    assert "globals = _CLOUDHEIGHT, _CLOUDTHICK" in result.stdout
    assert "extern unsigned short BadWeather;" in result.stdout
    assert "extern unsigned short CLOUDHEIGHT;" in result.stdout
    assert "extern unsigned short CLOUDTHICK;" in result.stdout
    assert "extern char g_" not in result.stdout
    assert "if (BadWeather)" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "if (!(!" not in result.stdout
    assert "BadWeather = 0;" in result.stdout
    assert "BadWeather = 1;" in result.stdout
    assert "CLOUDHEIGHT = 8150;" in result.stdout
    assert "CLOUDTHICK = 500;" in result.stdout
    assert "CLOUDHEIGHT = 125;" in result.stdout
    assert "CLOUDTHICK = 1000;" in result.stdout
    assert "0x7000" not in result.stdout
    assert "_start" not in result.stdout


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
    assert "unsigned short x;  // [bp+0x4] x" in result.stdout
    assert "unsigned short y;  // [bp+0x6] y" in result.stdout
    assert "if (x > y)" in result.stdout
    assert "return x;" in result.stdout
    assert "return y;" in result.stdout


def test_decompile_cli_recovers_small_cod_byte_condition_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_MousePOS")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _MousePOS" in result.stdout
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "unsigned short x;  // [bp+0x4] x" in result.stdout
    assert "unsigned short y;  // [bp+0x6] y" in result.stdout
    assert "globals = _MOUSE, _MouseX, _MouseY" in result.stdout
    assert "if (!(MOUSE))" in result.stdout
    assert "if (...)" not in result.stdout
    assert "&v1" not in result.stdout
    assert "return 0;" in result.stdout
    assert "v4 - v4" not in result.stdout
    assert "* 2" in result.stdout
    assert "MouseX = v5;" in result.stdout
    assert "MouseY = y;" in result.stdout
    assert "0x7000" not in result.stdout
    assert "28675" not in result.stdout
    assert "28677" not in result.stdout


def test_decompile_cli_recovers_configcrts_copy_loop():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_ConfigCrts")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _ConfigCrts" in result.stdout
    assert "unsigned short _ConfigCrts(void)" in result.stdout
    assert "do" in result.stdout
    assert "flag * 2" in result.stdout
    assert "546 + v5" in result.stdout
    assert "flag < 8" in result.stdout


def test_decompile_cli_recovers_rotate_pt_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_rotate_pt")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _rotate_pt" in result.stdout
    assert "int _rotate_pt()" in result.stdout
    assert "[bp+0x4] = s" in result.stdout
    assert "[bp+0x6] = d" in result.stdout
    assert "[bp-0x4] = y" in result.stdout
    assert "[bp-0x2] = x" in result.stdout
    assert "unsigned short s;  // [bp+0x2] s" in result.stdout
    assert "unsigned short d;  // [bp+0x6] d" in result.stdout
    assert "unsigned short y;  // [bp-0x4] y" in result.stdout
    assert "char x;  // [bp-0x2] x" in result.stdout
    assert "calls = _CosB, _SinB" in result.stdout
    assert "unsigned short d;  // [bp+0x6] d" in result.stdout
    assert "d * -1" in result.stdout
    assert "0 + v12" in result.stdout
    assert "2 + v12" in result.stdout
    assert "sub_101f();" in result.stdout


def test_decompile_cli_recovers_sethook_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetHook")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetHook" in result.stdout
    assert "int _SetHook()" in result.stdout
    assert "[bp+0x4] = Hook" in result.stdout
    assert "globals = _HookDown" in result.stdout
    assert "calls = _Message" in result.stdout
    assert "extern unsigned short HookDown;" in result.stdout
    assert "extern char g_" not in result.stdout
    assert "unsigned short Hook;  // [bp+0x2] Hook" in result.stdout
    assert "unsigned short v0;  // [bp-0x6]" in result.stdout
    assert "unsigned short v1;  // [bp-0x4]" in result.stdout
    assert "unsigned short v2;  // [bp-0x2]" in result.stdout
    assert "_Message();" in result.stdout
    assert "sub_102f();" not in result.stdout
    assert "HookDown == Hook" in result.stdout
    assert "HookDown = Hook;" in result.stdout
    assert "v2 = &v3;" in result.stdout
    assert "v1 = 5;" in result.stdout
    assert "v0 = v8;" in result.stdout
    assert "v5 * 16" not in result.stdout
    assert "!= Hook" not in result.stdout
    assert "return 1;" in result.stdout
    assert "Hook >> 8" not in result.stdout
    assert "v8 = 93;" in result.stdout
    assert "v8 = 106;" in result.stdout


def test_decompile_cli_recovers_setgear_guard_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetGear")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetGear" in result.stdout
    assert "int _SetGear()" in result.stdout
    assert "[bp+0x4] = G" in result.stdout
    assert "globals = _ejected, _Status, _Knots, _Alt, _MinAlt, _Damaged" in result.stdout
    assert "extern char Status[4];" in result.stdout
    assert "extern char g_" not in result.stdout
    assert "unsigned short G;  // [bp+0x2] G" in result.stdout
    assert "unsigned short v0;  // [bp-0x6]" in result.stdout
    assert "unsigned short v1;  // [bp-0x4]" in result.stdout
    assert "unsigned short v2;  // [bp-0x2]" in result.stdout
    assert "if (!(ejected))" in result.stdout
    assert "Status" in result.stdout
    assert "Alt" in result.stdout
    assert "MinAlt" in result.stdout
    assert "Damaged" in result.stdout
    assert "v12 = Alt;" in result.stdout
    assert "MinAlt != v12" in result.stdout
    assert "Knots <= 350" in result.stdout
    assert "!(!(" not in result.stdout
    assert "28679" not in result.stdout
    assert "* 0x100" not in result.stdout
    assert "v2 = &v3;" in result.stdout
    assert "v1 = 2;" in result.stdout
    assert "v0 = v14;" in result.stdout
    assert "v5 * 16" not in result.stdout
    assert "350" in result.stdout
    assert "v14 = 73;" in result.stdout
    assert "v14 = 52;" in result.stdout
    assert "_Message();" in result.stdout
    assert "sub_102f();" not in result.stdout


def test_decompile_cli_recovers_setdlc_state_store():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetDLC")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetDLC" in result.stdout
    assert "int _SetDLC()" in result.stdout
    assert "[bp+0x4] = DLC" in result.stdout
    assert "unsigned short DLC;  // [bp+0x4] DLC" in result.stdout
    assert "globals = _DirectLiftControl" in result.stdout
    assert "extern unsigned short DirectLiftControl;" in result.stdout
    assert "DirectLiftControl = DLC;" in result.stdout
    assert "DLC >> 8" not in result.stdout
    assert "return DLC;" in result.stdout


def test_decompile_cli_recovers_tidshowrange_layout_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_TIDShowRange")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _TIDShowRange" in result.stdout
    assert "int _TIDShowRange(void)" in result.stdout
    assert "[bp-0xc] = mseg" in result.stdout
    assert "globals = _Rp2, _Tscale, _Rp1" in result.stdout
    assert "char mseg;  // [bp-0xc] mseg" in result.stdout
    assert "0x7000" in result.stdout
    assert "28674" in result.stdout
    assert "146" in result.stdout
    assert "21" in result.stdout
    assert "29" in result.stdout
    assert "9" in result.stdout
    assert "782" in result.stdout
    assert "* 2" in result.stdout
    assert "sub_103b();" in result.stdout


def test_decompile_cli_recovers_drawradaralt_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_DrawRadarAlt")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _DrawRadarAlt" in result.stdout
    assert "int _DrawRadarAlt(void)" in result.stdout
    assert "[bp-0xc] = newalt" in result.stdout
    assert "[bp-0xa] = y2" in result.stdout
    assert "[bp-0x8] = soffset" in result.stdout
    assert "[bp-0x2] = b" in result.stdout
    assert "calls = _MapInEMSSprite, _TransRectCopy, _MDiv, _Rotate2D, _scaley, _DrawLine, _RectCopy" in result.stdout
    assert "if (!(*((short *)" in result.stdout
    assert "unsigned short y2;  // [bp-0xa] y2" in result.stdout
    assert "char b;  // [bp-0x2] b" in result.stdout
    assert "y2 = 0;" in result.stdout
    assert "y2 = 112;" in result.stdout
    assert ")) = 2;" in result.stdout
    assert "sub_1023();" in result.stdout


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
    assert "* 0x100) >> 8;" in result.stdout
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
            ("function: 0x1000 _mset_pos", "% 80", "% 25", "unsigned short x;  // [bp+0x4] x"),
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
                "* 2",
                "unsigned short x;  // [bp+0x4] x",
                "unsigned short y;  // [bp+0x6] y",
                "MouseX = v5;",
                "MouseY = y;",
            ),
            ("if (...)", "28675", "28677"),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "PLANES3.COD",
            "_Ready5",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _Ready5", "planecnt", "droll", "pdest", "* 46", "+ 18 + v3", "return"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookDown",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _LookDown", "if (!(BackSeat))", "Rp3D", "RpCRT1", "RpCRT2", "RpCRT4", "50", "27", "25", "39"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookUp",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _LookUp", "if (!(BackSeat))", "Rp3D", "RpCRT1", "RpCRT2", "RpCRT4", "150", "138", "136", "139"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBox",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBox", "return 1;", "a2 > v9", "a4 < v9"),
            ("if (...)",),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_SetHook",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _SetHook", "return 1;", "v8 = 93;", "v8 = 106;", "_Message();", "HookDown == Hook", "HookDown = Hook;", "v1 = 5;", "v0 = v8;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_SetGear",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _SetGear", "if (!(ejected))", "Status", "Alt", "MinAlt", "Damaged", "350", "v14 = 73;", "v14 = 52;", "_Message();", "v1 = 2;", "v0 = v14;"),
            ("v5 * 16",),
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
            ("function: 0x1000 _TIDShowRange", "mseg", "Rp2", "Tscale * 2", "146", "21", "29", "9", "782", "sub_103b();"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_DrawRadarAlt",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _DrawRadarAlt", "if (!(*((short *)", "y2 = 0;", "y2 = 112;", ")) = 2;", "sub_1023();"),
            (),
        ),
        (
            ISOD_COD,
            "fold_values",
            "NEAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            IMOD_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            ISOT_COD,
            "fold_values",
            "NEAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            ISOX_COD,
            "fold_values",
            "NEAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            IHOD_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            IHOT_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            ILOD_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            ILOT_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            IMOT_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
            (),
        ),
        (
            IMOX_COD,
            "fold_values",
            "FAR",
            20,
            60,
            ("function: 0x1000 fold_values", "123", "return"),
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
    assert "int _start(void)" in result.stdout
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
