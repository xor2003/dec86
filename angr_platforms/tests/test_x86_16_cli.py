from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
TRACE_PATH = REPO_ROOT / "angr_platforms" / "scripts" / "trace_x86_16_paths.py"
MONOPRIN_COD = REPO_ROOT / "cod" / "f14" / "MONOPRIN.COD"
NHORZ_COD = REPO_ROOT / "cod" / "f14" / "NHORZ.COD"
MAX_COD = REPO_ROOT / "cod" / "default" / "MAX.COD"
ICOMDO_COM = REPO_ROOT / "angr_platforms" / "x16_samples" / "ICOMDO.COM"


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
    assert "if (*((short *)" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "if (!(!" not in result.stdout
    assert "*((char *)(v1 * 16 + 6)) = 214;" in result.stdout
    assert "*((char *)(v1 * 16 + 9)) = 1;" in result.stdout
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
    assert "a1 <= a2" in result.stdout
    assert "return a1;" in result.stdout
    assert "return a2;" in result.stdout


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
