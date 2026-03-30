from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
COD_DIR = REPO_ROOT / "cod"


def _run_cod_proc(path: Path, proc: str, *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--proc",
            proc,
            "--timeout",
            str(timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=max(90, timeout * 6),
        check=False,
    )


def _assert_has_all(text: str, anchors: tuple[str, ...]) -> None:
    for anchor in anchors:
        assert anchor in text, anchor


def _assert_has_none(text: str, anchors: tuple[str, ...]) -> None:
    for anchor in anchors:
        assert anchor not in text, anchor


@pytest.mark.parametrize(
    ("cod_name", "proc_name"),
    (
        ("BIOSFUNC.COD", "_bios_clearkeyflags"),
        ("DOSFUNC.COD", "_dos_getfree"),
        ("DOSFUNC.COD", "_dos_loadOverlay"),
        ("DOSFUNC.COD", "_dos_getReturnCode"),
        ("EGAME2.COD", "_openFileWrapper"),
    ),
)
def test_cod_regression_targets_are_recoverable(cod_name: str, proc_name: str):
    result = _run_cod_proc(COD_DIR / cod_name, proc_name)

    assert result.returncode == 0, result.stderr + result.stdout
    assert f"function: 0x1000 {proc_name}" in result.stdout
    assert "Decompilation empty" not in result.stdout


@pytest.mark.xfail(strict=True, reason="far-pointer object recovery is not landed yet")
def test_cod_biosfunc_clearkeyflags_far_word_store():
    result = _run_cod_proc(COD_DIR / "BIOSFUNC.COD", "_bios_clearkeyflags")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(result.stdout, ("function: 0x1000 _bios_clearkeyflags",))
    assert any(anchor in result.stdout for anchor in ("MK_FP(0x0000, 0x0417)", "bios_keyflags", "bda_keyflags"))
    _assert_has_none(result.stdout, ("*((char *)(es * 16 + 1047))", "*((char *)(es * 16 + 1048))"))


@pytest.mark.xfail(strict=True, reason="typed REGS/SREGS object recovery is not landed yet")
def test_cod_dos_getfree_call_and_return_recovered():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_getfree")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_getfree",
            "intdos(&rin, &rout)",
            "rin.h.ah",
            "rin.x.bx",
            "rout.x.cflag",
            "return rout.x.bx",
        ),
    )
    _assert_has_none(
        result.stdout,
        (
            "rin = 72;",
            "rin = 65535;",
            "s_2 = &",
        ),
    )


@pytest.mark.xfail(strict=True, reason="wrapper return propagation is not landed yet")
def test_cod_dos_loadoverlay_wrapper_returns_loadprog():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_loadOverlay")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_loadOverlay",
            "loadprog",
            "file",
            "segment",
        ),
    )
    assert "return loadprog(file, segment, 3, 0);" in result.stdout
    _assert_has_none(
        result.stdout,
        (
            "3823()",
            "v12 << 16",
            "s_4 =",
            "s_6 =",
        ),
    )


@pytest.mark.xfail(strict=True, reason="wrapper staging-slot cleanup is not landed yet")
def test_cod_openfilewrapper_direct_forwarding():
    result = _run_cod_proc(COD_DIR / "EGAME2.COD", "_openFileWrapper")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(result.stdout, ("function: 0x1000 _openFileWrapper", "openFile(path, mode);"))
    _assert_has_none(
        result.stdout,
        (
            "s_2 = &",
            "s_4 = mode",
            "s_6 = path",
        ),
    )


@pytest.mark.xfail(strict=True, reason="call-result recovery is not landed yet")
def test_cod_dos_getreturncode_returns_value():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_getReturnCode")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_getReturnCode",
            "intdos(&rin, &rout)",
            "return",
        ),
    )
    _assert_has_none(result.stdout, ("void _dos_getReturnCode(void)",))
