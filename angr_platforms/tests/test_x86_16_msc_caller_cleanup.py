"""Regress caller-cleaned Microsoft C call sites through sidecar-free C output."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.semantics.immediate_semantics import sign_extend_u8_to_u16
from angr_platforms.X86_16.simos_86_16 import (
    SimCC8616MSCmedium,
    SimCC8616MSCsmall,
)

from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def _project_from_bytes(code: bytes) -> angr.Project:
    """Build one 16-bit blob project for caller-cleanup regressions."""
    return angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )


def test_msc_c_conventions_leave_argument_cleanup_to_caller() -> None:
    """The near-call return pops itself; C argument words remain caller-owned."""
    assert SimCC8616MSCsmall.CALLEE_CLEANUP is False
    assert SimCC8616MSCmedium.CALLEE_CLEANUP is False


def test_group83_immediate_sign_extension_is_exact() -> None:
    """Normalize positive and negative encoded bytes to exact word patterns."""
    assert sign_extend_u8_to_u16(0x04) == 0x0004
    assert sign_extend_u8_to_u16(0x80) == 0xFF80
    assert sign_extend_u8_to_u16(0xFC) == 0xFFFC
    assert sign_extend_u8_to_u16(0x1FC) == 0xFFFC


def test_stack_cleanup_immediate_lifts_as_typed_word_constant() -> None:
    """Keep ``add sp, imm8`` affine for angr's stack-pointer tracker."""
    project = _project_from_bytes(bytes.fromhex("83c404c3"))

    vex_text = str(project.factory.block(0x1000, num_inst=1, opt_level=0).vex)

    assert "Add16" in vex_text
    assert "0x0004" in vex_text
    assert "8Sto16" not in vex_text


def test_caller_cleanup_loop_preserves_affine_stack_pointer() -> None:
    """A call-cleanup backedge must survive MZ loader-width stack propagation."""
    code = bytes.fromhex("558bec5050e8180083c4044975f58be55dc3") + b"\x90" * 14 + b"\xc3"
    project = _project_from_bytes(code)
    project.arch.bits = 32
    cfg = project.analyses.CFGFast(normalize=True, function_starts=[0x1000, 0x1020])
    function = cfg.functions[0x1000]

    stack_tracker = project.analyses.StackPointerTracker(
        function,
        {project.arch.sp_offset},
        cross_insn_opt=False,
    )
    expected_offset = stack_tracker.offset_after(0x1001, project.arch.sp_offset)

    assert expected_offset is not None
    assert stack_tracker.offset_before(0x1003, project.arch.sp_offset) == expected_offset
    assert stack_tracker.offset_before(0x100E, project.arch.sp_offset) == expected_offset

    decompiler = project.analyses.Decompiler(function, cfg=cfg)

    assert decompiler.codegen is not None
    assert "/* unsupported instruction */" not in decompiler.codegen.text
    assert "sub_1020();" in decompiler.codegen.text


def test_sortd_percolateup_caller_cleanup_has_no_opaque_sp_expression(
    tmp_path: Path,
) -> None:
    """Lower ``call; add sp, 4`` without leaking opaque SP into flag C."""
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env.setdefault("INERTIA_DISABLE_TIMING", "1")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(isolated_binary),
            "--addr",
            "0x109e8",
            "--timeout",
            "120",
            "--no-alternate-source-c",
            "--window",
            "0x90",
            "--c-target",
            "portable-flat",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=240,
        check=False,
    )
    combined = f"{result.stderr}{result.stdout}"

    assert result.returncode == 0, combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "/* unsupported instruction */" not in result.stdout
    assert result.stdout.count("sub_107b8(") == 2
    assert result.stdout.count("sub_10768(") == 2
