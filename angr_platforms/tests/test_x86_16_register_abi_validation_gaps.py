"""Regression cases for hand-written-assembly patterns where emitted C loses semantics.

Each case is a tiny 8086 blob reduced from Lost Vikings (VIKINGS.EXE, written in assembly, no C
runtime conventions). The assertions state the *correct* expectation for the generated C; the
cases that the decompiler still gets wrong are marked ``xfail(strict=True)`` so they flip to a
hard failure, and must be un-marked, as soon as the underlying gap is fixed.

This module is intentionally not registered as a fast ownership target because those targets
may not carry skip/xfail marks.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
BASE = 0x1000
C_MARKER = "/* == c"


def _rel16(opcode: int, at: int, target: int) -> bytes:
    """Encode ``call``/``jmp`` with a 16-bit relative displacement (3-byte instruction)."""
    return bytes([opcode]) + ((target - (at + 3)) & 0xFFFF).to_bytes(2, "little")


def _blob(layout: dict[int, bytes], size: int) -> bytes:
    image = bytearray(b"\x90" * size)
    for offset, code in layout.items():
        image[offset : offset + len(code)] = code
    return bytes(image)


def _run(tmp_path: Path, name: str, code: bytes, *, addr: int = BASE) -> subprocess.CompletedProcess[str]:
    blob = tmp_path / f"{name}.bin"
    blob.write_bytes(code)
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env.setdefault("INERTIA_DISABLE_TIMING", "1")
    env["INERTIA_MSC_DOS_CHECK"] = "optional"
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(blob),
            "--blob",
            "--base-addr",
            hex(BASE),
            "--entry-point",
            hex(BASE),
            "--addr",
            hex(addr),
            "--timeout",
            "90",
            "--no-alternate-source-c",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
        check=False,
    )


def _function_body(result: subprocess.CompletedProcess[str]) -> str:
    """Return the emitted C of the analysed function, without prototypes and helper declarations."""
    combined = result.stdout + "\n" + result.stderr
    assert C_MARKER in combined, combined
    match = re.search(r"^\w[^\n;]*\([^\n;]*\)\n\{\n(?P<body>.*?)^\}", result.stdout, re.S | re.M)
    assert match is not None, result.stdout
    return match.group("body")


def _validation_passed(result: subprocess.CompletedProcess[str]) -> bool:
    combined = result.stdout + result.stderr
    return result.returncode == 0 and "direct validation=failed" not in combined and "validation=failed" not in combined


@pytest.mark.xfail(
    strict=True,
    reason="register ABI gap: `mov ax,[es:bx]; add bx,2; ret` (Lost Vikings sub_1547e, the VM immediate reader) "
    "is emitted as an empty body while tail validation reports it clean; AX is the return value and BX an output.",
)
def test_es_bx_word_reader_keeps_its_load_and_result(tmp_path):
    result = _run(tmp_path, "es_bx_reader", bytes.fromhex("268b07" "83c302" "c3"))

    body = _function_body(result)
    assert body.strip(), "an observable load through ES:BX must not disappear into an empty body"
    assert "inertia_es" in body or "return" in body


@pytest.mark.xfail(
    strict=True,
    reason="register ABI gap: `mov bx,[es:bx]; ret` (Lost Vikings sub_142cf, the VM jump helper) is emitted as an "
    "empty body although BX is the function's only output.",
)
def test_es_bx_pointer_update_is_not_dropped(tmp_path):
    result = _run(tmp_path, "es_bx_jump", bytes.fromhex("268b1f" "c3"))

    body = _function_body(result)
    assert body.strip(), "a function whose only effect is a register output must not become an empty body"


@pytest.mark.xfail(
    strict=True,
    reason="phi gap: after `mov ax,0 / test / jz / call f / mov ax,[86dc]` the join `or ax,[86de]` only sees the "
    "fall-through value (Lost Vikings sub_12352 loses the joystick word) while tail validation stays clean.",
)
def test_ax_phi_after_conditional_call_keeps_both_definitions(tmp_path):
    layout = {
        0x00: bytes.fromhex("b80000"),                 # mov ax,0
        0x03: bytes.fromhex("f706da86ffff"),           # test word [0x86da],0xffff
        0x09: bytes.fromhex("7406"),                   # jz 0x1011
        0x0B: _rel16(0xE8, BASE + 0x0B, BASE + 0x23),  # call f
        0x0E: bytes.fromhex("a1dc86"),                 # mov ax,[0x86dc]
        0x11: bytes.fromhex("0b06de86"),               # or ax,[0x86de]
        0x15: bytes.fromhex("a3b603"),                 # mov [0x3b6],ax
        0x18: bytes.fromhex("c3"),                     # ret
        0x23: bytes.fromhex("c70638120300c3"),         # f: mov word [0x1238],3 ; ret
    }
    result = _run(tmp_path, "ax_phi_after_call", _blob(layout, 0x30))

    body = _function_body(result)
    assert "g_86DC" in body or "34524" in body, "the value loaded on the call path must reach the join"


@pytest.mark.xfail(
    strict=True,
    reason="callsite gap: arguments pushed with the 8086 `push ax; push bp; mov bp,sp; mov [bp+2],imm; pop bp` "
    "idiom (Lost Vikings sound driver, sub_1c5ef) are treated as locals, so the far pointer 0BAD:0A53 never "
    "reaches the callee; validation fails but no correct call is recovered.",
)
def test_push_immediate_idiom_materializes_far_pointer_arguments(tmp_path):
    layout = {
        0x00: bytes.fromhex("55" "8bec"),                              # push bp ; mov bp,sp
        0x03: bytes.fromhex("50" "55" "8bec" "c74602ad0b" "5d"),       # push 0x0bad (8086 idiom)
        0x0D: bytes.fromhex("50" "55" "8bec" "c74602530a" "5d"),       # push 0x0a53 (8086 idiom)
        0x17: bytes.fromhex("ff7606"),                                 # push word [bp+6]
        0x1A: _rel16(0xE8, BASE + 0x1A, BASE + 0x28),                  # call g
        0x1D: bytes.fromhex("83c406"),                                 # add sp,6
        0x20: bytes.fromhex("5d" "c3"),                                # pop bp ; ret
        0x28: bytes.fromhex("55" "8bec" "8b4604" "8b5606" "8b4e08" "a33a12" "5d" "c3"),  # g(a, b, c)
    }
    result = _run(tmp_path, "push_imm_far_arg", _blob(layout, 0x40))

    body = _function_body(result)
    call = re.search(r"sub_1028\((?P<args>[^)]*)\)", body)
    assert call is not None, body
    arguments = [piece.strip() for piece in call.group("args").split(",") if piece.strip()]
    assert len(arguments) == 3, body
    assert any("2643" in piece or "0xa53" in piece.lower() for piece in arguments), body
    assert any("2989" in piece or "0xbad" in piece.lower() for piece in arguments), body
    assert _validation_passed(result)


def test_tail_jump_into_a_shared_callee_keeps_its_effects(tmp_path):
    """Guard: on a blob the tail-jumped callee is folded into the function; its store must survive.

    Lost Vikings sub_11439 (`jmp sub_16775` after a conditional call) loses the tail call in the
    whole-binary sweep where the target is an independently discovered function; that variant is
    documented in the merge request and cannot be reduced to a single blob yet.
    """
    layout = {
        0x00: _rel16(0xE8, BASE + 0x00, BASE + 0x10) + _rel16(0xE8, BASE + 0x03, BASE + 0x40) + b"\xc3",  # main
        0x10: bytes.fromhex("f606cf2542" "7503"),        # test byte [0x25cf],0x42 ; jnz +3
        0x17: _rel16(0xE8, BASE + 0x17, BASE + 0x30),    # call sub_a
        0x1A: _rel16(0xE9, BASE + 0x1A, BASE + 0x40),    # jmp sub_b (tail call)
        0x30: bytes.fromhex("c70634120100c3"),           # sub_a: mov word [0x1234],1 ; ret
        0x40: bytes.fromhex("c70636120200c3"),           # sub_b: mov word [0x1236],2 ; ret
    }
    result = _run(tmp_path, "tail_jmp_shared", _blob(layout, 0x50), addr=BASE + 0x10)

    body = _function_body(result)
    assert "4662" in body or "sub_1040" in body, body  # 0x1236 == 4662: the tail callee's store or the call itself
    assert _validation_passed(result), result.stdout + result.stderr
