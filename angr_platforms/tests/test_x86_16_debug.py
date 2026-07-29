from __future__ import annotations

import pytest
from angr_platforms.X86_16 import debug


def test_msg_prints_formatted_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    debug.MSG("value=%s", 7)

    captured = capsys.readouterr()
    assert captured.out == "value=7\n"
    assert captured.err == ""


def test_warn_is_nonfatal_and_respects_default_debug_level(capsys: pytest.CaptureFixture[str]) -> None:
    debug.WARN("port %x", 0x3F8)

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_info_respects_debug_level(capsys: pytest.CaptureFixture[str]) -> None:
    previous_level = debug.debug_level
    try:
        debug.set_debuglv(0)
        debug.INFO(1, "hidden")
        assert capsys.readouterr().out == ""

        debug.set_debuglv(1)
        debug.INFO(1, "visible %s", "line")
        assert "visible line" in capsys.readouterr().out
    finally:
        debug.debug_level = previous_level
