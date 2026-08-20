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


def test_error_raises_a_lifting_exception_instead_of_exiting(capsys: pytest.CaptureFixture[str]) -> None:
    from pyvex.errors import LiftingException

    with pytest.raises(debug.X86_16FrontendFatalError) as raised:
        debug.ERROR("not implemented: 0x%02x /%d\n", 0xC1, 1)

    assert isinstance(raised.value, LiftingException)
    assert "not implemented: 0xc1 /1" in str(raised.value)
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.err
    assert "not implemented: 0xc1 /1" in captured.err


def test_failed_assert_raises_instead_of_exiting() -> None:
    debug.ASSERT(True)
    with pytest.raises(debug.X86_16FrontendFatalError):
        debug.ASSERT(False)
