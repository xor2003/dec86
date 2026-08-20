"""Layer: Frontend/runtime.

Responsibility: provide debug printing helpers for the frontend emulator/lifter code.
Forbidden: recovery diagnostics, validation verdicts, or decompiler output changes.
"""

from __future__ import annotations

import sys
import traceback
from typing import TextIO

from pyvex.errors import LiftingException

# Constants for debug message types
F_ASSERT: int = 0
F_ERROR: int = 1
F_WARN: int = 2
F_INFO: int = 3
F_MSG: int = 4

# Global debug level
debug_level: int = 0

__all__ = [
    "ASSERT",
    "DEBUG_MSG",
    "ERROR",
    "X86_16FrontendFatalError",
    "F_ASSERT",
    "F_ERROR",
    "F_INFO",
    "F_MSG",
    "F_WARN",
    "INFO",
    "MSG",
    "WARN",
    "debug_print",
    "set_debuglv",
]

_DebugCaller = tuple[str, str, int]


class X86_16FrontendFatalError(LiftingException):  # type: ignore[misc]  # dynamic pyvex base
    """Fatal frontend condition (unimplemented encoding, broken invariant) raised instead of exiting.

    It subclasses pyvex's ``LiftingException`` so the block that hit it fails to lift and
    CFG recovery continues with the rest of the program, instead of terminating the whole
    decompiler process through ``sys.exit``.
    """


def _debug_caller() -> _DebugCaller:
    frame = traceback.extract_stack()[-3]
    return frame.filename, frame.name, frame.lineno or 0


def debug_print(
    message_type: int,
    file: str,
    function: str,
    line: int,
    level: int,
    fmt: str,
    *args: object,
) -> None:
    """Prints debug messages based on the message type and debug level."""
    typeset: dict[int, tuple[str | None, TextIO, bool]] = {
        F_ASSERT: ("ASSERT", sys.stderr, True),
        F_ERROR: ("ERROR", sys.stderr, True),
        F_WARN: ("WARN", sys.stderr, False),
        F_INFO: ("INFO", sys.stdout, False),
        F_MSG: (None, sys.stdout, False),
    }

    name, fp, fatal = typeset[message_type]

    if fatal or (level > 0 and (1 << (level - 1)) & debug_level):
        if name:
            print(f"[{name}{f'_{level}' if level else ''}] ", end="", file=fp)
            print(f"{function} ({file}:{line}) ", end="", file=fp)
        rendered = fmt % args
        print(rendered, file=fp)
        if fatal:
            raise X86_16FrontendFatalError(f"{name or 'FATAL'} {function} ({file}:{line}): {rendered.rstrip()}")


def ASSERT(cond: object) -> None:
    """Assert a condition; a failure prints the message and raises ``X86_16FrontendFatalError``."""
    if not cond:
        debug_print(F_ASSERT, *_debug_caller(), 0, "assertion failed: %s", cond)


def ERROR(fmt: str, *args: object) -> None:
    """Print an error message and raise ``X86_16FrontendFatalError`` for the current block."""
    debug_print(F_ERROR, *_debug_caller(), 0, fmt, *args)


def WARN(fmt: str, *args: object) -> None:
    """Prints a warning message."""
    debug_print(F_WARN, *_debug_caller(), 0, fmt, *args)


def INFO(level: int, fmt: str, *args: object) -> None:
    """Prints an informational message based on the debug level."""
    debug_print(F_INFO, *_debug_caller(), level, fmt, *args)


def DEBUG_MSG(level: int, fmt: str, *args: object) -> None:
    """Prints a debug message based on the debug level."""
    debug_print(F_MSG, *_debug_caller(), level, fmt, *args)


def MSG(fmt: str, *args: object) -> None:
    """Prints a regular message to stdout."""
    print(fmt % args, file=sys.stdout)


def set_debuglv(verbose: int | str) -> None:
    """Sets the global debug level."""
    global debug_level
    debug_level = int(verbose)
