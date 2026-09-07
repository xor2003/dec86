"""Read literal QA target inventories without executing Make recipes.

Layer: Tooling/gates.
Responsibility: preserve assignment order, appends, and duplicates in static
Makefile word lists consumed by architecture checks. This is not a general
Make evaluator: variable/function expansion and conditional evaluation are
not performed. Inventory entries must be literal, unescaped target words.
"""

from __future__ import annotations

import re
from collections.abc import Iterator


def _logical_lines(text: str) -> Iterator[str]:
    """Fold continued physical lines before interpreting assignments/comments."""
    pending = ""
    for line in text.splitlines():
        pending += line.lstrip() if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        yield pending
        pending = ""
    if pending:
        yield pending


def makefile_variable_words(makefile_text: str, variable_name: str) -> tuple[str, ...]:
    """Read literal =/:=/+=/?= assignments with Make's replacement semantics.

    Keep duplicates so the caller can reject them. An empty assignment still
    defines the variable, preventing a subsequent conditional default.
    """
    assignment = re.compile(r"^ *" + re.escape(variable_name) + r"\s*(:=|\+=|\?=|=)\s*(.*)$")
    words: list[str] = []
    defined = False
    for line in _logical_lines(makefile_text):
        match = assignment.fullmatch(line.partition("#")[0])
        if match is None:
            continue
        operator, value = match.groups()
        if operator == "?=" and defined:
            continue
        if operator != "+=":
            words.clear()
        words.extend(value.split())
        defined = True
    return tuple(words)
