"""Locate exact generated C function definitions for export tooling.

Layer: CLI/fallback/reporting.
Responsibility: identify balanced generated definitions without recovering or
changing decompiler semantics.
"""

from __future__ import annotations

import re
from pathlib import Path


def generated_function_definition_span(
    source: str,
    function_name: str,
) -> tuple[int, int]:
    """Return the exact span of one balanced generated C definition."""
    signature = re.search(
        rf"(?m)^[ \t]*[A-Za-z_][^\n;]*\b{re.escape(function_name)}"
        r"\s*\([^;\n]*\)\s*\{",
        source,
    )
    if signature is None:
        raise ValueError(f"missing generated definition for {function_name}")
    brace_start = source.find("{", signature.start())
    depth = 0
    for index in range(brace_start, len(source)):
        character = source[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return signature.start(), index + 1
    raise ValueError(f"unterminated generated definition for {function_name}")


def load_generated_function_artifacts(
    directory: Path,
    addresses: tuple[int, ...],
) -> dict[int, str]:
    """Load one exact generated C artifact for every requested address."""
    sources: dict[int, str] = {}
    for address in addresses:
        matches = tuple(sorted(directory.glob(f"{address:08x}-*.c")))
        if len(matches) != 1:
            raise ValueError(
                f"expected one generated artifact for {address:#x}, found {len(matches)}"
            )
        source = matches[0].read_text(encoding="utf-8", errors="replace")
        generated_function_definition_span(source, f"sub_{address:04x}")
        sources[address] = source
    return sources
