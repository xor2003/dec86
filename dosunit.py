#!/usr/bin/env python3
"""Command wrapper for the DOS unit execution harness.

Layer: Tooling/gates.
Responsibility: expose the DOS unit runner command without owning decompiler semantics.
"""

from __future__ import annotations

from tools.dosunit.dosunit import main

if __name__ == "__main__":
    raise SystemExit(main(prog="dosunit"))
