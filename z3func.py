#!/usr/bin/env python3
"""Compatibility command wrapper for the DOS unit execution harness.

Layer: Tooling/gates.
Responsibility: preserve the legacy DOS unit command name without owning decompiler semantics.
"""

from __future__ import annotations

from tools.dosunit.dosunit import main

if __name__ == "__main__":
    raise SystemExit(main(prog="z3func"))
