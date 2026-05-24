#!/usr/bin/env python3
"""
Micro-benchmarks for x86-16 opcode table registration hot paths.

Run:
  PYTHONPATH=angr_platforms ./.venv/bin/python scripts/benchmark_x86_16_lifting_opcode_tables.py
"""

from __future__ import annotations

import time
from types import SimpleNamespace

from angr_platforms.X86_16.instr_base import InstrBase
from angr_platforms.X86_16.instruction import CHK_IMM8, CHK_MODRM, MAX_OPCODE


def _dummy_handler() -> None:
    return None


def _new_host() -> SimpleNamespace:
    return SimpleNamespace(instrfuncs=[None] * MAX_OPCODE, chk=[0] * MAX_OPCODE)


def _bench_set_funcflag(iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        host = _new_host()
        for opcode in range(0xB0, 0xB8):
            InstrBase.set_funcflag(host, opcode, _dummy_handler, CHK_IMM8)
        for opcode in range(0x0F90, 0x0FA0):
            InstrBase.set_funcflag(host, opcode, _dummy_handler, CHK_MODRM)
    return time.perf_counter() - start


def _bench_register_range(iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        host = _new_host()
        InstrBase._register_opcode_range(host, 0x40, 0x47, _dummy_handler, 0)
        InstrBase._register_opcode_range(host, 0x50, 0x57, _dummy_handler, 0)
        InstrBase._register_opcode_range(host, 0x58, 0x5F, _dummy_handler, 0)
    return time.perf_counter() - start


def main() -> None:
    iterations = 20000
    set_funcflag_s = _bench_set_funcflag(iterations)
    register_range_s = _bench_register_range(iterations)

    print(f"iterations={iterations}")
    print(f"set_funcflag_total_s={set_funcflag_s:.6f}")
    print(f"set_funcflag_ns_per_registration={set_funcflag_s * 1e9 / (iterations * (8 + 16)):.2f}")
    print(f"register_range_total_s={register_range_s:.6f}")
    print(f"register_range_ns_per_registration={register_range_s * 1e9 / (iterations * (8 + 8 + 8)):.2f}")


if __name__ == "__main__":
    main()
