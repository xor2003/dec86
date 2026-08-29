from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.indexed_address_evidence import (
    collect_indexed_address_evidence_8616,
)
from angr_platforms.X86_16.ir.indexed_address_range_candidates import (
    collect_indexed_loop_ranges_from_ssa_8616,
)
from angr_platforms.X86_16.ir.indexed_address_range_contracts import (
    IndexedLoopGuardPolarity8616,
    IndexedLoopGuardRelation8616,
)
from angr_platforms.X86_16.ir.logical_memory_write_value import (
    LogicalWordWriteValueKind8616,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact

ZERO_BASED_INDEXED_LOOP = bytes.fromhex(
    "55 89 e5 83 ec 02 "
    "c7 46 fe 00 00 "
    "83 7e fe 04 "
    "73 0c "
    "8b 5e fe "
    "8a 87 00 02 "
    "ff 46 fe "
    "eb ee "
    "89 ec 5d c3"
)


def test_real_ssa_loop_produces_exact_constant_range_witness() -> None:
    project = angr.Project(
        io.BytesIO(ZERO_BASED_INDEXED_LOOP),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000, 0x100B, 0x1011, 0x101D},
        info={},
    )
    ssa = build_x86_16_function_ssa(
        build_x86_16_ir_function_artifact(project, function)
    )
    indexed = collect_indexed_address_evidence_8616(ssa)

    result = collect_indexed_loop_ranges_from_ssa_8616(ssa, indexed)

    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    fact = result.facts[0]
    assert fact.complete
    assert (fact.init, fact.step, fact.upper_bound) == (0, 1, 4)
    assert fact.init_write.kind is LogicalWordWriteValueKind8616.CONSTANT_ZERO
    assert (
        fact.step_write.kind
        is LogicalWordWriteValueKind8616.OLD_LOGICAL_WORD_PLUS_ONE
    )
    assert fact.guard.condition.op == "uge"
    assert fact.guard.relation is IndexedLoopGuardRelation8616.UNSIGNED_GE
    assert (
        fact.guard.polarity
        is IndexedLoopGuardPolarity8616.CONTINUE_WHEN_FALSE
    )
    assert fact.guard.proves_strict_unsigned_continue
    assert fact.natural_loop.entry_edges == ((0x1000, 0x100B),)
    assert fact.natural_loop.exit_edges == ((0x100B, 0x101D),)
