from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.alias.carry_borrow_projection import (
    CarryBorrowAliasFailure8616,
    project_carry_borrow_aliases_8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import MemSpace
from angr_platforms.X86_16.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.semantics.carry_borrow_links import analyze_carry_borrow_links_8616
from angr_platforms.X86_16.widening.carry_borrow_values import widen_carry_borrow_values_8616


def _lift_ssa(code: bytes) -> SSAFunctionArtifact:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    return build_x86_16_function_ssa(build_x86_16_ir_function_artifact(project, function))


def test_direct_and_byte_composed_memory_words_reach_widening() -> None:
    artifact = _lift_ssa(bytes.fromhex("2b 06 a6 0b 1b 16 a8 0b c3"))

    semantics = analyze_carry_borrow_links_8616(artifact)
    assert semantics.complete
    assert semantics.stats.raw_fact_count == semantics.stats.materialized_count == 1
    link = semantics.links[0]
    assert link.low_rhs.memory_word is not None
    assert link.high_rhs.memory_word is not None
    assert tuple(
        (address.space, address.offset, address.size)
        for address in link.low_rhs.memory_word.addresses
    ) == ((MemSpace.DS, 0x0BA6, 2),)
    assert tuple(
        (address.space, address.offset, address.size)
        for address in link.high_rhs.memory_word.addresses
    ) == ((MemSpace.DS, 0x0BA8, 1), (MemSpace.DS, 0x0BA9, 1))

    aliases = project_carry_borrow_aliases_8616(semantics)
    widening = widen_carry_borrow_values_8616(aliases)

    assert aliases.complete and aliases.stats.materialized_count == 1
    assert widening.complete and widening.stats.materialized_count == 1
    value = widening.values[0]
    assert value.address_space is MemSpace.DS
    assert value.source_memory is not None
    assert tuple(
        (address.offset, address.size) for address in value.source_memory.addresses
    ) == ((0x0BA6, 2), (0x0BA8, 1), (0x0BA9, 1))


def test_exact_low_high_constant_pair_reaches_widening() -> None:
    artifact = _lift_ssa(bytes.fromhex("2d 4b 00 83 da 00 c3"))

    semantics = analyze_carry_borrow_links_8616(artifact)
    aliases = project_carry_borrow_aliases_8616(semantics)
    widening = widen_carry_borrow_values_8616(aliases)

    assert semantics.complete and semantics.stats.materialized_count == 1
    assert aliases.complete and aliases.stats.materialized_count == 1
    assert widening.complete and widening.stats.materialized_count == 1
    value = widening.values[0]
    assert value.source_constant == 75
    assert value.low.rhs_constant is not None and value.low.rhs_constant.const == 75
    assert value.high.rhs_constant is not None and value.high.rhs_constant.const == 0


def test_mixed_constant_and_register_source_carriers_refuse() -> None:
    semantics = analyze_carry_borrow_links_8616(
        _lift_ssa(bytes.fromhex("2d 4b 00 19 ca c3"))
    )
    assert semantics.complete and semantics.stats.materialized_count == 1

    aliases = project_carry_borrow_aliases_8616(semantics)

    assert aliases.complete
    assert aliases.stats.raw_fact_count == aliases.stats.failure_count == 1
    assert (
        aliases.resolutions[0].failure
        is CarryBorrowAliasFailure8616.SOURCE_CARRIER_MISMATCH
    )
