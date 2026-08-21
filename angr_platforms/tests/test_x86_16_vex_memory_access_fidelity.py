from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import (
    AddressStatus,
    IndexedAddressAccessKind8616,
    IndexedAddressFailureKind8616,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_function_ssa,
    collect_indexed_address_evidence_8616,
)
from angr_platforms.X86_16.ir.vex_condition_transport import (
    VexConditionTransportNormalizer8616,
    build_vex_condition_transport_layout_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact


def _lift(code: bytes) -> IRFunctionArtifact:
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
    return build_x86_16_ir_function_artifact(project, function)


def _memory_instructions_at(artifact: IRFunctionArtifact, address: int) -> tuple[IRInstr, ...]:
    return tuple(
        instruction
        for instruction in artifact.blocks[0].instrs
        if instruction.addr == address and instruction.op in {"LOAD", "STORE"}
    )


def _memory_address(instruction: IRInstr) -> IRAddress:
    address = instruction.args[0]
    assert isinstance(address, IRAddress)
    return address


def test_push_indexed_word_normalizes_to_one_machine_load() -> None:
    evidence = collect_indexed_address_evidence_8616(
        build_x86_16_function_ssa(
            _lift(bytes.fromhex("55 89 e5 83 ec 02 c7 46 fe 01 00 8b 5e fe ff b7 36 01 c9 c3"))
        )
    )

    assert evidence.closed
    assert evidence.refusals == ()
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.coalesced_fact_count == 1
    (fact,) = evidence.facts
    assert fact.kind is IndexedAddressAccessKind8616.LOAD
    assert fact.address.space is MemSpace.DS
    assert fact.address.offset == 0x136
    assert fact.address.size == 2


def test_byte_immediate_store_uses_vex_constant_width() -> None:
    artifact = _lift(bytes.fromhex("c6 87 f1 08 07 c3"))

    (store,) = _memory_instructions_at(artifact, 0x1000)

    assert store.op == "STORE"
    assert store.size == 1
    assert _memory_address(store).size == 1
    assert store.args[1].size == 1


def test_indexed_word_store_normalizes_to_one_machine_store() -> None:
    evidence = collect_indexed_address_evidence_8616(
        build_x86_16_function_ssa(
            _lift(bytes.fromhex("55 89 e5 83 ec 02 c7 46 fe 01 00 8b 5e fe 89 87 4c 0b c9 c3"))
        )
    )

    assert evidence.closed
    assert evidence.refusals == ()
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.coalesced_fact_count == 1
    (fact,) = evidence.facts
    assert fact.kind is IndexedAddressAccessKind8616.STORE
    assert fact.address.space is MemSpace.DS
    assert fact.address.offset == 0xB4C
    assert fact.address.size == 2


def test_noncontiguous_same_instruction_micro_ops_refuse_normalization() -> None:
    index = IRValue(MemSpace.REG, name="bx", size=2)
    addresses = tuple(
        IRAddress(
            MemSpace.DS,
            base=("bx",),
            offset=offset,
            size=1,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
            base_values=(index,),
        )
        for offset in (0x200, 0x202)
    )
    artifact = build_x86_16_function_ssa(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(
                    0x1000,
                    tuple(
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.TMP, name=f"t{position}", size=1),
                            (address,),
                            size=1,
                            addr=0x1000,
                        )
                        for position, address in enumerate(addresses)
                    ),
                ),
            ),
        )
    )

    evidence = collect_indexed_address_evidence_8616(artifact)

    assert evidence.closed
    assert evidence.facts == ()
    assert evidence.stats.raw_fact_count == 2
    assert evidence.stats.normalized_fact_count == 1
    assert evidence.stats.coalesced_fact_count == 1
    assert evidence.refusals[0].failure is IndexedAddressFailureKind8616.ACCESS_MICRO_OP_CONFLICT


def test_ir_import_removes_exact_jcc_transport_load() -> None:
    artifact = _lift(bytes.fromhex("8b 5e fe d1 e3 38 87 4e 0b 7c 02 90 90 c3"))

    indexed_loads = tuple(
        instruction
        for instruction in artifact.blocks[0].instrs
        if instruction.op == "LOAD"
        and _memory_address(instruction).space is MemSpace.DS
        and _memory_address(instruction).base == ("bx",)
    )

    assert len(indexed_loads) == 1
    assert indexed_loads[0].addr == 0x1005
    assert indexed_loads[0].size == 1
    assert _memory_address(indexed_loads[0]).offset == 0xB4E
    assert _memory_instructions_at(artifact, 0x1009) == ()
    assert artifact.summary["condition_transport_raw_fact_count"] == 1
    assert artifact.summary["condition_transport_normalized_fact_count"] == 1
    assert artifact.summary["condition_transport_classified_fact_count"] == 1
    assert artifact.summary["condition_transport_materialized_count"] == 1
    assert artifact.summary["condition_transport_failure_count"] == 0


def test_jcc_transport_refuses_load_not_used_by_exit_guard() -> None:
    load_expr = SimpleNamespace(tag="Iex_Load", args=())
    statements = (
        SimpleNamespace(tag="Ist_IMark", addr=0x1005),
        SimpleNamespace(tag="Ist_WrTmp", tmp=1, data=load_expr),
        SimpleNamespace(tag="Ist_IMark", addr=0x1009),
        SimpleNamespace(tag="Ist_WrTmp", tmp=2, data=load_expr),
        SimpleNamespace(
            tag="Ist_Exit",
            guard=SimpleNamespace(tag="Iex_Const", args=()),
        ),
    )
    layout = build_vex_condition_transport_layout_8616(statements)
    normalizer = VexConditionTransportNormalizer8616(layout)
    address = IRAddress(MemSpace.DS, base=("bx",), offset=0x20, size=1)
    predecessor = IRInstr("LOAD", None, (address,), size=1, addr=0x1005)
    branch_load = IRInstr("LOAD", None, (address,), size=1, addr=0x1009)

    assert normalizer.observe_load(
        predecessor,
        IRValue(MemSpace.TMP, name="load_t1", size=1),
        1,
    ) is None
    assert normalizer.observe_load(
        branch_load,
        IRValue(MemSpace.TMP, name="load_t2", size=1),
        2,
    ) is None
    assert normalizer.stats().raw_fact_count == 0
