from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, IRCondition, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.vex_import import (
    apply_x86_16_vex_ir_artifact,
    build_x86_16_ir_function_artifact,
)


def _const(value: int):
    return SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=value))


def _get(offset: int):
    return SimpleNamespace(tag="Iex_Get", offset=offset)


def _rdtmp(tmp: int):
    return SimpleNamespace(tag="Iex_RdTmp", tmp=tmp)


def _binop(op: str, *args):
    return SimpleNamespace(tag="Iex_Binop", op=op, args=args)


def _wrtmp(tmp: int, data):
    return SimpleNamespace(tag="Ist_WrTmp", tmp=tmp, data=data)


def _store(addr, data):
    return SimpleNamespace(tag="Ist_Store", addr=addr, data=data)


def _exit(guard, dst):
    return SimpleNamespace(tag="Ist_Exit", guard=guard, dst=dst)


def _block(addr: int, *stmts, next_expr=None):
    return SimpleNamespace(addr=addr, vex=SimpleNamespace(statements=stmts, next=next_expr))


class _FakeFactory:
    def __init__(self, blocks):
        self._blocks = blocks

    def block(self, addr, opt_level=0):  # noqa: ARG002
        return self._blocks[addr]


def _project(blocks, function):
    return SimpleNamespace(
        factory=_FakeFactory(blocks),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function if addr == function.addr else None)),
    )


def test_vex_import_maps_si_based_store_to_typed_provisional_ds_address():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(20)),
                _wrtmp(1, _const(4)),
                _wrtmp(2, _binop("Iop_Add16", _rdtmp(0), _rdtmp(1))),
                _store(_rdtmp(2), _const(0x55)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    store = artifact.blocks[0].instrs[-1]
    addr = store.args[0]

    assert store.op == "STORE"
    assert store.dst is None
    assert isinstance(addr, IRAddress)
    assert addr.space == MemSpace.DS
    assert addr.base == ("si",)
    assert addr.offset == 4
    assert addr.status == AddressStatus.PROVISIONAL
    assert addr.segment_origin == SegmentOrigin.DEFAULTED


def test_vex_import_maps_bp_sub_offset_to_provisional_ss_frame_slot():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(18)),
                _wrtmp(1, _const(6)),
                _wrtmp(2, _binop("Iop_Sub16", _rdtmp(0), _rdtmp(1))),
                _store(_rdtmp(2), _const(1)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    store = artifact.blocks[0].instrs[-1]
    addr = store.args[0]

    assert isinstance(addr, IRAddress)
    assert addr.space == MemSpace.SS
    assert addr.base == ("bp",)
    assert addr.offset == -6
    assert addr.status == AddressStatus.PROVISIONAL
    assert addr.segment_origin == SegmentOrigin.DEFAULTED
    assert artifact.summary["frame_slot_count"] == 1
    assert artifact.summary["address_status_counts"]["provisional"] >= 1
    assert artifact.summary["segment_origin_counts"]["defaulted"] >= 1


def test_vex_import_keeps_register_pair_address_tuple_for_alias():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(14)),
                _wrtmp(1, _get(20)),
                _wrtmp(2, _binop("Iop_Add16", _rdtmp(0), _rdtmp(1))),
                _store(_rdtmp(2), _const(0x33)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    addr = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(addr, IRAddress)
    assert addr.base == ("bx", "si")
    assert addr.space == MemSpace.DS
    assert addr.segment_origin == SegmentOrigin.DEFAULTED


def test_vex_import_lifts_comparison_exit_to_typed_condition():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(8)),
                _wrtmp(1, _get(14)),
                _wrtmp(2, _binop("Iop_CmpEQ16", _rdtmp(0), _rdtmp(1))),
                _exit(_rdtmp(2), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cjmp = artifact.blocks[0].instrs[-1]
    cond = cjmp.args[0]

    assert cjmp.op == "CJMP"
    assert isinstance(cond, IRCondition)
    assert cond.op == "eq"
    assert [value.name for value in cond.args] == ["ax", "bx"]
    assert artifact.summary["condition_counts"] == {"eq": 1}


def test_vex_import_lifts_masked_nonzero_exit_to_typed_condition():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(20)),
                _wrtmp(1, _const(1)),
                _wrtmp(2, _binop("Iop_And16", _rdtmp(0), _rdtmp(1))),
                _exit(_rdtmp(2), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cjmp = artifact.blocks[0].instrs[-1]
    cond = cjmp.args[0]

    assert cjmp.op == "CJMP"
    assert isinstance(cond, IRCondition)
    assert cond.op == "masked_nonzero"
    assert [value.name for value in cond.args] == ["si", None]
    assert artifact.summary["condition_counts"] == {"masked_nonzero": 1}


def test_vex_import_records_successor_addrs_and_function_ssa():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000, 0x1010, 0x1020}, info={})
    project = _project(
        {
            0x1000: _block(0x1000, _wrtmp(0, _get(8)), next_expr=_const(0x1010)),
            0x1010: _block(0x1010, _wrtmp(0, _get(8)), next_expr=_const(0x1020)),
            0x1020: _block(0x1020, _wrtmp(0, _get(8))),
        },
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = apply_x86_16_vex_ir_artifact(project, codegen)

    assert changed is False
    assert codegen._inertia_vex_ir_artifact.blocks[0].successor_addrs == (0x1010,)
    assert codegen._inertia_vex_ir_function_ssa.summary["block_count"] == 3
    assert function.info["x86_16_vex_ir_function_ssa"]["summary"]["block_count"] == 3


def test_apply_vex_ir_artifact_attaches_summary_to_codegen_and_function_info():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {0x1000: _block(0x1000, _wrtmp(0, _get(22)), _store(_rdtmp(0), _const(2)))},
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = apply_x86_16_vex_ir_artifact(project, codegen)

    assert changed is False
    assert codegen._inertia_vex_ir_summary["instruction_count"] == 2
    assert function.info["x86_16_vex_ir_summary"]["instruction_count"] == 2
    assert "x86_16_vex_ir_function_ssa" in function.info
