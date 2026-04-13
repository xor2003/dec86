from __future__ import annotations

from typing import Any

from .core import (
    AddressStatus,
    IRAddress,
    IRAtom,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .regs import register_name_from_offset
from .ssa import build_x86_16_block_local_ssa
from .ssa_function import build_x86_16_function_ssa
from ..analysis.alias import storage_of
from ..analysis.stack_frame_ir import build_x86_16_ir_frame_access_artifact

__all__ = [
    "apply_x86_16_vex_ir_artifact",
    "build_x86_16_ir_function_artifact",
    "build_x86_16_ir_function_artifact_summary",
]


def _const(expr) -> int | None:
    con = getattr(expr, "con", None)
    return None if con is None else int(getattr(con, "value", 0))


def _int_size(expr, default: int = 2) -> int:
    size = getattr(getattr(expr, "result_size", None), "value", None)
    if size is None:
        size = getattr(expr, "ty", None)
    try:
        return int(size or default)
    except Exception:  # noqa: BLE001
        return default


def _infer_address_space(base: tuple[str, ...]) -> tuple[MemSpace, AddressStatus, SegmentOrigin]:
    if not base:
        return MemSpace.UNKNOWN, AddressStatus.UNKNOWN, SegmentOrigin.UNKNOWN
    if any(name in {"bp", "sp"} for name in base):
        return MemSpace.SS, AddressStatus.PROVISIONAL, SegmentOrigin.DEFAULTED
    return MemSpace.DS, AddressStatus.PROVISIONAL, SegmentOrigin.DEFAULTED


def _address_from_parts(base: tuple[str, ...], offset: int = 0, *, size: int = 0, expr: tuple[str, ...] | None = None) -> IRAddress:
    space, status, segment_origin = _infer_address_space(base)
    return IRAddress(
        space=space,
        base=base,
        offset=offset,
        size=size,
        status=status,
        segment_origin=segment_origin,
        expr=expr,
    )


def _cmp_condition(op: str, left: IRValue, right: IRValue) -> IRCondition | None:
    mapping = {
        "cmpeq": "eq",
        "cmpne": "ne",
        "cmplt": "lt",
        "cmple": "le",
        "cmpgt": "gt",
        "cmpge": "ge",
        "cascmp": "eq",
    }
    folded = op.lower()
    for needle, cond_op in mapping.items():
        if needle in folded:
            return IRCondition(op=cond_op, args=(left, right), expr=(op,))
    return None


def _nonzero_condition(value: IRValue, *, source: str) -> IRCondition:
    return IRCondition(op="nonzero", args=(value,), expr=(source,))


def _masked_nonzero_condition(left: IRValue, right: IRValue, *, source: str) -> IRCondition:
    return IRCondition(op="masked_nonzero", args=(left, right), expr=(source,))


def _expr_to_value(expr, tmps: dict[int, IRValue], conditions: dict[int, IRCondition]) -> IRValue:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        tmp_id = int(getattr(expr, "tmp"))
        if tmp_id in tmps:
            return tmps[tmp_id]
        if tmp_id in conditions:
            return IRValue(MemSpace.TMP, name=f"cond_t{tmp_id}", size=1, expr=("condition_tmp",))
        return IRValue(MemSpace.TMP, name=f"t{tmp_id}")
    if tag == "Iex_Get":
        name = register_name_from_offset(int(getattr(expr, "offset", -1)))
        return IRValue(MemSpace.REG, name=name, size=_int_size(expr))
    if tag == "Iex_Const":
        return IRValue(MemSpace.CONST, const=_const(expr), size=_int_size(expr))
    if tag == "Iex_Unop":
        args = tuple(getattr(expr, "args", ()) or ())
        if not args:
            return IRValue(MemSpace.UNKNOWN, name=str(getattr(expr, "op", "unop")), expr=("empty_unop",))
        inner = _expr_to_value(args[0], tmps, conditions)
        return IRValue(
            inner.space,
            name=inner.name,
            offset=inner.offset,
            const=inner.const,
            size=inner.size,
            expr=(str(getattr(expr, "op", "unop")),),
        )
    if tag == "Iex_Binop":
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return IRValue(MemSpace.TMP, name=f"expr:{op}", expr=(op,))
        left = _expr_to_value(args[0], tmps, conditions)
        right = _expr_to_value(args[1], tmps, conditions)
        cond = _cmp_condition(op, left, right)
        if cond is not None:
            return IRValue(MemSpace.TMP, name=f"cond:{cond.op}", size=1, expr=(op,))
        if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.CONST and right.const is not None:
            return IRValue(left.space, name=left.name, offset=left.offset + int(right.const), size=left.size, expr=(op,))
        if "Sub" in op and left.space == MemSpace.REG and right.space == MemSpace.CONST and right.const is not None:
            return IRValue(left.space, name=left.name, offset=left.offset - int(right.const), size=left.size, expr=(op,))
        if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.REG and left.name and right.name:
            return IRValue(MemSpace.TMP, name=f"addr:{left.name}+{right.name}", size=left.size, expr=(op, left.name, right.name))
        if "And" in op:
            return IRValue(MemSpace.TMP, name=f"mask:{left.name or 'lhs'}", size=max(left.size, right.size), expr=(op,))
        return IRValue(MemSpace.TMP, name=f"expr:{op}", size=max(left.size, right.size), expr=(op,))
    if tag == "Iex_Load":
        addr = _expr_to_address(getattr(expr, "addr", None), tmps, conditions, size=_int_size(expr))
        return IRValue(MemSpace.TMP, name="load", size=addr.size or _int_size(expr), expr=("load",))
    return IRValue(MemSpace.UNKNOWN, name=tag or "expr")


def _expr_to_address(expr, tmps: dict[int, IRValue], conditions: dict[int, IRCondition], *, size: int = 0) -> IRAddress:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        tmp_id = int(getattr(expr, "tmp"))
        tmp_value = tmps.get(tmp_id)
        if tmp_value is None:
            return IRAddress(
                MemSpace.UNKNOWN,
                size=size,
                status=AddressStatus.UNKNOWN,
                segment_origin=SegmentOrigin.UNKNOWN,
                expr=("rdtmp", f"t{tmp_id}"),
            )
        if tmp_value.space == MemSpace.REG and tmp_value.name is not None:
            return _address_from_parts((tmp_value.name,), tmp_value.offset, size=size, expr=("register_base", tmp_value.name))
        if tmp_value.expr and tmp_value.expr[:1] == ("Iop_Add16",) and len(tmp_value.expr) == 3:
            return _address_from_parts((tmp_value.expr[1], tmp_value.expr[2]), 0, size=size, expr=tmp_value.expr)
        return IRAddress(
            MemSpace.UNKNOWN,
            size=size,
            status=AddressStatus.UNKNOWN,
            segment_origin=SegmentOrigin.UNKNOWN,
            expr=("tmp_expr", tmp_value.name or "tmp"),
        )
    if tag == "Iex_Get":
        value = _expr_to_value(expr, tmps, conditions)
        return _address_from_parts(() if value.name is None else (value.name,), value.offset, size=size, expr=("register_get", value.name or ""))
    if tag == "Iex_Const":
        return IRAddress(
            MemSpace.UNKNOWN,
            offset=int(_const(expr) or 0),
            size=size,
            status=AddressStatus.UNKNOWN,
            segment_origin=SegmentOrigin.UNKNOWN,
            expr=("absolute_const",),
        )
    if tag == "Iex_Binop":
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return IRAddress(
                MemSpace.UNKNOWN,
                size=size,
                status=AddressStatus.UNKNOWN,
                segment_origin=SegmentOrigin.UNKNOWN,
                expr=(op,),
            )
        left = _expr_to_value(args[0], tmps, conditions)
        right = _expr_to_value(args[1], tmps, conditions)
        if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.CONST and right.const is not None and left.name:
            return _address_from_parts((left.name,), left.offset + int(right.const), size=size, expr=(op, left.name))
        if "Sub" in op and left.space == MemSpace.REG and right.space == MemSpace.CONST and right.const is not None and left.name:
            return _address_from_parts((left.name,), left.offset - int(right.const), size=size, expr=(op, left.name))
        if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.REG and left.name and right.name:
            return _address_from_parts(tuple(sorted((left.name, right.name))), 0, size=size, expr=(op, left.name, right.name))
        return IRAddress(
            MemSpace.UNKNOWN,
            size=size,
            status=AddressStatus.UNKNOWN,
            segment_origin=SegmentOrigin.UNKNOWN,
            expr=(op,),
        )
    return IRAddress(
        MemSpace.UNKNOWN,
        size=size,
        status=AddressStatus.UNKNOWN,
        segment_origin=SegmentOrigin.UNKNOWN,
        expr=(tag or "addr_expr",),
    )


def _expr_to_condition(expr, tmps: dict[int, IRValue], conditions: dict[int, IRCondition]) -> IRCondition:
    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        tmp_id = int(getattr(expr, "tmp"))
        if tmp_id in conditions:
            return conditions[tmp_id]
        return _nonzero_condition(_expr_to_value(expr, tmps, conditions), source=f"rdtmp:{tmp_id}")
    if tag == "Iex_Binop":
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) == 2:
            left = _expr_to_value(args[0], tmps, conditions)
            right = _expr_to_value(args[1], tmps, conditions)
            cond = _cmp_condition(op, left, right)
            if cond is not None:
                return cond
            if "And" in op:
                return _masked_nonzero_condition(left, right, source=op)
    return _nonzero_condition(_expr_to_value(expr, tmps, conditions), source=tag or "expr")


def _stmt_to_instr(stmt, tmps: dict[int, IRValue], conditions: dict[int, IRCondition]) -> IRInstr | None:
    tag = getattr(stmt, "tag", "")
    if tag == "Ist_WrTmp":
        data = getattr(stmt, "data", None)
        tmp_id = int(getattr(stmt, "tmp"))
        data_tag = getattr(data, "tag", "")
        dst = IRValue(MemSpace.TMP, name=f"t{tmp_id}", size=_int_size(data))
        if data_tag == "Iex_Load":
            addr = _expr_to_address(getattr(data, "addr", None), tmps, conditions, size=_int_size(data))
            tmps[tmp_id] = IRValue(MemSpace.TMP, name=f"load_t{tmp_id}", size=_int_size(data), expr=("load",))
            return IRInstr(op="LOAD", dst=dst, args=(addr,), size=_int_size(data))
        if data_tag == "Iex_Binop":
            op = str(getattr(data, "op", "BINOP"))
            args = tuple(getattr(data, "args", ()) or ())
            if len(args) == 2:
                left = _expr_to_value(args[0], tmps, conditions)
                right = _expr_to_value(args[1], tmps, conditions)
                cond = _cmp_condition(op, left, right)
                if cond is not None:
                    conditions[tmp_id] = cond
                elif "And" in op:
                    conditions[tmp_id] = _masked_nonzero_condition(left, right, source=op)
                tmps[tmp_id] = _expr_to_value(data, tmps, conditions)
                return IRInstr(op=op, dst=dst, args=(left, right), size=max(left.size, right.size))
        value = _expr_to_value(data, tmps, conditions)
        tmps[tmp_id] = value
        return IRInstr(op="MOV", dst=dst, args=(value,), size=value.size)
    if tag == "Ist_Put":
        offset = int(getattr(stmt, "offset"))
        dst = IRValue(MemSpace.REG, name=register_name_from_offset(offset), size=2)
        src = _expr_to_value(getattr(stmt, "data", None), tmps, conditions)
        return IRInstr(op="MOV", dst=dst, args=(src,), size=dst.size)
    if tag == "Ist_Store":
        addr = _expr_to_address(getattr(stmt, "addr", None), tmps, conditions, size=_int_size(getattr(stmt, "data", None)))
        data = _expr_to_value(getattr(stmt, "data", None), tmps, conditions)
        return IRInstr(op="STORE", dst=None, args=(addr, data), size=data.size)
    if tag == "Ist_Exit":
        cond = _expr_to_condition(getattr(stmt, "guard", None), tmps, conditions)
        target = _expr_to_value(getattr(stmt, "dst", None), tmps, conditions)
        return IRInstr(op="CJMP", dst=None, args=(cond, target), size=0)
    return None


def _block_to_ir(block) -> IRBlock:
    vex = getattr(block, "vex", None)
    addr = int(getattr(block, "addr", 0))
    if vex is None:
        return IRBlock(addr=addr, refusals=(IRRefusal("missing_vex", "block has no vex IR", addr),))
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    instrs: list[IRInstr] = []
    refusals: list[IRRefusal] = []
    for stmt in tuple(getattr(vex, "statements", ()) or ()):
        instr = _stmt_to_instr(stmt, tmps, conditions)
        if instr is None:
            tag = getattr(stmt, "tag", "")
            if tag:
                refusals.append(IRRefusal("unsupported_stmt", f"unsupported VEX statement {tag}", addr))
            continue
        instrs.append(instr)
    successor_addrs: list[int] = []
    for stmt in tuple(getattr(vex, "statements", ()) or ()):
        if getattr(stmt, "tag", "") == "Ist_Exit":
            dst = getattr(stmt, "dst", None)
            const_dst = _const(dst)
            if const_dst is not None:
                successor_addrs.append(int(const_dst))
    vex_next = getattr(vex, "next", None)
    next_const = _const(vex_next)
    if next_const is not None:
        successor_addrs.append(int(next_const))
    return IRBlock(
        addr=addr,
        instrs=tuple(instrs),
        refusals=tuple(refusals),
        successor_addrs=tuple(sorted(dict.fromkeys(successor_addrs))),
    )


def build_x86_16_ir_function_artifact(project, function) -> IRFunctionArtifact:
    blocks: list[IRBlock] = []
    refusals: list[IRRefusal] = []
    for block_addr in tuple(sorted(getattr(function, "block_addrs_set", ()) or ())):
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception as ex:  # noqa: BLE001
            refusals.append(IRRefusal("block_decode_failed", str(ex), int(block_addr)))
            continue
        ir_block = _block_to_ir(block)
        blocks.append(ir_block)
        refusals.extend(ir_block.refusals)
    return IRFunctionArtifact(
        function_addr=int(getattr(function, "addr", 0)),
        blocks=tuple(blocks),
        refusals=tuple(refusals),
        summary=build_x86_16_ir_function_artifact_summary(
            IRFunctionArtifact(function_addr=int(getattr(function, "addr", 0)), blocks=tuple(blocks), refusals=tuple(refusals))
        ),
    )


def build_x86_16_ir_function_artifact_summary(artifact: IRFunctionArtifact) -> dict[str, object]:
    space_counts = {space.value: 0 for space in MemSpace}
    address_status_counts = {status.value: 0 for status in AddressStatus}
    segment_origin_counts = {origin.value: 0 for origin in SegmentOrigin}
    condition_counts: dict[str, int] = {}
    ssa_binding_count = 0
    aliasable_values = 0
    for block in artifact.blocks:
        ssa_binding_count += len(build_x86_16_block_local_ssa(block).bindings)
        for instr in block.instrs:
            atoms: tuple[IRAtom, ...] = instr.args + (() if instr.dst is None else (instr.dst,))
            for atom in atoms:
                if isinstance(atom, IRCondition):
                    condition_counts[atom.op] = condition_counts.get(atom.op, 0) + 1
                    for value in atom.args:
                        space_counts[value.space.value] = space_counts.get(value.space.value, 0) + 1
                        if storage_of(value) is not None:
                            aliasable_values += 1
                    continue
                space_counts[atom.space.value] = space_counts.get(atom.space.value, 0) + 1
                if isinstance(atom, IRAddress):
                    address_status_counts[atom.status.value] = address_status_counts.get(atom.status.value, 0) + 1
                    segment_origin_counts[atom.segment_origin.value] = segment_origin_counts.get(atom.segment_origin.value, 0) + 1
                if storage_of(atom) is not None:
                    aliasable_values += 1
    frame = build_x86_16_ir_frame_access_artifact(artifact)
    return {
        "block_count": len(artifact.blocks),
        "instruction_count": sum(len(block.instrs) for block in artifact.blocks),
        "refusal_count": len(artifact.refusals),
        "space_counts": dict(sorted(space_counts.items())),
        "address_status_counts": dict(sorted(address_status_counts.items())),
        "segment_origin_counts": dict(sorted(segment_origin_counts.items())),
        "condition_counts": dict(sorted(condition_counts.items())),
        "aliasable_value_count": aliasable_values,
        "ssa_binding_count": ssa_binding_count,
        "frame_slot_count": len(frame.slots),
        "frame_refusal_count": len(frame.refusals),
    }


def apply_x86_16_vex_ir_artifact(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return False
    function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    artifact = build_x86_16_ir_function_artifact(project, function)
    setattr(codegen, "_inertia_vex_ir_artifact", artifact)
    setattr(codegen, "_inertia_vex_ir_summary", artifact.summary)
    setattr(codegen, "_inertia_vex_ir_frame", build_x86_16_ir_frame_access_artifact(artifact))
    setattr(codegen, "_inertia_vex_ir_function_ssa", build_x86_16_function_ssa(artifact))
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_vex_ir_artifact"] = artifact.to_dict()
        info["x86_16_vex_ir_summary"] = dict(artifact.summary)
        info["x86_16_vex_ir_frame"] = getattr(codegen, "_inertia_vex_ir_frame").to_dict()
        info["x86_16_vex_ir_function_ssa"] = getattr(codegen, "_inertia_vex_ir_function_ssa").to_dict()
    return False
