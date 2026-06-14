from __future__ import annotations

from collections.abc import Callable

from .core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

__all__ = [
    "block_segment_hints",
    "expr_to_address",
]


def _infer_address_space(base: tuple[str, ...]) -> tuple[MemSpace, AddressStatus, SegmentOrigin]:
    if not base:
        return MemSpace.UNKNOWN, AddressStatus.UNKNOWN, SegmentOrigin.UNKNOWN
    if any(name in {"bp", "sp"} for name in base):
        return MemSpace.SS, AddressStatus.STABLE, SegmentOrigin.PROVEN
    return MemSpace.DS, AddressStatus.PROVISIONAL, SegmentOrigin.DEFAULTED


def _parse_string_family(mnemonic: str) -> str | None:
    text = mnemonic.strip().lower()
    if not text:
        return None
    parts = text.split()
    base = parts[-1]
    for family in ("movs", "stos", "scas", "cmps", "lods", "ins", "outs"):
        if base.startswith(family):
            return family
    return None


def block_segment_hints(block) -> dict[tuple[str, ...], tuple[MemSpace, AddressStatus, SegmentOrigin]]:
    capstone = getattr(block, "capstone", None)
    insns = tuple(getattr(capstone, "insns", ()) or ())
    hints: dict[tuple[str, ...], tuple[MemSpace, AddressStatus, SegmentOrigin]] = {}
    for insn in insns:
        family = _parse_string_family(str(getattr(insn, "mnemonic", "")))
        if family in {"movs", "stos", "scas", "cmps", "ins"}:
            hints[("di",)] = (MemSpace.ES, AddressStatus.STABLE, SegmentOrigin.PROVEN)
        if family in {"movs", "lods", "cmps", "outs"}:
            hints.setdefault(("si",), (MemSpace.DS, AddressStatus.PROVISIONAL, SegmentOrigin.DEFAULTED))
    return hints


def _address_from_parts(
    base: tuple[str, ...],
    offset: int = 0,
    *,
    size: int = 0,
    expr: tuple[str, ...] | None = None,
    segment_hints: dict[tuple[str, ...], tuple[MemSpace, AddressStatus, SegmentOrigin]] | None = None,
) -> IRAddress:
    hinted = None if segment_hints is None else segment_hints.get(base)
    if hinted is None:
        space, status, segment_origin = _infer_address_space(base)
    else:
        space, status, segment_origin = hinted
    return IRAddress(
        space=space,
        base=base,
        offset=offset,
        size=size,
        status=status,
        segment_origin=segment_origin,
        expr=expr,
    )


def expr_to_address(
    expr,
    tmps,
    conditions,
    *,
    expr_to_value: Callable,
    size: int = 0,
    segment_hints: dict[tuple[str, ...], tuple[MemSpace, AddressStatus, SegmentOrigin]] | None = None,
) -> IRAddress:
    def _unknown(expr_tag: tuple[str, ...]) -> IRAddress:
        return IRAddress(
            MemSpace.UNKNOWN,
            size=size,
            status=AddressStatus.UNKNOWN,
            segment_origin=SegmentOrigin.UNKNOWN,
            expr=expr_tag,
        )

    def _from_rdtmp() -> IRAddress:
        tmp_id = int(getattr(expr, "tmp"))
        tmp_value = tmps.get(tmp_id)
        if tmp_value is None:
            return _unknown(("rdtmp", f"t{tmp_id}"))
        if tmp_value.space == MemSpace.REG and tmp_value.name is not None:
            return _address_from_parts(
                (tmp_value.name,),
                tmp_value.offset,
                size=size,
                expr=("register_base", tmp_value.name),
                segment_hints=segment_hints,
            )
        if tmp_value.expr and tmp_value.expr[:1] == ("Iop_Add16",) and len(tmp_value.expr) == 3:
            return _address_from_parts(
                (tmp_value.expr[1], tmp_value.expr[2]), 0, size=size, expr=tmp_value.expr, segment_hints=segment_hints
            )
        return _unknown(("tmp_expr", tmp_value.name or "tmp"))

    def _from_binop() -> IRAddress:
        op = str(getattr(expr, "op", ""))
        args = tuple(getattr(expr, "args", ()) or ())
        if len(args) != 2:
            return _unknown((op,))
        left = expr_to_value(args[0], tmps, conditions)
        right = expr_to_value(args[1], tmps, conditions)
        if (
            "Add" in op
            and left.space == MemSpace.REG
            and right.space == MemSpace.CONST
            and right.const is not None
            and left.name
        ):
            return _address_from_parts(
                (left.name,),
                left.offset + int(right.const),
                size=size,
                expr=(op, left.name),
                segment_hints=segment_hints,
            )
        if (
            "Sub" in op
            and left.space == MemSpace.REG
            and right.space == MemSpace.CONST
            and right.const is not None
            and left.name
        ):
            return _address_from_parts(
                (left.name,),
                left.offset - int(right.const),
                size=size,
                expr=(op, left.name),
                segment_hints=segment_hints,
            )
        if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.REG and left.name and right.name:
            return _address_from_parts(
                tuple(sorted((left.name, right.name))),
                0,
                size=size,
                expr=(op, left.name, right.name),
                segment_hints=segment_hints,
            )
        return _unknown((op,))

    tag = getattr(expr, "tag", "")
    if tag == "Iex_RdTmp":
        return _from_rdtmp()
    if tag == "Iex_Get":
        value = expr_to_value(expr, tmps, conditions)
        return _address_from_parts(
            () if value.name is None else (value.name,),
            value.offset,
            size=size,
            expr=("register_get", value.name or ""),
            segment_hints=segment_hints,
        )
    if tag == "Iex_Const":
        return IRAddress(
            MemSpace.UNKNOWN,
            offset=int(getattr(getattr(expr, "con", None), "value", 0) or 0),
            size=size,
            status=AddressStatus.UNKNOWN,
            segment_origin=SegmentOrigin.UNKNOWN,
            expr=("absolute_const",),
        )
    if tag == "Iex_Binop":
        return _from_binop()
    return _unknown((tag or "addr_expr",))
