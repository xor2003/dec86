# AUTO-GENERATED split from cli_runtime_shared.py
"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import typing
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol, TypeAlias, cast

import angr
from angr.analyses.decompiler import structured_codegen
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.analysis_helpers import InterruptCall, collect_dos_int21_calls, interrupt_service_name

from inertia_decompiler.cli_output import (
    _timestamped_print,
)

from .cli_c_ast_rewrites import _c_constant_value, _same_c_expression, _unwrap_c_casts

structured_c: Any = structured_codegen.c

print: Callable[..., None] = _timestamped_print

RegisterState: TypeAlias = dict[str, dict[tuple[str, ...], int]]


class _CFunctionLike(Protocol):
    """Structured C function surface consumed from angr codegen."""

    addr: int
    statements: object


class _CodegenLike(Protocol):
    """Structured codegen surface consumed from angr decompiler output."""

    cfunc: _CFunctionLike | None


class _FunctionLike(Protocol):
    """Function surface used to attach pseudo callees for DOS interrupt calls."""

    def get_call_target(self, insn_addr: int) -> int | None:
        """Return a resolved call target for an instruction address."""


__all__ = [
    "InterruptWrapperCall",
    "InterruptWrapperFieldAccess",
    "_normalize_interrupt_wrapper_name",
    "_interrupt_wrapper_call_kind",
    "_interrupt_wrapper_call_signature",
    "_interrupt_wrapper_field_path",
    "_interrupt_wrapper_field_role",
    "_interrupt_wrapper_field_access_summary",
    "_interrupt_wrapper_call_text",
    "collect_interrupt_wrapper_calls",
    "collect_interrupt_wrapper_field_accesses",
    "_attach_interrupt_wrapper_callees",
    "_interrupt_wrapper_register_state_value",
    "_interrupt_wrapper_record_register_write",
    "_interrupt_wrapper_helper_call_expr",
    "_interrupt_wrapper_result_helper_expr",
    "_interrupt_wrapper_result_extract_expr",
    "_interrupt_wrapper_result_replacement",
    "_interrupt_wrapper_result_expr_replacement",
    "_lower_interrupt_wrapper_result_reads",
    "_attach_dos_pseudo_callees",
]


def _iter_c_nodes(node: object, *, max_nodes: int = 10000) -> Iterator[object]:
    stack = [node]
    seen: set[int] = set()
    visited = 0
    while stack:
        current = stack.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        visited += 1
        if visited > max_nodes:
            return
        yield current
        if isinstance(current, (list, tuple)):
            stack.extend(reversed(current))
            continue
        for attr in (
            "lhs",
            "rhs",
            "operand",
            "condition",
            "condition_and_nodes",
            "else_node",
            "args",
            "statements",
            "expr",
            "variable",
        ):
            # Dynamic codegen boundary: angr structured-C node children vary by node class.
            child = getattr(current, attr, None)
            if child is None:
                continue
            if attr == "condition_and_nodes" and isinstance(child, list):
                for cond, body in reversed(child):
                    stack.append(body)
                    stack.append(cond)
            else:
                stack.append(child)


@dataclass(frozen=True)
class InterruptWrapperCall:
    """Normalized DOS interrupt wrapper call observed in structured C."""

    callee_name: str
    canonical_name: str
    kind: str
    arguments: tuple[object, ...]
    vector_arg: object | None = None
    inregs_arg: object | None = None
    outregs_arg: object | None = None
    sregs_arg: object | None = None


@dataclass(frozen=True)
class InterruptWrapperFieldAccess:
    """Structured-C field access into DOS interrupt wrapper register structs."""

    base_name: str
    field_path: tuple[str, ...]
    expr: object


def _normalize_interrupt_wrapper_name(name: str | None) -> str | None:
    if not isinstance(name, str) or not name:
        return None
    return name.lstrip("_")


def _interrupt_wrapper_call_kind(name: str | None, args: tuple[object, ...] | None = None) -> str | None:
    canonical = _normalize_interrupt_wrapper_name(name)
    if canonical not in {"int86", "int86x", "intdos", "intdosx"}:
        if canonical != "CallReturn" or not args:
            return None
        first_arg = _unwrap_c_casts(args[0])
        first_value = _c_constant_value(first_arg)
        if len(args) >= 4:
            return "int86x" if first_value is not None else "intdosx"
        if len(args) >= 3:
            return "int86" if first_value is not None else "intdos"
        return None
    return canonical


def _interrupt_wrapper_call_signature(node: object) -> InterruptWrapperCall | None:
    def _impl() -> InterruptWrapperCall | None:
        callee_name: str | None = None
        # Dynamic codegen boundary: CFunctionCall may carry either callee_func or callee_target.
        callee_func = getattr(node, "callee_func", None)
        if callee_func is not None:
            # Dynamic codegen boundary: angr callee function names are optional.
            callee_name = getattr(callee_func, "name", None)
        # Dynamic codegen boundary: CFunctionCall may carry a string callee_target.
        elif isinstance(getattr(node, "callee_target", None), str):
            # Dynamic codegen boundary: CFunctionCall may carry a string callee_target.
            callee_name = getattr(node, "callee_target")

        # Dynamic codegen boundary: CFunctionCall args may be absent on synthetic nodes.
        args = tuple(getattr(node, "args", ()) or ())
        kind = _interrupt_wrapper_call_kind(callee_name, args)
        if kind is None:
            return None
        if kind in {"int86", "int86x"}:
            vector_arg = args[0] if len(args) >= 1 else None
            inregs_arg = args[1] if len(args) >= 2 else None
            outregs_arg = args[2] if len(args) >= 3 else None
            sregs_arg = args[3] if kind == "int86x" and len(args) >= 4 else None
        else:
            vector_arg = None
            inregs_arg = args[0] if len(args) >= 1 else None
            outregs_arg = args[1] if len(args) >= 2 else None
            sregs_arg = args[2] if kind == "intdosx" and len(args) >= 3 else None

        return InterruptWrapperCall(
            callee_name=callee_name or kind,
            canonical_name=kind,
            kind=kind,
            arguments=args,
            vector_arg=vector_arg,
            inregs_arg=inregs_arg,
            outregs_arg=outregs_arg,
            sregs_arg=sregs_arg,
        )

    return _impl()


def _interrupt_wrapper_field_path(expr: object) -> InterruptWrapperFieldAccess | None:
    path: list[str] = []
    current = expr
    while isinstance(current, structured_c.CVariableField):
        # Dynamic codegen boundary: CVariableField field wrappers vary by angr version.
        field = getattr(current, "field", None)
        # Dynamic codegen boundary: field wrapper payload is optional.
        field_name = getattr(field, "field", None)
        if not isinstance(field_name, str) or not field_name:
            return None
        path.append(field_name)
        # Dynamic codegen boundary: nested field access base is supplied by structured C.
        current = getattr(current, "variable", None)

    if not isinstance(current, structured_c.CVariable):
        return None

    current_cvar = cast(Any, current)
    base_name = current_cvar.name
    if not isinstance(base_name, str) or not base_name:
        return None
    if not path:
        return None

    path.reverse()
    return InterruptWrapperFieldAccess(base_name=base_name, field_path=tuple(path), expr=expr)


def _interrupt_wrapper_field_role(base_name: str) -> str:
    if base_name == "inregs":
        return "input"
    if base_name == "outregs":
        return "output"
    if base_name == "sregs":
        return "segment"
    return "other"


def _interrupt_wrapper_field_access_summary(
    accesses: list[InterruptWrapperFieldAccess],
) -> dict[str, list[InterruptWrapperFieldAccess]]:
    summary: dict[str, list[InterruptWrapperFieldAccess]] = {
        "input": [],
        "output": [],
        "segment": [],
        "other": [],
    }
    for access in accesses:
        summary.setdefault(_interrupt_wrapper_field_role(access.base_name), []).append(access)
    return summary


def _interrupt_wrapper_call_text(sig: InterruptWrapperCall) -> str:
    args = [str(arg) for arg in sig.arguments if arg is not None]
    return f"{sig.canonical_name}({', '.join(args)})"


def collect_interrupt_wrapper_calls(codegen: _CodegenLike) -> list[InterruptWrapperCall]:
    """Return normalized interrupt-wrapper calls from structured C codegen."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return []

    calls: list[InterruptWrapperCall] = []
    for node in _iter_c_nodes(cfunc.statements):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        sig = _interrupt_wrapper_call_signature(node)
        if sig is not None:
            calls.append(sig)
    return calls


def collect_interrupt_wrapper_field_accesses(codegen: _CodegenLike) -> list[InterruptWrapperFieldAccess]:
    """Return register-struct field accesses from structured C codegen."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return []

    accesses: list[InterruptWrapperFieldAccess] = []
    for node in _iter_c_nodes(cfunc.statements):
        if not isinstance(node, structured_c.CVariableField):
            continue
        access = _interrupt_wrapper_field_path(node)
        if access is not None and access.base_name in {"inregs", "outregs", "sregs"}:
            accesses.append(access)
    return accesses


def _attach_interrupt_wrapper_callees(project: angr.Project, codegen: _CodegenLike, api_style: str) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    wrapper_calls = collect_interrupt_wrapper_calls(codegen)
    wrapper_field_accesses = collect_interrupt_wrapper_field_accesses(codegen)
    if not wrapper_calls and not wrapper_field_accesses:
        return False

    # Dynamic compatibility boundary: interrupt wrapper cache is attached to the third-party angr Project.
    cache = getattr(project, "_inertia_interrupt_wrappers", None)
    if not isinstance(cache, dict):
        cache = {}
        # Dynamic compatibility boundary: interrupt wrapper cache is attached to the third-party angr Project.
        typing.cast(typing.Any, project)._inertia_interrupt_wrappers = cache

    cache[cfunc.addr] = {
        "api_style": api_style,
        "calls": wrapper_calls,
        "field_accesses": wrapper_field_accesses,
        "field_access_summary": _interrupt_wrapper_field_access_summary(wrapper_field_accesses),
    }

    changed = False
    for node in _iter_c_nodes(cfunc.statements):
        if not isinstance(node, structured_c.CFunctionCall):
            continue
        sig = _interrupt_wrapper_call_signature(node)
        if sig is None:
            continue
        # Dynamic codegen boundary: CFunctionCall may omit callee_func.
        callee_func = getattr(node, "callee_func", None)
        if callee_func is None:
            continue
        # Dynamic codegen boundary: angr callee function names are optional.
        if getattr(callee_func, "name", None) != sig.canonical_name:
            callee_func.name = sig.canonical_name
            changed = True

    return changed


def _interrupt_wrapper_register_state_value(
    state: RegisterState,
    base_name: str,
    field_path: tuple[str, ...],
) -> int | None:
    return state.get(base_name, {}).get(field_path)


def _interrupt_wrapper_record_register_write(
    state: RegisterState,
    base_name: str,
    field_path: tuple[str, ...],
    value: int | None,
) -> None:
    def _impl() -> None:
        if value is None:
            return

        regs = state.setdefault(base_name, {})
        regs[field_path] = value & 0xFFFF

        if field_path == ("x", "ax"):
            ax = value & 0xFFFF
            regs[("h", "ah")] = (ax >> 8) & 0xFF
            regs[("h", "al")] = ax & 0xFF
        elif field_path == ("x", "bx"):
            bx = value & 0xFFFF
            regs[("h", "bh")] = (bx >> 8) & 0xFF
            regs[("h", "bl")] = bx & 0xFF
        elif field_path == ("x", "cx"):
            cx = value & 0xFFFF
            regs[("h", "ch")] = (cx >> 8) & 0xFF
            regs[("h", "cl")] = cx & 0xFF
        elif field_path == ("x", "dx"):
            dx = value & 0xFFFF
            regs[("h", "dh")] = (dx >> 8) & 0xFF
            regs[("h", "dl")] = dx & 0xFF
        elif field_path == ("h", "ah"):
            ah = value & 0xFF
            regs[("h", "ah")] = ah
            al = regs.get(("h", "al"))
            if al is not None:
                regs[("x", "ax")] = ((ah & 0xFF) << 8) | (al & 0xFF)
        elif field_path == ("h", "al"):
            al = value & 0xFF
            regs[("h", "al")] = al
            ah = regs.get(("h", "ah"))
            if ah is not None:
                regs[("x", "ax")] = ((ah & 0xFF) << 8) | (al & 0xFF)
        elif field_path == ("h", "bh"):
            regs[("h", "bh")] = value & 0xFF
        elif field_path == ("h", "bl"):
            regs[("h", "bl")] = value & 0xFF
        elif field_path == ("h", "ch"):
            regs[("h", "ch")] = value & 0xFF
        elif field_path == ("h", "cl"):
            regs[("h", "cl")] = value & 0xFF
        elif field_path == ("h", "dh"):
            regs[("h", "dh")] = value & 0xFF
        elif field_path == ("h", "dl"):
            regs[("h", "dl")] = value & 0xFF

    return _impl()


def _interrupt_wrapper_helper_call_expr(
    sig: InterruptWrapperCall,
    input_state: RegisterState,
    api_style: str,
    codegen: _CodegenLike,
) -> object | None:
    def _impl() -> object | None:
        vector = _c_constant_value(_unwrap_c_casts(sig.vector_arg)) if sig.vector_arg is not None else None
        if vector is None and sig.kind in {"intdos", "intdosx"}:
            vector = 0x21
        if vector is None:
            return None

        service_call = InterruptCall(insn_addr=0, vector=vector & 0xFF)
        if vector == 0x21:
            inregs = "inregs"
            ah = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "ah"))
            al = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "al"))
            ax = _interrupt_wrapper_register_state_value(input_state, inregs, ("x", "ax"))
            if ax is None and ah is not None and al is not None:
                ax = ((ah & 0xFF) << 8) | (al & 0xFF)
            if ax is not None and ah is None:
                ah = (ax >> 8) & 0xFF
            if ax is not None and al is None:
                al = ax & 0xFF

            if ah is None:
                return None

            service_call = InterruptCall(
                insn_addr=0,
                vector=0x21,
                ah=ah,
                al=al,
                ax=ax,
                bx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "bx")),
                cx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "cx")),
                dx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "dx")),
                ds=_interrupt_wrapper_register_state_value(input_state, inregs, ("ds",)),
                es=_interrupt_wrapper_register_state_value(input_state, inregs, ("es",)),
                ss=_interrupt_wrapper_register_state_value(input_state, inregs, ("ss",)),
                cs=_interrupt_wrapper_register_state_value(input_state, inregs, ("cs",)),
            )
        elif vector == 0x10:
            inregs = "inregs"
            ah = _interrupt_wrapper_register_state_value(input_state, inregs, ("h", "ah"))
            if ah is None:
                return None
            service_call = InterruptCall(
                insn_addr=0,
                vector=0x10,
                ah=ah,
                al=_interrupt_wrapper_register_state_value(input_state, inregs, ("h", "al")),
                ax=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "ax")),
                bx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "bx")),
                cx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "cx")),
                dx=_interrupt_wrapper_register_state_value(input_state, inregs, ("x", "dx")),
                ds=_interrupt_wrapper_register_state_value(input_state, inregs, ("ds",)),
                es=_interrupt_wrapper_register_state_value(input_state, inregs, ("es",)),
                ss=_interrupt_wrapper_register_state_value(input_state, inregs, ("ss",)),
                cs=_interrupt_wrapper_register_state_value(input_state, inregs, ("cs",)),
            )

        helper_name = interrupt_service_name(service_call, api_style)
        if helper_name.startswith("int86") or helper_name.startswith("intdos"):
            return None

        helper_args: list[object] = []
        if sig.kind in {"int86", "int86x"} and vector == 0x10:
            selector = _interrupt_wrapper_register_state_value(input_state, "inregs", ("h", "ah"))
            if selector is not None:
                helper_args.append(structured_c.CConstant(selector, SimTypeShort(False), codegen=codegen))
        if sig.kind in {"int86", "int86x"} and vector == 0x16:
            selector = _interrupt_wrapper_register_state_value(input_state, "inregs", ("h", "ah"))
            if selector is not None:
                helper_args.append(structured_c.CConstant(selector, SimTypeShort(False), codegen=codegen))
        if helper_name.endswith("getvect"):
            helper_args.append(structured_c.CConstant(0x21, SimTypeShort(False), codegen=codegen))

        return structured_c.CFunctionCall(helper_name, None, helper_args, codegen=codegen)

    return _impl()


def _interrupt_wrapper_result_helper_expr(helper_expr: object, codegen: _CodegenLike) -> object | None:
    # Dynamic codegen boundary: helper calls may carry either callee_target or callee_func.
    helper_name = getattr(helper_expr, "callee_target", None)
    if not isinstance(helper_name, str):
        # Dynamic codegen boundary: helper calls may carry either callee_target or callee_func.
        helper_func = getattr(helper_expr, "callee_func", None)
        # Dynamic codegen boundary: angr callee function names are optional.
        helper_name = getattr(helper_func, "name", None)
    if not isinstance(helper_name, str) or not helper_name:
        return None

    # Dynamic codegen boundary: CFunctionCall args may be absent on synthetic nodes.
    helper_args = list(getattr(helper_expr, "args", ()) or ())
    return structured_c.CFunctionCall(helper_name, None, helper_args, codegen=codegen)


def _interrupt_wrapper_result_extract_expr(
    access: InterruptWrapperFieldAccess, helper_expr: object, codegen: _CodegenLike
) -> object | None:
    def _impl() -> object | None:
        helper_call = _interrupt_wrapper_result_helper_expr(helper_expr, codegen)
        if helper_call is None:
            return None

        # Dynamic codegen boundary: helper calls may carry either callee_target or callee_func.
        helper_name = getattr(helper_call, "callee_target", None)
        if not isinstance(helper_name, str):
            # Dynamic codegen boundary: helper calls may carry either callee_target or callee_func.
            helper_func = getattr(helper_call, "callee_func", None)
            # Dynamic codegen boundary: angr callee function names are optional.
            helper_name = getattr(helper_func, "name", None)

        if access.base_name == "outregs" and access.field_path == ("x", "ax"):
            return helper_call

        if access.base_name == "outregs" and access.field_path in {("x", "bx"), ("x", "cx"), ("x", "dx")}:
            if "getvect" in str(helper_name) and access.field_path == ("x", "bx"):
                return structured_c.CFunctionCall(
                    "FP_OFF",
                    None,
                    [helper_call],
                    codegen=codegen,
                )
            return helper_call

        if access.base_name == "outregs" and access.field_path == ("h", "ah"):
            return structured_c.CBinaryOp(
                "And",
                structured_c.CBinaryOp(
                    "Shr",
                    helper_call,
                    structured_c.CConstant(8, SimTypeShort(), codegen=codegen),
                    codegen=codegen,
                ),
                structured_c.CConstant(0xFF, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            )

        if access.base_name == "outregs" and access.field_path == ("h", "al"):
            return structured_c.CBinaryOp(
                "And",
                helper_call,
                structured_c.CConstant(0xFF, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            )

        if "getvect" in str(helper_name):
            if access.base_name == "sregs" and access.field_path == ("es",):
                return structured_c.CFunctionCall(
                    "FP_SEG",
                    None,
                    [helper_call],
                    codegen=codegen,
                )

        if access.base_name == "sregs" and access.field_path == ("es",):
            return helper_call

        return None

    return _impl()


def _interrupt_wrapper_result_replacement(
    access: InterruptWrapperFieldAccess,
    helper_expr: object | None,
    api_style: str,
    codegen: _CodegenLike,
) -> object | None:
    if helper_expr is None:
        return None
    return _interrupt_wrapper_result_extract_expr(access, helper_expr, codegen)


def _interrupt_wrapper_result_expr_replacement(
    expr: object, helper_expr: object | None, api_style: str, codegen: _CodegenLike
) -> object | None:
    def _impl() -> object | None:
        if helper_expr is None:
            return None

        replacement = None
        # Dynamic codegen boundary: CVariable names are supplied by structured C.
        if isinstance(expr, structured_c.CVariable) and getattr(expr, "name", None) == "outregs":
            return _interrupt_wrapper_result_helper_expr(helper_expr, codegen)

        access = _interrupt_wrapper_field_path(expr)
        if access is not None:
            replacement = _interrupt_wrapper_result_replacement(access, helper_expr, api_style, codegen)
            if replacement is not None:
                return replacement

        # Dynamic codegen boundary: helper calls may carry either callee_target or callee_func.
        helper_name = getattr(helper_expr, "callee_target", None)
        if not isinstance(helper_name, str):
            # Dynamic codegen boundary: helper calls may carry either callee_target or callee_func.
            helper_func = getattr(helper_expr, "callee_func", None)
            # Dynamic codegen boundary: angr callee function names are optional.
            helper_name = getattr(helper_func, "name", None)
        if not isinstance(helper_name, str) or not helper_name:
            return None

        if helper_name in {"get_dos_version", "_dos_get_version", "dos_get_version"}:
            current_expr = cast(Any, _unwrap_c_casts(expr))
            if not isinstance(current_expr, structured_c.CBinaryOp) or current_expr.op not in {"Or", "Add"}:
                return None

            for high_expr, low_expr in ((current_expr.lhs, current_expr.rhs), (current_expr.rhs, current_expr.lhs)):
                high_expr = cast(Any, _unwrap_c_casts(high_expr))
                low_expr = _unwrap_c_casts(low_expr)
                if not isinstance(high_expr, structured_c.CBinaryOp) or high_expr.op not in {"Shl", "Mul"}:
                    continue

                scale = _c_constant_value(_unwrap_c_casts(high_expr.rhs))
                if scale != 8:
                    continue

                high_access = _interrupt_wrapper_field_path(high_expr.lhs)
                low_access = _interrupt_wrapper_field_path(low_expr)
                if (
                    high_access is not None
                    and low_access is not None
                    and high_access.base_name == low_access.base_name == "outregs"
                    and high_access.field_path == ("h", "ah")
                    and low_access.field_path == ("h", "al")
                ):
                    return structured_c.CFunctionCall(
                        helper_name,
                        # Dynamic codegen boundary: helper calls may carry callee_func.
                        getattr(helper_expr, "callee_func", None),
                        # Dynamic codegen boundary: CFunctionCall args may be absent on synthetic nodes.
                        list(getattr(helper_expr, "args", ()) or ()),
                        codegen=codegen,
                    )

        return None

    return _impl()


def _lower_interrupt_wrapper_result_reads(project: angr.Project, codegen: _CodegenLike, api_style: str) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    changed = False

    def visit(node: object, state: RegisterState, active_helper: object | None) -> None:
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            node_statements = cast(Any, node)
            local_state = {base_name: dict(values) for base_name, values in state.items()}
            current_helper = active_helper
            new_statements = []

            for stmt in node_statements.statements:
                if isinstance(stmt, structured_c.CAssignment):
                    lhs_access = _interrupt_wrapper_field_path(stmt.lhs)
                    if lhs_access is not None and lhs_access.base_name in {"inregs", "outregs", "sregs"}:
                        const_value = _c_constant_value(_unwrap_c_casts(stmt.rhs))
                        _interrupt_wrapper_record_register_write(
                            local_state,
                            lhs_access.base_name,
                            lhs_access.field_path,
                            const_value,
                        )

                    if current_helper is not None:
                        replacement = _interrupt_wrapper_result_expr_replacement(
                            stmt.rhs,
                            current_helper,
                            api_style,
                            codegen,
                        )
                        if replacement is not None and not _same_c_expression(stmt.rhs, replacement):
                            stmt = structured_c.CAssignment(stmt.lhs, replacement, codegen=codegen)
                            changed = True

                elif isinstance(stmt, structured_c.CFunctionCall):
                    sig = _interrupt_wrapper_call_signature(stmt)
                    if sig is not None:
                        helper = _interrupt_wrapper_helper_call_expr(sig, local_state, api_style, codegen)
                        if helper is not None:
                            current_helper = helper
                            if not _same_c_expression(stmt, helper):
                                stmt = helper
                                changed = True
                        else:
                            # Preserve the wrapper call itself as the result source when
                            # service-specific lowering is not possible yet.
                            current_helper = stmt

                elif isinstance(stmt, structured_c.CExpressionStatement):
                    # Dynamic codegen boundary: expression statements can omit expr in synthetic nodes.
                    expr = getattr(stmt, "expr", None)
                    if isinstance(expr, structured_c.CFunctionCall):
                        sig = _interrupt_wrapper_call_signature(expr)
                        if sig is not None:
                            helper = _interrupt_wrapper_helper_call_expr(sig, local_state, api_style, codegen)
                            if helper is not None:
                                current_helper = helper
                                if not _same_c_expression(expr, helper):
                                    stmt = structured_c.CExpressionStatement(
                                        cast(Any, helper), codegen=codegen
                                    )
                                    changed = True
                            else:
                                current_helper = expr

                visit(stmt, local_state, current_helper)
                new_statements.append(stmt)

            if new_statements != list(node_statements.statements):
                node_statements.statements = new_statements
            return

        if isinstance(node, structured_c.CIfElse):
            node_ifelse = cast(Any, node)
            for _cond, body in node_ifelse.condition_and_nodes:
                visit(body, {base_name: dict(values) for base_name, values in state.items()}, active_helper)
            if node_ifelse.else_node is not None:
                visit(
                    node_ifelse.else_node,
                    {base_name: dict(values) for base_name, values in state.items()},
                    active_helper,
                )

    visit(cfunc.statements, {}, None)
    return changed


def _attach_dos_pseudo_callees(
    project: angr.Project, function: _FunctionLike, codegen: _CodegenLike, api_style: str
) -> bool:
    def _impl() -> bool:
        cfunc = codegen.cfunc
        if api_style != "pseudo" or cfunc is None:
            return False

        dos_calls = collect_dos_int21_calls(function)
        if not dos_calls:
            return False

        pseudo_funcs = []
        for call in dos_calls:
            target = function.get_call_target(call.insn_addr)
            if target is None:
                continue
            pseudo_funcs.append(project.kb.functions.function(addr=target))

        if not pseudo_funcs:
            return False

        call_nodes = []
        for node in _iter_c_nodes(cfunc.statements):
            if not isinstance(node, structured_c.CFunctionCall):
                continue
            node_call = cast(Any, node)
            if node_call.callee_func is None:
                call_nodes.append(node_call)

        for node, pseudo_func in zip(call_nodes, pseudo_funcs):
            if pseudo_func is not None:
                node.callee_func = pseudo_func
        return bool(call_nodes)

    return _impl()
