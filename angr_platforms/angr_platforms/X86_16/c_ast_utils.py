"""Syntax-only helpers for angr structured C AST nodes.

Layer: Helper boundary.
Responsibility: provide syntax-only traversal and comparison for C AST nodes.

These helpers are shared by lowering, structuring, validation, and late
postprocess code.  They must remain syntax utilities: traversal, child
replacement, statement unwrapping, and structural expression equality.
This is a dynamic third-party angr boundary: callers may pass different
structured-codegen node classes and versions, so guarded getattr/setattr is
permitted here for C AST shape inspection and child replacement only.

Do not add stack/global/segment recovery, rendered-text parsing, semantic
classification, or validation exceptions here.  Semantic proof belongs in IR,
alias, widening, lowering, structuring, or validation-owned modules.
"""
from __future__ import annotations

import copy
import typing
from collections.abc import Callable, Iterator, Sequence
from contextlib import suppress
from functools import lru_cache
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CConstruct,
    CDirtyExpression,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

__all__ = [
    "_c_ast_cycle_path_8616",
    "_clone_c_ast_tree_8616",
    "_iter_c_node_occurrences_8616",
    "_iter_c_nodes_deep_8616",
    "_iter_c_statement_nodes_8616",
    "_replace_c_children_8616",
    "_safe_assign_cfunc_statements_8616",
    "_same_c_expression_8616",
    "_structured_codegen_node_8616",
    "_structured_slot_names_8616",
    "_unwrap_statements_8616",
]

_STRUCTURED_NON_CHILD_ATTRS_8616 = frozenset({"codegen", "idx", "tags"})
_STRUCTURED_CHILD_ATTRS_BY_CLASS_8616 = {
    "CAILBlock": ("block",),
    "CAssignment": ("lhs", "rhs"),
    "CBinaryOp": ("lhs", "rhs"),
    "CDoWhileLoop": ("condition", "body"),
    "CExpressionStatement": ("expr",),
    "CForLoop": ("initializer", "condition", "iterator", "body"),
    "CFunction": ("arg_list", "statements"),
    "CFunctionCall": ("callee_target", "callee_func", "args"),
    "CITE": ("cond", "iftrue", "iffalse"),
    "CIfBreak": ("condition",),
    "CIfElse": ("condition_and_nodes", "else_node"),
    "CIncompleteSwitchCase": ("head", "cases"),
    "CIndexedVariable": ("variable", "index"),
    "CMultiStatementExpression": ("stmts", "expr"),
    "CReturn": ("retval",),
    "CStatements": ("statements",),
    "CSwitchCase": ("switch", "cases", "default"),
    "CTypeCast": ("expr",),
    "CUnaryOp": ("operand",),
    "CVEXCCallExpression": ("callee", "operands"),
    "CVariableField": ("variable", "field"),
    "CWhileLoop": ("condition", "body"),
}


class _CFuncStatements8616(Protocol):
    """Statement root view needed at the dynamic third-party angr boundary."""

    statements: object


class _CodegenCFunc8616(Protocol):
    """Codegen view needed at the dynamic third-party angr boundary."""

    cfunc: _CFuncStatements8616


class _ConditionalPairs8616(Protocol):
    """Conditional children exposed by the dynamic codegen boundary."""

    condition_and_nodes: Sequence[tuple[object, object]] | None


class _SwitchCases8616(Protocol):
    """Case entries preserved and replaced at the dynamic codegen boundary."""

    cases: Sequence[object] | None


def _unwrap_statements_8616(node: object) -> tuple[object, ...]:
    """Safely extract statement children across the dynamic third-party angr boundary."""
    if node is None:
        return ()
    if isinstance(node, CStatements):
        return tuple(node.statements or ())
    if isinstance(node, (list, tuple)):
        return tuple(node)
    raw = getattr(node, "statements", ())
    if isinstance(raw, CStatements):
        return tuple(raw.statements)
    if isinstance(raw, (list, tuple)):
        return tuple(raw)
    return ()


def _structured_codegen_node_8616(value: object) -> bool:
    """Return whether a value participates in the structured C AST boundary."""
    return isinstance(value, CConstruct) or type(value).__module__.startswith(
        "angr.analyses.decompiler.structured_codegen"
    )


def _c_ast_cycle_path_8616(node: object, *, max_nodes: int = 16_384) -> tuple[str, ...]:
    """Return one owned-child path that proves a structured C AST cycle."""
    active_indexes: dict[int, int] = {}
    completed: set[int] = set()
    path: list[str] = []
    visited = 0

    def _structured_children(value: object, label: str) -> Iterator[tuple[str, object]]:
        """Yield labeled structured nodes from one dynamic child container."""
        if _structured_codegen_node_8616(value):
            yield label, value
            return
        if isinstance(value, dict):
            for key, child in value.items():
                yield from _structured_children(child, f"{label}[{key!r}]")
            return
        if isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                yield from _structured_children(child, f"{label}[{index}]")

    def _walk(current: object, edge: str) -> tuple[str, ...]:
        """Depth-first search using active-path identity, not shared-node identity."""
        nonlocal visited
        if not _structured_codegen_node_8616(current):
            return ()
        marker = id(current)
        op = getattr(current, "op", None)
        detail = f"[op={op}]" if isinstance(op, str) and op else ""
        entry = f"{edge}:{type(current).__name__}{detail}"
        if marker in active_indexes:
            return (*path, f"{entry}(cycle-to={active_indexes[marker]})")
        if marker in completed or visited >= max_nodes:
            return ()
        active_indexes[marker] = len(path)
        path.append(entry)
        visited += 1
        for attr in _structured_slot_names_8616(current):
            with suppress(Exception):
                value = getattr(current, attr)
                for child_edge, child in _structured_children(value, attr):
                    cycle = _walk(child, child_edge)
                    if cycle:
                        return cycle
        path.pop()
        active_indexes.pop(marker, None)
        completed.add(marker)
        return ()

    return _walk(node, "root")


def _clone_c_ast_tree_8616(node: object, memo: dict[int, object] | None = None) -> object:
    """Clone structured C nodes while preserving non-AST boundary objects."""
    if not _structured_codegen_node_8616(node):
        return node
    if memo is None:
        memo = {}
    marker = id(node)
    if marker in memo:
        return memo[marker]

    cloned = copy.copy(node)
    memo[marker] = cloned

    def _clone_value(value: object) -> object:
        """Clone nested structured nodes and child containers only."""
        if _structured_codegen_node_8616(value):
            return _clone_c_ast_tree_8616(value, memo)
        if isinstance(value, list):
            return [_clone_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(_clone_value(item) for item in value)
        if isinstance(value, dict):
            return {key: _clone_value(item) for key, item in value.items()}
        return value

    for attr in _structured_slot_names_8616(node):
        with suppress(Exception):
            setattr(cloned, attr, _clone_value(getattr(node, attr)))
    return cloned


def _safe_assign_cfunc_statements_8616(codegen: object, new_root: object, old_root: object) -> object:
    """Assign cfunc statements across the dynamic third-party angr boundary."""
    if isinstance(old_root, CStatements) and not isinstance(new_root, CStatements):
        if isinstance(new_root, list):
            new_root = CStatements(statements=new_root, codegen=codegen)
        else:
            new_root = CStatements(statements=[new_root], codegen=codegen)
    cast(_CodegenCFunc8616, codegen).cfunc.statements = new_root
    return new_root


@lru_cache(maxsize=256)
def _structured_slot_names_for_type_8616(value_type: type) -> tuple[str, ...]:
    """Collect slots across the dynamic third-party angr C AST boundary."""
    attrs: list[str] = []
    if value_type is object:
        return ()

    for cls in value_type.mro():
        slots = getattr(cls, "__slots__", ())
        if not slots:
            continue
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if isinstance(slot, str) and not slot.startswith("_") and slot not in _STRUCTURED_NON_CHILD_ATTRS_8616:
                attrs.append(slot)  # noqa: PERF401

    seen = set()
    ordered: list[str] = []
    for attr in attrs:
        if attr in seen:
            continue
        seen.add(attr)
        ordered.append(attr)
    return tuple(ordered)


def _structured_slot_names_8616(value: object) -> tuple[str, ...]:
    """List child slots across the dynamic third-party angr C AST boundary."""
    child_attrs = _STRUCTURED_CHILD_ATTRS_BY_CLASS_8616.get(type(value).__name__)
    if child_attrs is not None:
        return child_attrs

    base_attrs = _structured_slot_names_for_type_8616(cast(typing.Hashable, type(value)))
    if not hasattr(value, "__dict__"):
        return base_attrs

    attrs: list[str] = list(base_attrs)
    try:
        dynamic_keys = tuple(value.__dict__.keys())
    except Exception:
        dynamic_keys = ()
    if not dynamic_keys:
        return base_attrs
    attrs.extend(
        attr
        for attr in dynamic_keys
        if isinstance(attr, str) and not attr.startswith("_") and attr not in _STRUCTURED_NON_CHILD_ATTRS_8616
    )
    if not attrs:
        return ()

    seen = set()
    ordered: list[str] = []
    for attr in attrs:
        if attr in seen:
            continue
        seen.add(attr)
        ordered.append(attr)
    return tuple(ordered)


def _iter_c_node_children_8616(value: object, seen_values: set[int] | None = None) -> Iterator[object]:
    """Yield structured nodes directly contained by a dynamic boundary value."""
    if seen_values is None:
        seen_values = set()

    stack = [value]
    while stack:
        current = stack.pop()
        try:
            current_id = id(current)
        except Exception:
            continue
        if current_id in seen_values:
            continue
        seen_values.add(current_id)

        if _structured_codegen_node_8616(current):
            yield current
            continue

        if isinstance(current, (str, bytes)):
            continue

        if isinstance(current, dict):
            with suppress(Exception):
                stack.extend(tuple(current.values()))
            continue

        if isinstance(current, (list, tuple, set)):
            with suppress(Exception):
                stack.extend(tuple(current))
            continue


def _iter_c_statement_nodes_8616(root: object) -> Iterator[object]:
    """Iterate control-flow containers without descending into expressions."""
    stack = [root]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if not _structured_codegen_node_8616(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        for attr in ("statements", "body", "else_node", "condition_and_nodes", "cases", "default"):
            with suppress(Exception):
                value = getattr(current, attr)
                if isinstance(value, (list, tuple)):
                    for item in reversed(tuple(value)):
                        if isinstance(item, tuple):
                            stack.extend(reversed(item))
                        else:
                            stack.append(item)
                else:
                    stack.append(value)


def _replace_c_children_8616(
    node: object,
    transform: Callable[[object], object],
    seen: set[int] | None = None,
    *,
    should_process_child: Callable[[object, str], object] | None = None,
) -> bool:
    """Replace child nodes across the dynamic third-party angr C AST boundary."""
    scalar_attrs = (
        "lhs",
        "rhs",
        "expr",
        "operand",
        "variable",
        "index",
        "condition",
        "cond",
        "initializer",
        "iterator",
        "body",
        "iffalse",
        "iftrue",
        "switch",
        "default",
        "callee_target",
        "else_node",
        "retval",
        "stmts",
    )
    list_attrs = ("args", "operands", "statements")

    def _process_scalar_attr(current: object, attr: str, node_stack: list[object]) -> bool:
        """Process one scalar child across the dynamic third-party angr boundary."""
        if callable(should_process_child) and not bool(should_process_child(current, attr)):
            return False
        if not hasattr(current, attr):
            return False
        try:
            value = getattr(current, attr)
        except Exception:
            return False
        if not _structured_codegen_node_8616(value):
            return False
        new_value = transform(value)
        changed_local = False
        if new_value is not value:
            setattr(current, attr, new_value)
            changed_local = True
            value = new_value
        node_stack.append(value)
        return changed_local

    def _process_list_attr(current: object, attr: str, node_stack: list[object]) -> bool:
        """Process one list child across the dynamic third-party angr boundary."""
        if not hasattr(current, attr):
            return False
        try:
            items = getattr(current, attr)
        except Exception:
            return False
        if not items:
            return False
        changed_local = False
        new_items = None
        for idx, item in enumerate(items):
            if not _structured_codegen_node_8616(item):
                continue
            transformed_item = transform(item)
            if transformed_item is not item:
                if new_items is None:
                    new_items = list(items)
                new_items[idx] = transformed_item
                changed_local = True
            else:
                transformed_item = item
            node_stack.append(transformed_item)
        if new_items is None:
            return changed_local
        if attr == "statements" and isinstance(items, CStatements):
            new_items = CStatements(statements=new_items, codegen=getattr(current, "codegen", None))
        setattr(current, attr, new_items)
        return changed_local

    def _process_condition_pairs(current: object, node_stack: list[object]) -> bool:
        """Process conditional pairs across the dynamic third-party angr boundary."""
        if not hasattr(current, "condition_and_nodes"):
            return False
        try:
            pairs = cast(_ConditionalPairs8616, current).condition_and_nodes
        except Exception:
            pairs = None
        if not pairs:
            return False
        pair_changed = False
        new_pairs = []
        for cond, body in pairs:
            new_cond = transform(cond) if _structured_codegen_node_8616(cond) else cond
            new_body = transform(body) if _structured_codegen_node_8616(body) else body
            if new_cond is not cond or new_body is not body:
                pair_changed = True
            if _structured_codegen_node_8616(new_cond):
                node_stack.append(new_cond)
            if _structured_codegen_node_8616(new_body):
                node_stack.append(new_body)
            new_pairs.append((new_cond, new_body))
        if pair_changed:
            cast(_ConditionalPairs8616, current).condition_and_nodes = new_pairs
        return pair_changed

    def _process_switch_cases(current: object, node_stack: list[object]) -> bool:
        """Process switch cases across the dynamic third-party angr boundary."""
        if not hasattr(current, "cases"):
            return False
        try:
            cases = cast(_SwitchCases8616, current).cases
        except Exception:
            return False
        if not cases:
            return False
        changed_local = False
        new_cases = []
        for item in cases:
            if not isinstance(item, tuple) or len(item) != 2:
                new_cases.append(item)
                continue
            case_value, case_body = item
            new_value = transform(case_value) if _structured_codegen_node_8616(case_value) else case_value
            new_body = transform(case_body) if _structured_codegen_node_8616(case_body) else case_body
            if new_value is not case_value or new_body is not case_body:
                changed_local = True
            if _structured_codegen_node_8616(new_value):
                node_stack.append(new_value)
            if _structured_codegen_node_8616(new_body):
                node_stack.append(new_body)
            new_cases.append((new_value, new_body))
        if changed_local:
            cast(_SwitchCases8616, current).cases = new_cases
        return changed_local

    if seen is None:
        seen = set()
    changed = False
    node_stack = [node]

    while node_stack:
        current = node_stack.pop()
        if not _structured_codegen_node_8616(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)

        child_attrs = frozenset(_structured_slot_names_8616(current))
        for attr in scalar_attrs:
            if attr not in child_attrs:
                continue
            if _process_scalar_attr(current, attr, node_stack):
                changed = True
        for attr in list_attrs:
            if attr not in child_attrs:
                continue
            if _process_list_attr(current, attr, node_stack):
                changed = True
        if "condition_and_nodes" in child_attrs and _process_condition_pairs(current, node_stack):
            changed = True
        if "cases" in child_attrs and _process_switch_cases(current, node_stack):
            changed = True

    return changed


def _iter_c_nodes_deep_8616(node: object, seen: set[int] | None = None) -> Iterator[object]:
    """Iterate C AST nodes across the dynamic third-party angr boundary."""
    if seen is None:
        seen = set()
    if not _structured_codegen_node_8616(node):
        return

    node_stack = [node]
    while node_stack:
        current = node_stack.pop()
        node_id = id(current)
        if node_id in seen:
            continue
        seen.add(node_id)
        yield current

        seen_values: set[int] = set()
        for attr in _structured_slot_names_8616(current):
            try:
                value = getattr(current, attr)
            except Exception:
                continue
            if _structured_codegen_node_8616(value):
                node_stack.append(value)
            elif isinstance(value, (dict, list, tuple, set)):
                node_stack.extend(_iter_c_node_children_8616(value, seen_values))


def _iter_c_node_occurrences_8616(
    value: object,
    active_node_ids: frozenset[int] = frozenset(),
) -> Iterator[object]:
    """Yield each AST edge occurrence while refusing active-path cycles."""
    if isinstance(value, dict):
        for child in value.values():
            yield from _iter_c_node_occurrences_8616(child, active_node_ids)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            yield from _iter_c_node_occurrences_8616(child, active_node_ids)
        return
    if not _structured_codegen_node_8616(value):
        return
    node_id = id(value)
    if node_id in active_node_ids:
        return
    yield value
    child_active_ids = active_node_ids | {node_id}
    for attr in _structured_slot_names_8616(value):
        with suppress(Exception):
            # Dynamic boundary: angr C node child slots vary by class and version.
            yield from _iter_c_node_occurrences_8616(
                getattr(value, attr),
                child_active_ids,
            )


def _same_c_expression_8616(lhs: object, rhs: object) -> bool:
    """Compare C expressions across the dynamic third-party angr boundary."""

    def _same_stack_variable_8616(lvar: SimStackVariable, rvar: SimStackVariable) -> bool:
        """Compare stack variables across the dynamic third-party angr boundary."""
        return bool(
            lvar.offset == rvar.offset
            and lvar.size == rvar.size
            and lvar.base == rvar.base
            and lvar.region == rvar.region
        )

    def _dirty_identity_8616(node: CDirtyExpression) -> tuple[str, object] | None:
        """Build dirty-expression identity across the dynamic third-party angr boundary."""
        dirty = node.dirty
        reg_offset = None
        for attr in ("reg_offset", "reg", "variable_offset"):
            value = None
            with suppress(AttributeError, TypeError, ValueError):
                value = getattr(dirty, attr, None)
            if isinstance(value, int):
                reg_offset = value
                break
        if isinstance(reg_offset, int):
            bits = None
            with suppress(AttributeError, TypeError, ValueError):
                bits = getattr(dirty, "bits", None)
            size = None
            with suppress(AttributeError, TypeError, ValueError):
                size = getattr(dirty, "size", None)
            size_bits = bits if isinstance(bits, int) else size * 8 if isinstance(size, int) else None
            return ("dirty-reg", (reg_offset, size_bits))
        if isinstance(dirty, str) and dirty:
            return ("dirty-name", dirty)
        varid = getattr(dirty, "varid", None)
        if isinstance(varid, int):
            return ("dirty-varid", varid)
        tmp_idx = getattr(dirty, "tmp_idx", None)
        if isinstance(tmp_idx, int):
            return ("dirty-tmp", tmp_idx)
        name = getattr(dirty, "name", None)
        if isinstance(name, str) and name:
            return ("dirty-name", name)
        return None

    if type(lhs) is not type(rhs):
        return False
    if isinstance(lhs, CConstant):
        rhs_constant = cast(CConstant, rhs)
        return bool(lhs.value == rhs_constant.value)
    if isinstance(lhs, CTypeCast):
        rhs_cast = cast(CTypeCast, rhs)
        return _same_c_expression_8616(lhs.expr, rhs_cast.expr)
    if isinstance(lhs, CUnaryOp):
        rhs_unary = cast(CUnaryOp, rhs)
        return lhs.op == rhs_unary.op and _same_c_expression_8616(lhs.operand, rhs_unary.operand)
    if isinstance(lhs, CBinaryOp):
        rhs_binary = cast(CBinaryOp, rhs)
        return (
            lhs.op == rhs_binary.op
            and _same_c_expression_8616(lhs.lhs, rhs_binary.lhs)
            and _same_c_expression_8616(lhs.rhs, rhs_binary.rhs)
        )
    if isinstance(lhs, CITE):
        rhs_ite = cast(CITE, rhs)
        return (
            _same_c_expression_8616(lhs.cond, rhs_ite.cond)
            and _same_c_expression_8616(lhs.iftrue, rhs_ite.iftrue)
            and _same_c_expression_8616(lhs.iffalse, rhs_ite.iffalse)
        )
    if isinstance(lhs, CFunctionCall):
        rhs_call = cast(CFunctionCall, rhs)
        if not _same_call_target_8616(lhs, rhs_call):
            return False
        lhs_args = tuple(lhs.args or ())
        rhs_args = tuple(rhs_call.args or ())
        return len(lhs_args) == len(rhs_args) and all(
            _same_c_expression_8616(lhs_arg, rhs_arg) for lhs_arg, rhs_arg in zip(lhs_args, rhs_args, strict=True)
        )
    if isinstance(lhs, CIndexedVariable):
        rhs_indexed = cast(CIndexedVariable, rhs)
        return _same_c_expression_8616(lhs.variable, rhs_indexed.variable) and _same_c_expression_8616(
            lhs.index, rhs_indexed.index
        )
    if isinstance(lhs, CDirtyExpression):
        rhs_dirty = cast(CDirtyExpression, rhs)
        lhs_key = _dirty_identity_8616(lhs)
        rhs_key = _dirty_identity_8616(rhs_dirty)
        if lhs_key is not None or rhs_key is not None:
            return lhs_key == rhs_key
        return lhs.dirty is rhs_dirty.dirty
    if isinstance(lhs, CVariable):
        rhs_variable = cast(CVariable, rhs)
        lvar = lhs.variable
        rvar = rhs_variable.variable
        if type(lvar) is not type(rvar):
            return False
        if isinstance(lvar, SimRegisterVariable):
            return bool(lvar.reg == cast(SimRegisterVariable, rvar).reg)
        if isinstance(lvar, SimMemoryVariable):
            rhs_memory = cast(SimMemoryVariable, rvar)
            return bool(lvar.addr == rhs_memory.addr and lvar.size == rhs_memory.size)
        if isinstance(lvar, SimStackVariable):
            if not isinstance(rvar, SimStackVariable):
                return False
            return _same_stack_variable_8616(lvar, rvar)
    return lhs is rhs


def _same_call_target_8616(lhs: CFunctionCall, rhs: CFunctionCall) -> bool:
    """Compare call targets across the dynamic third-party angr boundary."""
    lhs_func = lhs.callee_func
    rhs_func = rhs.callee_func
    if lhs_func is not None or rhs_func is not None:
        if lhs_func is None or rhs_func is None:
            return False
        lhs_addr = getattr(lhs_func, "addr", None)
        rhs_addr = getattr(rhs_func, "addr", None)
        if isinstance(lhs_addr, int) or isinstance(rhs_addr, int):
            return lhs_addr == rhs_addr
        return getattr(lhs_func, "name", None) == getattr(rhs_func, "name", None)
    lhs_target = lhs.callee_target
    rhs_target = rhs.callee_target
    if lhs_target is None or rhs_target is None:
        return lhs_target is rhs_target
    return _same_c_expression_8616(lhs_target, rhs_target)
