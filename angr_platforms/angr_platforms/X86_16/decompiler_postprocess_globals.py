from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CBinaryOp, CConstant, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable

from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _global_load_addr_8616,
    _global_memory_addr_8616,
    _is_shifted_high_byte_8616,
    _iter_c_nodes_deep_8616,
    _make_word_global_8616,
    _match_scaled_high_byte_8616,
    _match_segmented_dereference_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
)

__all__ = [
    "_coalesce_word_global_loads_8616",
    "_coalesce_word_global_constant_stores_8616",
    "_apply_word_global_types_8616",
    "_prune_unused_unnamed_memory_declarations_8616",
]


def _coalesce_word_global_loads_8616(project, codegen) -> set[int]:
    if getattr(codegen, "cfunc", None) is None:
        return set()

    created = {}
    changed_addrs: set[int] = set()

    def make_word_global(addr: int):
        existing = created.get(addr)
        if existing is not None:
            return existing
        cvar = _make_word_global_8616(codegen, addr)
        created[addr] = cvar
        return cvar

    def transform(node):
        if not isinstance(node, CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr = _global_load_addr_8616(low_expr, project)
            if low_addr is None:
                continue
            high_addr = _match_scaled_high_byte_8616(high_expr, project)
            if high_addr != low_addr + 1:
                continue
            changed_addrs.add(low_addr)
            return make_word_global(low_addr)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
    _replace_c_children_8616(root, transform)
    return changed_addrs


def _coalesce_word_global_constant_stores_8616(project, codegen) -> set[int]:
    if getattr(codegen, "cfunc", None) is None:
        return set()

    changed_addrs: set[int] = set()

    def lhs_addr(node):
        addr = _global_memory_addr_8616(node)
        if addr is not None:
            return addr
        seg_name, linear = _match_segmented_dereference_8616(node, project)
        if seg_name != "ds":
            return None
        return linear

    def visit(node):
        if isinstance(node, CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, CAssignment)
                    and isinstance(node.statements[i + 1], CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    base_addr = lhs_addr(stmt.lhs)
                    next_addr = lhs_addr(next_stmt.lhs)
                    if base_addr is not None and next_addr == base_addr + 1:
                        if isinstance(stmt.rhs, CConstant) and isinstance(next_stmt.rhs, CConstant):
                            value = (stmt.rhs.value & 0xFF) | ((next_stmt.rhs.value & 0xFF) << 8)
                            new_statements.append(
                                CAssignment(
                                    _make_word_global_8616(codegen, base_addr),
                                    CConstant(value, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                            )
                            changed_addrs.add(base_addr)
                            i += 2
                            continue

                        if _is_shifted_high_byte_8616(next_stmt.rhs, stmt.rhs):
                            new_statements.append(
                                CAssignment(
                                    _make_word_global_8616(codegen, base_addr),
                                    stmt.rhs,
                                    codegen=codegen,
                                )
                            )
                            changed_addrs.add(base_addr)
                            i += 2
                            continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif hasattr(node, "condition_and_nodes"):
            for _, body in getattr(node, "condition_and_nodes", ()):
                visit(body)
            else_node = getattr(node, "else_node", None)
            if else_node is not None:
                visit(else_node)

    visit(codegen.cfunc.statements)
    return changed_addrs


def _apply_word_global_types_8616(codegen, addrs: set[int]) -> bool:
    if not addrs or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    target_type = SimTypeShort(False)

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        if getattr(variable, "addr", None) not in addrs:
            continue
        if getattr(variable, "size", None) != 2:
            variable.size = 2
            changed = True
        if getattr(cvar, "variable_type", None) != target_type:
            cvar.variable_type = target_type
            changed = True
        unified = getattr(cvar, "unified_variable", None)
        if unified is not None and getattr(unified, "size", None) != 2:
            try:
                unified.size = 2
                changed = True
            except Exception:
                pass

    for cextern in getattr(codegen, "cexterns", ()) or ():
        variable = getattr(cextern, "variable", None)
        if not isinstance(variable, SimMemoryVariable):
            continue
        if getattr(variable, "addr", None) not in addrs:
            continue
        if getattr(variable, "size", None) != 2:
            variable.size = 2
            changed = True
        if getattr(cextern, "variable_type", None) != target_type:
            cextern.variable_type = target_type
            changed = True

    unified_locals = getattr(codegen.cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        for variable, cvar_and_vartypes in list(unified_locals.items()):
            if not isinstance(variable, SimMemoryVariable):
                continue
            if getattr(variable, "addr", None) not in addrs:
                continue
            if getattr(variable, "size", None) != 2:
                variable.size = 2
                changed = True
            new_entries = {(cvariable, target_type) for cvariable, _vartype in cvar_and_vartypes}
            if new_entries != cvar_and_vartypes:
                unified_locals[variable] = new_entries
                changed = True

    return changed


def _prune_unused_unnamed_memory_declarations_8616(codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    used_variables: set[int] = set()
    for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
        if not isinstance(node, CVariable):
            continue
        variable = getattr(node, "variable", None)
        if variable is not None:
            used_variables.add(id(variable))
        unified = getattr(node, "unified_variable", None)
        if unified is not None:
            used_variables.add(id(unified))

    changed = False
    variables_in_use = getattr(codegen.cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for variable in list(variables_in_use):
            if not isinstance(variable, SimMemoryVariable):
                continue
            name = getattr(variable, "name", None)
            if not isinstance(name, str) or not name.startswith("g_"):
                continue
            if id(variable) in used_variables:
                continue
            cvar = variables_in_use[variable]
            unified = getattr(cvar, "unified_variable", None)
            if unified is not None and id(unified) in used_variables:
                continue
            del variables_in_use[variable]
            changed = True

    return changed
