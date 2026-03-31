from __future__ import annotations

import networkx
import angr.ailment as ailment
from angr.calling_conventions import default_cc
from angr.calling_conventions import SimComboArg, SimRegArg
from angr.analyses.calling_convention import utils as _cc_utils
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.analyses.decompiler.callsite_maker import CallSiteMaker
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CClosingObject,
    CConstant,
    CExpression,
    CFunctionCall,
    CITE,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.analyses.reaching_definitions import rd_state as _rd_state
from angr.analyses.variable_recovery import variable_recovery_base as _variable_recovery_base
from angr.sim_type import SimTypeBottom, SimTypePointer
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeShort
from angr.analyses.typehoon.simple_solver import BASE_LATTICES, BottomType, Int, Int16, TopType
from angr.analyses.typehoon import simple_solver as _typehoon_simple_solver
from angr.analyses.typehoon import translator as _typehoon_translator
try:
    from angr.analyses.typehoon import lifter as _typehoon_lifter
except ImportError:
    _typehoon_lifter = None
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.typehoon.typeconsts import Pointer, Int16 as TCInt16
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
from angr.sim_variable import SimMemoryVariable
from angr.sim_variable import SimRegisterVariable
from angr.sim_variable import SimStackVariable
from angr.sim_variable import SimStackVariable
from .annotations import ANNOTATION_KEY
from .analysis_helpers import resolve_direct_call_target_from_block
from .alias_model import _same_stack_slot_identity, _stack_slot_identity_for_variable
from .decompiler_postprocess_utils import (
    _c_constant_value_8616,
    _iter_c_nodes_deep_8616,
    _match_real_mode_linear_expr_8616,
    _match_bp_stack_load_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
    _segment_reg_name_8616,
    _structured_codegen_node_8616,
)


def _function_complexity_8616(project, function) -> tuple[int, int]:
    block_addrs = sorted(getattr(function, "block_addrs_set", ()) or ())
    byte_count = 0
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        byte_count += len(block.bytes)
    return len(block_addrs), byte_count


def _is_tiny_function_8616(project, function) -> bool:
    block_count, byte_count = _function_complexity_8616(project, function)
    return block_count <= 4 and byte_count <= 32


def _unwrap_synthetic_wide_return_8616(retval):
    if not isinstance(retval, CBinaryOp):
        return None

    candidates = []
    if retval.op == "Or":
        candidates.extend(((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)))
    elif retval.op == "Concat":
        candidates.extend(((retval.lhs, retval.rhs),))
    else:
        return None

    for maybe_wide, maybe_low in candidates:
        if isinstance(maybe_wide, CBinaryOp):
            if maybe_wide.op == "Shl" and _c_constant_value_8616(maybe_wide.rhs) == 16:
                return maybe_low
            if maybe_wide.op == "Concat":
                return maybe_low

    return None


def _promote_stack_prototype_from_bp_loads_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    if prototype is None:
        return False

    arg_names = getattr(prototype, "arg_names", None) or ()
    for name in arg_names:
        if name is None:
            continue
        if not (isinstance(name, str) and len(name) > 1 and name[0] == "a" and name[1:].isdigit()):
            return False

    if not getattr(codegen, "cfunc", None):
        return False

    stack_slots_by_offset = {}
    for variable, _cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimStackVariable):
            continue
        identity = _stack_slot_identity_for_variable(variable)
        if identity is not None:
            stack_slots_by_offset[getattr(variable, "offset", None)] = identity

    offsets = set()
    slot_identities = set()
    for stmt in getattr(codegen.cfunc.statements, "statements", ()) or ():
        if not isinstance(stmt, CReturn):
            continue
        retval = getattr(stmt, "retval", None)
        if retval is None:
            continue
        for node in _iter_c_nodes_deep_8616(retval):
            offset = _match_bp_stack_load_8616(node, project)
            if offset is not None and offset > 0:
                offsets.add(offset)
                slot_identity = stack_slots_by_offset.get(offset)
                if slot_identity is not None:
                    slot_identities.add(slot_identity)

    if len(slot_identities) > 1:
        return False

    existing_args = list(getattr(prototype, "args", ()) or ())

    if offsets:
        target_arg_count = max(len(existing_args), len(offsets) // 2 + 1)
        if target_arg_count > len(existing_args):
            new_args = list(existing_args)
            new_args.extend(
                SimTypeShort(False).with_arch(project.arch)
                for _ in range(target_arg_count - len(existing_args))
            )
        else:
            new_args = list(existing_args)
        arg_names = list(getattr(prototype, "arg_names", None) or ())
        if arg_names:
            arg_names.extend([None] * (len(new_args) - len(arg_names)))
    else:
        arg_names = getattr(prototype, "arg_names", None)

    def has_wide_return_pattern() -> bool:
        for stmt in getattr(codegen.cfunc.statements, "statements", ()) or ():
            if not isinstance(stmt, CReturn):
                continue
            retval = getattr(stmt, "retval", None)
            if not isinstance(retval, CBinaryOp) or retval.op != "Or":
                continue
            for maybe_shl, maybe_other in ((retval.lhs, retval.rhs), (retval.rhs, retval.lhs)):
                if not isinstance(maybe_shl, CBinaryOp) or maybe_shl.op != "Shl":
                    continue
                if _c_constant_value_8616(maybe_shl.rhs) != 16:
                    continue
                if isinstance(maybe_other, CVariable):
                    return True
        return False

    if offsets and target_arg_count > len(existing_args):
        new_proto = prototype.__class__(
            new_args,
            prototype.returnty,
            arg_names=arg_names,
            variadic=getattr(prototype, "variadic", False),
        ).with_arch(project.arch)
        func.prototype = new_proto
        func.is_prototype_guessed = False
        try:
            codegen.cfunc.prototype = new_proto
        except Exception:
            pass
        return True

    if not isinstance(prototype.returnty, SimTypeLong) or not has_wide_return_pattern():
        return False

    wide_ty = SimTypeLong().with_arch(project.arch)
    new_proto = prototype.__class__(
        [wide_ty],
        wide_ty,
        arg_names=getattr(prototype, "arg_names", None),
        variadic=getattr(prototype, "variadic", False),
    ).with_arch(project.arch)
    func.prototype = new_proto
    func.is_prototype_guessed = False
    try:
        codegen.cfunc.prototype = new_proto
    except Exception:
        pass
    return True


def _classify_return_shape_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    prototype = getattr(func, "prototype", None)
    if prototype is None:
        return False

    return_nodes = [node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements) if isinstance(node, CReturn)]
    if not return_nodes:
        return False

    tiny_function = _is_tiny_function_8616(project, func)
    changed = False
    value_returns = 0

    for ret in return_nodes:
        retval = getattr(ret, "retval", None)
        if retval is None:
            continue
        value_returns += 1
        if not tiny_function:
            continue
        replacement = _unwrap_synthetic_wide_return_8616(retval)
        if replacement is None:
            continue
        ret.retval = None
        changed = True

    has_value_return = any(getattr(ret, "retval", None) is not None for ret in return_nodes)
    shape = "scalar_ax" if has_value_return else "void"

    info = getattr(func, "info", None)
    if isinstance(info, dict):
        return_info = info.setdefault("x86_16_return_shape", {})
        return_info["shape"] = shape
        return_info["tiny_function"] = tiny_function
        return_info["value_returns"] = value_returns

    new_returnty = None
    if shape == "void":
        new_returnty = SimTypeBottom()
    elif shape == "scalar_ax" and isinstance(prototype.returnty, SimTypeLong):
        new_returnty = SimTypeShort(False)

    if new_returnty is None:
        return changed

    new_proto = prototype.__class__(
        list(getattr(prototype, "args", ()) or ()),
        new_returnty,
        arg_names=getattr(prototype, "arg_names", None),
        variadic=getattr(prototype, "variadic", False),
    ).with_arch(project.arch)
    func.prototype = new_proto
    func.is_prototype_guessed = False
    try:
        codegen.cfunc.prototype = new_proto
    except Exception:
        pass
    return True

def _apply_annotations_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    func_addr = getattr(codegen.cfunc, "addr", None)
    if func_addr is None:
        return False

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return False

    annotations = func.info.get(ANNOTATION_KEY)
    if not annotations:
        return False

    stack_specs = annotations.get("stack_vars", {})
    global_specs = annotations.get("global_vars", {})

    def global_spec_for(addr: int):
        spec = global_specs.get(addr)
        if isinstance(spec, str):
            return spec, None
        if isinstance(spec, dict):
            name = spec.get("name")
            vartype = spec.get("type")
            if isinstance(name, str):
                return name, vartype
        return None, None

    changed = False
    stack_vars_by_offset = {}
    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if isinstance(variable, SimStackVariable):
            stack_vars_by_offset[getattr(variable, "offset", None)] = cvar

    def spec_name_for(variable):
        offset = getattr(variable, "offset", None)
        spec = stack_specs.get(offset)
        if spec is None and isinstance(offset, int) and offset < 0:
            spec = stack_specs.get(offset + 2)
        if isinstance(spec, str):
            return spec, None
        if isinstance(spec, dict):
            return spec.get("name"), spec.get("type")
        return None, None

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimStackVariable):
            continue

        name, vartype = spec_name_for(variable)
        if name is None:
            current = getattr(variable, "name", None)
            if current and not current.startswith(("arg_", "s_", "v")):
                name = current

        if name is not None:
            target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
            if target is not None and getattr(target, "name", None) != name:
                target.name = name
                changed = True
            if getattr(variable, "name", None) != name:
                variable.name = name
                changed = True

        if vartype is not None and getattr(cvar, "variable_type", None) != vartype:
            cvar.variable_type = vartype
            changed = True

    for variable, cvar in getattr(codegen.cfunc, "variables_in_use", {}).items():
        if not isinstance(variable, SimMemoryVariable):
            continue
        name, vartype = global_spec_for(getattr(variable, "addr", None))
        if not isinstance(name, str):
            continue
        current = getattr(variable, "name", None)
        if current and not current.startswith(("g_", "field_")) and current != name:
            continue
        target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
        if target is not None and getattr(target, "name", None) != name:
            target.name = name
            changed = True
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        if vartype is not None and getattr(cvar, "variable_type", None) != vartype:
            cvar.variable_type = vartype
            changed = True

    def transform_globals(node):
        if not isinstance(node, CVariable):
            return node
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimMemoryVariable):
            return node
        name, vartype = global_spec_for(getattr(variable, "addr", None))
        if not isinstance(name, str):
            return node
        current = getattr(variable, "name", None)
        if current and not current.startswith(("g_", "field_")) and current != name:
            return node
        if getattr(variable, "name", None) != name:
            variable.name = name
            changed = True
        return CVariable(
            variable,
            variable_type=vartype if vartype is not None else getattr(node, "variable_type", None),
            codegen=codegen,
        )

    if _replace_c_children_8616(codegen.cfunc.statements, transform_globals):
        changed = True

    def transform(node):
        if not _structured_codegen_node_8616(node):
            return node
        if isinstance(node, CBinaryOp) and node.op in {"Or", "Add"}:
            for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                low_offset = _match_bp_stack_load_8616(low_expr, project)
                if low_offset is None:
                    continue
                high_offset = _match_bp_stack_load_8616(high_expr, project)
                if high_offset != low_offset + 1:
                    continue
                low_cvar = stack_vars_by_offset.get(low_offset)
                high_cvar = stack_vars_by_offset.get(high_offset)
                if low_cvar is not None and high_cvar is not None:
                    low_var = getattr(low_cvar, "variable", None)
                    high_var = getattr(high_cvar, "variable", None)
                    if isinstance(low_var, SimStackVariable) and isinstance(high_var, SimStackVariable):
                        if not _same_stack_slot_identity(low_var, high_var):
                            continue
                cvar = low_cvar
                if cvar is not None:
                    return cvar
        return node

    if _replace_c_children_8616(codegen.cfunc.statements, transform):
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

def _prune_unused_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    used_registers: set[int] = set()
    used_variables: set[int] = set()

    def collect_reads(node, *, assignment_lhs: bool = False):
        if not _structured_codegen_node_8616(node):
            return
        if isinstance(node, CVariable) and not assignment_lhs:
            variable = getattr(node, "variable", None)
            if variable is not None:
                used_variables.add(id(variable))
                if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) is not None:
                    used_registers.add(variable.reg)
            unified = getattr(node, "unified_variable", None)
            if unified is not None:
                used_variables.add(id(unified))
                if isinstance(unified, SimRegisterVariable) and getattr(unified, "reg", None) is not None:
                    used_registers.add(unified.reg)
            return

        for attr in ("rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "callee_target", "else_node", "retval"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                collect_reads(child)
        lhs = getattr(node, "lhs", None)
        if _structured_codegen_node_8616(lhs):
            collect_reads(lhs, assignment_lhs=isinstance(node, CAssignment))
        for attr in ("args", "operands", "statements"):
            seq = getattr(node, attr, None)
            if not seq:
                continue
            for item in seq:
                if _structured_codegen_node_8616(item):
                    collect_reads(item)
                elif isinstance(item, tuple):
                    for subitem in item:
                        if _structured_codegen_node_8616(subitem):
                            collect_reads(subitem)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for cond, body in pairs:
                if _structured_codegen_node_8616(cond):
                    collect_reads(cond)
                if _structured_codegen_node_8616(body):
                    collect_reads(body)

    collect_reads(codegen.cfunc.statements)

    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            for stmt in node.statements:
                visit(stmt)
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if (
                        isinstance(variable, SimRegisterVariable)
                        and getattr(variable, "reg", None) == flags_offset
                        and id(variable) not in used_variables
                        and getattr(variable, "reg", None) not in used_registers
                    ):
                        changed = True
                        continue
                new_statements.append(stmt)
            node.statements = new_statements

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)

        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed

def _c_expr_uses_register_8616(node, reg_offset: int) -> bool:
    if not _structured_codegen_node_8616(node):
        return False
    if isinstance(node, CVariable):
        variable = getattr(node, "variable", None)
        return isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == reg_offset

    for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iftrue", "iffalse", "callee_target", "else_node", "retval"):
        child = getattr(node, attr, None)
        if _structured_codegen_node_8616(child) and _c_expr_uses_register_8616(child, reg_offset):
            return True

    for attr in ("args", "operands", "statements"):
        seq = getattr(node, attr, None)
        if not seq:
            continue
        for item in seq:
            if _structured_codegen_node_8616(item) and _c_expr_uses_register_8616(item, reg_offset):
                return True
            if isinstance(item, tuple):
                for subitem in item:
                    if _structured_codegen_node_8616(subitem) and _c_expr_uses_register_8616(subitem, reg_offset):
                        return True

    pairs = getattr(node, "condition_and_nodes", None)
    if pairs:
        for cond, body in pairs:
            if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
                return True
            if _structured_codegen_node_8616(body) and _c_expr_uses_register_8616(body, reg_offset):
                return True

    return False

def _stmt_reads_reg_before_write_8616(stmt, reg_offset: int) -> tuple[bool, bool]:
    if not _structured_codegen_node_8616(stmt):
        return False, False

    if isinstance(stmt, CAssignment):
        lhs = stmt.lhs
        writes = (
            isinstance(lhs, CVariable)
            and isinstance(getattr(lhs, "variable", None), SimRegisterVariable)
            and getattr(lhs.variable, "reg", None) == reg_offset
        )
        reads = _c_expr_uses_register_8616(stmt.rhs, reg_offset)
        return reads, writes

    if isinstance(stmt, CStatements):
        for substmt in stmt.statements:
            reads, writes = _stmt_reads_reg_before_write_8616(substmt, reg_offset)
            if reads:
                return True, writes
            if writes:
                return False, True
        return False, False

    if type(stmt).__name__ == "CIfElse":
        cond_nodes = getattr(stmt, "condition_and_nodes", None) or ()
        for cond, body in cond_nodes:
            if _c_expr_uses_register_8616(cond, reg_offset):
                return True, False
            reads, writes = _stmt_reads_reg_before_write_8616(body, reg_offset)
            if reads:
                return True, writes
        else_node = getattr(stmt, "else_node", None)
        if else_node is not None:
            reads, writes = _stmt_reads_reg_before_write_8616(else_node, reg_offset)
            if reads:
                return True, writes
        return False, False

    if type(stmt).__name__ == "CWhileLoop":
        cond = getattr(stmt, "condition", None)
        if _structured_codegen_node_8616(cond) and _c_expr_uses_register_8616(cond, reg_offset):
            return True, False
        body = getattr(stmt, "body", None)
        if body is not None:
            return _stmt_reads_reg_before_write_8616(body, reg_offset)
        return False, False

    return _c_expr_uses_register_8616(stmt, reg_offset), False

def _prune_overwritten_flag_assignments_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    flags_offset = project.arch.registers.get("flags", (None, None))[0]
    if flags_offset is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, CStatements):
            new_statements = []
            statements = list(node.statements)
            for idx, stmt in enumerate(statements):
                remove = False
                if isinstance(stmt, CAssignment) and isinstance(stmt.lhs, CVariable):
                    variable = getattr(stmt.lhs, "variable", None)
                    if isinstance(variable, SimRegisterVariable) and getattr(variable, "reg", None) == flags_offset:
                        remainder = CStatements(statements[idx + 1 :], codegen=codegen)
                        reads, _writes = _stmt_reads_reg_before_write_8616(remainder, flags_offset)
                        if not reads:
                            remove = True
                if not remove:
                    new_statements.append(stmt)
                    visit(stmt)
                else:
                    changed = True
            node.statements = new_statements
            return

        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if _structured_codegen_node_8616(child):
                visit(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _cond, body in pairs:
                if _structured_codegen_node_8616(body):
                    visit(body)

    visit(codegen.cfunc.statements)
    return changed
