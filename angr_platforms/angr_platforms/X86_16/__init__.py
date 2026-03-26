__all__ = ["annotations", "arch_86_16", "lift_86_16", "load_dos_mz", "simos_86_16"]

from . import annotations, arch_86_16, lift_86_16, load_dos_mz, simos_86_16  # noqa: F401

try:
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
        CStatements,
        CTypeCast,
        CUnaryOp,
        CVariable,
    )
    from angr.analyses.decompiler.decompiler import Decompiler
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
    from .annotations import ANNOTATION_KEY
    from .analysis_helpers import resolve_direct_call_target_from_block

    _orig_is_sane_register_variable = _cc_utils.is_sane_register_variable

    def _is_sane_register_variable_8616(arch, reg_offset, reg_size, def_cc=None):
        if arch.name == "86_16":
            return True
        return _orig_is_sane_register_variable(arch, reg_offset, reg_size, def_cc=def_cc)

    if getattr(_cc_utils.is_sane_register_variable, "__name__", "") != "_is_sane_register_variable_8616":
        _cc_utils.is_sane_register_variable = _is_sane_register_variable_8616

    _orig_stack_addr_from_offset = _variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset

    def _stack_addr_from_offset_8616(self, offset):
        if self.arch.bits == 16:
            return (offset + 0x7FFE) & 0xFFFF
        return _orig_stack_addr_from_offset(self, offset)

    if (
        getattr(_variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset, "__name__", "")
        != "_stack_addr_from_offset_8616"
    ):
        _variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset = _stack_addr_from_offset_8616

    _orig_initial_stack_pointer = _rd_state.ReachingDefinitionsState._initial_stack_pointer

    def _initial_stack_pointer_8616(self):
        if self.arch.bits == 16:
            return claripy.BVS("stack_base", 16, explicit_name=True)
        return _orig_initial_stack_pointer(self)

    if getattr(_rd_state.ReachingDefinitionsState._initial_stack_pointer, "__name__", "") != "_initial_stack_pointer_8616":
        _rd_state.ReachingDefinitionsState._initial_stack_pointer = _initial_stack_pointer_8616

    class Pointer16(Pointer, TCInt16):
        def __init__(self, basetype=None, name: str | None = None):
            Pointer.__init__(self, basetype, name=name)
            TCInt16.__init__(self, name=name)

        def __repr__(self, memo=None):
            bt = self.basetype.__repr__(memo=memo) if isinstance(self.basetype, TCInt16) else repr(self.basetype)
            name_str = f"{self.name}#" if self.name else ""
            return f"{name_str}ptr16({bt})"

    if not hasattr(_typehoon_simple_solver, "Pointer16"):
        _typehoon_simple_solver.Pointer16 = Pointer16
        _typehoon_simple_solver.Pointer16_ = Pointer16()
        _typehoon_simple_solver.PRIMITIVE_TYPES = set(_typehoon_simple_solver.PRIMITIVE_TYPES) | {
            _typehoon_simple_solver.Pointer16_
        }

    base_lattice_16 = networkx.DiGraph()
    base_lattice_16.add_edge(TopType(), Int())
    base_lattice_16.add_edge(Int(), Int16())
    base_lattice_16.add_edge(Int16(), _typehoon_simple_solver.Pointer16_)
    base_lattice_16.add_edge(_typehoon_simple_solver.Pointer16_, BottomType())
    BASE_LATTICES[16] = base_lattice_16

    def _pointer_class_16(self):
        if self.bits == 16:
            return Pointer16
        if self.bits == 32:
            return _typehoon_simple_solver.Pointer32
        if self.bits == 64:
            return _typehoon_simple_solver.Pointer64
        raise NotImplementedError(f"Unsupported bits {self.bits}")

    _typehoon_simple_solver.SimpleSolver._pointer_class = _pointer_class_16

    _orig_simple_solver_init = _typehoon_simple_solver.SimpleSolver.__init__

    def _simple_solver_init_8616(
        self,
        bits: int,
        constraints,
        typevars,
        constraint_set_degradation_threshold: int = 150,
        stackvar_max_sizes=None,
    ):
        if bits != 16:
            return _orig_simple_solver_init(
                self,
                bits,
                constraints,
                typevars,
                constraint_set_degradation_threshold=constraint_set_degradation_threshold,
                stackvar_max_sizes=stackvar_max_sizes,
            )

        self.bits = bits
        self._constraints = constraints
        self._typevars = typevars
        self.stackvar_max_sizes = stackvar_max_sizes if stackvar_max_sizes is not None else {}
        self._constraint_set_degradation_threshold = constraint_set_degradation_threshold
        self._base_lattice = BASE_LATTICES[bits]
        self._base_lattice_inverted = networkx.DiGraph()
        for src, dst in self._base_lattice.edges:
            self._base_lattice_inverted.add_edge(dst, src)

        self.processed_constraints_count = 0
        self.simplified_constraints_count = 0
        self.eqclass_constraints_count = []

        self._equivalence = _typehoon_simple_solver.defaultdict(dict)
        for func_tv in list(self._constraints):
            if self._constraints[func_tv]:
                self.processed_constraints_count += len(self._constraints[func_tv])
                self.preprocess(func_tv)
                self.simplified_constraints_count += len(self._constraints[func_tv])

        self._repr_tv_to_tvs = _typehoon_simple_solver.defaultdict(set)
        for tv, repr_tv in self._equivalence.items():
            self._repr_tv_to_tvs[repr_tv].add(tv)

        self.solution = {}
        for tv, sol in self._equivalence.items():
            if isinstance(tv, _typehoon_simple_solver.TypeVariable) and isinstance(
                sol, _typehoon_simple_solver.TypeConstant
            ):
                self.solution[tv] = sol

        self._solution_cache = {}
        self.solve()
        for func_tv in list(self._constraints):
            self._convert_arrays(self._constraints[func_tv])

        for tv, tv_eq in self._equivalence.items():
            if tv not in self.solution and tv_eq in self.solution:
                self.solution[tv] = self.solution[tv_eq]

    if getattr(_typehoon_simple_solver.SimpleSolver.__init__, "__name__", "") != "_simple_solver_init_8616":
        _typehoon_simple_solver.SimpleSolver.__init__ = _simple_solver_init_8616

    def _translate_pointer16(self, tc):
        if isinstance(tc.basetype, _typehoon_translator.typeconsts.BottomType):
            internal = SimTypeBottom(label="void").with_arch(self.arch)
        else:
            internal = self._tc2simtype(tc.basetype)
        return SimTypePointer(internal).with_arch(self.arch)

    def _translate_simtype_pointer_16(self, st):
        base = self._simtype2tc(st.pts_to)
        if self.arch.bits == 16:
            return Pointer16(base)
        if self.arch.bits == 32:
            return _typehoon_translator.typeconsts.Pointer32(base)
        if self.arch.bits == 64:
            return _typehoon_translator.typeconsts.Pointer64(base)
        raise TypeError(f"Unsupported pointer size {self.arch.bits}")

    _typehoon_translator.TypeTranslator._translate_Pointer16 = _translate_pointer16
    _typehoon_translator.TypeTranslator._translate_SimTypePointer = _translate_simtype_pointer_16
    _typehoon_translator.TypeConstHandlers[Pointer16] = _typehoon_translator.TypeTranslator._translate_Pointer16
    _typehoon_translator.SimTypeHandlers[SimTypePointer] = _typehoon_translator.TypeTranslator._translate_SimTypePointer

    if _typehoon_lifter is not None:
        _orig_lifter_init = _typehoon_lifter.TypeLifter.__init__

        def _typelifter_init_16(self, bits: int):
            if bits not in (16, 32, 64):
                raise ValueError("TypeLifter only supports 16-bit, 32-bit, or 64-bit pointers.")
            self.bits = bits
            self.memo = {}

        def _lift_simtype_pointer_16(self, ty):
            if self.bits == 16:
                return Pointer16(self.lift(ty.pts_to))
            if self.bits == 32:
                return _typehoon_lifter.Pointer32(self.lift(ty.pts_to))
            if self.bits == 64:
                return _typehoon_lifter.Pointer64(self.lift(ty.pts_to))
            raise ValueError(f"Unsupported bits {self.bits}.")

        _typehoon_lifter.TypeLifter.__init__ = _typelifter_init_16
        _typehoon_lifter.TypeLifter._lift_SimTypePointer = _lift_simtype_pointer_16

    _orig_clinic_make_function_prototype = Clinic._make_function_prototype
    _orig_clinic_simplify_function = Clinic._simplify_function

    def _simtype_for_stack_size(size):
        if size == 1:
            return SimTypeChar()
        if size == 2:
            return SimTypeShort()
        if size == 4:
            return SimTypeLong()
        return SimTypeLongLong()

    def _has_dxax_wide_return(function):
        if function.project is None or function.project.arch.name != "86_16":
            return False
        endpoints = function.endpoints or ()
        for endpoint in endpoints:
            block_addr = endpoint.addr if hasattr(endpoint, "addr") else endpoint
            try:
                block = function.project.factory.block(block_addr)
            except Exception:
                continue
            if block.vex.jumpkind != "Ijk_Ret" or not getattr(block.capstone, "insns", None):
                continue
            last_ax = None
            last_dx = None
            for insn in reversed(block.capstone.insns[:-1]):
                try:
                    regs_read, regs_write = insn.insn.regs_access()
                except Exception:
                    continue
                regs_read = {insn.insn.reg_name(reg) for reg in regs_read}
                regs_write = {insn.insn.reg_name(reg) for reg in regs_write}
                if last_ax is None:
                    if "ax" in regs_write:
                        last_ax = "write"
                    elif "ax" in regs_read:
                        last_ax = "read"
                if last_dx is None:
                    if "dx" in regs_write:
                        last_dx = "write"
                    elif "dx" in regs_read:
                        last_dx = "read"
                if last_ax is not None and last_dx is not None:
                    break
            if last_ax == "write" and last_dx == "write":
                return True
        return False

    def _stack_arg_offsets_from_instructions(function):
        if function.project is None or function.project.arch.name != "86_16":
            return []
        offsets = set()
        for block_addr in function.block_addrs_set:
            try:
                block = function.project.factory.block(block_addr)
            except Exception:
                continue
            for insn in getattr(block.capstone, "insns", ()):
                for operand in getattr(insn.insn, "operands", ()):
                    if operand.type != 3 or getattr(operand, "size", None) != 2:
                        continue
                    mem = operand.mem
                    if mem.index:
                        continue
                    base = insn.insn.reg_name(mem.base).lower() if mem.base else None
                    if base not in {"bp", "sp"} or mem.disp < 4:
                        continue
                    offsets.add(mem.disp - 2)
        return sorted(offsets)

    def _make_function_prototype_8616(self, arg_list, variable_kb):
        if (
            self.project.arch.name == "86_16"
            and (not arg_list)
            and self.function.prototype is not None
            and self.function.is_prototype_guessed
        ):
            variables = variable_kb.variables[self.function.addr]
            wide_return = _has_dxax_wide_return(self.function)
            stack_args = []
            seen_offsets = set()
            for var in variables.get_variables():
                if not isinstance(var, SimStackVariable):
                    continue
                if getattr(var, "name", None) == "ret_addr":
                    continue
                if not variable_kb.variables.get_variable_accesses(var):
                    continue
                if var.offset < 2 or var.offset in seen_offsets:
                    continue
                seen_offsets.add(var.offset)
                size = max(var.size or self.project.arch.bytes, self.project.arch.bytes)
                stack_args.append((var.offset, size))

            returnty = self.function.prototype.returnty
            existing_arg_names = self.function.prototype.arg_names if self.function.prototype is not None else ()
            if wide_return and (
                returnty is None or isinstance(returnty, (SimTypeInt, SimTypeShort, SimTypeChar))
            ):
                returnty = SimTypeLong()
            if wide_return:
                instr_offsets = _stack_arg_offsets_from_instructions(self.function)
                if instr_offsets:
                    stack_args = []
                    idx = 0
                    while idx < len(instr_offsets):
                        offset = instr_offsets[idx]
                        if idx + 1 < len(instr_offsets) and instr_offsets[idx + 1] == offset + 2:
                            stack_args.append((offset, 4))
                            idx += 2
                            continue
                        stack_args.append((offset, 2))
                        idx += 1

            if stack_args:
                stack_args.sort(key=lambda item: item[0])
                collapsed_args = []
                idx = 0
                while idx < len(stack_args):
                    offset, size = stack_args[idx]
                    if (
                        wide_return
                        and size == 2
                        and idx + 1 < len(stack_args)
                        and stack_args[idx + 1][0] == offset + 2
                        and stack_args[idx + 1][1] == 2
                    ):
                        collapsed_args.append((offset, SimTypeLong()))
                        idx += 2
                        continue
                    collapsed_args.append((offset, _simtype_for_stack_size(size)))
                    idx += 1
                if returnty is None:
                    returnty = SimTypeInt()
                arg_names = existing_arg_names[: len(collapsed_args)] if existing_arg_names else ()
                self.function.prototype = SimTypeFunction(
                    [ty for _, ty in collapsed_args], returnty, arg_names=arg_names
                ).with_arch(self.project.arch)
                self.function.is_prototype_guessed = False
                return
            if wide_return:
                self.function.prototype = SimTypeFunction(
                    self.function.prototype.args,
                    returnty or SimTypeLong(),
                    arg_names=existing_arg_names,
                ).with_arch(self.project.arch)
                self.function.is_prototype_guessed = False
                return

        return _orig_clinic_make_function_prototype(self, arg_list, variable_kb)

    Clinic._make_function_prototype = _make_function_prototype_8616

    def _simplify_function_8616(
        self,
        ail_graph,
        remove_dead_memdefs=False,
        stack_arg_offsets=None,
        unify_variables=False,
        narrow_expressions=False,
        only_consts=False,
        fold_callexprs_into_conditions=False,
        rewrite_ccalls=True,
        rename_ccalls=True,
        removed_vvar_ids=None,
        arg_vvars=None,
        preserve_vvar_ids=None,
        max_iterations=None,
    ):
        cap = max_iterations if max_iterations is not None else self._simplification_max_iterations
        if self.project.arch.name == "86_16":
            block_count = len(ail_graph) if ail_graph is not None else 0
            stmt_count = 0
            if ail_graph is not None:
                for block in ail_graph:
                    stmt_count += len(getattr(block, "statements", ()))
            if block_count <= 8 and stmt_count <= 80:
                cap = min(cap, 1)
                narrow_expressions = False
        for idx in range(cap):
            simplified = self._simplify_function_once(
                ail_graph,
                remove_dead_memdefs=remove_dead_memdefs,
                unify_variables=unify_variables,
                stack_arg_offsets=stack_arg_offsets,
                narrow_expressions=narrow_expressions and idx == 0,
                only_consts=only_consts,
                fold_callexprs_into_conditions=fold_callexprs_into_conditions,
                rewrite_ccalls=rewrite_ccalls,
                rename_ccalls=rename_ccalls,
                removed_vvar_ids=removed_vvar_ids,
                arg_vvars=arg_vvars,
                preserve_vvar_ids=preserve_vvar_ids,
            )
            if not simplified:
                break

    if getattr(Clinic._simplify_function, "__name__", "") != "_simplify_function_8616":
        Clinic._simplify_function = _simplify_function_8616

    _orig_cite_c_repr_chunks = CITE.c_repr_chunks
    _orig_cunaryop_c_repr_chunks_not = CUnaryOp._c_repr_chunks_not

    def _unwrap_bool_constant(expr):
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        if isinstance(expr, CConstant) and isinstance(expr.value, int):
            return expr.value
        return None

    def _unwrap_double_not(expr):
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        if isinstance(expr, CUnaryOp) and expr.op == "Not":
            inner = expr.operand
            while isinstance(inner, CTypeCast):
                inner = inner.expr
            if isinstance(inner, CUnaryOp) and inner.op == "Not":
                return inner.operand
        return None

    def _unwrap_zero_comparison(expr):
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        if not isinstance(expr, CBinaryOp) or expr.op not in {"CmpEQ", "CmpNE"}:
            return None
        lhs_zero = _unwrap_bool_constant(expr.lhs)
        rhs_zero = _unwrap_bool_constant(expr.rhs)
        if rhs_zero == 0:
            return expr.op, expr.lhs
        if lhs_zero == 0:
            return expr.op, expr.rhs
        return None

    def _c_repr_chunks_8616(self, indent=0, asexpr=False):
        true_val = _unwrap_bool_constant(self.iftrue)
        false_val = _unwrap_bool_constant(self.iffalse)
        zero_cmp = _unwrap_zero_comparison(self.cond)
        if (true_val, false_val) == (0, 1):
            if zero_cmp is not None:
                op, other = zero_cmp
                if op == "CmpEQ":
                    yield from CExpression._try_c_repr_chunks(other)
                    return
                if op == "CmpNE":
                    yield "!", self
                    paren = CClosingObject("(")
                    yield "(", paren
                    yield from CExpression._try_c_repr_chunks(other)
                    yield ")", paren
                    return
            yield "!", self
            paren = CClosingObject("(")
            yield "(", paren
            yield from self.cond.c_repr_chunks()
            yield ")", paren
            return
        if (true_val, false_val) == (1, 0):
            if zero_cmp is not None:
                op, other = zero_cmp
                if op == "CmpEQ":
                    yield "!", self
                    paren = CClosingObject("(")
                    yield "(", paren
                    yield from CExpression._try_c_repr_chunks(other)
                    yield ")", paren
                    return
                if op == "CmpNE":
                    yield from CExpression._try_c_repr_chunks(other)
                    return
            yield from self.cond.c_repr_chunks()
            return
        yield from _orig_cite_c_repr_chunks(self, indent=indent, asexpr=asexpr)

    if getattr(CITE.c_repr_chunks, "__name__", "") != "_c_repr_chunks_8616":
        CITE.c_repr_chunks = _c_repr_chunks_8616

    if getattr(CUnaryOp._c_repr_chunks_not, "__name__", "") != "_c_unaryop_chunks_not_8616":
        def _c_unaryop_chunks_not_8616(self):
            unwrapped = _unwrap_double_not(self)
            if unwrapped is not None:
                yield from CExpression._try_c_repr_chunks(unwrapped)
                return
            yield from _orig_cunaryop_c_repr_chunks_not(self)

        CUnaryOp._c_repr_chunks_not = _c_unaryop_chunks_not_8616

    _orig_assign_unified_variable_names = VariableManagerInternal.assign_unified_variable_names

    def _assign_unified_variable_names_8616(self, labels=None, arg_names=None, reset=False, func_blocks=None):
        _orig_assign_unified_variable_names(self, labels=labels, arg_names=arg_names, reset=reset, func_blocks=func_blocks)

        if self.func_addr is None or not self.manager._kb.functions.contains_addr(self.func_addr):
            return
        function = self.manager._kb.functions[self.func_addr]
        if function.project is not None and function.project.arch.name == "86_16" and function.prototype is not None:
            stack_arg_names = list(function.prototype.arg_names) if function.prototype.arg_names else []
            stack_arg_vars = sorted(
                (
                    var
                    for var in self.get_unified_variables()
                    if isinstance(var, SimStackVariable) and var.offset >= 2
                ),
                key=lambda var: (var.offset, var.size or 0, var.ident or ""),
            )
            for idx, var in enumerate(stack_arg_vars):
                desired_name = stack_arg_names[idx] if idx < len(stack_arg_names) else f"a{idx}"
                if reset or var.name is None or var.name == var.ident or var.name.startswith(("a", "v")):
                    var.name = desired_name
                    var._hash = None

        annotations = function.info.get(ANNOTATION_KEY)
        if not annotations:
            return

        for var in self.get_unified_variables():
            if isinstance(var, SimStackVariable):
                spec = annotations["stack_vars"].get(var.offset)
                if spec is None:
                    continue
                if "name" in spec:
                    var.name = spec["name"]
                    var._hash = None
                if "type" in spec:
                    self.set_variable_type(var, spec["type"], mark_manual=True, all_unified=True)

    if getattr(VariableManagerInternal.assign_unified_variable_names, "__name__", "") != "_assign_unified_variable_names_8616":
        VariableManagerInternal.assign_unified_variable_names = _assign_unified_variable_names_8616

    _orig_assign_variable_names = VariableManagerInternal.assign_variable_names

    def _assign_variable_names_8616(self, labels=None, types=None):
        _orig_assign_variable_names(self, labels=labels, types=types)

        if self.func_addr != "global":
            return
        for function in self.manager._kb.functions.values():
            annotations = function.info.get(ANNOTATION_KEY)
            if not annotations:
                continue
            for addr, name in annotations["global_vars"].items():
                self.manager._kb.labels[addr] = name
                for var in self.get_global_variables(addr):
                    if isinstance(var, SimMemoryVariable):
                        var.name = name

    if getattr(VariableManagerInternal.assign_variable_names, "__name__", "") != "_assign_variable_names_8616":
        VariableManagerInternal.assign_variable_names = _assign_variable_names_8616

    _orig_returnmaker_handle_return = ReturnMaker._handle_Return

    def _combo_reg_expr(self, stmt, reg_arg):
        reg = self.arch.registers[reg_arg.reg_name]
        ins_addr = getattr(stmt, "ins_addr", None)
        if ins_addr is None and hasattr(stmt, "tags"):
            ins_addr = stmt.tags.get("ins_addr")
        return ailment.Expr.Register(
            self._next_atom(),
            None,
            reg[0],
            reg_arg.size * self.arch.byte_width,
            reg_name=self.arch.translate_register_name(reg[0], reg_arg.size),
            ins_addr=ins_addr,
        )

    def _handle_return_8616(self, stmt_idx, stmt, block):
        if (
            block is not None
            and self.function.prototype is not None
            and self.function.prototype.returnty is not None
            and type(self.function.prototype.returnty) is not SimTypeBottom
        ):
            ret_val = self.function.calling_convention.return_val(self.function.prototype.returnty)
            if isinstance(ret_val, SimComboArg) and len(ret_val.locations) == 2 and all(
                isinstance(loc, SimRegArg) for loc in ret_val.locations
            ):
                if stmt.ret_exprs and not (
                    len(stmt.ret_exprs) == 1 and getattr(stmt.ret_exprs[0], "bits", None) == 16
                ):
                    return _orig_returnmaker_handle_return(self, stmt_idx, stmt, block)
                low_reg, high_reg = ret_val.locations
                ins_addr = getattr(stmt, "ins_addr", None)
                if ins_addr is None and hasattr(stmt, "tags"):
                    ins_addr = stmt.tags.get("ins_addr")
                if ins_addr is None and block is not None:
                    ins_addr = block.addr
                low = _combo_reg_expr(self, stmt, low_reg)
                high = _combo_reg_expr(self, stmt, high_reg)
                low_32 = ailment.Expr.Convert(self._next_atom(), low.bits, 32, False, low, ins_addr=ins_addr)
                high_32 = ailment.Expr.Convert(self._next_atom(), high.bits, 32, False, high, ins_addr=ins_addr)
                shift = ailment.Expr.Const(self._next_atom(), None, 16, 32, ins_addr=ins_addr)
                ret_expr = ailment.Expr.BinaryOp(
                    self._next_atom(),
                    "Or",
                    [
                        low_32,
                        ailment.Expr.BinaryOp(
                            self._next_atom(),
                            "Shl",
                            [high_32, shift],
                            False,
                            bits=32,
                            ins_addr=ins_addr,
                        ),
                    ],
                    False,
                    bits=32,
                    ins_addr=ins_addr,
                )
                new_stmt = stmt.copy()
                new_stmt.ret_exprs = [ret_expr]
                return new_stmt
        return _orig_returnmaker_handle_return(self, stmt_idx, stmt, block)

    if getattr(ReturnMaker._handle_Return, "__name__", "") != "_handle_return_8616":
        ReturnMaker._handle_Return = _handle_return_8616

    _orig_callsite_get_call_target = CallSiteMaker._get_call_target

    def _get_call_target_8616(self, stmt):
        target = _orig_callsite_get_call_target(stmt)
        if target is not None or self.project.arch.name != "86_16":
            return target

        try:
            function = self.kb.functions.floor_func(self.block.addr)
        except Exception:
            function = None

        if function is not None and self.block.addr in getattr(function, "block_addrs_set", set()):
            target = function.get_call_target(self.block.addr)
            if target not in (None, 0x14, 20):
                return target

        try:
            return resolve_direct_call_target_from_block(self.project, self.block.addr)
        except Exception:
            return None

    if getattr(CallSiteMaker._get_call_target, "__name__", "") != "_get_call_target_8616":
        CallSiteMaker._get_call_target = _get_call_target_8616

    _orig_init_proto_cc = Function._init_prototype_and_calling_convention

    def _init_proto_cc_8616(self):
        _orig_init_proto_cc(self)

        if self.project is None or self.project.arch.name != "86_16":
            return

        if self.calling_convention is None:
            cc_cls = default_cc(
                self.project.arch.name,
                platform=self.project.simos.name if self.project.simos is not None else None,
            )
            if cc_cls is not None:
                self.calling_convention = cc_cls(self.project.arch)

        if self.prototype is None:
            self.prototype = self.project.factory.function_prototype()
            self.is_prototype_guessed = True
        if self.is_prototype_guessed and _has_dxax_wide_return(self):
            self.prototype = SimTypeFunction(self.prototype.args, SimTypeLong()).with_arch(self.project.arch)
            self.is_prototype_guessed = True

    if getattr(Function._init_prototype_and_calling_convention, "__name__", "") != "_init_proto_cc_8616":
        Function._init_prototype_and_calling_convention = _init_proto_cc_8616

    _orig_decompiler_decompile = Decompiler._decompile

    def _structured_codegen_node_8616(value) -> bool:
        return type(value).__module__.startswith("angr.analyses.decompiler.structured_codegen")

    def _c_constant_value_8616(node) -> int | None:
        if isinstance(node, CConstant) and isinstance(node.value, int):
            return node.value
        return None

    def _segment_reg_name_8616(node, project) -> str | None:
        if not isinstance(node, CVariable):
            return None
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            return None
        return project.arch.register_names.get(variable.reg)

    def _match_real_mode_linear_expr_8616(node, project) -> tuple[str | None, int | None]:
        if isinstance(node, CBinaryOp) and node.op == "Mul":
            for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                if _c_constant_value_8616(maybe_scale) != 16:
                    continue
                seg_name = _segment_reg_name_8616(maybe_seg, project)
                if seg_name is not None:
                    return seg_name, 0

        if not isinstance(node, CBinaryOp) or node.op != "Add":
            return None, None

        for maybe_mul, maybe_const in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            linear = _c_constant_value_8616(maybe_const)
            if linear is None:
                continue
            if not isinstance(maybe_mul, CBinaryOp) or maybe_mul.op != "Mul":
                continue
            for maybe_seg, maybe_scale in ((maybe_mul.lhs, maybe_mul.rhs), (maybe_mul.rhs, maybe_mul.lhs)):
                if _c_constant_value_8616(maybe_scale) != 16:
                    continue
                seg_name = _segment_reg_name_8616(maybe_seg, project)
                if seg_name is not None:
                    return seg_name, linear
        return None, None

    def _match_segmented_dereference_8616(node, project) -> tuple[str | None, int | None]:
        if not isinstance(node, CUnaryOp) or node.op != "Dereference":
            return None, None
        operand = node.operand
        if isinstance(operand, CTypeCast):
            operand = operand.expr
        return _match_real_mode_linear_expr_8616(operand, project)

    def _replace_c_children_8616(node, transform) -> bool:
        changed = False

        for attr in (
            "lhs",
            "rhs",
            "expr",
            "operand",
            "condition",
            "cond",
            "body",
            "iffalse",
            "iftrue",
            "callee_target",
            "else_node",
            "retval",
        ):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if _structured_codegen_node_8616(value):
                new_value = transform(value)
                if new_value is not value:
                    setattr(node, attr, new_value)
                    changed = True
                    value = new_value
                if _replace_c_children_8616(value, transform):
                    changed = True

        for attr in ("args", "operands", "statements"):
            if not hasattr(node, attr):
                continue
            try:
                items = getattr(node, attr)
            except Exception:
                continue
            if not items:
                continue
            new_items = []
            list_changed = False
            for item in items:
                if _structured_codegen_node_8616(item):
                    new_item = transform(item)
                    if new_item is not item:
                        list_changed = True
                    if _replace_c_children_8616(new_item, transform):
                        changed = True
                    new_items.append(new_item)
                else:
                    new_items.append(item)
            if list_changed:
                setattr(node, attr, new_items)
                changed = True

        if hasattr(node, "condition_and_nodes"):
            try:
                pairs = getattr(node, "condition_and_nodes")
            except Exception:
                pairs = None
            if pairs:
                new_pairs = []
                pair_changed = False
                for cond, body in pairs:
                    new_cond = transform(cond) if _structured_codegen_node_8616(cond) else cond
                    new_body = transform(body) if _structured_codegen_node_8616(body) else body
                    if new_cond is not cond or new_body is not body:
                        pair_changed = True
                    if _structured_codegen_node_8616(new_cond) and _replace_c_children_8616(new_cond, transform):
                        changed = True
                    if _structured_codegen_node_8616(new_body) and _replace_c_children_8616(new_body, transform):
                        changed = True
                    new_pairs.append((new_cond, new_body))
                if pair_changed:
                    setattr(node, "condition_and_nodes", new_pairs)
                    changed = True

        return changed

    def _iter_c_nodes_deep_8616(node, seen: set[int] | None = None):
        if seen is None:
            seen = set()
        if not _structured_codegen_node_8616(node):
            return
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        yield node

        for attr in dir(node):
            if attr.startswith("_") or attr in {"codegen"}:
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if _structured_codegen_node_8616(value):
                yield from _iter_c_nodes_deep_8616(value, seen)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if _structured_codegen_node_8616(item):
                        yield from _iter_c_nodes_deep_8616(item, seen)
                    elif isinstance(item, tuple):
                        for subitem in item:
                            if _structured_codegen_node_8616(subitem):
                                yield from _iter_c_nodes_deep_8616(subitem, seen)

    def _global_memory_addr_8616(node) -> int | None:
        if not isinstance(node, CVariable):
            return None
        variable = getattr(node, "variable", None)
        if not isinstance(variable, SimMemoryVariable):
            return None
        addr = getattr(variable, "addr", None)
        return addr if isinstance(addr, int) else None

    def _global_load_addr_8616(node, project) -> int | None:
        addr = _global_memory_addr_8616(node)
        if addr is not None:
            return addr
        seg_name, linear = _match_segmented_dereference_8616(node, project)
        if seg_name != "ds":
            return None
        return linear

    def _match_scaled_high_byte_8616(node, project) -> int | None:
        if not isinstance(node, CBinaryOp):
            return None

        if node.op == "Mul":
            pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
            for maybe_load, maybe_scale in pairs:
                if _c_constant_value_8616(maybe_scale) != 0x100:
                    continue
                addr = _global_load_addr_8616(maybe_load, project)
                if addr is not None:
                    return addr

        if node.op == "Shl":
            pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
            for maybe_load, maybe_scale in pairs:
                if _c_constant_value_8616(maybe_scale) != 8:
                    continue
                addr = _global_load_addr_8616(maybe_load, project)
                if addr is not None:
                    return addr

        return None

    def _make_word_global_8616(codegen, addr: int):
        return CVariable(
            SimMemoryVariable(addr, 2, name=f"g_{addr:x}", region=codegen.cfunc.addr),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )

    def _same_c_expression_8616(lhs, rhs) -> bool:
        if type(lhs) is not type(rhs):
            return False
        if isinstance(lhs, CConstant):
            return lhs.value == rhs.value
        if isinstance(lhs, CTypeCast):
            return _same_c_expression_8616(lhs.expr, rhs.expr)
        if isinstance(lhs, CUnaryOp):
            return lhs.op == rhs.op and _same_c_expression_8616(lhs.operand, rhs.operand)
        if isinstance(lhs, CBinaryOp):
            return (
                lhs.op == rhs.op
                and _same_c_expression_8616(lhs.lhs, rhs.lhs)
                and _same_c_expression_8616(lhs.rhs, rhs.rhs)
            )
        if isinstance(lhs, CITE):
            return (
                _same_c_expression_8616(lhs.cond, rhs.cond)
                and _same_c_expression_8616(lhs.iftrue, rhs.iftrue)
                and _same_c_expression_8616(lhs.iffalse, rhs.iffalse)
            )
        if isinstance(lhs, CVariable):
            lvar = getattr(lhs, "variable", None)
            rvar = getattr(rhs, "variable", None)
            if type(lvar) is not type(rvar):
                return False
            if isinstance(lvar, SimRegisterVariable):
                return getattr(lvar, "reg", None) == getattr(rvar, "reg", None)
            if isinstance(lvar, SimStackVariable):
                return (
                    getattr(lvar, "base", None) == getattr(rvar, "base", None)
                    and getattr(lvar, "offset", None) == getattr(rvar, "offset", None)
                    and getattr(lvar, "size", None) == getattr(rvar, "size", None)
                )
            if isinstance(lvar, SimMemoryVariable):
                return (
                    getattr(lvar, "addr", None) == getattr(rvar, "addr", None)
                    and getattr(lvar, "size", None) == getattr(rvar, "size", None)
                )
        return lhs is rhs

    def _is_shifted_high_byte_8616(high_expr, low_expr) -> bool:
        if not isinstance(high_expr, CBinaryOp) or high_expr.op != "Shr":
            return False
        if _c_constant_value_8616(high_expr.rhs) != 8:
            return False
        return _same_c_expression_8616(high_expr.lhs, low_expr)

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

    def _simplify_structured_expressions_8616(codegen) -> bool:
        if getattr(codegen, "cfunc", None) is None:
            return False

        def _is_c_constant_int_8616(expr, value: int) -> bool:
            return isinstance(expr, CConstant) and isinstance(expr.value, int) and expr.value == value

        def _extract_same_zero_compare_expr_8616(expr):
            if not isinstance(expr, CBinaryOp) or expr.op != "CmpEQ":
                return None
            if _is_c_constant_int_8616(expr.rhs, 0):
                return expr.lhs
            if _is_c_constant_int_8616(expr.lhs, 0):
                return expr.rhs
            return None

        def _extract_zero_flag_source_expr_8616(expr):
            if isinstance(expr, CBinaryOp):
                if expr.op == "Mul":
                    for maybe_logic, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                        if not _is_c_constant_int_8616(maybe_scale, 64):
                            continue
                        source_expr = _extract_same_zero_compare_expr_8616(maybe_logic)
                        if source_expr is not None:
                            return source_expr
                        if not isinstance(maybe_logic, CBinaryOp) or maybe_logic.op != "LogicalAnd":
                            continue
                        lhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.lhs)
                        rhs_expr = _extract_same_zero_compare_expr_8616(maybe_logic.rhs)
                        if lhs_expr is not None and rhs_expr is not None and _same_c_expression_8616(lhs_expr, rhs_expr):
                            return lhs_expr

                for child in (expr.lhs, expr.rhs):
                    if _structured_codegen_node_8616(child):
                        extracted = _extract_zero_flag_source_expr_8616(child)
                        if extracted is not None:
                            return extracted

            elif isinstance(expr, CUnaryOp):
                child = getattr(expr, "operand", None)
                if _structured_codegen_node_8616(child):
                    return _extract_zero_flag_source_expr_8616(child)

            elif isinstance(expr, CTypeCast):
                child = getattr(expr, "expr", None)
                if _structured_codegen_node_8616(child):
                    return _extract_zero_flag_source_expr_8616(child)

            return None

        def _simplify_zero_flag_comparison_8616(expr):
            if not isinstance(expr, CBinaryOp) or expr.op not in {"CmpEQ", "CmpNE"}:
                return expr

            if _is_c_constant_int_8616(expr.rhs, 0):
                source = expr.lhs
            elif _is_c_constant_int_8616(expr.lhs, 0):
                source = expr.rhs
            else:
                return expr

            source_expr = _extract_zero_flag_source_expr_8616(source)
            if source_expr is None:
                return expr
            if expr.op == "CmpEQ":
                return source_expr
            return CUnaryOp("Not", source_expr, codegen=codegen)

        def transform(node):
            simplified = _simplify_zero_flag_comparison_8616(node)
            if simplified is not node:
                return simplified
            if (
                isinstance(node, CBinaryOp)
                and node.op in {"LogicalAnd", "LogicalOr", "And", "Or"}
                and _same_c_expression_8616(node.lhs, node.rhs)
            ):
                return node.lhs
            if isinstance(node, CBinaryOp) and node.op in {"CmpEQ", "CmpNE"}:
                if isinstance(node.rhs, CConstant) and node.rhs.value == 0:
                    if (
                        isinstance(node.lhs, CBinaryOp)
                        and node.lhs.op == "Sub"
                        and isinstance(node.lhs.rhs, CConstant)
                    ):
                        return CBinaryOp(
                            node.op,
                            node.lhs.lhs,
                            node.lhs.rhs,
                            codegen=codegen,
                            tags=getattr(node, "tags", None),
                        )
                if isinstance(node.lhs, CConstant) and node.lhs.value == 0:
                    if (
                        isinstance(node.rhs, CBinaryOp)
                        and node.rhs.op == "Sub"
                        and isinstance(node.rhs.rhs, CConstant)
                    ):
                        return CBinaryOp(
                            node.op,
                            node.rhs.lhs,
                            node.rhs.rhs,
                            codegen=codegen,
                            tags=getattr(node, "tags", None),
                        )
            if isinstance(node, CBinaryOp) and node.op == "Sub" and _same_c_expression_8616(node.lhs, node.rhs):
                type_ = getattr(node, "type", None) or getattr(node.lhs, "type", None)
                if type_ is not None:
                    return CConstant(0, type_, codegen=codegen)
            return node

        root = codegen.cfunc.statements
        new_root = transform(root)
        if new_root is not root:
            codegen.cfunc.statements = new_root
            root = new_root
            changed = True
        else:
            changed = False

        if _replace_c_children_8616(root, transform):
            changed = True
        return changed

    def _extract_flag_test_info_8616(node):
        invert = False
        while True:
            if isinstance(node, CUnaryOp) and node.op == "Not":
                invert = not invert
                node = node.operand
                continue
            if isinstance(node, CITE):
                values = _bool_cite_values_8616(node)
                if values == (1, 0):
                    node = node.cond
                    continue
                if values == (0, 1):
                    invert = not invert
                    node = node.cond
                    continue
            break

        if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
            return None

        lhs = node.lhs
        rhs = node.rhs
        zero = None
        masked = None
        if isinstance(lhs, CBinaryOp) and lhs.op == "And" and isinstance(rhs, CConstant) and rhs.value == 0:
            masked = lhs
            zero = rhs
        elif isinstance(rhs, CBinaryOp) and rhs.op == "And" and isinstance(lhs, CConstant) and lhs.value == 0:
            masked = rhs
            zero = lhs
        if masked is None or zero is None:
            return None

        mask_lhs = masked.lhs
        mask_rhs = masked.rhs
        if isinstance(mask_lhs, CConstant) and isinstance(mask_lhs.value, int) and isinstance(mask_rhs, CVariable):
            bit = mask_lhs.value
            var = mask_rhs
        elif isinstance(mask_rhs, CConstant) and isinstance(mask_rhs.value, int) and isinstance(mask_lhs, CVariable):
            bit = mask_rhs.value
            var = mask_lhs
        else:
            return None

        predicate_negated = invert
        if node.op == "CmpEQ":
            predicate_negated = not predicate_negated
        return var, bit, predicate_negated

    def _extract_flag_predicate_from_expr_8616(node, bit: int):
        if isinstance(node, CBinaryOp):
            if node.op == "Mul":
                if isinstance(node.lhs, CConstant) and node.lhs.value == bit:
                    return node.rhs
                if isinstance(node.rhs, CConstant) and node.rhs.value == bit:
                    return node.lhs
            if node.op in {"Or", "And"}:
                lhs = _extract_flag_predicate_from_expr_8616(node.lhs, bit)
                if lhs is not None:
                    return lhs
                rhs = _extract_flag_predicate_from_expr_8616(node.rhs, bit)
                if rhs is not None:
                    return rhs
        return None

    def _c_expr_uses_var_8616(node, target) -> bool:
        if node is None:
            return False
        if isinstance(node, CVariable):
            return _same_c_expression_8616(node, target)
        for attr in (
            "lhs",
            "rhs",
            "operand",
            "cond",
            "iftrue",
            "iffalse",
            "expr",
            "condition",
            "else_node",
        ):
            child = getattr(node, attr, None)
            if hasattr(child, "__class__") and child.__class__.__name__.startswith("C"):
                if _c_expr_uses_var_8616(child, target):
                    return True
        for attr in ("statements", "operands", "condition_and_nodes"):
            child = getattr(node, attr, None)
            if isinstance(child, list):
                for item in child:
                    if isinstance(item, tuple):
                        for sub in item:
                            if hasattr(sub, "__class__") and sub.__class__.__name__.startswith("C"):
                                if _c_expr_uses_var_8616(sub, target):
                                    return True
                    elif hasattr(item, "__class__") and item.__class__.__name__.startswith("C"):
                        if _c_expr_uses_var_8616(item, target):
                            return True
        return False

    def _rewrite_flag_condition_pairs_8616(codegen) -> bool:
        if getattr(codegen, "cfunc", None) is None:
            return False

        changed = False

        def _last_assignment_in_stmt(stmt):
            if isinstance(stmt, CAssignment):
                return stmt, None
            if isinstance(stmt, CStatements) and stmt.statements:
                last = stmt.statements[-1]
                if isinstance(last, CAssignment):
                    return last, stmt
            return None, None

        def transform(node):
            nonlocal changed
            if not isinstance(node, CStatements):
                return node

            new_statements = []
            statements = list(node.statements)
            i = 0
            while i < len(statements):
                stmt = statements[i]
                next_stmt = statements[i + 1] if i + 1 < len(statements) else None

                matched = False
                assign_stmt, assign_container = _last_assignment_in_stmt(stmt)
                if (
                    isinstance(assign_stmt, CAssignment)
                    and isinstance(assign_stmt.lhs, CVariable)
                    and type(next_stmt).__name__ == "CIfElse"
                ):
                    cond_nodes = getattr(next_stmt, "condition_and_nodes", None)
                    if isinstance(cond_nodes, list) and cond_nodes:
                        cond, _body = cond_nodes[0]
                        info = _extract_flag_test_info_8616(cond)
                        if info is not None:
                            flag_var, bit, negate_predicate = info
                            if _same_c_expression_8616(assign_stmt.lhs, flag_var):
                                predicate = _extract_flag_predicate_from_expr_8616(assign_stmt.rhs, bit)
                                if predicate is not None:
                                    new_cond = (
                                        CUnaryOp("Not", predicate, codegen=codegen)
                                        if negate_predicate
                                        else predicate
                                    )
                                    cond_nodes[0] = (new_cond, cond_nodes[0][1])
                                    changed = True
                                    later_uses = any(
                                        _c_expr_uses_var_8616(rest, assign_stmt.lhs) for rest in statements[i + 2 :]
                                    )
                                    if not later_uses:
                                        if assign_container is None:
                                            matched = True
                                        else:
                                            assign_container.statements = assign_container.statements[:-1]

                if not matched:
                    new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements
            return node

        root = codegen.cfunc.statements
        transform(root)
        if _replace_c_children_8616(root, transform):
            changed = True
        return changed

    def _bool_cite_values_8616(node):
        if not isinstance(node, CITE):
            return None
        iftrue = _c_constant_value_8616(node.iftrue)
        iffalse = _c_constant_value_8616(node.iffalse)
        if iftrue in (0, 1) and iffalse in (0, 1):
            return iftrue, iffalse
        return None

    def _extract_bool_compare_term_8616(node):
        negated = False
        if isinstance(node, CUnaryOp) and node.op == "Not":
            negated = True
            node = node.operand
        if not isinstance(node, CITE):
            return None
        values = _bool_cite_values_8616(node)
        if values is None:
            return None
        if values == (1, 0):
            effective_negated = negated
        elif values == (0, 1):
            effective_negated = not negated
        else:
            return None
        compare = node.cond
        if not isinstance(compare, CBinaryOp):
            return None
        if compare.op not in {"CmpGT", "CmpGE", "CmpLT", "CmpLE"}:
            return None
        return compare, effective_negated, node

    def _make_bool_cite_8616(template: CITE, negated: bool, codegen):
        values = _bool_cite_values_8616(template)
        if values is None:
            return template
        zero = CConstant(0, getattr(template.iftrue, "type", None) or template.type, codegen=codegen)
        one = CConstant(1, getattr(template.iftrue, "type", None) or template.type, codegen=codegen)
        if negated:
            return CITE(template.cond, zero, one, tags=getattr(template, "tags", None), codegen=codegen)
        return CITE(template.cond, one, zero, tags=getattr(template, "tags", None), codegen=codegen)

    def _invert_cmp_op_8616(op: str) -> str | None:
        return {
            "CmpGT": "CmpLE",
            "CmpGE": "CmpLT",
            "CmpLT": "CmpGE",
            "CmpLE": "CmpGT",
        }.get(op)

    def _make_bool_expr_from_compare_8616(compare: CBinaryOp, negated: bool, codegen):
        if negated:
            inverted = _invert_cmp_op_8616(compare.op)
            if inverted is not None:
                return CBinaryOp(
                    inverted,
                    compare.lhs,
                    compare.rhs,
                    codegen=codegen,
                    tags=getattr(compare, "tags", None),
                )
        return CBinaryOp(
            compare.op,
            compare.lhs,
            compare.rhs,
            codegen=codegen,
            tags=getattr(compare, "tags", None),
        )

    def _fix_impossible_interval_guard_expr_8616(node, codegen):
        if not isinstance(node, CBinaryOp) or node.op != "LogicalAnd":
            return node
        left_info = _extract_bool_compare_term_8616(node.lhs)
        right_info = _extract_bool_compare_term_8616(node.rhs)
        if left_info is None or right_info is None:
            return node
        left_cmp, left_negated, left_template = left_info
        right_cmp, right_negated, right_template = right_info
        if not _same_c_expression_8616(left_cmp.rhs, right_cmp.rhs):
            return node

        low_ops = {"CmpGT", "CmpGE"}
        high_ops = {"CmpLT", "CmpLE"}

        if left_cmp.op in low_ops and right_cmp.op in high_ops and not left_negated and not right_negated:
            return CBinaryOp(
                "LogicalAnd",
                _make_bool_expr_from_compare_8616(left_cmp, True, codegen),
                _make_bool_expr_from_compare_8616(right_cmp, True, codegen),
                codegen=codegen,
                tags=getattr(node, "tags", None),
            )

        if left_cmp.op in low_ops and right_cmp.op == "CmpGE" and not left_negated and right_negated:
            return CBinaryOp(
                "LogicalAnd",
                _make_bool_expr_from_compare_8616(left_cmp, True, codegen),
                _make_bool_expr_from_compare_8616(right_cmp, False, codegen),
                codegen=codegen,
                tags=getattr(node, "tags", None),
            )

        return node

    def _fix_interval_guard_conditions_8616(codegen) -> bool:
        if getattr(codegen, "cfunc", None) is None:
            return False

        def transform(node):
            fixed = _fix_impossible_interval_guard_expr_8616(node, codegen)
            if fixed is not node:
                return fixed
            return node

        root = codegen.cfunc.statements
        new_root = transform(root)
        if new_root is not root:
            codegen.cfunc.statements = new_root
            root = new_root
            changed = True
        else:
            changed = False

        if _replace_c_children_8616(root, transform):
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

    def _postprocess_codegen_8616(project, codegen) -> bool:
        if getattr(codegen, "cfunc", None) is None:
            return False

        addrs = set()
        addrs |= _coalesce_word_global_loads_8616(project, codegen)
        addrs |= _coalesce_word_global_constant_stores_8616(project, codegen)

        changed = bool(addrs)
        if _apply_word_global_types_8616(codegen, addrs):
            changed = True
        if _prune_unused_unnamed_memory_declarations_8616(codegen):
            changed = True
        if _simplify_structured_expressions_8616(codegen):
            changed = True
        if _rewrite_flag_condition_pairs_8616(codegen):
            changed = True
        if _prune_unused_flag_assignments_8616(project, codegen):
            changed = True
        if _prune_overwritten_flag_assignments_8616(project, codegen):
            changed = True
        if _fix_interval_guard_conditions_8616(codegen):
            changed = True
        return changed

    def _decompile_8616(self):
        _orig_decompiler_decompile(self)
        if (
            self.project.arch.name == "86_16"
            and self.codegen is not None
            and _postprocess_codegen_8616(self.project, self.codegen)
        ):
            self.codegen.regenerate_text()

    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_8616":
        Decompiler._decompile = _decompile_8616
except Exception:
    pass


# Register SimProcedures for x86-16 dirty I/O helpers so runtime
# execution returns deterministic defaults when no PortIO device is present.
try:
    import angr as _angr
    from . import simprocs_io as _simprocs_io

    _angr.SIM_PROCEDURES = getattr(_angr, 'SIM_PROCEDURES', {})
    _arch_key = 'X86_16'
    if _arch_key not in _angr.SIM_PROCEDURES:
        _angr.SIM_PROCEDURES[_arch_key] = {}
    _angr.SIM_PROCEDURES[_arch_key]['x86g_dirtyhelper_IN'] = _simprocs_io.X86DirtyIN
    _angr.SIM_PROCEDURES[_arch_key]['x86g_dirtyhelper_OUT'] = _simprocs_io.X86DirtyOUT
except Exception:
    # Best-effort registration; if angr is absent or API differs, continue silently.
    pass

try:
    # Patch angr's VEX dirty helpers for x86 to return deterministic defaults
    # when no PortIO device is present. This overrides the engine-level helpers
    # that otherwise emit symbolic IN_... values.
    import angr.engines.vex.heavy.dirty as _dirty

    def _patched_x86g_dirtyhelper_IN(state, portno, sz):
        try:
            szv = int(sz) if isinstance(sz, int) else int(state.solver.eval(sz))
        except Exception:
            szv = 32
        if szv == 8:
            return state.solver.BVV(0xFF, 8)
        if szv == 16:
            return state.solver.BVV(0xFFFF, 16)
        return state.solver.BVV(0xFFFFFFFF, 32)

    def _patched_x86g_dirtyhelper_OUT(state, portno, sz, val):
        return None

    _dirty.x86g_dirtyhelper_IN = _patched_x86g_dirtyhelper_IN
    _dirty.x86g_dirtyhelper_OUT = _patched_x86g_dirtyhelper_OUT
except Exception:
    pass

# Keep runtime monkeypatch logic in a small module to follow SRP.
try:
    from . import patch_dirty as _patch_dirty
    _patch_dirty.apply_patch()
except Exception:
    pass

# Do not wrap Clinic._make_callsites with SIGALRM-based timeouts here.
# Raising out of Clinic causes angr resilience to drop decompilation results
# and return an empty codegen, which is worse than a slow but honest decompile.
