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
