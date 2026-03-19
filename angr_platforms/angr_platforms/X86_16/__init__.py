__all__ = ["annotations", "arch_86_16", "lift_86_16", "simos_86_16"]

from . import annotations, arch_86_16, lift_86_16, simos_86_16  # noqa: F401

try:
    import networkx
    import angr.ailment as ailment
    from angr.calling_conventions import default_cc
    from angr.calling_conventions import SimComboArg, SimRegArg
    from angr.analyses.decompiler.return_maker import ReturnMaker
    from angr.analyses.decompiler.structured_codegen.c import CClosingObject, CConstant, CITE, CTypeCast, CUnaryOp
    from angr.sim_type import SimTypeBottom, SimTypePointer
    from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeShort
    from angr.analyses.typehoon.simple_solver import BASE_LATTICES, BottomType, Int, Int16, TopType
    from angr.analyses.typehoon import simple_solver as _typehoon_simple_solver
    from angr.analyses.typehoon import translator as _typehoon_translator
    from angr.analyses.typehoon import lifter as _typehoon_lifter
    from angr.analyses.decompiler.clinic import Clinic
    from angr.analyses.typehoon.typeconsts import Pointer, Int16 as TCInt16
    from angr.knowledge_plugins.functions.function import Function
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from angr.sim_variable import SimMemoryVariable
    from angr.sim_variable import SimStackVariable
    from .annotations import ANNOTATION_KEY

    class Pointer16(Pointer, TCInt16):
        def __init__(self, basetype=None):
            Pointer.__init__(self, basetype)

        def __repr__(self, memo=None):
            if self.basetype is None:
                bt = "None"
            elif memo is None:
                bt = repr(self.basetype)
            else:
                bt = self.basetype.__repr__(memo=memo)
            return f"ptr16({bt})"

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

    def _unwrap_bool_constant(expr):
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        if isinstance(expr, CConstant) and isinstance(expr.value, int):
            return expr.value
        return None

    def _c_repr_chunks_8616(self, indent=0, asexpr=False):
        true_val = _unwrap_bool_constant(self.iftrue)
        false_val = _unwrap_bool_constant(self.iffalse)
        if (true_val, false_val) == (0, 1):
            yield "!", self
            paren = CClosingObject("(")
            yield "(", paren
            yield from self.cond.c_repr_chunks()
            yield ")", paren
            return
        if (true_val, false_val) == (1, 0):
            yield from self.cond.c_repr_chunks()
            return
        yield from _orig_cite_c_repr_chunks(self, indent=indent, asexpr=asexpr)

    if getattr(CITE.c_repr_chunks, "__name__", "") != "_c_repr_chunks_8616":
        CITE.c_repr_chunks = _c_repr_chunks_8616

    _orig_assign_unified_variable_names = VariableManagerInternal.assign_unified_variable_names

    def _assign_unified_variable_names_8616(self, labels=None, arg_names=None, reset=False, func_blocks=None):
        _orig_assign_unified_variable_names(self, labels=labels, arg_names=arg_names, reset=reset, func_blocks=func_blocks)

        if self.func_addr is None or not self.manager._kb.functions.contains_addr(self.func_addr):
            return
        function = self.manager._kb.functions[self.func_addr]
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
        return ailment.Expr.Register(
            self._next_atom(),
            None,
            reg[0],
            reg_arg.size * self.arch.byte_width,
            reg_name=self.arch.translate_register_name(reg[0], reg_arg.size),
            ins_addr=stmt.ins_addr,
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
                low = _combo_reg_expr(self, stmt, low_reg)
                high = _combo_reg_expr(self, stmt, high_reg)
                low_32 = ailment.Expr.Convert(self._next_atom(), low.bits, 32, False, low, ins_addr=stmt.ins_addr)
                high_32 = ailment.Expr.Convert(self._next_atom(), high.bits, 32, False, high, ins_addr=stmt.ins_addr)
                shift = ailment.Expr.Const(self._next_atom(), None, 16, 32, ins_addr=stmt.ins_addr)
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
                            ins_addr=stmt.ins_addr,
                        ),
                    ],
                    False,
                    bits=32,
                    ins_addr=stmt.ins_addr,
                )
                new_stmt = stmt.copy()
                new_stmt.ret_exprs = [ret_expr]
                new_statements = block.statements[::]
                new_statements[stmt_idx] = new_stmt
                self._new_block = block.copy(statements=new_statements)
                return
        return _orig_returnmaker_handle_return(self, stmt_idx, stmt, block)

    if getattr(ReturnMaker._handle_Return, "__name__", "") != "_handle_return_8616":
        ReturnMaker._handle_Return = _handle_return_8616

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
except Exception:
    pass
