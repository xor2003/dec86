__all__ = ["arch_86_16", "lift_86_16", "simos_86_16"]

from . import arch_86_16, lift_86_16, simos_86_16  # noqa: F401

try:
    import networkx
    from angr.calling_conventions import default_cc
    from angr.analyses.decompiler.structured_codegen.c import CClosingObject, CConstant, CITE, CTypeCast, CUnaryOp
    from angr.sim_type import SimTypeBottom, SimTypePointer
    from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLongLong, SimTypeShort
    from angr.analyses.typehoon.simple_solver import BASE_LATTICES, BottomType, Int, Int16, TopType
    from angr.analyses.typehoon import simple_solver as _typehoon_simple_solver
    from angr.analyses.typehoon import translator as _typehoon_translator
    from angr.analyses.typehoon import lifter as _typehoon_lifter
    from angr.analyses.decompiler.clinic import Clinic
    from angr.analyses.typehoon.typeconsts import Pointer, Int16 as TCInt16
    from angr.knowledge_plugins.functions.function import Function
    from angr.sim_variable import SimStackVariable

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

    def _make_function_prototype_8616(self, arg_list, variable_kb):
        if (
            self.project.arch.name == "86_16"
            and (not arg_list)
            and self.function.prototype is not None
            and self.function.is_prototype_guessed
        ):
            variables = variable_kb.variables[self.function.addr]
            stack_args = []
            seen_offsets = set()
            for var in variables.get_variables():
                if not isinstance(var, SimStackVariable):
                    continue
                if getattr(var, "name", None) == "ret_addr":
                    continue
                if var.offset < 2 or var.offset in seen_offsets:
                    continue
                seen_offsets.add(var.offset)
                size = max(var.size or self.project.arch.bytes, self.project.arch.bytes)
                if size == 1:
                    arg_ty = SimTypeChar()
                elif size == 2:
                    arg_ty = SimTypeShort()
                elif size == 4:
                    arg_ty = SimTypeInt()
                else:
                    arg_ty = SimTypeLongLong()
                stack_args.append((var.offset, arg_ty))

            if stack_args:
                stack_args.sort(key=lambda item: item[0])
                returnty = self.function.prototype.returnty if self.function.prototype.returnty is not None else SimTypeInt()
                self.function.prototype = SimTypeFunction([ty for _, ty in stack_args], returnty).with_arch(
                    self.project.arch
                )
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

    if getattr(Function._init_prototype_and_calling_convention, "__name__", "") != "_init_proto_cc_8616":
        Function._init_prototype_and_calling_convention = _init_proto_cc_8616
except Exception:
    pass
