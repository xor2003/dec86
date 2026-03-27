from __future__ import annotations

from pyvex.stmt import Put

from angr.analyses.calling_convention import calling_convention as _cc_analysis
from angr.errors import SimTranslationError
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from .simos_86_16 import SimCC8616MSCsmall

__all__ = ["apply_x86_16_calling_convention_compatibility"]


def _has_explicit_arg_names_8616(prototype) -> bool:
    arg_names = getattr(prototype, "arg_names", None) or ()
    for name in arg_names:
        if name is None:
            continue
        if not (isinstance(name, str) and len(name) > 1 and name[0] == "a" and name[1:].isdigit()):
            return True
    return False


def _guess_retval_type_8616(self, cc, ret_val_size):
    ret_type = _guess_retval_type_8616._orig(self, cc, ret_val_size)
    if self.project.arch.bits != 16 or ret_type is None:
        return ret_type
    if getattr(ret_type, "__class__", None).__name__ != "SimTypeShort":
        return ret_type
    if not getattr(cc, "OVERFLOW_RETURN_VAL", None) or getattr(cc, "RETURN_VAL", None) is None:
        return ret_type
    if getattr(self._function, "_argument_registers", None) or getattr(self._function, "_argument_stack_variables", None):
        return ret_type

    for ret_block in getattr(self._function, "ret_sites", ()):
        retval_updated, overflow_updated = False, False
        try:
            irsb = self.project.factory.block(ret_block.addr, size=ret_block.size).vex
        except SimTranslationError:
            continue
        irsb_text = irsb._pp_str()
        if "GET:I16(bp)" in irsb_text:
            continue
        for stmt in irsb.statements:
            if isinstance(stmt, Put):
                reg_name = self.project.arch.translate_register_name(stmt.offset, size=self.project.arch.bytes)
                if reg_name == cc.RETURN_VAL.reg_name:
                    retval_updated = True
                elif reg_name == cc.OVERFLOW_RETURN_VAL.reg_name:
                    overflow_updated = True
        if retval_updated and overflow_updated:
            return SimTypeLong().with_arch(self.project.arch)
    return ret_type


def _promote_wide_stack_return_to_wide_arg_8616(self, prototype):
    if self.project.arch.bits != 16 or prototype is None:
        return prototype
    if len(prototype.args) == 0 and isinstance(prototype.returnty, SimTypeLong):
        block_addrs = sorted(getattr(self._function, "block_addrs_set", ()) or ())
        if block_addrs:
            try:
                irsb = self.project.factory.block(block_addrs[0]).vex
            except SimTranslationError:
                irsb = None
            if irsb is not None:
                irsb_text = irsb._pp_str()
                if "GET:I16(bp)" in irsb_text:
                    ax_dx_puts = 0
                    for stmt in irsb.statements:
                        if isinstance(stmt, Put):
                            reg_name = self.project.arch.translate_register_name(stmt.offset, size=self.project.arch.bytes)
                            if reg_name in {"ax", "dx"}:
                                ax_dx_puts += 1
                    if ax_dx_puts == 2:
                        wide_ty = SimTypeLong().with_arch(self.project.arch)
                        return prototype.__class__([wide_ty], wide_ty).with_arch(self.project.arch)
    if len(prototype.args) != 2:
        return prototype
    if not all(type(arg) is SimTypeShort for arg in prototype.args):
        return prototype
    if type(prototype.returnty) is not SimTypeShort:
        return prototype

    block_addrs = sorted(getattr(self._function, "block_addrs_set", ()) or ())
    if not block_addrs:
        return prototype

    try:
        irsb = self.project.factory.block(block_addrs[0]).vex
    except SimTranslationError:
        return prototype

    irsb_text = irsb._pp_str()
    if "GET:I16(bp)" not in irsb_text:
        return prototype

    ax_dx_puts = 0
    for stmt in irsb.statements:
        if isinstance(stmt, Put):
            reg_name = self.project.arch.translate_register_name(stmt.offset, size=self.project.arch.bytes)
            if reg_name in {"ax", "dx"}:
                ax_dx_puts += 1

    if ax_dx_puts != 2:
        return prototype

    wide_ty = SimTypeLong().with_arch(self.project.arch)
    return prototype.__class__([wide_ty], wide_ty).with_arch(self.project.arch)


def _fallback_wide_stack_return_prototype_8616(self):
    block_addrs = sorted(getattr(self._function, "block_addrs_set", ()) or ())
    if not block_addrs:
        return None

    try:
        irsb = self.project.factory.block(block_addrs[0]).vex
    except SimTranslationError:
        return None

    irsb_text = irsb._pp_str()
    if "GET:I16(bp)" not in irsb_text or "Ijk_Ret" not in irsb_text:
        return None

    ax_dx_puts = 0
    for stmt in irsb.statements:
        if isinstance(stmt, Put):
            reg_name = self.project.arch.translate_register_name(stmt.offset, size=self.project.arch.bytes)
            if reg_name in {"ax", "dx"}:
                ax_dx_puts += 1

    if ax_dx_puts != 2:
        return None

    wide_ty = SimTypeLong().with_arch(self.project.arch)
    return SimCC8616MSCsmall(self.project.arch), SimTypeFunction([wide_ty], wide_ty).with_arch(self.project.arch)


def _set_function_prototype_8616(function, cc, prototype) -> tuple[object, object]:
    if getattr(function, "prototype", None) is not None and _has_explicit_arg_names_8616(function.prototype):
        return cc, function.prototype
    if prototype is not None and getattr(prototype, "_arch", None) is None:
        try:
            prototype = prototype.with_arch(function.project.arch)
        except Exception:
            pass
    function.prototype = prototype
    function.is_prototype_guessed = False
    if cc is not None:
        try:
            function.calling_convention = cc
        except Exception:
            pass
    return cc, prototype


def apply_x86_16_calling_convention_compatibility() -> None:
    if getattr(_cc_analysis.CallingConventionAnalysis._analyze_function, "__name__", "") != "_analyze_function_8616":
        _guess_retval_type_8616._orig = _cc_analysis.CallingConventionAnalysis._guess_retval_type
        _analyze_function_orig = _cc_analysis.CallingConventionAnalysis._analyze_function

        def _analyze_function_8616(self):
            result = _analyze_function_orig(self)
            if result is None:
                fallback = _fallback_wide_stack_return_prototype_8616(self)
                if fallback is None:
                    return result
                return _set_function_prototype_8616(self._function, *fallback)
            cc, prototype = result
            if prototype is None:
                fallback = _fallback_wide_stack_return_prototype_8616(self)
                if fallback is not None:
                    return _set_function_prototype_8616(self._function, *fallback)
            promoted = _promote_wide_stack_return_to_wide_arg_8616(self, prototype)
            if (
                promoted is not prototype
                and (
                    getattr(self._function, "prototype", None) is None
                    or getattr(self._function, "is_prototype_guessed", False)
                )
                and not _has_explicit_arg_names_8616(promoted)
            ):
                return _set_function_prototype_8616(self._function, cc, promoted)
            return cc, promoted

        _cc_analysis.CallingConventionAnalysis._analyze_function = _analyze_function_8616

    if getattr(_cc_analysis.CallingConventionAnalysis._guess_retval_type, "__name__", "") != "_guess_retval_type_8616":
        _guess_retval_type_8616._orig = _cc_analysis.CallingConventionAnalysis._guess_retval_type
        _cc_analysis.CallingConventionAnalysis._guess_retval_type = _guess_retval_type_8616
