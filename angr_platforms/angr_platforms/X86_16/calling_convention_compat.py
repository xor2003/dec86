from __future__ import annotations

from enum import Enum

from angr.analyses.calling_convention import calling_convention as _cc_analysis
from angr.analyses.calling_convention import fact_collector as _cc_fact_collector
from angr.analyses.calling_convention import utils as _cc_utils
from angr.errors import SimTranslationError
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from pyvex.expr import Get
from pyvex.stmt import Put

from .simos_86_16 import SimCC8616MSCsmall

__all__ = [
    "apply_x86_16_calling_convention_compatibility",
    "apply_x86_16_wide_stack_prototype_evidence",
]


class _WideReturnEvidence8616(Enum):
    NONE = 0
    DX_AX_TERMINAL_ARITH = 1


def _has_explicit_arg_names_8616(prototype) -> bool:
    arg_names = getattr(prototype, "arg_names", None) or ()
    for name in arg_names:
        if name is None:
            continue
        if not (isinstance(name, str) and len(name) > 1 and name[0] == "a" and name[1:].isdigit()):
            return True
    return False


def _irsb_reads_word_bp_8616(irsb, arch) -> bool:
    bp_offset = arch.registers["bp"][0]
    for stmt in irsb.statements:
        for expr in stmt.expressions:
            if isinstance(expr, Get) and expr.offset == bp_offset and expr.ty == "Ity_I16":
                return True
    return False


def _count_ax_dx_puts_8616(irsb, arch) -> int:
    count = 0
    for stmt in irsb.statements:
        if not isinstance(stmt, Put):
            continue
        reg_name = arch.translate_register_name(stmt.offset, size=arch.bytes)
        if reg_name in {"ax", "dx"}:
            count += 1
    return count


def _iter_function_blocks_8616(project, function):
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            yield project.factory.block(int(block_addr), opt_level=0)
        except SimTranslationError:
            continue


def _capstone_reg_name_8616(insn, reg_id: int) -> str:
    try:
        return str(insn.reg_name(reg_id)).lower()
    except Exception:
        return ""


def _instruction_writes_reg_8616(insn, reg_name: str) -> bool:
    operands = tuple(getattr(insn, "operands", ()) or ())
    if not operands:
        return False
    first = operands[0]
    if int(getattr(first, "type", -1)) != 1:
        return False
    return _capstone_reg_name_8616(insn, int(getattr(first, "reg", 0) or 0)) == reg_name


def _terminal_wide_return_evidence_8616(project, function) -> _WideReturnEvidence8616:
    """Detect a terminal DX:AX producer without relying on source names."""
    terminal_dx_ops = {"adc", "sbb", "mov"}
    for block in _iter_function_blocks_8616(project, function):
        insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
        if not insns:
            continue
        last_ax_idx = None
        last_dx_idx = None
        last_dx_mnemonic = None
        for idx, insn in enumerate(insns):
            if _instruction_writes_reg_8616(insn, "ax"):
                last_ax_idx = idx
            if _instruction_writes_reg_8616(insn, "dx"):
                last_dx_idx = idx
                last_dx_mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        if last_ax_idx is None or last_dx_idx is None:
            continue
        if last_dx_idx <= last_ax_idx:
            continue
        if last_dx_mnemonic in terminal_dx_ops:
            return _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH
    return _WideReturnEvidence8616.NONE


def _bp_word_load_offsets_from_instructions_8616(project, function) -> tuple[int, ...]:
    offsets: set[int] = set()
    for block in _iter_function_blocks_8616(project, function):
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            for operand in tuple(getattr(insn, "operands", ()) or ()):
                if int(getattr(operand, "type", -1)) != 3:
                    continue
                if int(getattr(operand, "size", 0) or 0) != 2:
                    continue
                mem = getattr(operand, "mem", None)
                if mem is None or not getattr(mem, "base", None):
                    continue
                if _capstone_reg_name_8616(insn, int(mem.base)) != "bp":
                    continue
                disp = int(getattr(mem, "disp", 0) or 0)
                if 0x8000 <= disp <= 0xFFFF:
                    disp -= 0x10000
                if disp >= 4:
                    offsets.add(disp)
    return tuple(sorted(offsets))


def _wide_stack_arg_count_from_offsets_8616(offsets: tuple[int, ...]) -> int:
    remaining = set(offsets)
    count = 0
    offset = 4
    while offset in remaining and offset + 2 in remaining:
        count += 1
        offset += 4
    return count


def _wide_stack_arg_prototype_from_function_8616(project, function, *, signed: bool = True):
    evidence = _terminal_wide_return_evidence_8616(project, function)
    if evidence is _WideReturnEvidence8616.NONE:
        return None
    arg_count = _wide_stack_arg_count_from_offsets_8616(_bp_word_load_offsets_from_instructions_8616(project, function))
    if arg_count <= 0:
        return None
    wide_ty = SimTypeLong(signed=signed).with_arch(project.arch)
    return SimCC8616MSCsmall(project.arch), SimTypeFunction([wide_ty] * arg_count, wide_ty).with_arch(project.arch)


def _guess_retval_type_8616(self, cc, ret_val_size):
    def _impl():
        ret_type = _guess_retval_type_8616._orig(self, cc, ret_val_size)
        if getattr(self.project.arch, "name", None) != "86_16" or ret_type is None:
            return ret_type
        if getattr(ret_type, "__class__", None).__name__ != "SimTypeShort":
            return ret_type
        if not getattr(cc, "OVERFLOW_RETURN_VAL", None) or getattr(cc, "RETURN_VAL", None) is None:
            return ret_type
        if getattr(self._function, "_argument_registers", None) or getattr(
            self._function, "_argument_stack_variables", None
        ):
            return ret_type

        for ret_block in getattr(self._function, "ret_sites", ()):
            retval_updated, overflow_updated = False, False
            try:
                irsb = self.project.factory.block(ret_block.addr, size=ret_block.size).vex
            except SimTranslationError:
                continue
            if _irsb_reads_word_bp_8616(irsb, self.project.arch):
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

    return _impl()


def _promote_wide_stack_return_to_wide_arg_8616(self, prototype):
    def _impl():
        if getattr(self.project.arch, "name", None) != "86_16" or prototype is None:
            return prototype
        wide_stack_proto = _wide_stack_arg_prototype_from_function_8616(self.project, self._function)
        if wide_stack_proto is not None:
            _cc, promoted = wide_stack_proto
            return promoted
        if len(prototype.args) == 0 and isinstance(prototype.returnty, SimTypeLong):
            block_addrs = sorted(getattr(self._function, "block_addrs_set", ()) or ())
            if block_addrs:
                try:
                    irsb = self.project.factory.block(block_addrs[0]).vex
                except SimTranslationError:
                    irsb = None
                if irsb is not None:
                    if _irsb_reads_word_bp_8616(irsb, self.project.arch):
                        if _count_ax_dx_puts_8616(irsb, self.project.arch) == 2:
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

        if not _irsb_reads_word_bp_8616(irsb, self.project.arch):
            return prototype

        if _count_ax_dx_puts_8616(irsb, self.project.arch) != 2:
            return prototype

        wide_ty = SimTypeLong().with_arch(self.project.arch)
        return prototype.__class__([wide_ty], wide_ty).with_arch(self.project.arch)

    return _impl()


def _fallback_wide_stack_return_prototype_8616(self):
    wide_stack_proto = _wide_stack_arg_prototype_from_function_8616(self.project, self._function)
    if wide_stack_proto is not None:
        return wide_stack_proto

    block_addrs = sorted(getattr(self._function, "block_addrs_set", ()) or ())
    if not block_addrs:
        return None

    try:
        irsb = self.project.factory.block(block_addrs[0]).vex
    except SimTranslationError:
        return None

    if not _irsb_reads_word_bp_8616(irsb, self.project.arch) or irsb.jumpkind != "Ijk_Ret":
        return None

    if _count_ax_dx_puts_8616(irsb, self.project.arch) != 2:
        return None

    wide_ty = SimTypeLong().with_arch(self.project.arch)
    return SimCC8616MSCsmall(self.project.arch), SimTypeFunction([wide_ty], wide_ty).with_arch(self.project.arch)


def _set_function_prototype_8616(function, cc, prototype) -> tuple[object, object]:
    existing = getattr(function, "prototype", None)
    if existing is not None and (
        _has_explicit_arg_names_8616(existing) or not bool(getattr(function, "is_prototype_guessed", True))
    ):
        return cc, existing
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


def apply_x86_16_wide_stack_prototype_evidence(project, function) -> bool:
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        return False
    existing = getattr(function, "prototype", None)
    if existing is not None and (
        _has_explicit_arg_names_8616(existing) or not bool(getattr(function, "is_prototype_guessed", True))
    ):
        return False
    inferred = _wide_stack_arg_prototype_from_function_8616(project, function)
    if inferred is None:
        return False
    cc, prototype = inferred
    _set_function_prototype_8616(function, cc, prototype)
    return True


def apply_x86_16_calling_convention_compatibility() -> None:
    if getattr(_cc_utils.is_sane_register_variable, "__name__", "") != "_is_sane_register_variable_8616":
        _orig_is_sane_register_variable = _cc_utils.is_sane_register_variable

        def _is_sane_register_variable_8616(arch, reg_offset, reg_size, def_cc=None):
            if arch.name == "86_16":
                return True
            return _orig_is_sane_register_variable(arch, reg_offset, reg_size, def_cc=def_cc)

        _cc_utils.is_sane_register_variable = _is_sane_register_variable_8616
        _cc_analysis.is_sane_register_variable = _is_sane_register_variable_8616
        _cc_fact_collector.is_sane_register_variable = _is_sane_register_variable_8616

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
