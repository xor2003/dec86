from __future__ import annotations

import functools
import logging
import threading

_LOCK = threading.Lock()
_APPLIED = False


def apply_pyvex_runtime_compatibility() -> None:
    global _APPLIED
    if _APPLIED:
        return

    with _LOCK:
        if _APPLIED:
            return

        try:
            from pyvex import const as pyvex_const
            from pyvex.lifting.util import lifter_helper
            from pyvex.lifting.util import vex_helper
        except Exception:
            return

        if getattr(pyvex_const.get_type_size, "__name__", "") != "_inertia_cached_get_type_size":
            original_get_type_size = pyvex_const.get_type_size

            @functools.lru_cache(maxsize=None)
            def _inertia_cached_get_type_size(ty):
                return original_get_type_size(ty)

            pyvex_const.get_type_size = _inertia_cached_get_type_size

        if getattr(pyvex_const.get_type_spec_size, "__name__", "") != "_inertia_cached_get_type_spec_size":
            original_get_type_spec_size = pyvex_const.get_type_spec_size

            @functools.lru_cache(maxsize=None)
            def _inertia_cached_get_type_spec_size(ty):
                return original_get_type_spec_size(ty)

            pyvex_const.get_type_spec_size = _inertia_cached_get_type_spec_size

        type_meta = vex_helper.TypeMeta
        if not getattr(type_meta, "_inertia_cached_getattr", False):
            original_getattr = type_meta.__getattr__
            cache: dict[str, object] = {}

            def _inertia_cached_type_getattr(self, name):
                cached = cache.get(name)
                if cached is not None:
                    return cached
                result = original_getattr(self, name)
                if name.startswith("int_"):
                    cache[name] = result
                return result

            type_meta.__getattr__ = _inertia_cached_type_getattr
            type_meta._inertia_cached_getattr = True

        gymrat_lift = getattr(lifter_helper.GymratLifter, "_lift", None)
        if getattr(gymrat_lift, "__name__", "") != "_inertia_safe_lift":
            JumpKind = lifter_helper.JumpKind
            IRSBCustomizer = lifter_helper.IRSBCustomizer
            LiftingException = lifter_helper.LiftingException
            vex_int_class = lifter_helper.vex_int_class
            log = lifter_helper.log

            def _inertia_safe_lift(self):
                self.thedata = (
                    self.data[: self.max_bytes]
                    if isinstance(self.data, (bytes, bytearray, memoryview))
                    else self.data[: self.max_bytes].encode()
                )
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(repr(self.thedata))
                instructions = self.decode()

                if self.disasm:
                    self.disassembly = [instr.disassemble() for instr in instructions]
                self.irsb.jumpkind = JumpKind.Invalid
                irsb_c = IRSBCustomizer(self.irsb)
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Decoding complete.")
                for i, instr in enumerate(instructions[: self.max_inst]):
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug("Lifting instruction %s", instr.name)
                    instr(irsb_c, instructions[:i], instructions[i + 1 :])
                    if irsb_c.irsb.jumpkind != JumpKind.Invalid:
                        break
                    if (i + 1) == self.max_inst:
                        instr.jump(None, irsb_c.irsb.addr + irsb_c.irsb.size)
                        break
                else:
                    if len(irsb_c.irsb.statements) == 0:
                        raise LiftingException("Could not decode any instructions")
                    irsb_c.irsb.jumpkind = JumpKind.NoDecode
                    dst = irsb_c.irsb.addr + irsb_c.irsb.size
                    dst_ty = vex_int_class(irsb_c.irsb.arch.bits).type
                    irsb_c.irsb.next = irsb_c.mkconst(dst, dst_ty)
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("%s", self.irsb)
                if self.dump_irsb:
                    self.irsb.pp()
                return self.irsb

            lifter_helper.GymratLifter._lift = _inertia_safe_lift

        _APPLIED = True
