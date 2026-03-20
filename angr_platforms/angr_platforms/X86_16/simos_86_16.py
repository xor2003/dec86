import claripy

from angr import SimProcedure
from angr.calling_conventions import (
    SimCC,
    SimRegArg,
    SimStackArg,
    register_default_cc,
    register_syscall_cc,
)
from angr.simos import SimOS, register_simos

from .arch_86_16 import Arch86_16


DOS_INT21_ADDR = 0xFF021


class DOSInt21(SimProcedure):
    """
    Minimal DOS interrupt stub used by the x86-16 real-mode lifter.
    We model `int 0x21` as a synthetic call target so CFG/decompilation
    can reason about it as a normal function edge.
    """

    NO_RET = False

    def run(self):  # pylint:disable=arguments-differ
        ah = self.state.regs.ah
        if self.state.solver.is_true(ah == 0x30):
            # DOS version query: AL=major, AH=minor
            self.state.regs.al = claripy.BVV(5, 8)
            self.state.regs.ah = claripy.BVV(0, 8)
            return claripy.BVV(0x0005, 16)

        return claripy.BVS("dos_int21_ax", 16)


class SimDOSintcall(SimCC):
    ARG_REGS = ["ax", "bx", "cx", "dx"]  # TODO
    RETURN_VAL = SimRegArg("ax", 2)
    ARCH = Arch86_16

    @staticmethod
    def _match(arch, args: list, sp_delta):   # pylint: disable=unused-argument
        # doesn't appear anywhere but syscalls
        return False

    @staticmethod
    def syscall_num(state):
        print("DOS int was called %s" % state.regs.ip_at_syscall)
        return state.regs.ax


class SimDOS86_16(SimOS):
    def __init__(self, project, **kwargs):
        super().__init__(project, name="DOS", **kwargs)

    def configure_project(self):
        super().configure_project()
        self.project.hook(DOS_INT21_ADDR, DOSInt21(), replace=True)


class SimCC8616MSCsmall(SimCC):
    ARG_REGS = []
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL = SimRegArg("dx", 2)
    ARCH = Arch86_16
    STACK_ALIGNMENT = 2
    CALLEE_CLEANUP = True


class SimCC8616MSCmedium(SimCC):
    ARG_REGS = []
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    RETURN_VAL = SimRegArg("ax", 2)
    OVERFLOW_RETURN_VAL = SimRegArg("dx", 2)
    ARCH = Arch86_16
    STACK_ALIGNMENT = 2
    CALLEE_CLEANUP = True


register_simos("DOS", SimDOS86_16)
register_default_cc("86_16", SimCC8616MSCsmall)
register_syscall_cc("86_16", "Linux", SimDOSintcall)
register_syscall_cc("86_16", "default", SimDOSintcall)
