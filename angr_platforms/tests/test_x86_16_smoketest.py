import io

import angr
import keystone as ks
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLong, SimTypePointer, SimTypeShort

from angr_platforms.X86_16.annotations import decompile_function
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.simos_86_16 import SimCC8616MSCsmall  # noqa: F401


def _project_from_bytes(code: bytes):
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def _project_from_asm(asm: str):
    ks_ = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_16)
    code, _ = ks_.asm(asm, as_bytes=True)
    return _project_from_bytes(bytes(code))


def _assert_word_signature(func, arg_count: int):
    assert func.prototype is not None
    assert len(func.prototype.args) == arg_count
    assert all(isinstance(arg, SimTypeShort) and arg.size == 16 for arg in func.prototype.args)
    assert isinstance(func.prototype.returnty, SimTypeInt)
    assert func.prototype.returnty.size == 16


def _assert_long_signature(func, arg_count: int):
    assert func.prototype is not None
    assert len(func.prototype.args) == arg_count
    assert all(isinstance(arg, SimTypeLong) and arg.size == 32 for arg in func.prototype.args)
    assert isinstance(func.prototype.returnty, SimTypeLong)
    assert func.prototype.returnty.size == 32


def test_mov_add_ret_smoke():
    code = b"\xb8\x01\x00\x05\x02\x00\xc3"  # mov ax,1; add ax,2; ret
    project = _project_from_bytes(code)

    block = project.factory.block(0x1000, len(code))
    irsb = block.vex

    assert irsb.jumpkind == "Ijk_Ret"
    assert any(stmt.__class__.__name__ == "Put" for stmt in irsb.statements)
    assert "Add16" in irsb._pp_str()

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    assert "return 3;" in dec.codegen.text


def test_reg_reg_arithmetic_smoke():
    project = _project_from_asm("mov ax,1; mov bx,2; add ax,bx; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    assert "return 3;" in dec.codegen.text


def test_cmp_je_lifts():
    project = _project_from_asm("mov ax,1; cmp ax,1; je done; mov ax,9; done: ret")
    code = project.loader.memory.load(0x1000, project.loader.main_object.max_addr - 0x1000 + 1)

    irsb = project.factory.block(0x1000, len(code)).vex
    assert irsb.jumpkind == "Ijk_Boring"
    assert "CmpEQ16" in irsb._pp_str()


def test_enter_local_stack_smoke():
    project = _project_from_asm("enter 2, 0; mov word ptr [bp-2], 1; mov ax, [bp-2]; leave; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert dec.codegen is not None
    assert "return 1;" in dec.codegen.text


def test_near_call_smoke():
    code = bytes.fromhex("e80100c3b80300c3")  # call 0x1004; ret; mov ax,3; ret
    project = _project_from_bytes(code)

    cfg = project.analyses.CFGFast(normalize=True)
    assert 0x1004 in cfg.functions

    caller = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    callee = project.analyses.Decompiler(cfg.functions[0x1004], cfg=cfg)

    assert caller.codegen is not None
    assert callee.codegen is not None
    assert "sub_1004()" in caller.codegen.text
    assert "return 3;" in callee.codegen.text


def test_stack_arg_prototype_inference():
    project = _project_from_asm(
        "push bp; mov bp, sp; mov ax, [bp+4]; mov dx, [bp+6]; add ax, dx; pop bp; ret",
    )

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 2)


def test_single_word_arg_signature_and_return_type():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; add ax, 1; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 1)
    assert "return v0 + 1;" in dec.codegen.text


def test_no_arg_frame_function_does_not_gain_phantom_arg():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, 7; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 0)
    assert "return 7;" in dec.codegen.text


def test_three_word_args_signature():
    project = _project_from_asm(
        "push bp; mov bp, sp; mov ax, [bp+4]; add ax, [bp+6]; add ax, [bp+8]; pop bp; ret"
    )

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 3)
    assert "return" in dec.codegen.text


def test_compiler_conditional_decomp_simplifies_bool_ite():
    project = _project_from_asm(
        "push bp; mov bp, sp; mov ax, [bp+4]; cmp ax, 2; jle base; mov ax, 0; jmp done; "
        "base: mov ax, 1; done: pop bp; ret"
    )

    cfg = project.analyses.CFGFast(normalize=True)
    dec = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert dec.codegen is not None
    assert "? 0 : 1" not in dec.codegen.text
    assert "if (!(" in dec.codegen.text


def test_conditional_two_word_args_signature():
    project = _project_from_asm(
        "push bp; mov bp, sp; mov ax, [bp+4]; cmp ax, [bp+6]; jle base; mov ax, 0; pop bp; ret; "
        "base: mov ax, 1; pop bp; ret"
    )

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_word_signature(func, 2)
    assert "? 0 : 1" not in dec.codegen.text


def test_wide_return_inference():
    project = _project_from_asm("mov ax, 0x5678; mov dx, 0x1234; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_long_signature(func, 0)
    assert "return" in dec.codegen.text


def test_wide_arg_and_return_inference():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; mov dx, [bp+6]; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    _assert_long_signature(func, 1)
    assert "return" in dec.codegen.text


def test_explicit_wide_return_codegen():
    project = _project_from_asm("mov ax, 0x5678; mov dx, 0x1234; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    func.prototype = SimTypeFunction([], SimTypeLong()).with_arch(project.arch)
    func.is_prototype_guessed = False
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    assert "return 305419896;" in dec.codegen.text


def test_explicit_near_pointer_prototype():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    func.prototype = SimTypeFunction([SimTypePointer(SimTypeChar())], SimTypePointer(SimTypeChar())).with_arch(
        project.arch
    )
    func.is_prototype_guessed = False
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    assert "char * _start(char *a0)" in dec.codegen.text
    assert "return a0;" in dec.codegen.text


def test_explicit_far_pointer_like_prototype():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; mov dx, [bp+6]; pop bp; ret")

    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[0x1000]
    func.prototype = SimTypeFunction([SimTypeLong(label="far_ptr")], SimTypeLong(label="far_ptr")).with_arch(
        project.arch
    )
    func.is_prototype_guessed = False
    dec = project.analyses.Decompiler(func, cfg=cfg)

    assert dec.codegen is not None
    assert "long _start" in dec.codegen.text
    assert "0x10000" in dec.codegen.text


def test_c_decl_annotation_applies_function_and_argument_names():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; add ax, [bp+6]; pop bp; ret")

    dec = decompile_function(project, 0x1000, c_decl="int add_words(int lhs, int rhs);")

    assert dec.codegen is not None
    assert "int add_words(int lhs, int rhs)" in dec.codegen.text
    assert "return lhs + rhs;" in dec.codegen.text


def test_stack_variable_annotation_applies_local_name():
    project = _project_from_asm(
        "push bp; mov bp, sp; sub sp, 2; mov ax, [bp+4]; add ax, [bp+6]; "
        "mov [bp-2], ax; mov ax, [bp-2]; mov sp, bp; pop bp; ret"
    )

    dec = decompile_function(
        project,
        0x1000,
        c_decl="int add_store(int lhs, int rhs);",
        stack_vars={-4: "total"},
    )

    assert dec.codegen is not None
    assert "int add_store(int lhs, int rhs)" in dec.codegen.text
    assert "unsigned short total;" in dec.codegen.text
    assert "total = lhs + rhs;" in dec.codegen.text


def test_bp_relative_stack_annotation_uses_assembly_displacement():
    project = _project_from_asm(
        "push bp; mov bp, sp; sub sp, 2; mov ax, [bp+4]; add ax, [bp+6]; "
        "mov [bp-2], ax; mov ax, [bp-2]; mov sp, bp; pop bp; ret"
    )

    dec = decompile_function(
        project,
        0x1000,
        c_decl="int add_store_bp(int lhs, int rhs);",
        bp_stack_vars={-2: "sum_local"},
    )

    assert dec.codegen is not None
    assert "unsigned short sum_local;" in dec.codegen.text
    assert "sum_local = lhs + rhs;" in dec.codegen.text


def test_c_decl_annotation_applies_pointer_signature():
    project = _project_from_asm("push bp; mov bp, sp; mov ax, [bp+4]; pop bp; ret")

    dec = decompile_function(project, 0x1000, c_decl="char *identity(char *src);")

    assert dec.codegen is not None
    assert "identity(char *src)" in dec.codegen.text
    assert "return src;" in dec.codegen.text
