import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable

from angr_platforms.X86_16.annotations import ANNOTATION_KEY
from angr_platforms.X86_16.arch_86_16 import Arch86_16

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

from angr_platforms.X86_16 import decompiler_postprocess as postprocess


class _FakePrototype:
    def __init__(self, args=None, returnty=None, *, arg_names=None, variadic=False):
        self.args = [SimTypeShort(False)] if args is None else list(args)
        self.returnty = SimTypeLong() if returnty is None else returnty
        self.arg_names = ("a0",) if arg_names is None else arg_names
        self.variadic = variadic

    def with_arch(self, _arch):
        try:
            self.returnty = self.returnty.with_arch(_arch)
        except Exception:
            pass
        self.args = [arg.with_arch(_arch) if hasattr(arg, "with_arch") else arg for arg in self.args]
        return self


def test_bp_stack_prototype_promotion_rejects_mixed_stack_regions(monkeypatch):
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1)
    project = SimpleNamespace(
        arch=SimpleNamespace(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(
                    prototype=_FakePrototype(),
                    is_prototype_guessed=True,
                )
            )
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(statements=[]),
            variables_in_use={
                SimStackVariable(4, 1, base="bp", name="a0", region=0x1000): SimpleNamespace(),
                SimStackVariable(6, 1, base="bp", name="a1", region=0x2000): SimpleNamespace(),
            },
        )
    )
    ret0 = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    ret1 = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    codegen.cfunc.statements.statements = [ret0, ret1]

    fake_nodes = [object(), object()]
    monkeypatch.setattr(postprocess, "_iter_c_nodes_deep_8616", lambda _retval: iter(fake_nodes))
    monkeypatch.setattr(
        postprocess, "_match_bp_stack_load_8616", lambda node, _project: 4 if node is fake_nodes[0] else 6
    )

    assert not postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)


def test_bp_stack_prototype_promotion_uses_annotated_stack_vars():
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("funcNumber",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "ovlLoadSegment"},
                    6: {"name": "funcNumber"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=SimpleNamespace(statements=[]), variables_in_use={})
    )

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert len(func.prototype.args) == 2
    assert func.prototype.arg_names == ["ovlLoadSegment", "funcNumber"]


def test_bp_stack_prototype_promotion_preserves_pointer_evidence():
    stack_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("s",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "s"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
        )
    )
    stack_cvar.codegen = codegen

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.args[0], SimTypePointer)
    assert "s *" in str(func.prototype.args[0]) or func.prototype.args[0].__class__.__name__ == "SimTypePointer"


def test_bp_stack_prototype_promotion_preserves_pointer_evidence_without_annotations():
    stack_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False)],
            arg_names=("s",),
            returnty=SimTypeShort(False),
        ),
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
            arg_list=[stack_cvar],
            functy=func.prototype,
        )
    )
    stack_cvar.codegen = codegen

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.args[0], SimTypePointer)
    assert codegen.cfunc.functy is func.prototype
    assert codegen.cfunc.arg_list == [stack_cvar]


def test_bp_stack_prototype_promotion_respects_scalar_source_decl_over_weak_pointer_promotion():
    stack_var = SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False), SimTypeShort(False)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "iRow1"},
                    6: {"name": "iRow2"},
                },
                "source_lines": (
                    "void SwapBars(int iRow1, int iRow2)",
                    "{",
                    "}",
                ),
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(
                statements=[
                    structured_c.CUnaryOp("Dereference", stack_cvar, codegen=c_codegen),
                ]
            ),
            variables_in_use={stack_var: stack_cvar},
            arg_list=[None, stack_cvar],
            functy=func.prototype,
        ),
    )
    stack_cvar.codegen = codegen

    postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert not isinstance(func.prototype.args[1], SimTypePointer)


def test_bp_stack_prototype_promotion_demotes_unproved_annotated_pointer_arg():
    arch = Arch86_16()
    first_stack_var = SimStackVariable(4, 2, base="bp", name="iRow1", region=0x1000)
    stack_var = SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch))
    first_stack_cvar = structured_c.CVariable(
        first_stack_var,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    stack_cvar = structured_c.CVariable(
        stack_var,
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    func = SimpleNamespace(
        prototype=_FakePrototype(
            args=[SimTypeShort(False).with_arch(arch), SimTypePointer(SimTypeShort(False)).with_arch(arch)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "iRow1"},
                    6: {"name": "iRow2"},
                },
                "source_lines": (
                    "void SwapBars(int iRow1, int iRow2)",
                    "{",
                    "}",
                ),
            }
        },
    )
    project = SimpleNamespace(
        arch=arch,
        _inertia_c_target="portable-flat",
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(statements=[]),
            variables_in_use={first_stack_var: first_stack_cvar, stack_var: stack_cvar},
            arg_list=[first_stack_cvar, stack_cvar],
            functy=func.prototype,
        ),
    )
    first_stack_cvar.codegen = codegen
    stack_cvar.codegen = codegen

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert not isinstance(func.prototype.args[1], SimTypePointer)
    assert not isinstance(stack_cvar.variable_type, SimTypePointer)


def test_annotation_arg_sync_demotes_unproved_pointer_from_source_scalar_arg():
    arch = Arch86_16()
    first_stack_var = SimStackVariable(2, 2, base="bp", name="iRow1", region=0x1000)
    second_stack_var = SimStackVariable(4, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch))
    first_stack_cvar = structured_c.CVariable(
        first_stack_var,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    second_stack_cvar = structured_c.CVariable(
        second_stack_var,
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    func = SimpleNamespace(
        addr=0x1000,
        prototype=_FakePrototype(
            args=[SimTypeShort(False).with_arch(arch), SimTypePointer(SimTypeShort(False)).with_arch(arch)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "iRow1"},
                    4: {"name": "iRow2"},
                },
                "source_lines": (
                    "void SwapBars( int iRow1, int iRow2 )",
                    "{",
                    "}",
                ),
            }
        },
    )
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch, _inertia_c_target="portable-flat"),
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=func.prototype,
            arg_list=[first_stack_cvar, second_stack_cvar],
        ),
    )
    first_stack_cvar.codegen = codegen
    second_stack_cvar.codegen = codegen

    changed = postprocess._sync_arg_list_from_annotations_8616(
        codegen=codegen,
        func=func,
        stack_specs=func.info[ANNOTATION_KEY]["stack_vars"],
        resolve_stack_cvar=lambda offset: {2: first_stack_cvar, 4: second_stack_cvar}.get(offset),
        promote_near_pointers=False,
    )

    assert changed is True
    assert not isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    assert not isinstance(second_stack_cvar.variable_type, SimTypePointer)


def test_annotation_arg_sync_uses_project_cod_metadata_source_flags():
    arch = Arch86_16()
    first_stack_var = SimStackVariable(2, 2, base="bp", name="iRow1", region=0x1000)
    second_stack_var = SimStackVariable(4, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch))
    first_stack_cvar = structured_c.CVariable(
        first_stack_var,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    second_stack_cvar = structured_c.CVariable(
        second_stack_var,
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    func = SimpleNamespace(
        addr=0x1000,
        prototype=_FakePrototype(
            args=[SimTypeShort(False).with_arch(arch), SimTypePointer(SimTypeShort(False)).with_arch(arch)],
            arg_names=("iRow1", "iRow2"),
            returnty=SimTypeBottom(),
        ),
        info={
            ANNOTATION_KEY: {
                "stack_vars": {2: {"name": "iRow1"}, 4: {"name": "iRow2"}},
                "source_lines": (),
            }
        },
    )
    codegen = SimpleNamespace(
        project=SimpleNamespace(
            arch=arch,
            _inertia_c_target="portable-flat",
            _inertia_cod_metadata_by_func_addr_8616={
                0x1000: SimpleNamespace(source_lines=("void SwapBars( int iRow1, int iRow2 )", "{", "}"))
            },
        ),
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=func.prototype,
            arg_list=[first_stack_cvar, second_stack_cvar],
        ),
    )
    first_stack_cvar.codegen = codegen
    second_stack_cvar.codegen = codegen

    changed = postprocess._sync_arg_list_from_annotations_8616(
        codegen=codegen,
        func=func,
        stack_specs=func.info[ANNOTATION_KEY]["stack_vars"],
        resolve_stack_cvar=lambda offset: {2: first_stack_cvar, 4: second_stack_cvar}.get(offset),
        promote_near_pointers=False,
    )

    assert changed is True
    assert not isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    assert not isinstance(second_stack_cvar.variable_type, SimTypePointer)


def test_fallback_arg_promotion_demotes_pointer_from_project_cod_scalar_flags():
    arch = Arch86_16()
    first_stack_var = SimStackVariable(2, 2, base="bp", name="iRow1", region=0x1000)
    second_stack_var = SimStackVariable(4, 2, base="bp", name="iRow2", region=0x1000)
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch))
    first_stack_cvar = structured_c.CVariable(
        first_stack_var,
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    second_stack_cvar = structured_c.CVariable(
        second_stack_var,
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(
        args=[SimTypeShort(False).with_arch(arch), SimTypePointer(SimTypeShort(False)).with_arch(arch)],
        arg_names=("iRow1", "iRow2"),
        returnty=SimTypeBottom(),
    )
    func = SimpleNamespace(addr=0x1000, prototype=prototype)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch, _inertia_c_target="portable-flat"),
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=prototype,
            arg_list=[first_stack_cvar, second_stack_cvar],
            statements=SimpleNamespace(statements=[]),
        ),
    )
    first_stack_cvar.codegen = codegen
    second_stack_cvar.codegen = codegen

    changed = postprocess._promote_from_fallback_args_8616(
        project=codegen.project,
        codegen=codegen,
        func=func,
        current_proto=prototype,
        existing_args=[first_stack_cvar, second_stack_cvar],
        source_pointer_flags=(False, False),
        promote_near_pointers=False,
    )

    assert changed is True
    assert not isinstance(codegen.cfunc.functy.args[1], SimTypePointer)
    assert not isinstance(second_stack_cvar.variable_type, SimTypePointer)


def test_apply_annotations_uses_project_cod_source_prototype_for_active_function():
    arch = Arch86_16()
    func = SimpleNamespace(addr=0x1000, name="SwapBars", prototype=None, info={})
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch))
    first_stack_cvar = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="iRow1", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    second_stack_cvar = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="iRow2", region=0x1000),
        variable_type=SimTypePointer(SimTypeShort(False)).with_arch(arch),
        codegen=c_codegen,
    )
    duplicate_second_cvar = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_6", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    body_call = structured_c.CFunctionCall("DrawBar", None, [duplicate_second_cvar], codegen=c_codegen)

    class _Functions:
        def function(self, *, addr, create=False):
            assert addr == 0x1000
            return func

    project = SimpleNamespace(
        arch=arch,
        _inertia_c_target="portable-flat",
        _inertia_cod_metadata_by_func_addr_8616={
            0x1000: SimpleNamespace(source_lines=("void SwapBars( int iRow1, int iRow2 )", "{", "}"))
        },
        kb=SimpleNamespace(functions=_Functions()),
    )
    codegen = SimpleNamespace(
        project=project,
        _function=SimpleNamespace(prototype=None, is_prototype_guessed=True),
        cfunc=SimpleNamespace(
            addr=0x1000,
            functy=None,
            arg_list=[first_stack_cvar, second_stack_cvar],
            statements=structured_c.CStatements(
                [structured_c.CExpressionStatement(body_call, codegen=c_codegen)],
                codegen=c_codegen,
            ),
            variables_in_use={
                first_stack_cvar.variable: first_stack_cvar,
                second_stack_cvar.variable: second_stack_cvar,
                duplicate_second_cvar.variable: duplicate_second_cvar,
            },
        ),
    )
    first_stack_cvar.codegen = codegen
    second_stack_cvar.codegen = codegen
    duplicate_second_cvar.codegen = codegen
    body_call.codegen = codegen

    changed = postprocess._apply_annotations_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)
    assert not any(isinstance(arg, SimTypePointer) for arg in func.prototype.args)
    assert not isinstance(second_stack_cvar.variable_type, SimTypePointer)
    assert codegen.cfunc.functy is func.prototype
    assert codegen._function.prototype is func.prototype
    assert codegen._function.is_prototype_guessed is False
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_codegen_prototype_sync_count_8616 >= 1
    assert body_call.args[0] is second_stack_cvar


def test_unify_positive_bp_arg_stack_variables_replaces_duplicate_body_slots():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch))
    arg_cvar = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="iRow2", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    duplicate_cvar = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_6", region=0x1000),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=c_codegen,
    )
    call = structured_c.CFunctionCall("DrawBar", None, [duplicate_cvar], codegen=c_codegen)
    statements = structured_c.CStatements(
        [structured_c.CExpressionStatement(call, codegen=c_codegen)],
        codegen=c_codegen,
    )
    cfunc = SimpleNamespace(
        arg_list=[arg_cvar],
        statements=statements,
        variables_in_use={
            arg_cvar.variable: arg_cvar,
            duplicate_cvar.variable: duplicate_cvar,
        },
        unified_local_vars={
            duplicate_cvar.variable: {(duplicate_cvar, duplicate_cvar.variable_type)},
        },
    )
    codegen = SimpleNamespace(cfunc=cfunc)

    changed = postprocess._unify_positive_bp_arg_stack_variables_8616(SimpleNamespace(arch=arch), codegen)

    assert changed is True
    assert call.args[0] is arg_cvar
    assert list(cfunc.variables_in_use.values()) == [arg_cvar]
    assert duplicate_cvar.variable not in cfunc.unified_local_vars
    assert codegen._inertia_arg_stack_identity_unified_8616 == 1
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_metadata_lookup_merges_rebased_source_annotations_into_partial_active_metadata():
    active = SimpleNamespace(
        addr=0x1000,
        prototype=None,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {2: {"name": "iRow1"}},
                "global_vars": {},
                "source_lines": (),
                "source_return_lines": (),
            }
        },
    )
    rebased = SimpleNamespace(
        addr=0x10768,
        prototype=None,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {},
                "global_vars": {},
                "source_lines": ("void SwapBars( int iRow1, int iRow2 )", "{", "}"),
                "source_return_lines": (),
            }
        },
    )

    class _Functions:
        def function(self, *, addr, create=False):
            assert create is False
            return {0x1000: active, 0x10768: rebased}.get(addr)

    project = SimpleNamespace(
        _inertia_original_linear_delta=0xF768,
        kb=SimpleNamespace(functions=_Functions()),
    )

    selected = postprocess._metadata_function_for_codegen_addr_8616(project, 0x1000)

    assert selected is active
    assert active.info[ANNOTATION_KEY]["source_lines"] == ("void SwapBars( int iRow1, int iRow2 )", "{", "}")


def test_metadata_lookup_uses_project_cod_metadata_source_annotations():
    active = SimpleNamespace(
        addr=0x1000,
        prototype=None,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {2: {"name": "iRow1"}},
                "global_vars": {},
                "source_lines": (),
                "source_return_lines": (),
            }
        },
    )

    class _Functions:
        def function(self, *, addr, create=False):
            assert create is False
            return active if addr == 0x1000 else None

    project = SimpleNamespace(
        _inertia_cod_metadata_by_func_addr_8616={
            0x1000: SimpleNamespace(source_lines=("void SwapBars( int iRow1, int iRow2 )", "{", "}"))
        },
        kb=SimpleNamespace(functions=_Functions()),
    )

    selected = postprocess._metadata_function_for_codegen_addr_8616(project, 0x1000)

    assert selected is active
    assert active.info[ANNOTATION_KEY]["source_lines"] == ("void SwapBars( int iRow1, int iRow2 )", "{", "}")


def test_bp_stack_prototype_promotion_shrinks_overguessed_stack_arguments():
    prototype = _FakePrototype(
        args=[SimTypeShort(False), SimTypeShort(False)],
        arg_names=("s", "a1"),
        returnty=SimTypeShort(False),
    )
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    4: {"name": "s"},
                },
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=SimpleNamespace(statements=[]),
            variables_in_use={},
            arg_list=["first", "second"],
            functy=prototype,
        )
    )

    changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)

    assert changed is True
    assert len(func.prototype.args) == 1
    assert func.prototype.arg_names == ["s"]
    assert codegen.cfunc.arg_list == ["first"]
    assert codegen.cfunc.functy is func.prototype


def test_bp_stack_prototype_promotion_counts_only_real_stack_arguments():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=SimpleNamespace(statements=[]), variables_in_use={})
    )
    ret = structured_c.CReturn(SimpleNamespace(), codegen=c_codegen)
    codegen.cfunc.statements.statements = [ret]
    fake_node = object()

    def fake_iter(_retval):
        return iter([fake_node])

    original_iter = postprocess._iter_c_nodes_deep_8616
    original_match = postprocess._match_bp_stack_load_8616
    try:
        postprocess._iter_c_nodes_deep_8616 = fake_iter
        postprocess._match_bp_stack_load_8616 = lambda node, _project: 4 if node is fake_node else None

        changed = postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)
    finally:
        postprocess._iter_c_nodes_deep_8616 = original_iter
        postprocess._match_bp_stack_load_8616 = original_match

    assert changed is True
    assert len(func.prototype.args) == 1
    assert func.prototype.arg_names == ["a0"]


def test_bp_stack_return_address_pruning_keeps_annotated_arguments():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    arg_var = SimStackVariable(2, 2, base="bp", name="segment", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=c_codegen)
    prototype = _FakePrototype(args=[SimTypeShort(False)], arg_names=("segment",), returnty=SimTypeShort(False))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={ANNOTATION_KEY: {"stack_vars": {2: {"name": "segment"}}}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000, arg_list=[arg_cvar], statements=structured_c.CStatements([], codegen=c_codegen)
        )
    )

    changed = postprocess._prune_return_address_stack_arguments_8616(project, codegen)

    assert changed is False
    assert codegen.cfunc.arg_list == [arg_cvar]
    assert func.prototype.arg_names == ("segment",)


def test_classify_return_shape_promotes_scalar_returns_from_void_prototypes():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    ret = structured_c.CReturn(
        structured_c.CConstant(0, SimTypeShort(False), codegen=c_codegen),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeShort)
    assert func.prototype.returnty.size == 16


def test_classify_return_shape_uses_source_return_lines_when_returns_are_missing():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "source_return_lines": ("return MK_FP(sreg.es, rout.x.bx);",),
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeLong)
    assert func.prototype.returnty.size == 32


def test_classify_return_shape_uses_void_source_decl_when_returns_are_missing():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "source_lines": (
                    "void ReInitBars()",
                    "{",
                    "}",
                ),
                "source_return_lines": (),
            }
        },
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)


def test_classify_return_shape_treats_explicit_void_returns_as_void():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    ret = structured_c.CReturn(None, codegen=c_codegen)
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeShort(False))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeBottom)


def test_void_return_value_prune_preserves_call_side_effect_and_control_flow():
    arch = Arch86_16()
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=arch))
    call = structured_c.CFunctionCall(
        "DrawTime",
        None,
        [structured_c.CConstant(1, SimTypeShort(False), codegen=c_codegen)],
        codegen=c_codegen,
    )
    ret = structured_c.CReturn(call, codegen=c_codegen)
    after = structured_c.CExpressionStatement(
        structured_c.CFunctionCall("After", None, [], codegen=c_codegen),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(args=[], arg_names=(), returnty=SimTypeBottom(label="void"))
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=False, info={})
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret, after], codegen=c_codegen))
    )

    changed = postprocess._prune_void_function_return_values_8616(project, codegen)

    assert changed is True
    statements = codegen.cfunc.statements.statements
    assert isinstance(statements[0], structured_c.CExpressionStatement)
    assert statements[0].expr is call
    assert isinstance(statements[1], structured_c.CReturn)
    assert statements[1].retval is None
    assert statements[2] is after
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True


def test_classify_return_shape_promotes_far_pointer_returns_from_void_prototypes():
    c_codegen = SimpleNamespace(next_idx=lambda _name: 1, project=SimpleNamespace(arch=Arch86_16()))
    ret = structured_c.CReturn(
        structured_c.CFunctionCall(
            "MK_FP",
            None,
            [
                structured_c.CConstant(0x1234, SimTypeShort(False), codegen=c_codegen),
                structured_c.CConstant(0x20, SimTypeShort(False), codegen=c_codegen),
            ],
            codegen=c_codegen,
        ),
        codegen=c_codegen,
    )
    prototype = _FakePrototype(returnty=SimTypeBottom())
    func = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, info={})
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)
        ),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=structured_c.CStatements([ret], codegen=c_codegen))
    )

    changed = postprocess._classify_return_shape_8616(project, codegen)

    assert changed is True
    assert isinstance(func.prototype.returnty, SimTypeLong)
    assert func.prototype.returnty.size == 32
