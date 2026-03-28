from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)


def _make_codegen():
    return SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=SimpleNamespace()),
        cstyle_null_cmp=False,
    )


def test_storage_domain_classifier_distinguishes_variable_domains():
    stack = _decompile._storage_domain_for_variable(_decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000))
    reg = _decompile._storage_domain_for_variable(_decompile.SimRegisterVariable(30, 2, name="v14"))
    mem = _decompile._storage_domain_for_variable(_decompile.SimMemoryVariable(0x2000, 2, name="v15"))

    assert stack == _decompile._StorageDomainSignature("stack", 2, _decompile._StorageView(0, 16))
    assert reg == _decompile._StorageDomainSignature("register", 2, _decompile._StorageView(0, 16))
    assert mem == _decompile._StorageDomainSignature("memory", 2, _decompile._StorageView(0, 16))


def test_storage_domain_classifier_distinguishes_subregister_widths():
    assert _decompile._storage_domain_for_variable(_decompile.SimRegisterVariable(30, 1, name="al")).view == _decompile._StorageView(0, 8)
    assert _decompile._storage_domain_for_variable(_decompile.SimRegisterVariable(30, 2, name="ax")).view == _decompile._StorageView(0, 16)


def test_storage_domain_classifier_marks_mixed_expressions():
    codegen = _make_codegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    reg_var = _decompile.SimRegisterVariable(30, 2, name="v14")
    stack_expr = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    reg_expr = _decompile.structured_c.CVariable(reg_var, codegen=codegen)

    pure_stack = _decompile.structured_c.CBinaryOp(
        "Add",
        stack_expr,
        _decompile.structured_c.CConstant(2, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    mixed = _decompile.structured_c.CBinaryOp("Add", stack_expr, reg_expr, codegen=codegen)

    assert _decompile._storage_domain_for_expr(pure_stack) == _decompile._StorageDomainSignature("stack", 2, _decompile._StorageView(0, 16))
    assert _decompile._storage_domain_for_expr(mixed) == _decompile._StorageDomainSignature("mixed")


def test_copy_alias_state_stops_mixed_domain_inlining():
    plain = _decompile._CopyAliasState(_decompile._StorageDomainSignature("register", 2), object())
    mixed = _decompile._CopyAliasState(_decompile._StorageDomainSignature("mixed"), object(), needs_synthesis=True)

    assert plain.can_inline()
    assert not mixed.can_inline()
    assert str(plain.domain) == "register:2"


def test_stack_pointer_alias_state_tracks_base_and_offset():
    codegen = _make_codegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    cvar = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    state = _decompile._StackPointerAliasState(cvar, 6)

    shifted = state.shifted(-2)

    assert shifted.base is cvar
    assert shifted.offset == 4
