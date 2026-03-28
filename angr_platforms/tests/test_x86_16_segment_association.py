from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
from types import SimpleNamespace

import archinfo


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
        project=SimpleNamespace(arch=archinfo.ArchX86()),
        cstyle_null_cmp=False,
    )


def _make_segmented_expr(stack_vars, *, offset=0):
    codegen = _make_codegen()
    es_reg = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(
            codegen.project.arch.registers["es"][0],
            2,
            name="es",
        ),
        codegen=codegen,
    )
    seg_part = _decompile.structured_c.CBinaryOp(
        "Mul",
        es_reg,
        _decompile.structured_c.CConstant(16, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    expr = seg_part
    for stack_var in stack_vars:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CVariable(stack_var, codegen=codegen),
            codegen=codegen,
        )
    if offset:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CConstant(offset, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return expr


def test_segmented_access_classifier_marks_single_stack_base_as_single():
    codegen = _make_codegen()
    project = codegen.project
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    expr = _make_segmented_expr([stack_var], offset=2)

    classified = _decompile._classify_segmented_addr_expr(expr, project)

    assert classified is not None
    assert classified.seg_name == "es"
    assert classified.assoc_kind == "single"
    assert classified.extra_offset == 2


def test_segmented_access_classifier_marks_multiple_stack_bases_as_over():
    codegen = _make_codegen()
    project = codegen.project
    first = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    second = _decompile.SimStackVariable(-8, 2, base="bp", name="v2", region=0x1000)
    expr = _make_segmented_expr([first, second])

    classified = _decompile._classify_segmented_addr_expr(expr, project)

    assert classified is not None
    assert classified.seg_name == "es"
    assert classified.assoc_kind == "over"
