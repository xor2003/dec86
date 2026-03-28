from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable


REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

from angr_platforms.X86_16 import decompiler_postprocess as postprocess


class _FakePrototype:
    def __init__(self):
        self.args = [SimTypeShort(False)]
        self.returnty = SimTypeLong()
        self.arg_names = ("a0",)
        self.variadic = False


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
    monkeypatch.setattr(postprocess, "_match_bp_stack_load_8616", lambda node, _project: 4 if node is fake_nodes[0] else 6)

    assert not postprocess._promote_stack_prototype_from_bp_loads_8616(project, codegen)
