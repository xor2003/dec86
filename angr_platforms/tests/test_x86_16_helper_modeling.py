from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)


def test_dos_pseudo_callee_attachment_accepts_partial_callnode_matches(monkeypatch):
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            statements=SimpleNamespace(),
        )
    )
    codegen.project = SimpleNamespace(arch=_decompile.Arch86_16())
    codegen.next_idx = lambda _name: 1

    first = _decompile.structured_c.CFunctionCall(None, None, [], codegen=codegen)
    second = _decompile.structured_c.CFunctionCall(None, None, [], codegen=codegen)

    fake_helper = SimpleNamespace(name="dos_int21", prototype=None)
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr: fake_helper if addr == 0x2000 else None))
    )
    function = SimpleNamespace(get_call_target=lambda _addr: 0x2000)

    monkeypatch.setattr(_decompile, "collect_dos_int21_calls", lambda _function: [SimpleNamespace(insn_addr=0x1234)])
    monkeypatch.setattr(_decompile, "_iter_c_nodes", lambda _node: [first, second])

    changed = _decompile._attach_dos_pseudo_callees(project, function, codegen, "pseudo")

    assert changed
    assert first.callee_func is fake_helper
    assert second.callee_func is None
