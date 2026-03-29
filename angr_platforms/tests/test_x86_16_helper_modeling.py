from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
import sys

from angr.sim_type import SimStruct, SimTypeShort


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


def test_interrupt_service_table_names_cover_common_bios_vectors():
    call_12 = _decompile.InterruptCall(insn_addr=0x1000, vector=0x12)
    call_13 = _decompile.InterruptCall(insn_addr=0x1002, vector=0x13)
    call_1a = _decompile.InterruptCall(insn_addr=0x1004, vector=0x1A)

    assert _decompile.interrupt_service_name(call_12, "pseudo") == "bios_memsize"
    assert _decompile.interrupt_service_name(call_12, "dos") == "_bios_memsize"
    assert _decompile.interrupt_service_name(call_13, "pseudo") == "bios_int13_disk"
    assert _decompile.interrupt_service_name(call_13, "dos") == "_bios_disk"
    assert _decompile.interrupt_service_name(call_1a, "pseudo") == "bios_timeofday"
    assert _decompile.interrupt_service_name(call_1a, "dos") == "_bios_timeofday"


def test_interrupt_service_renderer_uses_table_driven_names():
    call_12 = _decompile.InterruptCall(insn_addr=0x1000, vector=0x12)
    call_13 = _decompile.InterruptCall(insn_addr=0x1002, vector=0x13)

    assert _decompile.render_interrupt_call(call_12, "pseudo") == "bios_memsize()"
    assert _decompile.render_interrupt_call(call_12, "dos") == "_bios_memsize()"
    assert _decompile.render_interrupt_call(call_13, "pseudo") == "bios_int13_disk()"
    assert _decompile.render_interrupt_call(call_13, "dos") == "_bios_disk()"


def test_interrupt_wrapper_callees_are_classified_and_canonicalized(monkeypatch):
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1234, statements=SimpleNamespace()),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )
    project = SimpleNamespace()
    callee_func = SimpleNamespace(name="_int86x")
    call = _decompile.structured_c.CFunctionCall(
        "int86x",
        callee_func,
        [object(), object(), object(), object()],
        codegen=codegen,
    )

    monkeypatch.setattr(_decompile, "_iter_c_nodes", lambda _node: [call])

    changed = _decompile._attach_interrupt_wrapper_callees(project, codegen, "pseudo")

    assert changed
    assert callee_func.name == "int86x"
    cache_entry = project._inertia_interrupt_wrappers[0x1234]
    assert [item.canonical_name for item in cache_entry["calls"]] == ["int86x"]
    assert cache_entry["calls"][0].vector_arg is not None


def test_interrupt_wrapper_field_paths_capture_regs_subfields():
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    x_struct = SimStruct({"ax": SimTypeShort()}, name="REGS_X")
    regs_struct = SimStruct({"h": h_struct, "x": x_struct}, name="REGS")
    base_var = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(0, 2, base="bp", name="inregs", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )
    h_field = _decompile.structured_c.CStructField(regs_struct, 0, "h", codegen=codegen)
    ah_field = _decompile.structured_c.CStructField(h_struct, 0, "ah", codegen=codegen)
    first = _decompile.structured_c.CVariableField(base_var, h_field, codegen=codegen)
    second = _decompile.structured_c.CVariableField(first, ah_field, codegen=codegen)

    access = _decompile._interrupt_wrapper_field_path(second)
    assert access is not None
    assert access.base_name == "inregs"
    assert access.field_path == ("h", "ah")
