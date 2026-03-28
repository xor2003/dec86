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

from angr_platforms.X86_16.alias_domains import FULL16, HIGH8, LOW8, AX, register_domain_for_name, register_offset_for_name, register_pair_name, register_view_for_name
from angr_platforms.X86_16.alias_state import AliasState
from angr_platforms.X86_16.alias_transfer import RegisterConcatExpr, RegisterSliceExpr, read_register, write_register
from angr_platforms.X86_16.widening_alias import RegisterWideningCandidate, can_join_adjacent_register_slices


def _make_codegen():
    return SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=SimpleNamespace(registers={"ax": (0, 2), "bx": (6, 2), "cx": (2, 2), "dx": (4, 2)})),
        cstyle_null_cmp=False,
    )


def _make_reg_var(name: str, reg: int, size: int = 1):
    codegen = _make_codegen()
    return _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(reg, size, name=name),
        codegen=codegen,
    )


def test_register_alias_domains_cover_ax_al_ah():
    assert register_domain_for_name("al") == AX
    assert register_domain_for_name("ah") == AX
    assert register_view_for_name("al") == LOW8
    assert register_view_for_name("ah") == HIGH8
    assert register_view_for_name("ax") == FULL16
    assert register_pair_name("al") == "ax"
    assert register_offset_for_name("ax") == 0


def test_register_alias_state_round_trips_full_write_and_slice_reads():
    state = AliasState()
    token = object()

    write_register(state, "ax", token)

    assert read_register(state, "ax") is token
    assert isinstance(read_register(state, "al"), RegisterSliceExpr)
    assert isinstance(read_register(state, "ah"), RegisterSliceExpr)
    assert state.get(AX, FULL16).expr is token


def test_register_alias_state_marks_full_value_needs_synthesis_after_partial_overwrite():
    state = AliasState()
    seed = object()

    write_register(state, "ax", seed)
    write_register(state, "al", 0x56)

    full = state.get(AX, FULL16)
    assert full is not None and full.needs_synthesis

    synthesized = read_register(state, "ax")
    assert isinstance(synthesized, RegisterConcatExpr)
    assert synthesized.low == 0x56
    assert synthesized.high is not None


def test_register_widening_candidate_requires_same_domain_and_adjacent_views():
    low = _make_reg_var("al", 0)
    high = _make_reg_var("ah", 1)
    far = _make_reg_var("bh", 7)

    low_candidate = RegisterWideningCandidate.from_expr(low)
    high_candidate = RegisterWideningCandidate.from_expr(high)
    far_candidate = RegisterWideningCandidate.from_expr(far)

    assert low_candidate.is_joinable_with(high_candidate)
    assert not low_candidate.is_joinable_with(far_candidate)
    assert can_join_adjacent_register_slices(low, high)
    assert not can_join_adjacent_register_slices(low, far)


def test_register_pair_cleanup_helper_rebuilds_ax_from_al_and_ah():
    codegen = _make_codegen()
    low = _decompile.structured_c.CVariable(_decompile.SimRegisterVariable(0, 1, name="al"), codegen=codegen)
    high_base = _decompile.structured_c.CVariable(_decompile.SimRegisterVariable(1, 1, name="ah"), codegen=codegen)
    high = _decompile.structured_c.CBinaryOp(
        "Shl",
        high_base,
        _decompile.structured_c.CConstant(8, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    widened = _decompile._match_adjacent_register_pair_var_expr(low, high, codegen)

    assert widened is not None
    assert isinstance(widened.variable, _decompile.SimRegisterVariable)
    assert widened.variable.size == 2
    assert widened.variable.name == "ax"
