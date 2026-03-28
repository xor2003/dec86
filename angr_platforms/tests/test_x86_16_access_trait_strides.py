from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

_access_trait_member_candidates = _decompile._access_trait_member_candidates
_build_access_trait_evidence_profiles = _decompile._build_access_trait_evidence_profiles


def test_access_trait_profiles_keep_member_array_and_induction_lanes_distinct():
    traits = {
        "base_const": {
            ("ss", ("reg", 30), 4, 2): 5,
        },
        "base_stride": {
            ("ss", ("reg", 30), 16, 0, 2): 4,
        },
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {
            (("reg", 30), 16, 0, 2): 3,
        },
        "member_evidence": {},
        "array_evidence": {},
    }

    profiles = _build_access_trait_evidence_profiles(traits)

    assert profiles == {
        ("reg", 30): _decompile._AccessTraitEvidenceProfile(
            member_like=((4, 2, 5),),
            array_like=((0, 2, 4),),
            induction_like=((0, 2, 3),),
        )
    }


def test_access_trait_stride_evidence_feeds_member_candidates():
    traits = {
        "base_const": {},
        "base_stride": {
            ("ss", ("reg", 30), 16, 0, 2): 4,
        },
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }

    candidates = _access_trait_member_candidates(traits)

    assert candidates == {("reg", 30): [(0, 2, 4)]}


def test_access_trait_induction_evidence_feeds_member_candidates():
    traits = {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {
            (("reg", 30), 16, 0, 2): 3,
        },
        "member_evidence": {},
        "array_evidence": {},
    }

    candidates = _access_trait_member_candidates(traits)

    assert candidates == {("reg", 30): [(0, 2, 3)]}
