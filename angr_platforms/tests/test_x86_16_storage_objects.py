from inertia_decompiler.cli_access_object_hints import (
    AccessTraitObjectHint,
    _build_stable_access_object_hints,
)
from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles
from inertia_decompiler.cli_storage_objects import (
    build_storage_object_artifact,
    build_storage_object_records_from_hints,
    storage_object_record_for_key,
)


def test_storage_object_records_preserve_member_offsets_deterministically():
    records = build_storage_object_records_from_hints(
        {
            ("mem", 0x40): AccessTraitObjectHint(
                base_key=("mem", 0x40),
                kind="member",
                candidates=((4, 2, 5), (4, 2, 9), (8, 2, 3)),
            )
        }
    )

    record = records[("mem", 0x40)]
    assert record.object_kind == "member"
    assert record.candidate_offsets == (4, 8)
    assert record.primary_member_offset() == 4


def test_storage_object_record_for_key_supports_regioned_stack_fallback():
    records = build_storage_object_records_from_hints(
        {
            ("stack", "bp", -4): AccessTraitObjectHint(
                base_key=("stack", "bp", -4),
                kind="stack",
                candidates=((0, 2, 1),),
            )
        }
    )

    record = storage_object_record_for_key(records, ("stack", "bp", -4, 0x1000))

    assert record is not None
    assert record.object_kind == "stack"
    assert record.should_rename_stack() is True


def test_storage_object_artifact_records_refusal_for_mixed_evidence():
    traits = {
        "base_const": {
            ("ss", ("stack", "bp", -4), 4, 2, 1): 1,
        },
        "array_evidence": {
            (("stack", "bp", -4), ("reg", 2), 2, 4, 2): 1,
        },
    }

    artifact = build_storage_object_artifact(
        traits,
        build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        build_stable_access_object_hints=lambda raw_traits: _build_stable_access_object_hints(
            raw_traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        ),
    )

    assert artifact.records == {}
    assert artifact.refusals[("stack", "bp", -4)].reason == "mixed_or_unstable_evidence"
