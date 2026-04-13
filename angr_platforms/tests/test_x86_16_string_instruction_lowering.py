from __future__ import annotations

from angr_platforms.X86_16.string_instruction_artifact import (
    StringInstructionArtifact,
    StringInstructionRecord,
    StringInstructionRefusal,
)
from angr_platforms.X86_16.string_instruction_lowering import (
    build_x86_16_string_intrinsic_artifact,
    render_x86_16_string_intrinsic_c,
)


def _record(
    *,
    index: int,
    family: str,
    repeat_kind: str,
    width: int,
    direction_mode: str = "forward",
    zero_seeded_accumulator: bool | None = None,
) -> StringInstructionRecord:
    return StringInstructionRecord(
        index=index,
        family=family,
        mnemonic=family,
        repeat_kind=repeat_kind,
        width=width,
        source_segment="ds" if family in {"movs", "lods", "cmps"} else None,
        destination_segment="es" if family in {"movs", "stos", "scas", "cmps"} else None,
        direction_mode=direction_mode,
        zero_seeded_accumulator=zero_seeded_accumulator,
        zf_sensitive=family in {"scas", "cmps"},
    )


def test_string_instruction_lowering_accepts_rep_movs_as_memcpy_class():
    artifact = StringInstructionArtifact(records=(_record(index=0, family="movs", repeat_kind="rep", width=1),))

    lowered = build_x86_16_string_intrinsic_artifact(artifact)

    assert tuple(item.family for item in lowered.records) == ("memcpy_class",)


def test_string_instruction_lowering_accepts_repne_scas_zero_seed_as_strlen_class():
    artifact = StringInstructionArtifact(
        records=(_record(index=0, family="scas", repeat_kind="repnz", width=1, zero_seeded_accumulator=True),)
    )

    lowered = build_x86_16_string_intrinsic_artifact(artifact)

    assert tuple(item.family for item in lowered.records) == ("strlen_class",)
    assert "__x86_16_scas_zterm_len" in render_x86_16_string_intrinsic_c("strlen_like", lowered)


def test_string_instruction_lowering_combines_strlen_then_movs_into_strlen_copy_class():
    artifact = StringInstructionArtifact(
        records=(
            _record(index=0, family="scas", repeat_kind="repnz", width=1, zero_seeded_accumulator=True),
            _record(index=1, family="movs", repeat_kind="rep", width=1),
        )
    )

    lowered = build_x86_16_string_intrinsic_artifact(artifact)
    rendered = render_x86_16_string_intrinsic_c("strcpy_like", lowered)

    assert tuple(item.family for item in lowered.records) == ("strlen_copy_class",)
    assert "__x86_16_scas_zterm_len" in rendered
    assert "__x86_16_movs(&__x86_16_state, 1);" in rendered


def test_string_instruction_lowering_preserves_explicit_refusal_state():
    artifact = StringInstructionArtifact(
        records=(_record(index=0, family="movs", repeat_kind="rep", width=1),),
        refusals=(StringInstructionRefusal("mixed_direction_signal", "both directions observed"),),
    )

    lowered = build_x86_16_string_intrinsic_artifact(artifact)

    assert lowered.records == ()
    assert tuple(item.kind for item in lowered.refusals) == ("mixed_direction_signal",)
