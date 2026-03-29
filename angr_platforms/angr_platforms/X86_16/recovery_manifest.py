from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryLayerSpec:
    name: str
    purpose: str
    helpers: tuple[str, ...]


RECOVERY_LAYERS: tuple[RecoveryLayerSpec, ...] = (
    RecoveryLayerSpec(
        name="member_and_array_recovery",
        purpose="Turn repeated offsets and stride evidence into fields and arrays.",
        helpers=(
            "describe_x86_16_alias_recovery_api",
            "describe_x86_16_widening_pipeline",
            "x86_16_decompiler_readability.md",
        ),
    ),
    RecoveryLayerSpec(
        name="stable_stack_object_recovery",
        purpose="Turn stack-slot identity into locals and arguments with stable widths.",
        helpers=(
            "_stack_slot_identity_for_variable",
            "_same_stack_slot_identity",
            "annotate_stack_variable",
            "annotate_bp_stack_variable",
        ),
    ),
    RecoveryLayerSpec(
        name="stable_global_object_recovery",
        purpose="Keep global typing and object recovery width-stable and evidence-driven.",
        helpers=(
            "annotate_global_variable",
            "_apply_word_global_types_8616",
            "_coalesce_word_global_loads_8616",
            "_coalesce_word_global_constant_stores_8616",
        ),
    ),
    RecoveryLayerSpec(
        name="trait_to_type_handoff",
        purpose="Move from trait evidence profiles to downstream type and object decisions explicitly.",
        helpers=(
            "describe_x86_16_alias_recovery_api",
            "describe_x86_16_widening_pipeline",
            "describe_x86_16_decompiler_postprocess_stage",
        ),
    ),
    RecoveryLayerSpec(
        name="prototype_evidence_layer",
        purpose="Unify stack args, returns, helper calls, and far/near class evidence.",
        helpers=(
            "seed_calling_conventions",
            "_promote_stack_prototype_from_bp_loads_8616",
            "apply_x86_16_decompiler_return_compatibility",
        ),
    ),
    RecoveryLayerSpec(
        name="far_near_prototype_recovery",
        purpose="Keep far/near call signatures stable and output-visible.",
        helpers=(
            "extend_cfg_for_far_calls",
            "seed_calling_conventions",
            "describe_x86_16_decompiler_return_compatibility",
        ),
    ),
)


def describe_x86_16_recovery_layers() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    return tuple((layer.name, layer.purpose, layer.helpers) for layer in RECOVERY_LAYERS)


__all__ = ["RECOVERY_LAYERS", "RecoveryLayerSpec", "describe_x86_16_recovery_layers"]
