from angr_platforms.X86_16.recovery_manifest import RECOVERY_LAYERS, describe_x86_16_recovery_layers


def test_x86_16_recovery_layers_cover_current_recovery_boundary():
    assert [layer.name for layer in RECOVERY_LAYERS] == [
        "member_and_array_recovery",
        "stable_stack_object_recovery",
        "stable_global_object_recovery",
        "trait_to_type_handoff",
        "prototype_evidence_layer",
        "far_near_prototype_recovery",
    ]
    assert describe_x86_16_recovery_layers() == tuple((layer.name, layer.purpose, layer.helpers) for layer in RECOVERY_LAYERS)


def test_x86_16_recovery_layers_pin_existing_helpers():
    stack = RECOVERY_LAYERS[1]
    proto = RECOVERY_LAYERS[4]

    assert "_stack_slot_identity_for_variable" in stack.helpers
    assert "annotate_bp_stack_variable" in stack.helpers
    assert "seed_calling_conventions" in proto.helpers
    assert "apply_x86_16_decompiler_return_compatibility" in proto.helpers
