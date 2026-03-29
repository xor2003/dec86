from angr_platforms.X86_16.validation_manifest import (
    VALIDATION_FAMILIES,
    VALIDATION_LAYERS,
    describe_x86_16_validation_families,
    describe_x86_16_validation_layers,
)


def test_x86_16_validation_layers_cover_three_tier_discipline():
    assert [layer.name for layer in VALIDATION_LAYERS] == ["unit", "focused_corpus", "whole_program"]
    assert describe_x86_16_validation_layers() == tuple((layer.name, layer.default_checks) for layer in VALIDATION_LAYERS)


def test_x86_16_validation_layers_pin_expected_focus_checks():
    unit, focused, whole_program = VALIDATION_LAYERS

    assert "tests/test_x86_16_alias_register_mvp.py" in unit.default_checks
    assert "tests/test_x86_16_widening_model.py" in unit.default_checks
    assert "tests/test_x86_16_validation_manifest.py" in unit.default_checks
    assert "tests/test_x86_16_sample_matrix.py" in focused.default_checks
    assert "scripts/scan_cod_dir.py --mode scan-safe" in whole_program.default_checks


def test_x86_16_validation_families_cover_key_instruction_core_slices():
    assert [family.name for family in VALIDATION_FAMILIES] == [
        "addressing",
        "stack_control",
        "string",
        "alu",
        "interrupt_api",
    ]
    assert describe_x86_16_validation_families() == tuple(
        (family.name, family.default_checks) for family in VALIDATION_FAMILIES
    )
    assert "tests/test_x86_16_addressing_helpers.py" in VALIDATION_FAMILIES[0].default_checks
    assert "tests/test_x86_16_stack_helpers.py" in VALIDATION_FAMILIES[1].default_checks
    assert "tests/test_x86_16_string_helpers.py" in VALIDATION_FAMILIES[2].default_checks
    assert "tests/test_x86_16_alu_helpers.py" in VALIDATION_FAMILIES[3].default_checks
    assert "tests/test_x86_16_milestone_report.py" in VALIDATION_FAMILIES[4].default_checks
