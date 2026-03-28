from angr_platforms.X86_16.validation_manifest import VALIDATION_LAYERS, describe_x86_16_validation_layers


def test_x86_16_validation_layers_cover_three_tier_discipline():
    assert [layer.name for layer in VALIDATION_LAYERS] == ["unit", "focused_corpus", "whole_program"]
    assert describe_x86_16_validation_layers() == tuple((layer.name, layer.default_checks) for layer in VALIDATION_LAYERS)


def test_x86_16_validation_layers_pin_expected_focus_checks():
    unit, focused, whole_program = VALIDATION_LAYERS

    assert "tests/test_x86_16_alias_register_mvp.py" in unit.default_checks
    assert "tests/test_x86_16_widening_model.py" in unit.default_checks
    assert "tests/test_x86_16_sample_matrix.py" in focused.default_checks
    assert "scripts/scan_cod_dir.py --mode scan-safe" in whole_program.default_checks
