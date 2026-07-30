import os
from pathlib import Path

from inertia_decompiler.cache import DECOMPILATION_CACHE_SOURCE_FILES, _cache_file_fingerprint


def test_decompilation_cache_surface_includes_tail_validation_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "tail_validation.py" in names
    assert "tail_validation_condition_context.py" in names
    assert "tail_validation_fingerprint.py" in names
    assert "tail_validation_routing.py" in names


def test_decompilation_cache_surface_includes_condition_and_induction_rewrite_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "cli_decompilation.py" in names
    assert "condition_ir.py" in names
    assert "decompiler_postprocess_flags.py" in names
    assert "decompiler_postprocess_jcc.py" in names
    assert "decompiler_postprocess_stage.py" in names
    assert "type_array_matching.py" in names
    assert "cli_access_object_hints.py" in names
    assert "cli_access_profiles.py" in names
    assert "cli_access_traits.py" in names


def test_decompilation_cache_surface_includes_postprocess_optimization_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "const_prop.py" in names
    assert "dce.py" in names
    assert "dead_setup.py" in names
    assert "pass_driver.py" in names
    assert "decompiler_postprocess_typed_conditions.py" in names
    assert "decompiler_postprocess_utils.py" in names
    assert "segmented_memory_reasoning.py" in names


def test_binary_cache_fingerprint_changes_for_same_size_and_mtime_content(tmp_path: Path):
    binary = tmp_path / "ARGS.EXE"
    binary.write_bytes(b"first-content")
    original_stat = binary.stat()
    first = _cache_file_fingerprint(binary)

    binary.write_bytes(b"other-content")
    os.utime(binary, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    second = _cache_file_fingerprint(binary)

    assert first is not None
    assert second is not None
    assert first["size"] == second["size"]
    assert first["mtime_ns"] == second["mtime_ns"]
    assert first["sha256"] != second["sha256"]
