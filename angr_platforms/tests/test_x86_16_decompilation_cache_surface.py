import os
from pathlib import Path

import inertia_decompiler.cache as cache_module
from inertia_decompiler.cache import DECOMPILATION_CACHE_SOURCE_FILES, _cache_file_fingerprint


def test_decompilation_cache_surface_includes_tail_validation_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "tail_validation.py" in names
    assert "tail_validation_condition_context.py" in names
    assert "tail_validation_fingerprint.py" in names
    assert "tail_validation_routing.py" in names


def test_decompilation_cache_surface_includes_condition_and_induction_rewrite_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "callsite_prototype_declarations.py" in names
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


def test_function_cache_key_reuses_equivalent_binary_at_different_paths(tmp_path: Path):
    first_path = tmp_path / "first" / "SORTD.EXE"
    second_path = tmp_path / "second" / "SORTD.EXE"
    first_path.parent.mkdir()
    second_path.parent.mkdir()
    first_path.write_bytes(b"same-binary")
    second_path.write_bytes(b"same-binary")

    key_args = {
        "function_addr": 0x102E0,
        "function_name": "sub_102e0",
        "api_style": "pascal",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }
    first_key = cache_module._function_decompilation_cache_key(binary_path=first_path, **key_args)
    second_key = cache_module._function_decompilation_cache_key(binary_path=second_path, **key_args)

    assert first_key == second_key


def test_cache_json_store_replaces_final_path_atomically(monkeypatch, tmp_path: Path):
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", cache_dir)
    replacements: list[tuple[Path, Path]] = []
    original_replace = cache_module.os.replace

    def record_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        replacements.append((Path(source), Path(destination)))
        original_replace(source, destination)

    monkeypatch.setattr(cache_module.os, "replace", record_replace)
    key = {"binary": "SORTD.EXE", "addr": 0x10060}

    cache_module._store_cache_json("function_decompile", key, {"status": "ok", "payload": "return 0;"})

    assert len(replacements) == 1
    source, destination = replacements[0]
    assert destination == cache_module._cache_json_path("function_decompile", key)
    assert source.parent == destination.parent
    assert not source.exists()
    assert cache_module._load_cache_json("function_decompile", key) == {"status": "ok", "payload": "return 0;"}
