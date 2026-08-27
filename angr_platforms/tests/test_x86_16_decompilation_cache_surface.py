import os
from pathlib import Path

import pytest

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
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "sub_102e0",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }
    first_key = cache_module._function_decompilation_cache_key(binary_path=first_path, **key_args)
    second_key = cache_module._function_decompilation_cache_key(binary_path=second_path, **key_args)

    assert first_key == second_key


def test_function_cache_key_separates_semantic_runtime_modes(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }

    monkeypatch.delenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", raising=False)
    normal_key = cache_module._function_decompilation_cache_key(**key_args)
    monkeypatch.setenv("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS", "1")
    typed_switch_key = cache_module._function_decompilation_cache_key(**key_args)

    assert normal_key is not None
    assert typed_switch_key is not None
    assert normal_key != typed_switch_key


def test_function_cache_key_ignores_non_semantic_runtime_environment(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }
    monkeypatch.setenv("INERTIA_SERIAL_CLEAN_WORKER_RESULT", str(tmp_path / "first.json"))
    monkeypatch.setenv("INERTIA_ARCH_GUARD_VERIFIED_PARENT_PID", "100")
    monkeypatch.setenv("INERTIA_ALLOW_PARALLEL_MSC6_WORKERS", "0")
    monkeypatch.setenv("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", "1.5")
    monkeypatch.setenv("INERTIA_OTEL_EXPORT_OTLP", "0")
    monkeypatch.setenv("INERTIA_DISABLE_TIMING", "0")
    first_key = cache_module._function_decompilation_cache_key(**key_args)
    monkeypatch.setenv("INERTIA_SERIAL_CLEAN_WORKER_RESULT", str(tmp_path / "second.json"))
    monkeypatch.setenv("INERTIA_ARCH_GUARD_VERIFIED_PARENT_PID", "200")
    monkeypatch.setenv("INERTIA_ALLOW_PARALLEL_MSC6_WORKERS", "1")
    monkeypatch.setenv("INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE", "4")
    monkeypatch.setenv("INERTIA_OTEL_EXPORT_OTLP", "1")
    monkeypatch.setenv("INERTIA_DISABLE_TIMING", "1")
    second_key = cache_module._function_decompilation_cache_key(**key_args)

    assert first_key is not None
    assert second_key is not None
    assert first_key == second_key


def test_function_cache_key_ignores_sidecar_flag_only_without_sidecar_evidence(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }

    monkeypatch.delenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", raising=False)
    no_sidecar_default_key = cache_module._function_decompilation_cache_key(**key_args)
    monkeypatch.setenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", "1")
    no_sidecar_ignored_key = cache_module._function_decompilation_cache_key(**key_args)

    assert no_sidecar_default_key == no_sidecar_ignored_key

    binary.with_suffix(".COD").write_text("sidecar evidence", encoding="ascii")
    sidecar_ignored_key = cache_module._function_decompilation_cache_key(**key_args)
    monkeypatch.delenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616")
    sidecar_default_key = cache_module._function_decompilation_cache_key(**key_args)

    assert sidecar_ignored_key is not None
    assert sidecar_default_key is not None
    assert sidecar_ignored_key != sidecar_default_key


def test_recovery_cache_key_ignores_sidecar_flag_only_without_sidecars(monkeypatch, tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")

    monkeypatch.delenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", raising=False)
    no_sidecar_default_key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="direct_addr_work",
        extra={"addr": 0x102E0, "ignore_local_sidecar_hints": False},
    )
    monkeypatch.setenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", "1")
    no_sidecar_ignored_key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="direct_addr_work",
        extra={"addr": 0x102E0, "ignore_local_sidecar_hints": True},
    )

    assert no_sidecar_default_key == no_sidecar_ignored_key

    binary.with_suffix(".COD").write_text("sidecar evidence", encoding="ascii")
    sidecar_ignored_key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="direct_addr_work",
        extra={"addr": 0x102E0, "ignore_local_sidecar_hints": True},
    )
    monkeypatch.delenv("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616")
    sidecar_default_key = cache_module._recovery_cache_key(
        binary_path=binary,
        kind="direct_addr_work",
        extra={"addr": 0x102E0, "ignore_local_sidecar_hints": False},
    )

    assert sidecar_ignored_key is not None
    assert sidecar_default_key is not None
    assert sidecar_ignored_key != sidecar_default_key


def test_function_cache_key_separates_compiler_targets(tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x102E0,
        "active_function_addr": 0x102E0,
        "recovery_addr": None,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "sidecar_metadata_digest": None,
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }

    portable_key = cache_module._function_decompilation_cache_key(c_target="portable-flat", **key_args)
    msc_key = cache_module._function_decompilation_cache_key(c_target="msc-dos", **key_args)

    assert portable_key is not None
    assert msc_key is not None
    assert portable_key != msc_key


def test_function_cache_key_separates_recovery_and_sidecar_identity(tmp_path: Path):
    binary = tmp_path / "SORTD.EXE"
    binary.write_bytes(b"same-binary")
    key_args = {
        "binary_path": binary,
        "function_addr": 0x11000,
        "active_function_addr": 0x1000,
        "function_name": "RunMenu",
        "api_style": "pascal",
        "c_target": "portable-flat",
        "recovery_shape_digest": "shape",
        "annotation_evidence_digest": "annotations",
        "project_evidence_digest": "project",
        "enable_structured_simplify": True,
        "enable_postprocess": True,
    }

    base_key = cache_module._function_decompilation_cache_key(
        recovery_addr=0x11000,
        sidecar_metadata_digest=None,
        **key_args,
    )
    different_recovery_key = cache_module._function_decompilation_cache_key(
        recovery_addr=0x11010,
        sidecar_metadata_digest=None,
        **key_args,
    )
    sidecar_key = cache_module._function_decompilation_cache_key(
        recovery_addr=0x11000,
        sidecar_metadata_digest="metadata-sha256",
        **key_args,
    )

    assert base_key is not None
    assert different_recovery_key is not None
    assert sidecar_key is not None
    assert base_key != different_recovery_key
    assert base_key != sidecar_key


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


def test_cache_key_lock_is_removed_after_producer_finishes(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    key = {"binary": "SORTD.EXE", "addr": 0x102E0}
    lock_path = cache_module._cache_json_path("function_decompile", key).with_suffix(".lock")

    with cache_module._cache_key_lock("function_decompile", key):
        assert lock_path.exists()
    assert not lock_path.exists()

    with cache_module._cache_key_lock("function_decompile", key):
        assert lock_path.exists()


def test_cache_key_lock_times_out_when_another_producer_holds_it(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cache_module, "DECOMPILATION_CACHE_DIR", tmp_path / "cache")
    key = {"binary": "SORTD.EXE", "addr": 0x102E0}
    lock_path = cache_module._cache_json_path("function_decompile", key).with_suffix(".lock")
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text("other-process\n", encoding="ascii")

    with pytest.raises(TimeoutError, match="cache key lock"):  # noqa: SIM117
        with cache_module._cache_key_lock("function_decompile", key, timeout_seconds=0.1):
            raise AssertionError("lock unexpectedly acquired")
