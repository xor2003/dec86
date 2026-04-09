from importlib.util import module_from_spec, spec_from_file_location
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
import json
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "decompile_cod_dir.py"

_spec = spec_from_file_location("decompile_cod_dir", SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
_script = module_from_spec(_spec)
sys.modules[_spec.name] = _script
_spec.loader.exec_module(_script)


def test_choose_parallelism_caps_to_a_small_multi_core_pool(monkeypatch):
    monkeypatch.setattr(_script.os, "cpu_count", lambda: 12)
    monkeypatch.setattr(_script, "_mem_available_mb", lambda: 128_000)

    assert _script._choose_parallelism(100, 16_000, 8) == 3


def test_choose_parallelism_stays_single_worker_for_tight_memory(monkeypatch):
    monkeypatch.setattr(_script.os, "cpu_count", lambda: 12)
    monkeypatch.setattr(_script, "_mem_available_mb", lambda: 1_800)

    assert _script._choose_parallelism(100, 16_000, 8) == 1


def test_worker_failure_formatting_is_deterministic_for_broken_pools():
    item = _script.CodWorkItem(
        cod_path=Path("/tmp/DOSFUNC.COD"),
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    ex = BrokenProcessPool("A process in the process pool was terminated abruptly while the future was running or pending.")

    assert _script._worker_failure_summary(item, ex) == "parent pool breakage while recovering _dos_alloc (NEAR)"
    assert _script._format_worker_failure(item, ex) == (
        "/* parent pool breakage while recovering _dos_alloc (NEAR) */"
    )
    assert "BrokenProcessPool" not in _script._format_worker_failure(item, ex)


def test_describe_returncode_separates_timeout_signal_and_memory_pressure():
    timeout_kind, timeout_detail = _script._describe_returncode(
        3,
        "/* Timed out while recovering a function after 20s. */\n",
        "",
    )
    signal_kind, signal_detail = _script._describe_returncode(-9, "", "")
    rlimit_kind, rlimit_detail = _script._describe_returncode(
        1,
        "",
        "MemoryError: unable to allocate arena",
    )

    assert timeout_kind == "timeout"
    assert "timeout" in timeout_detail
    assert signal_kind == "signal_termination"
    assert "SIGKILL" in signal_detail
    assert rlimit_kind == "rlimit_kill"
    assert "memory pressure" in rlimit_detail


def test_render_result_block_records_exit_kind_and_detail(tmp_path):
    stdout_path = tmp_path / "sample.dec.stdout"
    stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
    result = _script.CodWorkResult(
        cod_path=Path("/tmp/DOSFUNC.COD"),
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        stdout_path=stdout_path,
        stderr="MemoryError: unable to allocate arena\n",
        returncode=1,
        exit_kind="rlimit_kill",
        exit_detail="child exited with status 1 after memory pressure",
    )

    rendered = _script._render_result_block(result)

    assert "exit kind" in rendered
    assert "rlimit_kill" in rendered
    assert "memory pressure" in rendered
    assert "exit code" in rendered


def test_run_work_item_preserves_timeout_without_scan_safe_fallback(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    scan_safe_called = False

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        stdout_path.write_text("/* Timed out while recovering a function after 20s. */\n", encoding="utf-8")
        return 3, "", False

    def fake_scan_safe(*_args, **_kwargs):  # noqa: ANN001
        nonlocal scan_safe_called
        scan_safe_called = True
        return None

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", fake_scan_safe)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.exit_kind == "timeout"
    assert scan_safe_called is False
    assert result.scan_safe_result is None
    rendered = _script._render_result_block(result)
    assert "exit kind timeout" in rendered
    assert "Timed out while recovering" in rendered


def test_run_work_item_normalizes_timeout_expired_bytes(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        stdout_path.write_text("stdout bytes\n", encoding="utf-8")
        return None, "stderr bytes\n", True

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.exit_kind == "subprocess_timeout"
    assert result.stderr == "stderr bytes\n"
    rendered = _script._render_result_block(result)
    assert "stderr bytes" in rendered
    assert "bytes found" not in rendered


def test_run_work_item_extracts_tail_validation_metadata_from_stderr(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
        return (
            0,
            (
                "[tail-validation] whole-tail validation clean across 1 functions\n"
                '@@INERTIA_TAIL_VALIDATION@@ {"records":[{"function_addr":4096,"function_name":"_dos_alloc","structuring":{"changed":false},"postprocess":{"changed":false}}],"scanned":1}\n'
            ),
            False,
        )

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.stderr == ""
    assert result.tail_validation_scanned == 1
    assert result.tail_validation_records == (
        {
            "cod_file": "DOSFUNC.COD",
            "function_addr": 4096,
            "function_name": "_dos_alloc",
            "proc_name": "_dos_alloc",
            "proc_kind": "NEAR",
            "structuring": {"changed": False},
            "postprocess": {"changed": False},
        },
    )
    rendered = _script._render_result_block(result)
    assert "tail-validation" not in rendered


def test_run_work_item_reuses_success_only_cache(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    item.cod_path.write_text("cod text", encoding="utf-8")
    calls = {"child": 0}

    monkeypatch.setattr(_script, "_SUCCESS_CACHE_DIR", tmp_path / "success-cache")
    monkeypatch.setattr(_script, "_cache_source_digest", lambda _paths: "digest-a")

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        calls["child"] += 1
        stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
        return (
            0,
            '@@INERTIA_TAIL_VALIDATION@@ {"records":[{"function_name":"_dos_alloc","structuring":{"changed":false},"postprocess":{"changed":false}}],"scanned":1}\n',
            False,
        )

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    first = _script._run_work_item(item, timeout=20, max_memory_mb=1024)
    second = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert calls["child"] == 1
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.exit_kind == "ok"
    assert second.tail_validation_scanned == 1
    assert second.tail_validation_records[0]["proc_name"] == "_dos_alloc"
    rendered = _script._render_result_block(second)
    assert "/* == 2/15 DOSFUNC.COD :: _dos_alloc [NEAR] == */" in rendered
    assert "return 1;" in rendered


def test_run_work_item_does_not_cache_timeout(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    item.cod_path.write_text("cod text", encoding="utf-8")
    calls = {"child": 0}

    monkeypatch.setattr(_script, "_SUCCESS_CACHE_DIR", tmp_path / "success-cache")
    monkeypatch.setattr(_script, "_cache_source_digest", lambda _paths: "digest-a")
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        calls["child"] += 1
        stdout_path.write_text("/* Timed out while recovering a function after 20s. */\n", encoding="utf-8")
        return 3, "", False

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)

    first = _script._run_work_item(item, timeout=20, max_memory_mb=1024)
    second = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert calls["child"] == 2
    assert first.from_cache is False
    assert second.from_cache is False
    assert first.exit_kind == "timeout"
    assert second.exit_kind == "timeout"


def test_run_work_item_does_not_cache_zero_exit_fallback(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    item.cod_path.write_text("cod text", encoding="utf-8")
    calls = {"child": 0}

    monkeypatch.setattr(_script, "_SUCCESS_CACHE_DIR", tmp_path / "success-cache")
    monkeypatch.setattr(_script, "_cache_source_digest", lambda _paths: "digest-a")
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        calls["child"] += 1
        stdout_path.write_text(
            "/* Function recovery timed out; produced non-optimized slice decompilation. */\n"
            "/* == c (non-optimized fallback) == */\n"
            "return 1;\n",
            encoding="utf-8",
        )
        return 0, "", False

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)

    first = _script._run_work_item(item, timeout=20, max_memory_mb=1024)
    second = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert calls["child"] == 2
    assert first.exit_kind == "ok"
    assert second.exit_kind == "ok"
    assert first.from_cache is False
    assert second.from_cache is False


def test_run_work_item_replaces_null_tail_validation_identity(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "COCKPIT.COD",
        proc_name="_DoCRT",
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        code=b"\x90",
    )

    def fake_child(_command, *, stdout_path, **_kwargs):  # noqa: ANN001
        stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
        return (
            0,
            (
                '@@INERTIA_TAIL_VALIDATION@@ {"records":[{'
                '"cod_file":null,"proc_name":null,"proc_kind":null,'
                '"function_addr":4096,"function_name":"_DoCRT",'
                '"structuring":{"changed":false},"postprocess":{"changed":true}'
                '}],"scanned":1}\n'
            ),
            False,
        )

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.tail_validation_scanned == 1
    assert result.tail_validation_records == (
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DoCRT",
            "proc_kind": "NEAR",
            "function_addr": 4096,
            "function_name": "_DoCRT",
            "structuring": {"changed": False},
            "postprocess": {"changed": True},
        },
    )


def test_run_work_item_uses_bounded_child_timeout(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    seen: dict[str, object] = {}

    def fake_child(_command, *, stdout_path, child_timeout, **_kwargs):  # noqa: ANN001
        seen["timeout"] = child_timeout
        stdout_path.write_text("/* == c == */\nreturn 1;\n", encoding="utf-8")
        return 0, "", False

    monkeypatch.setattr(_script, "_run_decompiler_child", fake_child)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: None)

    result = _script._run_work_item(item, timeout=3, max_memory_mb=1024)

    assert result.exit_kind == "ok"
    assert seen["timeout"] == 10


def test_uncollected_tail_validation_record_keeps_proc_identity():
    record = _script._uncollected_tail_validation_record(
        cod_path=Path("/tmp/COCKPIT.COD"),
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        exit_kind="timeout",
        exit_detail="decompiler CLI reported a recovery timeout",
    )

    assert record == {
        "cod_file": "COCKPIT.COD",
        "proc_name": "_DisplayMaster",
        "proc_kind": "NEAR",
        "tail_validation_uncollected": True,
        "exit_kind": "timeout",
        "exit_detail": "decompiler CLI reported a recovery timeout",
    }


def test_empty_tail_validation_metadata_record_becomes_named_uncollected(tmp_path):
    result = _script.CodWorkResult(
        cod_path=tmp_path / "COCKPIT.COD",
        proc_name="_DisplayMaster",
        proc_kind="NEAR",
        proc_index=4,
        proc_total=9,
        stdout_path=tmp_path / "out.txt",
        stderr="",
        returncode=0,
        exit_kind="ok",
        exit_detail="",
        tail_validation_records=(),
        tail_validation_scanned=1,
    )
    records: list[dict[str, object]] = []

    scanned = _script._append_tail_validation_records_for_result(records, result)

    assert scanned == 1
    assert records == [
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DisplayMaster",
            "proc_kind": "NEAR",
            "tail_validation_uncollected": True,
            "exit_kind": "ok",
            "exit_detail": "tail validation metadata omitted record details",
        }
    ]


def test_partial_tail_validation_metadata_adds_named_uncollected_gap(tmp_path):
    result = _script.CodWorkResult(
        cod_path=tmp_path / "COCKPIT.COD",
        proc_name="_DoCRT",
        proc_kind="NEAR",
        proc_index=1,
        proc_total=1,
        stdout_path=tmp_path / "out.txt",
        stderr="",
        returncode=0,
        exit_kind="ok",
        exit_detail="",
        tail_validation_records=(
            {
                "cod_file": "COCKPIT.COD",
                "proc_name": "_DoCRT",
                "proc_kind": "NEAR",
                "postprocess": {"changed": True},
            },
        ),
        tail_validation_scanned=2,
    )
    records: list[dict[str, object]] = []

    scanned = _script._append_tail_validation_records_for_result(records, result)

    assert scanned == 2
    assert records == [
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DoCRT",
            "proc_kind": "NEAR",
            "postprocess": {"changed": True},
        },
        {
            "cod_file": "COCKPIT.COD",
            "proc_name": "_DoCRT",
            "proc_kind": "NEAR",
            "tail_validation_uncollected": True,
            "exit_kind": "ok",
            "exit_detail": "tail validation metadata omitted record details",
        },
    ]


def test_tail_validation_baseline_helpers_round_trip(tmp_path, monkeypatch):
    cod_dir = tmp_path / "default"
    cod_dir.mkdir()
    cod_file = cod_dir / "DOSFUNC.COD"
    cod_file.write_bytes(b"")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_BASELINE_DIR", tmp_path / ".cache" / "tail_validation_baselines")
    baseline_path = _script._default_tail_validation_baseline_path(cod_dir, timeout=3, cod_files=[cod_file])
    baseline = {"version": 1, "entries": [{"proc_name": "_dos_alloc"}], "entry_count": 1}

    assert baseline_path.name == "DOSFUNC.timeout3.json"
    assert _script._load_tail_validation_baseline(baseline_path) is None

    _script._write_tail_validation_baseline(baseline_path, baseline)

    assert json.loads(baseline_path.read_text()) == baseline
    assert _script._load_tail_validation_baseline(baseline_path) == baseline


def test_tail_validation_cache_paths_are_stable_for_single_file_corpus(tmp_path, monkeypatch):
    cod_dir = tmp_path / "corpus"
    cod_dir.mkdir()
    cod_file = cod_dir / "DOSFUNC.COD"
    cod_file.write_bytes(b"\x90")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_CONSOLE_CACHE_DIR", tmp_path / ".cache" / "decompile_cod_dir")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_DETAIL_DIR", tmp_path / ".cache" / "tail_validation_details")

    console_path = _script._default_tail_validation_console_cache_path(cod_dir, timeout=3, cod_files=[cod_file])
    detail_path = _script._default_tail_validation_detail_path(cod_dir, timeout=3, cod_files=[cod_file])

    assert console_path.name == "DOSFUNC.timeout3.tail_validation_console.json"
    assert detail_path.name == "DOSFUNC.timeout3.tail_validation_surface.json"


def test_resolve_selected_cod_files_accepts_relative_and_basename(tmp_path):
    cod_dir = tmp_path / "cod"
    subdir = cod_dir / "f14"
    subdir.mkdir(parents=True)
    cockpit = subdir / "COCKPIT.COD"
    planes = subdir / "PLANES3.COD"
    cockpit.write_bytes(b"")
    planes.write_bytes(b"")

    selected = _script._resolve_selected_cod_files(cod_dir, ["f14/COCKPIT.COD", "PLANES3.COD"])

    assert selected == [cockpit, planes]


def test_filter_work_items_by_proc_names_reindexes_selected_items(tmp_path):
    items = [
        _script.CodWorkItem(tmp_path / "COCKPIT.COD", "_DoCRT", "NEAR", 1, 3, b"\x90"),
        _script.CodWorkItem(tmp_path / "COCKPIT.COD", "_DisplayMaster", "NEAR", 2, 3, b"\x90"),
        _script.CodWorkItem(tmp_path / "COCKPIT.COD", "_Other", "NEAR", 3, 3, b"\x90"),
    ]

    selected = _script._filter_work_items_by_proc_names(items, ["_displaymaster"])

    assert [(item.proc_name, item.proc_index, item.proc_total) for item in selected] == [
        ("_DisplayMaster", 1, 1)
    ]


def test_tail_validation_cache_paths_include_proc_selection(tmp_path, monkeypatch):
    cod_dir = tmp_path / "corpus"
    cod_dir.mkdir()
    cod_file = cod_dir / "COCKPIT.COD"
    cod_file.write_bytes(b"\x90")
    monkeypatch.setattr(_script, "_TAIL_VALIDATION_DETAIL_DIR", tmp_path / ".cache" / "tail_validation_details")

    detail_path = _script._default_tail_validation_detail_path(
        cod_dir,
        timeout=3,
        cod_files=[cod_file],
        proc_names=["_DisplayMaster"],
    )

    assert detail_path.name == "COCKPIT-_DisplayMaster.timeout3.tail_validation_surface.json"
