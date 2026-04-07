from importlib.util import module_from_spec, spec_from_file_location
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
import json
import subprocess
from subprocess import CompletedProcess
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


def test_run_work_item_uses_scan_safe_fallback_for_worker_failures(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )
    result_scan = _script.FunctionScanResult(
        cod_file="DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        byte_len=1,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        fallback_kind="lift_only",
        semantic_family="stack_control",
        semantic_family_reason="loop-heavy helper path",
        function_count=1,
        decompiled_count=0,
        stages=[],
    )

    def fake_run(*args, **kwargs):  # noqa: ANN001
        stdout_file = kwargs["stdout"]
        stdout_file.write("/* Timed out while recovering a function after 20s. */\n")
        return CompletedProcess(args=args[0], returncode=3, stdout="", stderr="")

    monkeypatch.setattr(_script.subprocess, "run", fake_run)
    monkeypatch.setattr(_script, "_run_scan_safe_fallback", lambda *_args, **_kwargs: result_scan)

    result = _script._run_work_item(item, timeout=20, max_memory_mb=1024)

    assert result.exit_kind == "fallback"
    assert result.exit_detail.startswith("scan-safe lift_only recovery")
    assert result.scan_safe_result is result_scan
    rendered = _script._render_result_block(result)
    assert "scan-safe" in rendered
    assert "fallback kind: lift_only" in rendered
    assert "Timed out while recovering" not in rendered


def test_run_work_item_normalizes_timeout_expired_bytes(monkeypatch, tmp_path):
    item = _script.CodWorkItem(
        cod_path=tmp_path / "DOSFUNC.COD",
        proc_name="_dos_alloc",
        proc_kind="NEAR",
        proc_index=2,
        proc_total=15,
        code=b"\x90",
    )

    def fake_run(*args, **kwargs):  # noqa: ANN001
        raise subprocess.TimeoutExpired(
            cmd=args[0],
            timeout=120,
            output=b"stdout bytes\n",
            stderr=b"stderr bytes\n",
        )

    monkeypatch.setattr(_script.subprocess, "run", fake_run)
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

    def fake_run(*args, **kwargs):  # noqa: ANN001
        stdout_file = kwargs["stdout"]
        stdout_file.write("/* == c == */\nreturn 1;\n")
        return CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="",
            stderr=(
                "[tail-validation] whole-tail validation clean across 1 functions\n"
                '@@INERTIA_TAIL_VALIDATION@@ {"records":[{"function_addr":4096,"function_name":"_dos_alloc","structuring":{"changed":false},"postprocess":{"changed":false}}],"scanned":1}\n'
            ),
        )

    monkeypatch.setattr(_script.subprocess, "run", fake_run)
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

    def fake_run(*args, **kwargs):  # noqa: ANN001
        seen["timeout"] = kwargs["timeout"]
        stdout_file = kwargs["stdout"]
        stdout_file.write("/* == c == */\nreturn 1;\n")
        return CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(_script.subprocess, "run", fake_run)
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
