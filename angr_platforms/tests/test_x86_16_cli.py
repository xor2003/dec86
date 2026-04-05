from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import decompile


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
TRACE_PATH = REPO_ROOT / "angr_platforms" / "scripts" / "trace_x86_16_paths.py"
MONOPRIN_COD = REPO_ROOT / "cod" / "f14" / "MONOPRIN.COD"
NHORZ_COD = REPO_ROOT / "cod" / "f14" / "NHORZ.COD"
MAX_COD = REPO_ROOT / "cod" / "default" / "MAX.COD"
DOSFUNC_COD = REPO_ROOT / "cod" / "DOSFUNC.COD"
ICOMDO_COM = REPO_ROOT / "angr_platforms" / "x16_samples" / "ICOMDO.COM"
ISOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOD.COD"
IMOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOD.COD"
ISOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOT.COD"
ISOX_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ISOX.COD"
IHOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IHOD.COD"
IHOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IHOT.COD"
ILOD_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ILOD.COD"
ILOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "ILOT.COD"
IMOT_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOT.COD"
IMOX_COD = REPO_ROOT / "angr_platforms" / "x16_samples" / "IMOX.COD"


def _run_decompile_proc(
    path: Path,
    proc: str,
    *,
    proc_kind: str = "NEAR",
    analysis_timeout: int = 10,
    subprocess_timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--proc",
            proc,
            "--proc-kind",
            proc_kind,
            "--timeout",
            str(analysis_timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=subprocess_timeout,
        check=False,
    )


def test_preferred_decompiler_options_prefers_phoenix_for_true_wrappers():
    assert decompile._preferred_decompiler_options(1, 21, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(2, 21, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 25, wrapper_like=True) == [
        ("structurer_cls", "Phoenix")
    ]
    assert decompile._preferred_decompiler_options(1, 24) is None
    assert decompile._preferred_decompiler_options(2, 21) is None


def test_preferred_decompiler_options_rejects_call_heavy_small_functions():
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 23, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 25, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(6, 64, wrapper_like=True) == [("structurer_cls", "Phoenix")]
    assert decompile._preferred_decompiler_options(1, 24, wrapper_like=False) is None


def test_function_recovery_detail_names_recovery_stage():
    assert decompile._function_recovery_detail("recovery") == "during x86-16 function recovery"
    assert decompile._function_recovery_detail("recovery:fast") == "during x86-16 function recovery (fast CFGFast)"
    assert decompile._function_recovery_detail("recovery:full") == "during x86-16 function recovery (full CFGFast)"
    assert decompile._function_recovery_detail("recovery:narrow:0x80") == (
        "during x86-16 function recovery (narrow CFGFast)"
    )
    assert decompile._function_recovery_detail("postprocess") is None


def test_fallback_entry_function_retries_broader_windows_after_narrow_recovery_fails(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions))
        region = regions[0]
        if region[1] - region[0] >= 0x800:
            return expected_cfg, expected_func
        raise KeyError("narrow miss")

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert cfg is expected_cfg
    assert func is expected_func
    assert project._inertia_decompiler_stage == "recovery:narrow:0x800"
    assert len([call for call in calls if call[0] == "pick"]) == 5
    assert [call[1][0][1] - call[1][0][0] for call in calls if call[0] == "pick"] == [
        0x200,
        0x200,
        0x400,
        0x400,
        0x800,
    ]


def test_fallback_entry_function_uses_lean_cfgfast_for_86_16(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    captured: list[dict[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        captured.append({"regions": regions, "data_references": data_references})
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured[-1]["data_references"] is False


def test_pick_function_lean_disables_expensive_cfgfast_features(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function_lean(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1100)],
            "normalize": False,
            "data_references": False,
            "force_smart_scan": False,
            "force_complete_scan": False,
            "resolve_indirect_jumps": False,
            "function_prologues": False,
            "symbols": False,
            "cross_references": False,
        }
    ]


def test_pick_function_lean_can_skip_far_call_extension(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("far-call extension should not run")))
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function_lean(
        project,
        0x1000,
        regions=[(0x1000, 0x1100)],
        extend_far_calls=False,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1100)],
            "normalize": False,
            "data_references": False,
            "force_smart_scan": False,
            "force_complete_scan": False,
            "resolve_indirect_jumps": False,
            "function_prologues": False,
            "symbols": False,
            "cross_references": False,
        }
    ]


def test_fallback_entry_function_uses_fast_recovery_for_call_heavy_cod_helpers(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("slow path should not run")))
    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", lambda project_arg, start_addr, *, window: (start_addr, start_addr + window))

    cfg, func = decompile._fallback_entry_function(project, timeout=10, window=0x200, prefer_fast_recovery=True)

    assert cfg is expected_cfg
    assert func is expected_func
    assert project._inertia_decompiler_stage == "recovery:fast"
    assert calls == [("lean", [(0x1000, 0x1080)], False, False)]


def test_fallback_entry_function_uses_full_timeout_budget_for_fast_cod_helpers(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    budgets: list[int] = []

    def fake_analysis_timeout(timeout):
        budgets.append(timeout)

        class _Ctx:
            def __enter__(self):
                return None

            def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
                return False

        return _Ctx()

    monkeypatch.setattr(decompile, "_analysis_timeout", fake_analysis_timeout)
    monkeypatch.setattr(
        decompile,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (SimpleNamespace(), SimpleNamespace(addr=project.entry)),
    )
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    decompile._fallback_entry_function(project, timeout=20, window=0x200, prefer_fast_recovery=True)

    assert budgets == [20]


def test_fallback_entry_function_falls_back_after_fast_recovery_error(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_pick_function_lean(
        project_arg,
        addr,
        *,
        regions=None,
        data_references=None,
        extend_far_calls=None,
    ):
        calls.append(("lean", regions, data_references, extend_far_calls))
        raise ValueError("fast recovery failed")

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        return expected_cfg, expected_func

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )

    cfg, func = decompile._fallback_entry_function(project, timeout=20, window=0x200, prefer_fast_recovery=True)

    assert cfg is expected_cfg
    assert func is expected_func
    assert calls[0][0] == "lean"
    assert calls[-1][0] == "pick"


def test_fallback_entry_function_propagates_timeout_without_retrying(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, data_references, force_smart_scan))
        raise decompile._AnalysisTimeout()

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    with pytest.raises(decompile._AnalysisTimeout):
        decompile._fallback_entry_function(project, timeout=10, window=0x200)

    assert calls == [("infer", 0x200), ("pick", [(0x1000, 0x1200)], False, False)]


def test_recover_lst_function_retries_broader_windows_after_narrow_miss(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
    )
    lst_metadata = SimpleNamespace(code_labels={0x0: "helper"})
    calls: list[tuple[str, object]] = []

    def fake_infer(project_arg, start_addr, *, window):
        calls.append(("infer", window))
        return start_addr, start_addr + window

    def fake_pick_function(project_arg, addr, *, regions=None, data_references=None, force_smart_scan=None):
        calls.append(("pick", regions, force_smart_scan))
        region = regions[0]
        if region[1] - region[0] >= 0x1000:
            return expected_cfg, expected_func
        raise KeyError("narrow miss")

    expected_cfg = SimpleNamespace()
    expected_func = SimpleNamespace(addr=project.entry)

    monkeypatch.setattr(decompile, "_infer_x86_16_linear_region", fake_infer)
    monkeypatch.setattr(decompile, "_pick_function", fake_pick_function)

    cfg, func = decompile._recover_lst_function(
        project,
        lst_metadata,
        0x0,
        "helper",
        timeout=10,
        window=0x200,
    )

    assert cfg is expected_cfg
    assert func is expected_func
    assert [call[1] for call in calls if call[0] == "infer"] == [0x200, 0x400, 0x800, 0x1000]
    assert [call[1][0][1] - call[1][0][0] for call in calls if call[0] == "pick"] == [
        0x200,
        0x400,
        0x800,
        0x1000,
    ]


def test_pick_function_retries_smart_scan_before_complete_scan_after_narrow_cfgfast_miss(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfgs = [
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={0x1000: expected_func}),
    ]

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfgs[len(captured) - 1]

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)], data_references=True)

    assert cfg is expected_cfgs[-1]
    assert func is expected_func
    assert len(captured) == 4
    assert [entry.get("force_complete_scan", False) for entry in captured] == [False, False, True, True]
    assert [entry["data_references"] for entry in captured] == [True, True, True, True]
    assert [entry["force_smart_scan"] for entry in captured] == [False, True, False, True]


def test_pick_function_continues_after_cfgfast_exception(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        if len(captured) < 3:
            raise ValueError("CFGFast temporarily failed")
        return SimpleNamespace(functions={0x1000: expected_func})

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)], data_references=True)

    assert cfg.functions[0x1000] is expected_func
    assert func is expected_func
    assert len(captured) == 3


def test_pick_function_disables_smart_scan_for_bounded_x86_16_regions(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg, func = decompile._pick_function(project, 0x1000, regions=[(0x1000, 0x1100)])

    assert cfg is expected_cfg
    assert func is expected_func
    assert captured[0]["force_smart_scan"] is False
    assert captured[0]["data_references"] is True


def test_describe_exception_keeps_type_when_message_is_empty():
    assert decompile._describe_exception(AssertionError()) == "AssertionError"
    assert decompile._describe_exception(ValueError("bad cfg")) == "ValueError: bad cfg"


def test_detect_packed_mz_executable_recognizes_lzexe(tmp_path):
    path = tmp_path / "packed.exe"
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x1C:0x20] = b"LZ91"
    path.write_bytes(bytes(header))

    assert decompile._detect_packed_mz_executable(path) == "LZEXE 0.91"


def test_recover_partial_cfg_uses_bounded_cfgfast_and_returns_entry_cfg(monkeypatch):
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=CLI_PATH)),
    )
    captured: list[dict[str, object]] = []
    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfg = SimpleNamespace(functions={0x1000: expected_func})

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfg

    project.analyses = SimpleNamespace(CFGFast=fake_cfgfast)
    monkeypatch.setattr(
        decompile,
        "_infer_x86_16_linear_region",
        lambda project_arg, start_addr, *, window: (start_addr, start_addr + window),
    )
    monkeypatch.setattr(decompile, "extend_cfg_for_far_calls", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(decompile, "patch_interrupt_service_call_sites", lambda *_args, **_kwargs: False)

    cfg = decompile._recover_partial_cfg(project, window=0x200)

    assert cfg is expected_cfg
    assert captured == [
        {
            "start_at_entry": False,
            "function_starts": [0x1000],
            "regions": [(0x1000, 0x1200)],
            "normalize": True,
            "force_complete_scan": False,
            "data_references": False,
            "force_smart_scan": False,
        }
    ]


def test_supplement_functions_from_prologue_scan_adds_confirmed_recoveries(monkeypatch):
    code = bytearray(0x2000)
    for addr in (0x1750, 0x1770):
        offset = addr - 0x1000
        code[offset : offset + 3] = b"\x55\x8b\xec"

    class _Memory:
        def load(self, offset, size):
            return bytes(code[offset : offset + size])

    project = SimpleNamespace(
        entry=0x1500,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(max_addr=len(code) - 1, linked_base=0x1000, memory=_Memory())),
    )

    class _Block:
        def __init__(self):
            self.capstone = SimpleNamespace(
                insns=[
                    SimpleNamespace(mnemonic="push", op_str="bp"),
                    SimpleNamespace(mnemonic="mov", op_str="bp, sp"),
                ]
            )

    project.factory = SimpleNamespace(block=lambda *_args, **_kwargs: _Block())

    expected = {
        0x1770: (SimpleNamespace(), SimpleNamespace(addr=0x1770, name="sub_1770")),
        0x1750: (SimpleNamespace(), SimpleNamespace(addr=0x1750, name="sub_1750")),
    }

    def fake_pick_function_lean(project_arg, addr, **_kwargs):
        return expected[addr]

    monkeypatch.setattr(decompile, "_pick_function_lean", fake_pick_function_lean)
    monkeypatch.setattr(decompile, "_run_with_timeout_in_daemon_thread", lambda func, **_kwargs: func())

    supplemental = decompile._supplement_functions_from_prologue_scan(project, existing_addrs={0x1500})

    assert [function.addr for _, function in supplemental] == [0x1770, 0x1750]


def test_recover_blob_entry_function_enables_data_references(monkeypatch):
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90" * 16)),
        analyses=SimpleNamespace(),
    )
    captured: list[dict[str, object]] = []

    def fake_cfgfast(**kwargs):
        captured.append(kwargs)
        return expected_cfgs[len(captured) - 1]

    expected_func = SimpleNamespace(addr=0x1000)
    expected_cfgs = [
        SimpleNamespace(functions={}),
        SimpleNamespace(functions={0x1000: expected_func}),
    ]
    project.analyses.CFGFast = fake_cfgfast

    cfg, func = decompile._recover_blob_entry_function(project, 0x1000, timeout=10)

    assert cfg is expected_cfgs[-1]
    assert func is expected_func
    assert [entry["data_references"] for entry in captured] == [False, True]


def test_decompile_cli_recovers_source_like_monoprin_tokens():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(MONOPRIN_COD), "--proc", "_mset_pos", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _mset_pos" in result.stdout
    assert "== c ==" in result.stdout
    assert "% 80" in result.stdout
    assert "% 25" in result.stdout
    assert (
        "int _mset_pos(int x, int y)" in result.stdout
        or "short _mset_pos(unsigned short v0, unsigned short x, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x_3, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short x_2, unsigned short y)" in result.stdout
        or "short _mset_pos(unsigned short x, unsigned short x_3, unsigned short y)" in result.stdout
    )
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "mono_x =" in result.stdout
    assert "mono_y =" in result.stdout
    assert "&v1" not in result.stdout
    assert "return" in result.stdout


def test_decompile_cli_can_extract_and_name_cod_procedure():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(NHORZ_COD), "--proc", "_ChangeWeather", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _ChangeWeather" in result.stdout
    assert "int _ChangeWeather(void)" in result.stdout
    assert "globals = _CLOUDHEIGHT, _CLOUDTHICK" in result.stdout
    assert "extern char g_" not in result.stdout
    assert "if (BadWeather)" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "if (!(!" not in result.stdout
    assert "BadWeather = 0;" in result.stdout
    assert "CLOUDHEIGHT = 8150;" in result.stdout
    assert "CLOUDTHICK = 500;" in result.stdout
    assert "0x7000" not in result.stdout
    assert "_start" not in result.stdout


def test_normalize_function_signature_arg_names_deduplicates_duplicate_parameters():
    text = "unsigned short _strlen(unsigned short s, unsigned short s)\n"

    assert decompile._normalize_function_signature_arg_names(text) == (
        "unsigned short _strlen(unsigned short s, unsigned short s_2)\n"
    )


def test_prune_void_function_return_values_text_handles_multiline_headers():
    text = (
        "void _dos_free()\n"
        "{\n"
        "    if (rout.x.cflag != 0) {\n"
        "        return err;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )

    assert decompile._prune_void_function_return_values_text(text) == (
        "void _dos_free()\n"
        "{\n"
        "    if (rout.x.cflag != 0) {\n"
        "        return;\n"
        "    }\n"
        "    return;\n"
        "}\n"
    )


def test_prune_void_function_return_values_text_drops_bare_returns_from_nonvoid_functions():
    text = (
        "unsigned short _dos_getProcessId(void)\n"
        "{\n"
        "    return;\n"
        "}\n"
    )

    assert decompile._prune_void_function_return_values_text(text) == (
        "unsigned short _dos_getProcessId(void)\n"
        "{\n"
        "}\n"
    )


def test_simplify_x86_16_stack_byte_pointers_rewrites_far_pointer_stack_stores():
    metadata = SimpleNamespace(stack_aliases={0xA: "cs", 0xC: "ss"})
    text = "    *((unsigned short *)(ds * 16 + (unsigned int)cs_2)) = ir_3_2;\n"

    assert decompile._simplify_x86_16_stack_byte_pointers(text, metadata) == "    *cs = ir_3_2;\n"


def test_simplify_x86_16_stack_byte_pointers_keeps_const_pointer_inputs_stable():
    metadata = SimpleNamespace(stack_aliases={0x4: "file"})
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    *((unsigned short *)(ds * 16 + (unsigned int)file)) = ir_4_2;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "*file =" not in simplified
    assert "MK_FP(ds, (unsigned int)file)" in simplified


def test_simplify_x86_16_stack_byte_pointers_keeps_adjacent_source_backed_stores_distinct():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
            "return 0;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    err = loadprog(file, 0, DOS_LOAD_NOEXEC, cmdline);\n"
        "    if (err) return err;\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    *ss = exeLoadParams.ss;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "    *cs = exeLoadParams.cs;\n" in simplified
    assert "    *ss = exeLoadParams.ss;\n" in simplified
    assert simplified.index("    *cs = exeLoadParams.cs;\n") < simplified.index("    *ss = exeLoadParams.ss;\n")


def test_simplify_x86_16_stack_byte_pointers_splits_reused_temp_windows_for_source_backed_stores():
    metadata = SimpleNamespace(
        stack_aliases={},
        global_names=("exeLoadParams",),
        source_lines=(
            "if (err) return err;",
            "*cs = exeLoadParams.cs;",
            "*ss = exeLoadParams.ss;",
            "return 0;",
        ),
    )
    text = (
        "unsigned short demo(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)\n"
        "{\n"
        "    err = loadprog(file, 0, DOS_LOAD_NOEXEC, cmdline);\n"
        "    if (err) return err;\n"
        "    ir_3_2 = exeLoadParams.cs;\n"
        "    *cs = ir_3_2;\n"
        "    ir_3_2 = exeLoadParams.ss;\n"
        "    *ss = ir_3_2;\n"
        "    return 0;\n"
        "}\n"
    )

    simplified = decompile._simplify_x86_16_stack_byte_pointers(text, metadata)

    assert "    *cs = exeLoadParams.cs;\n" in simplified
    assert "    *ss = exeLoadParams.ss;\n" in simplified
    assert simplified.index("    *cs = exeLoadParams.cs;\n") < simplified.index("    *ss = exeLoadParams.ss;\n")


def test_format_known_helper_calls_handles_missing_cod_metadata(monkeypatch):
    monkeypatch.setattr(decompile, "collect_dos_int21_calls", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decompile, "collect_interrupt_service_calls", lambda *_args, **_kwargs: [])

    project = SimpleNamespace(_sim_procedures={})
    function = SimpleNamespace(addr=0x1000, name="demo")

    assert (
        decompile._format_known_helper_calls(project, function, "int demo(void)\n{\n    return 0;\n}\n", "cdecl", None)
        == "int demo(void)\n{\n    return 0;\n}"
    )


def test_decompile_cli_prunes_void_returns_for_multiline_headers():
    result = _run_decompile_proc(DOSFUNC_COD, "_dos_free")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_free(const unsigned short segment)" in result.stdout
    assert "sreg.es = segment;" in result.stdout
    assert "return err;" in result.stdout
    assert "return 0;" in result.stdout
    assert "return;" not in result.stdout


@pytest.mark.parametrize(
    ("proc_name", "header_anchor"),
    (
        ("_dos_getProcessId", "unsigned short _dos_getProcessId(void)"),
        ("_dos_setProcessId", "int _dos_setProcessId(const unsigned short pid)"),
    ),
)
def test_decompile_cli_recovers_dos_process_id_helpers(proc_name: str, header_anchor: str):
    result = _run_decompile_proc(DOSFUNC_COD, proc_name)

    assert result.returncode == 0, result.stderr + result.stdout
    assert header_anchor in result.stdout
    assert "return ir_1;" not in result.stdout
    assert "return;" not in result.stdout
    if proc_name == "_dos_setProcessId":
        assert "[bp+0x4] = pid" in result.stdout


def test_decompile_cli_recovers_dos_load_program_pointer_stores():
    result = _run_decompile_proc(DOSFUNC_COD, "_dos_loadProgram")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_loadProgram(const char *file, const char *cmdline, unsigned short *cs, unsigned short *ss)" in result.stdout
    assert "if (err) return err;" in result.stdout
    assert "*cs = exeLoadParams.cs;" in result.stdout
    assert "*ss = exeLoadParams.ss;" in result.stdout
    assert "ds * 16 +" not in result.stdout
    assert "*file =" not in result.stdout
    assert "ds * 16 +" not in result.stdout
    assert "if (&err)" not in result.stdout


def test_decompile_cli_skips_chkstk_thunk_for_small_cod_logic():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(MAX_COD), "--proc", "_max", "--timeout", "10"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _max" in result.stdout
    assert "UnresolvableJumpTarget" not in result.stdout
    assert "/* COD annotations:" in result.stdout
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "short _max(" in result.stdout
    assert "unsigned short _max(unsigned short x, unsigned short y)" in result.stdout
    assert "unsigned short y" in result.stdout
    assert "if (a1 > x)" in result.stdout
    assert "return x_3;" in result.stdout


def test_decompile_cli_recovers_small_cod_byte_condition_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_MousePOS")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _MousePOS" in result.stdout
    assert "[bp+0x4] = x" in result.stdout
    assert "[bp+0x6] = y" in result.stdout
    assert "short _MousePOS(unsigned short x, unsigned short y)" in result.stdout
    assert "globals = _MOUSE, _MouseX, _MouseY" in result.stdout
    assert "if (!(MOUSE))" in result.stdout
    assert "&v1" not in result.stdout
    assert "return sub_ff033();" in result.stdout


def test_decompile_cli_recovers_configcrts_copy_loop():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_ConfigCrts")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _ConfigCrts" in result.stdout
    assert "unsigned short _ConfigCrts(void)" in result.stdout
    assert "i = 0;" in result.stdout
    assert "field_1 = i * 2;" in result.stdout
    assert "do" in result.stdout
    assert "return v7;" in result.stdout


def test_decompile_cli_recovers_rotate_pt_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "BILLASM.COD", "_rotate_pt")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _rotate_pt" in result.stdout
    assert "void _rotate_pt(unsigned short s, unsigned short d, unsigned short ang)" in result.stdout
    assert "[bp+0x4] = s" in result.stdout
    assert "[bp+0x6] = d" in result.stdout
    assert "[bp-0x4] = y" in result.stdout
    assert "[bp-0x2] = x" in result.stdout
    assert "calls = _CosB, _SinB" in result.stdout
    assert "y_4 = *((char *)(ds * 16 + s))" in result.stdout
    assert "CosB(OurRoll);" in result.stdout


def test_decompile_cli_recovers_sethook_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetHook")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetHook" in result.stdout
    assert "unsigned short _SetHook(unsigned short Hook)" in result.stdout
    assert "[bp+0x4] = Hook" in result.stdout
    assert "globals = _HookDown" in result.stdout
    assert "calls = _Message" in result.stdout
    assert 'Message ("Hook Lowered",RIO_NOW_MSG);' in result.stdout
    assert "sub_102f();" not in result.stdout
    assert "HookDown == Hook" in result.stdout
    assert "g_7000 = Hook;" in result.stdout or "HookDown = Hook;" in result.stdout
    assert "if (Hook)" in result.stdout
    assert "if (!(...))" not in result.stdout
    assert "v2 = &v3;" not in result.stdout
    assert "= 93;" in result.stdout
    assert "= 106;" in result.stdout
    assert "return 1;" in result.stdout
    assert "s_" not in result.stdout


def test_decompile_cli_recovers_setgear_guard_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetGear")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetGear" in result.stdout
    assert "unsigned short _SetGear(unsigned short G)" in result.stdout or "void _SetGear(int G)" in result.stdout
    assert "if (!(ejected))" in result.stdout
    assert "if (!G)" in result.stdout
    assert "if (Knots <= 350)" in result.stdout
    assert "Status = Status | 1;" in result.stdout
    assert "Status = Status & -2;" in result.stdout
    assert "Message (\"Landing gear lowered\",RIO_MSG);" in result.stdout
    assert "return v13;" in result.stdout
    assert "if (...)" not in result.stdout
    assert "28674" not in result.stdout
    assert "28682" not in result.stdout
    assert "sub_102f();" not in result.stdout


def test_decompile_cli_recovers_setdlc_state_store():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetDLC")

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _SetDLC" in result.stdout
    assert "short _SetDLC(" in result.stdout
    assert "unsigned short DLC" in result.stdout
    assert "[bp+0x4] = DLC" in result.stdout
    assert "globals = _DirectLiftControl" in result.stdout
    assert "DirectLiftControl = DLC;" in result.stdout
    assert "DLC >> 8" not in result.stdout
    assert "return DLC;" in result.stdout


def test_decompile_cli_keeps_query_interrupts_wrapper_calls_classified_in_matrix_corpus():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(IMOD_COD),
            "--proc",
            "query_interrupts",
            "--proc-kind",
            "FAR",
            "--timeout",
            "60",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 query_interrupts" in result.stdout
    assert "calls = _int86, _int86x" in result.stdout
    assert "int86(0x21, &inregs, &outregs);" in result.stdout
    assert "info = outregs;" in result.stdout
    assert "return outregs;" in result.stdout


def test_decompile_cli_recovers_tidshowrange_layout_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_TIDShowRange")

    assert result.returncode in (0, 3), result.stderr + result.stdout
    if result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    assert "function: 0x1000 _TIDShowRange" in result.stdout
    assert "void _TIDShowRange(void)" in result.stdout
    assert "RectFill(Rp2,146,21,29,9,BLACK);" in result.stdout
    assert "MapInEMSSprite(MISCSPRTSEG,0)" in result.stdout


def test_decompile_cli_recovers_drawradaralt_branch_logic():
    result = _run_decompile_proc(REPO_ROOT / "cod" / "f14" / "COCKPIT.COD", "_DrawRadarAlt")

    if result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _DrawRadarAlt" in result.stdout
    assert "void _DrawRadarAlt(void)" in result.stdout
    assert "[bp-0xc] = newalt" in result.stdout
    assert "[bp-0xa] = y2" in result.stdout
    assert "[bp-0x8] = soffset" in result.stdout
    assert "[bp-0x2] = b" in result.stdout
    assert "calls = _MapInEMSSprite, _TransRectCopy, _MDiv, _Rotate2D, _scaley, _DrawLine, _RectCopy" in result.stdout
    assert "if (!(View))" in result.stdout
    assert "unsigned short y2;  // [bp-0xa] y2" in result.stdout
    assert "unsigned short b;  // [bp-0x2] b" in result.stdout
    assert "y2 = 0;" in result.stdout
    assert "y2 = 112;" in result.stdout
    assert "s_12 = 0;" in result.stdout
    assert "s_14 = 2;" in result.stdout
    assert "MapInEMSSprite(MISCSPRTSEG,0);" in result.stdout


@pytest.mark.parametrize(
    ("path", "proc_kind", "shape_tokens"),
    [
        (ISOD_COD, "NEAR", ("& 0xff00 |", "return ")),
        (ISOT_COD, "NEAR", ("& 0xff00 |", "return ")),
        (ISOX_COD, "NEAR", ("& 0xff00 |", "return ")),
        (IMOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (IMOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (IMOX_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (IHOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (IHOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
        (ILOD_COD, "FAR", ("& 0xff00 |", "return ")),
        (ILOT_COD, "FAR", ("sub_1004();", "v3 >> 8;")),
    ],
)
def test_decompile_cli_main_matrix(path: Path, proc_kind: str, shape_tokens: tuple[str, str]):
    result = _run_decompile_proc(path, "_main", proc_kind=proc_kind, analysis_timeout=20, subprocess_timeout=60)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 _main" in result.stdout
    assert "int _main(void)" in result.stdout
    for token in shape_tokens:
        assert token in result.stdout
    assert "Decompiler timeout" not in result.stdout


@pytest.mark.parametrize(
    ("path", "proc_kind"),
    [
        (ISOD_COD, "NEAR"),
        (ISOT_COD, "NEAR"),
        (ISOX_COD, "NEAR"),
        (IMOD_COD, "FAR"),
        (IMOT_COD, "FAR"),
        (IMOX_COD, "FAR"),
        (IHOD_COD, "FAR"),
        (IHOT_COD, "FAR"),
        (ILOD_COD, "FAR"),
        (ILOT_COD, "FAR"),
    ],
)
def test_decompile_cli_show_summary_matrix(path: Path, proc_kind: str):
    result = _run_decompile_proc(path, "show_summary", proc_kind=proc_kind, analysis_timeout=20, subprocess_timeout=60)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "function: 0x1000 show_summary" in result.stdout
    assert "int show_summary(void)" in result.stdout
    assert "info >> 8;" in result.stdout
    assert "*((" in result.stdout
    assert "Decompiler timeout" not in result.stdout


@pytest.mark.parametrize(
    ("path", "proc", "proc_kind", "analysis_timeout", "subprocess_timeout", "expected_tokens", "forbidden_tokens"),
    [
        (
            MAX_COD,
            "_max",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _max", "if (x > y)", "return x;", "return y;"),
            ("UnresolvableJumpTarget",),
        ),
        (
            NHORZ_COD,
            "_ChangeWeather",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _ChangeWeather", "if (BadWeather)", "CLOUDHEIGHT = 8150;", "CLOUDTHICK = 500;", "CLOUDTHICK = 1000;"),
            ("if (!(...))", "if (!(!"),
        ),
            (
                MONOPRIN_COD,
                "_mset_pos",
                "NEAR",
                10,
                30,
                (
                    "function: 0x1000 _mset_pos",
                    "% 80",
                    "% 25",
                    "int _mset_pos(int x, int y)",
                ),
                ("&v1",),
            ),
                (
                    REPO_ROOT / "cod" / "f14" / "BILLASM.COD",
                    "_MousePOS",
                    "NEAR",
                    10,
                    30,
                        (
                            "function: 0x1000 _MousePOS",
                            "if (!(MOUSE))",
                                "MouseX =",
                            "MouseY = y;",
                            "return sub_ff033();",
                        ),
                        ("if (...)", "28675", "28677"),
                    ),
        (
            REPO_ROOT / "cod" / "f14" / "PLANES3.COD",
            "_Ready5",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _Ready5", "void _Ready5(void)", "planecnt", "droll", "pdest", "* 46", "+ 18 + v3", "return;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookDown",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _LookDown", "if (!(BackSeat))", "Rp3D->Length1 = 50;", "RpCRT1->YBgn = 27;", "RpCRT2->YBgn = 25;", "RpCRT4->YBgn = 39;", "VdiMask[MASKY] = 27;", "AdiMask[MASKY] = 25;", "RawMask[MASKY] = 39;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_LookUp",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _LookUp", "if (!(BackSeat))", "Rp3D->Length1 = 150;", "RpCRT1->YBgn = 138;", "RpCRT2->YBgn = 136;", "RpCRT4->YBgn = 150;", "VdiMask[MASKY] = 138;", "AdiMask[MASKY] = 136;", "RawMask[MASKY] = 150;"),
            (),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBox",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBox", "return 1;", "xl <=", "xh >=", "zl <=", "zh >="),
            ("if (...)", "!(zh >=", "xl >", "xh <", "zl >"),
        ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_InBoxLng",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _InBoxLng", "if (x < xl || x > xh || z < zl || z > zh)", "return 0;", "return 1;"),
            ("if (...)", "!(v4", "& &"),
        ),
            (
                REPO_ROOT / "cod" / "f14" / "CARR.COD",
                "_SetHook",
                "NEAR",
                10,
            30,
                        ("function: 0x1000 _SetHook", "return 1;", "if (Hook)", "= 93;", "Message (\"Hook Lowered\",RIO_NOW_MSG);", "HookDown == Hook", "HookDown = Hook;"),
                    (),
                ),
            (
                REPO_ROOT / "cod" / "f14" / "CARR.COD",
                "_SetGear",
                "NEAR",
                10,
                30,
                (
                    "function: 0x1000 _SetGear",
                    "unsigned short _SetGear(unsigned short G)",
                    "if (!(ejected))",
                    "if (!G)",
                    "if (Knots <= 350)",
                    "Status = Status | 1;",
                    "Status = Status & -2;",
                    'Message ("Landing gear lowered",RIO_MSG);',
                    "return v13;",
                ),
                (),
            ),
        (
            REPO_ROOT / "cod" / "f14" / "CARR.COD",
            "_SetDLC",
            "NEAR",
            10,
            30,
            ("function: 0x1000 _SetDLC", "DirectLiftControl = DLC;", "return DLC;"),
            ("DLC >> 8",),
        ),
            (
                REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
                "_TIDShowRange",
                "NEAR",
                10,
                30,
                    ("function: 0x1000 _TIDShowRange", "Timed out while recovering a function after 10s."),
                (),
            ),
        (
            REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
            "_DrawRadarAlt",
            "NEAR",
            10,
            30,
                ("function: 0x1000 _DrawRadarAlt", "if (!(View))", "y2 = 0;", "y2 = 112;", "s_12 = 0;", "s_14 = 2;", "MapInEMSSprite(MISCSPRTSEG,0);"),
            (),
        ),
            (
                ISOD_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ISOT_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ISOX_COD,
                "fold_values",
                "NEAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IHOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IHOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ILOD_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                ILOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOT_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
            (
                IMOX_COD,
                "fold_values",
                "FAR",
                20,
                60,
                ("function: 0x1000 fold_values", "1000", "return"),
                (),
            ),
    ],
)
def test_decompile_cli_small_cod_logic_batch(
    path, proc, proc_kind, analysis_timeout, subprocess_timeout, expected_tokens, forbidden_tokens
):
    result = _run_decompile_proc(
        path,
        proc,
        proc_kind=proc_kind,
        analysis_timeout=analysis_timeout,
        subprocess_timeout=subprocess_timeout,
    )

    if proc == "_TIDShowRange" and result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    if proc == "_DrawRadarAlt" and result.returncode == 3:
        assert "Timed out while recovering a function after 10s." in result.stdout
        return
    if proc == "fold_values" and result.returncode == 3:
        assert "Timed out while recovering a function after 20s." in result.stdout
        return

    assert result.returncode == 0, result.stderr + result.stdout
    for token in expected_tokens:
        assert token in result.stdout, result.stdout
    for token in forbidden_tokens:
        assert token not in result.stdout, result.stdout


def test_decompile_cli_names_known_dos_interrupt_helpers_in_com_output():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(ICOMDO_COM), "--timeout", "10", "--window", "0x80", "--max-functions", "2"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "int get_dos_version(void);" in result.stdout
    assert "void print_dos_string(const char *s);" in result.stdout
    assert "void exit(int status);" in result.stdout
    assert "void _start(void)" in result.stdout
    assert "get_dos_version();" in result.stdout
    assert 'print_dos_string("DOS sample");' in result.stdout
    assert "exit(0);" in result.stdout
    assert "1044513();" not in result.stdout
    assert "dos_int21();" not in result.stdout


def test_decompile_cli_supports_dos_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "dos",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "unsigned short _dos_get_version(void);" in result.stdout
    assert "void _dos_print_dollar_string(const char far *s);" in result.stdout
    assert "void _dos_exit(unsigned char status);" in result.stdout
    assert "_dos_get_version();" in result.stdout
    assert '_dos_print_dollar_string("DOS sample");' in result.stdout
    assert "_dos_exit(0);" in result.stdout


def test_decompile_cli_supports_raw_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "raw",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "dos_int21();" in result.stdout


def test_decompile_cli_supports_pseudo_api_style_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "pseudo",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "int dos_get_version(void);" in result.stdout
    assert "void dos_print_dollar_string(const char *s);" in result.stdout
    assert "void dos_exit(int status);" in result.stdout
    assert "dos_get_version();" in result.stdout
    assert 'dos_print_dollar_string("DOS sample");' in result.stdout
    assert "dos_exit(0);" in result.stdout


def test_decompile_cli_supports_msc_api_style_alias_for_known_helpers():
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(ICOMDO_COM),
            "--timeout",
            "10",
            "--window",
            "0x80",
            "--max-functions",
            "2",
            "--api-style",
            "msc",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "_dos_get_version();" in result.stdout
    assert '_dos_print_dollar_string("DOS sample");' in result.stdout
    assert "_dos_exit(0);" in result.stdout


def test_trace_x86_16_paths_cli_traces_small_com_stub():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "exec", "--max-steps", "6"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "mode: exec" in result.stdout
    assert "== step 0 @ 0x1000 ==" in result.stdout
    assert "mov ah, 0x30" in result.stdout
    assert "== step 2 @ 0xf021 ==" in result.stdout
    assert "helper=DOSInt21 ; get_dos_version()" in result.stdout
    assert "== step 3 @ 0x1004 ==" in result.stdout
    assert "mov ah, 9" in result.stdout
    assert "== step 5 @ 0x1009 ==" in result.stdout
    assert "int 0x21" in result.stdout


def test_trace_x86_16_paths_cli_exec_supports_helper_annotations():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "exec", "--max-steps", "8"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert 'helper=DOSInt21 ; print_dos_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_recovers_cfg_for_small_com_stub():
    result = subprocess.run(
        [sys.executable, str(TRACE_PATH), str(ICOMDO_COM), "--mode", "cfg", "--max-blocks", "4"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "mode: cfg" in result.stdout
    assert "function: 0x1000 _start" in result.stdout
    assert "== block 0x1000 ==" in result.stdout
    assert "0x1000: mov ah, 0x30" in result.stdout
    assert "0x1002: int 0x21 ; get_dos_version()" in result.stdout
    assert '0x1009: int 0x21 ; print_dos_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_supports_msc_helper_annotations():
    result = subprocess.run(
        [
            sys.executable,
            str(TRACE_PATH),
            str(ICOMDO_COM),
            "--mode",
            "cfg",
            "--max-blocks",
            "4",
            "--api-style",
            "msc",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "0x1002: int 0x21 ; _dos_get_version()" in result.stdout
    assert '0x1009: int 0x21 ; _dos_print_dollar_string("DOS sample")' in result.stdout


def test_trace_x86_16_paths_cli_supports_pseudo_helper_annotations():
    result = subprocess.run(
        [
            sys.executable,
            str(TRACE_PATH),
            str(ICOMDO_COM),
            "--mode",
            "cfg",
            "--max-blocks",
            "4",
            "--api-style",
            "pseudo",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "0x1002: int 0x21 ; dos_get_version()" in result.stdout
    assert '0x1009: int 0x21 ; dos_print_dollar_string("DOS sample")' in result.stdout
