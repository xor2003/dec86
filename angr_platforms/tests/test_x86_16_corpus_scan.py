from pathlib import Path

from angr_platforms.X86_16.corpus_scan import (
    FunctionScanResult,
    ScanTimeout,
    StageResult,
    _should_skip_scan_safe_cfg,
    _should_skip_scan_safe_back_edge,
    _should_skip_scan_safe_decompile,
    _should_skip_scan_safe_decompile_for_cfg_shape,
    extract_cod_functions,
    scan_function,
    classify_failure,
    summarize_results,
)


def test_corpus_scan_classifies_core_failure_kinds():
    assert classify_failure("load", ValueError("bad blob"))[0] == "load_failure"
    assert classify_failure("lift", RuntimeError("unsupported opcode 0f ff"))[0] == "unsupported_semantic"
    assert classify_failure("decompile", ScanTimeout("timed out"))[0] == "timeout"
    assert classify_failure("decompile", RuntimeError("maximum recursion depth exceeded"))[0] == "recursion_or_explosion"
    assert classify_failure("cfg", None)[0] == "cfg_failure"
    assert classify_failure("unknown", None)[0] == "analysis_failure"
    assert classify_failure("decompile", None, empty_codegen=True)[0] == "no_code_produced"


def test_corpus_scan_summary_groups_file_health():
    ok_result = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_a",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        function_count=1,
        decompiled_count=1,
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    partial_ok = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_b1",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    partial_fail = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_b2",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="cfg",
        failure_class="cfg_failure",
        reason="cfg broke",
        fallback_kind="block_lift",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", False, reason="cfg_failure")],
    )
    dead_file = FunctionScanResult(
        cod_file="C.COD",
        proc_name="_c",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="lift",
        failure_class="lift_failure",
        reason="lift broke",
        fallback_kind="none",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("lift", False, reason="lift_failure")],
    )

    summary = summarize_results([ok_result, partial_ok, partial_fail, dead_file], "scan-safe")

    assert summary["ok"] == 2
    assert summary["failed"] == 2
    assert summary["failure_counts"] == {"cfg_failure": 1, "lift_failure": 1}
    assert summary["fallback_counts"] == {"block_lift": 1, "cfg_only": 1}
    assert summary["full_decompile_count"] == 1
    assert summary["cfg_only_count"] == 1
    assert summary["lift_only_count"] == 0
    assert summary["block_lift_count"] == 1
    assert summary["visibility_debt"] == 2
    assert summary["recovery_debt"] == 1
    assert summary["readability_debt"] == 1
    assert summary["unclassified_failure_count"] == 0
    assert summary["blind_spot_budget"] == {
        "full_decompile_rate": 0.25,
        "cfg_only_rate": 0.25,
        "lift_only_rate": 0.0,
        "block_lift_rate": 0.25,
        "true_failure_rate": 0.5,
    }
    assert summary["debt"] == {"traversal": 2, "recovery": 1, "readability": 1}
    assert summary["files_scan_clean"] == ["A.COD"]
    assert summary["files_partial_success"] == ["B.COD"]
    assert summary["files_zero_success"] == ["C.COD"]
    assert summary["interrupt_api"] == {
        "dos_helpers": 0,
        "bios_helpers": 0,
        "wrapper_calls": 0,
        "unresolved_wrappers": 0,
    }


def test_corpus_scan_summary_accumulates_interrupt_api_counts():
    helper_result = FunctionScanResult(
        cod_file="D.COD",
        proc_name="_d",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        function_count=1,
        decompiled_count=1,
        interrupt_dos_helper_count=2,
        interrupt_bios_helper_count=1,
        interrupt_wrapper_call_count=3,
        interrupt_unresolved_wrapper_count=1,
        semantic_family="interrupt_api",
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )

    summary = summarize_results([helper_result], "scan-safe")

    assert summary["interrupt_api"] == {
        "dos_helpers": 2,
        "bios_helpers": 1,
        "wrapper_calls": 3,
        "unresolved_wrappers": 1,
    }
    assert summary["family_ownership"] == {
        "top_families": [{"family": "interrupt_api", "count": 1}],
        "top_failures": [],
        "top_fallbacks": [],
        "top_ugly_clusters": [],
    }


def test_corpus_scan_summary_ranks_repeat_failures():
    repeated_a = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_a1",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="decompile",
        failure_class="timeout",
        reason="timed out",
        fallback_kind="block_lift",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", False, reason="timeout")],
    )
    repeated_b = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_a2",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="decompile",
        failure_class="timeout",
        reason="timed out",
        fallback_kind="block_lift",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", False, reason="timeout")],
    )
    other = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_b",
        proc_kind="FAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="cfg",
        failure_class="cfg_failure",
        reason="cfg broke",
        fallback_kind="block_lift",
        semantic_family="addressing",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", False, reason="cfg_failure")],
    )

    summary = summarize_results([repeated_a, repeated_b, other], "scan-safe")

    assert summary["top_failure_classes"] == [
        {"failure_class": "timeout", "count": 2},
        {"failure_class": "cfg_failure", "count": 1},
    ]
    assert summary["family_ownership"]["top_families"] == [
        {"family": "stack_control", "count": 2},
        {"family": "addressing", "count": 1},
    ]
    assert summary["family_ownership"]["top_failures"] == [
        {"family": "stack_control", "count": 2},
        {"family": "addressing", "count": 1},
    ]
    assert summary["top_failure_stages"] == [
        {"stage": "decompile", "count": 2},
        {"stage": "cfg", "count": 1},
    ]
    assert summary["top_failure_files"] == [
        {"cod_file": "A.COD", "count": 2},
        {"cod_file": "B.COD", "count": 1},
    ]
    assert summary["top_failure_functions"][0] == {
        "cod_file": "A.COD",
        "proc_name": "_a1",
        "proc_kind": "NEAR",
        "failure_class": "timeout",
        "count": 1,
    }


def test_corpus_scan_summary_ranks_fallback_hotspots():
    fallback_a = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_a",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="decompile",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", True)],
    )
    fallback_b = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_b",
        proc_kind="FAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="cfg",
        fallback_kind="lift_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", True)],
    )
    fallback_c = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_c",
        proc_kind="NEAR",
        byte_len=4,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="decompile",
        failure_class="decompiler_crash",
        reason="boom",
        fallback_kind="block_lift",
        semantic_family="addressing",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", False, reason="decompiler_crash")],
    )

    summary = summarize_results([fallback_a, fallback_b, fallback_c], "scan-safe")

    assert summary["top_fallback_kinds"] == [
        {"fallback_kind": "block_lift", "count": 1},
        {"fallback_kind": "cfg_only", "count": 1},
        {"fallback_kind": "lift_only", "count": 1},
    ]
    assert summary["family_ownership"]["top_fallbacks"] == [
        {"family": "stack_control", "count": 2},
        {"family": "addressing", "count": 1},
    ]
    assert summary["top_fallback_files"] == [
        {"cod_file": "A.COD", "count": 2},
        {"cod_file": "B.COD", "count": 1},
    ]
    assert summary["top_fallback_functions"][0] == {
        "cod_file": "A.COD",
        "proc_name": "_a",
        "proc_kind": "NEAR",
        "fallback_kind": "cfg_only",
        "count": 1,
    }


def test_corpus_scan_summary_ranks_ugly_clusters():
    oversized = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_oversized",
        proc_kind="NEAR",
        byte_len=512,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="cfg",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", True, detail="skipped decompile for oversized function (512 bytes > 384); cfg ok")],
    )
    complex_cfg = FunctionScanResult(
        cod_file="A.COD",
        proc_name="_complex",
        proc_kind="NEAR",
        byte_len=128,
        has_near_call_reloc=False,
        has_far_call_reloc=False,
        ok=True,
        stage_reached="cfg",
        fallback_kind="cfg_only",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("decompile", True, detail="skipped decompile for complex CFG (blocks>8 or insns>200); cfg ok")],
    )
    relocation = FunctionScanResult(
        cod_file="B.COD",
        proc_name="_reloc",
        proc_kind="NEAR",
        byte_len=16,
        has_near_call_reloc=True,
        has_far_call_reloc=False,
        ok=False,
        stage_reached="cfg",
        failure_class="skipped_relocation",
        reason="contains unresolved call relocation pattern",
        fallback_kind="block_lift",
        semantic_family="stack_control",
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", False, reason="skipped_relocation", detail="contains unresolved call relocation pattern")],
    )

    summary = summarize_results([oversized, complex_cfg, relocation], "scan-safe")

    assert summary["top_ugly_clusters"] == [
        {"cluster": "call_relocation_rescue", "count": 1},
        {"cluster": "control_flow_explosion", "count": 1},
        {"cluster": "oversized_function", "count": 1},
    ]
    assert summary["family_ownership"]["top_ugly_clusters"] == [
        {"family": "stack_control", "cluster": "call_relocation_rescue", "count": 1},
        {"family": "stack_control", "cluster": "control_flow_explosion", "count": 1},
        {"family": "stack_control", "cluster": "oversized_function", "count": 1},
    ]


def test_scan_safe_skips_oversized_decompile_attempts():
    assert _should_skip_scan_safe_decompile(698, "scan-safe", 384) is True
    assert _should_skip_scan_safe_decompile(384, "scan-safe", 384) is False
    assert _should_skip_scan_safe_decompile(698, "lift", 384) is False
    assert _should_skip_scan_safe_decompile(698, "scan-safe", 0) is False


def test_scan_safe_skips_oversized_cfg_attempts():
    assert _should_skip_scan_safe_cfg(2608, "scan-safe", 192) is True
    assert _should_skip_scan_safe_cfg(1589, "scan-safe", 192) is True
    assert _should_skip_scan_safe_cfg(192, "scan-safe", 192) is False
    assert _should_skip_scan_safe_cfg(2608, "lift", 192) is False
    assert _should_skip_scan_safe_cfg(2608, "scan-safe", 0) is False


def test_scan_safe_skips_complex_cfg_shapes():
    class _FakeBlock:
        def __init__(self, insn_count: int):
            self.capstone = type("Capstone", (), {"insns": [object()] * insn_count})()

    class _FakeFunc:
        def __init__(self, blocks):
            self._blocks = blocks

        @property
        def blocks(self):
            return self._blocks

    class _FakeCfg:
        def __init__(self, blocks):
            self.functions = {0x1000: _FakeFunc(blocks)}

    assert _should_skip_scan_safe_decompile_for_cfg_shape(_FakeCfg([_FakeBlock(201)]), "scan-safe", 8, 200) is True
    assert _should_skip_scan_safe_decompile_for_cfg_shape(_FakeCfg([_FakeBlock(1)] * 9), "scan-safe", 8, 200) is True
    assert _should_skip_scan_safe_decompile_for_cfg_shape(_FakeCfg([_FakeBlock(20)]), "lift", 8, 200) is False
    assert _should_skip_scan_safe_decompile_for_cfg_shape(_FakeCfg([_FakeBlock(5)]), "scan-safe", 8, 200) is False


def test_scan_safe_skips_short_loop_heavy_functions():
    class _FakeOp:
        def __init__(self, imm):
            self.imm = imm

    class _FakeInsn:
        def __init__(self, address: int, mnemonic: str, imm: int | None):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = [] if imm is None else [_FakeOp(imm)]

    class _FakeCapstoneBlock:
        def __init__(self, insns):
            self.insns = insns

    assert _should_skip_scan_safe_back_edge(_FakeCapstoneBlock([_FakeInsn(0x1000, "jmp", 0x0FFF)]), "scan-safe", 128) is True
    assert _should_skip_scan_safe_back_edge(_FakeCapstoneBlock([_FakeInsn(0x1000, "jmp", 0x1010)]), "scan-safe", 128) is False
    assert _should_skip_scan_safe_back_edge(_FakeCapstoneBlock([_FakeInsn(0x1000, "mov", None)]), "scan-safe", 128) is False
    assert _should_skip_scan_safe_back_edge(_FakeCapstoneBlock([_FakeInsn(0x1000, "jmp", 0x0FFF)]), "lift", 128) is False


def test_scan_safe_keeps_empty_codegen_as_fallback_for_known_hotspots():
    repo_root = Path(__file__).resolve().parents[2]
    expectations = {
        ("OUTPUT.COD", "_hexdump"): "lift_only",
        ("START1.COD", "_processStoreInput"): "lift_only",
        ("UTIL.COD", "_sizeString"): "lift_only",
    }

    for (cod_name, proc_name), expected_fallback in expectations.items():
        cod_path = repo_root / "cod" / cod_name
        funcs = {name: (kind, code) for name, kind, code in extract_cod_functions(cod_path)}
        kind, code = funcs[proc_name]
        result = scan_function(
            cod_path,
            proc_name,
            kind,
            code,
            timeout_sec=5,
            mode="scan-safe",
            max_cfg_bytes=192,
            max_decompile_bytes=384,
        )
        assert result.ok is True
        assert result.failure_class is None
        assert result.fallback_kind == expected_fallback


def test_scan_safe_uses_lift_only_for_start3_timeout_hotspot():
    repo_root = Path(__file__).resolve().parents[2]
    cod_path = repo_root / "cod" / "START3.COD"
    funcs = {name: (kind, code) for name, kind, code in extract_cod_functions(cod_path)}
    kind, code = funcs["_sub_14BB4"]

    result = scan_function(
        cod_path,
        "_sub_14BB4",
        kind,
        code,
        timeout_sec=5,
        mode="scan-safe",
        max_cfg_bytes=192,
        max_decompile_bytes=384,
    )

    assert result.ok is True
    assert result.failure_class is None
    assert result.fallback_kind == "lift_only"
    assert result.stage_reached == "cleanup"
