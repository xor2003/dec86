from angr_platforms.X86_16.corpus_scan import FunctionScanResult, ScanTimeout, StageResult, classify_failure, summarize_results


def test_corpus_scan_classifies_core_failure_kinds():
    assert classify_failure("load", ValueError("bad blob"))[0] == "load_failure"
    assert classify_failure("lift", RuntimeError("unsupported opcode 0f ff"))[0] == "unknown_opcode_or_semantic"
    assert classify_failure("decompile", ScanTimeout("timed out"))[0] == "timeout"
    assert classify_failure("decompile", RuntimeError("maximum recursion depth exceeded"))[0] == "recursion_or_explosion"
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
        function_count=1,
        decompiled_count=1,
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
    assert summary["files_scan_clean"] == ["A.COD"]
    assert summary["files_partial_success"] == ["B.COD"]
    assert summary["files_zero_success"] == ["C.COD"]


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
        function_count=1,
        decompiled_count=0,
        stages=[StageResult("load", True), StageResult("cfg", False, reason="cfg_failure")],
    )

    summary = summarize_results([repeated_a, repeated_b, other], "scan-safe")

    assert summary["top_failure_classes"] == [
        {"failure_class": "timeout", "count": 2},
        {"failure_class": "cfg_failure", "count": 1},
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
