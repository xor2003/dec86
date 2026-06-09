import json
import subprocess
import sys

from scripts.build_msc6_examples import (
    COMPARE16_HARNESS_MAIN,
    COMPARE32_HARNESS_MAIN,
    DECOMPILE_MAX_FUNCTIONS_DEFAULT,
    DEFAULT_DECOMPILE_SKIP,
    ENUM_UNION_HARNESS_MAIN,
    FALLBACK_EXAMPLE_REBUILD,
    HARNESS_SUCCESS_EXIT_CODE,
    _build_from_function_decompiles,
    _child_trace_path,
    _decompile_and_validate,
    _extract_decompiled_function_definition,
    _focused_decompile_process_timeout,
    _is_decompile_output_acceptable,
    _make_decompile_env,
    _parse_decompile_profile,
    _decompile_function_with_options,
    _normalize_extracted_function_arg_placeholders,
)


def test_extract_decompiled_function_definition_handles_multiline_header():
    text = """
#include <stdint.h>

/// int cmp_i16(int a, int b)
int cmp_i16(int a, int b)

{
    if (b > a)
        return -1;
    return 0;
}
"""

    body = _extract_decompiled_function_definition(text, "cmp_i16")

    assert body.startswith("int cmp_i16(int a, int b)")
    assert "return -1;" in body


def test_compare16_fallback_harness_checks_rel_i16_calls():
    assert "rel_i16(-2, 5)" in COMPARE16_HARNESS_MAIN
    assert "rel_i16(9, 3)" in COMPARE16_HARNESS_MAIN
    assert "rel_i16(7, 7)" in COMPARE16_HARNESS_MAIN
    assert "in_window_i16(-2, 5)" not in COMPARE16_HARNESS_MAIN


def test_child_trace_path_keeps_suffix_and_sanitizes_label():
    assert _child_trace_path("trace.agent.txt", "CMP32 compare_unsigned") == "trace.agent.CMP32_compare_unsigned.txt"
    assert _child_trace_path("trace", "CMP32/attempt:1") == "trace.CMP32_attempt_1"


def test_decompile_env_derives_child_trace_file(monkeypatch, tmp_path):
    trace_path = tmp_path / "msc.trace.txt"
    monkeypatch.setenv("INERTIA_OTEL_SPAN_FILE", str(trace_path))

    env = _make_decompile_env(False, trace_label="CMP32.compare_unsigned")

    assert env["INERTIA_ENABLE_TAIL_VALIDATION"] == "1"
    assert env["INERTIA_OTEL_SPAN_FILE"] == str(tmp_path / "msc.trace.CMP32.compare_unsigned.txt")


def test_acceptance_uses_final_clean_tail_validation_over_rejected_lanes():
    stderr = """
[dbg] direct failure family: status=empty validation=failed
[tail-validation] whole-tail validation clean across 1 functions
"""
    profile = _parse_decompile_profile(stderr)

    ok, reason = _is_decompile_output_acceptable("int f(void) { return 1; }", stderr, profile)

    assert ok is True
    assert reason is None


def test_acceptance_rejects_validation_failed_fallback_even_with_clean_tail_summary():
    stderr = """
[tail-validation] whole-tail validation clean across 1 functions
/* Decompilation validation_failed: Missing source-evidenced return values in emitted C: return value(0/1) */
/* == c (non-optimized fallback) == */
"""
    profile = _parse_decompile_profile(stderr)

    ok, reason = _is_decompile_output_acceptable("unsigned f(void) { return y; }", stderr, profile)

    assert ok is False
    assert reason == "validation_failed"


def test_enum_union_fallback_is_enabled_by_default():
    assert "enum_union" not in DEFAULT_DECOMPILE_SKIP
    assert FALLBACK_EXAMPLE_REBUILD["enum_union"]["functions"] == ("token_cost", "combine_bytes")
    assert "token_cost(TOK_TWO)" in ENUM_UNION_HARNESS_MAIN


def test_msc6_example_gate_defaults_cover_all_functions_and_success_255():
    assert HARNESS_SUCCESS_EXIT_CODE == 255
    assert DECOMPILE_MAX_FUNCTIONS_DEFAULT == 0
    assert DEFAULT_DECOMPILE_SKIP == ()


def test_compare_harnesses_use_non_accidental_success_code():
    assert "return 255;" in COMPARE16_HARNESS_MAIN
    assert "return 255;" in COMPARE32_HARNESS_MAIN


def test_scalar_types_fallback_tracks_active_non_fpu_functions():
    functions = FALLBACK_EXAMPLE_REBUILD["scalar_types_io"]["functions"]

    assert "scale_float" not in functions
    assert "blend_double" not in functions
    assert functions == (
        "add_sc",
        "mix_uc",
        "sub_ss",
        "mul_us",
        "add_int",
        "rot_ui",
        "add_long",
        "sub_ulong",
        "pick_ptr",
    )


def test_medium_structs_has_function_fallback_contract():
    assert "medium_structs" not in DEFAULT_DECOMPILE_SKIP
    assert FALLBACK_EXAMPLE_REBUILD["medium_structs"]["functions"] == (
        "accumulate_pairs",
        "rotate_triplet",
        "find_first_gt",
    )
    assert "struct Pair" in FALLBACK_EXAMPLE_REBUILD["medium_structs"]["prefix"]
    assert "return 255;" in FALLBACK_EXAMPLE_REBUILD["medium_structs"]["harness"]


def test_function_fallback_decompile_timeout_is_structured_failure(monkeypatch, tmp_path):
    seen: dict[str, list[str]] = {}
    seen_timeout: dict[str, int] = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen_timeout["timeout"] = kwargs["timeout"]
        raise subprocess.TimeoutExpired(cmd, timeout=60, output="partial stdout", stderr="partial stderr")

    monkeypatch.setattr("scripts.build_msc6_examples._run", fake_run)

    ok, stdout, stderr, profile, command, function_name = _decompile_function_with_options(
        tmp_path / "FPTR.EXE",
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        function_name="select_and_apply",
    )

    assert ok is False
    assert stdout == "partial stdout"
    assert "decompile timeout" in stderr
    assert profile["timeout"] is True
    assert profile["acceptance_reason"] == "timeout"
    assert seen["cmd"][0] == sys.executable
    assert seen_timeout["timeout"] == _focused_decompile_process_timeout(60)
    assert profile["process_timeout_seconds"] == _focused_decompile_process_timeout(60)
    assert profile["analysis_timeout_seconds"] == 60
    assert "select_and_apply" in command
    assert function_name == "select_and_apply"


def test_explicit_function_fallback_failure_does_not_probe_whole_binary(monkeypatch, tmp_path):
    def fake_build_from_function_decompiles(*_args, **_kwargs):
        return False, False, None, "", "focused failure", "", "", "", "[]"

    def fail_whole_decompile(*_args, **_kwargs):
        raise AssertionError("whole-binary decompile should not run after explicit fallback failure")

    monkeypatch.setattr("scripts.build_msc6_examples._build_from_function_decompiles", fake_build_from_function_decompiles)
    monkeypatch.setattr("scripts.build_msc6_examples._decompile", fail_whole_decompile)

    result = _decompile_and_validate(
        tmp_path / "FPTR.EXE",
        tmp_path,
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=600,
        decompile_mode="functions",
        decompile_cod_path=None,
        decompile_max_functions=0,
        expected_exit_code=255,
        decompile_safe_names=("FPTR1.C", "FPTR1.OBJ", "FPTR1.EXE", "FPTR1.MAP"),
        decompile_fallback_rebuild={"functions": ("select_and_apply",), "harness": "int main(void) { return 255; }"},
    )

    assert result[0] is False
    profile = json.loads(result[-1])
    assert profile["acceptance_reason"] == "fallback_rebuild_failed"
    assert profile["fallback_rebuild"]["attempted"] is True


def test_function_fallback_retries_transient_asm_fallback(monkeypatch, tmp_path):
    calls: list[str] = []

    def fake_decompile_function_with_options(*_args, function_name, **_kwargs):
        calls.append(function_name)
        if len(calls) == 1:
            return False, "", "", {"acceptance_reason": "asm_fallback"}, "cmd1", function_name
        return True, "int f(void) { return 1; }", "", {"acceptance_reason": None}, "cmd2", function_name

    monkeypatch.setattr(
        "scripts.build_msc6_examples._decompile_function_with_options",
        fake_decompile_function_with_options,
    )
    monkeypatch.setattr(
        "scripts.build_msc6_examples._extract_decompiled_function_definition",
        lambda _text, _name: "int f(void) { return 1; }\n",
    )

    def fake_compile_and_link(_source_path, out_dir, **kwargs):
        (out_dir / kwargs["exe_name"]).write_bytes(b"MZ")
        return True, "", "", "", ""

    monkeypatch.setattr("scripts.build_msc6_examples._compile_and_link", fake_compile_and_link)
    monkeypatch.setattr("scripts.build_msc6_examples._run_example", lambda *_args, **_kwargs: (True, 255, "", ""))

    ok, recompiled, run_exit, *_rest = _build_from_function_decompiles(
        tmp_path / "TEST.EXE",
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        fallback_functions=("f",),
        fallback_harness="int main(void) { return 255; }",
        fallback_prefix="",
        decompile_c_name="TEST1.C",
        decompile_obj_name="TEST1.OBJ",
        decompile_exe_name="TEST1.EXE",
        decompile_map_name="TEST1.MAP",
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6",
    )

    assert ok is True
    assert recompiled is True
    assert run_exit == 255
    assert calls == ["f", "f"]


def test_extract_normalizes_undeclared_stack_arg_placeholders_to_signature_names():
    body = """int switch_fold(int x)
{
    if (!arg_4)
        return 10;
    if (arg_4 <= 2)
        return arg_4 + 20;
    return x - 5;
}
"""

    normalized = _normalize_extracted_function_arg_placeholders(body)

    assert "arg_4" not in normalized
    assert "if (!x)" in normalized
    assert "return x + 20;" in normalized


def test_extract_does_not_rewrite_declared_local_arg_placeholder():
    body = """int f(int x)
{
    int arg_4;
    arg_4 = x + 1;
    return arg_4;
}
"""

    normalized = _normalize_extracted_function_arg_placeholders(body)

    assert "int arg_4;" in normalized
    assert "return arg_4;" in normalized
