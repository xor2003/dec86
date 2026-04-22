#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = REPO_ROOT / ".venv" / "bin" / "python"


FAST_CHECKS: tuple[str, ...] = (
    # Phase 0-1: accounting and actionable validation reports.
    "angr_platforms/tests/test_decompile_cod_dir_parallelism.py",
    "angr_platforms/tests/test_x86_16_tail_validation.py",
    "angr_platforms/tests/test_x86_16_validation_manifest.py",
    "angr_platforms/tests/test_x86_16_milestone_report.py",
    "angr_platforms/tests/test_x86_16_package_exports.py",
    # Phase 4: alias model.
    "angr_platforms/tests/test_x86_16_alias_api_and_widening_proof.py",
    "angr_platforms/tests/test_x86_16_alias_register_mvp.py",
    "angr_platforms/tests/test_x86_16_storage_domain_alias.py",
    # Phase 5: widening correctness.
    "angr_platforms/tests/test_x86_16_widening_model.py",
    "angr_platforms/tests/test_x86_16_word_global_store_widening.py",
    # Phase 6: segmented memory model.
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py",
    "angr_platforms/tests/test_x86_16_segmented_memory.py",
    "angr_platforms/tests/test_x86_16_segment_association.py",
    # Phase 7: traits, types, objects.
    "angr_platforms/tests/test_x86_16_access_trait_arrays.py",
    "angr_platforms/tests/test_x86_16_access_trait_policy.py",
    "angr_platforms/tests/test_x86_16_access_trait_strides.py",
    "angr_platforms/tests/test_x86_16_mypy_monkeytype_targets.py",
    "angr_platforms/tests/test_x86_16_monkeytype_tooling.py",
    "angr_platforms/tests/test_x86_16_type_equivalence_classes.py",
    "angr_platforms/tests/test_x86_16_stack_prototype_promotion.py",
    # Phase 8: readability without semantic change.
    "angr_platforms/tests/test_x86_16_readability_goals.py",
    "angr_platforms/tests/test_x86_16_readability_set.py",
)


CORPUS_CHECKS: tuple[str, ...] = (
    # Phase 9 and slower correctness checks. Keep these explicit: they are not
    # part of the tight edit-test loop, but they are the broader plan gate.
    "angr_platforms/tests/test_x86_16_smoketest.py",
    "angr_platforms/tests/test_x86_16_compare_semantics.py",
    "angr_platforms/tests/test_x86_16_corpus_scan.py",
    "angr_platforms/tests/test_x86_16_cod_samples.py",
    "angr_platforms/tests/test_x86_16_runtime_samples.py",
    "angr_platforms/tests/test_x86_16_sample_matrix.py",
    "angr_platforms/tests/test_x86_16_80286_verifier.py",
)


PY_COMPILE_CHECKS: tuple[str, ...] = (
    "decompile.py",
    "inertia_decompiler/cli.py",
    "scripts/decompile_cod_dir.py",
    "scripts/run_plan3_checks.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation.py",
    "angr_platforms/angr_platforms/X86_16/alias_model.py",
    "angr_platforms/angr_platforms/X86_16/widening_alias.py",
    "angr_platforms/angr_platforms/X86_16/widening_model.py",
)


def _python() -> str:
    return str(PYTHON if PYTHON.exists() else Path(sys.executable))


def _run(argv: list[str]) -> None:
    print("+", " ".join(argv), flush=True)
    subprocess.run(argv, cwd=REPO_ROOT, check=True)


def _run_check(argv: list[str], *, allow_failure: bool = False) -> int:
    print("+", " ".join(argv), flush=True)
    completed = subprocess.run(argv, cwd=REPO_ROOT, check=False)
    if completed.returncode and not allow_failure:
        completed.check_returncode()
    return completed.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the PLAN3 validation checks.")
    parser.add_argument(
        "--include-corpus",
        action="store_true",
        help="Also run the slower corpus/sample checks from PLAN3 phase 9.",
    )
    parser.add_argument(
        "--include-cod-sweep",
        action="store_true",
        help="After tests, run scripts/decompile_cod_dir.py on the COD corpus or selected COD subset.",
    )
    parser.add_argument(
        "--cod-dir",
        default="cod",
        help="COD corpus directory for --include-cod-sweep.",
    )
    parser.add_argument(
        "--cod-file",
        action="append",
        default=[],
        help="Limit --include-cod-sweep to one COD file. Can be repeated.",
    )
    parser.add_argument(
        "--proc-name",
        action="append",
        default=[],
        help="Limit --include-cod-sweep to one PROC name. Can be repeated.",
    )
    parser.add_argument(
        "--cod-timeout",
        type=int,
        default=3,
        help="Per-PROC decompiler timeout in seconds for --include-cod-sweep.",
    )
    parser.add_argument(
        "--cod-max-workers",
        type=int,
        default=1,
        help="Worker count for --include-cod-sweep.",
    )
    parser.add_argument(
        "--cod-max-memory-mb",
        type=int,
        default=4096,
        help="Per-worker memory cap for --include-cod-sweep.",
    )
    parser.add_argument(
        "--cod-subprocess-timeout",
        type=int,
        default=180,
        help="Scheduler wait timeout in seconds for --include-cod-sweep.",
    )
    parser.add_argument(
        "--allow-cod-failures",
        action="store_true",
        help="Keep the runner exit code clean after COD timeouts/failures, while still printing and writing COD artifacts.",
    )
    parser.add_argument(
        "--write-tail-validation-baseline",
        action="store_true",
        help="Pass --write-tail-validation-baseline through to scripts/decompile_cod_dir.py during --include-cod-sweep.",
    )
    parser.add_argument(
        "--no-py-compile",
        action="store_true",
        help="Skip Python syntax compilation checks.",
    )
    args = parser.parse_args(argv)

    python = _python()
    pytest_targets = list(FAST_CHECKS)
    if args.include_corpus:
        pytest_targets.extend(CORPUS_CHECKS)
    if not args.no_py_compile:
        _run([python, "-m", "py_compile", *PY_COMPILE_CHECKS])
    _run([python, "-m", "pytest", "-q", *pytest_targets])
    if args.include_cod_sweep:
        cod_command = [
            python,
            "scripts/decompile_cod_dir.py",
            args.cod_dir,
            "--timeout",
            str(args.cod_timeout),
            "--max-workers",
            str(args.cod_max_workers),
            "--max-memory-mb",
            str(args.cod_max_memory_mb),
            "--subprocess-timeout",
            str(args.cod_subprocess_timeout),
        ]
        for cod_file in args.cod_file:
            cod_command.extend(["--cod-file", cod_file])
        for proc_name in args.proc_name:
            cod_command.extend(["--proc-name", proc_name])
        if args.write_tail_validation_baseline:
            cod_command.append("--write-tail-validation-baseline")
        cod_returncode = _run_check(cod_command, allow_failure=args.allow_cod_failures)
        if cod_returncode:
            print(f"COD sweep exited with status {cod_returncode}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
