# Full-Suite Refresh (2026-09-08)

## Census

**10,351 passed, 48 failed, 170 skipped**, 36 warnings, 10,569 total;
753.15 seconds, exit 1. This is the full configured collection, not the curated
default pipeline. It supersedes the September 7 census for remaining failures,
not any requirement for zero failures. The changed test population prevents
treating the one-failure net reduction as a completion percentage.

Command:

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=4 \
  ./.venv/bin/python -m pytest -n 7 --dist loadgroup --durations=10 \
  --tb=short --no-header -q --junitxml=/tmp/inertia-full-20260908-refresh.xml
```

Full output: `/tmp/inertia-full-20260908-refresh.log`; node-level failures and
timings are in the XML. No source edits or concurrent lint builds during the
run. The tracked Python/Makefile/pyproject diff hash was identical before/after:
`75f5a3a99bd1e28121cd723400e524c7faf45f808693d01195628a786f66ae6c`.
This hash does not attest untracked files. No pristine-HEAD or cold-cache claim.

## Failures By Module

Paths below are under `angr_platforms/tests/`.

| Module | Failed |
| --- | ---: |
| test_x86_16_cli.py | 15 |
| test_x86_16_sortdemo_regressions.py | 15 |
| test_x86_16_sample_matrix.py | 4 |
| test_x86_16_heapsort_widening_regression.py | 2 |
| test_x86_16_runtime_support_traces.py | 2 |
| test_x86_16_sortd_menu_pointer_table.py | 1 |
| test_cli_function_discovery_isolation.py | 1 |
| test_decompiler_architecture_check.py | 1 |
| test_x86_16_debug_info_real_compilers.py | 1 |
| test_x86_16_msc6_cmp32_regression.py | 1 |
| test_x86_16_msc_caller_cleanup.py | 1 |
| test_x86_16_sortdemo_positive_bp_acceptance.py | 1 |
| test_x86_16_status_flag_lift_context.py | 1 |
| test_x86_16_string_corpus_anchors.py | 1 |
| test_x86_16_tail_callsite_inventory.py | 1 |

## Immediate Priorities

1. Close the new IR module's full architecture-admission diagnostics; startup
   checks alone missed them. DoD: full architecture checker and its regression
   pass. Failure: weakening ownership/header or Make admission requirements.
2. Recheck InitMenu alongside InitBars. Two sidecar-free InitMenu cases now
   fail GCC on pointer operands to bitwise AND; the named case fails whole-tail
   guard/helper-call validation. Earlier focused passes are not current proof.
   Reason: the numeric register/object projection problem is not confined to
   InitBars. DoD: all named and sidecar-free regressions validate and compile.
   Failure: pointer casts, unproven DCE, or accepted changed/uncollected tails.
3. Trace the MSC6 signed-long comparison payload mismatch. Its diagnostic
   reports a signedness-only condition fingerprint delta, followed by worker
   status `ok` and `validated_payload_mismatch`. DoD: one coherent accepted
   payload with matching proofs, preserving 32-bit comparison behavior.
   Failure: bypassing the payload-integrity rejection or stripping casts blindly.
4. Then handle the remaining semantic and fixture batches from the previous
   audit, using this XML as the current node inventory. Do not equate text
   assertion failures with obsolete tests without inspecting typed behavior.

## Slowest Tests

JUnit durations include each test's measured phases and are not serial sums.

| Case | Seconds |
| --- | ---: |
| TIDShowRange layout logic | 228.78 |
| openFileWrapper direct forwarding | 165.60 |
| openFileWrapper helper declarations | 147.79 |
| named InitMenu pause guard | 119.79 |
| DrawTime clock return materialization | 107.54 |
| QuickSort pivot/recursive calls | 106.86 |
| InsertionSort word stores | 91.72 |
| openFileWrapper recoverability | 87.89 |
| sidecar-free InitMenu pointer table | 84.49 |
| RunMenu switch artifacts | 81.01 |

Worker snapshots showed active CPU-bound decompiler children, not an idle
runner. Several tests repeat the same executable/function under different
contracts. Sharing immutable results may help later, but no duplicate test is
removed here. Performance Step 10 remains deferred.

GitHub was checked live: latest pushed run 34141065397 on `511b0d3cb` remains
failed. The local changes are not remote-CI acceptance.

## Post-Audit Admission Repair

The four architecture diagnostics are addressed by the required IR ownership
header, future annotations and explicit type aliases, promotion inventory,
Make typed/Ruff admission, and QA admission of the two new regression files.
No checker was relaxed. Full architecture checks and direct-script startup
checks pass. Scoped Ruff and Pyright pass; scoped MyPy passes with explicit
package bases. The checker now uses `TYPE_CHECKING` to avoid duplicate branch
bindings while preserving direct-script runtime imports. Without explicit
package bases the standalone MyPy invocation still encounters duplicate module
discovery through dependencies; no global typing closure is claimed.

The original 48-failure census remains the historical result of the complete
run. Do not silently subtract focused repairs from it and call that a rerun.
Evidence: `/tmp/inertia-gp-admission-closed.log`,
`/tmp/inertia-gp-admission-direct.log`,
`/tmp/inertia-gp-admission-verified.log`.
