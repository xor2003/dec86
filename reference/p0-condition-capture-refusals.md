# Condition Capture Refusals (2026-09-08)

## Defect And Owner

IR condition capture filtered ConditionFailure out of its condition projection
and then unconditionally published zero failures. A valid condition in the
same block, or in another expected block, could make incomplete function-owned
evidence look complete. Exact-byte relifting repeated that loss and could cache
the apparent success. Synthetic regressions reproduced both paths before repair.
This is not a claim that a particular SORTD function exhibited the mixed input.

The IR capture now owns a shared, deterministic block-failure projection.
Fast capture refuses completion if any current-function block contains a typed
recovery failure. Exact relifting retains the same failure in its artifact and
counters using CONDITION_RECOVERY_FAILED. It is not cached as a success or as
an ordinary missing-condition result. Foreign-function failures are excluded.
The capture dictionaries now use the frontend's ConditionResult/ConditionSource
contracts instead of object; no casts or ignored type errors were added.

## Task Contract

- Reason: collected semantic refusals must survive every evidence projection.
- DoD: mixed successful/failed conditions cannot produce complete artifacts;
  failures elsewhere in the owned function also refuse; unrelated blocks do
  not contaminate results; retry does not reuse the failed artifact; valid
  capture reuse, state restoration, focused tests and default pipeline pass.
- Definition of Failure: dropping a refusal while reporting failure_count=0,
  marking partial evidence complete, disabling validation, treating source or
  names as proof, or moving condition recovery into Lowering/Rewrite.

## Verification

Failing-before: two capture cases, then the separate exact-relift regression.
After repair: 54 capture/relift/transfer tests pass in 19.83s, with seven
dependency deprecation warnings. Scoped Ruff, MyPy and Pyright pass.
The default pipeline passes all three lanes with no skips/timeouts, including
all seven MS C tiny compile/run/decompile/recompile/exit-code round trips.
Its unit lane passes 2,448 tests in 161.90s. The capture test module was then
added explicitly to the default inventory, with a permanent inclusion check;
the expanded unit-lane rerun passes **2,456 tests in 124.36s** with seven
dependency warnings, zero skipped lanes and zero timeouts. Its log and summary
are `/tmp/inertia-condition-failure-unit.log` and
`/tmp/inertia-condition-failure-unit-summary.json`. Scoped Ruff, MyPy and
Pyright also pass for the updated pipeline runner; `git diff --check` is clean.

`quality-fast` remains red with **92 MyPy diagnostic lines**, down from 94;
the capture's two dictionary-contract diagnostics are closed. Complete logs:
`/tmp/inertia-condition-failure-quality.log` and
`/tmp/inertia-condition-failure-pipeline.log`.
This checkpoint does not close InitMenu, full-suite failures or the full plan.
