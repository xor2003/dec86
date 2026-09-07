# RunMenu Binary Callee Flag Effects

## Scope And Status

RunMenu (`0x102e0`) remains **open**. This checkpoint repairs one IR summary
transport defect, not the function's complete acceptance contract.

Investigation began around 2026-09-07 14:11 +02:00. The implementation and
focused checks ran from approximately 14:23 to 14:34; broader gate time is
recorded below separately. The checkpoint finished at 14:41 +02:00, roughly
30 minutes after investigation began. These are wall-clock observations, not a fabricated
historical focused-work total.

## Root Cause And Ownership

The binary-only callee summary exposed incoming flag reads but no overwrites.
At `0x12bc0`, a nested CALL precedes PUSHF. The nested callee overwrites incoming
status bits before that save. Without the overwrite summary, PUSHF appeared to
read the caller's stack-adjustment flags at `0x10302` and `0x1030e`.

The lifter suppression context was functioning: before the change, it consumed
30 of 30 classified candidates with zero failures. The two problematic ADD SP
sites were not candidates because the input summary conservatively kept them.
Their retained flag expressions subsequently reached C as invalid pointer
arithmetic. No source names or binary-specific addresses enter the fix.

- Frontend marks unknown and out-of-image successor edges incomplete; an
  omitted edge is not proof of return.
- IR retains decoded instruction prefixes and exact bounded CFG edges. It
  preserves the longest prefix across repeated visits, including successor
  evidence when equal-length visits carry different incoming bits.
- The existing Semantics CFG solver computes all-path overwrite intersections.
- The typed binary summary transports those overwrites to the existing callee
  resolver. No recovery was added to Lowering, Rewrite, postprocess, or CLI.
- Unknown effects, unresolved edges, and exhausted budgets refuse overwrite
  publication. Saved FLAGS reads remain visible even when a later instruction
  overwrites all bits. Traversal still stops when no incoming bits survive.

## Reason, DoD, And Failure

Reason: remove falsely live flag computations using binary evidence while
retaining every genuinely observed incoming status bit.

Checkpoint DoD: fail-before/pass-after summary and edge regressions; actual-byte
nested CALL/PUSHF tests; conservative branch, loop, partial-write, save-before-
overwrite, unknown-effect, and budget cases; scoped Ruff/MyPy; regular pipeline
enrollment; development and executable-pipeline gates.

Definition of Failure: a preserved input bit is classified as unobserved, an
incomplete path proves overwrites, an instruction budget is silently exceeded,
or generated code loses a required call, argument class, return, or CFG edge.
RunMenu itself is not fixed until validation passes, its generated C compiles,
and its required source-level behavior survives the function regression.

## Evidence

- Initial summary regressions: 2 failed, 5 passed in 8.04s.
- Out-of-image edge regressions: all four failed before the frontend repair.
- Focused summary/projection/frontend tests: 47 passed in 8.56s before adding
  three actual-byte nested-call cases to the regular pipeline.
- Scoped Ruff (`check --fix`) and MyPy pass for touched production modules.
- `make quality-dev PYTHON=./.venv/bin/python`: passed, including 2,065 pytest
  cases in 87.36s, the external smoke test, and CMP16/LOOPS/FPTR guards. This run
  preceded the final enrollment of summary/projection tests in the fast lane.
- The live after-change probe publishes 32 raw, normalized, classified, and
  materialized candidates, zero failures. Both ADD SP sites now have all
  status writes proven dead. The pointer-based flag equations disappear.
- The live function still exits 4: gcc rejects `switch (reg0<16>)`. That same
  malformed selector is present in the before-change output. ESC case 27 and
  its return remain present. Whole-tail comparison is clean, but overall
  `validation=failed` remains visible because recompilation fails.
- Default `make test-pipeline`: passed all three lanes. The expanded fast lane
  passed 2,092 tests in 90.63s. Ultra QuickC passed four selected fixtures with
  validation collected and passed (44.78s). All seven selected MS C tiny
  constructs passed their complete round trips (84.07s).
- The unit lane's 91.04s wall time exceeds its 30s budget. Both external lanes
  remain within their budgets. Correctness success is not performance closure.
- `quality-hard` passed: full architecture, scoped linters/typing, mypyc smoke,
  2,092 tests in 105.31s, external smoke, and all three executable guards.
- After adding the final within-block instruction-budget parameter cases,
  all 52 focused summary/projection/frontend tests pass in 8.83s; Ruff passes.
  The broad 2,092-test counts above precede those two extra parameter cases.

No end-to-end speedup is claimed: these runs were not controlled performance
repeats. The last source-stable full-suite census and global typing debt are
unchanged by focused results.

## Next Boundary

Trace the typed switch selector's register identity into its reaching value
and C materialization. The initial source lead is
`structuring/typed_switch_seqnode.py::_register_expression_8616`, which creates
a raw AIL register. This is a lead, not a proven root cause. Repair the earliest
owner with missing evidence, not the rendered selector text. Re-run the live
sidecar-free RunMenu regression before claiming function acceptance.
