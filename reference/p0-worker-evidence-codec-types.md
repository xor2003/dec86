# Worker Evidence Codec Types (2026-09-08)

## Scope And Repair

The segment-program evidence decoder passed unvalidated nullable dictionary
values to four string enum constructors. This caused four global MyPy errors.
Its schema check also accepted `true` and `1.0` as schema version `1` because
Python equality treats those values as equal.

`segment_program_layout_codec.py` now consumes its existing strict integer
parser for the schema and a typed required-string parser before enum
construction. Optional string fields share the same nonempty-string check.
Invalid required fields identify the access/transfer field in their error.
No enum values, evidence counters, segment facts, or validation verdicts are
invented or relaxed.

The adjacent callsite codec now returns the typed `summary.to_dict()` result
directly, removing a redundant cast and its unused import. This is transport
contract cleanup, not callsite recovery or semantic materialization.

- Reason: worker evidence must enter the program join through a checked typed
  boundary; missing type annotations or unchecked casts are not a solution.
- DoD: reject noninteger schema versions, report missing/invalid required enum
  fields, preserve valid evidence round trips and closed-counter refusals,
  pass focused transport/cache tests and scoped tools, and measure broad gates.
- Definition of failure: accepting malformed evidence, coercing arbitrary
  values to strings, bypassing enum validation or closed-counter checks,
  silencing typing diagnostics, or calling a scoped pass global closure.

## Verification

Before: 14 failed, 8 passed in 8.27s. Two failures demonstrate accepted boolean
and floating-point schema values; twelve concern field-specific diagnostics
for invalid enum inputs, not previously accepted enum values.

After: 82 tests passed in 9.75s across segment-program layout, callsite codec,
serial worker cache, and test-pipeline tests. Scoped Ruff `check --fix`, MyPy,
and Pyright passed. Existing valid round trips and counter-integrity refusal
tests remain in that selection. Segment-program layout tests were added to
the default pipeline; they were already in QA and changed-file ownership.

Logs use `/tmp/inertia-segment-codec-types-` with suffixes `before.log`,
`final.log`, `mypy-final.log`, `pyright-final.log`, `quality.log`, and
`pipeline.log`. No InitBars repair, full-suite acceptance, or remote CI
acceptance is claimed here.

Global quality-fast still exits two, but its MyPy diagnostics fall from 116
to 111; neither touched codec appears in the remaining diagnostics. Default
test-pipeline passes all three lanes, including 2,345 unit tests in 116.73s
and all seven MS C tiny compile/run/decompile/recompile/run cases. The slowest
unit test was sidecar-free RunMenu ESC preservation at 41.67s, followed by
the reviewed indexed-address inventory at 23.34s.

Local timeline (2026-09-08, UTC+02:00): failing regressions 11:11:51-11:12:00;
final focused tests 11:13:33-11:13:43; default pipeline 11:14:00-11:17:40.
From first regression execution to terminal pipeline: about 5m49s, excluding
preceding investigation. This is measured batch duration, not a remaining-goal
estimate.
