# Logical Reload Provenance Checkpoint

## Reason And Owner

Types/Lowering may replay a segmented reload only while its value and address
base remain unchanged. Two replay selectors compared optional instruction
addresses numerically. An addressless SSA instruction in a reload/use boundary
block raised `TypeError` instead of refusing unsupported ordering evidence.

The selectors now refuse unknown boundary ordering and retain the existing
code. In an intermediate CFG block whose position is proven by the path, an
addressless instruction still undergoes effect checks: calls, stores and base
register writes refuse replay; an inert instruction does not need an invented
address. No effect is removed, and no repair is introduced in postprocess.

The owner also now declares the actual angr architecture required by
`SimType.with_arch`, constructs register identities inside the field-validation
branch, and distinguishes definition-address sets from optional use provenance.
Its production file shrank by 17 lines.

## Acceptance And Failure

- DoD: missing boundary addresses refuse without exceptions or mutations.
- DoD: intermediate-block effects remain checked, including addressless calls,
  stores and writes to the memory base register.
- DoD: valid intervals replay; complete unified identities retain precedence,
  incomplete unified identities fall back, and wholly incomplete ones refuse.
- DoD: scoped tools, types/docs and architecture guards pass; the real DOS
  pipeline remains green; these tests run routinely rather than only manually.
- Failure: skip an unknown boundary, assume an address, replay across clobbers,
  change identity precedence, weaken typing, or regress generated-C validation.

## Evidence

- Before: 16 failed and 24 passed in 8.57s; all failures were optional-address
  comparisons raising `TypeError`.
- After: 54 focused tests passed in 10.11s, including the existing ten carrier
  tests and four identity-precedence controls. Reported individual durations
  were below 1s.
- Scoped Ruff `--fix`, MyPy and Pyright pass. Startup architecture and changed
  non-test types/docs pass. Pipeline/ownership/Make inventory: 118 passed.
- Global `quality-fast` still fails, but MyPy diagnostics fell from 11 to four:
  one in callsite prototype declarations and three in the postprocess bridge.
  This does not close the full suite, CI, or the numeric-frame defect.
- `quality-dev` remains red on the two cache/summary transport `Any` returns
  recorded in the preceding checkpoint. Its downstream gates did not run.
- Initial default pipeline: 2,606 unit tests passed in 138.54s plus QuickC and
  all seven MS C tiny round trips; all three lanes passed. Four identity tests
  were added after collection. The final-tree repeat passed **2,610 tests in
  102.44s** plus QuickC and all seven MS C tiny round trips; three lanes passed,
  none failed/skipped/timed out. Final architecture, types/docs and ownership
  checks also passed. These timings are not a controlled performance comparison.

Logs: `/tmp/inertia-reload-boundaries-{before,tests,mypy,pyright,quality,architecture,admission,pipeline,dev}.log`.
Final repeats: `/tmp/inertia-reload-boundaries-final-{pipeline,quality,architecture}.log`.

## Timing

Baseline completed 2026-09-09 00:35:57 +02:00; final focused tests completed
00:40:27 +02:00 (4m30s later). This excludes earlier investigation and is not
an estimate for the remaining P0 work.
Final default pipeline completed 00:44:29 +02:00, 8m32s after the baseline.
