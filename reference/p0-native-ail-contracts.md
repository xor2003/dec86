# Native AIL Contract Checkpoint

## Reason And Layer

The installed angr AIL represents expressions using a Rust enum-backed class.
Its Python variant markers support runtime `isinstance` checks but do not
provide Pyright with field narrowing. Return compatibility consequently had
23 diagnostics despite valid runtime variant checks. Changing import spelling
was previously rejected and was not repeated.

The frontend adapter `ailment_variant_access.py` now describes individual
native payloads. Three exact payload readers were extracted from return
compatibility. Consumers still check the actual AIL variant before accessing
its typed view; a matching Python object shape is not evidence of that variant.
No return, alias, stack-identity or validation policy moved into the adapter.
Register destinations still require both the exact offset and width.
Block iteration still supports generators, not just lists and tuples.

## Acceptance And Failure

- DoD: native register, temporary and constant readers retain accepted values
  and refuse wrong variants, widths, indices and lookalike objects.
- DoD: existing return and stack-provenance regressions remain green, including
  rejection of stack offsets lacking BP-variable evidence.
- DoD: Ruff with automatic fixes, MyPy, scoped Pyright, architecture guards
  and the default DOS pipeline pass; the broader Pyright count is refreshed.
- Failure: replace runtime variant checks with structural guessing, widen
  payloads to `Any`, discard generator-backed blocks, weaken diagnostics or
  alter semantic recovery to satisfy the type checker.

## Evidence

- Baseline: 41 focused tests passed in 9.48s.
- After: 50 focused tests passed in 9.65s, including nine new controls.
  Both runs reported seven dependency warnings and no test duration above 1s.
- Scoped Ruff `check --fix`, MyPy and Pyright pass.
- The global CI-mode Pyright command reports eight remaining errors, down
  from 31. Return compatibility has no remaining diagnostics. Structuring,
  function evidence inventory and helper ABI remain open.
- The first architecture check correctly refused the new unregistered module.
  It was added to the ordinary promoted inventory and both Make source lists,
  without an exemption. Its regression module is now in the routine pipeline
  and changed-owner selection.
- Fourteen architecture regression controls pass in 24.77s, including the
  guards against dynamic field access after native variant checks.
- `quality-hard` passes full architecture, the type/doc ratchet, 2,645 unit
  tests in 119.54s and all three executable quality guards. The type ratchet
  initially caught a missing future-annotations import; it was fixed.
- `quality-fast` passes global Make MyPy and Ruff, 2,645 tests in 93.59s and
  all three executable quality guards. Existing Lizard complexity warnings
  remain visible. Global Vulture also passes.
- Quality guards report one shared active import surface, not independent
  Python/native parity or a performance improvement.
- Hard-lane slowest tests: sidecar-free RunMenu ESC preservation, 45.17s;
  InitBars stack-array preservation, 40.69s; indexed-address parity inventory,
  26.55s. These are elapsed test durations, not new profiling conclusions.
- The default pipeline passes all three lanes with no skips or timeouts:
  2,645 unit tests in 99.43s, QuickC fixtures and all seven MS C tiny round
  trips. Each tiny report confirms build/run/decompile/recompile/rebuilt-run
  success and matching original/rebuilt exit codes (255).
- This is a typed frontend compatibility checkpoint, not numeric-frame
  semantic repair, full-suite closure or remote CI closure.

Logs: `/tmp/inertia-native-ail-{before,after,mypy,final-pyright,global-pyright,guard-tests,hard,fast,vulture,pipeline}.log`.

## Timing

Investigation began 2026-09-09 01:12:53 +02:00. By 01:26:49 +02:00 the
focused tests, scoped MyPy and global Pyright refresh had completed; the hard
gate was running. The elapsed 13m56s includes investigation and verification,
not just implementation. No completion ETA is inferred from this interval.
By 01:34:19 +02:00 both quality gates had completed and the default pipeline
had started, 21m26s after investigation began.
The default pipeline was verified complete at 01:37:57 +02:00, 25m04s after
investigation began. This is the checkpoint's measured elapsed duration,
including repeated gates, not a forecast for the remaining plan.
