# Preserve Tail Transfer Origin (2026-09-08)

## Root Cause And Layer

The recovery-metadata collector `collect_neighbor_call_targets` first recorded
CFG callsites, then decoded tail jumps. A shared seen-key set discarded the
decoded evidence whenever CFG had already recorded the same site and target.
Consequently a proven tail transfer could remain `CFG_RESOLVED_CALL`, including
a stale return address. This was a production bug, not an obsolete test.

The collector now uses an insertion-ordered mapping keyed by site and target.
Proven tail evidence refines only a generic CFG entry. Existing decoded call
evidence keeps precedence. Tail kind and absent return address stay coherent,
without duplicate edges or changed ordering. Existing image, external-target,
and function-entry checks remain mandatory.

This is the earliest owner of the merged transfer inventory. No semantic
recovery was added to Rewrite, postprocess, or CLI. The fix preserves decoded
evidence rather than introducing a new call/argument recovery rule.

## Acceptance

- Reason: validation and call consumers must not lose a proven transfer kind
  through duplicate suppression.
- DoD: one correctly typed entry survives CFG overlap for direct near/far and
  stored near tails; its return address is absent; missing entry evidence does
  not upgrade a generic CFG entry; adjacent callsite tests and DOS gates pass.
  Met for this collector repair, not for the whole SORTD goal.
- Definition of failure: guess function entries, override decoded calls with
  weaker evidence, duplicate an edge, keep a tail return address, or bypass
  tail validation to obtain passing C.
- Before: one failed, three passed, 8.46s. Focused after: 79 passed, seven
  dependency warnings, 8.72s. All five slowest durations were under one second.
- Scoped Ruff (`check --fix`), MyPy and venv-selected Pyright pass for the
  production module and touched Python configuration modules.
- `quality-fast` remains red with 29 MyPy diagnostics outside this module.

## Pipeline Evidence

Default pipeline passed all three lanes: 2,507 unit tests in 130.63s,
four QuickC fixtures with validation passed, and all seven MS C tiny complete
round trips. Lane wall times: 131.032s, 45.329s, and 74.897s respectively.

The tail-inventory regression was then admitted into default focused targets,
Make QA tests, and the analysis-helper ownership rule. Separate admission and
tail checks passed 68 tests in 11.00s. The completed 2,507-test lane used the
selection loaded before that admission; do not claim it included the new entry.
No full-suite, InitMenu, or remote-CI closure is claimed.

Temporary logs: `/tmp/inertia-tail-origin-before.log`,
`/tmp/inertia-tail-origin-tests.log`, `/tmp/inertia-tail-origin-admission.log`,
`/tmp/inertia-tail-origin-pipeline.log`, `/tmp/inertia-tail-origin-quality.log`.
Durations are measured checks, not a total-plan ETA or performance benchmark.
