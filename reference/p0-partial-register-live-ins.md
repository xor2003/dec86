# Partial Register Live-Ins (2026-09-08)

## Reason And Ownership

While tracing InitBars numeric register projection, the SSA live-in analysis
was found to treat every subregister definition as a full parent definition.
For example, writing SI incorrectly hid an incoming upper ESI word from a
later ESI read; writing AL hid AH. At CFG joins, different byte definitions
on different paths incorrectly appeared to define the same complete register.

`ir/register_live_in.py` now performs the must-reaching analysis on register
bits. Lowering supplies its existing register-view inventory and consumes the
result through `gp_live_in_names_from_ssa_8616`. The large Lowering module
loses the old analysis rather than gaining another semantic mechanism.
No call setup is deleted and no host pointer is converted to a numeric offset.

## Acceptance And Failure

DoD: preserve upper-bit and high-byte live-ins after partial writes, require
definitions of the same bits on every incoming path, and avoid spurious
live-ins after complete writes. Keep the existing materializer connected,
run focused/static gates and the default MS C pipeline, and wire new tests
into both the default lane and changed-file ownership.

Definition of failure: a partial write kills untouched bits; mutually exclusive
path writes are combined as if both executed; existing GP lowering regressions
fail; or generated-code acceptance is claimed from live-in unit tests alone.

## Evidence

- Before: five new regressions failed, three passed in 8.18s.
- After: 26 new and existing GP tests passed in 9.48s under pytest `-n 7`.
- Scoped Ruff `check --fix`, MyPy and Pyright pass for the production analysis
  and consumer; startup architecture passes.
- Default pipeline: 2,241 unit tests passed in 102.83s, all seven MS C tiny
  compile/run/decompile/recompile/run cases passed, three lanes passed.
  This run preceded adding the eight new regressions to the default target list.
- Slowest unit test: RunMenu ESC, 41.28s. These timings are not a controlled
  speed comparison; no performance improvement is claimed.
- Global quality-fast failed with 118 MyPy diagnostic lines. The tooling-only
  scoped check additionally exposes three ownership-manifest import/export
  errors under explicit package bases; without it, duplicate module discovery
  aborts the check. No suppression was added. Tooling Pyright and Ruff pass.
- The ownership tests exposed stale expected lists from prior stack-reload and
  call-result work. Expectations now retain those already-registered tests;
  a new assertion checks selection of the partial-register regression.

The live sidecar-free InitBars worker still reports `validation_failed` after
17.59s, with both whole-tail stages stable and the same pointer-to-AX error.
This closes a partial-register live-in defect, not the full SI/ESI audit or
InitBars acceptance. Numeric LEA projection remains the next semantic blocker.

Logs: `/tmp/inertia-gp-partial-before.log`,
`/tmp/inertia-gp-partial-after.log`, `/tmp/inertia-gp-partial-gates.log`,
`/tmp/inertia-gp-partial-pipeline.log`,
`/tmp/inertia-gp-partial-inventory-after.log`,
`/tmp/inertia-gp-partial-initbars.json`.

## Ownership Import Follow-Up

The scoped tooling MyPy failures above are now repaired. The manifest imports
`PytestSourceIndex` directly from its defining module and uses `TYPE_CHECKING`
to expose a single package import path to static analysis. Runtime package
versus direct-script dispatch is unchanged. This also resolves the duplicate
module discovery error in the scoped invocation without special MyPy flags.

Reason: changed-file gates must remain statically checkable without dropping
their supported command-line execution modes. DoD: both subprocess invocation
modes select identical tests, and scoped Ruff/MyPy/Pyright pass. Failure means
an import crash, changed selection, or remaining scoped typing errors.

Verification: 109 ownership/pipeline tests pass in 2.10s, including the two
new subprocess cases; all five slowest durations are below one second.
Scoped Ruff `check --fix`, MyPy and Pyright pass for the tooling pair.
Evidence: `/tmp/inertia-ownership-imports-tests.log`. Global quality-fast has
not been rerun, so the earlier 118-line global census is not revised here.

## Partial Zero-Idiom Proof

The follow-up callee-proof inspection found the same overlap-versus-coverage
mistake in `semantics/register_value_preservation.py`: a self-clear of AL or
AH was accepted as a clear of AX or its other byte. Eight regression cases
failed before the repair (11 passed, 8.02s). The semantic helper now requires
coverage of the queried view; full-word clears still cover either byte.
Existing call-result consumers receive this corrected proof without adding
recovery to their compatibility layer.

Reason: a partial clear cannot prove the incoming full-word return value dead.
DoD: reject byte-to-word and disjoint-byte clear proofs, retain word-to-byte
proofs, and keep the call-result value live after AL clearing followed by AX
use. Definition of failure: a false full-register clear, loss of the required
call result, or regression in existing zero-extension behavior.

The final focused run passes 20 tests in 16.56s. Scoped Ruff `check --fix`,
MyPy and Pyright pass; startup architecture passes. The touched Protocol
method stubs retain docs and explicit ellipses for static checking.
Logs: `/tmp/inertia-partial-clear-before.log`,
`/tmp/inertia-partial-clear-final.log`,
`/tmp/inertia-partial-clear-quality.log`,
`/tmp/inertia-partial-clear-pipeline.log`.
Broad gates completed: the default unit lane passed 2,249 tests in 119.96s,
and all three pipeline lanes passed, including seven MS C tiny round trips.
Global quality-fast remains red with 117 MyPy diagnostic lines. The zero-idiom
test file was added to the default lane after this run started; its 20 cases
passed separately above. Updated pipeline/ownership tests pass 109 cases in
2.22s. Both recurring target selection and changed-file ownership now include
the zero-idiom regression. This is not InitBars acceptance or full-suite closure.
