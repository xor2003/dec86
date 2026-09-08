# Pyright Boundary And Audit Checkpoint

## Reason And Owners

The earlier eight-error count covered only Make's first failing Pyright batch,
not the whole repository. Closing it exposed 29 diagnostics in the next batch.
The first two root-module batches now pass. The configured whole-scope audit
has now finished; its full results are below. Do not report a fail-fast
command's last batch count as a repository total.

Changes preserve the existing layer boundaries:

- Frontend function-inventory protocols now have explicit abstract stub bodies.
- The helper ABI owner verifies that architecture binding still returns a
  function type before exposing it to consumers.
- Types/Lowering owns fixed-stack-probe replay and reads the supplied codegen's
  current project. Structuring binds that consumer without semantic recovery.
- Structuring's effect tuple and accepted-history list have explicit element
  types. Existing runtime classification and acceptance decisions are unchanged;
  previous history entries are retained rather than filtered.

## Acceptance And Failure

- DoD: the eight previously observed diagnostics disappear with no new `Any`,
  suppression, weakened check or semantic recovery in Rewrite.
- DoD: callback replay preserves project/codegen identity and its result;
  invalid helper binding refuses; accepted-history entries retain identity.
- DoD: focused tests, hard/fast quality gates and the default DOS pipeline pass.
- DoD: audit scope and early termination are explicit in all counts.
- Failure: mistake a clean early batch for global closure, discard diagnostic
  history, capture obsolete callback state or accept a non-function prototype.

## Evidence So Far

The initial focused run found a stale closure fixture (81 passed, one failed).
It lacked the `cfunc.statements` consumed by production's final pruning step.
The replacement verifies pruning follows materialization and checks all four
combinations of their change results, without weakening production.

The final focused run passes 94 tests in 11.97s with seven dependency warnings;
all reported test durations are below 1s. Scoped Ruff `--fix`, MyPy and Pyright
pass. The helper ABI, fixed-probe and complete structuring-validation modules
are admitted to the routine pipeline and Make inventories. `quality-hard`
passes with 2,736 unit tests in 142.54s and all three executable quality guards.
Global Vulture passes. The slowest hard-lane tests are RunMenu ESC preservation
(60.60s), InitBars stack-array preservation (59.14s) and indexed-address parity
(34.96s). These ran concurrently with a broad typing audit and are not a
controlled performance comparison. `quality-fast` also passes global Make
MyPy/Ruff, 2,736 unit tests in 99.36s and all three executable quality guards.
The guards report a shared active import surface, not independent native/Python
parity. Existing Lizard complexity warnings remain visible.

The default pipeline passes all three lanes with no skips or timeouts:
2,736 unit tests in 105.84s, QuickC and all seven MS C tiny round trips. Each
tiny report confirms successful compilation, decompilation, recompilation and
execution, with matching original/rebuilt exit codes of 255.

## Complete Configured-Scope Audit

Command: `PYTHON_JIT=1 CI=1 make pyright-all PYTHON=./.venv/bin/python PYRIGHT_WATCH=0`.

Result: **8,031 errors and 37 warnings**, with normal diagnostic failure (no
timeout or OOM). Per diagnostic location: **153 X86_16 errors, 28 CLI errors,
7,850 test errors**. These are static diagnostics, not failing pytest counts.
The configured scope includes X86_16, `angr_platforms/tests` and
`inertia_decompiler`; auxiliary scripts outside those paths are not covered.

Prioritize the 181 non-test diagnostics without disabling test diagnostics.
The largest non-test groups are register dependencies (19), structuring
codegen (13), CLI function-extent repair (9), segmented global loads (8),
physical registers (8), prototype seeding (7), runtime support (7) and DOS
interrupt ABI (6). Inspect runtime contracts and native boundaries before
choosing a fix; these counts are not evidence that all diagnostics are bugs.
Keep memory/processor/stack symbolic-value errors ahead of cosmetic cleanup.

DoD for subsequent typing work: all requested batches or the documented whole
scope execute, complete exit/count evidence is retained, touched non-test
contracts remain typed/documented, and focused plus DOS gates pass.
Failure: treat an early batch count as total, drop code or evidence to make a
type checker pass, or relabel static diagnostics as behavioral failures.

Logs: `/tmp/inertia-remaining-types-{final-tests,mypy,pyright,global-pyright,hard,fast,vulture,pipeline}.log`
and `/tmp/inertia-pyright-all-20260909.log`.

## Timing

Initial focused run launched 2026-09-09 01:40:35 +02:00. By 01:45:14 +02:00
the 94-test focused run and first-three-batch Pyright audit had finished.
This is 4m39s elapsed verification/implementation time, excluding initial
inspection, not an ETA for P0.
The whole-scope audit was verified complete by 01:51:12 +02:00, 10m37s
after the initial focused command launched.
The default pipeline was verified complete at 01:56:33 +02:00: 15m58s after
the initial focused command launched. This closes the bounded eight-error
repair and test-admission checkpoint, not overall typing or P0.
