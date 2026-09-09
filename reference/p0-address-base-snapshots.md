# Address Base Snapshots (2026-09-09)

## Root Cause And Repair

VEX address decomposition retained a register name and folded displacement but
discarded the temporary containing the original register read. SSA subsequently
bound the address base to the register version current at the memory operation.
For PUSH, that is after SP has already been decremented.

The minimal numeric-frame reproducer therefore described its two saved-BP bytes
as `SP(version=1)-2` and `SP(version=1)-1`, although version 1 already equals
entry SP minus two. Following that provenance would subtract twice. The original
frontend execution remained correct; the error was in the IR address projection.

`ir/vex_addressing.py` now carries base values through decomposition and retains
the exact VEX Get temporary when traversing its RdTmp. Existing SSA temporary
snapshot handling selects the earlier register version. Folded displacement is
kept separately, without being applied to the captured base twice. Direct Get
and legacy fallback cases retain their existing current-register interpretation.
No heuristic assumes that all bases are instruction-entry values or version zero.

- Layer: IR, at the point where VEX address provenance was discarded.
- Reason: storage consumers must use the value that actually formed an address,
  not the same register's later contents.
- DoD: preserve exact read snapshots through arithmetic/casts, prove PUSH BP,
  PUSH SP, repeated PUSH and nested ENTER bases, retain importer/SSA contracts,
  and pass the default DOS pipeline.
- Definition of failure: bind an old read to a new register version, double-count
  an offset, force every SP access to version zero, alter frontend byte wrapping,
  or call this field-preservation repair completed numeric-frame decompilation.

The live probe after repair describes PUSH at 1000h using SP version 0 and
temporary 1 for both bytes, offsets -2/-1. POP at 100Eh uses SP version 3 and
temporary 99, offsets 0/1. This retains the distinction between instructions.

## Verification

All four new snapshot tests fail before the production change: four failures,
seven dependency warnings, 12.40s. Afterward, snapshot/frame/logical-memory tests
pass **62 tests**, seven warnings, 9.52s. The broader importer, SSA, partial-register,
stack-frame and worker-cache-budget selection passes **66 tests**, seven warnings,
13.20s. All reported individual durations are below one second.

The four snapshot regressions are admitted to Make's routine/broad selections
and the default pipeline. Ruff `check --fix`, scoped MyPy and scoped Pyright pass.
The combined `quality-hard quality-fast test-pipeline` command exits zero.
The fast lane passes 2,853 tests in 135.65s; the default unit lane passes
2,853 tests in 119.63s. All three executable quality guards, QuickC fixtures
and seven MS C tiny compile/decompile/recompile/run cases pass. The external
lanes take 46.088s and 67.872s respectively; these are pipeline lane times,
not full-suite duration. Global Make MyPy/Ruff and architecture/context checks
pass; existing complexity warnings remain visible.

A separate frozen-source full-suite refresh with `PYTHON_JIT=1`,
`PYTHONHASHSEED=0`, timeout scale 4 and `pytest -n 7 --dist loadgroup` reports
**10,794 passed, 37 failed, 170 skipped, 102 warnings in 792.10s**. JUnit records
11,001 tests, zero errors, start 09:27:52.807 +02:00 and 791.706s of suite time.
The changed source/test/Makefile hashes match across the audit. The preceding
45-failure report has ten failures no longer present; two new failures appear.
Both reproduce in isolation: two failed, ten passed in 8.70s.

- The documentation test expected policy text physically inside `AGENTS.md`.
  It now verifies the mandatory link and checks the authoritative referenced file.
- The indexed PUSH proof gained the exact BX-read MOV at 100Eh ahead of the
  existing definition chain at 100Bh. The test now checks both instruction
  addresses and the complete chain, retaining its word-load, segmented address,
  storage identity and closed-evidence assertions.

Both modules are now admitted to the routine pipeline rather than only Make's
larger inventory. Their corrected checks, the snapshot regressions and pipeline
tests pass **66 tests**, seven warnings, 9.83s; Ruff `check --fix` passes.
The final hard/fast/default gates exit zero after admission: **2,865 tests**
pass in the fast lane (105.62s) and default unit lane (109.53s). All three
executable guards pass. QuickC passes in 2.667s; all seven MS C tiny round trips
pass in 26.723s with original and rebuilt exit codes 255. These external timings
reuse existing caches and are not a claimed optimization. Ruff, global Make
MyPy, the changed-file type/doc ratchet and architecture/context checks pass;
known broader Pyright debt and complexity warnings remain documented.
No production code changed after the full audit. Do not infer a new full-suite failure count
from focused repairs or call the suite green.

The slowest full-suite cases remain TID show-range recovery (257.490s), InitMenu
pause guard (126.842s), DrawTime (121.181s), QuickSort (118.641s), and the EGAME2
open-file forwarding/signature checks (111.958s/110.508s). This is an audit under
existing cache state and seven workers, not a controlled performance experiment.
The full suite remains above the accepted duration budget; no timeouts or
diagnostics were weakened.

The checkpoint also preserves the concurrently modified tracked `SORTDEMO_.dec`
under the user's all-tree commit authorization. It reports 17 decompiled
functions and three fallbacks; it was not generated or accepted by this repair.

The direct minimal generated-C probe remains invalid: it still assigns `&v0`
to the numeric DS store bytes and retains a host pointer in the frame return.
This checkpoint does not claim function acceptance or generated-C recompilation.
Memory SSA still refuses SP-relative storage: proving its function-wide
coordinate and consuming frame pairs through Alias remain the next boundary.
No origin filter, frame deletion or Rewrite-stage repair was introduced.

## Independent Test Isolation Repair

A bounded delegated investigation reproduced the full-suite-only failure in
`test_run_function_work_item_uses_fork_lane_for_force_isolated_project`.
The earlier worker profiling test left `INERTIA_OTEL_PROFILE_IN_PROCESS=1`
in the pytest worker's environment. Fork eligibility then changed for later tests,
which tried the deliberately forbidden project rebuild.

The profiling fixture now seeds this variable through `monkeypatch`, allowing
normal teardown to restore its prior state. Production CLI behavior is unchanged.
The worker reported a failing sequential reproducer before the change, three
passing sequential-wrapper checks afterward, and two passing real node IDs
under `-n 7`. Parent review and the 66-test run include the corrected fixture.
This is not proof that every full-suite order-dependent failure is resolved.

## Execution Rules

The user-requested persistent workflow rules now live in
[agent-execution.md](agent-execution.md), referenced mandatorily by `AGENTS.md`
and the supplemental glossary. The first full gate caught the glossary's size
limit after the rules were added there; moving the detailed policy into the
dedicated file restores the full architecture and agent-context checks without
changing their limits. Understand-Anything auto-update remains disabled.

Evidence: `/tmp/inertia-address-snapshot-*`, `/tmp/inertia-frame-alias-after.log`,
`/tmp/inertia-frame-codegen-snapshot.log`,
`/tmp/inertia-full-20260909-address-snapshots.{log,xml}`, and
`/tmp/inertia-snapshot-audit-*`. Temporary probes are not committed.
