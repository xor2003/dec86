# Historical Failure Replay (2026-09-08)

## Scope And Results

Replayed 47 surviving nodes from the previous full-suite XML:
**44 failed, 3 passed, 14 warnings, 315.27 seconds**. This is not a full-suite
census and cannot detect new failures outside that selection.

The old INC/DEC node was renamed to
`test_cfg_context_retains_live_incdec_flags_for_typed_jcc`; its repair and
focused verification are recorded separately in the main plan. Initial replay
attempts collected no tests because the historical name no longer existed.
Serial collection exposed that error; those attempts provide no test evidence.

The three passing historical failures are:

- Whole decompiler architecture contract.
- Sidecar-free MSC6 signed-long scalar comparison at 65614.
- Sidecar-free InitBars binary stack-array preservation.

Remaining failures by module: CLI 15; SORTDEMO regressions 14; sample matrix 4;
heapsort widening 2; runtime support traces 2; one each in menu pointer table,
function discovery isolation, real compiler debug information, positive-BP
acceptance, tail callsite inventory, string corpus anchors, and caller cleanup.
All three selected InitMenu tests still fail.

## Confirmed Test Contract Repair

Three CLI assertions incorrectly expected attempt/failure-family diagnostics
on stdout. The output owner explicitly writes these messages to stderr,
matching the requested generated-C stdout contract. Tests now check stderr
and also assert stdout does not contain those diagnostics.

- Reason: test the required stream contract, not obsolete behavior.
- DoD: preserve failed/uncollected statuses and retry-stop assertions while
  checking the correct stream; all three focused cases pass. Met.
- Definition of failure: move diagnostics back to stdout, weaken status checks,
  hide a failure, or treat a diagnostic as generated C.
- Verification: 3 passed, seven dependency warnings, 19.05s under concurrent
  corpus load; Ruff `check --fix` passed. No production code changed.

The replay workers collected the old assertions before this test-only edit.
Its 44 failures therefore include these three subsequently passing tests.
Do not report a fabricated 41-failure full-suite result by subtraction.

## Timing And Next Work

Slowest replay cases: TIDShowRange 244.682s; named InitBars 126.222s;
RunMenu 103.293s; QuickSort 97.988s; InitMenu pointer table 95.453s.
These are JUnit phase durations, not serial contributions to wall time.

Next: inspect the other CLI failures individually, separating stream/fixture
contract mismatches from genuine rejection or timeout; retain InitMenu's
numeric stack-address/effect proof as an open semantic blocker. The broad
corpus remains far from acceptance despite a passing default pipeline.

Replay used `PYTHON_JIT=1 PYTHONHASHSEED=0`, timeout scale 4, `pytest -n 7
--dist loadgroup --durations=10 --tb=short --no-header -q`, with explicit
historical node IDs. Source unchanged during replay except the three test
assertions after collection. No clean-HEAD or timing-benchmark claim.

Temporary evidence: `/tmp/inertia-failure-refresh-current.xml`,
`/tmp/inertia-failure-refresh-current.log`, `/tmp/inertia-cli-stream-tests.log`.

## Runtime Switch Fixture Repair

Both runtime-support materializer failures were stale positive fixtures:
they supplied register-view metadata and flat case nodes, but neither an AIL
SSA definition nor a predicate reading that SSA version. The Structuring
owner correctly returned `missing_ail_switch_expr`. No recovery rule was relaxed.

The duplicate bridge tests now share a parameterized, nested conditional
ladder with an explicit reaching definition. Both entry points exercise valid
binding, absent definition, and mismatched SSA reads. Positive cases preserve
SSA varid, expression index, register width/offset, case-body identities, the
default break and external default. Negative cases retain the original ladder
and assert the closed selector-binding refusal counts.

- Reason: success must rest on actual selector proof, not a fabricated AX read.
- DoD: both bridge entry points preserve the proven selector and refuse missing
  or mismatched evidence; surrounding selector and runtime tests pass. Met.
- Definition of failure: change production to accept unbound selectors, drop
  the call/value identity requirement, or remove the original case/default checks.
- Verification: 50 passed, seven dependency warnings, 9.14s with `pytest -n 7`;
  all five slowest individual durations were under one second. Ruff passes.
- Global `quality-fast` remains red with 29 MyPy diagnostics. No new semantic
  acceptance, default-pipeline, full-suite or remote-CI result is claimed.
- Consolidation removes 37 net lines from the oversized test module. The old
  `test_pre_codegen_typed_switch_materializer_uses_loop_break_default_evidence`
  node is now covered by the parameterized bridge test, not silently skipped.

Evidence: `/tmp/inertia-switch-refusal-before.log` (two failures/two passes),
`/tmp/inertia-switch-contract-verified.log`,
`/tmp/inertia-switch-contract-quality.log`. Durations are measured checks,
not an estimate of total remaining plan time.

## DOS Argument Representation Tests

The four synthetic BP-based INT 21h tests expected obsolete `[bp+offset]`
placeholders. The collector now renders typed Capstone operands with explicit
SS identity and access width. Expectations now check `SEG_U8` for AL/DL and
`SEG_U16` for word arguments, preserving exact stack offsets, service IDs,
argument order, pointer/value positions, and modern/DOS API spelling.

- Reason: prevent tests from requiring loss of segment and width information.
- DoD: all four previously failing cases pass without changing production
  behavior; adjacent sample tests and Ruff pass. Met.
- Definition of failure: restore widthless assembly placeholders, flatten SS
  into DS, accept arbitrary argument text, or call this whole-C acceptance.
- Before: four failures, 9.35s. After: eight passed, 15 skipped, seven dependency
  warnings, 9.29s. All five slowest individual durations were under one second.
- Skips: missing sample-matrix manifest (3), optional IMOD.EXE (5), ISOD.EXE
  (5), and ICOMDO.COM (2). None of the four repaired synthetic cases skipped.
- No production changes or lines added to the oversized test module. These
  collector/API-spelling checks do not prove Alias stack-variable recovery,
  whole-tail equivalence, or generated-C recompilation.

Logs: `/tmp/inertia-dos-argument-before.log` and
`/tmp/inertia-dos-argument-final.log`. Full-suite/CI and InitMenu remain open.
