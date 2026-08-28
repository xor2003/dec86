# Decompiler Runtime Optimization Plan

## Goal

Reduce cold, no-sidecar decompilation time without weakening semantic recovery,
tail validation, generated-C stability, type coverage, or layer ownership. The
next optimization is accepted only after the current correctness baseline is
green again.

Completed task bodies and rejected experiment logs were removed on 2026-08-28.
Git history through `3ca6f9497` retains their implementation and evidence.

## Current Evidence

- The latest cold default `sub_10ce0` run took 139.73 seconds and 691,464 KiB
  peak RSS. It emitted SHA-256
  `c18c611d72c4159c1eb501732c8c1fde2569490a0da36a0eaf6ee1773bce03a8`,
  but failed call-argument validation at callsite `0x10d2f`, target `0x107b8`:
  expected `BP+4`, actual `BP+5`. This is not an accepted baseline.
- The current focused regression set has 95 passing and 3 failing tests under
  `pytest -n 7`.
- Two failures recover a proven 32-bit call-return/stack comparison as a
  two-byte `SimStackVariable`. The low offset is correct (`BP-4`) but the width
  is not; this can truncate or mistype a 32-bit comparison.
- The third failure emits an explicit, semantically plausible condition,
  `if ((short)arg_4 <= 2)`, with one `return 0` and one `return 1`. Its current
  mismatch is the expected identifier `arg`, so it is a contract/naming gate
  until a focused semantic comparison proves otherwise.
- The latest direct-core profile records 166,496,618 calls and 91.848 profiler
  seconds. `_prime_structuring_validation_semantics_8616` owns 73.894 inclusive
  seconds, about 80% of the profile.
- Inclusive children of Structuring priming include segment/global
  materialization (22.727 seconds), segment/global semantic priming
  (20.996 seconds), the broad Lowering replay (14.216 seconds), runtime segment
  lowering (11.911 seconds), and direct-stack materialization (11.505 seconds).
  These values overlap and must not be added as independent costs.
- The shared deep C-AST iterator makes 2,088,147 calls and owns 23.440 seconds;
  child replacement owns 9.558 seconds. Query-index work is useful only when a
  current aggregate profile proves that a bounded consumer cohort reduces this
  total.
- Frontend lifting owns about 8.9 seconds and is secondary to Structuring
  replay on the current profile.
- `decompiler_postprocess_stage.py` is 17,846 lines. It is a major development,
  review, and typing cost, but postprocess is no longer the leading runtime
  owner. Extraction must follow the runtime-critical correctness work.
- CPython 3.14.7 exposes `sys._jit`, but this build reports both
  `is_available() == False` and `is_enabled() == False`; `PYTHON_JIT=1` is
  currently inert. mypyc remains the available native-compilation experiment.

All measurements are checkout-specific. Refresh them after correctness is
restored and before claiming a speedup.

## Remaining Problem Impact

| Priority | Problem | User-visible impact | Development impact |
| --- | --- | --- | --- |
| P0 | SORTD call argument is validated as `BP+5` instead of `BP+4` | Current generated C cannot be certified equivalent; a call can receive the wrong byte/word source | Blocks semantic acceptance of every pending optimization and makes wall-time comparisons non-authoritative |
| P0 | Proven 32-bit JCC stack pair is materialized as two bytes | A long comparison can be truncated or receive the wrong signedness/type | Two tests fail; the current compatibility decoder is consuming a width contract incorrectly |
| P1 | Structuring validation priming owns about 80% of direct-core profile time | Large functions decompile slowly and reach timeout/fallback more often | Dominates edit-run feedback and hides smaller optimization effects |
| P1 | Deep C-AST traversal owns 23.440 seconds | Adds latency to every large-function run | Encourages repeated ad hoc scans unless accepted mutation generations own index validity |
| P1 | Peak RSS is about 675 MiB for one cold large function | Aggressive outer parallelism can exceed the 2 GB aggregate budget | Four similar workers could consume about 2.7 GiB before overhead |
| P1 | The postprocess stage is 17,846 lines | No direct semantic failure, but ownership mistakes are easier to introduce | Slow comprehension, review, typing, and agent handoff |
| P2 | Boolean-condition test expects `arg`, output uses `arg_4` | Current observed output remains readable and has the expected branch/returns | Full test gate remains red until the naming contract or stale expectation is resolved |
| P2 | JIT is unavailable in the installed interpreter | No runtime improvement from `PYTHON_JIT=1` | Repeated JIT trials waste time; profile-guided mypyc is the only current native path |

## Acceptance Invariants

- Preserve `IR -> Alias -> Widening -> Types -> Structuring -> Rewrite`.
- Introduce storage width, call arguments, and condition semantics at their
  earliest authoritative owner, never in Rewrite or CLI fallback.
- Unknown evidence is `UNKNOWN_REFUSE`; it is never permission to delete code.
- Identical input and options produce deterministic C and status output.
- Every semantic change preserves required calls, branches, memory effects,
  return effects, and `validation=passed`.
- No test, validator, architecture check, ownership check, or typing rule is
  weakened to obtain a speedup.
- Every benchmark records command, revision/worktree state, wall time, peak
  RSS, output hash, function validation, and whole-tail validation.
- Keep aggregate decompiler worker memory at or below 2 GB.

## Ordered Work

### 1. Restore the Correctness Baseline

**Status:** in progress; blocks all performance acceptance

**Reason:** The current SORTD call-argument mismatch can change call semantics,
and the 32-bit JCC width regression can change long comparisons. Performance
work on a semantically rejected output is not an improvement.

**Work:**

- Trace the `0x10d2f -> 0x107b8` argument from binary IR through Alias stack
  identity, Widening, Types/Lowering, Structuring consumption, and validation.
- Fix the first authoritative coordinate owner that changes `BP+4` to `BP+5`.
  Do not patch the rendered call, validator, CLI, or postprocess text.
- Trace the proven adjacent two-word stack object consumed by the 32-bit JCC.
  Preserve the four-byte Widening/Types object instead of reusing a narrow
  same-offset `CVariable` in the compatibility decoder.
- Classify the boolean-condition failure by semantic equivalence. If `arg_4`
  is the canonical current argument name, update only the stale naming
  expectation; otherwise fix the authoritative argument declaration owner.
- Add focused negative tests for adjacent-but-unproved words, same-offset
  narrow subviews, changed call argument classes, and signed/unsigned long
  comparisons.
- Re-run the focused function regression before and after each semantic fix.

**DoD:** The 98-test focused set passes under `pytest -n 7`; the 32-bit operand
is a proved four-byte object; the boolean sample keeps one explicit condition
and both returns; the exact SORTD function and whole-file tail validation pass;
required calls and argument classes match binary evidence; a new cold baseline
records time, RSS, hash, and validation.

**Definition of Failure:** A coordinate or width is repaired in Rewrite, CLI,
rendered C, or validator policy; two adjacent words are widened without Alias
or Widening proof; a test is weakened before semantic equivalence is shown; a
required call/branch disappears; validation remains failed; or the fix depends
on SORTD addresses, names, source text, or sidecars.

### 2. Accept Pending Exact-Evidence Reuse

**Status:** implementation present; end-to-end acceptance blocked by Step 1

**Reason:** Equivalent-architecture condition relift reuse and the typed
assignment projection have focused evidence, but neither can be credited while
the shared semantic baseline fails.

**Work:**

- Re-run equivalent/fresh architecture cache tests and prove changed bytes,
  bit mode, semantic feature state, unknown architecture identity, incomplete
  artifacts, and LRU eviction still miss safely.
- Re-run assignment projection tests for missing, unique, and ambiguous
  outcomes. Ambiguous assignments remain fail-closed.
- Confirm the default route does not claim a 46.56-second assignment-scan gain
  when the legacy CLI stack rerun is disabled.
- Compare accepted output and validation after Step 1 without changing either
  implementation merely to match a historical hash.

**DoD:** Focused Ruff with `--fix`, strict mypy, architecture, ownership, and
pytest gates pass; equivalent fresh architectures perform zero repeated direct
lifts; assignment lookup uses one typed projection per accepted generation;
accepted SORTD output and both validation gates remain stable; only measured
owners receive performance credit.

**Definition of Failure:** Different lift semantics share a cache entry;
unknown architectures become equality-scoped; mutable or incomplete artifacts
are reused; duplicate assignments are guessed; CLI owns semantic stack
recovery; stale AST nodes survive a generation change; or a disabled code path
is credited with default-route speedup.

### 3. Publish Consumer-Specific Mutation Generations

**Status:** in progress; prerequisite for safe replay suppression

**Reason:** Exact full-AST fingerprints can prove stability but cost seconds on
productive Structuring rounds. Call order, object identity, and pass booleans
cannot prove that direct-stack or segment/global inputs are unchanged.

**Work:**

- Define typed mutation impacts for callsite summaries, stack objects,
  segment/global facts, declarations, condition artifacts, and subtree
  replacement.
- Publish generations only at the authoritative Structuring and Types/Lowering
  mutation owners.
- Route semantic consumers through one facade that records which generation
  each replay consumed.
- Retain exact AST witnessing only for paths not yet covered by authoritative
  generations.
- Keep closed counters for executed, changed, skipped-stable, and failed work.

**DoD:** At least one formerly repeated expensive replay is skipped without a
full-AST fingerprint; every relevant mutation advances the corresponding
consumer generation; counters close; focused mutation/misreport tests pass;
accepted C and both validation gates remain unchanged.

**Definition of Failure:** Stability is inferred from rendered text, call
order, object identity, or an unverified `changed` result; a relevant mutation
does not invalidate its consumer; generations are owned by CLI/Rewrite for
earlier semantics; accounting does not close; or productive work is skipped.

### 4. Reduce Structuring Validation Priming

**Status:** blocked on Step 3

**Reason:** Structuring priming owns 73.894 of 91.848 direct-core profiler
seconds. Its direct-stack, segment/global, runtime-segment, and broad replay
children are currently the largest feedback bottleneck, but earlier traces
showed productive rounds that cannot be removed by position alone.

**Work:**

- Capture each expensive consumer's exact input generation and mutation
  result inside the one productive stage-entry prime.
- Remove or narrow only a replay subsumed by a later authoritative replay with
  no intervening relevant generation change.
- Preserve productive early lowering needed by calls, returns, loops, and
  condition materialization.
- Keep the existing primed marker that makes later per-pass prime calls free.
- Re-profile after each bounded replay change.

**DoD:** Validation-prime cumulative time falls by at least 10%; at least one
duplicate direct-stack, segment/global, runtime-segment, or broad replay is
removed or narrowed; all productive rounds remain; exact output and validation
are stable; focused gates and an uncontended cold run pass below 2 GB RSS.

**Definition of Failure:** An owner boolean is the sole mutation witness; an
intervening mutation can be missed; another expensive whole-AST fingerprint is
added; productive Lowering is skipped; output/validation changes; or measured
prime time does not fall by at least 10%.

### 5. Bound Remaining C-AST Traversal

**Status:** pending after Steps 3-4 reprofile

**Reason:** The deep iterator owns 23.440 seconds and child replacement owns
9.558 seconds, but previous bounded cohorts reduced call counts without
materially reducing aggregate iterator time. More generic indexing is not
justified without a newly measured consumer.

**Work:**

- Re-profile after replay suppression and rank traversal consumers by
  cumulative time and call count.
- Add a typed query projection only for a read-only consumer with repeated
  queries over one accepted generation.
- Keep deterministic node order and explicit missing/unique/ambiguous results.
- Rebuild immediately after an accepted or witnessed mutation; mutating walks
  remain uncached.
- Stop a cohort if aggregate traversal time does not improve materially.

**DoD:** A current profile shows a material reduction in the 23.440-second
iterator owner; index construction occurs once per unchanged generation;
indexed and uncached results are equivalent; output, validation, determinism,
and the 2 GB memory budget are preserved.

**Definition of Failure:** Cached nodes survive mutation; a mutating consumer
receives cached nodes; semantic facts are inferred from C text or shape alone;
only a microbenchmark improves; aggregate traversal time is flat; memory is
unbounded; or ordering changes.

### 6. Make Validation Transactions Dirty-Pass Driven

**Status:** in progress

**Reason:** Validation is authoritative, but a provably stable pass should not
pay changed-pass regeneration, snapshot, cycle-scan, and tail-summary costs.
This follows Step 3 because reliable mutation generations are the safety
boundary.

**Work:**

- Finish extracting the guarded pass transaction into a typed postprocess
  orchestration owner.
- Use authoritative mutation generations plus the independent mutation witness
  to detect a pass that falsely reports stability.
- Delay expensive snapshots and summaries only where rollback safety permits.
- Share unchanged-generation cycle and traversal results.
- Preserve unconditional validation for reported or witnessed mutations.

**DoD:** Truly stable passes skip regeneration and tail-summary collection;
mutating and misreporting passes still snapshot, validate, and roll back;
metadata and AST restore coherently; focused snapshot, witness, and tail tests
pass; accepted output and validation remain stable.

**Definition of Failure:** Any mutation bypasses validation; rollback cannot
restore metadata and AST together; declaration or typed-input changes are
missed; validator strength is reduced; or saved work is not visible in a
current profile.

### 7. Split and Type the Postprocess Stage

**Status:** in progress; secondary runtime priority

**Reason:** The 17,846-line stage materially slows comprehension, review, type
checking, and safe agent work. Extraction must improve ownership rather than
move lines cosmetically, and it must not displace the current P0/P1 runtime
work.

**Work:**

- Extract the remaining pass transaction and validation-delta contracts to
  their authoritative postprocess/validation owners.
- Move Structuring/Lowering compatibility shims to their authoritative owners
  and delete redundant wrappers.
- Replace avoidable `getattr`/`setattr` on owned contracts with typed dot access.
- Keep new modules below 350 lines where practical and prevent net stage growth.
- Run strict mypy independently on every extracted production module.

**DoD:** The stage is materially smaller; every extracted module states
`Layer:` and `Responsibility:`, has explicit types and useful public docstrings,
and passes strict mypy; architecture/import/ownership tests pass; generated C
and validation remain unchanged.

**Definition of Failure:** Lines move without clearer ownership; casts hide an
untyped owned contract; semantic recovery moves into Rewrite; the stage grows;
public behavior exists only as implementation detail; or focused gates fail.

### 8. Compile Only a Reprofiled Hotspot With mypyc

**Status:** pending after Steps 3-7

**Reason:** Previous `c_ast_utils` and `vex_import` native experiments produced
no repeatable runtime gain and increased memory or build cost. mypyc is useful
only for a stable, strict-typed CPU hotspot that remains hot after algorithmic
work.

**Work:**

- Re-profile the accepted baseline after replay and traversal reductions.
- Select a small typed hotspot with low dynamic angr-boundary density.
- Compare source and native execution with identical input, caches, worker
  count, and validation.
- Preserve incremental native builds and Python fallback execution.

**DoD:** The candidate passes strict mypy and produces identical results; three
comparable runs show a repeatable hotspot or end-to-end gain exceeding
build/import overhead; RSS remains inside the aggregate budget; Python fallback
continues to pass.

**Definition of Failure:** A module is selected because it is merely large;
`Any` is hidden to satisfy mypyc; output or validation changes; build/startup
cost consumes the gain; memory materially regresses; or timing is noise.

### 9. Tune Outer Function Parallelism

**Status:** pending after single-function memory and time fall

**Reason:** Independent functions are the correct parallel boundary, but one
mutable function remains single-owner. At the current roughly 675 MiB peak per
large function, four equivalent workers can exceed the 2 GB budget.

**Work:**

- Compare 1, 2, 3, 4, and bounded N-1 workers on a multi-function binary after
  hotspot fixes.
- Enforce deterministic output ordering and an aggregate-memory-derived worker
  cap.
- Record utilization, wall time, peak aggregate RSS, failures, timeouts, and
  fallback counts.
- Keep focused pytest execution at `-n 7`; decompiler worker policy is a
  separate memory-bounded decision.

**DoD:** The default chooses the fastest stable setting within 2 GB; all
functions remain present; output order and hashes are deterministic; validation,
failure, timeout, and fallback counts do not regress.

**Definition of Failure:** A mutable AST is shared; memory is unbounded; timing
improves because functions disappear or fall back; output order changes;
timeouts increase; or worker overhead makes the default slower.

### 10. Final Regression and Performance Ratchet

**Status:** pending

**Reason:** Local microbenchmarks and profiler totals are diagnostic evidence,
not final proof that the decompiler improved.

**Work:**

- Run changed-file Ruff with `--fix`, strict typing, architecture, ownership,
  focused semantic tests, and `make quality-dev`.
- Run `make test-pipeline` before claiming semantic safety.
- Run the accepted cold target three times and report median, range, RSS,
  output hash, function validation, and whole-tail validation.
- Add a non-flaky performance ratchet only after variance is measured.

**DoD:** All required checks pass; three cold runs preserve semantic output and
show a repeatable material wall-time reduction; no function disappears; the
final evidence records remaining bottlenecks and bounded worker policy.

**Definition of Failure:** Any gate is skipped without disclosure; tests or
validators are weakened; timing uses one warm run; output or validation
regresses; or the ratchet is tighter than observed machine variance.

## Progress Rule

Work on the first incomplete step unless a blocker is explicitly recorded.
After every accepted change, update the relevant status and current evidence,
run changed-surface linters together, and re-run the focused semantic gate.
Re-profile before changing optimization targets. Remove completed step bodies
from this active plan; retain durable evidence in tests, typed contracts,
documentation, commit messages, and git history.
