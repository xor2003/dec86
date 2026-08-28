# Decompiler Runtime Optimization Plan

## Goal

Reduce cold, no-sidecar decompilation time without weakening semantic recovery,
tail validation, generated-C stability, type coverage, or layer ownership.
Optimize the largest measured wall-time owner first and reject speculative
caches or replay suppression that cannot demonstrate useful hits.

Completed task bodies and rejected experiment logs were removed on 2026-08-28.
Git history through `3ca6f9497` retains their implementation and evidence.

## Current Evidence

- The exact no-sidecar `sub_10ce0` regression now emits SHA-256
  `9047373bc10d3e1f485895af5fbd73831b03ef576d7afabf33cfa9080b0a85fd`,
  preserves the `0x10d2f -> 0x107b8` call as
  `sub_107b8(&g_0B4C[arg_4], &g_0B4C[arg_6])`, and reports
  `validation=passed` plus clean whole-tail validation for the focused
  function.
- The focused semantic regression set has 245 passing tests under
  `pytest -n 7`; strict mypy, Ruff with `--fix`, and the architecture import
  check also pass for the changed surface.
- Exact typed projection evidence now distinguishes the proven
  `DS:0x0B4C + (BP+6)*2` source from the adjacent but wrong `BP+4` source.
  Replaying the direct-stack consumer repairs the wrong projection and accepts
  the exact projection as already materialized.
- On the focused scheduler probe, 13 direct-stack requests changed on every
  replay before this slice. They now close as 5 changed, 3 stable, and 5
  skipped, with 8 executions and no failures. The five skipped requests still
  pay full-AST regeneration because their caller has no covered consumer
  generation scope yet.
- A current ordinary warm run takes 63.82 seconds and about 344 MiB RSS. The
  accepted post-change run took 68.35 seconds and 678,680 KiB RSS while
  preserving the accepted hash and both validation gates, so this slice has no
  end-to-end timing credit yet. A
  timing-heavy owner run takes 75.03 seconds and about 676 MiB RSS, so debug
  instrumentation materially affects both runtime and memory.
- Current wall-clock component timing attributes about 9-10 seconds to all
  segment/global materialization, but late stable replays contribute only
  about 1 second. The first replay contributes 4.52 seconds, including 2.60
  seconds of indexed lowering and 1.26 seconds of runtime segment lowering.
- The first semantic convergence, validation priming/snapshots, and
  post-validation render stabilization cost roughly 9, 7, and 8 seconds
  respectively. The render stabilization phase repeats direct-stack and
  segment/global consumers after AST regeneration and is the next bounded
  optimization target.
- A current cProfile run records 307,317,122 calls and 226.377 profiler seconds,
  but it inflates segment/global materialization to 35.381 seconds while direct
  wall timing measures about 9-10 seconds. cProfile remains useful for call
  relationships, not standalone acceptance timing.
- An exact byte/CFG raw-IR registry experiment produced 20 lookups and zero
  hits on the target path. It was fully removed under the Definition of
  Failure; no hashing overhead remains.
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
| P1 | Validation/render stabilization rebuilds full ASTs before stable semantic consumers can be skipped | Large functions decompile slowly and reach timeout/fallback more often | Five direct-stack requests now skip their consumer work, but still pay the dominant AST-regeneration cost |
| P1 | Cold indexed Alias/Widening context construction relifts the function census | Cold no-sidecar runs remain much slower than stable-cache runs | Frequent Alias/Widening edits invalidate the correct source-scoped persistent cache |
| P1 | Deep C-AST traversal remains a major profiled owner | Adds latency to every large-function run | Encourages repeated ad hoc scans unless accepted mutation generations own index validity |
| P1 | Instrumented peak RSS reaches about 676 MiB for one large function | Aggressive outer parallelism can exceed the 2 GB aggregate budget | Four similar workers can exceed the budget before process overhead |
| P1 | The postprocess stage is 17,846 lines | No direct semantic failure, but ownership mistakes are easier to introduce | Slow comprehension, review, typing, and agent handoff |
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

### 1. Publish Consumer-Specific Mutation Generations

**Status:** in progress; exact direct-stack projection reuse accepted, but its
caller still lacks a complete authoritative generation scope

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
- Preserve the accepted direct-stack projection matcher: it uses instruction
  provenance plus destination and source storage identity, rejects adjacent
  machine-BP offsets, and never relies on rendered names or text.
- Move the next skip boundary ahead of full-AST regeneration only after every
  relevant mutation in that caller advances the direct-stack consumer
  generation.

**DoD:** At least one formerly repeated expensive replay is skipped without a
full-AST fingerprint; every relevant mutation advances the corresponding
consumer generation; counters close; focused mutation/misreport tests pass;
accepted C and both validation gates remain unchanged.

**Definition of Failure:** Stability is inferred from rendered text, call
order, object identity, or an unverified `changed` result; a relevant mutation
does not invalidate its consumer; generations are owned by CLI/Rewrite for
earlier semantics; accounting does not close; or productive work is skipped.

### 2. Reduce Structuring Validation Priming

**Status:** blocked on Step 1

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

### 3. Bound Remaining C-AST Traversal

**Status:** pending after Steps 1-2 reprofile

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

### 4. Make Validation Transactions Dirty-Pass Driven

**Status:** in progress

**Reason:** Validation is authoritative, but a provably stable pass should not
pay changed-pass regeneration, snapshot, cycle-scan, and tail-summary costs.
This follows Step 1 because reliable mutation generations are the safety
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

### 5. Split and Type the Postprocess Stage

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

### 6. Compile Only a Reprofiled Hotspot With mypyc

**Status:** pending after Steps 1-5

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

### 7. Tune Outer Function Parallelism

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

### 8. Final Regression and Performance Ratchet

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
