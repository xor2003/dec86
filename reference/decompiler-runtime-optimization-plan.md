# Decompiler Runtime Optimization Plan

## Goal

Reduce cold, no-sidecar decompilation time without weakening semantic recovery,
tail validation, generated-C stability, type coverage, or layer ownership.
Optimize the largest measured wall-time owner first and reject speculative
caches or replay suppression that cannot demonstrate useful hits.

Completed task bodies and rejected experiment logs were removed on 2026-08-28.
Git history through `3ca6f9497` retains their implementation and evidence.

## Current Evidence

- In the current shared-worktree snapshot, the exact no-sidecar `sub_10ce0`
  regression emits SHA-256
  `14d97d8ac34d7b95308a8855a18224c76cf2251f151304b7c265791222dc808c`,
  preserves the `0x10d2f -> 0x107b8` call as
  `sub_107b8(&g_0B4C[arg_4], &g_0B4C[arg_6])`, and reports
  `validation=passed` plus clean whole-tail validation for the focused
  function.
- The focused semantic regression set has 245 passing tests under
  `pytest -n 7`; strict mypy, Ruff with `--fix`, and the architecture import
  check also pass for the changed surface.
- The timing-cache policy passes its focused and owned changed-surface gates;
  strict mypy and Ruff pass for all five touched production modules.
- Timing diagnostics now preserve upstream discovery/evidence cache identity
  while refusing direct, serial-worker, and function-result C reuse. An
  accepted repeated run fell from 160.85 to 46.90 seconds wall and from 119.01
  to 41.02 seconds decompilation, at 304,876 KiB RSS, with live stage timings,
  identical current C, and both validation gates passing.
- Current segment/global materialization totals about 8.2 seconds. Its first
  productive replay costs 4.74 seconds: indexed lowering is 2.61 seconds and
  runtime segment lowering is 1.39 seconds. The latter spends about 0.75 seconds
  in positive-BP argument materialization, including 0.713 seconds on the first
  all-caller argument-width census. Late stable replays total under one second.
- The first indexed replay spends 2.40 seconds collecting project-wide global
  object source evidence. The artifact is cached only inside one project, so
  each isolated function worker rebuilds the same all-caller evidence.
- An opt-in clean-worker cProfile of the six-function CMP16 sweep attributes
  17.64 of 33.95 profiled seconds in its slowest worker to Structuring
  validation priming, including 5.79 seconds of callsite-summary work and 2.09
  seconds of callee argument evidence. All six generated functions validate.
- `decompiler_postprocess_stage.py` is 17,846 lines. It is a major development,
  review, and typing cost, but postprocess is no longer the leading runtime
  owner. Extraction must follow the runtime-critical correctness work.
- CPython 3.14.7 exposes `sys._jit`, but this build reports both
  `is_available() == False` and `is_enabled() == False`; `PYTHON_JIT=1` is
  currently inert. mypyc remains the available native-compilation experiment.

All measurements are checkout-specific; refresh them after correctness is restored before claiming a speedup.

## Remaining Problem Impact

| Priority | Problem | User-visible impact | Development impact |
| --- | --- | --- | --- |
| P1 | Project-wide global-source and callee-arity evidence is rebuilt in every isolated worker | Adds about 3.1 seconds per affected function and repeats whole-program caller work | Whole-binary parallel runs duplicate the same immutable evidence in each process |
| P1 | The first productive segment/global replay costs about 4.74 seconds | Large functions remain slow even with stable evidence caches | Indexed and runtime-segment owners dominate the remaining semantic replay time |
| P1 | Cold indexed Alias/Widening context construction relifts the function census | Fully invalidated no-sidecar runs remain much slower than stable-cache runs | Alias/IR/Widening edits legitimately rebuild a roughly 30-second program artifact |
| P1 | Stable semantic consumers still rebuild full AST witnesses before some skips | Large functions decompile slowly and reach timeout/fallback more often | Five direct-stack requests skip consumer work but still pay generation cost |
| P1 | Deep C-AST traversal remains a major profiled owner | Adds latency to every large-function run | Encourages repeated ad hoc scans unless accepted mutation generations own index validity |
| P1 | A fully invalidated run reaches about 677 MiB RSS | Aggressive outer parallelism can exceed the 2 GB aggregate budget | Four cold workers can exceed the budget before process overhead |
| P1 | The postprocess stage is 17,846 lines | No direct semantic failure, but ownership mistakes are easier to introduce | Slow comprehension, review, typing, and agent handoff |
| P2 | JIT is unavailable in the installed interpreter | No runtime improvement from `PYTHON_JIT=1` | Repeated JIT trials waste time; profile-guided mypyc is the only current native path |

## Acceptance Invariants

- Preserve `IR -> Alias -> Widening -> Types -> Structuring -> Rewrite`.
- Introduce semantics at their earliest authoritative owner, never in Rewrite
  or CLI fallback.
- Unknown evidence is `UNKNOWN_REFUSE`; it is never permission to delete code.
- Identical input and options produce deterministic C and status output.
- Preserve calls, branches, memory/return effects, and `validation=passed`.
- No test, validator, architecture check, ownership check, or typing rule is
  weakened to obtain a speedup.
- Benchmarks record checkout, command, wall, RSS, C hash, and validation.
- Keep aggregate decompiler worker memory at or below 2 GB.

## Ordered Work

### 1. Persist Project-Wide Caller Evidence

**Status:** pending coordination with the active indexed-evidence transport work

**Reason:** The first indexed replay spends 2.40 seconds rebuilding immutable
global-source evidence, while the first runtime replay spends another 0.713
seconds rebuilding callee arity/width evidence. Neither all-caller artifact
crosses the persistent parent/worker boundary.

**Work:**

- Add typed codecs for complete global-source and callee arity/width evidence.
- Extend the coherent project-evidence bundle so layouts, ranges, source facts,
  and caller-interface facts share one schema and dependency identity.
- Collect both artifacts once on the complete parent catalog and transport them
  without reclassification into clean workers.
- Include every evidence owner in the scoped cache digest and reject partial or
  incoherent bundles.
- Preserve closed raw/normalized/classified/materialized/failure accounting.

**DoD:** A warm isolated worker performs zero transported all-caller rebuilds;
the first indexed/runtime replays fall by at least 2.7 seconds; codec round trips
are exact; stale, partial, and layout-mismatched records are refused; generated
C, validation, determinism, and the 2 GB budget are unchanged.

**Definition of Failure:** CLI reclassifies semantic facts; evidence can be
paired with a different layout, caller census, or target; cache invalidation
omits an owner; a missing artifact silently becomes empty evidence; output or
validation changes; or measured worker time does not materially improve.

### 2. Reduce the First Productive Segment/Global Replay

**Status:** child attribution complete; blocked on Step 1 transport

**Reason:** The first replay costs 4.74 seconds after stable cache reuse. Step 1
owns 2.40 seconds of indexed work and 0.713 seconds of runtime caller census;
remaining repeated runtime AST walks are the next measured owner.

**Work:**

- Reprofile after Step 1 and retain exact mutation/result accounting.
- Reuse read-only AST query projections only inside one unchanged root
  generation; invalidate immediately after mutation.
- Avoid rerunning evidence collectors whose typed project artifact is already
  attached and coherent.
- Keep productive materialization and every refusal path unchanged.

**DoD:** The first replay falls by at least 15%; at least one measured child
owner materially improves; current C hash and both validation gates remain
stable; focused equivalence/mutation tests and strict typing pass.

**Definition of Failure:** A productive lowering is skipped; an AST index
survives mutation; evidence is inferred from rendered text; closed accounting
is weakened; only a microbenchmark improves; or output/validation changes.

### 3. Publish Consumer-Specific Mutation Generations

**Status:** in progress; exact direct-stack projection reuse accepted, but its
caller still lacks a complete authoritative generation scope

**Reason:** Exact full-AST fingerprints can prove stability but cost seconds on
productive Structuring rounds. Call order, object identity, and pass booleans
cannot prove that direct-stack or segment/global inputs are unchanged. The same
generation contract is required before validation-prime replays can be removed.

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
- Remove or narrow a validation-prime replay only when no relevant generation
  changes before the authoritative later replay.

**DoD:** At least one formerly repeated expensive replay is skipped without a
full-AST fingerprint; every relevant mutation advances the corresponding
consumer generation; counters close; focused mutation/misreport tests pass;
validation-prime time falls by at least 10%; accepted C and both validation
gates remain unchanged.

**Definition of Failure:** Stability is inferred from rendered text, call
order, object identity, or an unverified `changed` result; a relevant mutation
does not invalidate its consumer; generations are owned by CLI/Rewrite for
earlier semantics; accounting does not close; or productive work is skipped.

### 4. Bound Remaining C-AST Traversal

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

### 5. Make Validation Transactions Dirty-Pass Driven

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

### 6. Split and Type the Postprocess Stage

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

### 7. Compile Only a Reprofiled Hotspot With mypyc

**Status:** pending after Steps 1-6

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

### 8. Tune Outer Function Parallelism

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

### 9. Final Regression and Performance Ratchet

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
