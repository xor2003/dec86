# Decompiler Runtime Optimization Plan

## Goal

Reduce cold, no-sidecar decompilation time without weakening semantic recovery,
tail validation, generated-C stability, type coverage, or architecture ownership.
Optimize the largest measured costs first. Parallel function workers remain a
separate outer scheduling concern; one mutable function AST stays single-owner
until its mutation contract is isolated.

## Current Evidence

- The original pure-binary SORTD function baseline is 128.91 seconds wall time,
  hash `98b6c22798ca9634eb08eec8cd7b50d2fbfcb02028ea4b5e6024c02e858762e6`.
  It reaches decompilation but fails the existing absolute final def-use guard,
  so it is a performance comparison baseline, not semantic acceptance evidence.
- In the instrumented profile, Structuring consumed about 73% of function time.
- Reusing the Structuring cycle state established a 113.66-second accepted
  comparison baseline. Slot-aware shared child replacement later established a
  91.08-second uncontended result for that same historical output generation.
- Concurrent semantic work then changed the generated output and removed the
  prior final def-use findings. The refreshed current-generation baseline is
  68.93 seconds wall time, 315,388 KiB peak RSS, hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
  with clean tail validation. Older timing results remain useful attribution
  evidence but are not valid current before/after comparisons.
- The largest inclusive owners were structuring semantic priming, segment/global
  materialization, direct-stack materialization, repeated C-AST traversal, and
  postprocess validation/snapshot work.
- A return-value owner probe on the accepted exact function preserved hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`
  and both validation gates while exposing the dominant replay waste:
  direct-stack MOV ran 14 times in 18.05 seconds and returned stable 9 times;
  runtime-segment lowering ran 17 times in 14.71 seconds and returned stable 12
  times; named-global lowering ran 22 times in 4.01 seconds and returned stable
  18 times. Consumer-specific invalidation is therefore ahead of additional
  traversal micro-optimization.
- `decompiler_postprocess_stage.py` was 17,974 lines at the start of the typed
  boundary work and is currently 17,874 lines in the shared worktree. The
  optimization work moved validation contracts, static pass policy, the
  rollback cache, accepted transaction generations, and blocking-reason policy
  into typed owned modules. The stage is currently 17,839 lines. Concurrent
  edits also changed the stage, so Task 6 still measures
  each extraction against its immediate pre-edit line count.
- `lowering/register_local_declarations.py` is currently typed, documented,
  ownership-mapped, and included in focused Ruff/mypy targets. It remains a
  protected verification target because concurrent work introduced it.
- A 2026-08-28 isolated low-overhead cold run is the latest shared-tree
  acceptance point: 57.00 seconds wall time, 359,940 KiB peak RSS, hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
  `validation=passed`, and clean whole-tail validation. A second timing-enabled
  cold run completed in 49.82 seconds at 356,908 KiB RSS with the same output
  and validation. The spread is retained as noise rather than presented as a
  speedup.
- The corresponding unique-key cold cProfile run recorded 244.2 million calls
  and 150.1 profiler-seconds. Structuring owned 72.1 seconds; exact indexed-
  Alias program construction owned 32.6 seconds; deep C-AST traversal owned
  22.9 seconds; postprocess owned 17.5 seconds; exact condition-cache relifting
  owned 7.1 seconds across 36 requests and 669 direct lifts. Building broad
  structured-AST query indexes cost only 2.0 seconds, so more query-index work
  is not the next largest target.
- The highest indexed-Alias and Frontend owners currently overlap active work
  in `indexed_address_program.py`, `function_ssa_registry.py`, Frontend
  reachability/boundary modules, and callee census. They remain the leading
  measured optimization opportunity, but this plan will not create conflicting
  implementations while those owners are being changed concurrently.
- The refreshed in-child profile records 131.3 million calls and 77.4
  profiler-seconds. `_prime_structuring_validation_semantics_8616` owns 57.7
  inclusive seconds, but caller attribution proves that only the stage-entry
  call performs work; five per-pass calls return immediately in effectively
  zero time. Inside the one productive prime, direct-stack materialization runs
  three times (two direct calls plus one broad-replay child), segment/global
  materialization runs three times by the same pattern, and two final condition
  refresh closures run. The shared deep AST walker owns 18.7 seconds across the
  profile. Duplicate proof-consuming consumers inside the single prime, not
  repeated full per-pass priming, are therefore the current largest feedback
  target.
- The focused Structuring validation contract gate is current again: all 70
  tests pass under `pytest -n 7`. Three stale mocks now return the owned typed
  condition-refresh result, and the prime-order regression records the current
  carrier-prune boundary without relaxing production to accept `None` or an
  untyped boolean.
- A partial forced-serial cold census exposed 156 condition-artifact requests:
  1,197 supplied block ranges but only 202 conditional owners. Validation
  retries repeatedly create equivalent `Arch86_16` instances, while the relift
  cache historically required exact Python architecture-object identity. The
  run was stopped after more than five minutes because one validation retry
  alone consumed 63 seconds; this is evidence for prioritizing retry reuse, not
  a valid end-to-end timing baseline.
- The 2026-08-28 shared tree no longer satisfies the previous SORTD acceptance
  point: a unique-key default-parallel run took 193.32 seconds / 660,436 KiB,
  decompiled 18/20 functions, and failed the whole-tail guard for `sub_101f0` on
  call-argument/parameter evidence. Performance work must not present that run
  as accepted or compare its changed output hash with the prior accepted hash.

All timings above are checkout-specific and must be refreshed before claiming a
new improvement.

## Acceptance Invariants

- Preserve the pipeline order: IR -> Alias -> Widening -> Types -> Structuring -> Rewrite.
- No semantic recovery moves into postprocess.
- No test, validation, architecture, ownership, or typing gate is weakened.
- Identical input and options produce deterministic C and status output.
- Every accepted semantic change still has `validation=passed` and no required
  call, branch, memory effect, or return effect disappears.
- Every shell benchmark records command, wall time, peak RSS, output hash,
  validation status, and source revision/worktree state.

## Ordered Work

### Immediate Priority Queue

1. Restore or coordinate the current SORTD whole-tail acceptance point before
   claiming another end-to-end speedup. Do not modify the concurrently owned
   call-argument/parameter surface merely to make the performance run pass.
2. Complete Task 5's dirty-pass and retry reuse work. The latest cold run shows
   validation retries now dominate user feedback, including one 63-second retry.
3. Complete Task 3D's consumer-specific mutation generation. Task 3H's exact
   trace proved all three expensive Structuring direct-stack and segment/global
   rounds productive, so no replay can be removed until an upstream owner
   publishes narrower invalidation evidence.
4. Coordinate the remaining indexed-Alias owner before editing it; do not
   duplicate the concurrent Frontend/indexed-Alias implementation.
5. Revisit Task 3H only after that mutation impact can distinguish rebuilt
   stack/global consumers; five later validation-prime calls are already free.
   Current low-overhead timing charges about 3.5 seconds to eight direct-stack
   rounds, including productive rounds that must still run.
6. Revisit Task 4G only with a design that materially reduces lift work. The
   tested `skip_stmts` and `cross_insn_opt` factory modes preserved the exact
   reachability surface but changed measured CPU time by only about 2%, below
   the acceptance threshold.
7. Use Task 5C's accepted Rewrite generation to shrink the 18k-line stage under
   Task 6. Do not move semantic recovery into Rewrite.
8. Re-profile the exact cold target with low-overhead timing before selecting a
   mypyc cohort. `PYTHON_JIT=1` is currently inert because the installed CPython
   reports `sys._jit.is_available() == False`.
9. Tune outer workers only after single-function costs fall. Keep deterministic
   ordering and aggregate memory at or below 2 GB.

### 1. Freeze a Current Baseline and Verify the New Lowering Boundary

**Status:** completed

**Reason:** Optimization without a current semantic and timing baseline cannot
distinguish a speedup from cache effects, output loss, or concurrent edits. The
register-local owner must be verified before the stage is changed around it.

**Work:**

- Run a cold no-sidecar SORTD benchmark and capture wall time, RSS, C hash, and
  validation result.
- Capture a focused profile with owner timings when a current profile is absent.
- Run Ruff, mypy, architecture, ownership, and focused selector tests for
  `register_local_declarations.py`.
- Record graph coverage and use exact source fallback for stale/untracked paths.

**DoD:** A reproducible baseline artifact identifies the dominant current costs;
the generated C hash and validation status are recorded; the register-local
module passes its focused checks without changing its proved storage contract.

**Definition of Failure:** The baseline is warm or cache-dependent without being
labelled, output/validation evidence is missing, concurrent changes make before
and after incomparable, or the lowering module is rewritten despite already
passing its contract.

### 2. Preserve Intermediate Evidence Across Late-Layer Edits

**Status:** completed

**Reason:** Repeated development runs were rebuilding binary discovery and the
whole-program indexed-Alias/Widening layout after unrelated postprocess and
lowering edits. The final generated-C cache must invalidate broadly, but an
earlier immutable evidence artifact should depend only on its actual owners.

**Work:**

- Give function-discovery and indexed-Alias caches typed source scopes.
- Include the exact discovery, frontend, IR, Alias, Widening, and shared
  contracts that can change each artifact.
- Exclude Types/Lowering, Structuring, Rewrite, validation, and request-owned
  AST query modules from the indexed-Alias source digest.
- Verify reuse with the final-result cache disabled.

**DoD:** Source-scope tests prove both required inclusions and late-layer
exclusions; persisted Widening reuse passes across fresh projects; two bounded
identical runs with the final-result cache disabled show the second run reaches
decompilation without repeating catalog or Alias construction.

**Definition of Failure:** A frontend, IR, Alias, Widening, binary, discovery
policy, or sidecar-policy change can reuse stale evidence; final generated C is
cached under the narrow scope; cache correctness depends on timestamps alone;
or the second run still performs whole-program discovery/Alias construction.

### 2A. Reuse Exact Frontend Caller Boundaries

**Status:** completed

**Reason:** The current profile charges 6.34 seconds to rebuilding 399 exact
Frontend reachability boundaries while seven callee queries inspect only 19
project/target pairs. The loaded binary and explicit caller-range inventory are
immutable during one decompilation, so rebuilding those boundaries adds no new
evidence.

**Work:**

- Cache closed exact boundaries on the corresponding binary project, keyed by
  the complete ordered range tuple.
- Keep direct-target matching, callsite summarization, and census accounting in
  their existing owners.
- Verify cache reuse, distinct-range invalidation, and closed failed ranges.
- Measure an uncontended exact no-sidecar target against the accepted hash and
  validation baseline.

**DoD:** Each exact project/range pair is materialized once; focused Ruff,
strict mypy, and cache/census tests pass; the exact target preserves generated-C
hash and clean validation; wall time or component timing records a material
reduction attributable to boundary reuse.

**Definition of Failure:** A changed range tuple reuses an old boundary,
boundaries cross project identities, incomplete reachability is promoted to a
valid function, matching or summary behavior changes, closed accounting no
longer balances, or uncontended measurement shows no owner reduction.

### 3. Skip Stable Whole-AST Lowering Replays With Authoritative Generations

**Status:** in progress with Lowering-owned request generation

**Reason:** Re-running segment/global and direct-stack materializers after every
possible subtree rebuild is the largest actionable repeated cost. A typed
generation contract is cheaper and safer than repeatedly fingerprinting the
entire AST.

**Work:**

- Define typed input and AST mutation generations in the owning Structuring and
  Types/Lowering modules.
- Project rebuilt callsite summaries to the exact fields consumed by
  direct-stack lowering; object identity is not a semantic generation.
- Mark generations dirty only at authoritative subtree replacement, fact
  publication, or declaration mutation points.
- Make segment/global and direct-stack replay return immediately when their
  consumed generation is unchanged.
- Dispatch post-render replay from typed pass impact: pure return replacement
  reruns only carrier liveness and register declaration publication, while any
  later AST mutation upgrades the request to a full replay.
- Keep counters for executed, changed, skipped-stable, and failed replay rounds.

**DoD:** On the target function, at least one previously repeated expensive
replay is skipped; stable replay cost drops materially; counters close the
evidence loop; exact C hash and tail validation match the baseline; focused
dirty-generation and subtree-rebuild tests pass.

**Definition of Failure:** A replay is skipped after any consumed fact or AST
surface changed, generation state is inferred from rendered text, counters can
report classified work with zero materialization/failure accounting, or output
semantics differ from the baseline.

### 3A. Break the Prototype-to-Callsite Replay Feedback Loop

**Status:** completed

**Reason:** The current profile charges 75.25 profiler-seconds to Structuring
semantic priming and 37.77 seconds to broad lowering replay. Focused probes show
one call-through-return summary alternating between `FUNCTION_RETURN` and no
return use. Types/Lowering wrote inferred prototypes through angr's legacy
`is_prototype_guessed = False` compatibility setter, which relabeled inferred
evidence as `USER`; recovery metadata then consumed that downstream mutable type
as if it were explicit evidence and invalidated otherwise stable replay inputs.

**Work:**

- Publish owned inferred void and scalar prototypes with exact
  `PrototypeSource.CCA_DECOMPILER` provenance.
- Let callsite recovery suppress binary call-through-return evidence only for a
  strong explicit void prototype; inferred Types/Lowering state cannot rewrite
  the upstream machine fact.
- Add focused provenance tests and probe the previously oscillating callsite.
- Re-profile before adding narrower generation skips.

**DoD:** Inferred prototypes never become `USER`; explicit signature/user void
contracts still suppress call-through-return classification; inferred void does
not suppress the machine fact; repeated callsite summaries are value-stable;
focused Ruff, strict mypy, and tests pass; the exact target preserves generated-C
hash and clean tail validation; broad replay count or time falls materially.

**Definition of Failure:** Any inferred owner still writes the legacy guessed
boolean, a weak/inferred void type can erase upstream return-use evidence, an
explicit void contract is ignored, callsite summaries still oscillate, replay
cost does not fall, or output/validation differs from the accepted baseline.

**Completion evidence:** Owned inferred void/scalar prototypes now retain
`CCA_DECOMPILER` provenance, and only strong explicit void provenance can
override call-through-return machine evidence. The previously alternating
callsite summary is stable. Typed post-codegen impact dispatch classifies the
only changed late owner, return-shape materialization, as
`RETURN_LIVENESS_ONLY`; it runs dead-carrier cleanup and register declaration
publication without replaying unrelated stack/global consumers. Adjacent
instrumented runs preserved accepted hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation while direct-stack MOV
invocations fell 14 -> 13, Structuring direct-stack replays 5 -> 4,
segment/global invocations 21 -> 20, and decompiler body time 40.63 -> 38.42
seconds. Ruff, strict mypy, and 95 focused scheduling/liveness tests pass.

### 3B. Make Strong Global Declaration Replay Idempotent

**Status:** completed

**Reason:** The remaining second broad Structuring replay reports exactly one
changed owner: signed-global declaration materialization. Its typed replacement
helper removes an already-equal declaration and appends it, changing declaration
order without changing storage or type semantics. That representation churn
keeps the expensive convergence loop alive.

**Work:**

- Have the signed-global owner recognize its exact previously published fact
  and declaration before invoking the generic stronger-declaration replacement.
- Preserve established declaration ordering when another typed owner has
  replayed between two signed-global passes.
- Add focused multi-declaration idempotence tests and re-run the replay-owner
  probe before deciding whether condition-refresh replay can be narrowed.

**DoD:** Applying the same signed-global evidence after an intervening typed
declaration replay preserves declaration order; the second materializer call returns `False`; focused
Ruff, strict mypy, and tests pass; the replay-owner probe no longer reports
signed-global declaration churn; exact generated-C hash and validation match the
accepted baseline.

**Definition of Failure:** Equal signed-global evidence changes tuple order or
reports a mutation; genuinely stronger signed type evidence is ignored; or generated C,
tail validation, or closed evidence accounting regresses.

**Completion evidence:** The signed-global owner now refuses to invoke the
generic stronger-declaration replacement when its exact fact and `long`
declaration are already published. A focused interleaving regression reproduces
aggregate declaration replay between signed passes. Ruff, strict mypy, and six
focused tests pass. The exact no-sidecar `0x10554` probe reports signed-global
changes `True` then `False`, broad replay changes `True` then `False`, preserves
hash `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
and passes both function and whole-tail validation.

### 3C. Close Condition Refresh Without a Broad Lowering Replay

**Status:** completed

**Reason:** After Task 3B, broad replay was already suppressed for closed
refreshes, but five validation-only semantic passes still invoked the entire
condition-refresh closure despite reporting no AST mutation. Nine refresh calls
spent 6.53 profiler-seconds, including 3.72 seconds rebuilding ten whole-AST
condition-surface tokens.

**Work:**

- Extract a typed condition-refresh result and transaction from the 18k-line
  Structuring stage into the Structuring owner.
- Keep root/surface invalidation, typed condition materialization, and explicit
  segment/global lowering in that closed transaction.
- Schedule no generic Lowering replay after a closed refresh; retain conservative
  broad replay only if the typed result reports an unclosed consumer class.
- Run mutation closure only when a validated pass reports an AST mutation;
  semantic no-op passes still execute tail validation against the primed state.
- Cover stable, root-replaced, in-place-mutated, stack-operand, and segmented-
  operand refresh paths, then re-profile the exact target.

**DoD:** Focused tests prove a stable refresh is skipped and each changed
condition surface is either fully closed by its owner or explicitly requests a
broad replay; validation-only refresh count on `0x10554` falls materially
without removing tail validation; Ruff, strict mypy, and architecture checks
pass; exact C hash, validation, and whole-tail result match the accepted
baseline; measured decompiler body time improves.

**Definition of Failure:** A refreshed SS/DS/ES operand escapes as an unlowered
carrier, a changed condition consumer is classified closed without evidence,
root/surface invalidation misses an in-place mutation, broad replay is removed
only for the sample address, output or validation changes, or the measured owner
count/time does not improve.

**Completion evidence:** Typed closure tests and condition materialization tests
pass 37 focused cases under `pytest -n 7`; Ruff and strict mypy pass. The exact
sidecar-free `0x10554` profile reduced refresh calls 9 -> 4, validation-wrapper
calls 7 -> 2, total core calls 161.86M -> 157.45M, core profile time 87.35 ->
80.80 seconds, and profiled wall time 125.43 -> 118.93 seconds. Generated C
retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation.

### 3D. Suppress Exact Stable Direct-Stack Replay Requests

**Status:** in progress; five late requests skipped, consumer generation pending

**Reason:** The current exact `0x10554` probe executes thirteen direct-stack MOV
materializations: four Structuring rounds, one postprocess bootstrap, and eight
CLI render-refresh rounds. The first three Structuring rounds, the postprocess
bootstrap, and one regenerated CLI tree report real mutations, so call position
is not a correctness boundary. One CLI request closes with no eligible facts;
six later CLI rounds report `changed=False` and cost about 0.15-0.20 seconds
each, while the stable fourth Structuring round costs about 0.77 seconds.
Repeating an identical request against unchanged owned inputs adds no evidence
and directly slows the edit-run feedback loop.

**Work:**

- Define a typed direct-instruction replay request containing every consumed
  option: source kinds, reload policy, stack-slot fallback, callee-saved prune,
  branch contract, and included materializer classes.
- Pair that request with authoritative structured-AST and lowering-fact
  generations owned by Structuring/Types-Lowering; never infer stability from
  call order, object identity alone, rendered C, or a whole-AST text digest.
- Route ordinary CLI and compatibility replay through the Structuring facade so
  one owner can close executed, changed, skipped-stable, and failed accounting.
- Preserve explicit postprocess salvage as a separately typed, validated request
  that cannot be suppressed by an ordinary full-replay result.
- Add positive tests for exact stable reuse and negative tests for every request
  field, AST mutation, fact publication, subtree replacement, and salvage mode.

**DoD:** At least the six measured late no-op MOV rounds are skipped on the exact
target while all productive rounds still execute; replay counters close and
identify the exact request/generations used; focused Ruff with `--fix`, strict
mypy, architecture/ownership checks, and `pytest -n 7` pass; generated C retains
hash `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`;
function and whole-tail validation pass; uncontended component or wall timing
shows a material reduction without exceeding the 2 GB aggregate memory budget.

**Definition of Failure:** Any productive replay is skipped; distinct source
kinds, reload/fallback/branch policy, salvage mode, AST generation, or fact
generation collide; CLI or Rewrite invents a second semantic cache owner;
stability is inferred from rendered text, object identity, or call position;
closed accounting does not balance; generated output or validation changes; or
the measured replay count/time does not improve enough to justify the added
state.

**Rejected experiment:** A typed CLI-local session keyed every replay option and
advanced its generation after each owner-reported mutation. It preserved the
accepted C hash and both validation gates, but reduced thirteen MOV executions
to twelve, not the required stable set, and measured 57.97 seconds versus the
57.10-second probe baseline. Repeated aggregate/call and segmented owners still
reported intervening mutations, so the session could not prove stability. The
implementation and tests were removed under this task's Definition of Failure.
Task 5 must publish authoritative, consumer-specific mutation impacts before
this skip can be attempted again.

**Renewed evidence:** A Lowering-boundary generation probe found that requests
9 through 14 have the same AST digest and node count, callsite projection, and
attached/function fact set, and all return `False`. Requests 7 and 8 share an
AST generation but produce different outcomes under different replay options.
The next implementation therefore keys the exact options and value-based facts
inside Types/Lowering, publishes the completed post-request as stable, and uses
the pre/post request delta as a mutation witness. CLI-local global invalidation
remains rejected.

**Accepted Lowering slice:** The authoritative request owner now lives in
`lowering/direct_stack_replay.py`; the Structuring module is a compatibility
export only. Requests use value-based facts, exact callsite fields, full AST
generation, function address, and all public MOV options. A reported mutation
clears stability without building a redundant post-request; a reportedly stable
pass publishes its post-request only after the pre/post witness agrees. A
pre/post mismatch upgrades a false stable report; failures clear stability and
close accounting. On the exact target, calls
10-14 fell from about 0.145-0.184 seconds each to 0.004-0.005 seconds,
`attempt_count` remained 9, `skipped_count` reached 5, and `failure_count` was
zero. Adjacent uncontended wall time fell 60.76 -> 54.55 seconds and peak RSS
fell 656,000 -> 321,196 KiB. The accepted C hash and both validation gates are
unchanged. The first of the six late stable calls still establishes stability
after an intervening AST mutation, so the full Task 3D DoD remains open pending
Task 5's consumer-specific mutation impact.

**Current profile consequence:** The exact request is correct but its full-AST
generation is too expensive for productive Structuring rounds: twelve request
generations consume 3.57 profiler-seconds, while all four Structuring MOV rounds
still execute. The next slice must replace that fingerprint with an
authoritative consumer mutation generation. Removing request fields or using
call order would trigger this task's Definition of Failure.

**Generation boundary finding:** Task 5C's accepted postprocess generation is
necessary but not sufficient as the direct-stack cache key. CLI render refresh
still runs callsite, aggregate, occurrence, widening, cleanup, and segment
consumers that can mutate the AST after postprocess closes. A postprocess-only
key would therefore skip productive replays. The safe completion path must
route those semantic consumers through a Structuring/Lowering facade that
publishes direct-stack impact, or retain the exact AST witness for any path not
covered by that authoritative generation.

**Accepted witness reduction:** A reported mutation now clears stability
without computing a redundant post-request. Reportedly stable passes still pay
the exact pre/post witness and only publish stability when both agree. The exact
target retained the accepted hash and both validation gates; request AST
generations fell 12 -> 9 and cumulative generation time fell 3.57 -> 2.77
profiler-seconds. Total wall time was noisy (117.04 -> 124.74 seconds), so only
the isolated 22% witness reduction is credited and consumer generations remain
the required completion design.

**Rejected runtime-segment sibling:** A value-generation probe found exact
duplicate runtime-segment requests only at rounds 13-17 on a 148-node late AST.
All were stable, but together cost about 0.08 seconds. Adding another replay
state owner would not be a material feedback improvement and therefore fails
the same benefit-versus-state criterion. No runtime-segment replay cache was
added; invalidation work stays focused on the expensive Structuring rounds.

### 3E. Stop Pre-Baseline Priming From Invalidating Post-Prime Consumers

**Status:** completed

**Reason:** Validation priming runs direct-stack and segment/global Lowering and
then establishes the authoritative before-summary. Its historical `changed`
bit was nevertheless merged into the post-pass replay impact. On the exact
target every ordinary Structuring pass is stable except the explicitly typed
`RETURN_LIVENESS_ONLY` pass, yet the stale priming bit upgrades that narrow
impact to `FULL_AST` and executes the 10.59-profiler-second broad replay.

**Work:**

- Define replay impact only from mutations occurring after the primed baseline.
- Keep every full-AST pass defaulted to `FULL_AST`; retain explicit
  `RETURN_LIVENESS_ONLY` ownership for pure return replacement.
- Prove a late full-AST result still upgrades the merged impact, while a closed
  pre-baseline prime cannot do so.

**DoD:** Focused impact/order tests pass; the exact target removes one broad
post-regeneration replay and retains the accepted C hash, `validation=passed`,
and clean whole-tail validation; Ruff with `--fix`, strict mypy, architecture,
and ownership checks pass; component or wall time falls materially.

**Definition of Failure:** A post-prime full-AST mutation receives no broad
replay, a pass can mutate while reporting stable without a hard contract/test,
direct-stack or segment carriers reappear in final C, exact output or validation
changes, or the measured broad replay count/time does not fall.

**Completion evidence:** Ruff, strict mypy, architecture, ownership, and 21
focused impact/order tests pass. The exact target retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation. Structuring direct-stack
replays fell 4 -> 3, removing the stale post-prime broad request, and the
adjacent uncontended wall result fell 66.69 -> 57.22 seconds. Segment/global
still ran six times, so that owner remains the next measured bottleneck.

### 3F. Gate Final Return-Closure Segment Replay on Typed Mutation

**Status:** completed

**Reason:** The exact caller/result probe found five segment/global requests in
the measured core. The first three materialize facts. The fourth follows switch
exit and terminal-return closure, reports every component stable, and costs
about 0.61 seconds because none of those preceding owners changed the target
AST. An unconditional replay adds no evidence.

**Work:**

- Publish a typed Structuring decision from switch-exit, terminal-call-return,
  and terminal-return-shape mutation results.
- Run the final return-closure segment/global replay only when that decision is
  true.
- Keep condition-refresh closure unchanged until its narrower segment-consumer
  proof exists.

**DoD:** Positive tests prove each return-closure mutation requests replay and a
fully stable closure does not; the exact target removes the stable request,
retains its accepted C hash and both validation gates, and records a material
component or wall-time reduction; Ruff with `--fix` and strict mypy pass.

**Definition of Failure:** Any changed switch/terminal/return-shape owner skips
segment closure, the decision is inferred from rendered C or sample identity,
the stable request remains, output or validation changes, or measured savings
do not justify the scheduling branch.

**Completion evidence:** Ruff, strict mypy, and 14 focused tests pass. The exact
caller/result probe fell from five segment/global requests to four: all three
productive requests and condition closure remained, while the fully stable
return-closure request disappeared. Its isolated cost was about 0.61 seconds.
The target retained the accepted C hash, `validation=passed`, and clean
whole-tail validation. Adjacent wall time varied 57.68 -> 60.67 seconds, so no
end-to-end gain is claimed for this slice.

### 3G. Reuse the Exact Generation Inside Nested Ownership Replay

**Status:** blocked; direct reuse rejected before implementation

**Reason:** One direct-stack execution builds an exact request generation, then
its nested Structuring branch/loop ownership callback builds the same complete
generation again even when the materializer has made no intervening mutation.
Task 3D attributes 2.77 profiler-seconds to nine full generations. The outer
Types/Lowering scheduler already owns the exact pre-operation generation and
can transfer it through a typed callback contract.

**Work:**

- Pass the exact pre-operation direct-stack generation into the materializer.
- Let the nested Structuring ownership callback consume it only when no earlier
  direct-stack component reported a mutation; otherwise rebuild as before.
- Keep direct callback calls without a supplied generation on the existing
  full-witness path.
- Add tests for supplied-generation reuse, stale-generation refusal after an
  intervening mutation, and unchanged closed replay accounting.

**DoD:** A stable direct-stack execution performs one fewer complete AST
generation; any preceding mutation forces a fresh generation; focused Ruff
with `--fix`, strict mypy, architecture/ownership checks, and direct-stack and
Structuring tests pass under `pytest -n 7`; the exact target reduces generation
count or cumulative generation time materially, retains C hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`, and
passes both validation gates within the 2 GB aggregate memory budget.

**Definition of Failure:** A supplied generation survives an intervening AST
or consumed-fact mutation, a direct ownership callback no longer performs its
own witness, closed accounting changes, the measured full-generation count or
time does not improve materially, output or validation changes, or the change
adds another untyped dynamic cache owner. A failed implementation is removed
and its measurement remains in this plan.

**Rejected design:** Passing the pre-operation generation whenever direct-stack
components reported `False` would bypass the existing false-stable guard: a
misreporting component could mutate the AST, then the nested ownership callback
could skip before the outer pre/post witness detected the mutation. No code was
changed. Task 5C must publish an accepted mutation generation before this reuse
can be implemented without weakening the guard.

### 3H. Remove Duplicate Consumers Inside Structuring Validation Priming

**Status:** blocked; profile attribution corrected, every expensive measured
replay is productive, rolling-generation experiment rejected and removed

**Reason:** The current in-child profile attributes 57.7 of 77.4
profiler-seconds to `_prime_structuring_validation_semantics_8616`. Exact
caller attribution shows one stage-entry call consumes all 57.7 seconds and
five per-pass calls return in zero measured time. The productive call itself
runs direct-stack and segment/global materialization three times each: early,
after call/return shaping, and inside the broad final Lowering replay. This
bootstrap duplication, together with repeated condition closure, dominates the
edit-run feedback loop.

**Work:**

- Capture the mutation result and consumed dependency of each expensive owner
  inside the stage-entry prime.
- Remove or narrow only a replay that a later authoritative replay subsumes and
  whose intervening owners publish no relevant mutation impact.
- Preserve productive early lowering required by call, return, loop, or
  condition materialization; do not infer stability from call order or
  rendered C.
- Keep the object-local primed marker because it already makes all five
  per-pass calls effectively free.
- Keep validation-delta acceptance, final whole-tail validation, and every
  productive Lowering replay unchanged.

**DoD:** The exact target reduces cumulative validation-prime time by at least
10%, and removes at least one duplicate direct-stack, segment/global, or broad
Lowering execution while every productive execution remains; focused Ruff with
`--fix`, strict mypy, architecture, ownership, and `pytest -n 7` pass; current C hash
`f86bd521ce979ae1ee2b5789853ac813978cf9d1928c7e73d3189f491c28db78`,
function validation, and whole-tail validation remain unchanged; an uncached
adjacent run improves the 40.54-second baseline by at least 10% without
exceeding 2 GB RSS.

**Definition of Failure:** Owner booleans become the sole mutation witness, an
intervening owner can rebuild a consumed subtree without invalidating the
optimization, an expensive whole-AST generation is added, productive Lowering
is skipped, output or validation changes, validation-prime cumulative time
does not fall by at least 10%, or fresh wall time does not improve materially.
Any failed implementation is removed.

**Rejected experiment:** A typed rolling baseline compared exact structured-AST
and tail-validation-input generations around every semantic pass. Focused
stable/misreport tests, Ruff, strict mypy, exact output, and both validation
gates passed. However fresh uncached runs regressed from 40.54 seconds to 44.26
and 50.43 seconds, with one sample reaching 582,900 KiB RSS. Subsequent caller
analysis proved the experiment targeted five already-free early returns rather
than repeated full primes. The entire implementation and tests remain removed
under this task's Definition of Failure.

**Blocking evidence:** An uncached low-overhead exact trace completed in 55.16
seconds at 319,312 KiB RSS, emitted hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
and passed function and whole-tail validation. All three Structuring
direct-stack rounds reported `changed=True`; their paired segment/global rounds
also reported productive changes. Removing any of them now would trigger this
task's Definition of Failure. The safe dependency is Task 3D's authoritative
consumer mutation impact, not another call-order or full-AST cache.

### 4. Build a Request-Owned C-AST Traversal Index

**Status:** rejected and removed

**Reason:** Deep C-AST iterators account for tens of millions of visits. Many
passes independently rediscover the same nodes and parent relationships.

**Work:**

- Add a typed, request-owned AST index outside the 18k-line orchestrator.
- Index nodes, parents, statement blocks, calls, assignments, variables, and
  stable storage identities needed by multiple consumers.
- Invalidate only on an authoritative AST mutation generation change.
- Migrate the highest-frequency read-only consumers first; retain dynamic
  boundary narrowing for third-party angr nodes.

**DoD:** Profiling shows fewer deep iterator calls and lower cumulative traversal
time; index construction occurs at most once per unchanged generation; migrated
consumers return results equivalent to uncached traversal in positive and
negative fixtures; memory remains within the 2 GB aggregate budget.

**Definition of Failure:** Cached parents/nodes survive mutation, consumers
derive semantic facts from C text or node shape alone, traversal count does not
fall, peak memory is unbounded, or ordering becomes nondeterministic.

### 4A. Prefilter Impossible Direct-Stack Reload Placements

**Status:** completed

**Reason:** The current profile charges 3.08 profiler-seconds to 20 recursive
register-use searches. Most searches are repeated misses for registers absent
from the current structured AST, while tagged-assignment indexing performs a
separate full traversal of the same root.

**Work:**

- Build one request-owned AST query index at the start of reload placement.
- Project the tagged-assignment index and canonical register-variable inventory
  from that same immutable query surface.
- Skip only a register-use insertion whose exact register identity is absent;
  every possible hit continues through the existing placement proof.
- Re-profile the exact no-sidecar target and retain only a measured owner drop.

**DoD:** Focused tests prove absent and present register identities, tagged
assignment projection remains exact, recursive register-use calls fall in the
profile, exact generated-C hash and tail validation match the baseline, and
Ruff plus strict mypy pass for every touched production file.

**Definition of Failure:** A register present behind a cast or third-party
coordinate is classified absent, an AST mutation can reuse a stale negative,
tagged-address accounting changes, recursive search count does not fall, or
generated C or validation differs from the accepted baseline.

### 4B. Refuse Expensive Before-Loop Proofs Without a Tagged Assignment

**Status:** completed

**Reason:** The accepted `0x10554` profile charges 3.00 profiler-seconds to
seven before-loop relocation requests. A focused runtime probe found 14 loop
candidates, but 13 contain no exact tagged assignment for the queried move.
Those impossible candidates still pay instruction-range, following-address,
CFG-coverage, and stack-read proofs even though relocation requires a positive
tagged-assignment count.

**Work:**

- Make the existing exact tagged-assignment count the fail-closed gate before
  any later loop-placement proof.
- Preserve the current deepest-loop traversal and all proofs for a positive
  candidate; do not infer absence from rendered C, names, or approximate shape.
- Add a focused negative regression that makes any expensive post-gate query a
  test failure, then re-profile the exact target.

**DoD:** Focused tests prove a loop with no exact tagged assignment never runs
range, following-address, CFG-coverage, or stack-read classification; positive
relocation fixtures remain unchanged; Ruff and strict mypy pass; the exact C
hash and both validation gates match the accepted baseline; relocation or
direct-stack cumulative time falls materially.

**Definition of Failure:** A positive tagged assignment is skipped, the guard
uses text or names instead of exact AST tags and storage identity, deepest-loop
ordering changes, output or validation differs, or profiling shows no material
owner reduction.

**Completion evidence:** A focused negative fixture makes every post-gate
range, following-address, CFG-coverage, and stack-read query fail the test; nine
focused negative and positive loop-placement tests pass. On the exact no-sidecar
`0x10554` profile, before-loop relocation fell from 3.00 to 0.63
profiler-seconds, direct-stack MOV materialization fell from 11.50 to 9.02
seconds, and total profiled calls fell from 167.68 million to 162.92 million.
The C hash remains
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
function validation and whole-tail validation pass, and peak RSS was 648,704
KiB. Ruff and focused strict mypy pass for the touched production surface.

### 4C. Remove Scalar and Direct-Child Container-Walker Handoffs

**Status:** completed

**Reason:** The accepted profile charges 28.91 cumulative seconds to the shared
deep C-AST iterator. Its child-boundary helper receives 6.18 million calls and
the surrounding list-extension handoff accumulates 19.12 seconds. Most owned
slots contain either one direct structured node or a scalar, neither of which
requires recursive container traversal.

**Work:**

- Append direct structured children without entering the container walker.
- Refuse scalar fields before the helper and preserve recursive handling for
  dict/list/tuple/set boundaries, shared nodes, and container cycles.
- Preserve deterministic depth-first order and re-profile the exact target.

**DoD:** Focused tests prove direct/scalar slots bypass the container helper and
existing shared-node/cycle order remains exact; Ruff and strict mypy pass;
helper calls and deep-iterator cumulative time fall materially; generated C,
validation, and whole-tail results match the accepted baseline.

**Definition of Failure:** Nested containers or condition-pair children
disappear, shared nodes are visited more than once, traversal order changes,
dynamic third-party fields raise instead of being refused, profile cost does
not fall materially, or generated output/validation changes.

**Completion evidence:** Strict mypy, Ruff, and 19 focused traversal/index
tests pass. On the exact target, container-helper calls fell 6.18M -> 620K,
shared deep-walker cumulative time fell 28.91 -> 20.93 seconds, and total core
calls fell 157.45M -> 133.16M. Generated C retained the accepted hash and both
validation gates passed. Total core time was flat within run variance, so only
the 7.97-second shared-walker reduction is credited.

### 4D. Remove Equivalent Postprocess Walker Handoffs

**Status:** completed

**Reason:** After Task 4C, the separate Rewrite utility walker costs 6.86
cumulative seconds and its container helper receives 1.01 million calls. It
uses the same expensive helper path for direct structured children and scalar
fields even though only nested containers need that machinery.

**Work:**

- Apply the direct-child/scalar fast path at the Rewrite utility boundary.
- Preserve its stricter dynamic getter, deterministic order, shared-node guard,
  and recursive container behavior.
- Keep this as traversal mechanics only; do not move semantic recovery into
  Rewrite or infer anything from rendered C.

**DoD:** Focused tests prove direct/scalar bypass and existing postprocess
fixtures pass; Ruff and strict mypy pass; helper calls and Rewrite-walker time
fall materially; exact C hash and both validation gates remain unchanged.

**Definition of Failure:** Rewrite traversal sees a different node sequence,
nested condition/switch containers disappear, helper cost does not fall,
dynamic boundary errors escape, semantics move into Rewrite, or output and
validation differ.

**Completion evidence:** Strict mypy, Ruff, and 81 focused postprocess/walker
tests pass. On the exact target, Rewrite helper calls fell 1.01M -> 91,756,
Rewrite-walker cumulative time fell 6.86 -> 3.63 seconds, and total core calls
fell 133.16M -> 128.96M. Generated C retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation. Whole-profile timing was
contaminated by unrelated direct-stack and lifting variance, so only the
isolated 3.23-second owner reduction is credited.

### 4E. Index Decoded Direct Calls Once Per Caller Census

**Status:** completed

**Reason:** The refreshed accepted profile shows caller-return evidence spending
5.09 cumulative seconds in `_callsites_for_target`; 415 target queries rescan
the same decoded ranges and invoke direct-call target classification 941,220
times. Candidate targets change, but the decoded instruction corpus is immutable
for one census, so direct callsites can be indexed once without changing return-
use semantics.

**Work:**

- Build a typed Frontend index from each decoded direct call target to its exact
  caller range, instruction tuple, instruction index, and callsite address.
- Preserve the existing target and address decoders and the Semantics-owned
  return-use classifier; the index owns lookup mechanics only.
- Normalize targets exactly as the current query path does, preserve duplicate
  overwrite order, and publish closed raw/normalized/classified/materialized/
  failure accounting.
- Re-profile the exact sidecar-free target before attempting bounded process
  parallelism for the larger indexed-Alias program build.

**DoD:** Focused tests prove deterministic indexing, 16-bit target aliasing,
invalid-callsite refusal, and one resolver call per decoded instruction; existing
caller-return-use tests pass under `pytest -n 7`; Ruff with `--fix` and strict
mypy pass; direct-target classification calls and cumulative caller-return time
fall materially; exact C hash and both validation gates remain unchanged.

**Definition of Failure:** Return-use classification moves into Frontend,
indirect calls become direct evidence, normalized targets collide beyond the
existing 16-bit rule, caller/callsite ordering changes, failures are hidden or
counters do not close, the profile owner does not fall materially, or generated
output/validation changes.

**Completion evidence:** The typed Frontend index reduced direct-call target
classification from 941,220 to 61,236 calls (93.5%), `_callsites_for_target`
from 5.086 to 0.187 profiler-seconds, and complete caller-return evidence from
6.032 to 3.484 profiler-seconds. Ninety-nine focused tests passed under
`pytest -n 7`; Ruff with `--fix`, strict mypy, changed-file linting,
architecture, agent-context, and ownership gates passed. The exact sidecar-free
target retained C hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation. The containing indexed-
Alias build varied from 36.16 to 67.15 profiler-seconds, so no end-to-end wall-
time improvement is claimed from this component measurement.

### 4F. Defer Exact Caller Boundaries Until a Target Match Exists

**Status:** rejected and removed

**Reason:** Low-overhead nested timing traced the first 3.05-second indexed-
global source collection to one 3.50-second callee census. Its range fallback
spends 3.48 seconds building 21 exact Frontend function boundaries even though
only ranges containing a matching direct call can contribute a typed fact.
The `0x11222` query has one decoded target match but materializes no fact, so
deferring the same broad inventory until after target filtering was insufficient.

**Work:**

- Decode each immutable caller range and retain only direct calls whose
  canonical target matches the requested callee.
- Request exact boundaries only for ranges containing those matches, while
  preserving caller order, summary behavior, padding-target canonicalization,
  and refusal behavior.
- Cache each exact Frontend range result independently so overlapping target
  inventories reuse both materialized boundaries and typed failures.
- Add regressions proving no-match refusal, matching-range selection, and
  overlapping inventory reuse.

**DoD:** The new regressions and existing callee-census/argument-evidence tests
pass under `pytest -n 7`; Ruff with `--fix`, strict mypy, architecture,
ownership, and changed-file gates pass; the measured `0x11222` owner falls
materially; the exact target retains its accepted C hash, function validation,
and whole-tail validation; end-to-end timing is reported without cProfile
distortion.

**Definition of Failure:** A range containing a matching call is omitted,
padding-target canonicalization changes, callsite or caller order changes,
missing boundaries become guessed summaries, distinct ranges collide, stale
boundaries survive a changed range key, decode failures become positive evidence,
the measured owner does not fall materially, or output and validation change.

**Rejected first slice:** Deferring the original 21-range inventory until after
target filtering preserved output but still took 3.95 seconds for `0x11222`:
the range scan found a direct target match that later failed typed summary
materialization. The broad inventory therefore still ran, triggering this
task's Definition of Failure. The replacement requests only matching ranges and
shares exact per-range Frontend results across inventories.

**Rejected final slice:** Restricting construction to the one matching range and
sharing exact per-range results still took 3.80 seconds for `0x11222`; the
one-time cost is inside the first reachability build rather than proportional
to inventory breadth. The accepted C hash and both validation gates remained
unchanged, but the performance DoD failed. The code and temporary regressions
were removed; the next task must profile the Frontend reachability owner itself.

### 4G. Remove Duplicate Work From First Frontend Reachability

**Status:** completed

**Reason:** Task 4F proved that one exact range still costs 3.80 seconds, nearly
the same as a 21-range inventory. `collect_instruction_reachability_8616`
directly asks angr for every block even though the Frontend already owns a typed
decoded-block inventory. The cost must be attributed inside this owner before
changing cache or decode contracts.

**Work:**

- Profile only the first uncached reachability request and separate block
  construction, Capstone instruction access, successor classification, and
  result materialization.
- Reuse an existing immutable Frontend artifact only when it contains every
  field required by the closed reachability evidence; otherwise extend the
  earliest owner with a typed result rather than cache dynamic angr blocks.
- Preserve exact region bounds, unresolved indirect-flow refusal, successor
  edges, decoded instruction addresses, and closed counters.
- Measure the isolated owner and the exact cold target after focused tests and
  static gates.

**DoD:** Focused reachability, boundary, and caller-census tests pass under
`pytest -n 7`; Ruff with `--fix`, strict mypy, architecture, ownership, and
changed-file gates pass; the first uncached owner falls materially without
increasing aggregate memory beyond 2 GB; exact C hash and both validation gates
remain unchanged.

**Definition of Failure:** Dynamic angr block objects are cached as durable
owned evidence, a decode refusal is hidden, indirect control flow becomes a
guessed successor, region or 16-bit address rules change, counters do not close,
the isolated owner does not improve materially, memory grows without a bounded
contract, or output and validation change.

### 4H. Reuse Exact Condition Relifts by Immutable Binary Evidence

**Status:** completed

**Reason:** The latest cold profile attributes 7.1 profiler-seconds to 36
`relift_function_condition_cache_8616` requests and 669 direct lifts. The
returned artifact is immutable and depends on exact block bytes, block ranges,
expected condition owners, and architecture semantics. Repeating that lift for
an unchanged request adds no evidence.

**Work:**

- Add a bounded IR-owned cache for complete immutable relift artifacts.
- Key reuse by architecture object identity, ordered block addresses and exact
  bytes, and expected condition-owner addresses; read the current bytes before
  every lookup so loader-memory changes invalidate the entry.
- Never cache byte-read failures, lift failures, or incomplete evidence.
- Preserve the isolated lifter-state transaction and closed evidence counters
  on every cache miss.

**DoD:** Focused tests prove an identical request lifts once, changed bytes and
changed architecture identity force a fresh lift, and incomplete artifacts are
not reused; Ruff with `--fix`, strict mypy, and condition-transfer tests pass
under `pytest -n 7`; the exact cold target preserves C hash and both validation
gates; direct-lift count and relift cumulative time fall materially without
unbounded memory growth.

**Definition of Failure:** A changed byte range or architecture reuses stale
conditions, a failed/incomplete artifact suppresses a retry, cache identity
depends only on function address, mutable ambient lifter state escapes into the
artifact, entries grow without a fixed bound, exact output or validation
changes, or the profile owner does not fall enough to justify the cache.

**Completion evidence:** The IR owner now rereads exact loader bytes and reuses
only complete immutable artifacts under a 32-entry architecture-identity cache.
Changed bytes, changed architecture identity, incomplete retry, and bounded
eviction regressions pass. The implementation extracted immutable contracts so
`condition_cache_relift.py` shrank from 346 to 312 lines. Ruff with `--fix`,
strict mypy, startup architecture, ownership, and 43 focused relift/transfer
tests pass. The exact cold target retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation. A comparable cold profile
reduced direct lifts from 669 to 437 and relift cumulative time from 7.13 to
5.11 profiler-seconds (28.3%). Its 61.75-second low-overhead sample did not beat
the 49.82-57.00-second pre-change range and receives no end-to-end wall-time
credit.

### 4I. Pack Live Status Bits Once Per Instruction

**Status:** completed

**Reason:** The accepted cold profile records 4,860 `Eflags.set_flag` calls and
3.59 cumulative seconds rebuilding packed FLAGS one bit at a time. Each update
recasts the same prior FLAGS value, creates another clear mask, and extends the
same expression chain. The liveness owner already decides which values are
required; packing those proven-live values together preserves semantics while
removing repeated container work and reducing downstream expression size.

**Work:**

- Replace sequential live-bit updates with one Frontend-owned helper that
  evaluates the same live factories in architectural bit order.
- Cast the prior FLAGS value once, clear the complete live mask once, pack each
  one-bit value at its architectural position, and publish one combined value.
- Preserve every non-live FLAGS bit, undefined-bit policy, lazy dead-value
  refusal, and integer/dynamic pyvex boundaries.
- Add focused whole-dead, partial-live, all-live, and concrete FLAGS projection
  regressions before measuring the exact target.

**DoD:** Focused flag/lifter/80386 tests pass under `pytest -n 7`; Ruff with
`--fix`, strict mypy, architecture, ownership, and changed-file gates pass; the
exact target preserves required conditions, C hash or a demonstrably improved
validated C generation, function validation, and whole-tail validation;
`set_flag` calls and packed-FLAGS cumulative time fall materially without
increasing failed liveness accounting.

**Definition of Failure:** A dead value factory is evaluated, a non-live FLAGS
bit changes, integer and pyvex values diverge, value evaluation order changes,
undefined flag policy is guessed, required branch conditions disappear,
liveness failures increase, generated C or validation regresses, or measured
packing/traversal cost does not fall enough to justify the rewrite.

**Completion evidence:** `eflags.py` now evaluates the same live factories in
architectural order and publishes one masked FLAGS value per instruction; it
shrunk from 776 to 764 lines. Concrete full/partial/dead regressions prove
sequential equivalence, preservation of unrelated bits, stable factory order,
and lazy refusal of dead factories. Ruff with `--fix`, strict mypy, startup
architecture, ownership, 244 focused flag/CFG/80386 tests, and the complete
`quality-dev` gate pass; the latter includes 1,863 curated pytest checks and all
three selected MS C tiny pipelines. The exact target retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation. `set_flag` fell from
4,860 calls / 3.59 seconds to 86 / 0.065; the replacement batch owner costs
5.06 versus 6.23 seconds, VEX statements fell 43,518 -> 42,042, and total cold
profile time fell 159.1 -> 144.4 seconds with about seven million fewer calls.
The 59.36-second low-overhead sample remains inside the existing wall/RSS noise
band and receives no standalone wall-time claim.

### 4J. Reuse Immutable Block-Local SSA Projections

**Status:** completed

**Reason:** The current cold profile records 990 block-local SSA projections
for 495 IR blocks and 5.61 cumulative seconds. IR diagnostics build each
projection to count bindings, then function SSA immediately rebuilds the same
immutable block. This is duplicate proof construction, not new evidence.

**Work:**

- Retain a bounded IR-owned cache of immutable `SSABlock` projections.
- Reuse only the identical `IRBlock` object; do not use structural dataclass
  equality because provenance fields intentionally excluded from equality still
  affect the SSA result.
- Keep cache publication thread-safe and cap retained entries well below the
  current 2 GB aggregate memory budget.
- Prove exact-object reuse and distinct-object provenance isolation before
  measuring the cold target.

**DoD:** Focused SSA, VEX-import, indexed-Alias, and condition-artifact tests pass
under `pytest -n 7`; Ruff with `--fix`, strict mypy, architecture, ownership,
and changed-file gates pass; uncached block projections fall from 990 toward the
495 unique-block inventory and cumulative SSA time falls materially; the exact
SORTD C hash, function validation, whole-tail validation, and required calls are
unchanged; peak RSS remains below 2 GB without a material unexplained increase.

**Definition of Failure:** Structurally equal but distinct blocks share a cached
result, source temporary or instruction provenance changes disappear, mutable
results escape, cache growth is unbounded, lock behavior serializes unrelated
expensive construction, exact output or validation changes, memory grows beyond
the budget, or measured duplicate SSA work does not fall enough to justify the
cache.

**Completion evidence:** IR now retains at most 128 immutable block-local SSA
projections and reuses them only by exact `IRBlock` object identity. Regressions
prove same-object reuse and prevent structurally equal blocks with distinct
`source_tmp` provenance from colliding. Uncached construction fell from 990 to
533 calls and cumulative block-local SSA time fell from 5.61 to 2.85
profiler-seconds; indexed-Alias program construction fell from 22.83 to 20.33
seconds in the current profile. A semantic-cache-bypassed current-tree A/B ran
in 54.91 seconds / 362,568 KiB with the cache and 57.14 seconds / 354,736 KiB
with only this cache disabled. Both generated exact hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
reported `validation=passed`, and completed clean whole-tail validation.
The focused IR/Alias surface passes 88 tests, `make check-files` passes 75
owned tests plus its file-level gates, and `quality-dev` passes strict mypy over
238 sources, Ruff, mypyc smoke over 38 modules, architecture, ownership, 1,863
curated tests, and the CMP16, LOOPS, and FPTR MS C quality pipelines.

### 4K. Refuse Empty Condition-Relift Work

**Status:** completed

**Reason:** Current-tree instrumentation found four indexed-Alias census
functions containing 23 valid blocks but zero canonical conditional owners,
plus repeated zero-block requests during current-function recovery. Entering
loader reads, global lifter-state isolation, and direct lifts cannot materialize
condition evidence when the authoritative expected-owner set is empty.

**Work:**

- Return a closed empty typed artifact before loader reads and lifter-state
  mutation when the expected-owner set is empty and every supplied block range
  is valid.
- Preserve one empty condition row per canonical block and retain the existing
  refusal path for invalid block ranges or unavailable project boundaries.
- Prove that neither loader reads nor direct lifts run on the empty-owner path.
- Measure direct-lift count and exact output after focused condition gates.

**DoD:** The empty-owner regression proves zero byte reads and zero direct lifts
while returning closed counters and deterministic block rows; invalid-range and
expected-condition regressions still pass; Ruff with `--fix`, strict mypy,
architecture, ownership, and changed-file gates pass; the exact SORTD C hash
and both validation gates remain unchanged; direct lifts fall by the measured
empty-owner block inventory without increasing failures.

**Definition of Failure:** A non-empty expected-owner set takes the fast path,
invalid ranges become accepted, a third-party boundary fixture changes from
`None` to an owned artifact, deterministic block rows disappear, any required
typed condition or pending source is lost, failures increase, exact output or
validation changes, or measured direct-lift work does not fall.

**Completion evidence:** The IR relift owner now returns a closed typed artifact
before byte reads or lifter-state mutation only when the expected-owner set is
empty and every supplied block range is valid. A focused regression proves zero
loader reads, zero direct lifts, deterministic empty block rows, and closed
counters. The seven-file condition surface passes 66 tests, strict mypy and Ruff
pass, and `make check-files` passes its architecture, context, ownership,
ratchet, and owned-test gates. A semantic-cache-bypassed exact SORTD run reduced
direct lifts from 437 to 405, retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
reported `validation=passed`, and completed clean whole-tail validation in
54.16 seconds at 362,912 KiB RSS. The timing remains within the current noise
band and receives no standalone wall-time credit.

### 4L. Reuse Relift Evidence Across Equivalent Frontend Architectures

**Status:** implementation completed; shared-tree acceptance blocked

**Reason:** Validation retries and isolated function projects construct fresh
`Arch86_16` objects with identical lift semantics. The exact-byte relift cache
required Python object identity, so every fresh project rebuilt the same typed
condition artifact. A partial serial census observed 1,197 supplied block
ranges for 202 conditional owners across 156 artifact requests.

**Work:**

- Publish an immutable frontend-owned lift-semantics key containing the exact
  architecture class, bit mode, endness configuration, pyvex architecture, and
  the semantic affine-condition feature state.
- Match complete relift entries by that key and the existing exact byte/request
  contract; retain identity-only matching for unknown architecture boundaries.
- Prove equivalent `Arch86_16` instances hit, changed bit modes miss, unknown
  objects remain identity-scoped, semantic feature changes miss, incomplete
  artifacts remain uncached, and LRU eviction behavior is unchanged.
- Measure one real SORTD relift request across two fresh projects, then run the
  changed-file gate and the current end-to-end target.

**DoD:** Ruff with `--fix`, strict mypy, architecture, ownership, and focused
tests pass; an equivalent fresh project performs zero second-pass direct lifts
and returns the identical immutable complete artifact; changed bytes, changed
bit mode, semantic feature state, unknown architecture identity, and incomplete evidence still miss;
the accepted exact SORTD C hash, function validation, and whole-tail validation
remain unchanged once the shared tree has an accepted baseline again.

**Definition of Failure:** Different lift semantics share an entry; unknown
third-party architectures become equality-scoped; mutable or incomplete
artifacts are reused; the cache becomes unbounded or nondeterministic; the
frontend key omits a runtime field that affects exact-byte lifting; focused
direct lifts do not fall; or accepted generated C/validation changes.

**Implementation evidence:** The frontend now exposes a typed immutable
lift-semantics key, while the IR cache preserves identity fallback for unknown
architectures. Thirteen focused tests and the complete changed-file gate pass,
including strict mypy for both production owners. On the real 12-block SORTD
sleep function, the first fresh project took 21.66 ms and 12 direct lifts; an
equivalent second project returned the same complete artifact in 0.082 ms with
zero additional lifts. End-to-end acceptance remains open: the concurrent
shared tree's unique-key default-parallel run took 193.32 seconds / 660,436 KiB
and failed pre-existing call-argument/parameter whole-tail evidence in
`sub_101f0`, so this task makes no full-run speedup or semantic-acceptance claim.

### 5. Make Validation and Rollback Work Dirty-Pass Driven

**Status:** in progress

**Reason:** Snapshots, cycle scans, regeneration, and tail summaries remain
expensive when a pass is provably stable. Validation must stay authoritative,
but unchanged work should not pay changed-pass costs.

**Work:**

- Extract the guarded pass transaction from `decompiler_postprocess_stage.py`
  into a typed postprocess orchestration module.
- Use typed mutation generations plus the existing mutation witness to detect
  misreported stable passes.
- Delay expensive snapshots and summaries where rollback safety permits; share
  one unchanged-generation cycle/traversal result.
- Preserve unconditional validation for passes that report or witness mutation.

**DoD:** Truly stable passes skip regeneration and tail-summary collection;
mutating passes, including a pass that falsely returns `False`, still snapshot,
validate, and roll back on failure; output and validation match baseline; focused
snapshot, mutation-witness, and tail-validation tests pass.

**Definition of Failure:** Any mutating pass bypasses validation, rollback cannot
restore metadata and AST coherently, a stable declaration/typed-input mutation
is missed, or a speedup is obtained by disabling validation.

### 5A. Batch the Exact Structured-AST Mutation Witness

**Status:** rejected and removed

**Reason:** Guarded optimization passes currently build six complete structured-
AST generations on the exact target. The generation owner spends about 2.52
profiler-seconds, including about 0.88 seconds in roughly 302,000 atom writes
that each issue two incremental hash updates. The byte stream is deterministic
and bounded by the already traversed AST, so batching the identical stream is a
smaller and safer first optimization than weakening mutation detection.

**Work:**

- Accumulate the existing length-delimited generation byte stream in one owned
  buffer and hash it once when the generation closes.
- Preserve exact atom order, lengths, reference numbering, node count, dynamic
  boundary handling, and digest bytes.
- Add focused equivalence tests covering scalar fields, shared references,
  mappings, sequences, sets, in-place field mutation, and raising properties.
- Re-profile the exact target before considering a different mutation witness.

**DoD:** Existing and new generation tests pass under `pytest -n 7`; Ruff with
`--fix` and strict mypy pass for the owner; every fixture produces the exact
pre-change digest and node count; an in-place mutation still changes the
generation; the exact target retains its accepted C hash and both validation
gates; generation cumulative time falls materially without exceeding the 2 GB
aggregate memory budget.

**Definition of Failure:** Any digest or node-count fixture changes, mutation
becomes invisible, unordered input becomes nondeterministic, dynamic boundary
errors escape, peak memory approaches the project budget, end-to-end output or
validation changes, or the measured generation cost does not improve enough to
justify the buffer.

**Rejected experiment:** Batching preserved the exact established digest and
mutation behavior, and focused tests plus Ruff and strict mypy passed. On a
five-run 1,001-node fixture, however, median generation time improved only 98.1
ms -> 93.8 ms (4.4%) while retaining the complete byte stream in memory. This
triggered the task's Definition of Failure, so the implementation and its
temporary fixture test were removed. A later 12,001-node check regressed from
0.359 to 0.528 CPU-seconds per generation and was likewise removed.

### 5B. Type Guarded-Pass State and Preflight Policy

**Status:** completed

**Reason:** The guarded pass driver is a roughly 1,100-line nested closure with
four mutable nonlocals and duplicated dynamic policy reads. That makes mutation
impact, snapshot ownership, and validation requirements difficult to review or
extend safely. A typed transaction boundary is the prerequisite for publishing
the consumer-specific mutation impact required by Task 3D; extraction alone is
not a runtime optimization claim.

**Work:**

- Move accepted-change, validation-baseline, cycle-path, and last-changed-pass
  state into one typed request-owned transaction contract.
- Move pass refusal, reject-budget, snapshot, and validation-enforcement policy
  into a pure typed preflight decision below the dynamic angr boundary.
- Keep metadata publication and semantic callbacks in their existing owners;
  do not infer impact from pass names, rendered C, or object identity.
- Add focused policy/state tests before extracting mutation witness and rollback
  execution in the next bounded transaction slice.

**DoD:** Every preflight outcome is represented by a typed enum/result; focused
tests cover ordinary execution, mandatory/forced validation, large-function
refusal, optional reject-budget skipping, optimization-pass validation, and
transaction-state updates; Ruff with `--fix` and strict mypy pass; the stage is
smaller; exact generated-C hash, function validation, and whole-tail validation
match the accepted baseline. Any runtime change is measured separately and no
speedup is claimed from extraction alone.

**Definition of Failure:** Validation or snapshot requirements weaken, a pass
that previously executed is refused or skipped without the same evidence,
dynamic codegen state becomes an untyped owned contract, mutable state remains
split between the closure and the new owner, semantics move into Rewrite,
the stage grows, focused gates fail, or generated output/validation changes.

**Completion evidence:** The 167-line typed
`postprocess/pass_transaction.py` now owns all four request-local transaction
fields and returns enum-backed preflight actions with lazy local-evidence
probing. Static force-validation policy moved to its existing policy owner,
which remains below 350 lines, and stale tests now assert that owner directly.
Strict mypy passes for the stage and both transaction-policy modules; Ruff,
changed-file linters, architecture/agent-context/ownership guards, and 134
focused policy/snapshot/runtime tests pass under `pytest -n 7`. The stage fell
to 17,882 lines. The exact sidecar-free `0x10554` run retained C hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation in 61.83 seconds with
317,348 KiB peak RSS. No runtime speedup is claimed for this extraction.

### 5C. Publish Accepted Postprocess Mutation Generations

**Status:** completed

**Reason:** Task 3D cannot replace whole-AST fingerprints with pass return
values because the guarded driver explicitly detects false `changed=False`
reports. The transaction state is the earliest owner that knows whether a
reported or witnessed mutation survived rollback and validation. It must
publish that accepted generation before consumer-specific replay can skip a
full witness safely.

**Work:**

- Add a typed immutable mutation-generation contract to the guarded transaction
  owner.
- Increment it only in `accept_change`, after the mutation has survived the
  existing cycle, rollback, and validation gates.
- Publish the final typed generation at the dynamic codegen boundary when the
  transaction closes, including early completion paths.
- Test stable, multiple accepted, misreported-and-witnessed, and rejected or
  restored mutations without changing pass scheduling.

**DoD:** Stable or rejected passes do not advance the generation; every accepted
reported or witnessed mutation advances it exactly once; all completion paths
publish one typed immutable value; focused Ruff with `--fix`, strict mypy,
transaction/snapshot/validation tests, architecture, and ownership checks pass;
the stage does not grow; exact C hash and both validation gates are unchanged.

**Definition of Failure:** A pass return value advances generation before
validation, rollback leaves an advanced generation, a witnessed false-stable
mutation is omitted, state is published as an untyped integer/string, any
existing validation or replay is skipped, the stage grows, or generated output
and validation change.

**Completion evidence:** `PostprocessPassTransactionState8616` now owns a typed
immutable accepted-mutation generation and increments it only through
`accept_change`, after the existing witness, cycle, rollback, and validation
gates. All three stage completion paths publish the typed generation. Stable,
multiple accepted, witnessed-name, and restored-state tests pass; the live
target restored three rejected cleanup passes without weakening validation.
Ruff with `--fix`, strict mypy, and 132 focused transaction, snapshot,
validation-policy, and rollback-cache tests pass under `pytest -n 7`; the
protected register-local owner also passes Ruff and strict mypy. The stage fell
from 17,882 to 17,874 lines for this slice. The current shared-tree output hash
is `f86bd521ce979ae1ee2b5789853ac813978cf9d1928c7e73d3189f491c28db78`;
the live 40.54-second run used 273,964 KiB RSS and passed function and whole-tail
validation. This prerequisite does not claim a runtime speedup by itself.

### 6. Split and Type `decompiler_postprocess_stage.py`

**Status:** in progress

**Reason:** The roughly 18,000-line module slows comprehension and type
checking, hides ownership, and blocks mypyc promotion. Extraction follows
measured boundaries, not cosmetic line movement.

**Work:**

- Move pass transaction/runtime configuration into a typed orchestration owner.
- Move validation-delta classification callbacks into validation-owned modules.
- Move remaining Structuring/Lowering compatibility shims to their authoritative
  owners, then delete redundant wrappers.
- Replace avoidable owned-contract `getattr`/`setattr` with dot access.
- Keep new modules below 350 lines where practical and prevent net growth of the
  original stage.
- Make each extracted production module independently pass strict mypy.

**DoD:** The stage is materially smaller; extracted modules have `Layer:` and
`Responsibility:` headers, explicit types and public docstrings; focused mypy no
longer emits `no-any-return` for moved contracts; architecture import checks and
ownership tests pass; decompiler output and validation remain unchanged.

**Definition of Failure:** Code is moved without changing ownership clarity,
casts merely conceal an untyped owned contract, semantic recovery moves later in
the pipeline, the stage grows, public behavior exists only in implementation,
or focused gates fail.

### 6A. Cache Bounded Function Instruction Inventory in Frontend

**Status:** completed

**Reason:** The fresh accepted profile charges 1.17 profiler-seconds to 74
calls of the stage-local linear instruction collector. The binary instruction
surface is immutable for one function request, but the 18k-line postprocess
stage repeatedly decodes and merges the same bounded stream.

**Work:**

- Move the bounded sequential decode and its typed result contract to the
  Frontend instruction-inventory owner.
- Key reuse by function entry, window, and the exact base-instruction surface.
- Leave only a compatibility wrapper and third-party codegen publication in the
  stage; preserve instruction-byte evidence and deterministic address order.

**DoD:** Focused tests prove exact reuse and invalidation for function, window,
and base-inventory changes; the stage becomes smaller; Ruff, strict mypy,
architecture, and ownership checks pass; the exact target preserves C hash and
validation; profile calls and cumulative time for the stage wrapper fall
materially.

**Definition of Failure:** A changed immutable instruction surface reuses stale
data, decode failures are reported as complete evidence, instruction ordering
or byte evidence changes, semantic classification moves into Frontend, the
stage grows, or output and validation differ.

**Completion evidence:** Exact function/window/base-surface tests prove reuse
and invalidation, and a stage regression proves cached byte evidence is not
reloaded. Ruff, strict mypy, architecture, agent-context, ownership, and 24
focused tests pass. The stage shrank by five lines in this slice and the
Frontend owner remains below 350 lines. On the accepted sidecar-free `0x10554`
profile, the stage wrapper fell from 74 calls / 1.170 cumulative seconds to 74
calls / 0.150 seconds. Generated C retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation. Total profiler time was
noisier and rose from 82.58 to 87.35 seconds, so only the isolated 1.02-second
owner reduction is credited.

### 6B. Close Exact Register-Local Declaration Coherence

**Status:** completed

**Reason:** The typed Lowering owner removed an entire provisional unified-map
key when moving one declaration, which could discard unrelated declarations.
It could also retain both stale and current type entries for the same exact
declaration. That violates the one-storage/one-authoritative-type contract and
can produce unstable or incorrect local declarations after replay.

**Work:**

- Remove only entries belonging to the moved declaration from provisional keys.
- Preserve peer declarations and delete a provisional key only when empty.
- Replace stale type entries under the exact unified identity and prove replay
  idempotence.
- Publish and enforce closed raw/normalized/classified/materialized/failure
  accounting.

**DoD:** Focused tests prove peer preservation, stale-type replacement, exact
unified identity, idempotence, missing-type refusal, and closed counters; Ruff
with `--fix` and strict mypy pass; the exact target retains its C hash and both
validation gates.

**Definition of Failure:** A peer declaration is removed, multiple types remain
for one declaration, a missing type is guessed, map repair becomes identity- or
name-heuristic, counters do not close, repeated replay reports a mutation, or
generated output/validation changes.

**Completion evidence:** Ruff, strict mypy, and six focused tests pass. The
coherence regression proves peer preservation, stale-type replacement, exact
unified identity, idempotence, missing-type refusal, and closed counters. The
exact sidecar-free target retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation.

### 6C. Extract Postprocess Runtime Configuration

**Status:** completed

**Reason:** Runtime policy, replacement authorization, complexity thresholds,
baseline-summary selection, and dynamic metadata publication are embedded in
the 18k-line stage. This slows review and typing and obscures the boundary
between immutable pass policy and guarded pass execution.

**Work:**

- Move the complete runtime-configuration transaction to a typed Rewrite
  orchestration owner below 350 lines.
- Keep only a compatibility wrapper and explicit complexity/baseline callbacks
  in the stage.
- Remove dead rebased trace-address computation and preserve every published
  metadata field and environment policy.

**DoD:** The extracted module has a Layer/Responsibility header, strict types,
and public docs; the stage shrinks materially; existing replacement/rebase,
large-function, baseline, timeout, and skip-policy tests pass; Ruff with `--fix`,
strict mypy, architecture, and ownership checks pass; exact output and
validation remain unchanged.

**Definition of Failure:** Dynamic policy is duplicated, metadata publication
changes, a cached baseline is ignored, large-function validation is weakened,
semantic recovery moves into Rewrite, the stage grows, or focused/exact gates
fail.

**Completion evidence:** Runtime configuration now lives in the 147-line typed
`postprocess/runtime_configuration.py`; the compatibility stage fell to 17,949
lines. Ruff, strict mypy, ten focused runtime/inventory tests, changed-file
linters, startup architecture, agent-context, and ownership checks pass. The
exact target retained the accepted C hash, `validation=passed`, and clean
whole-tail validation; the acceptance run completed in 50.64 seconds with
317,348 KiB peak RSS. This extraction claims maintainability/checking value,
not a runtime speedup.

### 6D. Extract Guarded Bootstrap Orchestration

**Status:** completed

**Reason:** The stage contains a long repeated sequence of skip checks, guarded
callback invocation, timing, validation-failure checks, and two special debug
messages. The sequence owns no semantics but obscures the guarded transaction
and makes pass order difficult to test independently.

**Work:**

- Move deterministic bootstrap sequencing into a typed Rewrite orchestration
  module below 350 lines.
- Inject every semantic operation from its existing authoritative boundary.
- Preserve skip policy, selector-return JCC suppression, timing/debug output,
  and stop-on-validation-failure behavior.

**DoD:** The stage shrinks materially; focused tests prove exact order, separate
MOV/INCDEC validation, skip behavior, JCC suppression, and immediate failure
stop; Ruff with `--fix`, strict mypy, architecture, ownership, and exact target
acceptance pass.

**Definition of Failure:** The extracted module implements semantic recovery,
reorders commands, combines MOV and INCDEC validation, runs after failure,
changes selector-return suppression, grows beyond 350 lines, or exact output and
validation change.

**Completion evidence:** Bootstrap sequencing now lives in the 149-line typed
`postprocess/bootstrap_orchestration.py`; the compatibility stage fell to
17,898 lines. Ruff, strict mypy, changed-file linters, 114 focused
bootstrap/snapshot tests, startup architecture, agent-context, and ownership
checks pass. Exact output retained hash
`9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
`validation=passed`, and clean whole-tail validation. The acceptance run was
60.82 seconds with 646,348 KiB RSS; no runtime gain is claimed.

### 6E. Extract Typed Validation Blocking-Reason Policy

**Status:** completed

**Reason:** Parsing and recording typed postprocess blocking reasons lived in
the 17k-line stage even though the enum and contract owner already lived in
`postprocess/validation_contracts.py`. This duplicated ownership and made a
small policy change require checking the entire stage.

**Work:**

- Move blocking-reason parsing, coercion, de-duplication, and publication to
  the existing typed validation-contract owner.
- Preserve stage compatibility imports for current callers and tests.
- Keep dynamic codegen mutation and validation execution in the stage.

**DoD:** The validation-contract owner remains below 350 lines with a
Layer/Responsibility header, strict types, and public docs; the stage shrinks;
existing snapshot and transaction tests pass; Ruff with `--fix`, strict mypy,
startup architecture, ownership, and diff checks pass; no semantic policy or
generated output changes.

**Definition of Failure:** Blocking reasons change order or multiplicity,
unknown values stop failing closed, dynamic stage execution moves into the
contract owner, either file loses types/docs, the owner exceeds 350 lines, the
stage grows, or focused architecture/tests fail.

**Completion evidence:** The 199-line validation-contract owner now owns typed
blocking-reason parsing and publication. Stage compatibility aliases preserve
existing consumers, while the stage fell from 17,874 to 17,839 lines. Ruff
with `--fix`, strict mypy including the untracked transaction owner, 120 focused
snapshot/transaction tests under `pytest -n 7`, startup architecture, ownership,
and diff checks pass. This extraction improves review and checking scope; it
does not claim a runtime speedup.

### 7. Compile Proven Hotspots With mypyc

**Status:** pending; `c_ast_utils` candidate rejected

**Reason:** mypyc is useful only after profiling and strict typing identify a
CPU-bound, stable contract. Compiling orchestration dominated by dynamic angr
objects will add build cost without useful speedup.

**Work:**

- Re-profile after Tasks 3-6.
- Select only typed CPU hotspots with low dynamic-boundary density, starting
  with traversal/index and pure fingerprint/generation helpers.
- Benchmark interpreted and mypyc builds with identical inputs and caches.

**DoD:** Each promoted module passes strict mypy and produces identical results;
three comparable runs show a repeatable end-to-end or hotspot improvement that
exceeds build/import overhead; fallback Python execution remains supported.

**Definition of Failure:** A module is compiled only because it is large,
dynamic `Any` is hidden to satisfy mypyc, generated C or validation changes,
startup/build overhead consumes the gain, or the improvement is noise.

**Rejected `c_ast_utils` candidate:** The hot walker passed strict mypy and
compiled successfully. A verified native-path run used `python -P` so the
isolated `.so`, rather than the source checkout, was imported. Generated C was
byte-identical and both validation gates passed, but wall time changed only
55.16 -> 54.64 seconds while RSS rose from 319,312 to 659,196 KiB. This is
noise with a material memory regression, so the walker is not promoted.

**Rejected `vex_import` candidate:** The module passed strict mypy and an
incremental native build completed in 11.73 seconds. Controlled source and
native runs from the same parent import context preserved the exact accepted C
hash and both validation gates, but measured 55.33 seconds / 694,380 KiB and
55.41 seconds / 694,784 KiB respectively. The native path provided no runtime
gain, so it was removed from the mypyc cohort and the normal 38-module build was
restored.

### 7A. Make mypyc Module-Cohort Changes Incremental

**Status:** completed

**Reason:** Adding one experimental `--module` changes the exact cohort string,
deletes the entire isolated mypyc cache, and rebuilds all configured modules.
The `c_ast_utils` probe rebuilt 39 modules and cost about 96 seconds before its
runtime value could be measured. This directly slows evidence-driven hotspot
selection.

**Work:**

- Separate the build schema from the requested module cohort.
- Preserve valid artifacts and markers for modules present in both cohorts.
- Remove only the extension pair, marker, and generated sources for a retired
  module.
- Keep full invalidation for a schema change and keep import smoke coverage for
  the complete requested cohort.

**DoD:** Adding one module marks only that module stale; removing one module
deletes only its importable native pair while preserving unrelated artifacts;
a schema change still resets the complete cache; focused Ruff with `--fix`,
strict mypy, and pytest pass; a live add/remove probe demonstrates incremental
behavior.

**Definition of Failure:** A removed extension remains importable, an unchanged
module rebuilds solely because cohort membership changed, a schema change
reuses incompatible artifacts, cache reconciliation can delete paths outside
the cache, the build script grows beyond 350 lines, or focused checks fail.

**Completion evidence:** Cache schema and module cohort now have separate typed
ownership in `scripts/mypyc_build_cache.py`; `scripts/build_mypyc.py` shrank
from 350 to 345 lines. Both tooling owners are promoted into the global
Makefile Ruff and typed-file lists. Ruff with `--fix`, strict mypy, the combined
`linters-files` target, nine focused tests under `pytest -n 7`, and diff checks
pass. Configuration and nested-package symlink tests prove cleanup cannot
escape the cache root. The one-time schema migration rebuilt 38
modules in 93.09 seconds at 240,792 KiB RSS. Adding `c_ast_utils` then compiled
only its main/native extension pair in 11.87 seconds while an existing
`validation_calls` artifact retained the same hash and mtime. Removing the
candidate rebuilt nothing, deleted both candidate extensions, smoke-tested all
38 default modules, and finished in 2.96 seconds.

### 8. Tune Outer Function Parallelism After Single-Function Costs Fall

**Status:** pending

**Reason:** Independent functions are the safe parallel boundary. Increasing
workers cannot accelerate one dominant mutable function and may hide its cost.

**Work:**

- Compare 1, 4, and N-1 workers on a multi-function binary after hotspot fixes.
- Keep deterministic result ordering and aggregate worker memory near or below
  2 GB.
- Record worker utilization, wall time, RSS, failures, and fallback counts.

**DoD:** The default worker policy selects the fastest stable bounded setting;
multi-function output ordering and hashes are deterministic; no worker crash,
timeout increase, or validation degradation occurs.

**Definition of Failure:** One mutable AST is shared across workers, peak memory
is unbounded, faster timing comes from missing functions or fallback, output
ordering changes, or worker overhead makes the default slower.

### 9. Final Regression and Performance Ratchet

**Status:** pending

**Reason:** A local microbenchmark is insufficient evidence for a decompiler
change. The improvement must survive focused and broad project gates.

**Work:**

- Run changed-file Ruff with `--fix`, strict typing, architecture, ownership,
  focused semantic tests, and `make quality-dev`.
- Run `make test-pipeline` before claiming semantic safety.
- Repeat the cold benchmark three times and report median, range, RSS, output
  hash, validation, and comparison to Task 1.
- Add a non-flaky performance ratchet only after variance is measured.

**DoD:** All required checks pass; three cold runs preserve semantic output and
show a repeatable material wall-time reduction; no previously generated function
disappears; the plan records final evidence and remaining bottlenecks.

**Definition of Failure:** Any gate is skipped without disclosure, tests are
weakened or removed, timing is reported from a single warm run, semantic hashes
or validation regress, or the ratchet is tighter than observed machine variance.

## Progress Rule

Update each task status and its evidence immediately after completion. Do not
mark a task complete from implementation alone: its DoD evidence must be present.
If a Definition of Failure triggers, restore the last accepted local behavior,
record the failed experiment, and continue with the next evidence-backed design.

## Execution Log

- A structured-AST digest initially evaluated angr properties and crashed on
  `Function.offset`. The digest now reads stored boundary state without executing
  descriptors; a raising-property regression test covers the contract.
- Reusing Structuring's known cycle state reduced the comparable cold run from
  128.91 to 113.66 seconds and preserved the exact C hash. The pure-binary
  validation failure remained unchanged. Task 1 records that status as the
  performance baseline; Task 3 still requires a stable-replay win.
- Postprocess now reuses known cycle state and resets it on rollback. Focused
  scan-count tests pass, but the first contended benchmark showed no material
  postprocess-time gain; this is not counted as a completed performance DoD.
- Direct-stack tagged reload traversal now stops after its first proven result.
  Its focused call-count test passes and the C hash is unchanged, but its isolated
  end-to-end effect was below observed run variance.
- The old profile attributes 78.33 cumulative seconds to deep C-AST iteration,
  including 45.38 profiler seconds in child-container generator handoff. An
  equivalent iterative child stack preserved output but measured 121.88 seconds
  versus 122.04 seconds; it failed the performance DoD and was reverted. Task 4
  must eliminate repeated traversals with an index rather than micro-tune them.
- A whole-AST segment/global replay digest was rejected and removed. On the
  target function it computed nine generations in 0.84 seconds but skipped zero
  structuring replays; all nine owner executions still ran. This triggered Task
  2's Definition of Failure and confirms that invalidation must be published at
  authoritative mutation sites rather than rediscovered by hashing the AST.
- The first request-owned exact-address index removes provably impossible
  tagged reload searches and reports closed query/hit/miss counters. Its focused
  Ruff, strict mypy, and nine reload/generation tests pass, and the target C hash
  remains exact. The first cold integration run measured 125.13 seconds wall
  time and 99.26 seconds function time, so it did not beat the best comparable
  113.66-second wall baseline. Task 4 remains in progress until profile evidence
  shows a material aggregate traversal reduction across higher-impact consumers.
- A direct-global cleanup probe found 54,480 comparison-only global-expression
  constructions from 9,804 assignment checks. Per-cleanup caching now constructs
  each immutable evidence expression once; its focused call-count test, Ruff,
  and strict mypy pass, and the exact target C hash is unchanged. The first cold
  run was 114.02 seconds versus the best comparable 113.66 seconds, so this is
  retained as bounded redundant-work removal but not counted as an end-to-end
  performance DoD.
- Register-local declaration publication now belongs to
  `lowering/register_local_declarations.py`. Structuring replays that typed owner;
  postprocess only restores third-party codegen pointers and no longer invents a
  fallback `short`, mutates declaration maps, or resolves unified identities.
  Six declaration tests, four selector tests, strict mypy, architecture, and
  ownership pass; the pure-binary target preserves the exact C hash and existing
  validation status.
- Current focused gates: Ruff clean; strict focused mypy clean for
  `c_ast_utils.py`, generation modules, and `register_local_declarations.py`;
  architecture and ownership checks pass; focused traversal/replay tests pass.
- A transitive strict-mypy probe remains blocked by concurrent global debt (151
  errors in 46 imported files). No ignore or cast was added to conceal it.
- Typed owner-result narrowing now lives in `pipeline/result_contracts.py` and
  rejects incorrect runtime return types with `PipelineHardError`. The stage,
  result boundary, register-local owner, validation contracts, and static pass
  policy pass focused strict mypy with zero errors; no cast or ignore hides the
  former 86 `no-any-return` errors.
- Postprocess validation enums/records moved to
  `postprocess/validation_contracts.py`; immutable pass-name policy moved to
  `postprocess/pass_validation_policy.py`. Both modules are below 350 lines,
  carry exact ownership headers, and have focused contract tests. The stage is
  now 17,964 lines versus its 17,974-line pre-work baseline.
- The focused postprocess/register boundary suite passes 192 tests under
  `pytest -n 7`; startup architecture and ownership checks pass. The full
  architecture checker still reports concurrent ownership/promotion defects in
  unrelated alias, IR, and widening files, so Task 6 remains in progress.
- A direct-global lvalue type prefilter preserves unknown third-party boundary
  objects while avoiding impossible comparisons for known non-variable C
  expressions. Its focused tests pass and the target output hash remains exact.
  The cold target run measured 123.58 seconds versus the 113.66-second best
  baseline, so this is bounded redundant-work removal, not a completed runtime
  DoD.
- A typed `PostprocessRollbackSnapshotCache8616` now reuses one coherent C-AST,
  metadata, text, project-function, and cycle snapshot across consecutive passes
  that report no mutation. Every accepted mutation, detected cycle mutation,
  exception, pre-pass root repair, and restore invalidates the cache. Four cache
  contract tests and 182 focused postprocess/structuring tests pass; strict mypy,
  Ruff, startup architecture, and ownership pass. The comparable cold run was
  111.01 seconds versus 113.66 seconds, with the exact C hash and the same three
  existing final def-use failures. This is a 2.3% accepted improvement, while
  Task 5 remains open for the typed transaction extraction and general mutation
  witness.
- A request-owned control-flow validation index builds root loop, condition,
  break-guard, and exact-address surfaces once and lazily indexes each loop body.
  `validation_control_flow.py` fell from 762 to 653 lines; the new owner is 210
  lines. The first uncontended cold run was 96.14 seconds and 316,924 KiB RSS,
  down 13.4% from the preceding 111.01-second run and 15.4% from the 113.66-second
  accepted baseline. The exact C hash and same three final def-use failures were
  preserved.
- The request index is now shared by required-call matching, call interfaces,
  argument classes, branch conditions, storage identity, software-interrupt
  validation, and control-flow validation. Required-call matching is a typed
  request contract built once rather than three times per summary; the old
  profile recorded 81 builds and 5.40 cumulative profiler-seconds. Focused
  validation tests pass 416 cases, with direct tests that fail on a root rewalk,
  wrong-root reuse, or match-surface rebuild. Strict focused mypy, Ruff, startup
  architecture, and ownership checks pass. An adjacent controlled run measured
  102.87 seconds and 642,948 KiB RSS with the exact C hash and existing three
  final def-use failures; it does not replace the 96.14-second best run.
- Direct-stack existing-update checks now collect one immutable node tuple and
  use it for both rendered-owner and semantic-match queries. A call-count test
  enforces one traversal instead of two; strict mypy, Ruff, and 250 focused
  lowering tests pass. Its 106.84-second run and the subsequent shared-index
  110.31-second run overlapped another active `decompile.py` process and are not
  valid comparative timing evidence. Both retained the exact C hash and same
  validation defects.
- INC/DEC replay now builds one request-owned AST index and reuses it across
  loop, existing-assignment, conflict, and dirty-assignment queries while the
  root is unchanged. Any material mutation rebuilds the index before the next
  fact. Ruff and strict mypy pass; 253 focused direct-stack and segmented-runtime
  tests pass, including a test that forbids a root rewalk when an index is
  supplied. The adjacent controlled run measured 101.57 seconds and 642,792 KiB
  RSS versus 102.87 seconds before the change; stable replay rounds fell from
  about 1.31-1.56 seconds to 1.14-1.36 seconds. The exact C hash and existing
  validation findings are unchanged. This is accepted as a bounded traversal
  reduction, not as a new best end-to-end result.
- A fresh core profile attributed 108.53 cumulative profiler-seconds to
  Structuring validation priming and 63.25 seconds to its segment/global
  coordinator. Within that owner, named, indexed, direct-store, and runtime
  lowering cost 9.44, 17.17, 11.34, and 36.76 seconds respectively. The shared
  deep walker handled about 2.91 million calls. This displaced mypyc and outer
  parallelism from the immediate queue: the largest cost remained redundant
  single-function AST work.
- Runtime-segment lowering now owns a request-local decomposition cache for
  generated linear carriers. It distinguishes a cached refusal from a miss and
  reports closed query accounting. On the target, each replay recorded about
  1,869 queries, 1,285 hits, and 584 misses; stable runtime rounds fell from
  roughly 0.48-0.63 seconds to 0.38-0.47 seconds. The controlled run measured
  99.89 seconds and 316,708 KiB RSS with the exact output hash and unchanged
  validation findings. Focused Ruff, strict mypy, and 313 tests pass.
- The shared lowering child replacer now consults its cached per-node-class
  child-slot map before probing third-party attributes. The previous profile
  charged child replacement 6.03 seconds inside named-global lowering and
  17.53 seconds inside runtime-segment lowering. The exact no-sidecar target
  completed in 91.08 seconds and 317,176 KiB RSS, improving the previous
  96.14-second best by 5.3% while preserving hash
  `98b6c22798ca9634eb08eec8cd7b50d2fbfcb02028ea4b5e6024c02e858762e6`
  and the same three final def-use findings.
- The postprocess compatibility replacer now applies the same child-slot guard,
  so `decompiler_postprocess_stage.py`, flags cleanup, simplification, and CLI
  regeneration no longer probe every possible child descriptor on every node.
  A descriptor regression, strict mypy, startup architecture, ownership, and
  467 focused tests pass. Its adjacent run preserved exact semantics and reduced
  the logged postprocess pass block from 12.7 to 11.7 seconds, but total wall
  time was 100.25 seconds with 642,996 KiB RSS; this is retained as bounded
  traversal removal and does not replace the 91.08-second best.
- Two segment/global materializers now discover statement blocks through the
  statement-only walker instead of walking every expression merely to find
  `CStatements`. Ruff, strict mypy, and the 185-item focused surface pass. A
  73.20-second current-generation run did not beat the 68.93-second baseline,
  so this is retained as bounded traversal removal rather than an end-to-end
  performance DoD.
- A parent-process `cProfile` attempt is invalid attribution evidence because
  the profiler spent almost all of its time waiting in `select.select` for the
  decompiler child process. Targeted in-child timing is authoritative for the
  current generation instead.
- Current-generation targeted timing attributes about 11 seconds to repeated
  segment/global coordination: indexed, runtime, direct, and named owners total
  approximately 4.45, 4.04, 2.71, and 1.79 seconds respectively. Postprocess is
  now about 1.3 seconds, so further postprocess micro-optimization is not the
  biggest current feedback win.
- Twenty-four segment/global rounds contain approximately two seconds of
  identical-root stable repeats. Whole-AST hashing remains forbidden as the
  authoritative skip contract because consumed evidence generations are not yet
  complete and later rounds can become productive after stable rounds.
- Graph and targeted profiling identified two Alias program builds in the
  direct-address startup path: a local target-function fact determines whether
  whole-program evidence is required, then the complete discovery census builds
  every function again. Reuse is under investigation at the Alias boundary and
  will be accepted only with exact-address, closed-accounting, and binary-
  provenance evidence; call-count suppression alone is insufficient.
- Instrumentation disproved the apparent Alias duplication. The local build
  materialized `0x10554` in 0.53 seconds, while the 7.93-second program build
  contained a distinct `0x10560` boundary and did not contain `0x10554`.
  Overlapping blocks are not identity evidence, so no unsafe reuse was added.
- The shared tree now scopes the persisted indexed-Alias layout cache to
  discovery, IR, Alias, and Widening implementation sources instead of the full
  decompiler. This should preserve the expensive whole-program artifact across
  ordinary postprocess/lowering edits; focused cache-key and exclusion tests are
  the next acceptance gate.
- The cache scope gate now passes 32 focused tests, including fresh-project
  persisted-layout reuse and explicit exclusion of postprocess, register-local,
  segmented-global, and AST-query/generation files. With the final-result cache
  disabled by `--trace-c-stages`, a bounded first run reached decompilation in
  16 seconds and the identical second run reached it in 2 seconds. The 14-second
  feedback improvement completes Task 2; cold-cache correctness remains covered
  by the wider owner source digest and binary content fingerprint.
- `StructuredAstQueryIndex8616` now exposes typed statement, assignment, call,
  and variable projections. `StructuredAstQuerySession8616` owns closed
  build/hit/invalidation accounting and rebuilds immediately after a reported
  mutation. Indexed-global lowering shares one index across stable word-pair,
  instruction-store, lvalue, and carrier subpasses. A call-count regression
  proves one build for the stable sequence; 188 indexed-global tests, Ruff, and
  strict mypy pass.
- The exact target after query-index integration preserved current hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`
  and clean validation, but measured 126.61 seconds and 643,576 KiB RSS. This
  does not establish an end-to-end speedup against the 68.93-second current
  baseline, so Task 4 remains in progress and only the measured traversal-count
  reduction is accepted.
- Direct-stack component timing on the current generation attributes about
  9.8 seconds to eight Structuring/validation-prime MOV replays and about 1.7
  seconds to eight later compatibility replays. Stable Structuring MOV rounds
  cost about 0.80-1.02 seconds each; reload matching and branch ownership are
  the largest cleanup components, but the aggregate remains smaller than the
  whole core and must be ranked against segment/global and validation owners.
- An exact tagged-assignment lookup was implemented, passed focused tests,
  preserved hash and validation, and then removed because tagged reload time
  remained about 0.32 seconds per stable replay. The target primarily exercised
  the untagged/register-use path, so the experiment triggered Task 4's
  Definition of Failure: additional index complexity without a measured owner
  reduction is not retained.
- A current low-overhead run completed in 76.68 seconds wall time and 315,956
  KiB peak RSS, preserving hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`
  and clean whole-tail validation. Its isolated decompiler child consumed
  55.56 seconds; parent OTEL cannot decompose that child, so the next ranking
  uses the built-in `INERTIA_CORE_CPROFILE_PATH` profiler inside the child.
- The authoritative in-child profile recorded 286.2 million calls and 168.4
  profiler-seconds in the core. Structuring validation priming owned 101.2
  inclusive seconds, segment/global replay 51.0, direct-stack replay 43.5, and
  the shared deep C-AST walker 55.3. In contrast, typed register-local
  declaration replay cost 0.27 and postprocess was no longer a leading owner.
  This confirms that replay traversal is the current feedback bottleneck and
  that postprocess extraction must not displace higher-impact runtime work.
- The tagged reload index now retains exact assignment objects in deterministic
  traversal order. Lowering can prove a wrong-register miss or update the exact
  assignment in place without recursively searching the entire AST; any
  unindexed insertion marks the request index incomplete and restores the safe
  traversal path. Eleven focused tests, Ruff, and strict mypy pass. On the exact
  target, `reload_tagged` fell from about 0.13 seconds to 0.002-0.003 seconds per
  Structuring replay, stable MOV rounds fell from 0.80-1.02 to 0.66-0.72
  seconds, and wall time fell from 76.68 to 66.96 seconds at 315,536 KiB RSS.
  The exact C hash and clean whole-tail validation are unchanged, completing
  this bounded Task 4 migration.
- Per-pass completion timing shows the four validated semantic passes that
  report no mutation consume only about 2.3 seconds in aggregate on the target.
  The costly Lowering replays occur mainly before the pass loop and before final
  validation, so skipping validation for stable semantic passes is not the next
  largest feedback win and remains subordinate to replay optimization.
- Postprocess pass descriptors and environment-derived runtime policy now live
  in typed `postprocess/pass_runtime.py` (126 lines). The dynamic stage keeps its
  five-value compatibility boundary but is 39 lines smaller in this checkout;
  no semantic owner moved into Rewrite. Strict mypy passes for the new owner,
  stage, and register-local owner; Ruff, architecture, ownership, and 232
  focused tests pass. The exact target preserves the accepted hash and clean
  validation at 69.44 seconds and 569,708 KiB RSS. This completes one bounded
  Task 6 extraction, not Task 6 as a whole.
- Current-generation component timing attributes about 12.3 seconds across the
  eleven main segment/global rounds. Runtime-segment lowering is the largest
  stable-round component at about 4.3 seconds, followed by indexed-global,
  direct-store, and named-global lowering. The later compatibility rounds cost
  only about 0.4 seconds in aggregate, so runtime-segment matching remains the
  next bounded Task 3/4 target.
- Runtime-segment feasibility now scans only the current expression root's
  top-level additive terms. Statements, calls, loops, dereferences considered
  as addresses, and other structured-C containers are refused without walking
  their descendants because the child replacer visits those expressions
  independently and linear decomposition cannot consume a nested arbitrary
  child as the current root's segment. A regression forbids container descent;
  all 236 segmented-runtime tests, Ruff, and strict mypy pass. One concurrent
  benchmark preserved exact hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`
  and clean validation, and its stable runtime rounds fell from about 3.74 to
  3.24 seconds in aggregate. Another agent's seven-process decompilation and
  mypyc work contaminated wall time and first-round timing, so this slice is
  semantically accepted but still requires an uncontended end-to-end run before
  receiving total-runtime credit.
- The next cold-run owner is now exact rather than inferred: seven distinct
  callee-arity requests spent 9.04 profiler-seconds in caller census, of which
  8.22 seconds came from repeatedly decoding independently framed caller ranges
  and 6.34 seconds came from rebuilding the same exact Frontend reachability
  boundaries 399 times. Ordinary recovered-function neighbor scanning cost only
  0.56 seconds, so it is not the immediate target.
- `frontend_function_boundary_index.py` now owns an immutable, exact-range-keyed
  boundary inventory on each binary project. Caller census consumes that typed
  Frontend index without changing target matching, callsite summarization, or
  closed evidence accounting. Ruff, strict mypy, and 14 focused tests pass. The
  uncontended exact target completed in 65.94 seconds at 315,656 KiB RSS,
  preserving accepted hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`
  and `validation=passed`. This is 4.3% below the 68.93-second current-generation
  baseline and completes Task 2A; a refreshed profile will separate its owner
  reduction from the adjacent runtime-segment guard.
- The accepted-state refresh profile preserved the exact hash and validation
  while reducing core profiler time from 168.4 to 141.1 seconds. Runtime-segment
  lowering fell from 25.8 to 18.6 profiler-seconds and direct-stack replay from
  43.5 to 33.0. The boundary inventory reduced 399 repeated boundary calls to
  21 cold builds, but those first builds still cost 5.33 profiler-seconds; this
  is now a cold Frontend owner rather than repeated replay work.
- A direct-stack tagged-assignment early exit passed focused tests and preserved
  output, but low-overhead MOV component timings did not improve and total wall
  time regressed to 74.70 seconds. It was removed under Task 4's Definition of
  Failure rather than retained as uncredited complexity.
- An explicit isolated caller-evidence owner was tested because direct discovery
  already recovers that project. Restricting range census to it changed the C
  hash to `bedfada92e0c8e6462b863db2a5dadd67f641248bb34b367bc4ff15e354cebff`
  and regressed wall time to 73.37 seconds despite clean validation. The entire
  experiment was removed: isolated and active/original evidence are not yet
  semantically interchangeable, so ownership reconciliation requires a
  dedicated evidence-delta test before it can be an optimization.
- The existing tail-validation summary generation cannot safely serve as a
  boundary-fingerprint cache key: it covers typed evidence and declarations but
  not in-place C-AST mutation. No unsafe fingerprint reuse was added. Task 5
  must first receive an authoritative AST mutation generation from Structuring
  and Rewrite owners.
- The Structuring codegen wrapper replayed direct-stack and segmented-global
  lowering even when `apply_structuring_codegen_8616()` reported that it did not
  rebuild the AST. Replay is now conditional on that exact owner result, while
  call-stack metadata replay and dead-carrier pruning remain unconditional.
  Ruff, strict stage mypy, and 68 focused tests pass. The exact target preserved
  hash `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`
  and clean validation. Its 75.47-second timing overlapped two CPU-heavy trace
  workers and receives no performance credit; an uncontended rerun remains the
  Task 3 acceptance gate.
- The uncontended rerun completed in 57.93 seconds with the exact accepted hash
  and clean validation, down 12.1% from the 65.94-second pre-guard target. A
  second exact duplicate was then removed: post-regeneration code called direct
  stack and segmented-global lowering immediately before the full replay that
  begins with those same consumers. The adjacent target fell to 53.61 seconds
  and 271,152 KiB RSS, preserving exact output and validation; a source-order
  regression enforces one authoritative post-regeneration replay.
- Structuring pass specs now publish a typed Lowering replay impact. Proven
  unobserved-return neutralization is `RETURN_LIVENESS_ONLY`: it removes a pure
  return carrier and cannot introduce stack/global address patterns, while the
  later full replay still closes liveness after text regeneration. This removed
  one additional false direct-stack replay (about 1.0 second) and one false
  segmented-global replay (about 0.76 second) from the target owner path.
  Ruff, strict mypy, focused impact/order tests, exact hash, and clean validation
  pass. The 54.81-second wall sample did not beat the adjacent 53.61-second run,
  so only the measured component reduction receives Task 3 credit.
- The void-tail-call guard decision now has one typed Structuring owner;
  postprocess re-exports the same enum for compatibility. This removes a private
  Rewrite-stage type import from Structuring. Strict mypy passes across both
  giant stages, the typed contract modules, and register-local declarations;
  80 focused ownership/stage tests pass.
- The refreshed accepted-state core profile records 228.7 million calls and
  124.1 profiler-seconds, down from 267 million calls and 141.1 seconds before
  the replay guards. Structuring validation priming still owns 88.9 inclusive
  seconds; three full lowering replays own 43.7 seconds, segment/global lowering
  owns 31.5 seconds, and direct-stack lowering owns 26.1 seconds. Postprocess and
  register-local declaration publication are no longer leading runtime owners.
- A mypyc experiment compiled `c_ast_utils` with the existing typed native
  cohort and verified that the extension was selected under an isolated import
  path. It preserved exact hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`
  and clean validation, but regressed the exact target to 72.87 seconds and
  651,104 KiB RSS versus the adjacent 53.61-54.81-second Python range. This
  triggers Task 7's Definition of Failure; `c_ast_utils` is not promoted, and
  mypyc remains behind the remaining replay reductions.
- Named segmented-global pair recovery now resolves a dirty carrier once and
  refuses every node whose resolved root is not the required `Add`/`Or` binary
  shape before entering the evidence cross-product. All 179 segmented-global
  tests, Ruff, and strict mypy pass. The exact target preserved its accepted
  hash and clean validation at 55.47 seconds; stable named-global rounds fell
  from roughly 0.13-0.15 seconds to 0.10-0.11 seconds. This is accepted as a
  bounded Task 4 query reduction, not a new end-to-end best.
- The exact caller-range direct-call index experiment preserved the accepted C
  and validation, but the child profile reduced the former range-census owner
  only from 6.77 to 6.25 profiler-seconds. Of that 6.25 seconds, 6.20 belongs to
  the existing exact function-boundary inventory; caller decoding itself costs
  about 0.05 seconds. The extra index therefore triggers the task Definition of
  Failure and was removed. The boundary inventory is the real remaining owner.
- Direct-stack reload placement now builds one request-owned AST query index,
  derives exact tagged assignments and register-variable identities from it,
  and refuses only impossible register-use searches. The canonical register
  identity moved from the 17k-line lowering file into a 77-line typed
  Types/Lowering owner. Ruff, strict mypy, 21 focused index/replay tests, and 74
  direct-stack materialization tests pass. Against the adjacent trace-mode run,
  `reload_register_use` fell from roughly 0.79 seconds across the target's
  replays to 0.000 seconds, while exact hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`
  and clean validation were preserved. The 57.88-second wall sample did not
  beat the prior 50.51-second best, so it is not an end-to-end wall-time claim.
  The in-child profile nevertheless closes Task 4A's bounded DoD: recursive
  register-use placement fell from 20 calls and 3.08 profiler-seconds to zero,
  direct-stack MOV materialization fell from 24.34 to 16.27 profiler-seconds,
  and total profile calls fell by about 11.4 million without changing output or
  validation.
- Rollback-cache mutation and closed evidence publication now live in the typed
  `PostprocessRollbackSnapshotController8616`; the rewrite stage no longer owns
  nested cache-accounting helpers. The focused snapshot/rollback/validation
  suite passes 123 tests under `pytest -n 7`, Ruff and strict mypy pass for the
  controller, stage, and protected register-local declaration owner, and startup
  layer-import checks pass. The exact no-sidecar target preserved hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
  `validation=passed`, and whole-tail cleanliness at 55.15 seconds and 558,464
  KiB RSS. This closes a bounded Task 6 extraction and preserves Task 5's
  rollback contract; authoritative mutation generations are still required to
  complete either task.
- Accepted Rewrite mutations now close through
  `PostprocessPassTransactionState8616` and publish one immutable typed
  generation on every stage exit. Stable and restored state does not advance
  it; accepted reported or witnessed changes do. Ruff with `--fix`, strict
  mypy, and 132 focused tests pass, and the stage shrank by eight lines. A live
  pure-binary run restored three rejected cleanup passes, produced current hash
  `f86bd521ce979ae1ee2b5789853ac813978cf9d1928c7e73d3189f491c28db78`,
  and passed function plus whole-tail validation in 40.54 seconds at 273,964
  KiB RSS. This completes Task 5C as a correctness prerequisite; it claims no
  standalone speedup.
- The shared-tree Structuring validation tests had four feedback-blocking
  failures after condition refresh became a typed result. The tests now use
  `StructuringConditionRefreshResult8616` and preserve the exact current
  refresh/lowering/carrier-prune sequence. Ruff with `--fix` passes and the
  complete focused module passes 70 tests under `pytest -n 7`; production was
  not weakened to tolerate legacy `None` or boolean mocks.
- A 2026-08-28 isolated refresh established 57.00 seconds / 359,940 KiB for a
  low-overhead cold run and 49.82 seconds / 356,908 KiB for a timing-enabled
  cold run. Both produced exact hash
  `9dc16640f0e4bb61e7ba04aa7d46c903ad80e06842b0cd5ed3cd610bbf011ec0`,
  `validation=passed`, and clean whole-tail validation. The unique-key cold
  profile recorded 150.1 profiler-seconds and moved exact condition relifting,
  at 7.1 seconds across 36 requests, ahead of further broad query indexing.
- Compiling `ir/vex_import.py` with mypyc was rejected after controlled source
  and native runs measured 55.33 and 55.41 seconds respectively with equivalent
  roughly 695 MiB peak RSS. Exact output and validation matched, but there was
  no performance benefit; the normal 38-module cohort was restored.
- Task 4H added bounded exact-byte reuse for complete condition-relift
  artifacts. The source owner shrank from 346 to 312 lines, 159 condition-
  surface tests and the full `quality-dev` gate pass, including 1,863 curated
  pytest checks and all three selected MS C tiny pipelines. The exact SORTD
  hash and both validation gates remain unchanged; the cold profile reduced
  direct lifts 669 -> 437 and relift cumulative time 7.13 -> 5.11 seconds.
- Task 4I replaced repeated live-bit FLAGS reconstruction with one exact masked
  update per instruction. The exact SORTD hash and both validation gates remain
  unchanged; 244 flag/CFG/80386 tests and `quality-dev` pass. Sequential
  `set_flag` work fell 4,860 -> 86 calls, VEX statements fell by 1,476, and the
  cold profile fell from 159.1 to 144.4 seconds with about seven million fewer
  Python calls.
