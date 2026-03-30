# x86-16 `.COD` Corpus Completion Plan

This plan is narrower than the full dream-decompiler roadmap.

Its purpose is to drive Inertia to a practical corpus-grade state where the
whole `.COD` corpus is:

- scannable without crashes
- free of silent blind spots
- steadily more readable

The target is not "pretty output at any cost". The target is:

1. no process-level failures on the corpus
2. no unknown or invisible failure regions
3. readability work driven by explicit evidence and real corpus pain

The architecture rule remains:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

This plan does not replace that rule. It applies it to the specific operational
goal of finishing the `.COD` corpus.

## Success Criteria

The corpus is considered "complete enough" only when all three conditions are
true at the same time.

### 1. No Crashes

- `scan-safe` can traverse the whole `.COD` tree without the driver dying
- no file causes process abort, uncontrolled exception escape, or cleanup-time
  traceback noise
- timeouts and skips are allowed only when they are bounded and classified

### 2. No Blind Spots

- every function ends in one of:
  - `decompile`
  - `cfg_only`
  - `lift_only`
  - `block_lift`
  - classified failure
- every failure has a stage and a failure class
- every conservative skip has an explicit reason
- there are no "unknown" buckets left in milestone reports except during
  short-lived investigation

### 3. Readable Progress

- the golden readability set stays green
- milestone reports show the top ugly clusters, not just top crashes
- new readability wins come from general recovery layers, not only local rescue
  rewrites

## Three Separate Tracks

The work should run on three tracks in parallel. Do not collapse them into one
"quality" bucket.

### Track A. Corpus Stability

Goal: traverse all `.COD` inputs safely.

This track owns:

- driver robustness
- timeout discipline
- memory limits
- cleanup safety
- bounded fallback policy

Primary entry points:

- [`corpus_scan.py`](../angr_platforms/X86_16/corpus_scan.py)
- [`scan_cod_dir.py`](../scripts/scan_cod_dir.py)

### Track B. Blind-Spot Elimination

Goal: remove invisible analysis gaps.

This track owns:

- failure taxonomy
- stage boundaries
- hotspot ranking
- fallback visibility
- baseline and milestone reporting

Primary entry points:

- [`corpus_scan.py`](../angr_platforms/X86_16/corpus_scan.py)
- [`milestone_report.py`](../angr_platforms/X86_16/milestone_report.py)
- [`validation_manifest.py`](../angr_platforms/X86_16/validation_manifest.py)

### Track C. Readability Uplift

Goal: make more of the corpus readable without weakening correctness.

This track owns:

- alias-first cleanup
- widening-driven byte-pair elimination
- segmented association quality
- trait/type/object recovery
- boolean/control-flow cleanup

Primary references:

- [`dream_decompiler_execution_plan.md`](./dream_decompiler_execution_plan.md)
- [`x86_16_decompiler_readability.md`](./x86_16_decompiler_readability.md)

## Phase 1. Finish Corpus Visibility

This phase is about knowing exactly what happens for every function.

### [x] 1.1. Eliminate unclassified outcomes

- `Priority`: `P0`
- `Why`:
  - unreadable output is acceptable temporarily
  - invisible failures are not acceptable
- `Required outcome`:
  - every function result has:
    - stage reached
    - fallback kind or failure class
    - short reason
- `Done when`:
  - the whole corpus can be summarized without hand-reading logs

- `Deterministic goal`:
  - every corpus result has a stage, fallback kind or failure class, and short reason
  - milestone reports never need an "unknown" bucket for routine triage

### [x] 1.2. Remove "unknown" buckets from reports

- `Priority`: `P0`
- `Why`:
  - `unknown_failure` is a planning blind spot
- `Required outcome`:
  - each recurring `unknown` path is converted into a real class such as:
    - `load_failure`
    - `lift_failure`
    - `cfg_failure`
    - `decompiler_crash`
    - `timeout`
    - `postprocess_failure`
    - `renderer_failure`
    - `recursion_or_explosion`
    - `unsupported_semantic`
- `Done when`:
  - milestone reports no longer need manual interpretation for top failures

- `Deterministic goal`:
  - recurring unknown paths are converted into stable classes such as `load_failure`, `lift_failure`, `cfg_failure`, `decompiler_crash`, `timeout`, `postprocess_failure`, `renderer_failure`, `recursion_or_explosion`, or `unsupported_semantic`
  - reports stay readable without manual log spelunking

### [x] 1.3. Track conservative skips as first-class outcomes

- `Priority`: `P0`
- `Why`:
  - `cfg_only` and `lift_only` are not failures, but they are still blind
    spots if not counted
- `Required outcome`:
  - reports include:
    - full decompile count
    - `cfg_only` count
    - `lift_only` count
    - `block_lift` count
  - top files and top functions are rankable by fallback kind
- `Done when`:
  - we can tell whether the corpus is "green by real decompile" or "green by
    bounded fallback"

- `Deterministic goal`:
  - reports always separate `decompile`, `cfg_only`, `lift_only`, and `block_lift`
  - the corpus can be ranked by fallback kind without manual parsing

## Phase 2. Make Whole-Corpus Scan Boring

This phase is complete only when `.COD` traversal is routine, not exciting.

### [x] 2.1. Keep `scan-safe` strictly conservative

- `Priority`: `P0`
- `Why`:
  - scan mode is for stability and visibility, not beauty
- `Required outcome`:
  - no risky beautification passes by default
  - fallback gates stay cheap, explicit, and documented
  - cleanup-time noise remains suppressed
- `Done when`:
  - new pretty-output work no longer threatens corpus traversal

- `Deterministic goal`:
  - scan-safe stays robust-first, with no risky beautification by default and no cleanup-time noise escape

### [x] 2.2. Bound the remaining hotspot classes

- `Priority`: `P0`
- `Why`:
  - long-tail outliers should become bounded outcomes, not blockers
- `Required outcome`:
  - every recurring hotspot category gets one of:
    - a cheap guardrail
    - a safe skip
    - a real fix
- `Examples`:
  - oversized functions
  - short loop-heavy helpers
  - pathological CFG shapes
  - cleanup/destructor noise
- `Done when`:
  - the whole corpus can run to completion on normal milestone sweeps

- `Deterministic goal`:
  - every recurring hotspot class is either guarded, safely skipped, or fixed
  - large corpus sweeps finish without a new uncapped hotspot class

### [x] 2.3. Preserve file and function progress logging

- `Priority`: `P1`
- `Why`:
  - long corpus runs should never feel stuck or opaque
- `Required outcome`:
  - file-start, progress, and file-end logging remain available
  - JSON summaries stay machine-readable
- `Done when`:
  - any stalled or slow corpus run can be localized immediately

- `Deterministic goal`:
  - file-start, progress, and file-end logging remain available
  - JSON summaries stay machine-readable during long runs

## Phase 3. Turn Blind Spots Into Work Queues

This phase turns the corpus from a foggy scan into an ordered engineering
backlog.

### [x] 3.1. Rank by stage, failure class, file, and function

- `Priority`: `P0`
- `Why`:
  - "what broke most often" is not enough
- `Required outcome`:
  - each milestone report ranks:
    - top failure classes
    - top failure stages
    - top fallback-heavy files
    - top fallback-heavy functions
- `Done when`:
  - planning can start from hotspot reports instead of ad hoc exploration

- `Deterministic goal`:
  - each milestone report ranks failures and fallbacks by stage, failure class, file, and function

### [x] 3.2. Add a blind-spot budget

- `Priority`: `P1`
- `Why`:
  - green scans can hide too many fallback-only functions
- `Required outcome`:
  - reports track:
    - percent fully decompiled
    - percent `cfg_only`
    - percent `lift_only`
    - percent true failures
  - milestone gates can fail if fallback-only coverage grows
- `Done when`:
  - we can see whether we are reducing blind spots or merely hiding them

- `Deterministic goal`:
  - reports always show the current split between full decompile, cfg_only, lift_only, and true failure
  - fallback-only coverage can fail a milestone gate if it grows

### [x] 3.3. Separate visibility debt from readability debt

- `Priority`: `P1`
- `Why`:
  - a function that is `cfg_only` has a different problem than a function that
    decompiles into bad C
- `Required outcome`:
  - reports distinguish:
    - traversal debt
    - recovery debt
    - readability debt
- `Done when`:
  - teams can work in parallel without mixing priorities

- `Deterministic goal`:
  - visibility debt, recovery debt, and readability debt always remain separately measured

## Phase 4. Raise the Readability Floor Across the Whole Corpus

This phase is about moving more of the corpus from "alive" to "useful".

### [x] 4.1. Fix the top ugly clusters, not isolated outputs

- `Priority`: `P1`
- `Why`:
  - whole-corpus readability only improves if repeated ugly forms are mined and
    ranked
- `Required outcome`:
  - milestone reports include top ugly clusters such as:
    - byte-pair arithmetic
    - split segmented word accesses
    - fake locals and stack noise
    - weak helper signatures
    - boolean noise
    - unresolved member or array opportunities
- `Done when`:
  - each readability sprint starts from ranked clusters instead of a single
    function

- `Deterministic goal`:
  - rank the repeated ugly forms that the scanner now surfaces as first-class
    readability clusters:
    - `byte_pair_arithmetic`
    - `split_segmented_word_accesses`
    - `fake_locals_and_stack_noise`
    - `weak_helper_signatures`
    - `boolean_noise`
    - `unresolved_member_or_array_opportunities`
  - spend each readability sprint on the top repeated cluster, not on one
    showcase function
  - verify the sprint focus from the `readability_goal_summary` surface in the
    milestone report

### 4.2. Spend the first major readability budget on alias and widening

- `Priority`: `P0`
- `Why`:
  - the biggest readable-C wins still come from earlier layers
- `Required outcome`:
  - more byte-pair and projection cleanup moves onto alias/widening APIs
  - late rewrite stops solving storage questions
  - downstream passes consume alias facts instead of recomputing them
- `Done when`:
  - several old local coalescers become thin wrappers over shared proof-based
    logic

- `Deterministic goal`:
  - make byte-pair and projection cleanup consume alias and widening proofs
  - stop late rewrite from re-solving storage identity
  - keep downstream passes consuming alias facts instead of recomputing them
  - use the milestone report surfaces:
    - `alias_api`
    - `widening_pipeline`
    - `projection_cleanup_rules`
    - `source_backed_rewrite_debt`

### 4.3. Only then spend on traits, types, and objects

- `Priority`: `P1`
- `Why`:
  - object-like readability gains are valuable but must stay evidence-driven
- `Required outcome`:
  - improved field, array, global, and stack-object rendering comes from:
    - stable alias facts
    - widening
    - trait profiles
    - downstream type/object policy
- `Done when`:
  - readable object output increases without a spike in hallucinated structs or
    arrays

- `Deterministic goal`:
  - let stable alias and widening facts feed traits, types, and object policy
  - improve field, array, global, and stack-object rendering without widening
    the hallucination surface
  - verify the effect through:
    - `recovery_layers`
    - `validation_families`
    - `readability_set`
    - `readability_tiers`

## Phase 5. Remove the Last Real Blind Spots

Blind spots are not only crashes. They also include systematic regions the
project does not yet explain well.

### [x] 5.1. Fallback-heavy functions become explicit backlog items

- `Priority`: `P1`
- `Why`:
  - `lift_only` and `cfg_only` functions are the remaining map of coverage
    gaps
- `Required outcome`:
  - maintain a bounded queue of:
    - most frequent `cfg_only` functions
    - most frequent `lift_only` functions
    - most important files with low full-decompile ratio
- `Done when`:
  - fallback-heavy regions are being reduced intentionally, not accidentally

- `Deterministic goal`:
  - the report always exposes the top cfg_only and lift_only files and functions as an explicit backlog

### [x] 5.2. Define "readable enough" tiers

- `Priority`: `P1`
- `Why`:
  - "readable" is too vague at corpus scale
- `Required outcome`:
  - classify full-decompile outputs into tiers:
    - `R0`: alive but mostly unusable
    - `R1`: ugly but understandable
    - `R2`: useful source-like C
    - `R3`: strong corpus exemplar
- `Done when`:
  - the project can measure whole-corpus readability movement, not only local
    wins

- `Deterministic goal`:
  - full-decompile outputs are always classed into R0, R1, R2, or R3

### [x] 5.3. Make "no blind spots" a merge gate

- `Priority`: `P0`
- `Why`:
  - otherwise visibility debt creeps back in
- `Required outcome`:
  - nontrivial changes must not:
    - increase unclassified results
    - increase unknown fallbacks
    - reduce full-decompile coverage without explanation
- `Done when`:
  - the corpus cannot quietly become less observable

- `Deterministic goal`:
  - nontrivial changes cannot increase unclassified results or reduce visibility without an explicit explanation

## Phase 6. Source-C Decompilation Correctness

This phase keeps decompilation correctness explicit while readability work
continues.

### [x] 6.1. Keep semantic compare and runtime samples green

- `Priority`: `P0`
- `Why`:
  - readable output is only useful if the decompiler still matches the source C
- `Required outcome`:
  - compare-style probes stay aligned with the original COD C logic
  - runtime samples remain green
  - correctness regressions are triaged before readability work is counted as a win
- `Deterministic goal`:
  - keep `tests/test_x86_16_cod_samples.py`, `tests/test_x86_16_compare_semantics.py`, and
    `tests/test_x86_16_runtime_samples.py` green
  - keep the correctness report tied to source-C and semantic slices
- `Done when`:
  - semantic and runtime probes stay green across ordinary corpus changes

### [x] 6.2. Keep sample matrix and 80286 verifier aligned

- `Priority`: `P0`
- `Why`:
  - corpus decompilation has to agree with the original COD source C and
    hardware-backed verification
- `Required outcome`:
  - the sample matrix stays representative of the COD source C logic
  - the 80286 verifier stays green
  - correctness work can point at concrete opcode families instead of vague confidence
- `Deterministic goal`:
  - keep `tests/test_x86_16_cod_samples.py`, `tests/test_x86_16_sample_matrix.py`, and
    `tests/test_x86_16_80286_verifier.py` green
  - keep the sample-matrix / verifier pairing visible in the milestone report
- `Done when`:
  - representative samples and hardware-backed checks remain in agreement

### [x] 6.3. Keep calling-convention and return compatibility faithful

- `Priority`: `P0`
- `Why`:
  - decompilation correctness collapses if prototypes and returns drift away
    from the original COD source C calling surfaces
- `Required outcome`:
  - calling-convention compat remains explicit
  - return compat remains explicit
  - helper lowering does not invent impossible signatures
- `Deterministic goal`:
  - keep `calling_convention_compat` and `decompiler_return_compat` as the
    source of truth for the decompiler boundary
  - keep `tests/test_x86_16_cod_samples.py`, `tests/test_x86_16_helper_modeling.py`, and their validation tests green
- `Done when`:
  - the decompiler boundary continues to preserve correct call/return shape

### [x] 6.4. Keep interrupt lowering correctness-driven and bounded

- `Priority`: `P1`
- `Why`:
  - interrupt lowering must stay helper-backed and visible so it does not
    become a hidden semantics sink
- `Required outcome`:
  - interrupt core semantics remain separate from DOS/BIOS/MS-C helper
    lowering
  - wrapper paths remain classified
  - unresolved wrappers stay visible as bounded debt
- `Deterministic goal`:
  - keep the interrupt boundary surfaces in `milestone_report`
  - keep `interrupt_api_surface`, `interrupt_core_surface`, and
    `interrupt_lowering_boundary` aligned with the source-C wrapper logic
- `Done when`:
  - interrupt lowering can be audited without opening the whole decompiler
    pipeline

## Current Completion Snapshot

- Completed steps: `17`
- Total tracked steps: `19`
- Strict completion: `89.47%`
- Weighted completion: `89.47%`

## Recommended Milestone Loop

Use this loop for all major corpus work.

1. Run bounded `scan-safe` over the target `.COD` tree.
2. Produce a milestone report with:
   - failure classes
   - fallback classes
   - top files
   - top functions
   - top ugly clusters
3. Choose one of:
   - stability hotspot
   - blind-spot hotspot
   - readability hotspot
4. Fix it at the earliest correct architectural layer.
5. Re-run:
   - unit tests
   - focused corpus tests
   - scan-safe sanity
6. Record whether the change:
   - reduced failures
   - reduced fallback-only coverage
   - improved readability clusters
   - reduced special-case debt

## What Not To Do

- Do not call the corpus "done" because `scan-safe` is green if too much of it
  is still `cfg_only` or `lift_only`.
- Do not call the corpus "readable" because a few showcase functions look good.
- Do not hide visibility debt under new postprocess rewrites.
- Do not trade scan-safe robustness for one attractive output.
- Do not let one-off rescues become the main method for whole-corpus progress.

## Short Practical Priority Order

If we compress everything into the next practical sequence, it is:

1. make every corpus outcome visible and classifiable
2. finish whole-corpus `scan-safe` stability
3. measure fallback-only coverage explicitly
4. mine top ugly readability clusters
5. spend quality budget first on alias/widening-driven cleanup
6. spend the next budget on trait/type/object recovery
7. keep turning fallback-heavy regions into readable full decompiles

## The Simple Human Version

The `.COD` corpus is only really "done" when:

- nothing crashes
- nothing important is invisible
- the ugly parts are ranked and shrinking
- readable wins come from architecture, not miracles

That is the operational meaning of:

"whole COD readable and not crashes and no blind spots"
