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

### [x] 4.2. Spend the first major readability budget on alias and widening

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

### [x] 4.3. Only then spend on traits, types, and objects

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

## Phase 7. COD Recovery Architecture Backlog

This phase is the systematic `.COD` decompilation roadmap. It is not about one
sample and it is not permission for source-specific rescue work. The repeating
MSC-corpus failures are:

- helper calls collapsing into raw stack temps and magic addresses
- return values being dropped after otherwise-recognized calls
- globals like `rin`, `rout`, `sreg`, and `exeLoadParams` not being recovered
  as typed objects
- far pointers and segmented memory being flattened or half-flattened
- medium-model far-call recovery still timing out or mis-targeting some
  functions
- larger `.COD` functions still hitting timeout, sparse-region, or
  under-recovery failures

The architectural rule remains:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

The practical meaning for `.COD` work is:

- correctness and recovery quality before prettiness
- calling-convention recovery before wrapper cleanup
- typed object recovery before field-name polish
- segmented/far-pointer recovery before pointer-like lowering
- expression simplification before final C text cleanup

### 7.1. Lock exact COD success criteria

- `Priority`: `P0`
- `Why`:
  - `.COD` work needs explicit “correct enough” and “recompilable enough”
    definitions so progress is measurable
- `Deterministic goal`:
  - every `.COD` milestone uses these three tiers:
    - `Tier A correctness`:
      - parameters match `.COD` stack layout
      - returns come from the real architectural return register or memory
        object
      - calls use the right callee and argument order
      - control flow preserves branches, loops, and returns
      - loads/stores preserve byte vs word width
      - `DS`, `SS`, `ES`, and far pointers are not silently merged
    - `Tier B recompilation`:
      - helper-based C is possible for DOS/MSC wrappers
      - typed globals/structs such as `union REGS`, `struct SREGS`, and load
        parameter objects are visible
      - final C does not tolerate artifacts like:
        - `s_2 = &v3;`
        - `return v12 << 16 | 3823();`
        - `rin = 72;`
        - split-byte stores for known word stores
    - `Tier C first-milestone regression goals`:
      - `_bios_clearkeyflags` becomes a word store to low memory
      - `_dos_alloc`, `_dos_free`, `_dos_resize`, `_dos_getfree`, and
        `_dos_getReturnCode` emit real `intdos`/`intdosx` calls with typed
        `rin`/`rout`/`sreg` and emit their returns
      - wrappers like `_dos_loadOverlay`, `_dos_runProgram`, and
        `_openFileWrapper` emit direct helper calls with correct args and
        return propagation
      - timeout rate drops on the bounded sample-matrix / COD scanner
- `Done when`:
  - milestone reports can state correctness and recompilation progress without
    ad hoc prose

### 7.2. Keep a fixed COD regression matrix

- `Priority`: `P0`
- `Why`:
  - the first COD milestone needs a stable target set before any pipeline work
- `Deterministic goal`:
  - the fixed target set is kept explicit and test-backed:
    - `BIOSFUNC.COD`
    - `DOSFUNC.COD`
    - `OVERLAY.COD`
    - one wrapper-heavy game file such as `EGAME2.COD`
    - one timeout-heavy larger game file such as `EGAME11.COD`
  - regression layers are always split into:
    - recovery tests
    - semantic anchor tests
    - anti-anchor tests
  - the focused regression harness in
    `tests/test_x86_16_cod_regressions.py` remains the first gate
- `Done when`:
  - the fixed COD targets can be rechecked with one focused test command

### 7.3. Treat `.COD` metadata as recovery input

- `Priority`: `P0`
- `Why`:
  - `.COD` metadata is the biggest honest advantage over arbitrary binaries
- `Deterministic goal`:
  - COD-mode recovery records seed:
    - function starts
    - stack arg names and sizes
    - known globals
    - wrapper signatures
    - local helper symbols
    - model hints when sample-matrix context provides them
  - CFG seeding uses metadata-driven function starts instead of relying on
    rediscovery from `0x1000`
  - direct far-callee seeding is extended from startup-only cases to
    metadata-driven COD callees
- `Done when`:
  - wrappers and medium-model far targets recover from metadata instead of
    heuristics alone

### 7.4. Recover external MSC/DOS call surfaces before cleanup

- `Priority`: `P0`
- `Why`:
  - dropped returns and numeric helper calls are currently the biggest
    correctness failure in `DOSFUNC.COD`
- `Current implementation note`:
  - known helper signatures are now surfaced as typed declarations before
    decompilation
  - anonymous COD call expressions now recover to the source-backed helper
    call text when the listing provides it
  - wide-return wrapper artifacts are simplified for known helper calls
  - the remaining work in this phase is return propagation on harder wrappers
    and the non-semantic staging cleanup that still appears in multi-call
    functions
- `Deterministic goal`:
  - `analysis_helpers.py` owns an MSC/DOS extern signature catalog for at
    least:
    - `_intdos`
    - `_intdosx`
    - `_fprintf`
    - `_fflush`
    - `_abort`
    - `_ERROR`
    - `_DEBUG`
    - `_INFO`
    - `_sprintf`
    - `_strlen`
    - `_strcat`
    - `_sizeString`
  - signatures attach before decompilation, alongside the existing interrupt
    wrapper / DOS pseudo-callee attachment
  - direct callsite argument attachment preserves:
    - outgoing stack args
    - varargs status
    - real return values
  - wrapper-return propagation preserves `AX` returns for one-call wrappers
- `Done when`:
  - `_dos_loadOverlay`, `_dos_getfree`, and `_dos_getReturnCode` stop dropping
    return semantics and stop degrading into raw numeric helper calls

### [x] 7.5. Recover known COD objects through alias and types

- `Priority`: `P0`
- `Why`:
  - typed object recovery is the main blocker behind `rin = 72;`-style junk
- `Deterministic goal`:
  - `cod_known_objects.py` defines exact layouts for:
    - `union REGS`
    - `struct SREGS`
    - `exeLoadParams`
    - `ovlLoadParams`
  - `alias_model.py` adds:
    - `dgroup_global` storage identity for metadata-backed globals
    - far-pointer local object domains for `(segment, offset)` stack objects
    - an explicit outgoing-call staging-slot classification
  - `widening_model.py` supports:
    - DGROUP field widening for known object fields
    - far word load/store widening when the alias proof is valid
    - forbidden joins across segments or across clobbers
  - `cod_type_recovery.py` lowers stable object views to field syntax only
    after alias and widening facts are stable
- `Current implementation note`:
  - `cod_known_objects.py` now defines the shared COD object catalog
  - COD-mode annotations attach those object types before decompilation
  - generic source-backed rewrites now use the known-object catalog rather
    than per-function rescue paths
- `Done when`:
  - outputs move from:
    - `rin = 72;`
    - `rin = 65535;`
    - `sreg = segment;`
  - toward:
    - `rin.h.ah = 0x48;`
    - `rin.x.bx = 0xffff;`
    - `sreg.es = segment;`

### [x] 7.6. Recover segmented and far-pointer semantics conservatively

- `Priority`: `P0`
- `Why`:
  - BIOS and overlay cases still flatten segmented state too aggressively
- `Deterministic goal`:
  - segmented memory stays split at least into:
    - `DS:DGROUP`
    - `SS:DGROUP`
    - `ES:external/far object`
    - absolute low-memory / BDA objects when the segment is constant zero
  - a stable far-pointer object representation is used when stack or globals
    carry `(segment, offset)` pairs that are later dereferenced
  - known absolute-memory objects such as `0x0000:0x0417` can lower to named
    helpers or named low-memory objects
  - word-width far stores remain word stores
- `Done when`:
  - `_bios_clearkeyflags` stops decompiling as two anonymous byte stores
- `Current implementation note`:
  - adjacent byte stores into a shared segmented address now coalesce into a
    single far word store when the address and high-byte pattern prove it is
    the same object

### [x] 7.7. Remove non-semantic wrapper stack noise

- `Priority`: `P1`
- `Why`:
  - `s_*` call-staging locals still block recompilable wrappers
- `Deterministic goal`:
  - stack-slot identity distinguishes:
    - real parameters
    - real locals
    - outgoing-call staging slots
  - wrapper simplification only runs after:
    - callee signatures are correct
    - arg identity is correct
    - return propagation is correct
  - simple forwarding wrappers stop emitting:
    - `s_2 = &v3;`
    - `s_4 = mode;`
    - `s_6 = path;`
- `Current implementation note`:
  - the one-call forwarding wrapper shape is now cleaned up generically for
    `_openFileWrapper` and `_dos_loadOverlay`
  - the remaining work in this area is to apply the same conservative
    staging-slot cleanup to any additional wrappers that still expose
    stack-noise after call/return recovery
- `Done when`:
  - `_openFileWrapper`, `_dos_loadOverlay`, and similar wrappers decompile as
    direct forwarding calls

### [x] 7.8. Improve condition recovery and timeout triage together

- `Priority`: `P1`
- `Why`:
  - larger `.COD` functions need both cleaner conditions and better timeout
    visibility
- `Deterministic goal`:
  - early condition simplification rewrites typed-object comparisons such as
    `rout.x.cflag != 0` before final C text generation
  - return-value path simplification recovers final `AX` returns after one
    condition
  - bounded scanner metrics always record:
    - function name
    - block count
    - byte count
    - call count
    - known-object count
    - whether metadata was used
    - timeout stage
    - anchor-quality score
  - the first timeout milestone is:
    - reduce timeout count by 30% at `--timeout-sec 10`
    - no regressions on simple wrappers
    - no increase in empty decompilations
- `Current implementation note`:
  - timeout-stage counts are now exposed in corpus scan summaries and
    milestone reports, so timeout triage is no longer implicit
  - the remaining work in this step is handled by the generic simplification
    passes that already normalize typed-object comparisons and final returns
- `Done when`:
  - timeout-heavy `.COD` outliers are ranked by cause and the simple wrapper
    cases stay green

### Current Phase-7 first implementation backlog

1. `Commit 1`: regression harness and anti-anchors
2. `Commit 2`: metadata-driven function seeding and model hints
3. `Commit 3`: MSC extern signature catalog and callsite typing
4. `Commit 4`: DGROUP global alias domain and known object catalog
5. `Commit 5`: widening for known object fields and far word stores
6. `Commit 6`: condition and return simplification on typed objects
7. `Commit 7`: wrapper simplifier
8. `Commit 8`: timeout classification and scan-safe reporting

### Definition of done for Phase 7

Phase 7 is only done on the fixed target set when:

- `_bios_clearkeyflags` is a far word store, not split byte stores
- `_dos_getfree` emits typed `rin/rout` field accesses, the `intdos` call, the
  `cflag` check, and `return rout.x.bx;`
- `_dos_getReturnCode` emits a return value
- `_dos_loadOverlay` emits `return loadprog(file, segment, 3, 0);`
- `_openFileWrapper` emits a direct call without fake staging locals
- the bounded COD scan reports fewer bogus numeric callees and fewer timeouts
  than before

## Current Completion Snapshot

- Completed steps: `23`
- Total tracked steps: `27`
- Strict completion: `85.19%`
- Weighted completion: `85.19%`

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
