# Dream Decompiler Execution Plan

This document turns Inertia's high-level "dream decompiler" vision into a
practical execution roadmap.

It is intentionally narrower and more actionable than the architecture summary
in `AGENTS.md`.

The target architecture stays:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

The purpose of this plan is to answer four practical questions for each major
step:

- what should be built
- how important it is
- how hard it is
- how it improves real decompilation quality

## Priority Scale

- `P0`: foundation work that unlocks multiple later steps
- `P1`: high-impact quality work for the current target corpus
- `P2`: important follow-up work after the recovery foundation is stable
- `P3`: polish, breadth, or extension work

## Complexity Scale

- `Low`: small and bounded change, low architecture risk
- `Medium`: multi-file change or pipeline boundary change
- `High`: changes core recovery logic or cross-pass interaction
- `Very High`: architecture-shaping work with serious regression risk

## Phase A. Stable Platform

This phase keeps the decompiler usable on real 16-bit x86 programs while the
later recovery architecture evolves.

### A1. Close Real Corpus Blocking Opcode Gaps

- `Priority`: `P1`
- `Complexity`: `Medium`
- `How it helps`:
  - prevents decompilation from failing before recovery even starts
  - reduces time wasted debugging "quality" issues that are really lift/runtime
    issues
- `Low-level steps`:
  - keep mining `.COD` and sample-matrix binaries for blocking mnemonics
  - add compare-style semantics tests for instructions that still block real
    code
  - add focused lift/decompile regressions for each newly unblocked sample
  - use MartyPC as a reference when an instruction family still needs clearer
    semantic factoring or flag/stack/control-transfer organization
- `Exit signal`:
  - new real-sample failures are more often readability/recovery failures than
    missing opcode failures

### A2. Keep Loader, Runtime, and Interrupt Baseline Stable

- `Priority`: `P1`
- `Complexity`: `Medium`
- `How it helps`:
  - keeps `.EXE` / `.COM` analysis viable
  - stops execution or CFG issues from polluting decompilation work
- `Low-level steps`:
  - keep DOS MZ loader regressions green
  - preserve DOS/BIOS interrupt behavior needed by current sample corpus
  - extend bounded far-call and whole-binary recovery helpers only when a real
    sample needs it
- `Exit signal`:
  - loader/runtime changes are mostly maintenance, not the main blocker for new
    corpus cases

### A3. MartyPC-Style Instruction-Core Factoring

- `Priority`: `P2`
- `Complexity`: `Medium`
- `How it helps`:
  - keeps instruction semantics easier to reason about and test
  - reduces the chance that future 386 real-mode additions will be bolted onto
    16-bit handlers as special cases
  - improves scan stability and semantic readability for hot paths such as
    string ops, stack ops, ALU flags, and control transfer
- `Low-level steps`:
  - keep instruction families split into small semantic helpers instead of one
    large handler
  - keep ALU flag updates centralized and width-parametric
  - keep string, stack, and near/far control-transfer helpers separate
  - make instruction semantics width-extensible so 32-bit operand-size support
    can be added later without rewriting the 16-bit baseline
  - treat future 386 real-mode instructions with 16-bit addressing as a mixed-
    width extension of the same instruction-core, not a separate architecture
- `Dependencies`:
  - `A1`
  - `A2`
- `Exit signal`:
  - new instruction support can be added with small, width-aware helpers rather
    than ad hoc branching in existing 16-bit handlers

## Reference Implementation Notes: MartyPC

MartyPC is not a decompiler, but it is a useful reference implementation for the instruction-core side of the x86-16 stack. The most useful patterns to borrow are:

- split instruction families into small semantic modules instead of one monolithic executor
- keep string operations explicit, with side effects and direction-flag updates localized
- centralize ALU flag updates instead of scattering flag logic across instruction handlers
- keep near/far jump, call, return, and interrupt paths separate and explicit
- make stack push/pop semantics simple and reusable
- keep operand width and address width as separate concepts so future 386 real-mode instructions with 16-bit addressing do not contaminate the current 16-bit baseline
- make mixed-width instruction semantics width-extensible from the start, especially for ALU, shifts/rotates, and stack/control-transfer helpers

For Inertia, these ideas are most useful as low-level guidance for x86-16 maintenance work, not as a replacement for the alias/widening/type pipeline. The practical application order is:

1. keep instruction handlers in small semantic groups
2. prefer shared helpers for repeated flag, stack, and control-transfer behavior
3. use MartyPC-style clarity when cleaning up handlers that still affect scan stability or real-sample correctness
4. keep operand-size and address-size concerns explicit so the future 386 real-mode path can remain a bounded extension of the same helpers
5. keep these instruction-level patterns downstream of the architecture boundary already fixed in `IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

## Remaining Roadmap

The completed baseline and recovery milestones are intentionally omitted from
this roadmap. What remains is the work that still needs to be done or
continuously improved.

### [x] A0.1. Milestone Baseline Report Generator

- `Priority`: `P1`
- `Complexity`: `Medium`
- `How it helps`:
  - turns scan-safe output into a reusable milestone artifact
  - makes progress comparable across architecture changes
- `Low-level steps`:
  - build one report entry point that combines:
    - scan-safe summary
    - validation-manifest results
    - corpus success/failure rates
    - top failure classes and hotspots
  - add room for readability clusters and blocked mnemonic summaries instead of
    keeping those only as ad hoc notes
  - make the report reproducible from one command over the active corpus slice
- `Dependencies`:
  - `A0`
- `Exit signal`:
  - each milestone has one reproducible baseline report instead of scattered
    scan logs and test notes

### [x] A0.2. Golden Readability Set

- `Priority`: `P1`
- `Complexity`: `Medium`
- `How it helps`:
  - protects the best human-facing wins while deeper refactors land
  - keeps readability tracked as explicitly as scan stability
- `Low-level steps`:
  - promote the current readable samples and anchor-based tests into an
    explicit golden readability set
  - keep a bounded list of representative `.COD`, `.COM`, and `.EXE` functions
  - define 3-5 stable anchors per function:
    - key constants
    - readable helper calls
    - cleaner loops/conditions
    - field/array/member shapes where applicable
  - connect the set to `x86_16_decompiler_readability.md` so the notes and
    tests stay aligned
- `Dependencies`:
  - `A0`
- `Exit signal`:
  - the project has a named readability set, not just scattered anchor tests

### [ ] B3. Segmented Memory Association

- `Priority`: `P1`
- `Complexity`: `Very High`
- `How it helps`:
  - enables safe pointer/object recovery in real-mode code
  - reduces segmented-address arithmetic noise in output C
- `Low-level steps`:
  - keep `ss`, `ds`, and `es` distinct as storage spaces
  - classify base association as `single`, `const`, or `over-associated`
  - make object-lowering conditional on stable association
  - extend association checks from local shape matching toward function-level
    reasoning
  - treat repeated uses of one stack slot differently from genuinely distinct
    stack slots so `ss`-based object lowering stays conservative
- `Dependencies`:
  - `B1`
  - ideally `B2`
- `Exit signal`:
  - pointer-like lowering in segmented code is driven by explicit association
    state instead of local guesswork

### [x] B4. Formal Alias API For Downstream Recovery

- `Priority`: `P1`
- `Complexity`: `Medium`
- `How it helps`:
  - gives widening, traits, and object policy one shared vocabulary for storage
    truth
  - prevents new passes from recreating alias logic locally
- `Low-level steps`:
  - formalize downstream-facing helpers around:
    - same-domain checks
    - compatible-view checks
    - needs-synthesis checks
    - can-join checks
  - keep register, stack-slot, and segmented-memory cases available through the
    same API shape
  - migrate any remaining direct shape-guessing callers onto alias helpers
- `Dependencies`:
  - `B1`
  - `B2`
  - `B3`
- `Exit signal`:
  - downstream passes depend on alias API calls rather than their own storage
    heuristics

### [x] B5. Widen Candidate Extraction Layer

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - turns widening from local join helpers into a real pipeline stage
  - makes widening debuggable on real functions
- `Low-level steps`:
  - collect explicit widening candidates for:
    - register pairs
    - stack byte pairs
    - segmented adjacent loads
    - whole/slice/whole projection shapes
  - add a debug-visible candidate dump for bounded real functions
  - keep the extraction step independent from the final rewrite decision
- `Dependencies`:
  - `B4`
- `Exit signal`:
  - widening starts from an explicit candidate list rather than scattered local
    join opportunities

### [x] B6. Compatibility Proof Stage

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - makes widening decisions explainable and testable
  - separates “candidate exists” from “candidate is safe”
- `Low-level steps`:
  - formalize proof checks for:
    - same domain
    - adjacent compatible views
    - same version / no clobber
    - safe segment family
    - safe stack-slot identity
  - surface proof failures in focused tests and debug reporting
  - keep proof output reusable by later object/type layers
- `Dependencies`:
  - `B5`
- `Exit signal`:
  - widening is accepted or rejected by an explicit proof layer, not by one
    combined helper

### [ ] B7. Store-Side Widening

- `Priority`: `P2`
- `Complexity`: `High`
- `How it helps`:
  - cleans up split byte stores into clearer word-sized assignments
  - reduces noisy store-side arithmetic in stack and segmented code
- `Low-level steps`:
  - start with stable stack-slot store pairs
  - extend to stable segmented-memory store pairs only after association is
    strong enough
  - keep widths preserved and reject mixed/overlapping unsafe cases
  - verify on corpus cases where adjacent byte stores currently survive into C
- `Dependencies`:
  - `B6`
  - `B3`
- `Exit signal`:
  - adjacent byte stores are recovered as wider assignments only when safety is
    proven

### [ ] B8. Segment-Aware Object Roots

- `Priority`: `P2`
- `Complexity`: `Very High`
- `How it helps`:
  - gives later field/array recovery a stable notion of real-mode object roots
  - reduces the gap between segmented association and actual object lowering
- `Low-level steps`:
  - define stable roots for:
    - `ss:frameoff`
    - `ds:const/global`
    - helper-produced stable bases
  - keep segment identity attached to the root instead of collapsing
    everything into one pointer model
  - let object candidates form only from stable roots that survive association
    policy gates
- `Dependencies`:
  - `B3`
  - `C2`
- `Exit signal`:
  - field/array recovery operates on segment-aware roots instead of raw address
    arithmetic alone

### [ ] C3. Member And Array Recovery

- `Priority`: `P2`
- `Complexity`: `High`
- `How it helps`:
  - turns repeated offsets and stride loops into fields and arrays
  - makes output significantly more source-like
- `Low-level steps`:
  - map repeated offsets to field candidates
  - map stride/induction patterns to array candidates
  - keep mixed evidence conservative by preferring no rewrite when member and
    array evidence conflict on the same base
  - prefer "no rewrite" over guessed pretty output when evidence conflicts
- `Dependencies`:
  - `C1`
  - `C2`
  - `B3`
- `Exit signal`:
  - object-like code increasingly shows members and arrays instead of `*(base +
    k)` arithmetic

### [x] C2.1. Stable Stack Object Recovery

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - turns stack-slot identity into clearer locals and arguments
  - reduces fake temporaries and stack noise in output
- `Low-level steps`:
  - preserve stable stack objects as explicit locals/args
  - keep byte/word subviews attached to one stack object family
  - reject early overmerge across distinct stack regions
  - keep stack annotations and typed stack evidence flowing into the object
    layer
- `Dependencies`:
  - `B2`
  - `B4`
- `Exit signal`:
  - stack code looks object-like and width-stable instead of byte-slice-heavy

### [x] C2.2. Stable Global Object Recovery

- `Priority`: `P2`
- `Complexity`: `High`
- `How it helps`:
  - makes globals look less synthetic and more typed
  - connects typed global annotations to true global object recovery
- `Low-level steps`:
  - distinguish scalar globals from object roots
  - preserve widths in declarations and uses
  - carry typed global annotation evidence into final declarations
  - stop at scalar/global-root presentation when stronger object evidence is
    still missing
- `Dependencies`:
  - `B3`
  - `B8`
- `Exit signal`:
  - globals are consistently typed and only become objects when base evidence
    is strong enough

### [x] C2.3. Trait-To-Type Handoff

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - makes the evidence-to-type boundary explicit instead of implicit
  - keeps trait collection from drifting back into direct object rewrites
- `Low-level steps`:
  - define one formal handoff shape from trait evidence profiles to the type
    layer
  - include:
    - evidence category
    - width stability
    - address-space origin
    - base identity
    - ambiguity flags
  - keep object/type decisions downstream of that handoff only
- `Dependencies`:
  - `C1`
  - `B4`
  - `B8`
- `Exit signal`:
  - trait logic emits evidence objects, and type/object layers consume them
    explicitly

### [x] C4. Prototype And Calling Convention Recovery

- `Priority`: `P1`
- `Complexity`: `Very High`
- `How it helps`:
  - improves arguments, returns, helper calls, and overall C shape
  - unlocks partial recompilability as a side effect
- `Low-level steps`:
  - improve stack-argument recovery on top of stack alias identity
  - improve near/far-call aware signature handling
  - preserve multiword return handling and keep explicit wide-return
    prototypes width-stable through decompilation
  - promote explicit prototypes only with strong evidence
  - keep helper signatures and callsites stable across corpus runs
- `Dependencies`:
  - `B2`
  - `B3`
  - `C2`
- `Exit signal`:
  - function signatures become a strength of the output instead of a frequent
    readability weakness

### [x] C4.1. Prototype Evidence Layer

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - makes function-boundary decisions explainable by evidence instead of
    scattered heuristics
  - unifies arguments, returns, helper signatures, and far/near call class
- `Low-level steps`:
  - define explicit prototype evidence for:
    - stack-argument windows
    - register returns
    - multiword returns
    - far/near call class
    - helper metadata
    - callsite agreement
  - keep existing typed annotations and wide-return handling as inputs to this
    layer, not separate special cases
- `Dependencies`:
  - `C2.1`
  - `C2.2`
- `Exit signal`:
  - prototype decisions can be described as evidence composition rather than
    one-off heuristics

### [x] C4.2. Stack-Argument Recovery

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - separates arguments from locals more reliably
  - improves signatures and body readability together
- `Low-level steps`:
  - recover argument windows from stack-slot identity
  - distinguish argument slots from local stack objects
  - preserve widths and partial views
  - keep prototype promotion conservative when stack identity is mixed
- `Dependencies`:
  - `C4.1`
  - `C2.1`
- `Exit signal`:
  - common functions stop inventing bogus locals/args around the frame

### [x] C4.3. Far/Near Prototype Recovery

- `Priority`: `P2`
- `Complexity`: `Very High`
- `How it helps`:
  - addresses one of the major DOS-specific readability gaps at function
    boundaries
  - connects far-call discovery to output-level prototype quality
- `Low-level steps`:
  - preserve far/near call class as output-visible prototype evidence
  - connect bounded far-call target recovery and calling-convention seeding to
    function signature recovery
  - keep helper signatures stable when the callee model is known, and stay
    conservative otherwise
- `Dependencies`:
  - `C4.1`
  - `A2`
- `Exit signal`:
  - medium-model startup/helper code shows fewer weak or misleading call
    signatures

### [ ] D7. Thin Late-Rewrite Boundary

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - keeps alias/widening/object/prototype logic out of the final printer-ish
    cleanup layer
  - preserves a clean architecture boundary
- `Low-level steps`:
  - keep late rewrite limited to:
    - tiny boolean cleanup
    - tiny algebraic cleanup
    - declaration cleanup
    - final pretty-print normalization
  - move any lingering storage or evidence reasoning upstream
- `Dependencies`:
  - `D5`
  - `D6`
- `Exit signal`:
  - late rewrite no longer hides recovery logic that belongs upstream

### [ ] D35. Source-Backed Rewrite Audit

- `Priority`: `P2`
- `Complexity`: `Medium`
- `How it helps`:
  - makes it explicit which wins still come from guarded source-backed rescues
    and which are now explained by the general recovery pipeline
  - prevents the source-backed layer from quietly turning into a second hidden
    architecture
- `Low-level steps`:
  - keep `cod_source_rewrites.py` as the explicit registry for source-backed
    rewrites instead of scattering them through decompile-time helpers
  - annotate each rewrite spec as one of:
    - temporary rescue
    - permanent guarded oracle
    - already subsumed by general recovery
  - add a small summary/report helper over the rewrite registry so the current
    debt is visible
  - prefer moving subsumed cases into tests plus guards rather than deleting
    their evidence entirely
- `Dependencies`:
  - `C3`
  - `C4`
  - `D7`
- `Exit signal`:
  - every source-backed rewrite has an explicit status and the active rescue
    set is small and explainable

### [ ] D36. Promote Rescues Into Regression Oracles

- `Priority`: `P2`
- `Complexity`: `Medium`
- `How it helps`:
  - converts one-off wins into durable validation instead of permanent hidden
    policy
  - gives a concrete measure of whether architecture is replacing special cases
- `Low-level steps`:
  - when alias/widening/type/prototype layers cover a case, move the old
    source-backed behavior into:
    - a focused test anchor
    - a guarded fallback only when still necessary
  - keep sample-matrix and `.COD` cases as the main acceptance layer for
    “rescue retired successfully”
  - prefer registry-level downgrade from active rewrite to oracle rather than
    ad hoc deletion
- `Dependencies`:
  - `D35`
- `Exit signal`:
  - more former rescue cases are enforced by tests than by active rewrite code

### [ ] D37. Special-Case Debt Tracker

- `Priority`: `P2`
- `Complexity`: `Low`
- `How it helps`:
  - turns “we think the architecture is replacing hacks” into something we can
    inspect
  - helps decide whether the next win should land in core recovery or in a
    temporary guarded rewrite
- `Low-level steps`:
  - track the number of active source-backed rewrite specs
  - track how many golden cases still require explicit rescue
  - track how many now pass through the general alias/widening/type/prototype
    path
  - include this in milestone notes alongside scan-safe and validation-manifest
    summaries
- `Dependencies`:
  - `D35`
  - `D36`
- `Exit signal`:
  - the special-case surface trends down over time instead of drifting upward

### [ ] D38. Readability Issue Mining

- `Priority`: `P2`
- `Complexity`: `Medium`
- `How it helps`:
  - keeps readability work tied to the actual corpus, not just intuition
  - helps sort ugly output into alias, widening, type, callsite, or late-rewrite
    buckets
- `Low-level steps`:
  - use `x86_16_decompiler_readability.md` as the human-facing snapshot of
    “good now”, “mixed but promising”, and “still ugly” cases
  - keep pairing scan-safe hotspot data with readability snapshots so we can
    distinguish stability blockers from readability blockers
  - rank recurring output ugliness such as:
    - byte-pair arithmetic
    - temp soup
    - raw segmented arithmetic
    - unresolved callsites
    - weak member/array recovery
    - boolean/interval noise
  - route each ugly cluster back to the right architectural layer before
    implementing another local rewrite
- `Dependencies`:
  - `A0`
  - `C3`
  - `C4`
- `Exit signal`:
  - each milestone can point to a few top readability clusters and the layer
    responsible for fixing them

### [ ] D39. Boolean And Condition Cleanup Refinement

- `Priority`: `P2`
- `Complexity`: `Medium`
- `How it helps`:
  - improves late readability without reopening alias or type decisions
  - directly targets noisy interval and flag-derived conditions that still make
    output look like recovered IR
- `Low-level steps`:
  - keep improving the bounded late-cleanup helpers in:
    - `decompiler_postprocess_simplify.py`
    - `decompiler_postprocess_flags.py`
  - preserve the current explicit cleanup families:
    - boolean simplification
    - flag-condition pairing
    - impossible interval-guard repair
  - only add new condition simplifiers when they are clearly semantics-preserving
    and stay downstream of stable evidence
  - keep focused tests for representative flag/guard cleanups so readability
    wins remain honest
- `Dependencies`:
  - `D7`
  - `D38`
- `Exit signal`:
  - common conditions get shorter and clearer without reintroducing hidden
    semantic recovery into late rewrite

### [ ] D40. Control-Flow Readability Polishing

- `Priority`: `P3`
- `Complexity`: `High`
- `How it helps`:
  - makes mature output look like decompiled source instead of recovered IR
- `Low-level steps`:
  - cleaner loops
  - fewer goto-like leftovers
  - improved switch recovery when safe
- `Dependencies`:
  - `D38`
- `Exit signal`:
  - selected bodies become structurally easier to read

### [ ] D41. Naming Polish Over Object Recovery

- `Priority`: `P3`
- `Complexity`: `Medium`
- `How it helps`:
  - names stop fighting structure recovery
  - output feels less synthetic
- `Low-level steps`:
  - naming informed by object/member/array identity
  - helper family naming
  - conservative fallback naming when evidence is weak
- `Dependencies`:
  - `D27`
  - `D28`
  - `D33`
- `Exit signal`:
  - final naming is driven by recovered structure, not just ad hoc hints

### [ ] D42. Optional Recompilable Subset

- `Priority`: `P3`
- `Complexity`: `High`
- `How it helps`:
  - validates deeper architecture quality without turning the project into a
    transpiler
- `Low-level steps`:
  - choose a narrow output subset
  - compile it
  - compare behavior when practical
- `Dependencies`:
  - most of blocks `3` through `10`
- `Exit signal`:
  - a small recurring subset remains compilable with limited manual repair

## Remaining Working Order

If we compress the remaining roadmap into the next major execution sequence,
the best order is:

1. keep the scan lane and baseline stable
2. finish any remaining instruction-core factoring needed for scan stability
3. push segmented-memory association toward a stronger policy gate
4. finish member and array recovery
5. finish prototype and calling-convention recovery
6. keep late rewrite thin and honest
7. polish control flow and naming last

## Stop Rules

Pause and reassess if:

- widening starts producing more wrong code than it removes
- object/type recovery becomes prettier but less honest
- alias work adds complexity without reducing local special cases
- new wins keep requiring one-off rescues instead of becoming reusable

## Success Signal

This plan is working if each major layer:

- explains multiple older wins with one architectural idea
- reduces the number of local hacks needed for new corpus cases
- improves both correctness and readability together
- leaves the test discipline stronger than before
