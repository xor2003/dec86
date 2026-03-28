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

## Phase B. Recovery Foundation

This is the highest-value architecture phase. It turns isolated wins into a
coherent recovery pipeline.

### B1. Register Alias MVP

- `Priority`: `P0`
- `Complexity`: `High`
- `How it helps`:
  - gives widening a safe proof source
  - improves subregister reasoning
  - reduces accidental byte-pair joins
- `Low-level steps`:
  - keep register domains explicit for `AX/BX/CX/DX`
  - keep `full16`, `low8`, and `high8` views explicit
  - maintain alias state with `needs_synthesis`
  - route one real widening path through alias-proven register joins
- `Dependencies`:
  - none; this is the first recovery foundation step
- `Exit signal`:
  - register pair reconstruction no longer depends on pure expression-shape
    matching

### B2. Stack-Slot Alias Identity

- `Priority`: `P0`
- `Complexity`: `Very High`
- `How it helps`:
  - improves stack tracking, argument reasoning, and local recovery
  - lays the foundation for cleaner prototypes and stack object identity
- `Low-level steps`:
  - model stable `bp`-framed stack slots as domains
  - support byte and word views for stack slots
  - track partial vs full slot writes conservatively
  - add safe `bp`-relative byte-pair joins only after alias proof
  - keep the first MVP narrow: explicit `bp` base, displacement, width, and
    region metadata for stack slots
  - use stack-slot identity when promoting prototypes from `bp` loads so mixed
    stack regions do not trigger false argument expansion
- `Dependencies`:
  - `B1`
- `Exit signal`:
  - stack byte-pair cleanup and prototype reasoning start depending on stack
    identity, not isolated local rewrites
  - the MVP already handles simple `bp`-framed locals and can be extended to
    more stack forms without changing the core alias boundary

### B3. Segmented Memory Association

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

### B4. Unified Widening Pass

- `Priority`: `P0`
- `Complexity`: `Very High`
- `How it helps`:
  - removes duplicated byte-pair logic
  - makes output less sensitive to local tree shape
  - improves readability across register, stack, and memory cases
- `Low-level steps`:
  - extract widening candidates from alias-proven pieces
  - prove compatibility before rewrite
  - support register pair joins
  - support stack byte-pair joins
  - support safe adjacent memory joins
  - normalize whole/slice/whole and projection cleanup patterns
- `Dependencies`:
  - `B1`
  - `B2`
  - partly `B3` for segmented memory quality
- `Exit signal`:
  - widening lives as one coherent recovery stage instead of multiple unrelated
    cleanup tricks

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

## Phase C. Evidence To Types To Objects

This phase converts cleaner value recovery into source-like object recovery.

### C1. Trait Evidence Profiles

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - stops traits from being only naming hints
  - makes type and object recovery evidence-driven
- `Low-level steps`:
  - keep separate evidence streams for:
    - member-like access
    - array-like access
    - induction-like access
    - repeated offsets
    - stride evidence
    - stack-like access that is still evidence-driven but not yet a full object
      type guess
  - build stable evidence profiles per base object
  - make stack bases prefer stack-like evidence first when ordering candidate
    names, and keep that priority stable through candidate-field-name
    generation instead of letting a later sort erase it
  - let stack bases surface `stack` as the preferred rewrite kind when
    stack-like evidence is present, so stack-object recovery has a distinct
    path from member/array rewriting
  - render stack-like trait-driven stack objects with stack-object naming
    (`local_` / `arg_`) instead of forcing them through the generic
    `field_`-style member naming path
  - keep positive tests on real `.COD` and `snake` helpers
- `Dependencies`:
  - `B1`
  - `B4`
- `Exit signal`:
  - traits can feed object/type decisions without relying on raw bucket dicts
  - stack-aware evidence profiles are available as a first-class trait lane for
    later stack/object recovery work, including base-aware candidate ordering

### C2. Stable Stack and Global Object Recovery

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - improves locals, arguments, globals, and width-preserving object recovery
  - reduces raw address arithmetic in output
- `Low-level steps`:
  - preserve byte/word widths for recovered stack objects
  - improve stable global naming and typed global usage, including typed
    annotation specs that keep global name and type evidence together
  - keep typed `bp_stack_vars` / stack annotations as the first working
    evidence-preserving stack-object path, so recovered locals can retain their
    width and type instead of collapsing back to generic temps
  - use evidence profiles to choose conservative stack/global object rewrites
  - keep stack-object rewrites separate from printer-only cleanup
- `Dependencies`:
  - `B2`
  - `C1`
- `Exit signal`:
  - more real samples present stable locals/globals instead of temp-heavy
    address arithmetic

### C3. Member and Array Recovery

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

### C4. Prototype and Calling Convention Recovery

- `Priority`: `P1`
- `Complexity`: `Very High`
- `How it helps`:
  - improves arguments, returns, helper calls, and overall C shape
  - unlocks partial recompilability as a side effect
- `Low-level steps`:
  - improve stack-argument recovery on top of stack alias identity
  - improve near/far-call aware signature handling
  - preserve multiword return handling
  - promote explicit prototypes only with strong evidence
  - keep helper signatures and callsites stable across corpus runs
- `Dependencies`:
  - `B2`
  - `B3`
  - `C2`
- `Exit signal`:
  - function signatures become a strength of the output instead of a frequent
    readability weakness

## Phase D. Corpus-Scale Generalization

This phase broadens good architecture across a wider real corpus.

### D1. Replace One-Off Wins With General Recovery

- `Priority`: `P1`
- `Complexity`: `High`
- `How it helps`:
  - reduces dependence on allowlists and rescue rewrites
  - makes improvements transfer to new binaries with less manual work
- `Low-level steps`:
  - identify current wins that still depend on source-backed rescues
  - move repeated successful patterns into general recovery layers when safe
  - keep source-backed rewrites as anchors and regressions, not the only
    mechanism
- `Dependencies`:
  - `B` and `C` phases
- `Exit signal`:
  - new real sample improvements increasingly come from architecture, not a new
    one-off rule

### D2. Corpus-Driven Quality Mining

- `Priority`: `P1`
- `Complexity`: `Medium`
- `How it helps`:
  - keeps effort focused on the real target corpus
  - highlights the next highest-ROI readability failures
- `Low-level steps`:
  - keep mining `.COD`, sample-matrix binaries, and `snake.exe`
  - track frequent readability failures:
    - temp soup
    - broken object shapes
    - poor helper signatures
    - ugly startup/runtime output
  - rank quality gaps by recurrence, not only by aesthetics
- `Dependencies`:
  - none beyond the current corpus workflow
- `Exit signal`:
  - the roadmap is driven by real repeated failures instead of intuition alone

### D3. Multi-Level Validation Discipline

- `Priority`: `P0`
- `Complexity`: `Medium`
- `How it helps`:
  - keeps the architecture sustainable
  - prevents local wins from quietly damaging the broader baseline
- `Low-level steps`:
  - keep unit tests for alias, widening, traits, and type internals
  - keep focused corpus tests for known-good helpers and `.COD` cases
  - keep whole-program sanity checks for `snake.exe` and sample-matrix binaries
  - require each meaningful recovery change to pass all three layers before
    broad rollout
- `Dependencies`:
  - none; this should run throughout all phases
- `Exit signal`:
  - new architectural work has a stable regression harness by default

## Phase E. Dream-Quality Polish

This phase is about maturity, not a new foundation.

### E1. Better Call Recovery and Helper Modeling

- `Priority`: `P2`
- `Complexity`: `High`
- `How it helps`:
  - improves readability of real startup/runtime and helper-heavy code
  - reduces fake `sub_...` noise
- `Low-level steps`:
  - improve call target recovery in bounded CFG paths
  - preserve helper names and signatures more consistently
  - reduce `callee None` style decompiler failures on real samples
- `Dependencies`:
  - `C4`
  - `D1`
- `Exit signal`:
  - helper-heavy real binaries become readable without heavy manual rescue

### E2. Stronger Readability and Partial Recompilability

- `Priority`: `P3`
- `Complexity`: `High`
- `How it helps`:
  - turns useful decompilation into output that is also easier to port, study,
    and partially rebuild
- `Low-level steps`:
  - improve boolean cleanup, loop shapes, and switch recovery where evidence is
    already strong
  - keep synthetic temporaries low
  - keep prototypes, object widths, and pointer types stable enough that a
    subset of output remains compilable with limited manual repair
- `Dependencies`:
  - most of `B`, `C`, and `D`
- `Exit signal`:
  - "recompilable subset" becomes a recurring property of good outputs instead
    of an occasional accident

## Recommended Working Order

If we want the highest return with the least wasted work, the next major queue
should be:

1. `B2` Stack-slot alias identity
2. `B4` Unified widening on top of alias proof
3. `C1` Trait evidence profiles
4. `C2` Stable stack/global object recovery
5. `C4` Prototype and calling convention recovery
6. `C3` Member and array recovery
7. `D1` Generalize repeated wins across the real corpus

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
