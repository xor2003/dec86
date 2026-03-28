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

### C3. Member And Array Recovery

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

### C4. Prototype And Calling Convention Recovery

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

### D7. Thin Late-Rewrite Boundary

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

### D40. Control-Flow Readability Polishing

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

### D41. Naming Polish Over Object Recovery

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

### D42. Optional Recompilable Subset

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
