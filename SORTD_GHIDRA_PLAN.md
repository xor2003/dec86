# SORTD Inertia/Ghidra Comparison And Improvement Plan

## Scope And Truth Sources

This report covers only the 20 non-library functions emitted by Inertia for
sidecar-free `SORTD.EXE`. Ghidra's 138 recovered functions are scanned only to
find bodies corresponding to those 20 functions; runtime/library functions are
not compared.

Correctness priority:

1. binary IR/CFG, typed effects, and whole-tail validation
2. compile and behavior gates
3. `SORTDEMO.C` as an optional comparison oracle
4. Ghidra output as a diagnostic peer, never as truth

Numeric function and global names are acceptable when the executable has no
debug information. Source names below identify addresses for this report only;
they must not become recovery evidence.

## Measured Baseline

Fresh command on 2026-08-06:

```text
./decompile.py SORTD.EXE --ignore-local-sidecar-hints --no-alternate-source-c -q
```

- selected/decompiled: 20/20 non-library functions
- validation: 20/20 passed; whole-tail validation clean
- assembly/details fallback: 0
- empty functions, timeouts, tracebacks: 0
- default function execution: 7 clean processes, one function per process
- elapsed: 4:36.36; CPU utilization: 478%; peak RSS: 305,748 KiB
- stdout separation: only generated C; diagnostics remain on stderr
- direct stdout recompilation: passed strict GCC syntax checking with all 20
  generated function bodies in one canonical translation unit
- default regression pipeline: 3/3 lanes passed; 1,788 focused tests, four
  Ultra QuickC fixtures, and all seven MS C tiny constructs passed their
  compile/decompile/recompile/exit-code contracts

The previous direct-output defect concatenated independently valid payloads and
produced conflicting declarations. Whole-binary stdout now uses the same owned,
structured export contract as generated artifacts. Conflicts are typed failures
reported on stderr with a nonzero exit status.

## Address Coverage

Ghidra entries before NOP padding are mapped to Inertia's canonical body entry.

| Inertia body | Source label | Ghidra entry | Leading NOPs | Status |
| --- | --- | --- | ---: | --- |
| `0x10010` | main | `0x10010` | 0 | matched |
| `0x10060` | InitMenu | `0x1005d` | 3 | matched |
| `0x101f0` | DrawFrame | `0x101db` | 21 | matched |
| `0x102e0` | RunMenu | `0x102cc` | 20 | matched |
| `0x10498` | DrawTime | `0x10491` | 7 | matched |
| `0x10560` | InitBars | `0x10554` | 12 | matched |
| `0x10678` | ReInitBars | `0x10672` | 6 | matched |
| `0x106c8` | DrawBar | `0x106c8` | 0 | matched |
| `0x10768` | SwapBars | `0x1075b` | 13 | matched |
| `0x107b8` | Swaps | `0x10794` | 36 | matched |
| `0x10808` | InsertionSort | missing | - | Ghidra discovery loss |
| `0x108d0` | BubbleSort | missing | - | Ghidra discovery loss |
| `0x10970` | HeapSort | missing | - | Ghidra discovery loss |
| `0x109e8` | PercolateUp | `0x109e8` | 0 | matched |
| `0x10a88` | PercolateDown | missing | - | Ghidra discovery loss |
| `0x10b50` | ExchangeSort | missing | - | Ghidra discovery loss |
| `0x10c18` | ShellSort | missing | - | Ghidra discovery loss |
| `0x10ce0` | QuickSort | missing | - | Ghidra discovery loss |
| `0x10e70` | Beep | `0x10e5d` | 19 | matched |
| `0x10f38` | Sleep | `0x10f18` | 32 | matched |

For all 13 address-matched bodies, the sets of direct calls to the 20
application functions agree. The seven missing Ghidra bodies are a Ghidra
function-discovery defect: Inertia discovers them from the binary and validates
their generated C.

## Whole-File Findings

### Closed P0: Recompilable normal output

Inertia previously repeated `g_08F0_entry` and emitted stale/conflicting callee
declarations such as `int` versus `short` return types. Batch stdout now
canonicalizes those declarations and passes `gcc -std=c11 -Wall -Wextra
-Werror -fsyntax-only` without changing or losing any of the 20 bodies.

Owner: CLI/export assembly in `inertia_decompiler/`. Function postprocess must
not reconcile interprocedural declarations.

### P0: Semantic completeness

The prior assembly fallbacks and lost control effects are closed in the current
run. In particular, Beep retains its `duration < 75` guard and both byte-output
arguments, DrawFrame initializes its loop variable before the pre-test loop,
and Sleep uses the widened clock result. All 20 pass validation.

The generated behavior gate now compiles and executes unchanged output for all
19 non-library functions covered by `SORTDEMO.C` function self-tests. `main`
has no source function-selftest contract; it remains compile- and
validation-covered. This does not yet claim whole-program replacement
equivalence.

### P1: Ghidra semantic errors

The matched Ghidra output is useful for control-flow comparison but is not a
better correctness oracle:

- InitMenu assigns its loop variable `0x4d00` instead of preserving the binary
  increment, changing termination and menu traversal.
- InitBars indexes by `% 0x60b` and stores an uninitialized stack value where
  the binary/source behavior selects a bounded random entry and swaps values.
- PercolateUp passes a computed object address as a row index to the redraw
  call; the call argument class is wrong.
- Beep loses an argument on an output-port call and exposes register fragments.
- ReInitBars does not express the complete widened clock store cleanly.
- DrawFrame, DrawTime, and InitMenu leave stack-call setup variables in forms
  that are not directly recompilable C.
- DrawBar recovers a 34-byte buffer although the binary-proven Inertia object is
  44 bytes (the source declaration has 43 elements).

Where these differ, Inertia's binary evidence plus passing validation wins.

### P1: Inertia type and readability debt

Cross-function return and parameter contracts still disagree before export
canonicalization. Several source-void procedures render as scalar-returning
functions, even when callers ignore the result. This should be solved from
binary caller/return-use summaries in Types/Lowering, not by source names and
not by Rewrite.

Raw `SEG_U*` accesses remain appropriate when DS object identity is unproven.
They are readability debt, not permission to guess a global. Numeric names are
not a defect under the no-debug-information requirement.

### P2: Performance

Default N-1 clean-process execution is working and deterministic with seven
workers on this eight-CPU host. The measured run used about 302 MiB peak RSS,
well below the 2 GiB budget, and reduced the prior three-worker wall time from
about 467 seconds to about 274 seconds. Do not parallelize mutable fallback
rebuilds until their project state and aggregate memory are measured in
isolation; the validated primary function jobs are already parallel.

## Ordered Plan With Per-Step DoD

### 1. Canonicalize whole-binary stdout at CLI/export

Status: complete.

Definition of done:

- normal whole-binary stdout is assembled from accepted typed function
  payloads through one structured declaration table
- `./decompile.py SORTD.EXE > out.c` followed by strict GCC syntax checking has
  zero declaration/type conflicts
- every one of the 20 generated function bodies remains present and unchanged
- assembly conflicts stop the CLI with a clear stderr error and nonzero status
- direct single-function output and `--output-c-dir` artifacts remain stable
- focused export/CLI tests, Ruff `--fix`, types/docs, and architecture checks pass

### 2. Expand behavior proof beyond the sort core

Status: complete for every source-selftested non-library function.

Definition of done:

- every source-selftested application function has a generated-C harness
- required calls and value-versus-pointer argument classes are checked
- generated execution matches the source oracle's return values, memory
  effects, and expected exit code
- the default or expanded pipeline fails on missing functions, sanitizer
  failures, behavioral differences, assembly fallback, or validation failure
- no source text or name is used to recover semantics

Measured closure: 19/19 generated function bodies compile and execute unchanged
under ASan/UBSan against source-derived outcomes. The cases include RunMenu
Escape/dispatch behavior, DrawTime timing/sound arguments, Beep output-port
arguments, full-width ReInitBars copies, and InitMenu pointer-table traversal.
The final expanded pipeline passes 5/5 lanes. Its status parser associates
deferred canonical definitions and their declaration preludes with the exact
function record, so batch stdout cannot create false "generated C missing"
results or bypass leakage/call-contract checks.

### 3. Unify interprocedural function contracts at Types/Lowering

Status: pending.

Definition of done:

- each internal function has one binary-evidenced return/parameter contract
  shared by its definition and every callsite before export
- ignored returns become `void` only when the caller census is complete and no
  return use exists; unknown evidence refuses conversion
- signedness and pointer/value classes survive clean-worker transport
- closed evidence counters report every classified and materialized contract
- focused negative tests prove refusal on conflicting or incomplete callers

### 4. Keep discovery and semantic-loss ratchets permanent

Status: complete for the current 20-function baseline.

Structuring now distinguishes machine facts from facts joined to one exact AST
placement site. Exact instruction provenance plus exact stack destination
tracks a Lowering-typed function designator without reinterpreting its value;
tagless replay still requires strict source identity. A classified placement
with no materialized assignment is a hard pipeline error, while an unjoined
fact is retained as `UNKNOWN_REFUSE`.

Definition of done:

- the sidecar-free pipeline continues to require exactly these 20 application
  addresses, 20/20 validation, zero empty/fallback/timeout/traceback results
- comparison diagnostics remain restricted to Inertia's 20 functions and
  account for NOP-padded entry aliases deterministically
- regressions cover Beep's minimum-duration guard and call arguments,
  DrawFrame's pre-test initializer, Sleep's widened condition, and RunMenu's
  Escape return
- any classified semantic fact with zero materialization fails the pipeline
- all seven MS C tiny constructs compile, run, decompile without asm fallback,
  recompile, and match the required DOS exit code

### 5. Improve readability only from proof

Status: pending after recompilation and behavior gates.

Definition of done:

- proven stack slots render as locals/arguments and proven aggregate layouts
  render as arrays/structs without conflicting declarations
- explicit signed conditions survive rendering and recompilation
- unresolved segment/global identity stays explicit rather than guessed
- numeric function names remain valid when no symbol evidence exists
- every readability change keeps validation and behavior gates green

### 6. Profile before further parallelization

Status: primary N-1 execution complete; fallback work deferred.

Definition of done:

- deterministic function order and output hashes are unchanged across repeats
- aggregate worker RSS stays below 2 GiB with a documented worker cap
- pass-level profiles identify CPU-bound owners before adding concurrency
- mutable fallback rebuilds remain serial until isolated-state and OOM tests
  prove bounded parallel execution

### 7. Borrow Reko's proven quality mechanisms without its unsafe fallbacks

Status: pending. The comparison artifact is
`comparisons/reko/SORTD/reko-0.12.4/NON_LIBRARY_COMPARISON.md`.

This step is about decompilation quality only. Reko 0.12.4 is not a better
whole-function oracle: 14/20 corresponding application bodies contain
`<invalid>` or `<unknown>`, and QuickSort explicitly loses eight recursive call
arguments. Its useful mechanisms are narrower:

- Beep preserves the minimum-duration guard, word-to-byte timer writes, Sleep
  argument, and final speaker-control restore;
- Sleep keeps the split-word clock value as one 32-bit calculation and
  comparison;
- InitBars retains both initialization loops and the random-selection dataflow;
- Swaps keeps the two-byte object exchange as one object operation.

Use `borrow/reko/` as design evidence, not as semantic truth and not as code to
copy blindly. Reko is GPL-licensed and has a different IR/type model; any
implementation must be independently expressed in Inertia's owned typed
contracts and reviewed against this project's licensing requirements.

#### 7.1 Re-run wide-value recovery at evidence-producing boundaries

Reko runs its `LongAddRewriter` immediately after register SSA, repeats it after
value propagation, then eliminates condition codes and runs
`LongComparisonFuser`; it fuses sliced stores afterward. See:

- `borrow/reko/src/Decompiler/Analysis/SccWorker.cs:170-232`
- `borrow/reko/src/Decompiler/Analysis/LongAddRewriter.cs:37-94`
- `borrow/reko/src/Decompiler/Analysis/LongComparisonFuser.cs:40-106`

Implement the equivalent idea in Inertia's existing Widening ownership rather
than adding a rewrite pass:

1. Normalize proven low/high carriers (`DX:AX`, adjacent 16-bit stack/global
   halves, and carry/borrow-linked pairs) after Alias establishes storage
   identity.
2. Re-run only the widening candidates whose inputs changed after typed value
   propagation or call-summary materialization; do not repeatedly scan the
   whole AST.
3. Materialize 32-bit add/subtract, divide, slice, store, and comparison facts
   before Structuring. Preserve signedness and exact low/high provenance.
4. Fuse multi-block high-word/low-word comparisons only when CFG targets,
   condition polarity, and both carrier identities prove one comparison.
5. Unknown or conflicting halves remain separate; they are never joined by
   adjacency or shape alone.

Acceptance cases:

- Sleep remains `goal = wait + clock()` followed by one correct 32-bit clock
  comparison, with `validation=passed`.
- ReInitBars keeps one 32-bit `clStart` store rather than unrelated 16-bit
  writes.
- Beep keeps the 32-bit dividend/divisor relationship and the exact low-byte
  and high-byte slices passed to the two timer-port writes.
- Negative tests reject cross-block joins with mismatched carry provenance,
  segment space, alias object, or branch target.

#### 7.2 Build one interprocedural storage contract, then bind calls exactly

Reko first derives each procedure signature from program dataflow and only then
rewrites calls and returns. Inputs include sequence registers, individual
registers, and sorted stack slots; outputs come from live-out storage. See:

- `borrow/reko/src/Decompiler/Analysis/CallRewriter.cs:85-155`
- `borrow/reko/src/Decompiler/Analysis/CallRewriter.cs:158-220`
- `borrow/reko/src/Decompiler/Analysis/ProcedureFlow.cs`

Its `CallApplicationBuilder` binds sequence and stack storage from reaching SSA
definitions, but falls back to synthesized invalid arguments when binding
fails. See `borrow/reko/src/Decompiler/Analysis/CallApplicationBuilder.cs:183-264`.
Borrow the former and explicitly forbid the latter.

Extend plan step 3 in Types/Lowering as follows:

1. Compute a whole-program, SCC-aware contract for every internal function:
   exact stack offsets and widths read, register/sequence inputs, preserved and
   clobbered storage, return/live-out storage, stack delta, and signed/value/
   pointer class.
2. Bind every call argument from the reaching definition of that exact storage
   at that callsite. A split value carries its sequence identity and slice
   provenance; a stack argument carries its BP/SP-relative source identity.
3. Iterate contracts only to a deterministic fixed point. A caller and callee
   disagreement is a typed conflict, not permission to pick one signature.
4. Never synthesize an argument, read an arbitrary current-SP slot, or emit an
   invalid placeholder. Missing proof is `UNKNOWN_REFUSE`, retains the lower
   representation, and fails materialization if the call was classified.
5. Feed the accepted contract into definitions and all callsites before C
   emission; export must not reconcile signatures afterward.

Acceptance cases:

- Beep's two `outp(0x42, ...)` calls bind the low and high byte of the same
  proven quotient, and `Sleep(duration)` binds the full duration value.
- SwapBars binds both row values to DrawBar and the first row value to DrawTime.
- QuickSort binds both arguments on every recursive edge, including the two
  opposite call orders; a Reko-like missing recursive argument is a hard gate
  failure.
- A negative fixture with incomplete caller coverage refuses a unified
  signature and emits no guessed argument.

#### 7.3 Infer arrays and small structures from alias-equivalent accesses

Reko's type pipeline normalizes expressions, builds equivalence classes,
collects constraints, builds aggregate types, replaces type variables, and only
then rewrites memory expressions. See:

- `borrow/reko/src/Decompiler/Typing/TypeAnalyzer.cs:33-111`
- `borrow/reko/src/Decompiler/Typing/EquivalenceClassBuilder.cs`
- `borrow/reko/src/Decompiler/Typing/TypeCollector.cs`
- `borrow/reko/src/Decompiler/Typing/DataTypeBuilder.cs`
- `borrow/reko/src/Decompiler/Typing/TypedExpressionRewriter.cs:208-315`

Adopt a bounded version after Alias and Widening, owned by Types/Lowering:

1. Group accesses only by proven `Address(space, base, offset)` alias identity,
   not textual similarity or numeric proximity across objects.
2. Collect typed constraints from load/store width, constant field offset,
   proven induction stride, call argument class, copy width, and widening
   identity.
3. Materialize an array only when one base, one element width, and consistent
   indexed accesses are proven. Materialize a structure only when non-overlap
   or an explicit union relation accounts for every observed field.
4. Keep conflicting constraints as separate typed alternatives and leave raw
   segmented accesses in C. Do not reproduce Reko's giant `Eq_*` unions or
   member-pointer expressions.
5. Rewrite memory expressions to object/field/index access only after the
   aggregate contract is accepted; this final rewrite introduces no new
   semantics.

Acceptance cases:

- InitBars proves the 43-word stack array from its initialization loop,
  bounded random index, and same-object replacement store.
- `abarPerm` and `abarWork` prove independent arrays of two-byte elements;
  each element proves byte `len` and byte `clr` fields from consistent offsets.
- Swaps materializes one two-byte temporary and three whole-object copy effects,
  while pointer/value argument classes remain unchanged.
- ReInitBars proves whole-element copies between the two arrays without merging
  their base identities.
- Negative tests reject a structure/array when accesses cross DS/SS, use
  inconsistent stride, overlap without union evidence, or have an unbounded
  index.

#### 7.4 Closed evidence and gates

Each of the three mechanisms must report
`raw_fact_count`, `normalized_fact_count`, `classified_fact_count`,
`materialized_count`, and `failure_count`. If `classified > 0` and
`materialized == 0`, the owning pipeline stage fails.

Definition of done:

- focused before/after regressions cover Beep, Sleep, InitBars, ReInitBars,
  Swaps, SwapBars, and QuickSort;
- all affected functions have `validation=passed`, no semantic call loss, and
  generated output no farther from `SORTDEMO.C` than the current baseline;
- the sidecar-free 20-function gate, strict GCC translation-unit check, 19
  generated behavior harnesses, and all seven MS C tiny constructs pass;
- `make test-pipeline PYTHON=./.venv/bin/python` passes before claiming the
  mechanism improved decompilation;
- no source name, source text, Reko output text, address allowlist, or rendered-C
  pattern participates in recovery;
- no semantic work is added to postprocess, CLI, or export assembly.

### 8. Borrow Ghidra's strongest mechanisms at their owning layers

Status: source-mapped design work, implementation pending.

The useful Ghidra evidence is in its native decompiler core under
`/home/xor/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`. These are
implementation signposts, not proof that every Ghidra result is correct. In
particular, the mechanisms below explain quality seen in `main`, DrawFrame,
RunMenu, SwapBars, Swaps, Beep, and Sleep, but must be tightened so Inertia
does not reproduce Ghidra's known SORTD errors.

Ghidra is Apache-2.0 licensed, but this plan borrows algorithms and separation
of responsibilities rather than copying source. Any copied or closely adapted
implementation still requires an explicit license and notice review.

#### 8.1 Keep stack locations in SSA until locals can be proven

Ghidra does not recover locals from rendered stack syntax. Its `Heritage`
engine constructs SSA for disjoint memory locations, delays stack-memory SSA
until locations are discovered, inserts phi nodes, renames definitions, and
guards memory across LOAD, STORE, and calls. `ActionStackPtrFlow` separately
solves stack-pointer changes and repairs stack-relative loads. See:

- `heritage.hh:190-315` (`Heritage`, memory SSA, guards, phi placement, rename)
- `heritage.cc:986-1065` (`discoverIndexedStackPointers`)
- `heritage.cc:1443-1605` (call, STORE, and LOAD guards)
- `heritage.cc:2479-2705` (SSA rename, phi placement, and heritage pass)
- `coreaction.cc:113-206` (`StackSolver::solve`, `StackSolver::build`)
- `coreaction.cc:262-512` (`ActionStackPtrFlow`)
- `varmap.cc:1120-1320` (`MapState::gatherVarnodes`,
  `ScopeLocal::restructureVarnode`, `ScopeLocal::restructure`)

Implement the equivalent in Inertia's IR and Alias layers:

1. Give each stack read/write an `Address(space=SS, base=entry_sp_or_bp,
   offset, width)` identity before naming any local or argument.
2. Build memory definitions and joins per exact stack range; split or merge
   overlapping ranges only with byte-accurate evidence.
3. Model call stack delta and clobbers as typed effects. Unknown delta prevents
   local materialization instead of silently rebasing later accesses.
4. Lower an SS range to one local only after all definitions, uses, widths,
   joins, and escapes agree. Keep unresolved accesses explicit.

This should remove Ghidra-like stack setup temporaries from DrawFrame,
DrawTime, and InitMenu without moving stack recovery into Rewrite. Negative
tests must cover overlapping locals, SP changes on one branch, escaped stack
addresses, and DS/SS offset collisions.

#### 8.2 Recover call and return contracts from storage trials

Ghidra treats a call signature as an evolving dataflow contract. It checks
candidate input storage against alias information over multiple passes, then
resolves a calling-convention model and builds call inputs. Outputs are
recovered from live uses; split return registers are joined with a `PIECE`
operation. See:

- `coreaction.cc:1754-1820` (`ActionActiveParam`, `ActionActiveReturn`)
- `coreaction.cc:1858-1983` (`ActionReturnRecovery`)
- `fspec.hh:1628-1727` (`FuncCallSpecs`, active inputs/outputs and stack delta)
- `fspec.cc:5585-5805` (trial-use checks and input/output construction)
- `coreaction.cc:4680-4740` (`ActionPrototypeTypes` and input extension)

Use this to refine plan steps 3 and 7.2 in Types/Lowering:

1. Represent each candidate parameter/return as a typed storage trial with
   width, exact stack/register identity, reaching definition, use evidence,
   signedness, and value-versus-pointer class.
2. Resolve a function contract only after the complete caller census agrees;
   join split returns only when both pieces have the same return provenance.
3. Apply the accepted contract to the callee and every callsite in one
   transaction. Conflicts remain typed failures, never export repairs.
4. Require every emitted argument to retain its reaching-definition proof.

The hard negative boundary comes from Ghidra itself: PercolateUp converted an
object address into a row value, and Beep lost an output-port argument. Those
outputs become rejection fixtures for argument-class changes and incomplete
trials. QuickSort's two recursive edges remain the fixed-point stress test.

#### 8.3 Propagate types through IR, aliases, and bounded object ranges

Ghidra initializes a temporary type from each operation, propagates only a
more-specific type across p-code edges, propagates pointer target types to
known aliases, reconciles return types, and writes accepted types back. Its
local map then combines fixed and open range hints; an indexed LOAD/STORE is
considered array evidence only when it has a nonzero proven step. See:

- `coreaction.cc:5095-5500` (`ActionInferTypes`)
- `varmap.cc:170-355` (`RangeHint::attemptJoin`, `RangeHint::merge`)
- `varmap.cc:896-1081` (`MapState::addRange`, `addFixedType`,
  `reconcileDatatypes`, `addGuard`)
- `ruleaction.cc:6671-6835` (`RulePtrArith`, `RuleStructOffset0`)
- `ruleaction.cc:7597-7775` (`RulePieceStructure`)
- `ruleaction.cc:9618-9775` (`RulePtrFlow`)

Adopt this after Alias and Widening, with stricter Inertia evidence:

1. Propagate types through owned IR operations using a deterministic
   specificity order; block propagation at conflicting aliases or segment
   spaces.
2. Convert integer arithmetic to pointer/index/field operations only when the
   base `Address`, element width, stride, and bounds are proven.
3. Reconcile overlapping range hints only when one byte-accurate array,
   structure, or explicit union accounts for every access.
4. Preserve raw segmented accesses when evidence conflicts.

Do not borrow Ghidra's fallback assumption that an unlocked indexed range has
at least four elements (`varmap.cc:1215-1219`). InitBars' wrong `% 0x60b`,
uninitialized store, and DrawBar's wrong 34-byte object are mandatory negative
fixtures. Array bounds must come from CFG/range evidence, not a default size.

#### 8.4 Normalize split values and carry before type and structure recovery

Ghidra has dedicated p-code rules for converting PIECE/extension forms,
eliminating redundant carry expressions, combining low/high add-subtract
pieces, and preserving pointer flow through segmented casts. See:

- `ruleaction.cc:213-260` (`RulePiece2Zext`, `RulePiece2Sext`)
- `ruleaction.cc:4002-4055` (`RuleCarryElim`)
- `ruleaction.cc:5288-5355` (`RulePieceAddSub`)
- `ruleaction.cc:11583-11980` (`RulePieceCarryAdd`)
- `ruleaction.cc:9264-9305` (`RuleSegmentCastPtrArith`)

Implement these ideas only in Inertia's Widening layer, after Alias proves
carrier identity. A wide `Value` must retain low/high slice provenance, carry
or borrow provenance, signedness, and its segmented address space. Sleep,
ReInitBars, DrawTime, and Beep are positive fixtures. Ghidra's remaining
`CARRY2`/register fragments are evidence that shape-only fusion is insufficient;
mismatched branch, carrier, segment, or definition must produce
`UNKNOWN_REFUSE`.

#### 8.5 Collapse CFG regions only after conditions are explicit

Ghidra first identifies loop backedges and nesting, then repeatedly collapses
well-constrained graph regions into sequence, AND/OR, if, if/else, while,
do/while, and switch nodes. Only afterward does it order blocks and mark the
remaining unstructured edges as gotos. See:

- `blockaction.cc:1124-1184` (`CollapseStructure::labelLoops`,
  `orderLoopBodies`)
- `blockaction.cc:1284-1573` (sequence, condition, if, and loop rules)
- `blockaction.cc:1649-1715` (switch collapse)
- `blockaction.cc:1877-1895` (`CollapseStructure::collapseAll`)
- `blockaction.cc:2169-2196` (`ActionBlockStructure`, `ActionFinalStructure`)

Use the same conservative region-collapse order in Structuring, but consume
only Inertia `Condition` objects whose flag/value provenance is already
explicit. Every collapse must preserve exact entry, exit, backedge, and branch
polarity. RunMenu and DrawFrame are positive fixtures; InitMenu's corrupted
loop update is the negative fixture proving that a pretty loop is not enough.
When a region cannot be proven, retain a deterministic goto instead of
inventing a loop or condition.

#### 8.6 Explicitly do not borrow Ghidra's function-start patterns

Ghidra's pattern-driven discovery lives in
`Ghidra/Features/BytePatterns/src/main/java/ghidra/app/analyzers/FunctionStartAnalyzer.java`.
It is not a SORTD strength: the analyzed image missed InsertionSort,
BubbleSort, HeapSort, PercolateDown, ExchangeSort, ShellSort, and QuickSort.
Inertia's existing binary CFG/call-target discovery and permanent 20-function
ratchet are stronger for this corpus. Compiler byte patterns may be optional
evidence, but never a required or primary discovery mechanism.

#### 8.7 Implementation order and closed gate

Implement in pipeline order, not in order of visible C prettiness:

1. IR/Alias stack memory SSA and call effects.
2. Widening PIECE/carry normalization.
3. Types/Lowering call contracts and aggregate ranges.
4. Structuring region collapse from explicit conditions.

Each owner reports the standard closed evidence counters. Before accepting a
mechanism, compare its focused functions before and after, require
`validation=passed`, no call loss, correct argument classes, and no output
farther from `SORTDEMO.C`. Then run the sidecar-free 20-function gate, strict
GCC translation-unit check, all 19 behavior harnesses, the seven MS C tiny
constructs, and `make test-pipeline PYTHON=./.venv/bin/python`.

#### 8.8 Concrete Inertia integration and migration map

The source references above are sufficient to study Ghidra, but implementation
must extend Inertia's existing proof surfaces rather than create duplicate
passes. Use this map as the handoff:

| Mechanism | Reuse or extend | Migrate or retire | First focused tests |
| --- | --- | --- | --- |
| function memory SSA | `ir/ssa_function.py`, `ir/effects.py`, `ir/address_ir.py` | extend SSA keys from scalar `IRValue` identity to exact `Address` ranges; do not add AST-local SSA | `test_x86_16_ir_ssa.py`, `test_x86_16_segment_stack_restore.py` |
| stack identity and call clobbers | `alias/state.py`, `alias/transfer.py`, `alias/callsite_stack_merge.py` | replace any later inference of stack identity from C variables | `test_x86_16_alias_state_transfer.py`, `test_x86_16_segmented_stack_alias.py` |
| split-value/carry widening | `widening/stack_widening.py`, `widening/register_widening.py`, `widening/word_projection_recomposition.py` | move semantic work out of instruction-to-C recovery in `structuring/compare32_recovery.py`; Structuring may consume the resulting wide `Condition` only | `test_x86_16_alias_api_and_widening_proof.py`, `test_x86_16_compare32_recovery.py` |
| function contracts | `lowering/stack_prototype_materialization.py`, `lowering/callee_argument_interface.py`, `lowering/return_type_evidence.py` | remove prototype discovery/reconciliation from `decompiler_postprocess.py` and `decompiler_postprocess_stage.py` as equivalent typed consumers become available earlier | `test_x86_16_stack_prototype_promotion.py`, `test_x86_16_return_type_evidence.py`, `test_x86_16_validation_call_argument_sources.py` |
| aggregate ranges | `lowering/stack_aggregate_objects.py`, `lowering/object_lowering.py`, `type_equivalence_classes.py`, `type_array_matching.py` | replace Capstone-derived aggregate facts with IR/Alias range facts; postprocess may replay an accepted type but may not discover it | `test_x86_16_stack_aggregate_objects.py`, `test_x86_16_sortd_indexed_aggregate_regression.py` |
| region structuring | `structuring/loop_recovery.py`, `structuring/control_flow.py`, `structuring/condition_lowering.py`, `structuring/typed_switch_seqnode.py` | retire direct assembly-shape semantic recovery as typed CFG regions cover each case | `test_x86_16_loop_recovery.py`, `test_x86_16_structuring_switch.py`, `test_x86_16_typed_switch_seqnode.py` |

The migration rule is strict: first make the earlier typed producer pass the
existing positive and refusal tests, then switch one downstream consumer to
that contract, and only then remove the superseded late producer. Do not keep
two semantic authorities active for the same fact.

#### 8.9 The key Ghidra lesson is iteration, not one pass

Ghidra's quality comes partly from repeatedly running mutually dependent
analyses to a fixed point. Its main action order is visible in
`coreaction.cc:5560-5770`: Heritage runs before active parameter/return
recovery; local ranges and types are rebuilt; simplification and stack-pointer
flow run; then block structure and pointer rules run. This is why listing the
individual rules without their scheduling would be incomplete.

Inertia should use a bounded typed worklist instead of blindly repeating the
whole decompiler:

1. IR or Alias changes enqueue only affected storage ranges and callsites.
2. Accepted alias changes enqueue dependent widening candidates.
3. Accepted widening changes enqueue dependent type, contract, and condition
   facts.
4. Accepted contract/type changes enqueue affected callers, callees, and CFG
   regions.
5. Stop at a deterministic fixed point. A configured iteration limit produces
   an explicit failure with the still-changing fact identities.

The cache key for each fact must include function address, exact storage or CFG
identity, input fact versions, and analysis version. Sorted worklists and typed
status values preserve determinism across worker processes.

#### 8.10 Smallest high-impact implementation milestone

Do not start by cloning all of Ghidra's Heritage or type system. The first
vertical milestone should be one exact SS memory range flowing through the
entire owned pipeline:

1. Extend function SSA so one `SS:BP+offset` range has versioned definitions
   and phi inputs across branches.
2. Preserve that range through a call only when the typed call effect proves
   it is not clobbered or escaped.
3. Join a proven adjacent low/high pair into one wide `Value` when applicable.
4. Materialize the resulting local/argument through the existing Lowering
   consumer, with no semantic discovery in postprocess.
5. Validate its register, memory, return, and control-flow effects before and
   after rendering.

Use DrawFrame's initialized loop local as the positive SORTD case. Use an
overlapping-width stack fixture and a branch with unknown SP delta as refusal
cases. Once this vertical slice passes, generalize the same contracts to Beep
call arguments, Sleep's wide clock value, and InitBars aggregate ranges.

### 9. Direct decompilation-result comparison index

Use these links immediately before and after each implementation change. They
point to the current saved Inertia baseline, Ghidra C output, and Reko 0.12.4 C
output. The peer outputs are diagnostics, not truth: an Inertia change is an
improvement only when validation and behavior gates still pass and the result
is semantically clearer or more complete than both peers.

| Function | Inertia baseline | Ghidra result | Reko result |
| --- | --- | --- | --- |
| main | [`SORTD.default-check.dec:406`](SORTD.default-check.dec#L406) | [`FUN_1000_0010...c:4`](SORTD_decomp/FUN_1000_0010_1000_0010.c#L4) | [`SORTD_0800.c:8`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L8) |
| InitMenu | [`:1400`](SORTD.default-check.dec#L1400) | [`FUN_1000_005d...c:4`](SORTD_decomp/FUN_1000_005d_1000_005d.c#L4) | [`:38`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L38) |
| DrawFrame | [`:849`](SORTD.default-check.dec#L849) | [`FUN_1000_01db...c:2`](SORTD_decomp/FUN_1000_01db_1000_01db.c#L2) | [`:120`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L120) |
| RunMenu | [`:105`](SORTD.default-check.dec#L105) | [`FUN_1000_02cc...c:4`](SORTD_decomp/FUN_1000_02cc_1000_02cc.c#L4) | [`:159`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L159) |
| DrawTime | [`:717`](SORTD.default-check.dec#L717) | [`FUN_1000_0491...c:4`](SORTD_decomp/FUN_1000_0491_1000_0491.c#L4) | [`:336`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L336) |
| InitBars | [`:1290`](SORTD.default-check.dec#L1290) | [`FUN_1000_0554...c:4`](SORTD_decomp/FUN_1000_0554_1000_0554.c#L4) | [`:399`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L399) |
| ReInitBars | [`:472`](SORTD.default-check.dec#L472) | [`FUN_1000_0672...c:4`](SORTD_decomp/FUN_1000_0672_1000_0672.c#L4) | [`:454`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L454) |
| DrawBar | [`:338`](SORTD.default-check.dec#L338) | [`FUN_1000_06c8...c:4`](SORTD_decomp/FUN_1000_06c8_1000_06c8.c#L4) | [`:482`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L482) |
| SwapBars | [`:291`](SORTD.default-check.dec#L291) | [`FUN_1000_075b...c:2`](SORTD_decomp/FUN_1000_075b_1000_075b.c#L2) | [`:510`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L510) |
| Swaps | [`:246`](SORTD.default-check.dec#L246) | [`FUN_1000_0794...c:4`](SORTD_decomp/FUN_1000_0794_1000_0794.c#L4) | [`:540`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L540) |
| InsertionSort | [`:1136`](SORTD.default-check.dec#L1136) | missing (discovery loss) | [`:564`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L564) |
| BubbleSort | [`:637`](SORTD.default-check.dec#L637) | missing (discovery loss) | [`:619`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L619) |
| HeapSort | [`:785`](SORTD.default-check.dec#L785) | missing (discovery loss) | [`:668`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L668) |
| PercolateUp | [`:576`](SORTD.default-check.dec#L576) | [`FUN_1000_09e8...c:4`](SORTD_decomp/FUN_1000_09e8_1000_09e8.c#L4) | [`:717`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L717) |
| PercolateDown | [`:914`](SORTD.default-check.dec#L914) | missing (discovery loss) | [`:759`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L759) |
| ExchangeSort | [`:1212`](SORTD.default-check.dec#L1212) | missing (discovery loss) | [`:809`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L809) |
| ShellSort | [`:1057`](SORTD.default-check.dec#L1057) | missing (discovery loss) | [`:866`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L866) |
| QuickSort | [`:1495`](SORTD.default-check.dec#L1495) | missing (discovery loss) | [`:920`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L920) |
| Beep | [`:997`](SORTD.default-check.dec#L997) | [`FUN_1000_0e5d...c:2`](SORTD_decomp/FUN_1000_0e5d_1000_0e5d.c#L2) | [`:1060`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L1060) |
| Sleep | [`:530`](SORTD.default-check.dec#L530) | [`FUN_1000_0f18...c:2`](SORTD_decomp/FUN_1000_0f18_1000_0f18.c#L2) | [`:1092`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L1092) |

The compact peer assessment and known defects are linked at
[`NON_LIBRARY_COMPARISON.md:43`](comparisons/reko/SORTD/reko-0.12.4/NON_LIBRARY_COMPARISON.md#L43).
When a result file is regenerated, update this table in the same change because
line anchors may move.

For every focused implementation, save the new Inertia output separately and
compare the exact function against all available columns. Record in the change
notes: preserved calls and argument classes, preserved memory effects, improved
expressions/control flow/types, remaining ugliness, and validation verdict. A
peer-looking result without passing validation is a regression, not a win.
