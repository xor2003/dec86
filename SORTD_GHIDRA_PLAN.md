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

Reason: Independently valid function payloads can still form an invalid or
semantically inconsistent translation unit when declarations are concatenated.
The CLI/export owner must assemble one canonical whole-binary result without
repairing function semantics.

Definition of done:

- normal whole-binary stdout is assembled from accepted typed function
  payloads through one structured declaration table
- `./decompile.py SORTD.EXE > out.c` followed by strict GCC syntax checking has
  zero declaration/type conflicts
- every one of the 20 generated function bodies remains present and unchanged
- assembly conflicts stop the CLI with a clear stderr error and nonzero status
- direct single-function output and `--output-c-dir` artifacts remain stable
- focused export/CLI tests, Ruff `--fix`, types/docs, and architecture checks pass

Definition of failure:

- stdout contains duplicate or conflicting declarations, drops or changes a
  function body, or requires postprocess semantic repair
- an assembly conflict is hidden, emitted only as metadata, or exits successfully
- any focused CLI/export, compilation, typing, documentation, or architecture
  gate fails

### 2. Expand behavior proof beyond the sort core

Status: complete for every source-selftested non-library function.

Reason: Compilation and tail validation do not alone prove application-visible
behavior. Executing generated bodies against independently derived outcomes
catches lost calls, wrong argument classes, memory-effect drift, and incorrect
control flow.

Definition of done:

- every source-selftested application function has a generated-C harness
- required calls and value-versus-pointer argument classes are checked
- generated execution matches the source oracle's return values, memory
  effects, and expected exit code
- the default or expanded pipeline fails on missing functions, sanitizer
  failures, behavioral differences, assembly fallback, or validation failure
- no source text or name is used to recover semantics

Definition of failure:

- any source-selftested function lacks an unchanged generated-C harness or an
  expected call, return, memory effect, or exit code differs
- sanitizer, fallback, validation, or generated-function-presence failures do
  not fail the default or expanded pipeline
- source names, source text, or peer output participate in semantic recovery

Measured closure: 19/19 generated function bodies compile and execute unchanged
under ASan/UBSan against source-derived outcomes. The cases include RunMenu
Escape/dispatch behavior, DrawTime timing/sound arguments, Beep output-port
arguments, full-width ReInitBars copies, and InitMenu pointer-table traversal.
The final expanded pipeline passes 5/5 lanes. Its status parser associates
deferred canonical definitions and their declaration preludes with the exact
function record, so batch stdout cannot create false "generated C missing"
results or bypass leakage/call-contract checks.

### 3. Unify interprocedural function contracts at Types/Lowering

Status: in progress; argument storage, return-use caller-census refusal, and
typed register-return condition forms are enforced.

Reason: Definition/callsite signature disagreement is evidence that the project
has competing interprocedural truths. One binary-evidenced contract must own
parameter, return, stack-delta, signedness, and pointer/value decisions before
rendering or export.

Definition of done:

- each internal function has one binary-evidenced return/parameter contract
  shared by its definition and every callsite before export
- ignored returns become `void` only when the caller census is complete and no
  return use exists; unknown evidence refuses conversion
- signedness and pointer/value classes survive clean-worker transport
- closed evidence counters report every classified and materialized contract
- focused negative tests prove refusal on conflicting or incomplete callers

Definition of failure:

- a contract is inferred from an incomplete caller census, guessed storage, a
  function/source name, or rendered C
- definitions and callsites receive different contracts, or CLI/postprocess
  reconciles them after Lowering
- evidence counters do not close, conflict/unknown cases are silently accepted,
  or focused validation and behavior gates regress

Measured progress on 2026-08-17:

- `CalleeArgumentCountEvidence8616.closes_census` now requires every discovered
  caller to be normalized, classified, and materialized with zero failures.
- one classifiable caller plus any unclassified caller now yields `UNKNOWN`,
  and Types/Lowering refuses interface unification instead of accepting a
  transient local header; a function with no discovered callers may still use
  body-local argument evidence.
- argument-width evidence and positive-BP interface lowering consume the same
  closed-census contract rather than reconstructing a weaker verdict.
- return-use recovery now inventories every proven label/prologue alias in one
  evidence record; the CLI no longer scans aliases independently and selects a
  partial result that happens to classify as unused.
- a recursive read-modify-write consumer of `AX` now proves a used return and
  blocks `void` demotion. Only a recursive terminal `call; ret` pass-through
  cycle may be excluded, and that cycle cannot independently prove `void`.
- Capstone register-access facts distinguish a return-carrier read-modify-write
  from a pure clobber before Types/Lowering consumes the caller census.
- Semantics now owns a typed per-terminal-path return-storage state. Wide
  `DX:AX` promotion requires every entry-reachable terminal path to prove the
  pair with closed counters; one word-only path, an incomplete CFG successor,
  a stale `DX`, or an intervening non-epilogue instruction refuses promotion.
- the compatibility AX-lane projection is empty when terminal-path collection
  is incomplete, so legacy type consumers cannot infer from a successful
  subset while the typed evidence still exposes the failed census.
- negative tests cover incomplete collection, malformed cached evidence,
  incomplete `UNKNOWN` evidence, the no-caller boundary, recursive value use,
  recursive pass-through exclusion, and calls split across entry aliases.
- the exact Ultra QuickC `args` regression retains both required calls, and the
  default pipeline passes 3/3 lanes: 1,469 focused tests, 4/4 Ultra QuickC
  fixtures, and all seven MS C tiny compile/decompile/recompile/runtime cases.
- the return-use focused surface passes 103 tests; the complete changed-file
  gate passes Ruff, MyPy for seven source modules, type ratchet, architecture,
  MCP/Understand-Anything state, ownership, and 175 related tests.
- the return-storage focused surface passes 38 tests and its changed-file gate
  passes Ruff, MyPy, type ratchet, architecture, context, ownership, and 159
  related tests. A repeated default pipeline remains 3/3 green; its longest MS
  C fixture stayed within normal variance rather than adding fallback work.
- Semantics now owns complete terminal stack-cleanup evidence. Callee cleanup
  is accepted only when every entry-reachable return is classified, all five
  evidence counters close, and every return agrees on one even immediate.
- callsite summarization no longer decodes a guessed 256-byte window and trusts
  its first `ret`. Conflicting return immediates, an incomplete CFG successor,
  an indirect/bodyless branch, or malformed cleanup evidence now refuses the
  cleanup contract; a bodyless direct terminal return remains supported.
- the terminal-cleanup and downstream call-contract surface passes 155 focused
  tests. Ruff `--fix`, MyPy, type ratchet, architecture ownership, MCP/context,
  and ownership-manifest gates pass for the complete changed surface, and the
  repeated default pipeline passes all focused, Ultra QuickC, and seven MS C
  tiny compile/decompile/recompile/runtime contracts.
- Types/Lowering now owns one closed source-order argument-storage contract.
  Every proven argument carries an exact stable `SS:BP+offset` identity and
  width; physical right-to-left push order is normalized once and consumed by
  both definitions and callsite declarations. An incomplete width census
  refuses materialization instead of falling back to one local call summary.
- Mixed-width tests prove that physical `(word, dword)` pushes become source
  `(dword, word)` storage at `BP+4` and `BP+8`; zero-argument and incomplete-
  census cases close or refuse explicitly. The focused argument-contract
  surface passes 126 tests and the changed-file gate passes Ruff `--fix`,
  MyPy, type ratchet, architecture/context, ownership, and 361 selected tests.
- The repeated default pipeline passes 3/3 lanes after this contract change:
  1,469 focused tests, 4/4 Ultra QuickC fixtures, and all seven MS C tiny
  compile/decompile/recompile/runtime cases. The promoted QuickC `args`
  fixture also passed three concurrent deterministic stress runs.
- Semantics now publishes one exact terminal return-storage class only after
  every reachable path agrees. `AL`, `AH`, `AX`, and `DX:AX` remain distinct;
  mixed or incomplete paths have no scalar projection. Calling-convention and
  all active return-type/value consumers use this exact contract, so a wide
  `DX:AX` result can no longer be silently narrowed to `AX` through the legacy
  lane-set compatibility view.
- Exact-storage negatives cover mixed paths, incomplete collection, and both
  direct and terminal-call attempts to type `DX:AX` as a word. The focused
  surface passes 56 tests; its changed-file gate passes Ruff `--fix`, MyPy for
  eight source modules, type/docs ratchets, architecture/context, ownership,
  and 230 selected tests. The default pipeline remains 3/3 green.

Remaining task-3 work: conditional, indexed, indirect, stack, overlapping, and
multi-output live-out storage plus stack effects beyond closed terminal `ret`
cleanup. Exact stable direct DS/ES must-write outputs and their caller-side
condition uses now enter the same storage contract without being misprojected
as scalar C returns. Input trials, exact reaching-definition binding,
scalar/pointer register outputs, all strict/non-strict/equality `DX:AX`
condition forms, recursive return pass-through propagation, SCC-wide
production publication, and one transaction that updates definitions and
callsites are implemented.

### 4. Keep discovery and semantic-loss ratchets permanent

Status: complete for the current 20-function baseline.

Reason: The known-good 20-function corpus is a durable completeness boundary.
Permanent discovery, materialization, fallback, and tiny-example ratchets stop
later cleanup or performance work from silently dropping code or effects.

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

Definition of failure:

- any expected application function disappears, aliases nondeterministically,
  falls back to assembly/details, times out, or fails validation
- a classified fact is not materialized and the pipeline still succeeds
- any Beep, DrawFrame, Sleep, RunMenu, or MS C tiny regression escapes the
  enforced pipeline

### 5. Improve readability only from proof

Status: pending after recompilation and behavior gates.

Reason: Stack locals, aggregates, signed conditions, and object names are useful
only when they are projections of accepted Alias, Widening, Types, and
Structuring facts. Readability must expose proof, not manufacture semantics.

Definition of done:

- proven stack slots render as locals/arguments and proven aggregate layouts
  render as arrays/structs without conflicting declarations
- explicit signed conditions survive rendering and recompilation
- unresolved segment/global identity stays explicit rather than guessed
- numeric function names remain valid when no symbol evidence exists
- every readability change keeps validation and behavior gates green

Definition of failure:

- output becomes prettier by guessing a local, type, object, condition, name,
  call argument, or control-flow shape
- unresolved segmented identity is hidden or distinct address spaces are merged
- recompilation, validation, call preservation, or behavior is worse than the
  recorded baseline

### 6. Profile before further parallelization

Status: primary N-1 execution complete; fallback work deferred.

Reason: The validated primary path already uses available CPUs, while mutable
fallback rebuilds may share project state and multiply memory. Profiling and
isolation evidence are required before concurrency can safely reduce wall time.

Definition of done:

- deterministic function order and output hashes are unchanged across repeats
- aggregate worker RSS stays below 2 GiB with a documented worker cap
- pass-level profiles identify CPU-bound owners before adding concurrency
- mutable fallback rebuilds remain serial until isolated-state and OOM tests
  prove bounded parallel execution

Definition of failure:

- concurrency is added without pass-level timing, isolated-state tests, and
  aggregate memory measurements
- output order or hashes become nondeterministic, worker RSS exceeds the 2 GiB
  budget, or a worker failure is lost
- measured wall time does not improve materially or semantic gates regress

### 7. Borrow Reko's proven quality mechanisms without its unsafe fallbacks

Status: pending. The comparison artifact is
`comparisons/reko/SORTD/reko-0.12.4/NON_LIBRARY_COMPARISON.md`.

Reason: Reko demonstrates useful placement and iteration strategies for wide
values, call storage, and aggregate typing, but its invalid placeholders and
known SORTD losses violate Inertia's evidence contract. Borrowing must be
mechanism-specific and independently implemented at Inertia's owning layers.

Definition of done:

- tasks 7.1 through 7.4 satisfy their individual DoD and refusal cases
- independently implemented mechanisms improve the named SORTD functions while
  preserving validation, calls, behavior, recompilation, and layer ownership
- licensing review confirms that no incompatible Reko implementation was copied

Definition of failure:

- Reko output, source names, addresses, rendered text, or invalid placeholders
  become semantic evidence or recovery fallbacks
- an implementation copies incompatible code, bypasses Inertia's typed
  contracts, or introduces semantic recovery in Rewrite/CLI/export
- any closed gate in task 7.4 fails or a peer-looking result is accepted over
  binary validation

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

Reason: Split-word values become recoverable at several points after Alias,
propagation, and call summaries. Re-running only affected Widening candidates
can recover complete arithmetic and conditions without a late AST heuristic.

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

Definition of done:

- all listed Sleep, ReInitBars, and Beep acceptance cases pass with closed
  Widening evidence counters and `validation=passed`
- affected-candidate scheduling is deterministic and avoids whole-AST rescans
- mismatched carrier, carry/borrow, segment, alias, definition, or CFG evidence
  produces an explicit refusal and preserves the lower representation

Definition of failure:

- low/high halves are joined by adjacency, register shape, or rendered syntax
  without exact identity and carry/borrow provenance
- widening is introduced in Structuring, Rewrite, CLI, or export
- any call argument, memory effect, comparison, validation verdict, or negative
  refusal case regresses

#### 7.2 Build one interprocedural storage contract, then bind calls exactly

Reason: The largest remaining semantic risk is disagreement between function
definitions and individual callsites. A whole-program storage contract makes
every emitted argument and return traceable to its exact reaching definition.

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

Definition of done:

- every internal function has one deterministic SCC-aware contract consumed by
  its definition and all callsites before C emission
- all Beep, SwapBars, QuickSort, and incomplete-census acceptance cases pass,
  including exact value-versus-pointer classes and recursive argument order
- contract evidence counters close and transport preserves typed storage
  identities across clean workers

Definition of failure:

- an argument or return is synthesized, selected from an arbitrary stack slot,
  repaired in export, or accepted without reaching-definition proof
- recursive or conflicting caller evidence is ignored, resolved by order, or
  converges nondeterministically
- any required call/argument is lost or an unknown/conflict does not refuse

#### 7.3 Infer arrays and small structures from alias-equivalent accesses

Reason: Proven aggregate identities can replace noisy segmented accesses and
whole-object byte traffic with readable arrays and fields. The transformation
is valid only after Alias, Widening, and bounded range evidence agree.

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

Definition of done:

- InitBars, `abarPerm`, `abarWork`, Swaps, and ReInitBars satisfy all listed
  array/field/copy acceptance cases with every observed byte accounted for
- the accepted aggregate contract is owned by Types/Lowering and its final
  rendering introduces no new semantic fact
- all cross-segment, inconsistent-stride, overlap, and unbounded-index fixtures
  refuse materialization and retain explicit accesses

Definition of failure:

- arrays or structures are inferred from proximity, source shape, peer output,
  default element counts, or accesses from different alias objects/spaces
- overlapping or unbounded accesses are hidden by a guessed aggregate
- pointer/value classes, copy widths, validation, or behavior regress

#### 7.4 Closed evidence and gates

Reason: Mechanism-specific improvements are not durable unless every fact is
accounted for and the complete binary, compile, behavior, tiny-example, and
architecture gates enforce the same contract.

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

Definition of failure:

- evidence counters are missing/inconsistent, or classified facts can reach
  zero materialization without failing their owning stage
- any focused function, 20-function corpus, GCC, behavior-harness, MS C tiny,
  architecture, typing, documentation, or test-pipeline gate fails
- recovery depends on source/peer text, names, address allowlists, rendered C,
  or a late semantic repair layer

### 8. Borrow Ghidra's strongest mechanisms at their owning layers

Status: implementation in progress from the IR/Alias vertical milestone.

Reason: Ghidra's strongest results come from memory SSA, storage trials, typed
range propagation, split-value normalization, conservative CFG collapse, and
bounded iteration. Inertia needs equivalent capabilities while retaining its
stricter segmented-memory and validation contracts.

Definition of done:

- tasks 8.1 through 8.10 meet their individual DoD in pipeline order
- each mechanism has one authoritative typed owner and replaces, rather than
  duplicates, any superseded late semantic producer
- the full task 8.7 closed gate passes and known Ghidra SORTD errors remain
  explicit negative fixtures

Definition of failure:

- Ghidra output is treated as truth, known Ghidra guesses are reproduced, or
  semantic work lands later than its owning layer
- two active passes own the same fact, or migration removes durable behavior
  before its typed replacement and tests exist
- licensing review is skipped for copied/adapted code or any closed gate fails

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

Status: in progress; exact `SS:BP+offset` ranges now partition into canonical
byte cells with versioned definitions and joins through IR and Alias. Safe
exact ranges still reach the first Lowering materializer, while composed-view
object materialization, Widening, and multi-function generalization remain.

Reason: Early conversion of stack storage into loosely related C temporaries
loses definition, join, width, escape, and call-clobber evidence. Exact SS range
SSA is required before a stack range can safely become one local or argument.

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

Measured progress on 2026-08-21:

- `IRCallStackEffect8616` now applies stack deltas to the coordinate they
  actually move. A complete, known callee-cleanup delta may preserve an
  explicitly preserved `SS:BP+offset` or entry-SP range, while a nonzero delta
  still refuses a current-`SP` range and an unknown delta refuses every range.
- the Semantics callsite-summary producer is covered end to end through
  function memory SSA for a value argument cleaned by the callee. Positive BP,
  nonzero-SP, and unknown-delta cases prevent either blanket refusal or unsafe
  preservation.
- 33 focused IR/Semantics/Alias/Lowering tests pass. Sidecar-free DrawFrame,
  DrawTime, and InitMenu compile/validation regressions pass unchanged.
  `quality-dev` passes Ruff `--fix`, MyPy, mypyc smoke, architecture/context/
  ownership checks, 1,523 tests, and all three quality comparisons. The
  required pipeline passes its focused, Ultra QuickC, and seven MS C tiny
  compile/run/decompile/recompile/runtime lanes.
- IR now partitions every accepted exact BP access by all observed byte
  boundaries. Stores define each canonical cell, loads retain ordered reaching
  slices, and joins create one phi per changed cell while the original access
  remains the accounting unit. Exact one-cell accesses retain the compatible
  versioned-address path.
- Call effects are checked against each original access range. If one escaped
  or unpreserved view is refused, its entire connected overlap component is
  refused, preventing a partially accepted neighbor from consuming an ignored
  store.
- Alias projects complete multi-cell accesses as typed composed views, rechecks
  that every slice is contained by the original storage identity, and keeps
  exact one-cell accesses on the existing fact path. Malformed views and
  inconsistent overlap relations have typed refusals.
- Lowering does not guess one C object for a composed view. It emits an explicit
  `COMPOSED_BYTE_VIEW_UNPROVEN` outcome for each such access, while preserving
  the existing exact-range materializer. Safe split/merge object
  materialization remains the next part of this task.
- The byte-view surface passes 32 focused tests plus sidecar-free DrawFrame,
  DrawTime, and InitMenu compilation/validation regressions.
  `quality-dev` passes Ruff `--fix`, strict MyPy, the 38-module mypyc smoke,
  architecture/context/ownership gates, 1,523 tests, and all three quality
  comparisons. The mandatory seven-worker pipeline passes all three lanes,
  including Ultra QuickC and all seven MS C tiny compile/run/decompile/
  recompile/decompiled-run cases.

This should remove Ghidra-like stack setup temporaries from DrawFrame,
DrawTime, and InitMenu without moving stack recovery into Rewrite. Negative
tests must cover overlapping locals, SP changes on one branch, escaped stack
addresses, and DS/SS offset collisions.

Definition of done:

- exact SS ranges have versioned definitions, phi joins, byte-accurate overlap
  handling, and typed call delta/clobber effects in IR/Alias
- DrawFrame, DrawTime, and InitMenu improve through Lowering-owned locals while
  every listed overlap/SP/escape/segment fixture refuses unsafe materialization
- evidence counters close and validation, behavior, and recompilation remain
  green

Definition of failure:

- stack identity is reconstructed from rendered C, variable names, or raw
  numeric proximity, or DS and SS storage are conflated
- an unknown stack delta, overlap, escape, or clobber is silently ignored
- locals are discovered in Structuring/Rewrite or any required effect regresses

#### 8.2 Recover call and return contracts from storage trials

Status: in progress. Exact input storage-trial collection, `DX:AX`
direct-global return materialization, replay-safe call accounting, exact
final-callsite multiplicity validation, deterministic return/live-out trial
collection, signed/unsigned strict and non-strict `DX:AX` ordering use typing,
sign-insensitive equality/inequality use typing, recursive pass-through
propagation, production SCC publication, and atomic callee plus callsite type
application are complete. Exact direct DS/ES must-write live-outs with one
unclobbered caller condition use are implemented; broader memory live-outs and
stack effects remain.

Reason: Calls and returns cross function boundaries where local inference is
insufficient. Typed storage trials allow a complete caller census to prove
inputs, outputs, stack delta, and split returns without guessed signatures.

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

Measured progress on 2026-08-20:

- direct-global `DX:AX` stores now consume or reuse one exact typed call across
  same-group, cross-group, and replayed C-AST projections; cleanup refuses to
  remove a standalone call unless the matching canonical assignment is active
- synthesized value calls retain their instruction identity, allowing the
  existing callsite declaration owner to infer the proven return class
- callee arity no longer aliases unrelated linear code targets by low 16 bits;
  explicit project aliases remain the only rebasing authority
- an incomplete whole-program arity census emits an honest unprototyped
  declaration with the proven return type instead of guessing parameters
- isolated sidecar-free ReInitBars and DrawTime regressions pass strict GCC,
  `validation=passed`, whole-tail validation, and exact one-call assertions
- Tail Validation now owns a typed callsite-multiplicity report with closed
  evidence counters. It counts only final C calls carrying an exact required
  machine instruction identity; target names, rendered C, and untagged calls
  are not treated as multiplicity proof
- an assignment-RHS call plus a standalone call with the same `ins_addr` now
  fails the absolute final semantic guard and persists as a
  `callsite_multiplicity` snapshot failure, while two distinct machine
  callsites targeting the same callee pass
- the validation cache contract was versioned, and the new module/test are in
  the promoted Makefile, architecture, and ownership inventories. Ruff
  `--fix`, MyPy, types/docs, architecture/context/ownership, 490 selected
  changed-surface tests, and both isolated sidecar-free SORTD regressions pass
- typed IR analysis now proves the machine-BP to angr entry-SP coordinate
  before stack-memory SSA Lowering. Unknown coordinates refuse local
  materialization, positive BP ranges remain typed storage-trial refusals, and
  exact materialization retires only the obsolete entry-SP declaration
  projection. Width-to-type Lowering now maps proven one-, two-, and four-byte
  scalar ranges exactly instead of ignoring width
- the three stack-annotation regressions now emit one `BP-2` `unsigned short`
  local with the requested name and no stale byte, dword, or split-argument
  declaration. Their strengthened smoke tests pass; 152 related tests and the
  512-test changed-surface gate pass with Ruff `--fix`, MyPy, types/docs,
  architecture/context, and ownership checks
- the `whsum` declaration failure no longer reproduces: the existing
  Types/Lowering owner consumes the complete caller-width census and emits
  `void sub_105e6(unsigned short a0, unsigned short a1);`; the CLI only replays
  that typed contract before rendering. Tail validation passes and C11 syntax
  checking with implicit declarations promoted to errors succeeds
- the fixture now requires that source-backed prototype in its generated-C
  contract, so the default pipeline cannot pass if the declaration disappears
- the required seven-worker default `make test-pipeline` passes all three
  lanes: 1,486 focused tests, four validated QuickC fixtures, and all seven MS
  C tiny compile/decompile/recompile/runtime constructs. The measured lane
  times on the final edited-state run were 79.702s, 101.846s, and 174.758s
  respectively; only the focused lane exceeded its 30s advisory budget
- typed Types/Lowering contracts now retain exact stack/register identity,
  width, SSA reaching definition and use, signedness, pointer/value class,
  split-return provenance, stack delta, and the mandatory five evidence
  counters. A deterministic SCC solver closes only complete callsite censuses
  and retains typed refusal reasons for every unresolved or conflicting set
- focused QuickSort and mutual-recursion fixtures converge independently of
  input order; Beep-like incomplete censuses and PercolateUp-like
  pointer-to-value changes refuse, and split `DX:AX` outputs require one shared
  provenance before joining
- one atomic transaction contract now represents an accepted callee contract
  with every proof-bearing callsite binding. Focused tests prove that omitted
  callsites cannot be consumed, but the main Types/Lowering path does not yet
  publish the SCC result to production declaration and prototype consumers
- the direct-caller census now retains one typed origin record per callsite:
  evidence project, exact caller function address, machine callsite address,
  and typed summary. Argument-count and width evidence derive from that same
  census, so the production trial collector no longer has to guess which
  function or rebased project owns a summary. The extraction also reduced the
  oversized argument-count module from 392 to 177 lines; Ruff `--fix`, MyPy,
  architecture/context/ownership gates, and 453 selected tests pass
- a Types/Lowering reaching-definition resolver now verifies the exact typed
  CALL use and binds immediate, `SS:BP` value, stable `DS`/`ES` value, and
  `SS:BP` address arguments to program-owned SSA definitions. Split global
  loads retain byte-accurate memory pieces; a claimed BP address must trace
  through local SSA aliases to the matching BP origin, while missing,
  conflicting, and call-output facts refuse with typed reasons and closed
  evidence counters. All four production modules remain below 350 lines; seven
  real-lifter regressions and the 508-test ownership-expanded changed-surface
  gate pass with Ruff `--fix`, MyPy, types/docs, architecture/context, and
  ownership checks. `quality-dev` passes, and the default seven-worker pipeline
  passes 1,502 focused tests, four validated QuickC fixtures, and all seven MS
  C tiny compile/decompile/recompile/runtime constructs; lane times were
  37.270s, 63.146s, and 108.145s
- Ruff `--fix`, MyPy, ownership/header guards, architecture/context checks,
  115 related tests, and the 655-test changed-surface gate pass. The default
  seven-worker pipeline also passes 1,495 focused tests, four QuickC fixtures,
  and all seven MS C tiny compile/decompile/recompile/runtime constructs; lane
  times were 36.554s, 69.144s, and 107.550s
- the IR layer now owns a lazy, exact-function SSA registry so every retained
  caller origin resolves against one program-owned dataflow artifact; missing
  function bounds, IR refusal, and SSA refusal are typed failures, and only
  proven artifacts are cached
- the production Types/Lowering input collector joins the closed caller census,
  exact source-order `SS:BP+offset` callee storage, SSA reaching definitions,
  condition signedness, and binary pointer-use evidence. It materializes
  immediate, stack value/address, and split `DS`/`ES` global trials with exact
  source and destination pieces; pointer signedness is explicitly not
  applicable rather than guessed
- duplicate machine callsites, unknown stack delta, missing caller SSA,
  reaching-definition conflicts, piece mismatches, and unknown or conflicting
  signedness/value classes refuse with typed reasons and closed five-field
  counters. Seven real-lifter tests cover positive and refusal behavior, and
  the focused interprocedural surface passes 20 tests
- the changed-surface gate passes Ruff `--fix`, MyPy for ten source files,
  types/docs and dot-access ratchets, architecture/context/ownership checks,
  and 540 selected tests. `quality-dev` passes, including the 38-module mypyc
  import smoke and three no-regression quality comparisons. The required
  seven-worker `make test-pipeline` passes 1,509 focused tests and all six
  selected tiny MS C compile/run/decompile/recompile/decompiled-run programs
- the caller return-use census now retains one typed fact per direct machine
  call: exact caller function, callsite, witness instruction, use kind, verdict,
  and recursive-pass-through exclusion. Transitive wrapper observations update
  only the verdict and preserve the local return witness; unknown paths remain
  visible failures. The owner was extracted from the oversized callsite summary
  into a 96-line recovery-metadata contract while preserving public re-exports
- five focused exact-fact tests, all 14 caller-use regressions, 145 broader
  caller-evidence consumer tests, and the 456-test changed-file gate pass with
  Ruff `--fix`, MyPy, types/docs, architecture/context, and ownership checks
- return definitions now distinguish ordinary SSA/constant values from typed
  `CALL_OUTPUT` producers. An observed return use binds only to the unique typed
  CALL at the exact machine callsite and an exact accepted target address; it
  never fabricates an SSA version or aliases targets by their low 16 bits
- AX and split DX:AX definitions retain exact register storage and one shared,
  deterministic call provenance. Unknown/unobserved uses, missing callsites,
  target mismatches, invalid storage, and duplicate pieces are typed atomic
  refusals. Return trials now require `CALL_OUTPUT` at their own callsite
- seven real-lifter producer tests and six updated SCC/solver tests pass. The
  463-test changed-file gate also passes Ruff `--fix`, MyPy, types/docs,
  architecture/context/ownership, and confirms Understand-Anything automatic
  updates remain disabled
- a dedicated Types/Lowering classifier now joins one exact caller return-use
  witness, Alias-owned AX/AL/AH storage identity, and canonical `ConditionIR`.
  Signed ordering proves a signed scalar return; unsigned ordering retains its
  proven unsigned interpretation but refuses the still-ambiguous pointer/value
  class, while equality, missing witnesses, split carriers, contradictory
  identities, and duplicate semantic projections remain typed atomic refusals
- the classifier retains its exact condition and all five evidence counters.
  Ten focused classification tests include real lifted signed/unsigned/equality
  branches and the complete refusal matrix. Ruff `--fix`, MyPy, types/docs,
  architecture/context/ownership, and the 473-test changed-file gate pass;
  Understand-Anything automatic updates remain disabled
- the Alias layer now owns exact full-word SP/BP/SI/DI domains and angr register
  offsets in addition to AX/BX/CX/DX. This lets Types/Lowering identify legal
  8086 address carriers without creating a competing register map
- a dedicated Types/Lowering classifier now starts at one exact, versionless AX
  `CALL_OUTPUT`, follows only versioned equal-width semantic MOVs in the exact
  witness block, and proves pointer class only when that lineage reaches one
  stable, segment-proven, single-base DS/ES/SS LOAD or STORE. Pointer
  signedness is explicitly `NOT_APPLICABLE`
- mixed address bases, provisional addresses, carrier clobbers, absent
  dereferences, duplicate witnesses, versioned or mismatched call outputs, and
  caller identity mismatches remain typed refusals. The shared result/evidence
  contract was extracted so the scalar classifier is 254 lines, the contract
  is 147 lines, and the pointer classifier is 342 lines
- eleven focused pointer tests cover real-lifter positive and refusal paths;
  the ownership-expanded changed-file gate passes Ruff `--fix`, MyPy for six
  selected source files, types/docs, architecture/context/ownership checks,
  and 509 selected tests. Understand-Anything automatic updates remain
  disabled. The required full pipeline was not rerun for this bounded
  same-block prerequisite
- the first cross-block probe exposed an earlier IR defect: real pyvex
  `Exit.dst` values are direct constants, while VEX import accepted only
  wrapped constant expressions. Conditional blocks therefore retained only
  one of their taken/fallthrough successors, making later SSA blocks appear
  disconnected. VEX import now normalizes both boundary forms before building
  `IRBlock.successor_addrs`; it does not synthesize edges in Types/Lowering
- a dedicated real-lifter CFG regression proves that both successors survive
  and that function SSA records the complete predecessor join. Thirty-five
  focused IR/SSA tests and the 91-test ownership-expanded changed-file gate
  pass Ruff `--fix`, MyPy, types/docs, architecture/context/ownership checks,
  and the disabled Understand-Anything auto-update guard
- returned-pointer lineage now crosses only authoritative function-SSA CFG
  edges. At a join, every predecessor must retain the same Alias-owned
  full-word carrier domain and any register phi must contain the exact sorted
  `(source_block, value)` inputs produced by those predecessors
- direct edges and compatible all-predecessor phi joins retain complete typed
  edge and phi evidence through the final stable DS/ES/SS dereference. A
  clobbered predecessor, incomplete CFG, corrupted phi, ambiguous/provisional
  address, or reachable cycle refuses with a stable typed reason; cycles are
  not guessed through an implicit fixed point
- block-local transfer and CFG/phi convergence have separate Types/Lowering
  owners. The pointer classifier was reduced from 342 to 145 lines; its 244-line
  block-transfer and 298-line flow modules remain below the 350-line ratchet
- six new real-lifter CFG tests cover direct transfer, compatible phi input,
  clobbered joins, corrupted phi evidence, incomplete CFG, and cycle refusal.
  All 18 focused pointer/CFG tests pass, and the ownership-expanded changed-file
  gate passes Ruff `--fix`, MyPy for nine production files, types/docs,
  architecture/context/ownership checks, and 527 selected tests in 52.38s.
  Understand-Anything automatic updates remain disabled. The required full
  pipeline was not rerun for this bounded pointer-flow increment
- deterministic return/live-out collection now joins the complete input
  callsite census with Semantics-owned terminal carrier proof, exact caller
  return-use facts, program-owned SSA, versionless `CALL_OUTPUT` definitions,
  and the existing scalar-condition or segmented-pointer classifiers. Proven
  `AX` scalar and pointer uses become solver-ready return trials; closed unused
  returns preserve their callsites with no invented output
- machine instruction addresses are not assumed to identify one SSA
  instruction. Scalar trials require one direct Alias-matching register read,
  while pointer trials consume the exact alias step already retained by the
  pointer-flow proof. Corrupt censuses, exact function/target mismatches,
  unknown terminal storage, unsupported use kinds, and unproven `DX:AX` use
  remain typed refusals
- the collector, per-callsite materializer, and typed result contracts are
  separate Types/Lowering owners at 291, 339, and 90 lines. The SCC solver now
  refuses an empty incomplete callsite set instead of raising `IndexError`.
  Six real-lifter collection tests, all 53 focused return/SCC tests, and the
  68-test ownership-expanded changed-surface gate pass with Ruff `--fix`,
  MyPy, types/docs, architecture/context, and ownership checks. Understand-
  Anything automatic updates remain disabled
- a dedicated 323-line condition/CFG selector and 256-line split classifier
  now prove non-strict signed or unsigned lexicographic `DX:AX` comparisons.
  The proof retains the three canonical conditions, exact SSA CFG edges,
  control-only trampoline blocks, both Alias-owned storage pieces, and distinct
  AX/DX use instructions before creating one shared-provenance output trial
- incomplete AX-only evidence, semantically active trampolines, non-adjacent
  comparison pieces, competing chains, and broken CFG paths remain typed
  refusals. One real-lifter integration regression and three direct selector
  tests cover the acceptance and dangerous refusal boundaries
- all 57 focused return/SCC tests pass. The ownership-expanded changed-file
  gate passes Ruff `--fix`, MyPy for ten production modules, types/docs,
  architecture/context/ownership checks, and 500 selected tests. Understand-
  Anything automatic updates remain disabled; the required full semantic
  pipeline was not rerun for this bounded split-return increment
- Semantics now retains an exact direct target, terminal return instruction,
  and CFG block path for each caller-selected call-result pass-through. The
  closed evidence census refuses active post-call effects, indirect calls,
  ambiguous CFGs, duplicate candidates, and missing identities; four focused
  pass-through tests and the existing terminal-call tests cover these bounds
- Types/Lowering now lowers each proven recursive pass-through into a deferred
  trial retaining the exact SSA `CALL`, target, terminal machine return, and
  CFG path without inventing storage, signedness, or a pointer/value class. A
  recursion-only trial remains complete collection evidence, but the solver
  refuses it as `PASSTHROUGH_OUTPUT_UNRESOLVED` instead of accepting an empty
  output contract. Three real-lifter tests cover the positive identity join,
  witness mismatch, and mandatory no-seed refusal
- the SCC solver now advances a non-empty, otherwise valid direct output seed
  through deferred recursive pass-throughs as an explicit fixed-point state.
  It never treats an empty/void shape as a seed, and recursion-only evidence
  still refuses as `PASSTHROUGH_OUTPUT_UNRESOLVED`
- accepted callsite bindings retain the exact deferred `CALL`, target,
  terminal return, and CFG-path proof beside the shared function output slots;
  no synthetic RET SSA read or export-time signature repair is introduced. A
  callsite carrying both direct-return and pass-through evidence is a typed
  `CALLSITE_SET_CONFLICT`
- the single-function join was extracted into a 340-line Types/Lowering owner,
  reducing the SCC solver from 350 to 196 lines. All 18 focused return/SCC
  tests pass, and the ownership-expanded changed-file gate passes Ruff
  `--fix`, MyPy for five production files, types/docs,
  architecture/context/ownership checks, and 505 selected tests. Understand-
  Anything automatic updates remain disabled
- a 330-line production Types/Lowering lifecycle owner now collects the current
  function's closed input and return trials, replaces that function in the
  immutable sorted program trial payload, resolves every retained SCC, and
  publishes the complete result in one project assignment before prototype and
  declaration consumers run. The atomic payload now retains both source trials
  and their accepted/refused resolutions
- incomplete input or return collection leaves the preceding atomic payload
  unchanged. A complete solver conflict is published as a typed refusal, and
  both definition-width and callsite-declaration consumers refuse to fall
  through that known conflict to older heuristic evidence
- production publication/replay, incomplete-collection preservation, typed
  conflict publication, and refusal-aware declaration tests pass. The focused
  interprocedural surface passes 32 tests; the ownership-expanded gate passes
  Ruff `--fix`, MyPy for eight production files, types/docs,
  architecture/context/ownership checks, and 663 selected tests. Understand-
  Anything automatic updates remain disabled
- one shared Types/Lowering adapter now projects accepted scalar storage widths
  and signedness to exact angr `SimType` objects and preserves proven 16-bit
  near-pointer pointee types. Empty output sets remain unproven rather than
  being guessed as `void`; multiple logical outputs and unsupported widths are
  typed refusals
- prototype preflight verifies exact source-order `SS:BP` storage, C argument
  identity and width, pointer pointee coherence, and the accepted output shape
  before any mutation. The application transaction then updates C arguments,
  the callee prototype, function metadata, and the callsite return declaration
  together; a published typed refusal blocks older width reconciliation
- focused tests prove scalar width/signedness projection, `DX:AX` long return
  projection, near-pointer preservation, no partial mutation on refusal,
  lifecycle ordering, and one identical return type at the callee and callsite.
  The 73-test integrated surface, Ruff `--fix`, MyPy, architecture/context and
  ownership guards, and `quality-dev` including the 38-module mypyc smoke pass
- one typed decision-graph owner now proves signed and unsigned strict and
  non-strict ordering plus equality and inequality from exact Alias-owned
  `DX:AX` pieces, canonical `ConditionIR`, authoritative function-SSA edges,
  common sinks, and refusal-free control-only trampolines. The prior condition
  module is a 23-line compatibility facade; the authoritative owner remains
  below the 350-line ratchet
- equality/inequality trials retain `SIGN_INSENSITIVE` rather than claiming
  source signedness. The shared SimType adapter uses a canonical unsigned C
  projection that preserves all proven bits while the typed trial remains the
  authoritative sign interpretation
- real-lifter tests cover signed and unsigned strict comparisons and equality/
  inequality, while malformed sink topology and active trampoline paths refuse
  explicitly. The integrated return/type surface passes 83 tests
- the complete edited-state `quality-dev` gate passes Ruff `--fix`, MyPy for 65
  source files, the 38-module mypyc compile/import smoke, architecture/context/
  ownership checks, 1,523 fast-pipeline tests, and all three decompilation
  quality comparisons
- the required seven-worker default pipeline passes 3/3 lanes: 1,523 focused
  tests, 4/4 validated Ultra QuickC fixtures, and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run constructs. Lane times were 37.728s,
  63.614s, and 107.548s; only the focused lane exceeded its advisory budget
- VEX STORE import now derives the direct-memory width from the resolved value,
  preserving byte stores carried through temporaries instead of defaulting the
  address and store to a word
- Semantics now classifies exact stable direct DS/ES stores as must-write only
  when every entry-reachable machine-return path writes the same byte range.
  Conditional writes, incomplete/non-return terminals, indirect aliases,
  overlapping direct ranges, and DS/ES identity conflicts refuse atomically
  with closed evidence counters
- Types/Lowering now binds one such output to the exact caller `CALL_OUTPUT`,
  follows only an authoritative unclobbered SSA CFG path, and activates a
  live-out trial only for the direct load named by canonical `ConditionIR`.
  VEX JCC replay loads do not become duplicate machine uses; absent uses remain
  inactive rather than being invented
- signed/unsigned ordering, equality, and zero-use evidence retain exact
  storage, callsite, definition, condition, and signedness. Intervening direct
  clobbers become `NOT_REACHED`; indirect aliases, calls, cycles, incomplete
  CFG, overlaps, target mismatch, conditional callee writes, and conflicting
  signedness remain typed refusals
- accepted memory outputs use the distinct `LIVE_OUT` role in the existing SCC
  contract. The C return-type adapter consumes only `RETURN`, so a memory-only
  function is not incorrectly emitted with a scalar return type
- the semantic and lowering modules have explicit architecture and test owners
  and are registered in the Makefile typed, Ruff, and focused-test ratchets.
  Ruff `--fix`, focused MyPy for the complete production surface, architecture/
  ownership checks, and 73 focused tests pass
- the edited-state `quality-dev` gate passes Ruff `--fix`, MyPy, the 38-module
  mypyc compile/import smoke, architecture/context/ownership checks, 1,523
  focused tests, and all three decompilation-quality comparisons
- the required seven-worker pipeline passes 3/3 lanes: 1,523 focused tests,
  4/4 validated Ultra QuickC fixtures, and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run constructs. Lane times were 44.760s,
  72.383s, and 137.923s
- next implementation boundary: generalize live-out evidence only when Alias
  and SSA can prove conditional, indexed, indirect, stack, overlapping, or
  multiple output storage without inferring semantics from rendering

Definition of done:

- candidate inputs/outputs retain exact storage, width, reaching-definition,
  use, signedness, and pointer/value evidence through deterministic trials
- one accepted contract is transactionally applied to the callee and every
  callsite after complete-census agreement
- PercolateUp and Beep reject the known bad transformations, while both
  QuickSort recursive edges converge with all arguments preserved

Definition of failure:

- incomplete or conflicting trials produce a guessed argument, return, stack
  delta, or export-time signature repair
- split returns are joined without shared provenance or a pointer is converted
  to a scalar value class without proof
- fixed-point order changes the contract or any required call is lost

#### 8.3 Propagate types through IR, aliases, and bounded object ranges

Reason: Type information must follow value and alias provenance across the
pipeline before memory expressions can become pointers, indexes, fields, or
aggregates. Bounded range evidence prevents useful typing from becoming shape
guessing.

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

Definition of done:

- deterministic specificity propagation is implemented across owned IR,
  aliases, calls/returns, and exact object ranges
- pointer/index/field and aggregate materialization requires proven base,
  element width, stride, bounds, segment space, and complete access coverage
- InitBars and DrawBar reject Ghidra's bad modulus, uninitialized value, default
  count, and undersized-object outcomes while positive bounded cases improve

Definition of failure:

- a default element count, numeric proximity, unlocked range, or rendered
  expression creates a pointer, array, structure, or field
- conflicting aliases, address spaces, bounds, or overlaps are merged rather
  than preserved explicitly
- accepted types diverge between IR, contracts, diagnostics, rendering, or tests

#### 8.4 Normalize split values and carry before type and structure recovery

Status: complete for the current exact direct-carrier scope. The production
pre-Lowering path computes one coherent Semantics -> Alias -> Widening artifact
for exact ADC/SBB pairs. It preserves
block-local VEX provenance, proves same-block or dominating CFG/phi flags,
retains every original byte address for adjacent DS/ES memory sources, and
refuses conflicting phi, segment, range, definition, or Alias evidence. Exact
Alias-proven stack destinations materialize through Types/Lowering as one
four-byte object. Direct 16-bit loads, byte-composed words, and exact low/high
constant pairs now remain distinct typed carriers through Widening. Ruff
`--fix`, strict MyPy, architecture/ownership checks, and 33 focused
SSA/carry/borrow tests pass. Beep and DrawTime pass their source-backed
acceptance tests. IR block ownership now removes exact overlapping VEX micro-operations
before SSA: the real Sleep function classifies and removes all ten duplicates,
leaves one producer for the call at `0x10f52`, and records zero ownership
failures. Semantics now derives one typed stack effect for every CALL and
materializes used `AX` or `DX:AX` returns as exact `CALL_OUTPUT` definitions on
unambiguous return edges before function SSA. Block-local SSA reserves entry
version zero and honors the register version captured by each VEX temporary;
this removes the prior pre-write/post-write version collision without weakening
carry proof. The 18 focused call-output, call-effect, carry-output, and SSA tests
pass, including a corrupted-version refusal. The exact `CALL_OUTPUT` producer
now projects through Alias and Widening into Types/Lowering and closes the former
Sleep and ReInitBars materialization gap.

Reason: Split carriers and carry/borrow expressions obscure the single values
needed by type propagation and explicit conditions. Widening must normalize
them while exact Alias and definition provenance is still available.

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

Definition of done:

- Widening produces typed wide values with exact low/high slice, carry/borrow,
  signedness, definition, and segment provenance before Types/Structuring
- Sleep, ReInitBars, DrawTime, and Beep pass focused positive regressions and
  closed evidence counters
- every mismatched branch/carrier/segment/definition fixture produces
  `UNKNOWN_REFUSE` and preserves the original lower representation

Definition of failure:

- split values are fused by shape, adjacency, register convention, or AST text
- semantic normalization occurs in Structuring, Rewrite, CLI, or export
- a slice, carry, memory effect, condition, or call argument changes incorrectly

Measured closure on 2026-08-21:

- IR retains one immutable `DX:AX` call-output provenance through both SSA
  pieces; Alias requires exact shared callsite, target, storage, and definition
  identity before Widening accepts the pair
- Types/Lowering joins the accepted call output, one exact four-byte `SS:BP`
  source, one exact stack destination, and every carrier instruction address;
  it creates one wide assignment only after the destination stack object exists
- Structuring may place the call and carrier statements in the same immediate
  statement group or in one exact adjacent nested `CStatements` sibling. The
  Lowering placement owner accepts only carrier-only assignment/expression
  leaves with complete address coverage; calls, unrelated effects, control-flow
  nodes, ambiguous parents, and missing coverage remain classified hard failures
- the real sidecar-free Sleep regression retains both clock calls, materializes
  the wide goal arithmetic, and passes whole-tail validation. Source-backed and
  sidecar-free ReInitBars and DrawTime regressions also pass, as does Beep's
  call/argument/validation acceptance test
- Beep's direct-address output keeps an unprototyped `Sleep()` declaration
  because that deliberately incomplete one-function caller census cannot prove
  a whole-program signature. The regression enforces this typed refusal while
  still requiring the exact four-byte call argument and behavior
- 13 focused placement/provenance tests cover same-group and nested positive
  cases, idempotence, missing source materialization, unjoined calls, mixed
  calls/effects, and ambiguous parent refusal. All edited production modules
  remain below 350 lines
- `quality-dev` passes Ruff `--fix`, MyPy for 94 source modules, the 38-module
  mypyc import smoke, architecture/context/ownership checks, 1,523 focused
  tests, and all three decompilation-quality comparisons
- the required seven-worker default pipeline passes all three lanes: 1,523
  focused tests, 4/4 validated Ultra QuickC fixtures, and all seven MS C tiny
  compile/run/decompile/recompile/decompiled-run constructs

#### 8.5 Collapse CFG regions only after conditions are explicit

Reason: Structured loops and branches are trustworthy only when their CFG
boundaries and `Condition` provenance are already explicit. Conservative region
collapse improves readability without inventing branch meaning.

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

Definition of done:

- Structuring collapses regions in deterministic sequence/condition/loop/switch
  order using only typed `Condition` objects and exact CFG topology
- RunMenu and DrawFrame improve while preserving entry, exits, backedges,
  polarity, calls, and validation
- InitMenu's bad loop-update shape is rejected and every unproven region retains
  a deterministic goto

Definition of failure:

- assembly or rendered-C shape supplies condition or loop semantics
- a prettier region changes entry/exit/backedge/polarity or hides an unresolved
  edge
- unproven control flow is guessed instead of retained explicitly

#### 8.6 Explicitly do not borrow Ghidra's function-start patterns

Reason: Ghidra's pattern-driven discovery missed seven application functions
that Inertia discovers and validates. Compiler patterns cannot replace binary
CFG/call-target evidence or weaken the permanent completeness ratchet.

Ghidra's pattern-driven discovery lives in
`Ghidra/Features/BytePatterns/src/main/java/ghidra/app/analyzers/FunctionStartAnalyzer.java`.
It is not a SORTD strength: the analyzed image missed InsertionSort,
BubbleSort, HeapSort, PercolateDown, ExchangeSort, ShellSort, and QuickSort.
Inertia's existing binary CFG/call-target discovery and permanent 20-function
ratchet are stronger for this corpus. Compiler byte patterns may be optional
evidence, but never a required or primary discovery mechanism.

Definition of done:

- binary CFG/call-target discovery remains authoritative and the sidecar-free
  20-function address ratchet passes deterministically
- any compiler pattern support is optional typed evidence with explicit
  provenance, conflicts, and refusal behavior
- fixtures prove that missing/wrong patterns cannot remove, rename, resize, or
  create a required function

Definition of failure:

- a corpus/address allowlist or compiler byte pattern becomes the primary or
  required function-discovery mechanism
- any of the seven Ghidra-missed functions disappears or needs sidecar/pattern
  evidence to survive
- pattern disagreement is silently preferred over binary CFG evidence

#### 8.7 Implementation order and closed gate

Reason: The shortest reliable path follows ownership dependencies. Earlier
storage and value facts must exist before contracts, types, and CFG structure
can consume them, and every stage needs a closed regression boundary before the
next stage expands the blast radius.

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

Definition of done:

- tasks execute in the stated IR/Alias, Widening, Types/Lowering, Structuring
  order and each stage closes its evidence counters and focused tests first
- before/after artifacts prove no call loss, correct argument classes,
  `validation=passed`, and no result farther from the source oracle
- the 20-function, GCC, 19-harness, seven-tiny-example, and test-pipeline gates
  all pass from one recorded source state

Definition of failure:

- work advances past a failed/unknown earlier owner or introduces a downstream
  repair for a missing upstream fact
- before/after evidence is absent, stale, or taken from different source states
- any required focused or full gate fails, is skipped, or is weakened

#### 8.8 Concrete Inertia integration and migration map

Reason: Existing proof surfaces must be extended instead of creating another
parallel decompiler pipeline. A concrete producer/consumer migration map keeps
one authoritative owner per fact and makes technical-debt removal enforceable.

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

Definition of done:

- every table row has an earlier typed producer, an explicitly migrated
  consumer, focused positive/refusal tests, and removal of the superseded late
  producer
- imports and architecture checks enforce the documented owner boundaries
- IR, typed contracts, consumers, diagnostics, documentation, and tests expose
  one coherent representation of each migrated concept

Definition of failure:

- old and new producers remain simultaneously authoritative or disagree
- semantic recovery is added to root compatibility, postprocess, CLI, export,
  or another layer outside the map
- a late producer is removed before its behavior survives in contracts, tests,
  and documentation

#### 8.9 The key Ghidra lesson is iteration, not one pass

Reason: Alias, widening, contracts, types, conditions, and CFG structure depend
on each other's accepted facts. A bounded typed worklist reaches the necessary
fixed point without repeatedly rebuilding the whole decompiler or losing
determinism.

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

Definition of done:

- typed dependencies enqueue only affected facts and converge to the same
  sorted fixed point across repeated and multi-process runs
- cache keys include function, exact storage/CFG identity, input versions, and
  analysis version
- iteration exhaustion reports an explicit typed failure listing still-changing
  fact identities; it never emits a partial success

Definition of failure:

- the implementation blindly repeats whole-program/AST passes or has an
  unbounded worklist
- worker count, scheduling, or cache warmth changes accepted facts or output
- iteration limits, stale cache entries, or dependency cycles silently produce
  incomplete materialization

#### 8.10 Smallest high-impact implementation milestone

Status: complete for the first exact word range, including the closed pipeline
gates. Generalization continues under 8.1 and 8.2.

Reason: One exact SS range exercised through IR, Alias, Widening, Lowering, and
validation proves the cross-layer contracts before generalizing expensive
memory SSA and interprocedural changes across the entire binary.

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

Measured progress on 2026-08-17:

- function SSA now versions exact stable `SS:BP+offset:size` LOAD/STORE ranges
  independently from scalar SSA and creates deterministic memory phi inputs at
  branch joins; serialized `IRAddress` projections retain the version
- store and phi versions are globally deterministic within the function, and
  a bounded fixed-point solver carries reaching versions through CFG edges
- overlapping byte ranges and provisional SP-relative ranges are explicit
  refusals; they remain unversioned and are counted in the five-field evidence
  loop rather than being materialized as locals
- `IRCallStackEffect8616` records net stack delta, preserved ranges, escaped
  ranges, and completeness. Unknown calls refuse range propagation; only a
  complete zero-net-delta effect that explicitly preserves and does not escape
  the exact range may carry its version through the call
- the Alias layer now projects every versioned stack LOAD, STORE, and memory
  phi through the canonical storage-identity model, preserves the exact SSA
  version and phi inputs, and carries every upstream refusal into a typed Alias
  refusal; mixed-storage phi inputs refuse instead of joining by shape
- the Alias projection runs immediately after VEX function SSA in both owned
  structuring execution paths and hard-fails if upstream evidence accounting is
  open. Fixed-point exhaustion also returns only unversioned blocks plus one
  refusal per access, never a partial SSA artifact
- the Types/Lowering adapter deduplicates exact Alias SSA versions into storage
  candidates and invokes the existing Alias-fact stack lowering consumer.
  Frame-control words, overlaps, provisional SP ranges, unknown calls, and any
  candidate that fails materialization remain typed refusals or hard failures;
  accepted ranges become real `SimStackVariable`/`CVariable` objects
- action 3 is not applicable to DrawFrame's single 16-bit loop range; no
  adjacent low/high pair is present to widen. Its refusal boundary remains
  covered by the existing exact-carrier Widening tests rather than shape fusion
- block-local IR SSA now preserves every `IRValue` provenance field while
  assigning versions, recursively versions `IRBinaryValue` operands and
  indexed-address expressions, and retains `IRCondition.width_bits`; it no
  longer drops `source_tmp`, memory-access, or index evidence needed by
  Widening
- a real sidecar-free `add ax,bx; adc dx,cx` lift proves that the exact VEX
  temporary chain from the prior flags value through the carry mask and high
  add survives SSA (`t71 -> t72 -> t73 -> t75 -> t77 -> DX`)
- every imported `WrTmp` definition now retains its numeric `source_tmp`, so
  Semantics resolves definitions without parsing `tNN` display names
- typed Semantics evidence now closes the exact low-result, final flags version,
  carry/borrow extraction, high base operation, high final operation, and all
  operand definitions for real `add/adc` and `sub/sbb` lifts. Widening consumes
  those links with canonical Alias register domains and retains both slices,
  signedness `unknown`, definitions, and carry/borrow provenance in one 32-bit
  fact; it does not inspect mnemonics, assembly, C, or AST shape
- real-lifter positive tests and mask, cross-block, result-carrier, segment, and
  source-definition refusal tests close all five evidence counters. Ruff
  `--fix`, MyPy, architecture/context/ownership gates, and 162 seven-worker
  changed-surface tests pass; all new production modules remain below 350 lines
- final acceptance passes `quality-dev` with the 38-module mypyc smoke, 1,523
  focused tests, and all three quality comparisons. The required default test
  pipeline is 3/3 green: 1,523 tests, Ultra QuickC fixtures, and all seven MS C
  tiny compile/run/decompile/recompile/decompiled-run cases; there are no
  failures or timeouts
- after this provenance repair, `quality-dev` passes Ruff `--fix`, MyPy, the
  38-module mypyc compile/import smoke, architecture/context/ownership checks,
  1,523 focused tests, and all three decompilation-quality comparisons. The
  required seven-worker pipeline passes 3/3 lanes: 1,523 focused tests, 4/4
  validated Ultra QuickC fixtures, and all seven MS C tiny build/run/decompile/
  recompile/decompiled-run constructs; lane times were 30.383s, 65.414s, and
  101.599s
- final return-type regeneration now consumes the complete caller-use census
  and exact terminal register-storage contract in Types/Lowering. `NONE` plus
  `UNUSED` removes only side-effect-free synthetic returns; AX storage is
  preserved and call/dirty return expressions hard-fail
- DrawFrame passes both source-backed and isolated sidecar-free focused checks.
  The no-sidecar result has `validation=passed`, a `void` four-argument
  signature, `char local_52[80]`, the exact loop local, all nine required calls,
  a pre-test loop, and no scalar return; whole-tail validation is clean
- immutable IR and Alias contracts are split from their 292-line and 248-line
  solvers, keeping all four new modules below 350 lines. Ruff `--fix`, MyPy,
  types/docs, architecture/context, ownership, and 506 changed-surface tests
  pass. The required pipeline is 3/3 green: 1,469 unit-focused tests, Ultra
  Quick C, and all seven MS C tiny compile/decompile/recompile/runtime cases.

Remaining milestone work: generalize the accepted wide-value and exact source-
carrier contracts to the prioritized SORTD functions. The required full
pipeline must be rerun after that function-level increment; no pair may be
fused from mnemonic or AST shape alone.

Definition of done:

- all five vertical-slice actions are implemented with one exact stack-range
  identity and no semantic discovery in postprocess
- DrawFrame's initialized loop local passes as the positive case, while
  overlapping-width and unknown-SP-delta fixtures refuse materialization
- focused before/after validation, call/memory/control-flow checks, strict GCC,
  and the required pipeline gates pass before generalization begins

Definition of failure:

- the range loses identity or provenance between layers, or a call clobber,
  overlap, phi input, or unknown SP delta is ignored
- postprocess/CLI reconstructs the local or wide value from rendered output
- generalization starts before the positive and refusal vertical-slice gates pass

### 9. Direct decompilation-result comparison index

Reason: Address-aligned, function-specific artifacts make quality changes
reviewable and prevent subjective claims based on whichever peer output looks
best. The index also records Ghidra discovery losses explicitly.

Definition of done:

- all 20 Inertia functions have current Inertia and available peer links mapped
  by binary address, with missing peer functions labeled explicitly
- each focused change records calls/argument classes, memory effects, control
  flow/types, remaining debt, and validation verdict before and after
- regenerated artifacts update line anchors in the same change and peers remain
  diagnostic inputs rather than semantic truth

Definition of failure:

- links or addresses are stale, missing, or point to a different binary/source
  state without disclosure
- a comparison omits semantic calls, memory effects, argument classes, or
  validation and reports only cosmetic similarity
- Ghidra, Reko, or `SORTDEMO.C` output is used directly as recovery evidence

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
