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

## Current Checkpoint (2026-09-01)

Current sidecar-free command:

```text
PYTHONHASHSEED=0 PYTHON_JIT=1 ./decompile.py SORTD.EXE \
  --ignore-local-sidecar-hints --no-alternate-source-c -q
```

- discovery and execution attempt all 20 non-library functions
- the strict executable-only gate emits validated C for all 20 functions with
  zero discovery failures, empty bodies, fallbacks, timeouts, or tracebacks
- generated C contains no unsupported/unknown-instruction marker and no packed
  parity, overflow, `eflags`, or `cc_op` equation
- a fresh unquiet executable-only run on 2026-08-28 completed in about 202
  seconds, used seven function workers at roughly 1.9 GB aggregate RSS, and
  reported 20/20 decompiled with whole-tail validation clean
- the untouched 723-line portable-flat translation unit passes
  `gcc -std=c11 -fsyntax-only` with no diagnostics; all Swaps callsites render
  typed `g_0B4C[...]` pointers rather than raw assembly or unsupported markers
- `sub_109e8`, DrawFrame `0x101f0`, DrawBar `0x106c8`, DrawTime `0x10498`,
  SwapBars `0x10768`, QuickSort `0x10ce0`, Beep `0x10e70`, and Sleep `0x10f38`
  pass their exact executable-only gates
- DrawBar `0x106c8` now consumes the typed machine-BP address source when
  replaying call arguments, rather than retaining a higher-scoring stale
  scalar-byte expression at the colliding entry-SP coordinate; its whole-tail
  validation passes. The same fix removes DrawFrame `0x101f0`'s call-argument
  mismatches
- DrawFrame's regenerated `mov bp, sp` GP-state carrier is consumed in
  Types/Lowering only when its owned BP write and the decoded canonical entry
  pair agree. This removes the false `inertia_ebp = ... &local_2` statement and
  the `uninitialized-read:stack-local:SS:BP-0x2:size2` failure; all source-
  required calls and loop semantics survive, whole-tail validation passes, and
  the generated function passes strict C11 syntax
- Sleep `0x10f38` passes live Tail Validation and its permanent executable-only
  gate with exactly two binary-proven clock calls, correct loop-exit ownership,
  and the exact four-byte positive-BP parameter materialized by Types/Lowering
- InitMenu `0x10060` now derives its pause guard from the exact block-local
  dword `OR` inputs, preserves both calls in the zero branch, and passes whole-
  tail validation without an unsupported condition or raw flag carrier
- InitMenu's sidecar-assisted output also drops only typed, proven-unobserved
  physical AX/EAX call-result assignments in Types/Lowering; assigned fixed
  stack probes remain owned by the existing typed frame lowering. Both the
  sidecar-free and sidecar-assisted outputs pass strict portable-C compilation
- ReInitBars `0x10678` is ratified with exactly one clock call at binary
  callsite `0x10683`; Lowering recognizes the third-party AIL tag protocol and
  removes only the duplicate carrier statement for that exact callsite
- BubbleSort `0x108d0` is ratified after Types/Lowering retained the adjacent
  unchanged global-to-stack copy
- Beep `0x10e70` is ratified after Types/Lowering
  unified machine-BP call-return storage with the projected entry-SP local;
  the existing `inp(0x61)` call and its argument are preserved unchanged, both
  control guards are correct
- byte-executed slices of typed word stack accesses retain their Alias-owned
  word identity; this closes DrawTime and QuickSort without changing the
  frontend's independently resolved byte execution contract
- caller-observed byte-return signedness is aggregated only after a complete
  Frontend callsite census. Types/Lowering now projects the proven AL return
  class into the callee prototype and final C rendering; incomplete evidence
  and prototype conflicts remain typed refusals
- the `scalar_types_io` gate retains the high-bit case
  `mix_uc(64, 0) == 128`, so a wrongly signed byte return cannot pass through
  integer promotion unnoticed. Its fresh 2026-09-01 run is green: all ten
  selected functions decompile, the translation unit recompiles, and the
  rebuilt executable exits `255`
- the current exact repository baseline is 10,137 collected, 9,944 passed,
  23 failed, and 170 skipped in 852.88 seconds with seven pytest workers. The
  exact last-failed rerun then reported 19 failed and 3 passed in 221.20
  seconds. Subsequent focused closures project 13 failures, but that count is
  not confirmed until the next complete audit
- the full-binary to exact-function project boundary now transports validated,
  immutable callee pointer-argument evidence through the existing ABI seeding
  service. HeapSort therefore emits typed `Swaps` pointers, passes Tail
  Validation and strict C11 syntax, and retains the source-required call
  argument classes without semantic recovery in CLI or Rewrite
- Swaps now remains a single three-assignment object exchange after the final
  shared-call codegen regeneration. Lowering removes only the tagged raw
  temporary load already consumed by its unique exact pointer-swap proof;
  unrelated effects and untagged ambiguity remain preserved. Stack-probe
  return-frame cleanup also precedes helper removal, and Tail Validation maps
  exact-region argument slots onto machine-BP ABI coordinates. The live
  function keeps `iSwaps += 1`, emits one `barTmp = bar1[0]`, reports
  `validation=passed`, and passes strict generated-C syntax
- a current-tree stack-object regression inverted the containment predicate and
  selected storage smaller than the requested access. Restoring the owned
  invariant `storage_size >= access_width` preserves byte views of aggregates
  and arrays and keeps wide-return low halves distinct; all 236 segmented
  runtime lowering tests pass
- accepted results are cached and refused functions are revalidated

The validation-clean loop/control-flow family is now closed. ReInitBars,
BubbleSort, ExchangeSort, and PercolateUp pass their live function regressions
with `validation=passed`; the four-test live lane passed in 47.44 seconds and
the changed structuring/Condition-IR surface passed 127 tests. Storage identity
remains in Condition IR, status-flag liveness remains in IR, and loop shape
remains in Structuring. CLI changes only preserve proven function names and
persist already accepted retry-lane C artifacts.

The accepted-payload CMP16 defect is closed. Widening copy propagation had
propagated `mask = 0` across conditional `mask |= bit` updates because it did
not invalidate inherited definitions at a branch join. Widening now refuses
that stale continuation state. Structuring return-chain integrity also consumes
the mask-accumulator return fingerprint, so a later pass cannot replace the
proven return before Tail Validation snapshots it. The regressions failed
before the fixes; real `rel_i16` returns `mask`, all six comparisons survive,
and the complete `compare16` compile/decompile/recompile/runtime gate exits
`255`.

A later current-tree CMP16 regression is also closed at Structuring. The final
`JNE` return edge was paired with an exact-tagged `call ? 0 : 1` AST condition;
the return-chain selector understood explicit zero comparisons but not this
equivalent truth-value projection, so it retained inverted polarity. The typed
selector now normalizes explicit zero tests, direct/negated calls, and boolean
call ITEs only when both expressions prove the same CFG branch. Three focused
selection regressions plus the 130-test return-chain surface pass. The real
`main` emits `if (in_window_i16(9, 1, 7)) return 13;`, reports
`validation=passed`, and the CMP16/LOOPS/FPTR optimization suite and complete
`quality-dev` gate pass.

The current focused unit lane passes **1,919 tests** under seven workers. A
fresh `quality-dev` passes direct Ruff `--fix`, MyPy over 266 files, the
39-module mypyc compile/import smoke, complexity, architecture, ownership, the
unit lane, and all three decompilation optimization comparisons. Promoted-file
coverage now includes the new Frontend, IR, Lowering, Structuring, validation,
and CLI modules rather than leaving them outside the real Ruff/MyPy gates.

The mandatory 2026-09-02 default and expanded pipelines are fully green. The
latest 1,919-test unit lane finished in about 65 seconds, and the required
SORTD generated-C, Ultra QuickC, and full MS C tiny lanes returned success. The MS C
lane covers `compare16`, `simple_control`, `loops_jumps`, `storage_classes`,
`function_pointers`, `pointer_memory`, and `scalar_types_io`; every selected
translation unit recompiles and its rebuilt executable exits `255`.

`simple_control/classify` is closed at Types/Lowering: the GP-state projection
preserves instruction provenance, and the final pre-validation orchestrator
replays the existing condition-argument type owner using projected machine-BP
coordinates. The generated signature is `unsigned short classify(short x)`;
the selected fallback validates, recompiles, and the rebuilt executable exits
`255`. Harness reporting now records rejected rebased attempts separately from
the selected validation result, so a clean accepted fallback reports zero final
failures without erasing its attempted-failure history.

`function_pointers/select_and_apply` is closed by authoritative stack identity,
not its stale placeholder name. Types/Lowering publishes verified stack-
prototype materialization even when the C AST was already physically correct;
Rewrite no longer aliases arguments by generated names. Tail Validation now
captures Structuring-materialized condition origin keys and stack coordinates
on both sides of Rewrite, rolls back drift, and records a hard failure. The
150-test changed surface, Ruff/MyPy/type ratchets, `quality-dev`, and the real
four-function gate pass; the emitted guard remains `if (which)` and the returned
call remains `apply_twice(fn, value)`.

A later full-pipeline replay exposed an independent Tail Validation crash in
that same function. Fingerprint simplification reconstructed a temporary
`CBinaryOp` and reran angr type inference over an archless signed word. Tail
Validation now clones the already typed template and substitutes only the
simplified children, preserving its result type, common type, codegen, and
tags. The regression fails on the old constructor path and passes on the typed
projection; the real function validates and returns `apply_twice(fn, value)`.

The Ultra QuickC `args` fixture is also closed at Types/Lowering. Stack-C
canonicalization preserves owned condition tags, exact writable scalar views
lose only equal-width signedness casts, near data pointers use explicit guest-
offset projections, and exact function pointers remain callable values. The
structural fixture contract recognizes equivalent segmented indexed loads from
the parsed C AST instead of demanding one rendered spelling. Tail Validation,
portable compilation, MS C compilation, and rebuilt execution all pass.

The DOS `_dos_loadProgram` wrapper is closed without Rewrite-owned semantic
repair. Types/Lowering recognizes a call result after its typed condition has
been projected from AX into the exact `SS:BP-2` store, and requires the explicit
AX-to-stack binding. Semantics classifies only epilogue instructions that
preserve AX/DX; Structuring follows a bounded jump-only path to the return,
resolves the active error object through the machine-BP coordinate registry,
and materializes `return err;` plus the proven zero continuation return. The
consumed argument PUSH byte carrier is pruned only with exact PUSH provenance.
Both CLI invocation shapes validate and recompile with direct `cs[0]`/`ss[0]`
stores. Focused Ruff/MyPy, `quality-dev` with 1,923 tests, and the mandatory
external pipeline pass.

The larger DOS `loadprog` body is now also closed at its owning layers.
Types/Lowering preserves one binary-proven four-byte `cmdline` stack owner and
projects its exact low/high word views without inventing a fifth logical
argument. Tail Validation consumes the same typed projection facts for call
sources and def-use. Structuring refuses a legacy linear-terminal scan when the
CFG has multiple value predecessors, then recovers only an exact-tagged return
from its own terminal predecessor. The success path is therefore the
binary-proven `return 0`, while the invalid-type and DOS-error paths retain
their distinct `return 1` and `return err`. The generic failing-before
regressions, 261 related tests, direct Ruff/MyPy, live COD validation, portable
recompilation, and `quality-dev` pass. No Rewrite or CLI semantic repair was
added.

The F14 CARR bounds predicates are closed at the Widening/Types and Structuring
boundaries. Required 32-to-16 semantic casts now remain exact low-word
projections, a complete CFG-proven wide predicate persists its stack-pair facts
across later C-AST rebuilds, and the existing atomic wide-return graph owner is
the only total-return materializer. `_InBoxLng` emits four long comparisons,
six logical long arguments, two return leaves, and `validation=passed` in about
8-10 seconds. `_InBox` and the ordinary single-JCC return diamond retain their
correct polarity. The 142-test condition/validation surface, both live CARR
functions, `quality-dev`, and the mandatory 1,922-test plus external executable
pipeline pass.

No test, validation check, or unsupported-input refusal was weakened. The goal
remains incomplete because Tasks 3, 5, 6, 7, and 8 remain open; the required
default, expanded, and changed-surface gates are currently green.

## Execution Ledger And Estimation

Ledger start: `2026-08-29T08:16:21+02:00` (`Europe/Belgrade`). Historical
start, finish, and effort values that were not measured at the time are marked
`pre-ledger` or `unknown`; they are not reconstructed from commit dates. From
this checkpoint onward, each active step records:

- start and finish wall-clock timestamps
- focused engineering time, excluding unattended test time and pauses
- wall span separately, so long tests do not distort implementation estimates
- test/build wait separately from focused engineering time
- acceptance evidence and the next unclosed boundary
- the previous and revised remaining-time range plus the evidence for any change

Start is written at the first task-directed command, not when a failure was
first noticed. Finish is written only after the row's DoD passes. `Spent` is
updated at each checkpoint; pauses and unattended test/build waits are excluded.
Unknown historical values remain unknown instead of being inferred from file or
commit timestamps. These rules make forecast error measurable per root cause.

The fixed weights below define total progress. A task advances only when its
DoD evidence passes; code volume, elapsed calendar time, and plausible-looking
output do not advance the percentage.

| Task | Weight | Complete | Started | Finished | Focused spent | Remaining focused estimate | Evidence / next boundary |
| --- | ---: | ---: | --- | --- | ---: | ---: | --- |
| 1. Whole-binary export | 5% | 100% | pre-ledger | pre-ledger | unknown | 0h | Closed by canonical stdout and strict compilation evidence. |
| 2. Behavior proof | 8% | 100% | pre-ledger | pre-ledger | unknown | 0h | Closed for all source-selftested non-library functions. |
| 3. Interprocedural contracts | 20% | 95% | pre-ledger | - | unknown | 17-27h | Signed stack arguments, exact function-pointer values, indirect calls, typed pointer-memory byte values, atomic argument replay, and terminal local pointer-output carriers are closed; broader multi-output storage remains. |
| 4. Semantic-loss ratchets | 7% | 100% | pre-ledger | pre-ledger | unknown | 0h | Closed by the strict 20/20 executable-only gate and permanent tests. |
| 5. Proof-backed readability | 8% | 0% | not started | - | 0h | 8-12h | Starts only after the semantic and behavior gates remain closed. |
| 6. Profiling and performance | 10% | 70% | pre-ledger | - | unknown | 8-12h | Measure aggregate PSS and profile the single-function serial tail. |
| 7. Reko mechanisms | 8% | 0% | not started | - | 0h | 10-16h | Implement only mechanisms supported by owned typed evidence. |
| 8. Ghidra mechanisms | 34% | 85% | pre-ledger | - | unknown | 45-65h | Curated acceptance is green, but the complete 10,091-test audit exposed remaining call/type/CFG and COD recovery families that must close before this task can claim completion. |
| **Total** | **100%** | **75%** | - | - | **historical total unavailable** | **80-115h** | Weighted completion is 75% after correcting the earlier curated-only estimate. Quality and executable pipelines are green; the complete-suite baseline is 9,865 passed, 56 failed, and 170 skipped. The latest exact last-failed rerun is 26 failed and 25 passed in 224.10s after closing the stale indexed-inventory baseline. |

Task-owner estimates above overlap where Tasks 3 and 8 share a mechanism. They
are not summed. The non-overlapping forecast table below is the authoritative
source for the total remaining estimate.

### Active Step Timing

| Step | Started | Finished | Focused spent | Wall span | Status | Remaining focused estimate | Acceptance evidence |
| --- | --- | --- | ---: | ---: | --- | ---: | --- |
| CMP16 coordinate-domain collision isolation and Types/Lowering refusal | `2026-08-29 07:18 +02:00` (first recorded command) | `2026-08-29 09:03 +02:00` | unknown before ledger plus 35-45m after `08:16` | 1h45m | completed | 0h | Two regressions failed before and pass after the fix. Real `rel_i16` emits all six distinct comparisons with `validation=passed`. Initial rollback-leak hypothesis was disproved; the owner was BP/entry-SP coordinate resolution. |
| Changed-surface verification for the CMP16 fix | `2026-08-29 08:49 +02:00` | `2026-08-29 09:03 +02:00` | 8-12m | 14m | completed | 0h | Ruff `--fix`, focused MyPy/type ratchet, architecture checks, 97 related tests, 50 owned tests, and the focused real executable gate pass. |
| Exact logical stack-word ownership | `2026-08-29 09:04 +02:00` | `2026-08-29 09:21 +02:00` | 15-17m | 17m | completed | 0h | Exact Alias logical-read identity now permits one proven two-byte `SS:BP` owner; unproven same-variable recomposition still refuses. Twelve focused tests pass and the live smoke AST now contains `v5 = arg_4` instead of a false byte recomposition. |
| Packed FLAGS preservation validation and production lift context | `2026-08-29 09:21 +02:00` | `2026-08-29 09:31 +02:00` | 9-10m | 10m | completed | 0h | Seventeen focused context/validation tests have 16 passes; the only remaining failure is the end-to-end smoke shape. The previous whole-postprocess `uninitialized eflags` discard is gone, and the live AST exposes the next independent Structuring defect. |
| Collapse pure identical-return guards in Structuring | `2026-08-29 09:34 +02:00` | `2026-08-29 10:10 +02:00` | 26-31m engineering; test waits excluded | 36m | completed | 0h | Structuring owns the typed pure-guard proof and closed evidence counters; Tail Validation consumes its exact delta. Widening now propagates block definitions into returns, and regenerated argument names preserve the Lowering-owned BP/entry-SP projection. Ruff, MyPy for all eight production files, the type/doc ratchet, startup architecture/context/ownership checks, 17 focused tests, and the complete 568-test owned surface pass. |
| Original six focused failures | `2026-08-29 10:10 +02:00` | `2026-08-29 11:06 +02:00` | 40-50m; test waits excluded | 56m | completed | 0h | The final C-declaration smoke now emits `return lhs + rhs;`; Beep and DrawTime remain validation-clean. Twenty-five focused and 188 changed-surface tests pass. Ruff `--fix`, direct MyPy over seven production modules, file type/doc ratchets, and startup architecture/context/ownership checks pass. |
| Current focused-lane failure closure | `2026-08-29 11:14 +02:00` | `2026-08-31 23:54 +02:00` | historical subtotal retained; waits excluded | continued through `2026-08-31` | completed | 0h | Sleep, Swaps, DrawTime, InitMenu, loop/control-flow, call/object/indexed-storage, DrawFrame, and RunMenu families pass their function DoDs. |
| Call/object/indexed-storage materialization family | `2026-08-31 21:43 +02:00` | `2026-08-31 22:22 +02:00` | 24-30m focused; repeated test waits excluded | 39m | completed | 0h | Five live regressions and 161 supporting cases pass. Types/Lowering preserves stronger object expressions, named calls and declarations share one target identity, and rollback cleanup retains validated braces/affine rendering. Ruff, MyPy, type/doc ratchets, and startup architecture checks pass. |
| DrawFrame validation and postprocess-baseline closure | `2026-08-31 22:27 +02:00` | `2026-08-31 22:59 +02:00` | 18-24m focused; repeated test waits excluded | 32m | completed | 0h | Tail Validation consumes the closed pure identical-return proof for the exact two-effect `if/else` surface. Postprocess baseline canonicalization now keys on its typed transaction-completion generation, not an initialized change flag. The live sidecar-free function, 167 related tests, Ruff, MyPy, type/doc ratchets, and startup architecture checks pass. |
| RunMenu packed-FLAGS carrier validation closure | `2026-08-31 23:29 +02:00` | `2026-08-31 23:54 +02:00` | 17-20m focused; repeated live-test waits excluded | 25m | completed | 0h | All postprocess passes were disabled to prove the carrier pre-existed Rewrite. Register-backed AIL virtuals retain their physical storage identity, exact packed-FLAGS evidence is consumed only at matching instruction sites, both live gates pass in 50.04s, 175 related tests pass, and emitted stdout passes `gcc -std=c11 -fsyntax-only`. |
| Frontend/debug and test-profile contract closure | `2026-08-29 11:27 +02:00` (delegated window) | `2026-08-29 11:49 +02:00` | 10-15m agent time, overlapped | 22m | completed | 0h | A truly unsupported `SLDT EAX` fixture preserves the required clear exit, and the inventory replacement selects the current topology regression. Eight focused tests plus Ruff and MyPy pass. |
| Stack-coordinate, argument-identity, and stack-object unit closure | `2026-08-29 11:27 +02:00` (parallel local/delegated window) | `2026-08-29 11:49 +02:00` | 15-22m, overlapped | 22m | completed | 0h | Canonical entry-SP coordinates and exact body-owned argument identity now agree. Thirteen focused tests pass; the fixture-only canonicalization changes preserve production refusal behavior. |
| Wide call-output, loop control-flow, and argument closure for live Sleep | `2026-08-29 11:36 +02:00` | `2026-08-29 12:41 +02:00` | 47-58m engineering; test waits excluded | 1h05m | completed | 0h | Live Tail Validation, the permanent executable-only Sleep test, the combined 151-test Types/Lowering and Structuring surface, direct Ruff/MyPy, and parallel `make linters-files` pass. The function retains two clock calls and one 32-bit argument. |
| Exact inner-break ownership under a typed loop header | `2026-08-29 11:49 +02:00` | `2026-08-29 11:54 +02:00` | 4-5m | 5m | completed | 0h | Regression failed before and all 16 loop-break tests pass after the existing owner checks exact break candidates before refusing a typed header. |
| Final condition-refresh/loop-closure pass order | `2026-08-29 11:54 +02:00` | `2026-08-29 11:58 +02:00` | 3-4m | 4m | completed | 0h | The order regression failed before and 17 related tests pass after final condition refresh precedes final loop-break closure. |
| Typed composite-loop-exit ownership for Sleep | `2026-08-29 11:58 +02:00` | `2026-08-29 12:24 +02:00` (checkpoint) | 17-22m; test waits excluded | 26m | completed | 0h | The regression failed before the fix. Condition chains now precede loop materialization; exact CFG-backed ownership handles both pre- and post-break projections, isolates nested loops, and refuses re-entry targets. The related 122-test surface and live `0x10f38` Tail Validation pass. |
| Positive-BP 32-bit argument plan/interface closure for Sleep | before `2026-08-29 12:24 +02:00`; exact first command was lost at compaction | `2026-08-29 12:35 +02:00` | 10-17m; approximate because the start preceded the retained ledger checkpoint | unknown | completed | 0h | Live instrumentation proved a closed one-argument/four-byte caller census but a wrongly narrowed two-byte body plan. The test failed before the generic storage-width precedence fix; the unit and permanent executable gates now pass with `materialized=1`, `failure=0`. |
| ALU carry/borrow effect-order integrations | `2026-08-29 11:27 +02:00` (delegated) | `2026-08-29 12:07 +02:00` | 25-35m agent time, overlapped; exact timer unavailable | 40m | completed | 0h | Both integrations report one materialized effect and zero failures. Fifty-two focused tests, Ruff `--fix`, MyPy on four production modules, and diff checks pass. |
| Complete focused pytest refresh after Sleep closure | `2026-08-29 12:42:58 +02:00` | `2026-08-29 12:49:42 +02:00` | 0m engineering | 6m44s test wall | completed | 0h | Exact Makefile target: 3,968 passed, 17 failed, 13 warnings. The ten slowest tests are recorded by pytest; the longest was InitMenu at 135.49s. |
| Reproduce and symptom-cluster the 17 focused failures | `2026-08-29 12:49:42 +02:00` | `2026-08-29 12:54:19 +02:00` | 4m37s; test waits excluded | 4m37s plus 2m45s retry test wall | completed | 0h | Exact 17-node retry: 16 failed and one sidecar HeapSort timeout passed. The 16 failures are assigned to six symptom families; earliest-layer owner proof remains part of each implementation row, not this clustering row. |
| Swaps destination identity and validation-blind-spot closure | `2026-08-29 12:54:19 +02:00` | `2026-08-29 13:32 +02:00` | 31-35m; waits excluded | 37m41s | completed | 0h | Two failing-before regressions prove the machine-BP/entry-SP collision and the validation blind spot. Exact coordinate selection preserves all three object-copy effects; duplicate storage identity is refused. The live Swaps regression passes with `validation=passed`, strict C syntax, and the correct three assignments. |
| DrawTime carry-predicate sibling-join closure | `2026-08-29 13:30 +02:00` | `2026-08-29 13:43 +02:00` | 10-13m; waits excluded | 13m | completed | 0h | A failing-before CFG-ownership regression proves the low subtraction may be a sibling of the flags definition. Types/Lowering now performs the existing unique exact arithmetic fallback for a typed missing predicate. The live DrawTime regression and a 72-test carry/Swaps cluster pass with clean Tail Validation and C syntax. |
| InitMenu condition, call-result, and final-brace closure | `2026-08-29 14:23 +02:00` (approximate; first command lost at compaction) | `2026-08-29 15:16 +02:00` | 35-45m; waits excluded | 53m | completed | 0h | Frontend publishes the exact dword-OR zero condition; Types/Lowering removes only typed unobserved AX/EAX results and assigned fixed probes with frame proof; Rewrite only forces braces around already-structured multi-statement bodies. All three live tests, 94 focused tests, Ruff, MyPy, type/doc ratchets, and startup architecture checks pass. |
| Validation-clean loop/control-flow family | `2026-08-29 15:29 +02:00` | `2026-08-29 16:50 +02:00` | exact focused subtotal unavailable after interruption; test waits excluded | 1h21m | completed | 0h | ReInitBars, BubbleSort, ExchangeSort, and PercolateUp pass live Tail Validation; 127 changed-surface tests and the four-test executable lane pass. Generic ambiguity/refusal tests cover storage identity, ordered pretests, duplicate breaks, and pretest condition surfaces. |
| Retry-lane artifact persistence and checkpoint gates | `2026-08-31 10:54 +02:00` | `2026-08-31 13:30 +02:00` | 25-35m engineering; broad external wait excluded | 2h36m including shared-tree integration and external test wall | completed | 0h | Retry-lane C is persisted only after accepted validation. The final late-integration lane passes 18 focused tests with six fixture-dependent loader skips; Ruff, MyPy over 263 files, the 39-module mypyc smoke, architecture/ownership checks, 1,882 pytest cases, and all three pure-Python/mypyc quality comparisons pass. Measured candidate timing was mixed under shared-machine load: CMP16 1.174x and LOOPS 2.616x faster, FPTR 0.254x of baseline, so no universal speedup is claimed. The clean optimization-input rebuild now enforces the fixtures' intentional exit code 255. The broader `test-pipeline` remains red and is recorded below. |
| CMP16 accepted-return closure and pre-validation integrity guard | `2026-09-01 03:28 +02:00` | `2026-09-01 03:55 +02:00` | 15-20m engineering; test waits excluded | 27m | completed | 0h | Failing-before Lowering, Frontend adapter, Widening, and return-integrity regressions isolate the exact stale branch-join definition. Real `rel_i16`, the full `compare16` round trip, 187 related tests, Ruff, MyPy, and the optimization suite pass. |
| Simple-control signed argument and GP-provenance closure | `2026-09-01 03:56 +02:00` | `2026-09-01 04:54 +02:00` | 25-35m engineering; test waits excluded | 58m | completed | 0h | Two failing-before regressions prove the lost GP tags and wrong raw-BP signedness consumer. The real three-function round trip validates the selected outputs, recompiles, and exits `255`; 157 related tests and the default pipeline's 1,906-test lane pass. |
| Architecture promotion and accepted-attempt reporting integrity | `2026-09-01 04:20 +02:00` | `2026-09-01 04:57 +02:00` | 18-25m engineering, overlapping the simple-control gate waits | 37m | completed | 0h | Startup architecture is green, quality-dev passes Ruff/MyPy/mypyc and 1,906 tests, and final versus attempted validation failures are separate typed profile fields. Forty-eight harness tests pass. |
| Function-pointer stack identity and condition-integrity closure | `2026-09-01 05:45 +02:00` (first retained checkpoint) | `2026-09-01 06:20 +02:00` | 30-40m engineering; test waits excluded | 35m | completed | 0h | A failing-before production-shaped regression isolates name-first aliasing of raw stack offset `2` to offset `4`. Alias-owned machine-BP identity is now the only substitution proof, the no-op materialization marker is durable, and Tail Validation rejects any later condition-storage drift. The 150-test surface, file gates, `quality-dev` with 1,906 tests, and the complete four-function runtime gate pass with rebuilt exit `255`. |
| Pointer-memory typed value/storage closure | `2026-09-01 06:20 +02:00` (diagnosis checkpoint) | `2026-09-01 06:41 +02:00` | 15-20m engineering; test waits excluded | 21m | completed | 0h | The stack-coordinate registry now distinguishes an 8-bit semantic value from its 16-bit ABI slot. It refuses the high byte and an adjacent word argument. The 389-test architecture/coordinate surface, Ruff, MyPy, startup guard, and clean three-function compile/decompile/recompile/runtime gate pass with rebuilt exit `255`. |
| Ultra arguments, GP-frame scope, and function-pointer projection closure | `2026-09-01 09:41 +02:00` | `2026-09-01 11:04 +02:00` | 45-60m engineering; test waits excluded | 1h23m | completed | 0h | Condition tags survive stack canonicalization; writable scalar lvalues normalize only with exact physical-width proof; data pointers retain guest-offset semantics; exact function pointers remain callable; canonical `push bp`/`pop bp` is excluded from the GP snapshot consumer and remains owned by frame lowering. Focused regressions fail before and pass after. Ruff, MyPy over 266 files, mypyc smoke, architecture/ownership, 1,913 unit tests, Ultra QuickC, all MS C tiny constructs, and optimization comparisons pass. |
| Tail Validation typed temporary-projection closure | before `2026-09-01 14:11 +02:00`; exact first command lost at compaction | `2026-09-01 14:24 +02:00` | exact focused subtotal unavailable after compaction; final 13m retained; waits excluded | at least 13m retained | completed | 0h | The failing-before archless signed-word regression passes; the real `select_and_apply` emits the required returned call with `validation=passed`; 66 focused tests pass; Ruff, MyPy, the 1,915-test mandatory pipeline, all external round trips, and `quality-dev` pass. |
| CMP16 final return-chain polarity closure | `2026-09-01 19:55 +02:00` (diagnosis checkpoint) | `2026-09-01 20:33 +02:00` | 25-35m engineering; repeated executable and gate waits excluded | 38m | completed | 0h | Production tracing proved `JNE` decoded as `CmpNE` while the exact-tagged AST carried `call ? 0 : 1`. Structuring now selects decoded polarity only with same-branch proof. Three focused selection tests, 130 existing return-chain tests, direct Ruff/MyPy, the real CMP16 function, all three optimization comparisons, and `quality-dev` pass. |
| Architecture ownership promotion and `quality-hard` refresh | `2026-09-01 20:34 +02:00` | `2026-09-01 20:46 +02:00` | 6-10m engineering; gate waits excluded | 12m | completed | 0h | Every newly owned production module has an exact layer header and is enrolled in the Ruff/MyPy and architecture-promotion inventories. `quality-hard` passes Ruff `--fix`, MyPy over 266 files, mypyc smoke over 39 compiled modules, architecture/startup/context checks, and the hard regression lane. |
| angr Clinic semantic-stage compatibility closure | `2026-09-01 20:48 +02:00` | `2026-09-01 21:02 +02:00` | 9-12m engineering; pipeline waits excluded | 14m | completed | 0h | The dependency-updated Clinic now always runs pre-SSA, SSA, post-SSA, and variable-recovery semantics. Cost policy bounds inner peephole work only. The 24-test Clinic/runtime surface, direct Ruff/MyPy, the three previously failing helpers, all 1,915 curated tests, and all seven MS C round trips pass. |
| InitMenu dead packed-FLAGS chain closure | `2026-09-01 21:33 +02:00` | `2026-09-01 22:01 +02:00` | 20-25m engineering; repeated executable waits excluded | 28m | completed | 0h | DCE atomically removes pure empty two-arm conditions and lets Lowering-owned packed-FLAGS live-in protection expire when no consumer remains. Eighty-four focused tests, direct Ruff/MyPy, and the real sidecar-free `0x10060` gate pass; generated C contains neither `inertia_flags` nor the `v48`-`v58` parity chain. |
| DrawBar exact stack-address replay closure | before `2026-09-01 22:34 +02:00`; exact first command lost at compaction | `2026-09-01 22:49 +02:00` | 55-75m engineering; test waits excluded | at least 15m retained | completed | 0h | A failing-before production-shaped regression proves that whole-call quality scoring could preserve a stale scalar low byte over an exact typed `BP_ADDRESS` source. Types/Lowering now resolves the machine-BP coordinate and the compatibility replay consumes that identity before generic score comparison. Five new source/projection tests, 188 related tests, Ruff, MyPy, `quality-dev` with 1,915 tests, the mandatory pipeline with all seven MS C round trips, and live `0x106c8` Tail Validation pass. The sibling `0x101f0` call mismatches are gone; its independent `BP-0x2` carrier failure is the next root cause. |
| DrawFrame regenerated frame-setup carrier closure | `2026-09-01 22:50 +02:00` | `2026-09-01 23:03 +02:00` | 18-25m engineering; gate waits excluded | 13m retained plus gate wall | completed | 0h | A failing-before production-shaped regression proves that the exact `mov bp, sp` carrier survived after earlier cleanup consumed the structured `push bp` carrier. Types/Lowering now accepts the owned BP setup write only with a decoded canonical entry pair. The refusal case, 10 frame tests, 490 related tests, Ruff, MyPy, strict C11 syntax, live `0x101f0` Tail Validation, `quality-dev`, and the mandatory 1,915-test plus seven-round-trip pipeline pass. Required DrawFrame calls and loop semantics match the source oracle. |
| QuickSort short-circuit guard and generated-runtime closure | `2026-09-02 02:10 +02:00` | `2026-09-02 02:49 +02:00` | 25-35m engineering; repeated gate waits excluded | 39m | completed | 0h | Structuring binds each pretest guard to its exact JCC evidence and derives a predecessor only from a uniquely proven short-circuit CFG chain. Both QuickSort scan guards and recursive calls survive, the generated sort core compiles and terminates correctly, and ambiguous/mismatched evidence refuses. Types/Lowering also preserves the signed Sleep comparison through an explicit semantic cast on both operands. Nineteen focused pretest tests, 21 wide-call/Sleep tests, `quality-dev`, and the expanded acceptance pipeline pass. |
| Terminal local pointer-output versus scalar-return closure | `2026-09-02 03:04 +02:00` | `2026-09-02 04:03 +02:00` | 40-55m engineering; gate waits excluded | 59m | completed | 0h | Semantics records a typed all-terminal-path carrier role from decoded operand facts; Types consumes it only with complete unused-caller evidence and a guessed prototype. Sidecar-free Swaps becomes `void`, `_SetDLC` keeps its scalar return, uncertain/direct-global cases refuse demotion, and `quality-dev` plus the required external executable pipeline pass. |
| `_ConfigCrts` indexed-load and live-carrier closure | `2026-09-02 04:28 +02:00` | `2026-09-02 05:05 +02:00` | 24-30m engineering; gate waits excluded | 37m | completed | 0h | Types/Lowering projects exact byte lanes from wider binary load-site evidence, Widening recomposes only a typed virtual word destination, and Rewrite cleanup keeps nested temporaries live at enclosing continuations. The failing-before regressions, real sidecar-free function, 29 focused tests, Ruff, MyPy, mypyc smoke, `quality-dev`, and mandatory plus expanded executable pipelines pass. |
| Quiet native-tool output contract | `2026-09-02 05:05 +02:00` | `2026-09-02 05:18 +02:00` | 10-13m | 13m | completed | 0h | Make recipes suppress duplicate command echo and pass concise native Ruff, MyPy, pytest, and lizard flags. The startup checker has a compact-success mode but preserves full failures. Fifty-seven contract tests, direct Ruff/MyPy, and the focused Make targets pass. |
| COD frontend-fixture and timeout-reporting realignment | `2026-09-02 05:18 +02:00` | `2026-09-02 05:27 +02:00` | 8-9m | 9m | completed | 0h | Five stale block-lift fixture expectations now preserve byte-safe split loads, explicit `NEXT` fallthrough, and dead FLAGS-write elimination. The direct timeout path again reports its recovery phase and larger-timeout hint inside valid C comments. Six block-lift cases plus the process-helper and timeout regressions pass. |
| `_dos_getfree` cleanup-transaction closure | `2026-09-02 05:28 +02:00` | `2026-09-02 05:34 +02:00` | 6m; test waits overlap | 6m | completed | 0h | Rewrite policy now restores and refuses only the optional unused-global declaration cleanup when its validation delta differs. COD/source semantics, the exact `intdos` call, the zero-carry error branch, both return paths, live `validation=passed`, Ruff, MyPy, and nine focused tests pass. |
| F14 regenerated global-read identity closure | `2026-09-02 05:53 +02:00` | `2026-09-02 06:20 +02:00` | 11-14m engineering; broad gate waits excluded | 27m | completed | 0h | Types/Lowering now revisits runtime helper surfaces after regeneration, traverses non-`CStatements` roots, and reconciles the existing explicit COD storage/display alias. Live `_ChangeWeather` emits `if (BadWeather)` with validation clean; three failing suite nodes plus four generic ordering/traversal tests, Ruff, direct MyPy, `quality-dev`, and mandatory plus expanded pipelines pass. |
| Native tool flag and token-output ratchet extension | `2026-09-02 06:20 +02:00` | `2026-09-02 06:23 +02:00` | 3m | 3m | completed | 0h | Ruff quiet/concise, MyPy plain/no-color, Pyright warning-level, pytest short-traceback/no-header, and Lizard warnings-only preserve actionable findings while suppressing success noise. Contract tests, direct invocations, and `quality-dev` pass. |
| `_MousePOS` regenerated physical-register carrier closure | `2026-09-02 06:23 +02:00` | `2026-09-02 06:44 +02:00` | 10-14m engineering; broad gate waits excluded | 21m | completed | 0h | Lowering replays the two exact global stores, then Rewrite folds only an adjacent dead `SimRegisterVariable` carrier with physical-register identity and suffix/live-out proof. A later use refuses. Live `_MousePOS` emits `MouseX = x << 1;`, preserves `MouseY`, `interrupt_int33`, and `return 4`, recompiles, and reports `validation=passed` plus whole-tail clean. Forty-nine focused tests, Ruff, direct MyPy, and `quality-dev` with 1,921 tests pass. |
| F14 `_InBox`/`_InBoxLng` predicate and durable wide-pair closure | `2026-09-02 06:45 +02:00` | `2026-09-02 08:00 +02:00` | 40-50m engineering; repeated corpus and gate waits excluded | 1h15m | completed | 0h | Types/Lowering recognizes only exact 16-bit semantic projections and persists stack pairs only after complete CFG proof. Structuring invokes its existing atomic wide-return owner before competing replay and reuses the recorded proof after AST rebuilds. `_InBoxLng` emits six long arguments and four comparisons with `validation=passed`; `_InBox` and the scalar JLE regression retain correct polarity. The 142-test related surface, two live CLI cases, Ruff, MyPy, `quality-dev`, and the mandatory 1,922-test external pipeline pass. |
| Machine-BP prototype identity and indexed byte-pointer closure | `2026-09-02 08:30 +02:00` | `2026-09-02 09:25 +02:00` | 40-50m engineering; focused waits excluded | 55m | completed | 0h | Types/Lowering now recognizes a sole pointer carrier in either x86 effective-address register and refuses two-carrier ambiguity. Stack prototype materialization joins physical C arguments to logical annotations through the owned machine-BP coordinate instead of raw entry-SP offsets. Failing-before tests cover both defects; 77 related tests, Ruff, MyPy, live `fill_bytes`, and the three-function `pointer_memory` compile/decompile/recompile/runtime construct pass in 16.21s with a `char *dst` byte store. |
| Stored call-return early-exit and DOS wrapper closure | `2026-09-02 09:39 +02:00` | `2026-09-02 10:45 +02:00` | 45-55m engineering; repeated live and gate waits excluded | 1h06m | completed | 0h | Exact PUSH provenance removes the split byte carrier. Lowering joins the projected stack condition to its AX call-result binding; Semantics proves the jump-only epilogue path preserves return registers; Structuring resolves the machine-BP error object and materializes both returns. Failing-before unit tests, both live CLI modes, 83 related checks with only the pre-existing `loadprog` body failure, direct Ruff/MyPy, `quality-dev` with 1,923 tests, and the mandatory external pipeline pass. |
| DOS `loadprog` wide-stack view and path-specific terminal-return closure | `2026-09-02 10:55 +02:00` | `2026-09-02 11:53 +02:00` | 35-45m engineering; repeated live and gate waits excluded | 58m | completed | 0h | Types/Lowering owns one four-byte `cmdline` argument and exact word projections; Tail Validation consumes the same typed projection facts; Structuring refuses cross-path linear substitution and materializes the exact tagged success return from its own CFG predecessor. Generic failing-before tests, 261 related checks, direct Ruff/MyPy, live `validation=passed`, portable recompilation, and `quality-dev` pass. |
| Swaps return-frame, validation-coordinate, and final projection closure | before `2026-09-02 14:02 +02:00`; exact start lost at compaction | `2026-09-02 14:13 +02:00` | exact focused subtotal unavailable after compaction; final diagnosis and gates retained | at least 11m retained | completed | 0h | Lowering consumes the typed CALL return frame before removing the fixed stack probe; Tail Validation translates exact-region C slots to machine-BP ABI offsets; Structuring replays the unique pointer-swap projection after final codegen regeneration and removes only tagged consumed carriers. The live Swaps test passes with one temporary load, both stores, the global increment, `validation=passed`, and strict C syntax. Focused pointer, return-frame, coordinate, and owner tests, Ruff, direct MyPy, `quality-dev` with 1,923 tests, mypyc smoke, and all three quality comparisons pass. |
| Function-wide entry-SP to machine-BP validation-coordinate closure | before `2026-09-02 15:06 +02:00`; exact start lost at compaction | `2026-09-02 15:22 +02:00` | 15-25m focused; complete local gate wall excluded | at least 16m retained | completed | 0h | Types/Lowering now owns one typed C-function coordinate projection. It accepts only the coherent 16-bit near-frame delta from entry-SP `+2` to machine-BP `+4`, applies it consistently to arguments and locals, and refuses already-projected, incomplete, or mixed interfaces. An uncached live DrawBar run and its permanent regression return zero with `validation=passed`; 99 focused tests, Ruff, MyPy, architecture checks, and `quality-dev` with 1,924 tests plus all required external quality comparisons pass. |
| Required project gates after the fix | `2026-08-29 08:51 +02:00` | `2026-09-02 06:40 +02:00` | historical subtotal retained; test time excluded | continued through `2026-09-02` | completed | 0h | Ruff, MyPy over the production surface, the 39-module mypyc smoke, architecture and ownership checks, and 1,921 curated tests pass. All three quality comparisons pass at 1.356x-1.526x. The expanded pipeline remains 5/5: SORTD decompiles 20/20 functions with zero validation failures or timeouts, its generated translation unit compiles with zero warnings, the 19-function sort-core behavior gate passes, and every selected Ultra QuickC and MS C tiny round trip passes. No exclusion or weakened check was added. |
| Complete repository pytest closure | `2026-09-02` | - | latest full audit wall 852.88s; closure work tracked per root family | active | in progress | 20-35h, overlapping task 9 | The exact baseline is 9,944 passed, 23 failed, 170 skipped out of 10,137. The latest exact last-failed rerun is 19 failed and 3 passed in 221.20s. Focused closures project 13 remaining failures; only a complete rerun may replace the exact count, and final DoD remains zero failures. |

#### Machine-BP prototype identity and indexed byte-pointer closure contract

Reason: 16-bit effective addresses may carry a near pointer in either Capstone
`base` or `index`. The generated C variables may simultaneously use entry-SP
coordinates while annotations use machine-BP coordinates. Missing either fact
widens byte stores or shifts argument types onto the next physical word.

DoD: one decoded argument carrier in either effective-address register yields
an exact pointee-width fact; two argument carriers refuse; prototype replay
joins only by owned machine-BP identity; `fill_bytes` retains a byte pointer;
Tail Validation, Ruff, MyPy, focused tests, and the complete `pointer_memory`
runtime construct pass.

Definition of failure: rendered-assembly or function-name matching; accepting
an address with two argument carriers; joining annotations by list position or
raw `SimStackVariable.offset`; `short *` byte-store widening; validation,
recompile, or generated runtime failure.

#### Stored call-return early-exit and DOS wrapper closure contract

Reason: the call result was stored at `SS:BP-2`, but the typed condition and C
AST could expose different projections of that same storage. The error edge
then carried AX unchanged through a jump-only epilogue while angr retained only
placeholder returns. A byte-executed PUSH carrier also survived as an invalid
casted lvalue.

DoD: Lowering joins only an exact call-return store, typed condition, and
register binding; Semantics proves every instruction on the bounded error path
preserves AX/DX until return; Structuring resolves the active C object by owned
machine-BP identity and fills both placeholder returns; consumed PUSH cleanup
requires exact instruction provenance and argument identity. Both COD CLI
shapes emit `if (err) return err;`, direct output-pointer stores, and `return 0;`
with `validation=passed`; Ruff, MyPy, focused tests, `quality-dev`, and the
mandatory external pipeline pass.

Definition of Failure: rendered-text, procedure-name, or address-specific
recovery; accepting a projected stack condition without its return-register
binding; treating an unknown instruction as return-register preserving;
resolving stack identity by raw offset when a machine-BP projection exists;
deleting a non-PUSH store or a PUSH without exact consumed-argument proof;
missing either return or pointer store; any validation, compile, focused-test,
lint, type, or mandatory-pipeline failure.

#### F14 `_InBox`/`_InBoxLng` predicate closure contract

Reason: the complete 32-bit comparison graph was present in typed ConditionIR,
but mutable C declarations temporarily split each long argument into two words.
The canonical wide-return owner therefore lost its Widening proof after later
AST rebuilds. An experimental total-return helper duplicated Structuring
ownership, and placing chain materialization before legacy JCC replay inverted
an ordinary scalar return diamond.

DoD: Types/Lowering accepts a semantic cast as a low-word projection only when
its destination is exactly 16 bits and its four-byte stack owner covers the
adjacent high slice. Structuring atomically consumes every raw JCC fact, proves
all four 32-bit comparisons and both return leaves, records the synthesized
wide conditions as durable typed evidence, and remains the sole total-return
owner across AST rebuilds. `_InBoxLng` has six logical long parameters, the
four source-equivalent range comparisons, both return values, and
`validation=passed`; `_InBox` and a generic scalar JLE return diamond keep
correct polarity. Focused refusal tests, Ruff, MyPy, `quality-dev`, and the
mandatory external pipeline pass.

Definition of Failure: accepting an 8-bit or untyped cast as a word projection;
widening adjacent stack words without either an external pair proof or a
complete CFG proof anchored by one proven operand; recovering from rendered C,
assembly text, procedure names, or corpus addresses; retaining a second
total-return materializer; allowing legacy replay to overwrite a canonically
owned wide root; losing or inverting any comparison or return leaf; splitting
the final logical long arguments; any Tail Validation failure; or any focused
lint, type, compile, behavior, or mandatory-pipeline failure.

#### `_MousePOS` regenerated physical-register carrier closure contract

Reason: regeneration ran Rewrite cleanup before the final Types/Lowering global
identity replay. That replay correctly materialized `MouseX = cx`, but the
resulting adjacent `cx = x << 1` carrier was too late for cleanup and physical
register names were excluded from the generic dead-copy classifier.

DoD: Types/Lowering remains the only owner of the global-store and interrupt
semantics. Final orchestration reruns AST-only cleanup after all Lowering and
Structuring replays. Rewrite identifies physical registers by typed
`SimRegisterVariable` coordinates, folds only an adjacent movable producer with
one matching consumer and no suffix/live-out use, and refuses a later use. Live
`_MousePOS` preserves both global stores, the interrupt call and its value
arguments, and the explicit AX-derived `return 4`; generated C recompiles,
reports `validation=passed`, and has whole-tail validation clean. Generic
positive/identity/refusal, focused CLI, Ruff, MyPy, and `quality-dev` pass.

Definition of Failure: deriving the fold from rendered C, a function name, COD
text, or an address; moving global or interrupt semantics into Rewrite; folding
a register with any later structured-AST use; keying physical identity on a
Python object id; deleting or changing the interrupt call or either global
store; treating the interrupt helper return as the proven AX result; leaving an
undeclared register in generated C; or any focused compile, validation, lint,
type, or broad development-gate failure.

#### F14 regenerated global-read identity closure contract

Reason: runtime segmented-memory lowering could create a typed `SEG_U16` read
after named-global materialization had already run, while the final regeneration
hook replayed naming only when runtime lowering reported a fresh mutation. The
named-load walker also descended only from `CStatements`, so valid alternative
structured roots stranded a proven read even though exact COD `EQU` storage and
display identities had already been recorded.

DoD: Types/Lowering traverses every supported structured-C root, reruns named
global materialization after runtime helper creation, and reapplies the existing
unambiguous storage/display identity facts after regeneration even when the
helper already exists. Live `_ChangeWeather` preserves both branches and all six
global stores, emits `if (BadWeather)`, reports whole-tail validation clean, and
focused positive/order/refusal, Ruff, and MyPy checks pass. Raw no-label output
may retain a numeric global but must use the current portable runtime segment
identifier.

Definition of Failure: deriving names or control flow from rendered C; merging
ambiguous aliases; replacing generated storage identity instead of projecting
the explicit display alias; limiting traversal to one root class; running
semantic recovery in Rewrite or CLI text processing; losing a branch/store;
retaining the synthetic analysis-image address in labeled CLI C; or any focused
validation, type, lint, or source-call/store survival failure.

#### `_dos_getfree` cleanup-transaction closure contract

Reason: unused generated-global declaration pruning is cleanup-only, but a
non-destructive validation mismatch made its rejection fail the whole function
after the validated baseline had already been restored. The emitted function
was semantically correct and matched the COD source, yet the CLI returned a
validation failure solely because this optional cleanup lacked reject-and-
continue policy.

DoD: Rewrite transaction policy classifies only the declaration-prune pass as
locally rejectable and budgeted, while keeping it outside mandatory semantic
validation. A rejected pass restores the prior validated snapshot. The real COD
function preserves `intdos(&rin, &rout)`, the `cflag == 0` error path, zero and
`rout.x.bx` returns, and reports whole-tail `validation=passed`; focused policy,
COD, Ruff, and MyPy checks pass.

Definition of Failure: accepting a mismatched cleanup result instead of
restoring it; making semantic, call, CFG, alias, type, or structuring passes
optional; changing the source-proven branch polarity; hiding validation state;
matching the function name/address/rendered text as recovery evidence; or any
focused validation, lint, type, call-survival, or return-path failure.

#### COD frontend-fixture and timeout-reporting realignment contract

Reason: five block-lift fixtures encoded obsolete physical VEX shapes from
before independently resolved byte-safe accesses, explicit fallthrough targets,
and dead FLAGS-write suppression. Separately, the terminal direct timeout path
lost the phase and retry guidance required by the CLI contract.

DoD: fixtures assert the current semantic frontend contract without changing
the preserved byte-safe access implementation; fallthrough remains explicit and
dead overwritten flag writes remain absent. Timeout stdout remains valid C
comments and includes both the recovery phase and larger-timeout hint. Focused
block-lift, timeout, and process-helper tests pass.

Definition of Failure: restoring wide unwrapped guest-memory accesses; removing
an explicit control-flow target; requiring a dead FLAGS write; weakening a
semantic assertion merely to fit output; emitting non-C metadata on stdout;
dropping timeout classification or guidance; or changing production semantics
to satisfy a stale fixture.

#### Quiet native-tool output contract

Reason: repeated Make echo plus verbose native tool formatting consumed agent
context without improving diagnostics, especially for broad parallel gates.

DoD: Make exposes overridable concise native flags for Ruff, MyPy, Pyright,
pytest, and Lizard, suppresses duplicate recipe echo, and uses compact startup
output only on success. Ruff uses quiet rather than silent mode, so remaining
diagnostics survive. Full command output is retained in temporary logs for
failures; native exit codes, warnings, test collection, lint/type scope, and
required gates are unchanged. Focused Makefile and startup-check regressions
pass.

Definition of Failure: suppressing a checker, warning family, failure detail,
collection item, or exit status; replacing a native machine-readable/concise
mode with lossy text filtering; hiding required commands; or making local and
Make-invoked tool policy diverge.

#### `_ConfigCrts` indexed-load and live-carrier closure contract

Reason: the byte-safe frontend correctly exposed independently resolved bytes
from one wider binary load, but Types/Lowering rendered each byte as the whole
indexed word. After exact recomposition, late Rewrite cleanup then deleted the
word producer inside a loop because it could not see the return continuation.

DoD: Types/Lowering consumes exact load-site width and segmented-address
evidence to project each byte lane; Widening recomposes only exact low/high
projections into an Alias-proven word or a typed two-byte virtual destination;
Rewrite cleanup carries live-out identities across loops and branches and
refuses unsafe deletion. Failing-before positive and refusal tests pass, the
real sidecar-free function returns and stores the same complete word with
`validation=passed`, and focused, lint, type, mypyc, mandatory, and expanded
executable gates are green.

Definition of Failure: changing the byte-safe frontend access contract;
matching function names, addresses, assembly, or rendered C; treating every
byte as a whole word; recomposing without exact lane and width proof; deleting
a producer live after a nested statement body; moving semantic recovery into
Rewrite; losing the store or return; or any required validation, test, type,
lint, compilation, or runtime gate failure.

#### Terminal local pointer-output versus scalar-return closure contract

Reason: physical AX liveness alone cannot distinguish a scalar function result
from a temporary local value that is reloaded only to complete a terminal
write through a pointer argument. Treating both as returns gave Swaps a false
scalar API; treating every terminal store as output would erase legitimate
direct-global scalar returns such as `_SetDLC`.

DoD: Semantics derives a typed carrier role from decoded operands and requires
the same proof on every terminal path; later reads/writes, direct global stores,
and ambiguous paths refuse. Types may demote only when that proof is complete,
all known callers explicitly ignore the return, and the prototype is guessed.
Focused positive and refusal tests pass, live Swaps is `void`, `_SetDLC` remains
scalar, and Ruff, MyPy, architecture, `quality-dev`, and the external executable
pipeline are green.

Definition of Failure: using function names, addresses, source, assembly text,
or rendered C as proof; making a broad terminal-store rule; demoting an explicit
prototype or a used/unknown caller; accepting mixed terminal paths; implementing
the semantic distinction in Structuring, Rewrite, or CLI; losing a pointer
write or scalar return; or any required type, lint, architecture, validation,
focused-test, compilation, or runtime gate failure.

#### Complete repository pytest closure contract

Reason: the curated pipeline intentionally optimizes development latency and
does not exercise every COD/debug corpus, compatibility contract, or slow live
decompilation. Calling that lane "all tests" hid independent production defects
and made the earlier 79% estimate too optimistic.

DoD: the exact command `pytest -n 7 --dist loadgroup --durations=10` collects the
complete repository suite and exits zero; every currently failing node either
passes after an owning-layer correction or is removed only with written proof
that it is duplicate, superseded, or invalid. Skips remain classified and
intentional. The ten slowest tests and their owner families are recorded, and
the curated quality/executable gates remain green.

Definition of Failure: reporting curated or last-failed results as the complete
suite; adding `xfail`, skip, ignore, timeout inflation, or test deletion to hide
a production defect; fixing rendered C or a corpus address instead of the owner;
running without the required seven-worker profile; omitting slow-test evidence;
or leaving any full-suite failure while claiming the goal or plan complete.

#### QuickSort short-circuit and Sleep comparison closure contract

Reason: a pretest guard without exact branch evidence was borrowing a later
predicate solely because both shared a candidate body target. That inverted
QuickSort's scan exits and made generated execution diverge. Separately, the
wide-call condition owner cast the call result to signed long but left the
other operand dependent on a later mutable declaration, creating a mixed-sign
comparison warning.

DoD: Structuring selects a guard only from exact JCC identity or a unique
short-circuit predecessor whose alternate edge is the same proven exit;
ambiguity and mismatched tags refuse. Both QuickSort scans and recursive calls
survive Tail Validation, generated C compiles, and the behavior harness
terminates with source-equivalent results. Types/Lowering applies the signed
semantic view to both Sleep comparison operands. Focused tests, `quality-dev`,
and all five expanded acceptance lanes pass.

Definition of Failure: selecting evidence by a shared target without exact
branch ownership; deriving through multiple predicates or unequal exits;
repairing polarity or casts in Rewrite/CLI; matching rendered C, assembly text,
function names, or addresses as proof; losing a call or scan; retaining a
compiler warning or runtime timeout; or weakening any validation or test gate.

#### DrawFrame regenerated frame-setup carrier closure contract

Reason: a canonical `push bp; mov bp, sp` entry may lose every structured
`push bp` carrier during earlier semantic cleanup while GP-state lowering keeps
the setup write as a coherent `inertia_ebp` assignment. Requiring only the
vanished push carrier strands exact decoded frame evidence and makes a compiler
frame effect look like an uninitialized user local.

DoD: a failing-before production-shaped test proves the missing-push-carrier
case; a noncanonical decoded entry refuses pruning; the owner consumes only an
exact tagged BP setup write paired with decoded canonical entry evidence; live
DrawFrame retains every source-required call and loop, passes whole-tail
validation and strict C11 syntax, and all changed-surface and mandatory project
gates pass.

Definition of Failure: pruning from a function address, C spelling, variable
name, or rendered text; accepting a noncanonical entry or an unowned write;
moving the repair to Rewrite; losing a DrawFrame call or control-flow effect;
leaving validation changed/uncollected; or weakening/excluding any gate.

#### InitMenu dead packed-FLAGS chain closure contract

Reason: DCE correctly made the obsolete flag-derived branch empty, but Tail
Validation observed that no-op control node and rolled the pass back. After the
empty branch was removed atomically, Lowering's live-in owner inventory still
made every assignment to the packed FLAGS identity permanently protected, so a
semantically dead parity/update chain survived in generated C.

Definition of done: DCE removes only explicit empty `if/else` nodes whose
condition is proven pure; effectful conditions are refused; a packed-FLAGS
initializer remains while an exact consumer exists and expires after the full
consumer chain is dead; evidence counters close; focused Ruff, MyPy, and tests
pass; real sidecar-free `SORTD.EXE` `0x10060` reports `validation=passed` and
emits no raw `inertia_flags`, parity temporaries, or unsupported instruction.

Definition of failure: deleting a single-arm or effectful condition; treating
packed-FLAGS metadata as permission to delete a still-read initializer; keeping
an initializer after all consumers disappear; failing evidence closure, type,
lint, focused tests, C syntax, or Tail Validation; or retaining any raw FLAGS
carrier/parity chain in the accepted `0x10060` C.

#### CMP16 return-chain polarity closure contract

Reason: the machine `JNE` target returns `13`, but Structuring paired that edge
with the equivalent-looking `call ? 0 : 1` truth-value projection and retained
its opposite polarity. Exact branch ownership and decoded JCC meaning must stay
coherent when a return chain is rebuilt.

Definition of done: the selector uses a typed same-branch proof; explicit zero
tests, direct/negated calls, and boolean call ITEs have one normalized polarity;
an unproven branch identity refuses replacement; focused and existing
return-chain tests pass; the real CMP16 `main` preserves all thirteen calls and
returns with `validation=passed`; Ruff, MyPy, optimization comparisons, and
`quality-dev` pass.

Definition of failure: choosing decoded or structured polarity without matching
CFG ownership, accepting `CmpEQ` for the taken `JNE` return edge, matching
rendered C or assembly text, repairing the condition in Rewrite or validation,
losing a call/return, or any required test, lint, type, executable, or quality
gate failure.

#### Architecture hard-gate promotion closure contract

Reason: a production module that owns semantic or structural behavior but is
absent from the global type/lint and architecture inventories can silently
drift outside the layer rules even when its focused tests pass.

Definition of done: every newly introduced owner is enrolled in the project
Ruff/MyPy targets and the architecture promotion set, exact layer headers pass
the ownership checker, and the complete edited-state `quality-hard` target
returns zero without exclusions or weakened checks.

Definition of failure: any owner remains outside those inventories, an exact
layer marker is missing, Ruff/MyPy/mypyc/architecture/context checks fail, or a
new skip, ignore, or reduced check scope is used to obtain a green result.

#### angr Clinic semantic-stage compatibility closure contract

Reason: after the angr/Python dependency refresh, Clinic requires argument and
de-SSA mappings produced by its pre-SSA, SSA, and post-SSA stages before
variable recovery. Inertia's tiny-helper cost policy was incorrectly bypassing
those semantic stages and later produced either an assertion or raw invalid C.

Definition of done: cost guards may bound inner simplification and peephole
work but cannot skip semantic Clinic stages; a focused contract proves stage
execution; `inc_one`, `bump_static`, and `add_sc` produce readable C with clean
Tail Validation; direct Ruff/MyPy pass; and the complete `test-pipeline`
recompiles and executes all seven MS C tiny constructs with exit `255`.

Definition of failure: any semantic Clinic stage is bypassed, empty argument or
de-SSA inputs are invented, a rendered-C repair hides raw addressing, one of
the three focused helpers asserts/falls back/fails validation, or any curated
unit or external round-trip gate fails.

#### Simple-control signed-argument closure contract

Reason: condition-proven signedness belongs to Types/Lowering, while the final
AST orchestrator may only replay that owner after late condition regeneration.
Losing GP assignment tags also made canonical frame pruning unable to identify
the original `mov bp, sp` carrier.

Definition of done: provenance survives GP subregister projection; normalized
ConditionIR facts use authoritative machine-BP coordinates; the selected
`classify`, `sum_to`, and `switch_fold` outputs have clean Tail Validation;
generated C recompiles; the rebuilt executable exits `255`; focused Ruff,
MyPy, architecture, unit, and default-pipeline gates retain the evidence.

Definition of failure: raw positive-BP inference in Rewrite, rendered-C or
assembly matching, an architecture-guard exception that moves semantics late,
loss of an argument/sign/branch, conflating a rejected attempt with the selected
result, rebuilt exit other than `255`, or any required regression/gate failure.

#### Function-pointer stack-identity closure contract

Reason: Structuring had materialized the exact `which` condition at machine
`BP+4`, but Rewrite replaced it through the stale display name `arg_6` with the
next argument at `BP+6`. Tail Validation then canonicalized both surfaces and
missed the storage redirect.

Definition of done: argument substitution consumes only Alias-owned stack
identity; verified stack-prototype materialization is published even when the
AST needs no physical change; Tail Validation compares keyed stack coordinates
across Rewrite and hard-fails drift; `select_and_apply` tests `which`, retains
both function targets, and returns `apply_twice(fn, value)`; the four-function
translation unit recompiles and exits `255`; focused tests, Ruff, MyPy,
type/doc ratchets, `quality-dev`, and optimization comparisons pass.

Definition of failure: argument recovery by display name, rendered C, source,
or assembly text; semantic repair in Rewrite; accepting changed or uncollected
condition storage; loss of either function target or a call argument; rebuilt
exit other than `255`; or any required test, type, documentation, lint,
architecture, validation, or optimization gate failure.

#### Pointer-memory typed value/storage closure contract

Reason: MS C passes an `unsigned char` in a two-byte stack slot, but the load
at machine `BP+6` consumes only its typed low-byte value. Treating the missing
one-byte projection as a raw angr offset redirected it to the following word
argument at `BP+8`.

Definition of done: Types/Lowering records storage width and semantic value
width separately; exact and low-value lookups consume the same Alias-owned
machine-BP identity; high-byte and adjacent-word byte requests refuse; the
generated fill loop assigns `value`, all three functions have clean Tail
Validation, the translation unit recompiles, the rebuilt executable exits
`255`, and focused Ruff, MyPy, architecture, and unit gates pass.

Definition of failure: inferring the argument from a name, rendered C, COD, or
assembly text; implementing value/storage recovery in Rewrite; accepting a
high-byte or adjacent-slot collision; emitting `dst[i] = count`; rebuilt exit
other than `255`; or any required type, lint, architecture, validation, unit,
compile, or runtime gate failure.

#### InitMenu step 5c closure contract

Reason: a block-local dword zero test, unused physical call-result carriers, and
multi-statement C bracing had distinct owners; conflating them would move
semantics into Rewrite and make Tail Validation less trustworthy.

Definition of done: the exact binary-derived condition reaches Structuring,
both branch calls survive, only typed unobserved AX/EAX results are discarded,
the generated sidecar-free and sidecar-assisted C compiles, Tail Validation is
clean, and the permanent live and refusal tests pass.

Definition of failure: any source/name/address/rendered-text recovery, semantic
statement movement in Rewrite, deletion under unknown return-use evidence,
lost call, unsupported/raw flag carrier, validation failure, or C compile error.

#### Loop/control-flow step 5d closure contract

Reason: the failing functions shared validation-clean but noncanonical loop
surfaces whose conditions, exits, and storage identities crossed Condition IR,
status-flag liveness, and Structuring ownership boundaries.

Definition of done: ReInitBars, BubbleSort, ExchangeSort, and PercolateUp pass
live Tail Validation; required calls and stores survive; ordered pretests,
duplicate breaks, and pretest initializers/bodies are materialized only from
unique typed IR/CFG evidence; focused tests and changed-surface gates pass.

Definition of failure: any rendered-text, symbol-name, or address-specific
recovery; semantic repair in Rewrite or CLI; ambiguous condition/loop ownership
accepted instead of refused; lost call/store; validation failure; or focused
test, type, documentation, lint, or compilation failure.

#### Call/object/indexed-storage step 5e closure contract

Reason: exact call arguments, pointer classes, segmented live-ins, object
widths, and indexed global storage cross Alias and Types/Lowering contracts;
late name-based or rendered-C repair can silently change value-versus-pointer
semantics.

Definition of done: all five live materialization regressions pass with
`validation=passed`; required calls, argument classes, indexed stores, and
object widths survive; generated C passes portable syntax checks; the closed
evidence counters have no classified-but-unmaterialized facts; focused tests,
Ruff, MyPy, type/doc ratchets, and architecture ownership checks pass.

Definition of failure: any function/address/source/COD/rendered-text-specific
guess; name-based pointer or helper substitution; semantic repair in Rewrite or
CLI; lost call/store, wrong value-versus-pointer class, ambiguous evidence
accepted instead of refused, Tail Validation failure, C compile error, or any
required focused type, documentation, lint, architecture, or test failure.

#### DrawFrame step 5f closure contract

Reason: Structuring had a closed typed proof that both pure guard arms returned
the same value, while Tail Validation omitted the normal two-effect `if/else`
surface. Independently, postprocess mistook an initialized compatibility flag
for proof that its transaction had completed and compared against a stale
uncanonicalized baseline.

Definition of done: sidecar-free DrawFrame emits all three fill, position, and
buffer-output calls; retains the source-equivalent inclusive loop; compiles as
portable C; reports `validation=passed`; and its focused tests, Ruff, MyPy,
type/doc ratchets, and startup architecture check pass.

Definition of failure: accepting unrelated validation channels or unbounded
control-flow deltas; repairing the guard in Rewrite; parsing rendered C; using
a function/address-specific exception; losing a required call, loop bound, or
argument class; or any required focused gate failure.

#### RunMenu step 5g closure contract

Reason: Tail Validation must distinguish an arbitrary unresolved virtual from
an AIL virtual with exact physical-register provenance. Otherwise typed IR
evidence for packed FLAGS preservation is collected but cannot be consumed,
and valid structured C is rejected at final emission.

Definition of done: sidecar-free RunMenu retains `local_2 = sub_11292();`, all
ten switch cases, and `case 27: return;`; emits `extern long g_0132;`; reports
`validation=passed` and clean whole-tail validation; compiles under strict C11;
and exact-site, wrong-site, focused flag/validation/structuring, lint, type/doc,
and startup architecture gates pass.

Definition of failure: treating every virtual carrier as initialized; accepting
a packed-FLAGS read without exact frontend instruction evidence; adding a
RunMenu/address/rendered-C exception; repairing semantics in Rewrite or CLI;
losing a call, case, return, or signed declaration; or any required focused
gate failure.

### Forecasted Execution Steps

This table is the estimation calibration record for the remaining plan. A row
gets an actual start only when work begins and an actual finish only after its
DoD passes. `Spent` is focused engineering time; unattended builds and test
wall time are recorded in the active-step table or acceptance evidence. The
estimate is revised after every completed row, so later estimates are based on
measured root-cause closure time rather than the number of failing tests.
The final cell in each row is that row's DoD. Missing any listed condition,
weakening a gate, or moving semantics to a later layer is its definition of
failure; the detailed reason and failure clauses remain authoritative in the
numbered task section below.
The rows are non-overlapping and currently sum to the same rounded 80-115h total
as the weighted task ledger. Estimates for the remaining live families are deliberately
separate: a passing test count cannot hide an independent semantic owner or a
validation blind spot.

#### Remaining priority by impact

Priority is determined by semantic blast radius and dependency leverage, not
by the easiest percentage gain:

1. **P0 - Step 9, full-suite semantic and interprocedural-contract closure.**
   This is the only remaining step that advances both Task 3 and Task 8, makes
   the complete pytest collection trustworthy again, and removes correctness
   and recompilability defects on which every later quality task depends. The
   first vertical slice, the larger DOS `loadprog` body, is closed: one
   binary-proven four-byte stack owner and its exact Tail Validation subviews
   survive, and each terminal return is recovered only from its own CFG
   predecessor. The active boundary is now the exact full collection and its
   refreshed failure inventory. Process remaining failures by shared owner:
   multi-output/indexed/indirect storage first, type and object identity second,
   CFG/condition recovery third, and isolated corpus regressions only after
   those shared mechanisms close.
2. **P1 - Step 10, profile and optimize the serial tail.** Start implementation
   after the first P0 family closes and an exact full-suite baseline is stable;
   collect profiles during P0 test waits. Keep only optimizations whose measured
   savings repay their engineering cost across the remaining gates and remain
   under the 2 GiB aggregate-worker budget.
3. **P2 - Step 11, proof-backed readability.** Begin only after the semantic
   suite is green, because readable output must consume stable typed evidence
   rather than hide unresolved ownership defects.
4. **P3 - Step 12, evidence-supported Reko mechanisms.** Implement last, and
   only where the existing IR/Alias/Types contracts can prove the mechanism;
   this has less immediate corpus and gate leverage than P0-P2.

P0 definition of done: every currently failing in-scope repository test is
either corrected by a generic earliest-layer implementation or retired with
documented supersession evidence; the exact complete collection has zero
failures; `quality-hard`, default, and expanded pipelines pass; and all closed
evidence counters remain balanced. P0 definition of failure: accepting a
curated lane as full-suite success, changing tests to bless semantic loss,
repairing calls/types/storage in Rewrite or CLI, introducing corpus-specific
logic, or leaving any unexplained failure hidden by selection, timeout, skip,
or output filtering.

| Order | Step | Start | Finish | Spent | Current estimate | Dependency / completion boundary |
| ---: | --- | --- | --- | ---: | ---: | --- |
| 1 | Reproduce and symptom-cluster the current focused failures | `2026-08-29 12:49:42 +02:00` | `2026-08-29 12:54:19 +02:00` | 4m37s focused; 2m45s test wall separate | complete | Complete lane: 3,968 passed / 17 failed. Exact retry: 16 failed / 1 passed. Six independent symptom families are recorded. |
| 2 | Close frontend/debug and test-profile contract failures | `2026-08-29 11:27 +02:00` | `2026-08-29 11:49 +02:00` | 10-15m agent time, overlapped | complete | Focused failures pass without weakening unsupported-instruction exits or retiring required coverage. |
| 3 | Close stack-coordinate, argument-identity, and stack-object unit failures | `2026-08-29 11:27 +02:00` | `2026-08-29 11:49 +02:00` | 15-22m local/agent time, overlapped | complete | Machine-BP facts resolve through the authoritative coordinate projection; focused unit clusters and refusal cases pass. |
| 4 | Close ALU carry/borrow effect-order integrations | `2026-08-29 11:27 +02:00` (delegated) | `2026-08-29 12:07 +02:00` | 25-35m agent time, overlapped; exact timer unavailable | complete | Generated C preserves one low-half operation and one proven high-half carry/borrow effect; both focused integrations and the 52-test suite pass. |
| 5a | Fix Swaps destination identity and the Tail Validation blind spot | `2026-08-29 12:54:19 +02:00` | `2026-08-29 13:32 +02:00` | 31-35m; test waits excluded | complete | The first incorrect consumer was Types/Lowering's raw entry-SP lookup for machine-BP arguments. Two unit regressions, live C semantics, Tail Validation, strict C syntax, and the changed-surface checks pass. |
| 5b | Close DrawTime carry-predicate sibling ownership | `2026-08-29 13:30 +02:00` | `2026-08-29 13:43 +02:00` | 10-13m; test waits excluded | complete | A typed missing predicate searches the complete function only through the existing unique exact arithmetic/CFG ownership proof. Ambiguous and mismatched evidence still refuse; the focused and live regressions pass. |
| 5c | Close the three InitMenu validation/condition failures | `2026-08-29 14:23 +02:00` (approximate) | `2026-08-29 15:16 +02:00` | 35-45m focused; 63.22s final live-test wall separate | complete | Exact binary-backed conditions and the pause guard validate; both calls survive; sidecar-free and sidecar-assisted C compile; Rewrite adds braces only and does not recover semantics. |
| 5d | Close the five validation-clean loop/control-flow shape failures | `2026-08-29 15:29 +02:00` | `2026-08-29 16:50 +02:00` | exact focused subtotal unavailable after interruption | complete | ReInitBars, BubbleSort, ExchangeSort, and PercolateUp use IR/CFG-owned condition and loop structure, pass live Tail Validation, and retain required calls and stores. |
| 5e | Close the five call/object/indexed-storage materialization failures | `2026-08-31 21:43 +02:00` | `2026-08-31 22:22 +02:00` | 24-30m focused; final 54.31s test wall separate | complete | Five live regressions plus supporting unit contracts pass; exact typed target identity removes stale numeric declarations and lower-level IR replay cannot overwrite stronger object lowering. |
| 5f | Close the DrawFrame validation failure | `2026-08-31 22:27 +02:00` | `2026-08-31 22:59 +02:00` | 18-24m focused; final 10.86s related-suite wall separate | complete | DrawFrame passes Tail Validation with no semantic repair in Structuring cleanup or Rewrite; the source-equivalent loop and every required call survive. |
| 5g | Close the RunMenu portable-C declaration failure | `2026-08-31 23:29 +02:00` | `2026-08-31 23:54 +02:00` | 17-20m focused; final two-test live wall 50.04s | complete | RunMenu validates, compiles as portable C, retains the Escape path and call result, and consumes packed-FLAGS evidence only through exact physical-register identity. |
| 6 | Rerun the complete focused pytest lane and classify any newly exposed failures | `2026-09-01` (exact start not retained) | `2026-09-01 03:55 +02:00` | test wall recorded separately | complete | The complete unit lane passes 1,906 tests; each external MS C failure has a concrete function-level symptom. |
| 6a | Close CMP16 stale accepted-return propagation and its validation blind spot | `2026-09-01 03:28 +02:00` | `2026-09-01 03:55 +02:00` | 15-20m focused; test waits excluded | complete | Widening invalidates branch-joined definitions, Structuring guards the proven return fingerprint, and the full `compare16` round trip exits `255`. |
| 7a | Close `simple_control` GP provenance and signed argument projection | `2026-09-01 03:56 +02:00` | `2026-09-01 04:54 +02:00` | 25-35m focused; test waits excluded | complete | The existing Types/Lowering owner consumes projected machine-BP coordinates; all three selected functions validate and the rebuilt executable exits `255`. |
| 7b | Close function-pointer stack identity and condition integrity | `2026-09-01 05:45 +02:00` (first retained checkpoint) | `2026-09-01 06:20 +02:00` | 30-40m focused; test waits excluded | complete | Alias-owned storage identity survives Rewrite; the generic validation guard rejects argument redirects; the full `function_pointers` gate exits `255`. |
| 7c | Close `pointer_memory` typed byte-value storage | `2026-09-01 06:20 +02:00` | `2026-09-01 06:41 +02:00` | 15-20m focused; test waits excluded | complete | Types/Lowering owns the typed low-byte projection inside the word ABI slot; the full gate exits `255`. |
| 7d | Fix and rerun the remaining `scalar_types_io` gate | diagnosis refreshed `2026-09-01 06:20 +02:00` | `2026-09-01 11:04 +02:00` | included in the measured Ultra arguments closure; waits excluded | complete | All ten selected functions validate; the translation unit recompiles and the rebuilt executable exits `255`. |
| 7e | Close CMP16 final return-chain branch polarity | `2026-09-01 19:55 +02:00` | `2026-09-01 20:33 +02:00` | 25-35m focused; test waits excluded | complete | Structuring reconciles exact-tagged call truth projections with the decoded JCC only under same-branch proof; real CMP16 validation and `quality-dev` pass. |
| 7f | Close DrawBar's machine-BP/entry-SP call-address collision | before `2026-09-01 22:34 +02:00`; exact first command lost at compaction | `2026-09-01 22:49 +02:00` | 55-75m focused; waits excluded | complete | Exact typed address-source identity overrides stale whole-call quality scoring; live `0x106c8` validates and the default pipeline remains green. The then-independent DrawFrame frame-carrier failure is tracked by 7g. |
| 7g | Close DrawFrame's regenerated canonical frame-setup carrier | `2026-09-01 22:50 +02:00` | `2026-09-01 23:03 +02:00` | 18-25m focused; waits excluded | complete | An owned BP setup write plus decoded canonical entry evidence survives earlier PUSH cleanup; live `0x101f0` validates, compiles, and retains every required call and loop. |
| 8 | Run `quality-hard`, `test-pipeline`, and required expanded acceptance gates | started `2026-09-01` | `2026-09-02 02:49 +02:00` | historical gate work plus 25-35m final closure engineering; test walls separate | complete | `quality-hard`, `quality-dev`, 1,919 curated tests, and the expanded 5/5 acceptance pipeline are green without exclusions or weakened checks. |
| 8a | Audit the complete pytest collection and classify every failure family | `2026-09-02` | `2026-09-02 03:04 +02:00` | test wall recorded separately | complete | Exact `pytest -n 7 --dist loadgroup --durations=10` audit: 10,091 collected, 9,865 passed, 56 failed, 170 skipped in 724.28s. Failures are grouped into COD/F14/DOSFUNC recovery, SORTD/source-sidecar behavior, three fast unit-contract families, and the slow TIDShowRange/debug corpus. |
| 9a | Close terminal local pointer-output carrier versus scalar-return identity | `2026-09-02 03:04 +02:00` | `2026-09-02 04:03 +02:00` | 40-55m focused; quality and pipeline waits separate | complete | Semantics owns a typed all-terminal-path proof; Types consumes it only with complete unused-caller evidence and a guessed prototype. Swaps becomes `void`, direct-global `_SetDLC` remains scalar, uncertain paths refuse demotion, `quality-dev` and the required executable pipeline pass. |
| 9b | Close `_ConfigCrts` byte-lane projection and cross-structure temporary liveness | `2026-09-02 04:28 +02:00` | `2026-09-02 05:05 +02:00` | 24-30m focused; gate waits excluded | complete | Types/Lowering preserves exact byte subviews, Widening proves exact word recomposition, and Rewrite cleanup refuses deletion across a live enclosing continuation. Real Tail Validation, 29 focused tests, `quality-dev`, and mandatory plus expanded pipelines pass. |
| 9c | Preserve validated callee pointer evidence across exact-function project views | `2026-09-02 12:43 +02:00` | `2026-09-02 13:01 +02:00` | about 18m focused; test waits included | complete | The existing ABI seeding service rebases immutable pointer evidence, detects conflicts, and makes HeapSort's two `Swaps` arguments typed pointers. Focused source-assisted and sidecar-free validation, strict C11 syntax, Ruff, MyPy, architecture checks, and `quality-dev` pass. |
| 9d | Keep Swaps call-frame and pointer-swap projections coherent through final regeneration | before `2026-09-02 14:02 +02:00`; exact start lost at compaction | `2026-09-02 14:13 +02:00` | exact subtotal unavailable after compaction | complete | Typed return-frame ownership, machine-BP validation coordinates, and the unique exact swap projection now survive their downstream consumers. Live Swaps has exactly three object-copy assignments, the counter effect, clean Tail Validation, and strict C syntax; focused Ruff, MyPy, `quality-dev`, and regression gates pass. |
| 9e | Keep typed C-function stack coordinates coherent across final validation | before `2026-09-02 15:06 +02:00`; exact start lost at compaction | `2026-09-02 16:08 +02:00` | 45-60m focused after the first checkpoint; broad gate wall separate | complete | The Types/Lowering owner accepts only the canonical near-frame entry-SP-to-BP delta and may project unregistered negative locals, while positive slots remain under Alias/type ownership. Live uncached DrawBar passes; 101 focused tests, `quality-dev` with 1,924 tests, and the mandatory pipeline are green. `scalar_types_io`, including `add_long`, recompiles and exits `255`. |
| 9 | Finish remaining general interprocedural contracts, full-suite failure families, and open Ghidra mechanisms | `2026-09-02 02:10 +02:00` | - | prior closures plus completed 9c/9d/9e slices; waits excluded where recorded | 55-76h pending exact recalibration | Tasks 3 and 8 meet their per-step DoD for general indexed, indirect, stack, multi-output, type, CFG, COD, and full-suite contracts; the exact complete collection reaches zero failures without hiding coverage. |
| 10 | Profile and optimize the remaining serial decompiler tail | not started | - | 0h | 8-12h | Aggregate PSS stays within the 2 GiB budget and measured wall time improves without semantic or validation regression. |
| 11 | Add proof-backed readability improvements | not started | - | 0h | 8-12h | Readability changes consume existing typed evidence and all semantic gates remain green. |
| 12 | Implement evidence-supported Reko mechanisms | not started | - | 0h | 9-15h | Task 7 per-step DoD passes; unsupported mechanisms remain explicit refusals. |

#### Step 9c acceptance contract

Reason: pointer-argument classification was already correct in the full-binary
project, but its per-project registry disappeared when CLI created an exact
function project. The downstream call lowering therefore received no pointer
identity and rendered numeric values even though the callee evidence existed.

Definition of done:

- the existing Types/Lowering ABI service transfers only already-validated,
  immutable pointer evidence and rebases only the source and target addresses
- conflicting target evidence refuses replacement, incomplete prototypes do
  not discard independent pointer evidence, and no new pointer classification
  occurs at the project boundary
- source-assisted and sidecar-free HeapSort preserve both `Swaps` pointer
  argument classes, report `validation=passed`, and compile as strict C11
- focused tests, Ruff `--fix`, MyPy, architecture import checks, and
  `quality-dev` pass

Definition of failure:

- CLI, Structuring, or Rewrite infers pointer semantics from names, addresses,
  rendered C, or call shape
- evidence is silently overwritten, transported without validation, or lost
  merely because a complete prototype cannot yet be formed
- output becomes prettier while a call, argument class, memory effect, CFG
  edge, Tail Validation result, compile gate, type, documentation, or lint gate
  regresses

#### Step 9d acceptance contract

Reason: Swaps exposed three projection-coherence defects. Fixed stack-probe
removal could leave its CALL return-frame artifacts behind; exact-function C
arguments used entry-SP-like slots while validation compared machine-BP ABI
slots; and final shared-call regeneration could restore a raw temporary load
already consumed by the lowering-owned pointer-swap projection.

Definition of done:

- fixed stack-probe removal consumes its typed CALL return frame first and does
  not emit the return IP as a local/object write
- Tail Validation maps the active exact C argument list to deterministic
  machine-BP ABI offsets and refuses incomplete or ambiguous layouts
- one unique exact pointer-swap sequence survives final Structuring
  regeneration; only an extra temporary load tagged inside the already-proven
  instruction region is removed
- live Swaps retains the global increment, one temporary load, both pointer
  stores, `validation=passed`, and strict generated-C compilation
- focused return-frame, pointer-swap, validation-coordinate, and owner tests,
  Ruff `--fix`, MyPy, and index coverage pass

Definition of failure:

- generic DCE is taught to discard arbitrary pointer reads, or Rewrite/CLI
  reconstructs the swap
- an untagged, ambiguous, unrelated, call-bearing, memory-writing, or
  control-flow statement is removed
- argument names, source labels, function addresses, rendered C, or corpus
  shape become semantic evidence
- the global increment, either pointer store, call/frame effect, validation
  verdict, compile gate, type, documentation, lint, or deterministic output
  regresses

#### Step 9e acceptance contract

Reason: Tail Validation had begun canonicalizing final C arguments onto
machine-BP ABI offsets, but unregistered locals still used angr entry-SP
offsets. DrawBar therefore compared the same storage as `BP-0x2c` versus
`BP-0x2e`, and some final arguments as `BP+0x4` versus `BP+0x2`. Keeping the
argument-only translation in Tail Validation created two competing coordinate
truths.

Definition of done:

- Types/Lowering owns a typed function-wide coordinate projection and Tail
  Validation consumes that owner instead of duplicating ABI arithmetic; final
  argument storage may prove the coordinate relation while a transient
  function type is unavailable, but it does not prove parameter types
- only the coherent 16-bit near-frame relation from entry-SP `+2` to
  machine-BP `+4` is accepted; mixed, incomplete, already-projected, and
  noncanonical interfaces refuse
- the function-wide fallback projects only negative local slots; unregistered
  positive slots keep their original coordinate so wide-argument
  materialization remains the authoritative owner
- argument and local dependencies use the same proven delta, so DrawBar loses
  all `+2/+4` and `-0x2e/-0x2c` false mismatches
- an uncached live DrawBar run and its permanent regression report
  `validation=passed`, retain generated C, and return zero
- focused coordinate, call-argument, fingerprint, and DrawBar tests, Ruff
  `--fix`, MyPy, architecture ownership, mypyc smoke, `quality-dev`, and the
  mandatory external pipeline pass; `scalar_types_io` recompiles and its
  rebuilt executable exits `255`

Definition of failure:

- Tail Validation, Rewrite, or CLI guesses a universal `+2` correction without
  a coherent final argument-storage interface
- a machine-BP, mixed, one-off `+6`, ambiguous, or incomplete interface is
  shifted; unrelated segmented runtime lowering changes as a side effect
- an unregistered positive slot is shifted before Alias/type materialization,
  or a split-word intermediate surface blocks a proven wide argument
- arguments and locals are canonicalized by separate owners or source/COD,
  names, addresses, assembly, rendered C, or corpus shape become evidence
- DrawBar loses a call, argument dependency, memory effect, return, CFG edge,
  validation verdict, recompilation result, type, documentation, lint, or
  deterministic output

### Estimate History

| Checkpoint | Remaining focused estimate | Change | Evidence |
| --- | ---: | ---: | --- |
| `2026-08-29 11:49 +02:00` | 91-139h | baseline | Five focused failures closed; 2 ALU and 16 live SORTD checks reproduced. |
| `2026-08-29 12:05 +02:00` | 90-138h | -1h / -1h | Sleep moved from an unclassified rendering symptom to one Structuring ownership boundary; two generic regressions pass. |
| `2026-08-29 12:07 +02:00` | 89-133h | -1h / -5h | Both delegated ALU integrations pass their DoD, removing that whole forecast row. |
| `2026-08-29 12:24 +02:00` | 89-132h | 0h / -1h after rounding | Sleep's composite loop-exit ownership now passes 122 related tests and live Tail Validation. The remaining Sleep failure is isolated to one Types/Lowering positive-BP plan/interface decision. |
| `2026-08-29 12:41 +02:00` | 88-131h | -1h / -1h | Sleep's permanent sidecar-free test, combined 151-test surface, and parallel per-file linter/type ratchets pass; its remaining prototype boundary was a generic contained-view width precedence defect. |
| `2026-08-29 12:59 +02:00` | 95-145h | +7h / +14h | The exact retry reduced 17 failures to 16 reproducible failures but exposed six independent owner families. Swaps also reveals a Tail Validation blind spot, so the previous single-bucket 2.25-9.5h estimate was not defensible. |
| `2026-08-29 13:16 +02:00` | 94-144h | -1h / -1h after rounding | Live pass-by-pass identity tracing isolates Swaps to one Types/Lowering coordinate-consumer defect. The step remains open because its failing-before test, production correction, and Tail Validation rejection case have not all passed. |
| `2026-08-29 13:43 +02:00` | 93-141h | -1h / -3h after rounding | Swaps passes its complete function-fix DoD. DrawTime's independently exposed carry-predicate failure also has a failing-before generic regression, an earliest-layer fix, live `validation=passed`, strict C syntax, and a 72-test related cluster. |
| `2026-08-29 15:16 +02:00` | 92-137h | -1h / -4h after rounding | InitMenu's three live failures close in 35-45 focused minutes across their distinct Frontend, Types/Lowering, and cleanup owners. The permanent three-test live gate and 94 focused tests pass. |
| `2026-08-31 11:10 +02:00` | 90-132h | -2h / -5h | The loop/control-flow family and its retry-artifact reporting contract pass their focused DoD. The fresh full MS C lane exposes five explicit later-task failures instead of being reported as green. |
| `2026-08-31 22:22 +02:00` | 87-124h | -3h / -8h | Step 5e closed faster than forecast after three shared root causes were isolated: lowering precedence, validated rollback cleanup completeness, and typed call/declaration target coherence. Five live regressions, 161 supporting cases, file gates, and startup architecture checks pass. |
| `2026-08-31 22:59 +02:00` | 86-121h | -1h / -3h | Step 5f closed through two generic validation contracts: exact identical-return delta cardinality and typed postprocess transaction completion. DrawFrame passes sidecar-free with source-equivalent control flow; 167 related tests and all changed-surface gates pass. |
| `2026-08-31 23:54 +02:00` | 85-120h | -1h / -1h | Step 5g closed faster than forecast after pass isolation proved the defect pre-existed postprocess. Register-backed AIL virtuals now retain exact physical-register identity in validation; wrong-site packed-FLAGS reads still fail. Both live RunMenu gates, 175 related tests, changed-file gates, startup architecture checks, and strict C syntax pass. |
| `2026-09-01 03:55 +02:00` | 82-116h | -3h / -4h | CMP16's accepted-return defect closed at Widening, with a Structuring integrity guard that prevents Tail Validation from blessing the same loss later. The current unit lane and three of seven MS C constructs pass; four constructs remain independently red. |
| `2026-09-01 04:57 +02:00` | 80-113h | -2h / -3h | `simple_control` closes in 25-35 focused minutes at GP projection and condition-argument Types/Lowering. Quality-dev is fully green, the unit lane remains 1,906/1,906, four of seven MS C constructs pass, and selected-versus-attempted validation reporting is explicit. |
| `2026-09-01 06:20 +02:00` | 75-105h | -5h / -8h | `function_pointers` closes after pass tracing isolates a name-first Rewrite alias. The correction consumes machine-BP identity only, and a typed Tail Validation surface now rejects future stack-coordinate redirects. The 150-test surface, quality-dev, optimization suite, and complete runtime gate pass. |
| `2026-09-01 06:41 +02:00` | 74-103h | -1h / -2h | `pointer_memory` closes after separating a byte value from its word ABI storage slot in Types/Lowering. Exact refusal tests, 389 related tests, architecture startup, and the clean three-function runtime gate pass. |
| `2026-09-01 14:24 +02:00` | 70-99h | -4h / -4h | Atomic argument replay, byte stack projection, and validation-only typed expression projection close the two replayed MS C failures. The mandatory 1,915-test pipeline, all external round trips, and `quality-dev` pass. |
| `2026-09-01 20:33 +02:00` | 70-99h | unchanged | An unplanned current-tree CMP16 regression consumed 25-35 focused minutes but did not close a remaining weighted task. Its same-branch Structuring fix now passes the real executable, 133 focused tests, all optimization comparisons, and `quality-dev`; `quality-hard` and the broad gates remain open. |
| `2026-09-01 20:46 +02:00` | 70-99h | unchanged | The edited-state `quality-hard` gate now passes after all new owners were promoted into the global lint/type and architecture inventories. Step 8 remains open until the fresh default, expanded, and broad full-suite gates pass. |
| `2026-09-01 21:02 +02:00` | 70-99h | unchanged | The dependency-updated angr Clinic exposed an invalid semantic-stage shortcut. The generic runtime-policy correction closes the three newly failing MS C helpers and restores the full default pipeline; Step 8 remains open for expanded and broad gates. |
| `2026-09-01 22:49 +02:00` | 70-99h | unchanged | DrawBar's typed exact-address replay now validates and the mandatory pipeline remains green. This closes an unplanned regression inside the still-partial shared interprocedural/Ghidra task, so no weighted milestone or forecast row closes yet. DrawFrame's independent `BP-0x2` frame carrier is next. |
| `2026-09-01 23:03 +02:00` | 70-99h | unchanged | DrawFrame's regenerated canonical setup carrier now validates and the mandatory pipeline remains green. This closes the sibling regression but not a weighted top-level DoD; Step 8 still requires expanded and broad gates, and Step 9 remains the next semantic family. |
| `2026-09-02 02:49 +02:00` | 68-96h | -2h / -3h | Exact JCC ownership and conservative short-circuit predecessor recovery close QuickSort's two scan guards and generated-runtime timeout. A signed semantic-view correction closes the final Sleep warning. `quality-dev` and the complete expanded 5/5 pipeline pass with 1,919 curated tests, SORTD 20/20, zero validation failures/timeouts/compiler warnings, and a passing generated sort-core behavior gate. The weighted total remains 79% after rounding because the broader call/type/CFG task is still open. |
| `2026-09-02 04:03 +02:00` | 80-115h | +12h / +19h | The first exact 10,091-test repository audit proves that curated green did not mean full-suite green: 9,865 passed, 56 failed, and 170 skipped. Four failures have since been corrected or independently verified, leaving about 52 projected pending an exact rerun. The Swaps terminal pointer-output carrier now closes at Semantics and Types with `quality-dev` and the executable pipeline green, but the newly explicit full-suite root families increase the honest forecast and reduce weighted completion to 75%. |
| `2026-09-02 05:18 +02:00` | 80-115h | unchanged | The exact last-failed rerun is now 47 failures and 25 passes in 287.46s. `_ConfigCrts` closes with failing-before regressions, live `validation=passed`, and green quality, mandatory, and expanded pipelines; its separate COD block-lift fixture remains independently red and is the next investigation. The weighted total remains 75% after rounding. |
| `2026-09-02 06:44 +02:00` | 80-115h | unchanged | The exact last-failed rerun is 34 failures and 25 passes in 237.00s. F14 regenerated global reads and `_MousePOS`'s dead physical-register carrier close with live validation, compile, liveness-refusal, and `quality-dev` evidence. These improve the still-open shared Ghidra/full-suite task but do not complete a weighted milestone, so total progress remains 75%. |
| `2026-09-02 08:04 +02:00` | 80-115h | unchanged | The CARR scalar/wide predicate family closes at the existing Types/Lowering and Structuring owners with validation, focused tests, `quality-dev`, and the mandatory external pipeline green. The exact last-failed rerun improves from 34 to 32 failures while retaining 25 passes and finishes in 237.88s. The remaining failures still span independent call/type, segmented-memory width, CFG, and SORTD regeneration families, so the weighted total and forecast remain 75% and 80-115h. |
| `2026-09-02 08:30 +02:00` | 80-115h | unchanged | Four stale assertions are corrected only where current output is source-equivalent, recompilable, and reports `validation=passed`: Ready5's word store, F14 LookUp's hexadecimal literal, ReInitBars' explicit cast/control shape, and portable `main`'s hexadecimal mode constant. BubbleSort's direct calls likewise accept explicit ABI casts. The exact last-failed lane is now 27 failures and 26 passes in 167.42s; DOS pointer typing, overlay uninitialized storage, SetGear flag provenance, and the remaining semantic families stay red. |
| `2026-09-02 09:25 +02:00` | 80-115h | unchanged | The `pointer_memory` timeout is closed at Types/Lowering: indexed x86 addresses recognize one unambiguous argument carrier, and prototype replay joins entry-SP C variables to annotations by machine-BP identity. Failing-before tests, 77 related tests, direct Ruff/MyPy, live `fill_bytes`, and the complete three-function construct pass; generated runtime finishes instead of timing out. The weighted total remains 75% because the complete-suite and remaining SORTD semantic families are still open. |
| `2026-09-02 09:39 +02:00` | 80-115h | unchanged | The mandatory pipeline is green with 1,923 tests and every required MS C runtime construct. The exact last-failed lane is 26 failures and 25 passes in 224.10s. DOS `loadProgram` now retains its two pointer outputs, but its invalid casted low-byte lvalue and missing return flow remain the next independent root. |
| `2026-09-02 10:45 +02:00` | 80-115h | unchanged | DOS `_dos_loadProgram` is closed across both CLI shapes. Exact PUSH provenance removes the invalid split carrier; typed AX-to-stack binding, machine-BP object identity, and a bounded return-register-preserving epilogue proof materialize both returns at their owning layers. Focused Ruff/MyPy, 83 related checks with only the already-known larger `loadprog` body failure, `quality-dev` with 1,923 tests, and the mandatory external pipeline pass. The weighted total remains 75% pending the refreshed full-suite lane and remaining COD/SORTD families. |
| `2026-09-02 11:53 +02:00` | 80-115h | unchanged pending exact audit | The larger DOS `loadprog` body closes in 35-45 focused minutes. A typed four-byte stack owner now supplies exact validation subviews, and Structuring refuses a multi-predecessor linear return scan before recovering each exact-tagged terminal value from its own CFG predecessor. Generic failing-before tests, 261 related checks, direct Ruff/MyPy, live COD validation, portable recompilation, and `quality-dev` pass. The weighted total and forecast remain unchanged until the exact full collection refreshes the remaining independent failure families. |
| `2026-09-02 13:01 +02:00` | 80-115h | unchanged pending exact audit | The refreshed exact collection establishes a 10,132 collected / 9,931 passed / 31 failed / 170 skipped baseline in 1,314.23s. Three infrastructure defects and four stale semantic-shape assertions are closed. HeapSort's remaining pointer-argument defect is then closed generically by transporting validated callee evidence across project views; focused validation, strict C11 syntax, Ruff, MyPy, architecture checks, and `quality-dev` pass. About 23 failures are projected, not confirmed, until the next exact audit. |
| `2026-09-02 16:08 +02:00` | 80-115h | unchanged pending exact audit | The exact full audit remains 10,137 collected / 9,944 passed / 23 failed / 170 skipped in 852.88s; the exact last-failed rerun remains 19 failed / 3 passed in 221.20s. Architecture enrollment, one stale fixture, four cosmetic assertions, and DrawBar's function-wide coordinate drift are closed. The final local-only coordinate rule passes an uncached DrawBar gate, 101 focused tests, `quality-dev` with 1,924 tests, and the mandatory pipeline; `scalar_types_io` recompiles and exits `255`. About 13 failures are projected, not confirmed, until the next exact audit. |

Current expected finish for the complete plan is **80-115 focused engineering
hours**, approximately **2.0-3.8 working weeks** at 30-40 focused hours per
week, or roughly **2026-09-16 through 2026-09-29** if work continues at that
rate. The midpoint forecast is about **98 focused hours / 2026-09-22**.
This is a range, not a calendar promise: newly exposed semantic failures can
increase it. The next recalibration occurs after the complete focused-lane
DoD for each subsequent family, using measured focused time per independent
root cause rather than the raw count of failing tests.

## Historical Measured Baseline

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

Latest required-gate verification on 2026-08-28 passes all three default lanes
with zero failures, skips, or timeouts. The focused lane passes 1,841 tests in
66.77 seconds; all four Ultra QuickC fixtures pass in 55.39 seconds; and all
seven MS C tiny constructs pass their compile, original-run, decompile,
recompile, and decompiled-run contracts in 55.89 seconds. The focused lane
remains over its historical 30-second soft budget and is retained as
performance debt, not hidden as a correctness pass. The hard gate also passes
Ruff `--fix`, strict MyPy over 224 source files, the 38-module mypyc
compile/import smoke, architecture and ownership checks, and 1,841 tests. The
generated-C quality comparisons pass without semantic-quality regression.

This rerun caught a real `scalar_types_io/byteops_unsigned` validation
regression after the byte-safe frontend work: word-aligned frame bindings were
incorrectly replacing the proven one-byte access width of direct stack
variables. Tail Validation now keeps direct access width distinct from frame
allocation width. The focused construct decompiles all ten functions, validates
cleanly, recompiles, and returns the expected 255; the full default pipeline
keeps that behavior as a permanent external gate.

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

### Closed P0: Semantic completeness

The current edited tree passes the strict executable-only 20/20 gate with zero
validation failures or unsupported-instruction output. RunMenu `0x102e0` keeps
its Escape return, and DrawTime/QuickSort consume byte-executed stack slices
through complete Alias range evidence rather than Rewrite or CLI repair.

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

Default N-1 clean-process execution is working with seven workers on this
eight-CPU host. The current cold run is 278.41 seconds and an unchanged-tree
replay is 95.90 seconds. Accepted results are cached; failed results are always
revalidated. The remaining serial tail requires pass-level optimization inside
complex functions, not more worker fan-out or mutable shared-project rebuilds.

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

Measured maintenance on 2026-08-21:

- the real strict 20-function payload exposed three compatible return-contract
  variants: K&R `unsigned short` versus `unsigned long`, and exact-parameter
  `void` versus return-capable `int` declarations. These are now joined by one
  typed export-contract owner; incompatible parameter or return classes remain
  hard assembly conflicts
- declaration joining moved into the 177-line
  `generated_external_function_contracts.py` module, reducing
  `generated_translation_unit_assembly.py` from 370 to 235 lines without
  changing function bodies
- direct binary candidate inventory and the selected function queue are again
  reported as distinct counts; the strict gate now reports 20 queued and 20
  materialized functions instead of relabeling 254 raw candidates as queued

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

Fresh verification on 2026-08-22 passes all five expanded lanes with zero
failures, skips, or timeouts: the focused Python lane completes in 45.196
seconds, Ultra QuickC passes 4/4 fixtures and validation, and all seven MS C
tiny constructs pass compile/run/decompile/recompile/decompiled-run checks.
Sidecar-free SORTD decompiles 20/20 functions with zero validation failures,
timeouts, or tracebacks; its canonical translation unit compiles and the 19
source-selftested bodies pass the generated behavior gate. The independent
status/source-contract scoreboard passes 20/20. `quality-hard` also passes
Ruff `--fix`, strict MyPy for 121 source files, the mypyc build/import smoke,
architecture/context/ownership checks, and generated-C comparisons.

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
- VEX import now resolves callable pyvex result types through the block type
  environment and converts their bit widths to exact byte widths. Byte
  interrupt stores therefore remain byte stores through IR, Lowering, and
  final validation instead of being silently promoted to words.
- IR owns two lossless normalizations: exact same-instruction little-endian
  byte micro-operations coalesce into one machine access, and an exact
  JCC-only transport load is rebound to the immediately preceding CMP value.
  Frontend VEX topology remains unchanged because altering it regressed the
  Ultra QuickC `args` control flow and duplicated one distinct call argument.
- The fresh sidecar-free SORTD indexed-address census closes at 42 raw facts,
  36 normalized facts, six coalesced facts, 36 classified facts, 35 Alias
  materializations, and one explicit refusal. Collector parity reports 31
  matches, four Alias-only pointer accesses in `0x107b8`, eight legacy-only
  BP/SS false positives, and zero identity conflicts.
- The complete checkpoint passes the 499-test changed-file gate, a broader
  112-pass/65-skip semantic selection, all 1,673 default-pipeline tests, all
  four Ultra QuickC fixtures, and all seven MS C tiny compile/decompile/
  recompile/runtime cases. The hard gate also passes Ruff `--fix`, strict
  MyPy, architecture/context/ownership checks, mypyc compile/import smoke for
  38 modules, and all three generated-C quality comparisons.
- Callsite summaries now retain the exact decoded return-store instruction
  address instead of dropping it after classifying destination and width.
  Structuring uses that typed address, the exact call instruction tag, and one
  unique adjacent sequential ownership witness to bind call results across
  unrelated angr dirty carriers; dirty IDs and rendered names are not proof.
- The uncached sidecar-free `_TIDShowRange` regression now emits
  `mseg = MapInEMSSprite(2, 0); if (mseg)` and preserves all arguments. Its
  uninitialized AX condition is closed, reducing the final def-use failures
  from 39 to 31. The 116-test callsite/Structuring surface, Ruff `--fix`,
  strict MyPy, and architecture checks pass.
- Structuring shared-tail replay exposed one projection disagreement at the
  `_RectCopy` callsite `0x1085`: two statements referenced the same structured
  call node, but the callsite summary classified its return as used. The exact
  machine witness is `lcall 0x11e, 6; add sp, 0x10; sub ax, ax`; the final
  instruction clobbers the return value rather than consuming it.
- Semantics now owns exact `sub reg, reg` and `xor reg, reg` zero-idiom facts.
  Both bounded and linear caller return-use classifiers consume that single
  fact and classify the witness as `CLOBBERED`; Structuring can therefore
  coalesce the duplicate statement occurrence without postprocess repair.
  Focused Ruff `--fix`, strict MyPy for the four touched source modules, and 16
  return-use/shared-tail tests pass.
- Two uncached real `_TIDShowRange` runs retain exactly two body-level
  `_RectCopy` calls and report zero duplicate-callsite or multiplicity
  diagnostics. The previous segmented-write mismatch is absent from the
  current final verdict.
- Alias now consumes the generic decoded register reaching-source proof at
  exact condition-producer boundaries. The `_TIDShowRange` roots close at two
  raw self-test candidates, two classified storage identities, two materialized
  bindings, and zero failures: `mseg` is `SS:BP-0xc`, while the switch selector
  is `DS:0x7002`. The existing Alias carrier owner then propagates the selector
  through the exact `DEC AX` chain and materializes comparisons against `1..4`.
  Explicit ES absolute loads refuse DS identity, and competing owned bindings
  hard-fail. The prior 88 unresolved SSA register-carrier reads are absent.
- The focused source-binding/carrier/reaching-source surface passes 25 tests;
  the changed-file gate passes Ruff `--fix`, strict MyPy for six non-test
  modules, type/docs ratchets, architecture/context/ownership checks, and 64
  selected tests.
- Structuring now owns regenerated aliases of one exact stored call result.
  It requires one unique typed `SS:BP+offset` destination and same-sequence C
  AST dominance with no intervening destination write, unrelated call, or
  control transfer; ambiguous or nested occurrences refuse without mutation.
  Machine source order is deliberately not used because every regenerated
  occurrence carries the same original VEX position.
- The uncached real `_TIDShowRange` run closes at one raw, normalized,
  classified, and materialized ownership fact with zero failures and two
  rewritten aliases. Final C contains exactly one body-level
  `mseg = MapInEMSSprite(2, 0);`, preserves `if (mseg)`, reports
  `validation=passed`, and passes whole-tail validation.
- Eight focused ownership tests, the 60-test shared-call/Structuring surface,
  Ruff `--fix`, strict MyPy, and architecture checks pass. The prior CLI smoke
  test no longer accepts timeout as success; its fresh seven-worker real run
  passes in 219.27 seconds and enforces exact call counts and validation.
- Types/Lowering now publishes every condition-derived and binary-proven
  pointer interface to the authoritative prototype registry before later
  stack/segment replays. A stale same-precedence CCA snapshot can no longer
  restore unsigned arguments over signed `ConditionIR` or restore scalar
  arguments over a proven pointer class; stronger signature/user snapshots
  still win.
- Parameter validation now distinguishes logical C width from ABI stack-slot
  width. A byte scalar in a two-byte MS C slot may match either projection,
  while a logical type wider than its storage or a width matching neither
  projection refuses validation.
- The terminal-call Types/Lowering owner now replaces an inferred `void`
  prototype only when closed caller-use evidence, a typed callee return, and an
  exact AX-preserving terminal path agree. It publishes that contract before
  Structuring materializes `return callee(...)`; explicit signature/user
  prototypes remain immutable.
- The real `compare16`, `simple_control`, `function_pointers`,
  `pointer_memory`, and `scalar_types_io` fixtures compile, decompile,
  recompile, validate, and return `255`. `select_and_apply` retains the required
  returned `apply_twice` call, and `fill_bytes` retains its byte-pointer
  interface. The focused condition/terminal-return/validation surfaces pass
  216 tests, and the full required pipeline passes 3/3 lanes.

Remaining task-3 work: materializing indexed, indirect, stack, and broader
multi-output live-out storage plus stack effects beyond closed terminal `ret`
cleanup. Exact stable direct DS/ES must-write outputs and
their caller-side condition uses now enter the same storage contract only when
every target-reaching caller path preserves the call output; mixed-path and
partial-overwrite cases refuse. Input trials, exact reaching-definition binding,
scalar/pointer register outputs, all strict/non-strict/equality `DX:AX`
condition forms, recursive return pass-through propagation, SCC-wide
production publication, and one transaction that updates definitions and
callsites are implemented.

### 4. Keep discovery and semantic-loss ratchets permanent

Status: complete; the current strict whole gate is 20/20 with zero discovery,
materialization, fallback, validation, timeout, or traceback failures.

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

Status: in progress; primary N-1 execution, accepted-result caching, and
complexity-prioritized clean-worker submission are complete, while aggregate
PSS verification and per-function hot-path work remain.

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

Measured maintenance on 2026-08-21: the frontend `Memory` wrapper no longer
defines a custom destructor merely to delete its owned bytearray. A SIGALRM
timeout could interrupt that destructor with the `BaseException`-derived
`AnalysisTimeout`, producing an unraisable traceback after successful
decompilation. Normal Python ownership now releases the bytearray, and a
structural regression prevents the unnecessary destructor from returning.

Fixed-budget decompiler measurements must also wait for codebase-memory indexing
to become idle. One automatic graph refresh consumed about 6.6 CPUs and 8 GiB
RSS, causing the unchanged 50-second startup catalog to close at 17/20 and then
19/20 entries. The same edited tree closed at 20/20 once indexing finished; do
not weaken discovery or validation timeouts to hide external host contention.

Measured maintenance on 2026-08-27:

- pure-binary clean-process failures no longer trigger an evidence-identical
  in-process retry; sidecar-backed retries remain when evidence can differ
- the remaining replay cost belongs to uncached failed functions; caching their
  failure payloads is forbidden because failure details vary under contention

Measured maintenance on 2026-08-28:

- clean workers now use deterministic longest-processing-time-first submission
  from the already available block/byte complexity estimate; result collection
  and C emission retain original stable indexes
- on the same edited tree, workers, environment, and binary, wall time fell from
  259.25s to 211.86s (47.39s, 18.3%) while user CPU stayed effectively flat at
  1161.45s versus 1153.79s. The generated C files are byte-identical, all 20
  functions decompile, asm/detail fallback remains zero, and whole-tail
  validation is clean
- the earlier 440.56s longest-first experiment is superseded: it did not use
  this bounded clean-worker submission contract and was not a valid predictor
  for the current queue. Remaining speed work must profile internal passes,
  especially the 42-block QuickSort worker that still closes the final wave

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

- tasks 8.1 through 8.11 meet their individual DoD in pipeline order
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

Status: complete; exact `SS:BP+offset` ranges partition into canonical byte
cells with versioned definitions and joins through IR and Alias. Widening now
accepts a composed byte-view component only when every range is nested under
one unique Alias-equivalent owner, and Lowering materializes that owner. General
non-laminar contained views are now covered. Exact call-bearing direct scalar
writes are covered when typed call effects prove that the unique owner survives;
the project-wide multi-function semantic-artifact handoff is complete. The
overlap, escape, one-branch SP-change, and DS/SS-collision negative-fixture DoD
is complete. Sidecar-free DrawFrame and DrawTime retain clean Lowering-owned
locals without setup temporaries, and InitMenu no longer conflates its `BP-2`
loop local with an unreferenced `BP+2` control-slot declaration.

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

Implement the equivalent in Inertia's IR, Alias, Widening, and Lowering layers:

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
- Widening owns composed stack-object proof. It accepts only a connected overlap
  component whose ranges are all contained by one unique owner with consistent
  Alias storage, and carries every source access, fact, version, and byte phi
  into the accepted artifact. Partial sibling overlap is accepted only when
  that owner contains every range; ownerless partial overlap, missing or
  ambiguous ownership, inconsistent storage, and orphan views refuse the whole
  component.
- Lowering consumes that exact Widening artifact instead of rediscovering
  storage. Missing, stale, or incomplete Widening fails the pipeline; a refused
  component suppresses every covered exact fragment so no partial local can
  escape. Existing exact-range materialization remains unchanged.
- Structured-C word recomposition now treats AST variables only as a
  materialization target. It consumes the current complete Widening artifact,
  requires exact function, `SS:BP`, owner, low-byte, and high-byte ranges, and
  refuses missing, stale, ambiguous, cross-region, wrong-offset, or wrong-scale
  evidence. The declared projection pass runs after its artifact producer; the
  previous independent `SimStackVariable` ownership reconstruction is removed.
- A typed Widening resolver now classifies each structured stack view as
  `NOT_CANDIDATE`, `ACCEPTED`, or `REFUSED` against the current object artifact.
  Proven low/high byte reads project from the unique word owner, and pure byte
  assignments become tag-preserving read/modify/write assignments to that
  owner. A call-bearing RHS is accepted only when every tagged C callsite maps
  one-to-one to an exact IR call effect that proves the complete owner range is
  preserved. Untagged, mismatched, duplicate, incomplete, and clobbering call
  evidence refuses; other side effects remain unchanged. Stale, refused,
  ambiguous, cross-function, and unmaterialized owners cannot bypass the typed
  decision.
- Scalar-view expression construction is isolated from proof resolution and
  supports exact byte or word subranges of proven 2-byte and 4-byte owners.
  Reads use unsigned owner-width shifts and masks; pure writes preserve every
  non-view bit with a tag-preserving read/modify/write assignment. Unsupported
  three-byte views refuse, and the older two-byte recomposition fold remains
  word-only so a dword owner cannot replace a partial value. Nested pure RHS
  reads are projected before the containing-owner write is finalized.
- The immediate object Widening, Lowering, and artifact-backed projection
  lifecycle passes 46 focused cases. Sidecar-free ExchangeSort, DrawFrame,
  DrawTime, and InitMenu compilation/validation regressions pass. Ruff `--fix`,
  strict MyPy, mypyc smoke, architecture/context/ownership gates, and all three
  quality comparisons pass. The mandatory seven-worker pipeline is 3/3 green:
  1,548 focused tests, four validated Ultra QuickC fixtures, and all seven MS C
  tiny compile/run/decompile/recompile/decompiled-run constructs; no lane
  failed, skipped, or timed out.
- Project-wide exact-function SSA now has one IR-owned readiness registry. Raw
  `IR` artifacts may upgrade once to canonical `SEMANTIC` artifacts; they cannot
  downgrade, and divergent same-stage publication refuses without replacing
  accepted evidence. The main Semantics path publishes its call-effect-enriched
  artifact, while lazy exact-function lookup performs the same enrichment for
  interprocedural consumers.
- Types/Lowering storage-trial, return, and live-out consumers now require the
  Semantics-ready registry artifact instead of rebuilding an independent raw
  SSA view. Two-function tests prove independent address caching, replay object
  identity, typed missing-function refusal, one-way upgrade, and conflict
  refusal. The broader interprocedural surface passes 120 tests, and six real
  sidecar-free SORTD regressions pass with compilation and validation intact.
- The closed checkpoint passes Ruff `--fix`, project-wide MyPy, mypyc import
  smoke, architecture/context/ownership checks, and all three quality
  comparisons. The mandatory seven-worker pipeline is 3/3 green: 1,582 focused
  tests, four validated Ultra QuickC fixtures, and all seven MS C tiny
  compile/run/decompile/recompile/decompiled-run constructs; no lane failed,
  skipped, or timed out.
- The explicit branch-dependent `SS:SP` join fixture now proves the
  correctness-first refusal path end to end: IR reports
  `unproven_stack_range`, Alias retains the typed upstream refusal, and
  Lowering creates no candidate or C local. The equal-offset explicit DS/SS
  fixture proves that DS remains a distinct typed address outside stack SSA and
  only the SS owner can materialize. No production semantic workaround was
  required; the existing IR -> Alias -> Lowering ownership boundary was
  already conservative. Both fixtures are enforced by the Makefile and focused
  pipeline. The checkpoint passes 31 focused tests, six real SORTD regressions,
  `quality-dev`, and all three mandatory pipeline lanes: 1,584 focused tests,
  four validated Ultra QuickC fixtures, and all seven MS C tiny constructs.
- Types/Lowering now owns declaration-map cleanup separately from argument
  inference. It classifies exact Alias stack identities below the first ABI
  argument, removes only declarations absent from both the function body and
  header, and refuses unknown-width, ABI-crossing, body-owned, header-owned,
  and overlapping views. Typed evidence reports raw, normalized, classified,
  materialized, failed, and refused facts; classified facts cannot silently
  produce zero materializations.
- The sidecar-free InitMenu regression now rejects any surviving `BP+2`
  declaration owner while preserving its calls, strict portable-flat compile,
  `validation=passed`, and clean whole-tail result. Fresh DrawFrame and DrawTime
  captures retain their clean local shapes. The first cold isolated InitMenu
  run reached clean validation but hit the unchanged 180-second watchdog; the
  warm acceptance passed in 72.2 seconds, so no timeout was relaxed and the
  cold-path variance remains performance debt under task 6.
- Seven declaration-identity cases and the existing eight argument-identity
  cases pass. Ruff `--fix`, strict MyPy, mypyc import smoke, architecture,
  context, ownership, and `quality-dev` gates pass. The mandatory seven-worker
  pipeline is 3/3 green with 1,589 focused tests, four validated Ultra QuickC
  fixtures, and all seven MS C tiny compile/run/decompile/recompile/decompiled-
  run constructs.

This should remove Ghidra-like stack setup temporaries from DrawFrame,
DrawTime, and InitMenu without moving stack recovery into Rewrite. Negative
tests must cover overlapping locals, SP changes on one branch, escaped stack
addresses, and DS/SS offset collisions.

Definition of done:

- exact SS ranges have versioned definitions, phi joins, byte-accurate overlap
  handling, and typed call delta/clobber effects in IR/Alias
- every accepted composed view has one unique Alias-equivalent Widening owner;
  every unresolved component refuses atomically before Lowering
- DrawFrame, DrawTime, and InitMenu improve through Lowering-owned locals while
  every listed overlap/SP/escape/segment fixture refuses unsafe materialization
- evidence counters close and validation, behavior, and recompilation remain
  green

Definition of failure:

- stack identity is reconstructed from rendered C, variable names, or raw
  numeric proximity, or DS and SS storage are conflated
- an unknown stack delta, overlap, escape, or clobber is silently ignored
- Lowering bypasses, recreates, or accepts a stale/incomplete Widening decision
- locals are discovered in Structuring/Rewrite or any required effect regresses

#### 8.2 Recover call and return contracts from storage trials

Status: in progress. Exact input storage-trial collection, `DX:AX`
direct-global return materialization, replay-safe call accounting, exact
final-callsite multiplicity validation, regenerated stored-result alias
ownership, deterministic return/live-out trial
collection, signed/unsigned strict and non-strict `DX:AX` ordering use typing,
sign-insensitive equality/inequality use typing, recursive pass-through
propagation, production SCC publication, and atomic callee plus callsite type
application are complete. Exact terminal call-result passthrough now also
updates inferred caller return types before Structuring while preserving
explicit signature/user interfaces. Exact direct DS/ES must-write live-outs with condition
uses preserved on every target-reaching caller CFG path are implemented,
including a deterministic union when different callers consume disjoint proven
outputs. Nested overlapping direct views now materialize only through a unique
maximal Alias owner. Widening projects exact and contained direct caller views
from that owner, retaining the proven byte offset and exact access width before
Types/Lowering creates a trial. Every project-wide trial, return, and live-out
consumer now reads the canonical Semantics-ready exact-function SSA artifact.
RunMenu call-result-to-stack materialization is complete. The first terminal
pointer-parameter output slice reaches a logical callee-parameter registry;
exact caller-target projection from expression reaching definitions and typed
callsite effect/object materialization are complete. Proof-driven pointee/object
typing, indexed effects, and broader object-type materialization remain.

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
  follows every authoritative SSA CFG path that can reach the candidate use,
  and activates a live-out trial only for the direct load named by canonical
  `ConditionIR`.
  VEX JCC replay loads do not become duplicate machine uses; absent uses remain
  inactive rather than being invented
- signed/unsigned ordering, equality, and zero-use evidence retain exact
  storage, callsite, definition, condition, and signedness. A full exact write
  on every target-reaching path becomes `NOT_REACHED`; a clean/write join or a
  partial overlapping write is `INTERVENING_WRITE`. Indirect aliases, calls,
  cycles, incomplete CFG, target mismatch, conditional callee writes, and
  conflicting signedness remain typed refusals
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
- one dedicated Types/Lowering join owner now forms the deterministic union of
  exact `LIVE_OUT` storage across a complete caller census. Different callers
  may consume disjoint proven outputs from one callee without forcing every
  callsite to have an identical live-out subset. Input and scalar-return roles
  retain their identical-shape agreement requirement
- the join refuses same-storage type conflicts, duplicate storage within one
  callsite, malformed trial roles, and incomplete caller censuses. A primitive-
  field total-order key keeps mixed DS/ES storage deterministic without
  comparing raw enums. Seven focused tests cover disjoint, multiple-output, and
  mixed DS/ES acceptance plus each refusal. The owner is 252 lines, and
  extracting it reduced the function solver from 350 to 262 lines
- the edited-state `quality-dev` gate passes Ruff `--fix`, MyPy, the 38-module
  mypyc compile/import smoke, architecture/context/ownership checks, 1,598
  tests, and all three decompilation-quality comparisons. The required pipeline
  passes 3/3 lanes with the same 1,598 tests, 4/4 validated Ultra QuickC
  fixtures, and all seven MS C tiny build/run/decompile/recompile/decompiled-run
  constructs
- RunMenu's exact `call 0x11292; mov [bp-2], al` evidence was already collected
  correctly, but the Types/Lowering classifier required the impossible
  production state `stack_cleanup == 0`; callsite collection represents the
  absence of a positive caller cleanup as `None`. The classifier now accepts
  `None` or legacy `0` only when argument count and widths are exactly empty,
  while contradictory positive cleanup remains a typed refusal
- the strict sidecar-free RunMenu regression now materializes
  `local_2 = sub_11292();`, retains the subsequent value argument and Escape
  exit, passes strict portable-flat compilation, `validation=passed`, and clean
  whole-tail validation. The permanent regression requires both the assignment
  and Escape case; the focused callsite/Lowering surface passes 100 tests
- the closed checkpoint passes Ruff `--fix`, MyPy, the 38-module mypyc compile/
  import smoke, architecture/context/ownership checks, 1,598 focused tests, and
  all three quality comparisons. The mandatory seven-worker pipeline passes all
  three lanes with 4/4 Ultra QuickC fixtures and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run constructs; no lane failed, skipped, or
  timed out
- the frontend now classifies `cmp r8, imm8` and transfers an exact low-byte
  direct `DS`/`ES` provenance through an equal-width register copy. High-byte
  and transformed carriers explicitly refuse transfer. VEX import retains the
  parent 16-bit register storage identity while recording the one-byte effect
  width
- real producer and interprocedural regressions prove that
  `mov al, [mem]; mov bl, al; cmp bl, 0` reaches the canonical exact-function
  SSA artifact and materializes the required `LIVE_OUT` trial
- the strict sidecar-free gate passes 20/20 attempted, classified, decompiled,
  materialized, normalized, queued, raw, and selected functions with zero
  timeout, traceback, discovery, empty-output, validation, or policy failures
- the final edited-state `quality-dev` gate passes Ruff `--fix`, MyPy, the
  38-module mypyc compile/import smoke, architecture/context/ownership checks,
  1,604 focused tests, and all three generated-C quality comparisons
- the mandatory seven-worker pipeline passes 3/3 lanes: the same 1,604 focused
  tests, 4/4 validated Ultra QuickC fixtures, and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run constructs with matching exit code 255;
  no lane failed, skipped, or timed out
- the prior caller path proof used `any(...)`, so one clean successor could
  short-circuit traversal and hide a sibling write, unknown alias, or call before
  both paths merged at the same condition load. A dedicated 292-line
  Types/Lowering owner now computes reverse target reachability and joins every
  target-reaching path as `CLEAN`, `OVERWRITTEN`, `NOT_REACHED`, or
  `UNKNOWN_REFUSE`; disconnected branches and exits remain irrelevant
- fifteen focused regressions cover mixed clean/write, clean/alias, clean/call,
  partial overlap, full overwrite, disconnected load, and a blocked branch that
  cannot reach the load. The materializer shrank from 340 to 242 lines, and the
  new owner is registered in the Ruff, MyPy, architecture, and test-ownership
  inventories
- the strict sidecar-free edited-state gate passes 20/20 with zero fallback,
  timeout, traceback, discovery, empty-output, validation, or policy failures.
  All 12 bodies emitted by the timeout-limited pre-change run are byte-identical;
  the edited run additionally emitted the eight pre-change timeout functions
- the final `quality-dev` gate passes Ruff `--fix`, MyPy, the 38-module mypyc
  compile/import smoke, architecture/context/ownership checks, 1,610 focused
  tests, and all three quality comparisons. The mandatory seven-worker pipeline
  passes the same 1,610 tests, 4/4 Ultra QuickC fixtures, and all seven MS C tiny
  build/run/decompile/recompile/decompiled-run contracts with exit code 255
- closed `UNUSED` caller-return evidence now permits the existing Types/Lowering
  owner to demote an exact synthetic terminal zero to `void`, even when the
  terminal machine state still carries `AX`. Nonzero constants, variable
  returns, effectful call returns, and incomplete caller censuses remain scalar
  or refuse demotion
- the sidecar-free SORTD artifact changes only four source-void functions:
  InitMenu, RunMenu, Swaps, and QuickSort. Their signatures become `void` and
  synthetic `return 0;` statements become bare returns; all calls and other C
  statements are byte-identical to the preceding artifact. The strict gate now
  requires RunMenu's binary-proven `case 27: return;`, and rejects either a
  scalar RunMenu signature or an Escape `break`
- the edited-state strict gate passes 20/20 functions with zero fallback,
  timeout, traceback, discovery, empty-output, validation, or policy failures.
  Focused positive and refusal regressions pass; `quality-dev` passes Ruff,
  MyPy, mypyc smoke imports, architecture/context/ownership checks, 1,612 tests,
  and all three quality comparisons. The mandatory seven-worker pipeline passes
  the same 1,612 tests, 4/4 Ultra QuickC fixtures, and all seven MS C tiny
  build/run/decompile/recompile/decompiled-run contracts
- Semantics now retains the exact terminal-path partition for stable direct
  `DS`/`ES` outputs: store sites, all entry-reachable return terminals, and the
  subset definitely written before return. `MUST_WRITE` and `CONDITIONAL`
  dispositions are valid only when that typed path evidence is internally
  complete and coherent
- Types/Lowering projects a conditional output as an explicit `MAY_WRITE`
  memory effect through caller collection and the accepted atomic function
  contract. It never invents an unconditional `CALL_OUTPUT` definition or value
  trial. Conversely, a must-write effect without its exact value trial and a
  conditional effect with such a trial both refuse the whole contract
- positive and refusal coverage passes across 129 Semantics and
  interprocedural-storage tests. Ruff `--fix`, focused MyPy, types/docs ratchets,
  mypyc smoke imports, and explicit graph-available architecture/context/
  ownership checks pass. The strict sidecar-free gate remains 20/20 with zero
  fallback, timeout, traceback, discovery, empty-output, validation, or policy
  failures
- the edited-state `quality-dev` gate passes 1,617 tests and all three generated-C
  quality comparisons. The mandatory seven-worker pipeline passes the same
  1,617 tests, 4/4 Ultra QuickC fixtures, and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run contracts; no selected lane failed,
  skipped, or timed out
- the sidecar-free ReInitBars baseline already emits exactly one
  `g_0BA6 = sub_1137e();` assignment with `unsigned long` callee and global
  declarations, strict GCC acceptance, `validation=passed`, and clean whole-
  tail validation. Its regression now guards the full 32-bit declaration
  contract instead of prompting a false implementation fix
- Semantics now publishes each exact overlapping direct `DS`/`ES` range with
  terminal-path evidence and does not decide storage ownership. Alias binds
  every range to a segment-preserving identity, records all nested subviews,
  and selects one unique maximal owner. Crossing overlaps, duplicate storage,
  missing Alias facts, and unproven segment origins refuse atomically with all
  five evidence counters
- Alias now owns the typed segmented range relation used by downstream layers:
  exact, contained, contains, crossing, disjoint, unproven, and unknown. DS and
  ES equal numeric offsets remain distinct storage spaces, and incomplete
  overlap evidence cannot be promoted by Widening or Lowering
- Widening now groups direct caller loads under the unique maximal Alias owner
  and publishes exact whole or contained views with the exact byte offset,
  width, instruction sites, and source accesses. Crossing overlap, unproven
  range identity, conflicting widths, and conflicting storage refuse the whole
  view collection with closed evidence counters
- Types/Lowering consumes the Widening view instead of rediscovering overlap.
  It creates the `CALL_OUTPUT` definition and storage trial at the projected
  view's exact range; caller-path analysis uses the Alias-owned relation to
  distinguish a disjoint write from a full or partial overwrite
- positive and refusal coverage passes across the Semantics, Alias, live-out,
  and storage-slot surfaces. The changed-file gate passes 668 tests with Ruff
  `--fix`, MyPy, types/docs, architecture/context, and ownership checks. The
  strict executable-only SORTD gate remains 20/20 with zero timeout, traceback,
  discovery, empty-output, validation, or policy failure
- the edited-state `quality-dev` gate passes 1,622 tests, the 38-module mypyc
  compile/import smoke, and all three generated-C quality comparisons. The
  mandatory seven-worker pipeline passes 3/3 lanes: the same 1,622 tests, 4/4
  validated Ultra QuickC fixtures, and all seven MS C tiny build/run/decompile/
  recompile/decompiled-run contracts; no lane failed, skipped, or timed out
- contained high-byte production integration, duplicate-load grouping,
  segment separation, disjoint-write preservation, whole-owner overwrite, and
  crossing/unproven/conflicting refusal fixtures pass. The changed-file gate
  passes 672 tests with Ruff `--fix`, MyPy, types/docs, architecture/context,
  and ownership checks. The strict executable-only SORTD gate remains 20/20
  with zero timeout, traceback, discovery, empty-output, validation, or policy
  failure
- the edited-state `quality-dev` gate passes the 38-module mypyc compile/import
  smoke and all three generated-C quality comparisons, with measured candidate
  speedups of 7.484x, 4.817x, and 4.304x and no quality regression. The
  mandatory seven-worker pipeline passes 3/3 lanes: 1,633 focused tests, 4/4
  validated Ultra QuickC fixtures, and all seven MS C tiny build/run/decompile/
  recompile/decompiled-run contracts
- Types/Lowering now joins every exact whole or contained caller projection
  under one canonical Alias-owned memory-output object. Register and sequence
  returns remain scalar function outputs, while exact callsite views retain
  their Widening provenance. DS and ES remain distinct ownership spaces
- conflicting owners, crossing ranges, missing, extra, or duplicate trials,
  and signedness or value-class conflicts refuse the object transaction with
  closed evidence counters. Seven focused object tests cover whole/high-byte,
  disjoint-caller, segment, conflict, missing, duplicate, and orphan cases
- the focused object/storage surface passes 23 tests. The changed-file gate
  passes Ruff `--fix`, MyPy, types/docs, architecture/context, ownership, and
  628 selected tests; strict executable-only SORTD remains 20/20, and
  `quality-dev` passes its mypyc and generated-C comparison gates. The
  mandatory seven-worker pipeline passes 3/3 lanes: 1,640 focused tests, 4/4
  validated Ultra QuickC fixtures, and all seven MS C tiny build/run/decompile/
  recompile/decompiled-run contracts; lane times are 29.266s, 55.004s, and
  82.097s with zero failure, skip, or timeout
- atomic publication now revalidates each accepted Alias-owned memory object
  against the exact effects and optional `LIVE_OUT` trials retained by the same
  caller/callsite binding. Missing callsites or effects, duplicate owners or
  views, trial mismatches, and orphan effects or trials refuse before the
  project contract surface is mutated
- the transaction proof has typed verdicts, failure reasons, and all five
  evidence counters. Its focused publication/storage surface passes 25 tests,
  including valid replay and four post-solver corruption cases; the diagnostic
  `PipelineHardError` names the typed failure while retaining structured detail
- the `mul_us` scalar fixture exposed two distinct terminal-value defects. The
  Semantics fact for implicit `mul` output now names `AX` as its destination,
  and Structuring consumes the resulting typed AX lineage before a plausible
  but stale `return a;` can bypass it. No semantic repair was added to Rewrite
  or CLI; the startup architecture guard rejected that wrong-layer dependency
- the Structuring owner accepts one fully proven terminal block and one return,
  closes all five evidence counters, and replaces an existing value only when
  the candidate is equivalent or extends its left-hand AX read/modify/write
  lineage. Ambiguous CFGs, multiple returns, unsupported widths, missing proof,
  and unrelated reshaping are typed refusals that preserve the existing body
- tail validation caught the first over-broad implementation widening a byte
  local in `byteops_unsigned`; the non-extension refusal now keeps its exact
  byte storage while allowing `mul_us` to become `return a * b;`. The focused
  171-test surface, Ruff `--fix`, strict focused MyPy, architecture checks, and
  all ten scalar compile/run/decompile/recompile/decompiled-run functions pass
- after the Python/angr dependency upgrade, `fill_bytes` exposed an owned
  Types/Lowering API mismatch rather than a condition-recovery defect. Angr now
  passes a shared recursive-type `memo` into `SimType._with_arch`; the fixed
  16-bit near-pointer implementation used the old signature, so codegen text
  regeneration raised before Structuring or Postprocess validation could be
  collected. Its implementation now preserves and forwards that memo through
  the public architecture-binding contract
- a function-prototype regression exercises the exact recursive binding path.
  Ruff `--fix`, strict focused MyPy, and all 11 focused SimType tests pass; the
  full three-function `pointer_memory` compile/run/decompile/recompile/
  decompiled-run gate is green with clean tail validation and exit code 255
- caller storage trials now build SSA from the Frontend-owned exact function
  boundary rather than a synthetic entry-only block. The old one-block census
  stopped at an early stack-probe call, silently missed later application
  callsites, and refused otherwise proven pointer inputs and returns as
  `CALLSITE_NOT_FOUND`
- the focused multi-block census regression proves every exact block reaches IR
  import. The real `scalar_types_io` `pick_ptr` contract is now accepted as two
  pointer inputs, one scalar selector, and one pointer return; its unchanged
  generated C recompiles and the rebuilt DOS executable returns 255
- next implementation boundary: publish pointer-parameter memory outputs before
  attempting general indexed or indirect effects. In SORTD `Swaps` (`0x107b8`),
  exact IR stores through `BX` at `0x107d7` and `0x107df` retain distinct SSA
  versions; the Alias reaching-source owner proves those versions come from
  callee inputs `SS:BP+4` and `SS:BP+6`, respectively
- the vertical slice must preserve the pointer-relative segment, offset, width,
  store sites, terminal-path disposition, and parameter storage through
  Semantics, Alias, Widening, and Types/Lowering. Caller targets may be projected
  only from each exact reaching argument definition. Ambiguous bases, competing
  parameter sources, partial path coverage, and caller target conflicts must
  remain typed refusals
- conditional, exact whole-owner, contained, overlapping-caller-view, and
  object-owned direct stable `DS`/`ES` effects are complete for their current
  scope and must not be reconstructed from rendered C
- the first pointer-parameter output vertical slice is implemented at its
  owning layers. Semantics retains all four terminal byte stores in sidecar-free
  Swaps `0x107b8`; Alias proves the two distinct BX versions originate at
  `SS:BP+4` and `SS:BP+6`; Widening forms two exact two-byte parameter-relative
  views; Types/Lowering publishes logical output parameters 0 and 1 in one
  project-local typed registry with closed evidence counters
- exact caller memory targets are now projected at the separate Lowering join.
  IR owns exact
  16-bit modular affine traces with constants, stack-derived terms,
  coefficients, logical-word reconstruction, and SSA definition paths;
  Types/Lowering requires that projection to agree with the typed callsite
  source and retains the exact outgoing byte definitions. Carry-dependent,
  malformed, width-conflicting, unsupported, missing, and contradictory
  expressions refuse with distinct typed reasons
- the sidecar-free Swaps census proves and atomically publishes all 18 targets
  across nine callers: 17 exact affine expression arguments, including the
  two-source form at `0x10c8e`, plus the direct `DS:0x0b4c` offset. Each target
  joins the callee-proven `DS` segment and two-byte width without guessing a
  pointee type or converting dynamic storage into a direct global identity.
  The storage lifecycle now publishes this registry immediately after callee
  output views and before input trials
- typed caller effect/object materialization is complete at the function
  contract boundary. The live-out collector partitions all 18 targets by exact
  caller/callsite, the object join groups them into two callee-owned pointer
  outputs with nine views each, and atomic publication revalidates every view
  against the original callsite effect. Dynamic targets never become direct
  `StorageIdentity8616.MEMORY` owners or fabricated scalar `LIVE_OUT` trials;
  duplicate, mismatched, missing, and orphaned facts refuse atomically. The
  next boundary is proof-driven pointee/object typing and code-generation
  consumption, not another effect-recovery pass
- the production integration exposed and removed a cross-layer Semantics veto:
  one same-segment indirect STORE previously erased every independently proven
  direct terminal STORE as a possible alias conflict. Semantics now retains the
  direct fact without claiming disjointness; Alias and interprocedural Lowering
  remain the only owners of the relationship. The real Swaps pipeline test
  carries both effects through the accepted function contract
- Ruff `--fix`, strict MyPy, type/doc/dot-access ratchets, startup architecture,
  context and ownership checks, and the 725-test ownership-expanded
  changed-file gate pass. The mandatory full pipeline passes 1,841 curated
  tests plus all seven MS C tiny compile/decompile/recompile/exit-behavior
  examples; its external semantic summary is three passed, zero failed, zero
  skipped, and zero timed out
- the pointer slice and its adjacent return/declaration ownership fixes pass the
  focused semantic tests, strict MyPy, Ruff `--fix`, and the full sidecar-free
  gate: 20 attempted, normalized, classified, decompiled, and materialized;
  zero timeout, traceback, discovery, empty-output, validation, or policy
  failures. DrawTime and DrawBar declarations consume exact Frontend range
  boundaries when direct-call stubs are empty, and Beep keeps its two-argument
  interface without read-only return probes materializing phantom arguments
- the fresh post-fix sidecar-free SORTD run decompiles 20/20 functions with
  `validation=passed`, clean whole-tail validation, no unsupported instruction
  or assembly fallback output, and strict GCC acceptance. Its 723-line C is
  byte-identical to the pre-fix output; the loaded run took 283.15 seconds at
  451% CPU with 328,380 KiB parent maximum RSS
- direct-stack replay now distinguishes a changed structured statement root
  from newly published typed evidence. Evidence-only publication remains a
  stable C result, duplicate stores remain suppressed, and a failed
  `SemanticLaneState` is never cached as stable, so a repaired materializer is
  retried instead of skipped. Nine focused replay/materialization regressions
  pass with Ruff `--fix` and strict MyPy
- the edited-state `quality-hard` gate passes Ruff `--fix`, strict MyPy across
  224 production files, the 38-module mypyc import smoke, complexity,
  architecture/startup/context/ownership checks, and 1,841/1,841 fast-pipeline
  tests in 84.32s. CMP16, LOOPS, and FPTR generated-C quality comparisons all
  pass; measured candidate speed ratios were 2.641x, 2.176x, and 0.884x
- caller-observed byte-return recovery now has one complete-census join in
  Types/Lowering. It aggregates exact post-call extension evidence, refuses
  empty/provisional/conflicting observations without caching them, and applies
  the accepted signedness to both the function prototype and the final
  regenerated C surface. Focused acceptance, refusal, conflict, and projection
  tests pass, and the uncached real `mix_uc` function renders as
  `unsigned char` with `validation=passed`
- the scalar fixture and both generated runtime harness projections now require
  `mix_uc(64, 0) == 128`; this high-bit assertion closes the signedness hole
  that low-bit arithmetic alone could not detect. Its ten-function full DOS
  pipeline passes compile, original execution, decompilation, validation,
  recompilation, and decompiled execution with expected exit code 255
- the current milestone passes Ruff `--fix`, strict MyPy across 254 source
  files, the 39-module mypyc smoke, 139 callsite/interface tests, 236 segmented
  runtime lowering tests, and 1,871 fast-pipeline tests. The idle-host
  optimization suite and mandatory full `test-pipeline` remain pending because
  a concurrent seven-worker decompilation caused the CMP16 baseline to hit the
  unchanged 180-second timeout before quality comparison

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

Status: in progress; the IR-to-Alias prerequisite and first project-wide
Widening consumer migration are complete. Indexed DS/ES addresses retain exact
versioned terms and Alias storage/index ownership; Widening now owns two-byte
global layout, exact copy-family joins, and the first exact static bounded-range
publication. Types/Lowering consumes that range for exact existing declaration
extents. General type propagation and replacement of the remaining per-function
legacy rendering collectors remain.

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

Measured progress on 2026-08-21:

- `IRAddress.base_values` preserves each dynamic address term as an `IRValue`,
  and block-local SSA assigns the exact register version used by the memory
  access instead of leaving only an unversioned register-name tuple
- the new IR owner classifies every indexed DS/ES load or store and traces the
  supported same-block `MOV`/`SHL` chain to a stable `SS:BP` source; multiple
  terms, missing/conflicting definitions, unsupported expressions, unproven
  addresses, and unsupported shifts remain typed refusals
- all five evidence counters close, direct segmented accesses stay outside the
  indexed census, and the producer does not infer Alias identity, bounds,
  arrays, structures, C types, or rendered expressions
- `X86_16/ir/indexed_address_pipeline.py` publishes the closed IR artifact in
  the main execution path, and `X86_16/alias/indexed_address_projection.py`
  refuses to run when that earlier owner is missing or has the wrong contract
- Alias preserves DS versus ES, displacement, access width, exact index SSA
  value, shift, definition path, and canonical `SS:BP+offset` source range;
  the direct Alias API now refuses symbolic DS/ES addresses instead of
  collapsing them to the constant displacement
- the canonical segmented Alias range builder now accepts negative BP-relative
  stack offsets while retaining nonnegative DS/ES offsets
- `X86_16/lowering/indexed_address_collector_parity.py` publishes a typed,
  non-semantic migration census with matched, Alias-only, legacy-only, and
  duplicate keys; real lifted load and store fixtures have exact parity, while
  divergent and duplicate fixtures remain visible
- nineteen indexed real-lifter, Alias, refusal, and parity regressions pass;
  every inventory mismatch class has a direct regression, repeated same-site
  typed refusals remain visible, and the ownership-expanded focused selection
  passes 75 tests
- `quality-dev` and `quality-hard` pass Ruff `--fix`, strict MyPy, the 38-module
  mypyc compile/import smoke, 1,673 focused tests, and all three generated-C
  comparisons. The required default pipeline passes its focused suite and all
  seven MS C tiny compile/run/decompile/recompile/decompiled-run constructs
- the sidecar-free SORTD indexed-aggregate regression passes recompilation and
  validation in 23.34s after the main-path IR/Alias artifacts were enabled
- `scripts/indexed_address_parity_inventory.py SORTD.EXE` now runs the canonical
  sidecar-free, non-library function catalog and writes deterministic JSON to
  stdout (or `--report-out PATH`); the durable measured report and work order
  are recorded in this section, while the JSON is reproducible and is not kept
  as a temporary repository artifact
- the 20-function SORTD inventory now closes from 42 raw frontend memory
  micro-operations to 36 normalized machine accesses: 6 exact
  same-instruction little-endian pairs are coalesced, 35 facts reach Alias,
  and 1 remains a typed refusal
- collector parity now has 31 matched keys, 4 Alias-only keys, 8 legacy-only
  keys, no duplicates, and no identity conflicts; 17 function reports are
  exact and 3 remain divergent
- machine-instruction review proves that the 8 legacy-only keys are late
  collector false positives: each uses BP-based addressing and therefore SS,
  while the legacy global collector incorrectly reports DS
- the former width/provenance conflicts are closed at their authoritative
  boundaries: VEX result widths are resolved against the IRSB type environment,
  IR coalesces only exact same-instruction contiguous micro-operations without
  changing the frontend byte-access ABI, and IR import rebinds only an exact
  JCC transport load to the identical immediately preceding CMP value; the
  established frontend VEX shape remains unchanged for angr structuring
- the 4 remaining Alias-only accesses are the two pointer-argument loads and
  two pointer-argument stores in function `0x107b8` (`Swaps` in the reviewed
  source); they are valid Alias evidence but are not bounded global aggregate
  evidence
- Alias now classifies only exact direct unscaled dereferences as
  pointer-relative and exact scaled nonzero-base accesses as globally indexed
  candidates. The closed sidecar-free census reports 4 pointer-relative facts,
  31 globally indexed candidates, and 1 retained upstream refusal; mixed forms
  remain typed refusals, and no Alias role claims aggregate bounds
- the role classifier is attached atomically by the existing Alias main-path
  publisher. Real lifted pointer/global fixtures, ambiguous and upstream
  refusal fixtures, ownership checks, and the whole-SORTD census are permanent
  regressions
- normalized indexed STORE facts retain every exact VEX byte-lane member. IR
  traces each member backward through supported same-block SSA operations and
  materializes a copy only when all lanes converge on one unchanged indexed LOAD
- Alias resolves both copy endpoints to canonical facts and accepts the relation
  only when both are globally indexed with the same exact stack index storage and
  shift. Pointer-relative, transformed, width-conflicting, and different-index
  cases remain typed refusals
- the sidecar-free SORTD copy census closes all 8 indexed STORE candidates: 3
  are exact IR copies and 5 are IR refusals; Alias retains 2 globally indexed
  copies and 6 refusals. The accepted sites are `0x106a9 -> 0x106b2`
  (`DS:0x08f0` to `DS:0x0b4c`) and `0x10871 -> 0x1087a`
  (`DS:0x0b4a` to `DS:0x0b4c`)
- Alias now publishes one immutable 20-function program census from the
  complete binary-discovery catalog and reuses the canonical IR SSA registry;
  exact supplied boundaries are validated before cached artifacts can replay.
  A missing or conflicting function remains a typed program refusal
- Widening consumes every Alias access/copy fact or refusal exactly once. A
  partial program suppresses all layout inference; transformed copies and
  different index identities retain separate families or refuse layouts
- the current sidecar-free Widening census closes 44 inputs as 27 consumed and
  17 explicit refusals. It proves only `DS:0x08f0` and `DS:0x0b4c` as two-byte
  layouts and joins their family only through the exact `0x08f0 -> 0x0b4c`
  copy; the `0x0b4a -> 0x0b4c` copy has no proven source layout and cannot join
- `project_global_object_layout.py` no longer manufactures indexed storage
  views from instruction-backed collectors. CLI discovery transports the
  complete catalog without semantic classification, Alias owns the census,
  Widening owns layout/family proof, and Lowering hard-fails an open artifact
- real-lifter positives and refusals, registry/cache replay, and the isolated
  sidecar-free SORTD aggregate regression pass. The latter keeps strict GCC,
  `validation=passed`, whole-tail cleanliness, `g_08F0_entry`, and the exact
  `g_0B4C` copy behavior; its measured wall time was 39.60 seconds
- implementation order is now: (1) [done] fix machine width and owning
  instruction provenance, (2) [done] close the whole-SORTD identity-conflict
  census, (3) [done] classify Alias facts as pointer-relative versus global
  indexed candidates, (4) [done] prove whole-element load-to-store value paths
  in IR and project both endpoints through Alias, (5) [done] migrate project
  layout recovery to Alias-fed Widening, (6) [done for exact static loop bounds]
  publish bounded object ranges and consume them in Types/Lowering, and now
  (7) generalize range/type propagation to dynamic, indexed, indirect, stack,
  and field-bearing objects. Widening must not consume the parity inventory or
  any rendered representation
- Widening now reduces the complete Alias program census into one closed final
  project-range artifact. Static exact loop bounds may produce a range;
  dynamic bounds, incomplete function evidence, uncovered accesses, layout
  mismatches, and segment conflicts remain typed refusals with closed counters
- the range artifact has one typed deterministic codec and is transported with
  its exact layout dependency through project caches and clean-worker JSON.
  Missing, malformed, open, or cross-layout records refuse instead of being
  reconstructed independently inside a worker
- Types/Lowering consumes only that transported Widening artifact, binds it to
  one exact existing segmented global declaration, and strengthens only the
  proven array extent. Ambiguous or missing names hard-fail when a classified
  range cannot materialize; upstream dynamic-range refusals leave declarations
  unchanged
- focused positive, refusal, cache, worker-transport, and declaration tests
  pass. The complete edited-state `quality-hard` gate passes Ruff `--fix`,
  strict MyPy for 211 source files, mypyc import smoke for 38 modules,
  architecture/context/ownership checks, 1,808 tests, and all three generated-C
  comparisons
- the required default pipeline passes the same 1,808 tests and every selected
  MS C compile/run/decompile/recompile/decompiled-run contract. All ten
  `scalar_types_io` functions validate, recompile, and produce rebuilt exit 255;
  no pipeline lane fails, skips, or times out

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

Status: complete for the bounded split-value and carry/borrow scope exercised by
SORTD. Semantics -> Alias -> Widening retains exact ADC/SBB values, and typed
pre-join CFG instruction ownership now prevents the former instruction-address-
only placement contract from claiming ambiguous branch joins.

Structuring now publishes typed pre-join Clinic CFG instruction ownership with
exact block/instruction sites and typed missing, ambiguous, unreachable, and
order-conflict outcomes. Carry Lowering retains both low/high block addresses,
requires that artifact on the main execution path, and refuses another
reaching definition of the same FLAGS identity. Explicit C predicate projection
is Lowering-only and consumes the already typed ADD_WITH_CARRY or
SUB_WITH_BORROW relation; it does not infer semantics from rendered C.

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

Measured closure on 2026-08-28:

- 22 focused carry/CFG ownership tests pass, including two mutually exclusive
  SUB/borrow chains sharing one FLAGS SSA identity, another reaching machine
  definition, duplicate owners, missing owners, and same-block order conflict
- the fresh strict sidecar-free SORTD gate generates and validates all 20
  application functions with zero fallback, timeout, traceback, discovery, or
  policy failure. DrawTime emits `sub_10e70(arg_4 * 60, 75)`, both exact Sleep
  argument shapes, no raw `ss << 4`, and `validation=passed`
- the same edited source state passes `quality-hard`, the default test pipeline,
  strict MyPy, Ruff `--fix`, architecture/context/ownership checks, all three
  generated-C comparisons, and every selected MS C end-to-end contract

#### 8.5 Collapse CFG regions only after conditions are explicit

Status: in progress. The exact switch-case edge to a proven enclosing
loop-tail exit is complete for RunMenu; general sequence/condition/loop/switch
region collapse remains open.

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

Measured progress on 2026-08-21:

- Structuring now owns an exact typed-AST transformation from switch-case
  gotos to the enclosing loop-tail label into `break`; Rewrite and CLI do not
  infer or repair this control flow
- the owner requires one unambiguous target, no executable suffix, no nested
  breakable scope, no external incoming target, complete codegen publication,
  and exact materialization evidence; every ambiguity refuses and preserves the
  original goto
- tail validation consumes only the matching typed `goto:<address>` delta and
  leaves unrelated deltas for their authoritative validators
- the sidecar-free RunMenu output converts nine proven exits, removes
  `LABEL_10488`, retains the Escape path, and passes whole-tail validation;
  focused tests cover the positive topology, idempotence, evidence counters,
  exact validation composition, and all refusal cases
- discovery-cache replay now re-emits the exact restored source-region evidence
  diagnostic, so strict cold and replay runs enforce the same 20/20 discovery
  contract instead of treating a correct cache hit as missing evidence
- the strict cold current-source and cached-replay checks both report
  20 raw, normalized, classified, and materialized functions, zero discovery
  failures, zero timeouts, zero tracebacks, and zero validation failures
- `quality-dev` passes Ruff `--fix`, MyPy, the 38-module mypyc import smoke,
  architecture/context/ownership checks, 1,613 tests, and all three
  decompilation-quality comparisons; the required test pipeline also passes
  its three selected lanes, including Ultra QuickC and all seven MS C tiny
  compile/run/decompile/recompile/decompiled-run constructs
- concurrent code-graph indexing can consume most host CPUs and cause false
  function-deadline failures. Acceptance runs therefore use bounded resource
  isolation; semantic timeouts were not increased to hide host contention
- exact-function relifting now owns `ConditionIR` for real projects. The old
  lifter compatibility cache is keyed only by rebased block address and cannot
  prove ownership across extracted functions; a two-project regression rejects
  complete sibling evidence at the same address
- the real five-function `compare16` batch now passes tail validation, C
  recompilation, and DOS behavior with exit `255` instead of the contaminated
  exit `12`; the permanent MS C tiny pipeline retains this end-to-end ratchet
- the MS C `switch_fold` regression was a Structuring projection-lifetime
  defect: a proven selector-return condition did not remain authoritative after
  later condition/lowering regeneration, so rendered C could retain an
  uninitialized carrier. Structuring now fingerprints the exact selector and
  return projection, checks it against the live AST, replays it at every owned
  lifecycle boundary, and hard-fails any active but stale projection
- Ultra QuickC `args` exposed a separate Structuring identity defect. The
  semantic call condition was intentionally preserved, but the C expression
  still carried tags from the preceding call and its exact binary-arm
  orientation had not been published. Call-return materialization now selects
  the unique typed `ConditionIR` from structured callsite identity plus the
  callsite summary return block, then restamps the C condition with that exact
  identity. Rendered names and stale tags are fallback evidence only
- binary-arm classification infers an empty arm only as the complement of an
  independently CFG-proven opposite arm. A nonempty unknown arm, ambiguous
  reachability, or non-unique callsite/return identity refuses materialization
  and preserves the existing structure
- the repaired real `args` fixture retains both required calls and places
  `local_4 = 1` only under the proven `v` branch; it has
  `validation=passed`, recompiles, and passes its runtime/source contract. The
  focused Structuring/import surface passes 92 tests, and the required gate
  passes 1,709 focused tests, 4/4 validated QuickC fixtures, and all seven MS C
  tiny constructs. Ruff `--fix`, strict focused MyPy, `linters-dev`, and the
  architecture/context/ownership checks are green

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

#### 8.11 Eliminate dead status-flag definitions before C expressions exist

Status: complete for the bounded SORTD status-flag and unsupported-instruction
closure. Typed per-bit same-block and function-CFG proofs, direct-callee
summaries, and lazy frontend emission are implemented for `ADD`, `SUB`, `INC`,
`DEC`, `SHL`, `SHR`, and `SAR`. On the exact `sub_109e8` CLI path all 11
classified CFG candidates materialize and packed flag equations fall from 4 to
0. The strict sidecar-free corpus now closes 20/20, and the required default
project pipeline passes.

Reason: Eagerly materialized packed-status updates retain large parity and
carry equations even when later instructions overwrite every affected flag.
This obscures otherwise simple C and increases simplifier and codegen work.
The proof must track each flag independently because instructions such as
`INC` preserve carry while `ADC` and `SBB` consume it.

Definition of done:

- Semantics owns a typed per-bit read/overwrite contract for decoded x86
  instructions; the frontend only projects Capstone evidence into it
- same-basic-block writes are omitted only after all written bits are proven
  overwritten before any read, and absent lookahead keeps complete flags
- the exact `sub_109e8` `SUB -> SAR 1 -> MOV -> INC` sequence is covered, while
  `INC -> ADC`, conditional reads, zero/unknown shift counts, and unknown
  instructions retain the prior flags
- a later IR/CFG liveness pass handles cross-block deadness with successor,
  loop, and call-effect evidence; the frontend does not guess beyond its block
- the five evidence counters close for every suppression decision, and a
  classified dead write cannot reach zero materialization
- `sub_109e8` loses the dead flag equations without losing either call, changing
  branch polarity, or worsening tail validation; focused gates, the SORTD
  corpus, strict recompilation, MS C tiny examples, types/docs, and Ruff pass

Current evidence on 2026-08-27:

- 24 focused status-liveness tests cover same-block, successor, loop, call,
  live-condition, unknown-edge, cache-relift, and zero-materialization cases
- partial-live `SHL`, `SHR`, and `SAR` regressions prove that a ZF-only
  successor does not construct parity equations; unknown/live paths keep flags
- 188 status-liveness and 80386 edge tests pass, including instruction execution
  semantics beyond the decompiler-only projection
- all 11 exact `sub_109e8` candidates close with `failure_count=0`; the prior
  uninitialized `reg+0x24` carriers were FLAGS, and those failures disappear
  when the CFG artifact is consumed
- Structuring now resolves direct-stack assignments through the Lowering-owned
  machine-BP to entry-SP registry, closing the independent `0x10a4f` ownership
  failure without weakening classified/materialized evidence checks
- Types/Lowering persists the proven complete aggregate typedef through codegen
  rollback, so final rendering no longer emits an incomplete `g_08F0_entry`
- the exact sidecar-free function has `validation=passed`, whole-tail validation
  clean, GCC acceptance, both calls intact, and no unsupported instructions;
  no call/body repair occurs in Rewrite or CLI
- the current whole-file C output has zero unsupported/unknown-instruction and
  zero packed flag-equation markers; the strict run validates all 20 selected
  non-library functions with no fallback, empty body, timeout, or traceback
- Beep's exact gate preserves the one-argument `inp(0x61)` call node, binds its
  typed machine `[BP-2]` return store to the projected `local_2`, emits both
  required uses, and passes tail validation without call reconstruction
- changed-source Ruff `--fix`, MyPy, mypyc, types/docs, architecture, and
  ownership checks pass; the default pipeline passes 1,763 Python tests and all
  three selected MS C tiny-example build/run/decompile/recompile lanes with no
  failures, skips, or timeouts

Definition of failure:

- flags are deleted as one packed value instead of per bit, or carry is dropped
  across `INC/DEC` before `ADC/SBB`
- calls, indirect control flow, unknown instructions, or uncertain successors
  are treated as overwrites without typed evidence
- flag semantics are repaired from assembly/rendered C or in Structuring,
  postprocess, CLI, or export code
- output is merely prettier while call, control-flow, validation, compilation,
  behavior, evidence-accounting, typing, documentation, or lint gates regress

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
