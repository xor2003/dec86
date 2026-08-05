# Sidecar-Free SORTD Plan

Goal: decompile the executable-only SORTD image to validated, recompilable C
without `.COD`, `.LST`, `.MAP`, appended debug data, or source substitution.

Current baseline (2026-08-05):

- discovery evidence: raw=20, normalized=20, classified=20, materialized=20,
  failures=0
- selected and attempted: 20/20
- accepted C: 20/20 (`0x10010`, `0x10060`, `0x101f0`, `0x102e0`, `0x10498`, `0x10560`, `0x10678`, `0x106c8`, `0x10768`, `0x107b8`,
  `0x10808`, `0x108d0`, `0x10970`, `0x109e8`, `0x10a88`, `0x10b50`,
  `0x10c18`, `0x10ce0`, `0x10e70`, and `0x10f38`); the ratchet requires all twenty
  accepted functions
- validation failures: 0/20
- empty C: 0/20; former empty results `0x102e0` and `0x10560` are accepted
- timeout count: 0; traceback count: 0
- generated translation unit: 20 functions, zero compiler errors/warnings
- generated nine-function sort core: compilation passed and behavior passed
- source-aware SORTDEMO: 20/20 accepted, 20/20 source contracts, 20/20
  validation, zero fallback
- pytest verification uses `pytest -n 7`; independent process fan-out remains
  bounded by a 2 GiB aggregate RSS budget, while mutable per-binary fallback
  rebuilds remain serial until their state is isolated
- focused declaration/global regressions: 191/191 passed under
  `pytest -n 7 --dist loadgroup`
- default pipeline: 3/3 lanes passed, including all seven MS C fixtures compiling,
  running, decompiling with clean validation, recompiling, and returning the
  expected DOS exit code `255`
- expanded pipeline: 5/5 lanes passed; current artifact is
  `angr_platforms/.cache/test_pipeline/summary.json`
- performance debt remains visible: the expanded `unit-focused` lane passed in
  44.38s against its advisory 30s budget; semantic status is unaffected
- the eight promoted production/tooling owners changed by the final
  call-argument closure pass scoped `make check-files`: Ruff, mypy,
  type/doc/access, architecture, context, ownership, and selected tests pass;
  142 focused pipeline/validation tests and the 3/3 default pipeline pass. An
  inclusive run still sees 48 pre-existing mypy errors in the legacy
  `decompiler_postprocess_calls.py` compatibility module and 22 in
  `scripts/check_decompiler_architecture.py`, both owned by the concurrent broad
  type promotion. Do not report that separate global type gate as green.

Final update-only global declaration closure and per-step DoD:

1. Join exact update-only DS storage into global symbol identity.
   Definition of done: `DirectGlobalUpdateEvidence8616(offset, width, delta)`
   contributes a generic storage name only when no stronger symbol reference
   exists; focused tests prove update-only inclusion and named-reference
   precedence.
2. Reconcile angr declaration caches at Types/Lowering.
   Definition of done: exact non-stack DS offset/width evidence removes only
   stale `unified_local_vars` entries and dead carrier indexes; stack variables,
   unmatched globals, and the actual global index remain; closed evidence
   counters report every classified removal.
3. Preserve dynamic third-party boundaries.
   Definition of done: real angr functions reconcile cached declarations, while
   synthetic or older CFunction surfaces without `unified_local_vars` perform a
   typed zero-work reconciliation instead of failing.
4. Prove real output and full behavior.
   Definition of done: sidecar-free `sub_107b8` has one external `g_0BA4` and no
   shadowing local; validation passes; the 20-function translation unit and
   nine-function behavior harness pass; default and expanded pipelines pass.

Final QuickC call-argument determinism closure and per-step DoD (complete):

1. Reconcile binary-proven near-pointer parameter width at Types/Lowering.
   Definition of done: the emitted C function and canonical angr function
   prototype both retain the same two-byte near-pointer parameter; later
   annotation refresh cannot restore the stale one-byte type; focused prototype,
   segmented lowering, and real `ARGS.EXE` validation pass.
2. Remove reusable object-ID aliases from protected call arguments.
   Definition of done: protected expressions retain the exact call object,
   lookup requires `entry.call is call`, dead-call IDs cannot resolve to a new
   call, and the synthetic ID-collision regression passes.
3. Add an absolute binary-source identity guard at Tail Validation.
   Definition of done: exact one-push callsite summaries preserve every proven
   BP-relative dependency in the final C argument; grouped or unknown evidence
   remains unclassified; a recycled constant pointer is refused without AST
   repair, while `arg_5[local_2]` passes.
4. Ratchet the fix into normal development gates.
   Definition of done: the new identity and source-validation tests are owned,
   included in `FOCUSED_PYTEST_TARGETS` and `QA_PYTEST_TARGETS`, architecture
   checks pass, fresh QuickC runs are deterministic, and the default pipeline
   reports 3/3 passed with no failures or timeouts.

## 1. Deterministic Binary Discovery

Status: complete for deterministic discovery and the 20/20 decompilation
ratchet; broader program-memory work continues in section 9.

Work:

- derive the startup-bounded application region from binary CFG evidence
- rank the exact 20 framed application entries ahead of runtime functions
- isolate display-catalog cache keys by discovery policy and source digest
- retry only failed classified entries and refuse incomplete catalogs

Definition of done:

- repeated clean-cache runs report `20/20/20/20/0`
- the exact expected 20 addresses are selected once each
- runtime/library/interior entries do not displace application functions
- focused discovery, cache-policy, retry, Ruff, and Pyright checks pass

## 2. Preserve Proven Function Bounds

Status: complete.

Work:

- attach each binary-derived `[entry, next_entry)` interval to the recovered
  function contract
- use cheap entry materialization during catalog discovery
- consume the exact interval only when rebuilding a fresh function for
  decompilation

Definition of done:

- discovery does not treat padding or disconnected bytes as required CFG
  coverage
- fresh workers receive the source function's exact binary interval
- `RunMenu` reaches the semantic pipeline with its complete 76-block graph
- focused boundary-propagation tests, Ruff, and Pyright pass

## 3. Enforce The Sidecar-Free Ratchet

Status: complete.

Work:

- derive the MZ executable image from tracked `SORTDEMO.EXE`, excluding its
  appended debug overlay
- run it alone as `SORTD.EXE`
- add `sortd-sidecar-free` to the expanded pipeline
- record exact discovery, attempt, accepted-C, empty, and traceback counts

Definition of done:

- `make test-pipeline-expanded` includes the executable-only lane
- the lane requires the exact 20-address oracle and 20/20 attempt coverage
- the lane requires all 20 accepted C functions, no empty function, no timeout
  signal, and no traceback
- parser, pipeline-contract, ownership, Ruff, and Pyright tests pass

## 4. Remove Noisy Pipeline Exceptions

Status: complete.

Owning layers:

- timeout cleanup: `inertia_decompiler/runtime_support.py`, discovery timeout
  orchestration, and `X86_16/corpus_scan.py`
- invalid statement collection:
  `angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py`

Work:

- prevent signal timeouts from firing inside x86-16 memory deallocation
- find which structuring pass inserts a non-`CStatement` value and fix that pass
  at its typed AST boundary

Definition of done:

- the full sidecar-free transcript contains no Python traceback
- no pass is silently skipped because an owned C statement collection contains
  an invalid value
- focused negative tests reproduce both old failures
- the lane's `maximum_tracebacks` is 0

## 5. Fix Semantic Validation Families At Their Owners

Status: complete.

Order:

1. Alias/storage identity and segmented DS/SS lowering.
2. Widening and typed condition transfer.
3. Structuring only after earlier facts are stable.
4. Rewrite only for cleanup; never repair semantics there.

Current families:

- raw DS/global identity and unresolved flag carriers, including `RunMenu`
- stack-slot/global/AX identity drift in loop conditions
- helper-call interface and stack-write deltas
- QuickSort typed `CmpGT(arg_*, arg_*)` control-flow delta
- `0x10010`: complete; binary-proven call/store evidence reconnects the return
  value of the call at `0x10021` to its AX carrier and the subsequent byte
  stores at `0x10027`, even when caller evidence proves this function's own
  return unused
- `0x10f38`: complete; typed callsite evidence excludes proven callee-saved
  frame pushes, widening materializes `DX:AX` call-result arithmetic, and
  Structuring lowers the CFG-proven wide loop condition

Completed infrastructure:

- near JCC/JMP targets retain relocated linear addresses
- final condition materialization recomputes CFG-proven conditions after AST
  drift
- caller-return evidence crosses recovered-project and clean-process boundaries
- forced serial execution always uses one synchronous clean worker, even when
  telemetry/background threads exist
- `0x10f38` emits `local_4 = sub_1137e() + a0` and
  `if (sub_1137e() > local_4) break`, reports `validation=passed` in focused
  and whole-file lanes, and raises the accepted whole-file floor from 3 to 4
- the `0x10f38` evidence loop is covered by typed callsite, lowering,
  materialization replay/idempotence, carrier pruning, and Structuring tests;
  the changed-file gate and 307 focused tests pass
- `0x10010` emits `v5 = sub_12a29(43)` before the two exact global byte
  stores and reports `validation=passed` in direct, externally-void worker,
  and whole-file lanes; the accepted whole-file floor is now 5/20
- sidecar-free scalar call-return materialization is covered by exact positive,
  refusal, and replay tests; missing declaration metadata initializes to an
  explicit empty owned contract
- `0x102e0` now terminates as `validation_failed` with retained partial C
  instead of spending the remaining budget on rewrite salvage and being
  misreported as a timeout; the direct and whole-file CLI paths preserve the
  typed work-item status
- the sidecar-free ratchet enforces `maximum_timeouts=0`, including refusal of
  stale `partial timeout` labels on validation-failed functions
- architectural segment-register live-ins now lower from typed IR segment
  state to explicit `inertia_cs/ds/es/ss` runtime state; `0x109e8` no longer
  fails final def-use validation on an uninitialized DS carrier
- angr's typed `Insert` expression is classified before the legacy call bridge
  and lowered in Types/Lowering to exact little-endian mask/or operations;
  call-argument recovery cannot collapse its three operands
- validated sidecar-free ASTs bypass legacy text-based staging DCE and generic
  return pruning; live AX assignments and distinct fallthrough returns remain
  intact through final emission
- `0x109e8` and `0x10a88` now report `validation=passed` in the serial whole
  gate, raising the accepted floor from 5 to 7 with 0 empty functions,
  0 timeouts, and 0 tracebacks
- binary-proven anonymous direct DS/ES loads now remain explicit `SEG_U*`
  accesses instead of collapsing to raw `mem_*` variables; `0x108d0` reports
  `validation=passed` sidecar-free and raises the accepted floor from 7 to 8
- tail-validation def-use consumes typed `SegmentStateArtifact` entry facts,
  so proven architectural DS/ES/SS/CS live-ins are initialized without
  admitting ordinary unproven register carriers; `0x10970` and `0x10c18`
  report `validation=passed` sidecar-free and raise the floor from 8 to 10
- Alias now proves proper containment between bounded stack storage views, and
  Widening consumes that proof after instruction-backed width promotion to
  remove redundant high-byte recomposition; `0x10b50` reports
  `validation=passed` sidecar-free with all required calls preserved and
  raises the floor from 10 to 11
- Types/Lowering now persists binary-proven stack aggregate types through the
  angr variable manager and replays them after AST regeneration; direct binary
  caller-use evidence proves `0x106c8` has an unobserved result, while CLI
  declaration materialization recognizes array declarators without inventing a
  scalar duplicate. The focused executable-only regression and serial
  whole-file gate both report `validation=passed`, preserve both fill calls and
  the output call, emit `char local_2c[44]`, and raise the floor from 11 to 12
- exact binary callsite evidence for DrawFrame's physical `PUSH SS` plus
  `PUSH BP-0x52` arguments is delegated by Structuring to the
  Types/Lowering segment-state owner through a typed service contract; the
  legacy call bridge has no new protected-layer import. The isolated
  executable regression and forced-serial whole-file gate preserve all three
  buffer output calls as `sub_12756(local_52, inertia_ss)`, retain the
  80-byte stack object and 16-bit loop variable, report `validation=passed`,
  and raise the floor from 12 to 13
- Types/Lowering now creates deterministic generic indexed-global identities
  only when exact binary DS offset/width evidence exists and no indexed COD
  evidence exists. ReInitBars materializes the binary-proven dword clock
  store, emits `g_0B4C[local_2] = g_08F0[local_2]`, preserves
  `sub_106c8(local_2)`, reports `validation=passed`, and raises the floor from
  13 to 14. Mismatched sidecar joins remain refused rather than being guessed.
- Frontend call-target collection now prefers exact Capstone direct-call
  targets over stale CFG near offsets. Calling-convention initialization
  preserves non-guessed prototypes, full-project stubs receive bounded binary
  callee ABI evidence, and terminal evidence-backed DCE removes consumed
  storage-free flag/global setup chains. DrawTime emits one dword argument for
  each call at `0x10f18`, including `SEG_U32(inertia_ds, 306) - 75`, reports
  `validation=passed`, and raises the sidecar-free floor from 14 to 15.
- Structuring now splits an angr-collapsed multi-JCC loop header only after
  exact binary branch facts prove that every suffix guard and duplicated body
  effect is materialized in the loop body. Types/Lowering re-expresses an exact
  sidecar-free indexed store source through the destination base only when
  width, stack-index identity, and shift match; named sidecar identities remain
  untouched. InsertionSort emits
  `g_0B4C[local_4] = g_0B4C[local_4 - 1]`, reports
  `validation=passed`, passes portable-flat compilation, and raises the
  sidecar-free floor from 15 to 16.
- Structuring now transports an exact loop-condition segment-load producer
  only when one `ConditionIR` fact matches the final condition occurrence;
  missing and ambiguous producers are refused. Types/Lowering consumes that
  provenance, recognizes canonical Widening load identities, and closes an
  anonymous direct DS scalar from raw `CVariable` through helper to typed
  `g_0BA2` in one pass. A typed materialization marker prevents later replay
  from converting the global back into `SEG_U16`. Named and sidecar-free
  HeapSort, sidecar-free InsertionSort, and sidecar-free ReInitBars all report
  `validation=passed`; their serial family gate passes 4/4 in 135.52 seconds.
- Types/Lowering now treats repeated indexed loads with the same base, width,
  BP index slot, shift, and adjustment as one materialization-equivalent site
  class only when the segment contract proves entry `DS` at every matching
  instruction. Conflicting or unknown physical segment sources still refuse.
  DrawBar's three low-byte reads now remain
  `abarWork[iRow].field_0` through late AST replay instead of reverting to
  `SEG_U8`; its focused binary regression passes portable-flat compilation and
  whole-tail validation. The six-function closure gate for named HeapSort,
  sidecar-free HeapSort, InsertionSort, ReInitBars, InitMenu, and DrawBar passes
  6/6 in 152.70 seconds.
- The same six-function closure remains green after removing sample-specific
  call-arity tables: 6/6 in 195.77 seconds. Call-materialization now requires
  binary-proven logical arity; contradictory physical push and logical argument
  counts are refused, and the complete owner regression lane passes 169/169.
- IR values now retain the exact instruction that performed a segmented memory
  access, separately from the later CMP/TEST flag producer. Structuring matches
  that typed address evidence instead of borrowing compare or branch addresses,
  and condition refresh replays the complete stage-owned named/indexed global
  sequence. The call-argument compatibility consumer also uses an existing
  dword scalar symbol ref before falling back to `SEG_U32`. InitMenu now emits
  `cszMenu` and scalar `clPause` expressions without `clPause[1]`, raw flag
  carriers, or `SEG_U*`; its focused binary run passes GCC, whole-tail
  validation, and all source-shape assertions in 63.24 seconds.
- Binary discovery now clamps public-entry NOP alias scans to the mapped image
  boundary, proving all four callers of InitMenu's `0x1005d` public entry leave
  its return unused. Types/Lowering materializes `void sub_10060(void)` from
  that closed evidence and replaces conflicting scalar/array argument guesses
  for one otherwise identical physical call interface with an honest
  unprototyped declaration. Cleanup removes only unread resolved-call SSA
  result carriers while preserving every call and refusing unresolved calls.
  InitMenu reports `validation=passed`, passes portable-flat compilation with
  no `vvar_*`, and raises the sidecar-free floor from 16 to 17.
- The changed-file gate passes Ruff, Pyright, type/docs, architecture,
  agent-context, and ownership checks. Its mapped real-binary snapshot reports
  146 passed and 11 known failures in 25m00s; the failure set is the prior set
  minus InitMenu, with no new failure family.
- The broad changed-test snapshot after this ratchet passed 186 tests and
  failed 12 legacy SORTDEMO regressions in 26m01s. Ruff, Pyright, type/docs,
  architecture, agent-context, and ownership gates passed. The failures are
  tracked as unresolved rather than treated as a green full-suite result;
  the sidecar-free DrawBar failure was order-sensitive and passed immediately
  when rerun in isolation.
- Types/Lowering preserves InitBars' binary-proven `BP-0x5a` 86-byte stack
  partition as `unsigned short local_5a[43]` through CFunction rebuilds. The
  final CLI compile-hygiene scanner now distinguishes non-generic declarations
  from non-declaration statements, so a preceding stack struct cannot cause
  scalar duplicates for later array and scalar locals. The stripped executable
  regression reports `validation=passed`, portable-flat compilation and
  whole-tail validation pass, all required calls and exact DS stores survive,
  and the forced-serial whole-file gate raises the floor from 17 to 18 with
  0 empty functions, 0 timeouts, and 0 tracebacks.
- Callsite recovery now retains the exact caller-side `ADD SP, imm`
  instruction address alongside the cleanup byte count. Types/Lowering
  publishes a closed consumed-cleanup evidence census only for exact
  materialized calls, and conservative DCE removes only dead temporary
  carriers tagged to those instructions. RunMenu preserves all required calls,
  emits the binary-proven dword updates and boolean store without `vvar_*` or
  unresolved expressions, reports `validation=passed`, and passes
  portable-flat recompilation. The executable-only ratchet now requires
  `0x102e0` and raises the floor from 18 to 19.
- Frontend SUB routing now requires an exact same-block CMP or DEC/JCC
  consumer before taking the simple condition path, preserving both typed
  QuickSort conditions and non-branch call-argument arithmetic. Types/Lowering
  canonicalizes binary-proven NOP-padding call aliases, and a Structuring-bound
  typed service replays that identity after every legacy argument regeneration
  without introducing a protected Rewrite import. InitMenu, ShellSort, and
  QuickSort pass their executable-only regressions; the forced-serial corpus
  report `/tmp/sortd-sidecar-free-20-fixed.json` records 20/20 accepted,
  0 validation failures, 0 empty functions, 0 timeouts, 0 tracebacks, and
  0 violations.

Definition of done for each fixed family:

- add a minimal typed regression at the earliest owning layer
- add or tighten one real SORTD function regression
- focused function reports `validation=passed`
- required calls survive with correct value/pointer argument classes
- output is closer to `SORTDEMO.C` than the previous baseline
- Ruff `--fix`, Pyright, focused tests, and `make check-files` pass
- increase `minimum_decompiled` or reduce another failure ceiling immediately

## 6. Recover The Empty Function

Status: complete.

Work:

- retain generated partial C, never misreport a pipeline contract failure as
  an empty decompilation
- capture the typed stop/pass/block family for every genuinely empty result
- fix the earliest lift, IR, alias, widening, type, or structuring owner
- do not add address/name/source-sidecar substitutions

Definition of done:

- the full sidecar-free run reports zero genuinely empty functions
- tail validation passes
- required source-level calls survive with correct argument classes
- the lane's `maximum_empty` is 0

## 7. Close The Whole-Binary Goal

Status: complete.

Progress:

- Clean serial workers use the narrow CLI entrypoint, current-parent architecture
  attestation, and measured timeout floors. Optional Rizin timeout is contained
  at discovery ownership and falls through to binary evidence.
- Workers ignore local sidecar semantics. A parent may use a sidecar public entry
  only to bound binary padding before handing the canonical prologue to the
  sidecar-free worker.
- The final source-aware status lane reports all 20 functions decompiled,
  validated, and source-contract clean with no fallback or quality blocker.
- The expanded serial pipeline covers focused units, Ultra QuickC, all six MS C
  tiny compile-decompile-recompile-execute cases, sidecar-free SORTD, and
  source-aware SORTDEMO; its generated sort-core child passes compilation and
  behavior.
- Runtime import ownership is enforced on CLI startup through content-hash
  attestation, while Makefile retains the full architecture audit.
- The historical mapped regression snapshot passed all 1,921 tests. The suite
  has since expanded beyond 2,400 tests and currently has tracked failures;
  historical green evidence is not treated as the current full-suite result.

Definition of done:

- sidecar-free evidence remains `20/20/20/20/0`
- unmodified `./decompile.py ./SORTD.EXE` emits generated C for all 20 functions
- all 20 functions report `validation=passed`
- generated C passes the configured portable-flat acceptance checks
- no asm/details fallback, empty result, timeout, traceback, or silent function
  loss remains
- `make quality-fast PYTHON=./.venv/bin/python` passes
- `make test-pipeline PYTHON=./.venv/bin/python` passes
- `make test-pipeline-expanded PYTHON=./.venv/bin/python` passes serially
- the full mapped pytest set passes: 1,921 passed in the final post-fix run
- the final ratchet requires 20 accepted C functions, 0 empty functions, and 0
  tracebacks

## 8. Prove Generated-C Behavior

Status: in progress: the current nine-function sort-core milestone is complete;
expansion to every source-selftested function remains.

Progress:

- the MS C DOS source oracle passes all `SORTDEMO.C` function selftests and
  returns the required success exit code 255
- the generated gate extracts nine binary-addressed sort functions, keeps their
  generated bodies unchanged, maps only binary DS storage and external runtime
  interfaces, compiles with AddressSanitizer and UndefinedBehaviorSanitizer,
  and checks the same source-derived primitive and sorting outcomes
- Types/Lowering proves InitBars' indexed stack range, while Structuring owns
  replay and CFG placement of the direct stack move before its indexed use.
- QuickSort's two binary-proven stack moves replay at the owning `do` body entry
  after every AST rebuild. Structuring compares exact branch and loop intervals:
  a loop nested in an arm supersedes that arm, an arm nested in a loop wins, and
  ambiguous overlap is refused. Both sidecar-free and source-backed regressions
  require the per-iteration assignments before the first inner scan.
- cleanup prunes a zero-use pure virtual definition only when its dirty value
  carries explicit register storage; opaque dirty values and address carriers
  remain untouched.
- PercolateDown's exact loopback owns its recurrence assignment inside the
  constant-true loop. Focused InitBars, QuickSort, and PercolateDown runs are
  validation-clean and close their evidence censuses.
- The current 20/20 executable-only transcript feeds the unchanged nine-function
  sanitizer gate, which reports `functions=9 compile=passed behavior=passed`.

Work:

- expand from the sort core to every source-selftested function

Definition of done:

- the source oracle passes under MS C and DOS execution
- generated InsertionSort preserves the binary-proven signed low-byte conversion
- all generated sort functions compile together with sanitizers enabled
- every generated sort produces the source-derived result and exit code
- the gate fails on missing functions, compile errors, sanitizer failures, or
  behavioral mismatch
- the expanded test pipeline runs this gate serially after producing a fresh
  20/20 sidecar-free transcript
- the final candidate covers all source-selftested functions; no claim of
  whole-program equivalence is made from sort-core evidence alone

## 9. Whole-Application Generated-C Quality

Status: in progress. The 2026-08-01 executable-only lane now emits and validates
all 20 functions and compiles their exact bodies as one warning-free translation
unit. Proven program-memory layout, one canonical data image, broader behavioral
coverage, pass-level profiling, and intermediate analysis caches remain open.

Remaining baseline:

- the current exact sidecar-free cold run takes 645 seconds; validated warm
  whole-function reuse takes 14 seconds, while uncached pass-level costs for
  InitBars, RunMenu, QuickSort, and InitMenu still require focused profiling
- the nine-function generated sort-core sanitizer gate passes, while behavior
  coverage for the remaining source-selftested functions is still absent

Current acceptance:

- `/tmp/sortd-zero-warning-final` contains the fresh executable-only transcript,
  20 clean function artifacts, the combined translation unit, and JSON reports
- the corpus reports 20/20 decompiled, with raw, normalized, classified, and
  materialized counts all 20 and zero discovery failures, validation failures,
  empty outputs, timeouts, tracebacks, or violations
- the exact combined translation unit reports compiler exit 0, 0 errors, and
  0 warnings; the unchanged nine-function generated sort-core reports compile
  and behavior passed

### 9.1 Close Semantic False Greens

Status: complete.

Owner: Structuring for CFG-proven loop exits; Types/Lowering for stack argument
identity; Validation for path-sensitive definite-assignment proof. Rewrite must
not repair any of these defects.

Progress:

- Structuring preserves the binary-proven RunMenu escape edge as
  `case 27: return` through the bounded exact-region epilogue. The focused
  function remains validation-clean and the executable-only ratchet rejects a
  transcript that loses the return.
- Final tail validation now consumes the Structuring-owned switch-exit evidence
  as an absolute obligation, independently of before/after rewrite deltas. It
  rejects a missing case, a non-return body, a missing binary target anchor,
  ambiguous duplicates, conflicting exits, and malformed evidence with closed
  raw/normalized/classified/materialized/failure counts. Evidence is published
  even when the expected loop/switch AST shape is already missing, closing the
  prior stable-but-broken false green.
- The normal real-CLI RunMenu regression passes with `validation=passed` and the
  ESC case. After removing an invalid attempt to attach segment summaries to
  slotted angr `Function` objects, the exact sidecar-free `SORTD.EXE` command
  also exits zero, reports `status=ok` and `validation=passed`, emits
  `case 27: return`, and has no traceback. Both paths now have owned focused
  regressions.
- Types/Lowering now derives positive-BP argument identity from generated AST
  stack variables, then joins it with a typed binary caller census before
  changing a function header. Consistent zero-argument callsites clear a stale
  generated header; conflicting caller evidence refuses materialization.
- DrawTime emits its row value as an initialized word argument and preserves
  the value-class Beep call. Beep emits both frequency and duration as initialized
  value arguments, with no `BP+4`/`BP+6` pseudo-locals. Both sidecar-free focused
  runs report `validation=passed`, whole-tail validation clean, and portable-flat
  compilation clean.
- A later expanded run exposed a generic Beep false negative: a local defined
  under `frequency != 0` was read in the `else` of `frequency == 0`, but
  Validation activated guarded definitions only for true branches. Validation
  now canonicalizes exact structured predicate complements through Condition IR
  and activates them only for a single-condition `else`. Predicate writes still
  invalidate the proof. The 9 focused predicate tests, 97-test Validation family,
  real sidecar-free Beep acceptance, 4-function positive-BP suite, and 747-test
  changed-file gate pass. The subsequent cold whole-file sidecar-free ratchet
  passes 20/20 with zero validation failures, empty outputs, timeouts,
  tracebacks, or violations, closing this regression.
- Unit fixtures cover consistent zero, consistent multiword, conflicting, stale
  byte-view, guessed-zero, authoritative-zero, signed-interface, and unused-slot
  cases. The argument and caller censuses close raw, normalized, classified,
  materialized, and failure counts without promoting ambiguous evidence.

Definition of done:

- a focused before/after RunMenu regression proves the ESC edge from binary CFG
  evidence and the final generated C contains the corresponding returning case
- RunMenu remains `validation=passed`, retains every required call, and no longer
  has an unconditional user-visible loop with no exit
- focused DrawTime and Beep regressions emit initialized typed arguments with
  signatures consistent with their binary callsites
- strict portable-flat compilation reports no uninitialized stack-argument use
  for either function
- all changed semantic passes close their evidence census with no classified
  fact left unmaterialized, and negative fixtures prove refusal on ambiguity
- final semantic validation fails when any binary-proven structured exit is
  absent from the exact final AST, even if stage snapshots are otherwise stable

### 9.2 Establish One Translation-Unit Contract

Status: complete.

Owner: Types/Lowering and CLI/export assembly. Function-local Rewrite must not
invent or reconcile interprocedural declarations.

Progress:

- the CLI writes one clean accepted-C artifact per function, separately from
  diagnostics, in direct and batch modes
- a pycparser-backed export assembler deduplicates identical declarations,
  orders aggregate types before dependent declarations, and selects generated
  definitions as the canonical internal function contracts without changing
  function-body ASTs
- the expanded serial pipeline requires all 20 artifacts and runs the strict
  whole-unit compiler ratchet
- binary caller evidence now follows padded public-entry aliases in both
  ordinary and rebased projects; ShellSort emits `void sub_10c18(void)`, retains
  its pointer/value calls, and remains validation-clean
- callsite summaries classify an immediate forwarded `PUSH DX`/`PUSH AX` pair
  as a wide return use and stop at the next unrelated call; structured export
  joins compatible external prototypes, discards weaker K&R declarations, and
  removes the `sub_1143a`/`sub_12756` conflicts without changing call bodies
- the compiler gate now requires a zero compiler exit and defaults to zero
  allowed errors and warnings; an unparsed nonzero compiler failure cannot pass
- caller-owned aggregate source-family evidence now reaches `sub_107b8` through
  canonical callee identity, so its definition and calls share the proven BAR
  pointee contract; the shifted `g_0B4E` view is emitted as the canonical
  `g_0B4C[index + 1]` object view
- the exact callsite pointer-table evidence for `g_0136` and typed high-word
  ordering evidence for `g_0132` now materialize compatible pointer and signed
  wide declarations in Types/Lowering; conflicting evidence refuses promotion
- final emitted-C cleanup recognizes angr's hexadecimal `local_a`/`local_1c`
  stack names as generated declarations and removes only unreferenced,
  uninitialized declarations; focused tests preserve annotated human names
- the final serial artifact run under `/tmp/sortd-zero-warning-final` reports
  20/20 accepted functions and a strict combined translation unit with compiler
  exit 0, 0 errors, and 0 warnings

Definition of done:

- all 20 exact generated bodies compile as one translation unit with strict
  warnings and no conflicting declarations, repeated type definitions, or
  incompatible call signatures
- each callee has one canonical return and argument contract shared by its
  definition and every callsite
- the expanded serial pipeline fails on a whole-translation-unit compile error
- no generated body is replaced or textually repaired to satisfy compilation

### 9.3 Infer Proven Program Memory Layout

Status: in progress. This is a prerequisite for using one-segment assumptions in
global-object recovery; a classic memory-model name is diagnostic only and must
never control lowering.

Owners: IR owns path-specific segment values and effective-address facts;
function/program summaries under `X86_16/` own interprocedural layout evidence;
Alias and Types/Lowering consume proven storage and pointer-width facts. CLI may
report the result but Rewrite must not infer, repair, or flatten segmentation.

Current evidence and blockers:

- `ir/segment_state.py` already builds per-block CS/DS/ES/SS entry and exit
  states, and lowering already distinguishes default DS from explicit ES access
- `analysis_helpers.collect_direct_far_call_targets` and callsite summaries
  expose direct far calls and proven far-pointer widths
- the MZ loader's segment spans prove image layout only; relocation locations do
  not prove the identity of the primary data segment
- `segmented_memory_reasoning.detect_far_pointers` is currently test-only and
  wraps supplied expressions rather than collecting production evidence
- segment-state joins now treat unknown/conflicting predecessors as unknown,
  arbitrary register-sourced writes remain unknown, and typed same-block
  register copies can preserve a proven segment identity
- VEX `IMark` addresses now reach typed IR instructions, decoded string facts
  retain those addresses, and string effects consume exact pre-instruction
  segment state instead of any proven function exit
- Alias now proves same-block and cross-block stack-backed segment save/restore
  from exact typed `SS:SP` byte stores, loads, lossless byte composition, and
  predecessor joins; ambiguous SS aliases invalidate the proof. Exact string
  effects and the function contract consume pre-instruction state rather than
  global exits
- no downstream semantic consumer currently uses the whole-program join of discovery closure, unresolved
  indirect control, segment clobbers/restores, static data accesses, near/far
  calls, and near/far/huge pointer evidence into every downstream consumer; the
  typed core join and worker transport now exist, while consumption remains
  incomplete

The typed program contract must report independent evidence instead of one
guessed label: primary static data region, code-segment reachability, CS/DS and
SS/DS entry relations, observed far code, far static and dynamic data, huge
pointer normalization, function-discovery closure, and unresolved segment or
control effects. Per-function and per-block facts override any program default.
An ES video/string/heap access does not invalidate a single primary DS region;
only that access remains explicit. A DS save/change/restore is scoped only when
Alias and stack evidence prove the restoration on every relevant path.

Order and per-step definition of done:

1. Make segment-state analysis a sound may/must lattice.

   Definition of done: unknown or conflicting predecessors produce unknown
   must-state; register-sourced writes prove physical identity only through typed
   value flow; consumers request the state for the exact block/access; focused
   branch, loop, unknown-source, segment-copy, and save/restore tests pass.

   Progress: complete. Focused branch, loop, unknown-source, segment-copy, typed register
   save/restore, VEX-address propagation, and exact string-access tests pass.
   The main path now runs VEX import, Alias stack-fragment restoration, IR
   segment-state transfer, and the function contract in that order. A real VEX
   `push ds` / DS clobber / `pop ds` fixture proves both bytes, restores the
   entry DS identity, and records DS as restored rather than clobbered. Missing
   bytes, conflicting predecessor fragments, and ambiguous `SS` aliases remain
   `UNKNOWN_REFUSE`; the state kind is an enum instead of a parsed string.
   Same-block and cross-block restoration regressions pass, including a
   485-test changed-file gate. Remaining memory-effect consumers migrate under
   step 4 rather than extending the lattice owner. Recovered function-graph
   edges now replace incomplete low-16 VEX successors, and the fixed point
   preserves dataflow bottom for predecessors that have not been processed yet;
   focused rebased-CFG and nested-loop tests prevent either source of false
   segment unknowns from returning.

2. Build a typed per-function segment contract.

   Definition of done: each function records entry requirements, effective
   segment at each memory access, writes, clobbers, proven restorations, and
   near/far control transfers; temporary ES overrides remain local; an unproved
   DS change conservatively invalidates later DS simplification; callee clobbers
   propagate to callers.

   Progress: complete for the currently recovered function set. The main IR
   path attaches a typed function-local contract with
   exact memory-access segment identities, entry dependencies, explicit writes,
   proven register-backed restorations, exit clobbers, typed refusals, and a
   closed evidence census. The contract also publishes exact pre-instruction
   segment identity states for address formation, without fabricating memory
   access facts. A function-summary owner now adds typed near/far
   call and tail-jump facts, retains unresolved calls as `UNKNOWN_REFUSE`, and
   reaches a deterministic fixed point for transitive callee clobbers. Missing
   or transitively incomplete callees poison effect completeness instead of
   guessing preservation. Frontend call targets use a typed enum, and the old
   collector no longer misclassifies direct near calls as far calls. Focused
   transfer/refusal/propagation tests and the 501-test changed-file gate pass.
   Stack-backed restoration is complete in Alias/IR and is consumed here; the
   summary layer does not infer it.

   Verification after same-block stack restoration: the changed-file gate,
   `make quality-fast`, and 1,398 focused pipeline tests pass. The first default
   pipeline run exposed an order-sensitive Ultra QuickC `args` pointer-call
   loss; its Alias restore census was empty, an immediate isolated rerun passed
   4/4 fixtures, and a complete default rerun passed all three lanes. All six
   serial MS C tiny cases passed compile, original execution, decompile,
   recompile, and generated execution. The initial red run remains performance
   and determinism evidence rather than being discarded.

   Verification after cross-block restoration and the discovery-cache work:
   the 424-test ownership-selected lane and `make quality-fast` pass, including
   1,398 fast tests. The full default pipeline also passes all 1,398 shared
   tests and all six serial MS C tiny build/run/decompile/recompile/run cases.

3. Join function contracts into closed whole-program layout evidence.

   Definition of done: unresolved indirect calls/branches, overlays, incomplete
   discovery, unknown segment sources, or unknown external clobbers force the
   affected verdict to `UNKNOWN`; the result is deterministic and closes
   raw/normalized/classified/materialized/failure counters; classified evidence
   with zero materialization is fatal.

   Progress: core join and serial-worker transport complete; downstream
   consumption remains open. Typed function evidence is serialized with a
   versioned worker schema, cache hits require matching function evidence, and
   the deterministic program contract reports independent discovery,
   control-flow, segment-effect, overlay, primary-data, far-code, far-data,
   huge-normalization, CS/DS, and SS/DS verdicts. Missing summaries, incomplete
   discovery, unresolved indirect control, unknown accesses/effects, external
   targets, and overlays force the affected verdict to `UNKNOWN_REFUSE`.
   Direct fork results now return the evidence explicitly; no state is attached
   to slotted angr `Function` objects. Positive, refusal, malformed transport,
   cache-identity, determinism, and slotted-boundary fixtures pass.

4. Consume only local must-proof in Alias and Types/Lowering.

   Definition of done: proven primary-DS accesses can use coherent globals and
   near pointers; proven far objects and override sites retain correct far or
   explicit segmented forms; unknown cases remain honestly ugly; every changed
   function has `validation=passed`, no semantic call loss, and no address-space
   or observable-memory regression.

   Progress: the main DS object-entry consumers are implemented, but the full
   consumer audit remains in progress. A typed
   segment-access policy matches the function-local IR contract by exact
   instruction provenance, segment register, offset, and width. Only a proven
   physical `ds` source may enter the DS object namespace; proven ES/non-DS
   overrides remain explicit, and missing, unknown, or conflicting local facts
   refuse lowering. Both real-mode dereference and address materializers consume
   this policy and publish a closed typed census. Named and indexed
   segmented-global helpers, load-site evidence, byte-pair loads, and
   near-pointer helpers now pass through the same policy before entering the
   primary DS object namespace. Direct `CVariable` object references and indexed
   dword subword projections are guarded as well. Generated call arguments now
   preserve `CallsiteSummary8616.push_arg_instruction_addrs` through a bound
   Types/Lowering provenance service; address helpers consume exact
   pre-instruction state while memory loads still require exact access facts.
   Late `SEG_U*` runtime accesses now rejoin an exact binary indexed-load site
   before entering the policy: base, width, BP index, scale, and instruction
   address must all agree. This closes the handoff where InsertionSort's
   `DS:0B4C + BP-2*2` load had remained scalar while its proven destination
   family was emitted as an aggregate. The runtime segment helper contract is
   access-neutral and shared by load lowering, store lowering, and final memory
   validation; it still refuses non-entry-DS physical sources.
   Direct `PUSH [DS:index+offset]` call arguments now publish the same exact
   indexed-load fact instead of falling outside the prior register-only
   collector. A typed direct-stack consumer class prevents raw VEX carrier nodes
   for that push from being mistaken for global writes; only the final runtime
   load is materialized. The sidecar-free InitMenu regression therefore emits
   `sub_12756(g_0136[local_2], inertia_ds)` with one `char *` pointer-table
   contract, remains `validation=passed`, and compiles without pointer-conversion
   warnings. Explicit ES and unknown/unsupported segment overrides refuse this
   DS materialization in focused fixtures.
   Focused fixtures cover exact site selection,
   conflicting sites, ES preservation, unknown refusal, DS materialization,
   helper-bypass refusal, and word-write validation identity. Tail validation now
   expands an exactly typed dereference write to byte-precise locations, closing
   the previous false delta between a word DS access and its two-byte global
   representation. The real sidecar-free ShellSort acceptance now emits both
   `sub_107b8` arguments as `&g_0B4C[...]`, retains the call, passes GCC syntax,
   and reports `validation=passed` with a clean whole-tail check. The default
   pipeline is green, while the expanded pipeline exposed and now has a focused
   fix for the InitMenu pointer-table warning; its full serial rerun remains the
   acceptance gate. Remaining work is to audit broader near-pointer type
   consumers and finish that expanded project gate before marking this step
   complete. The current executable-only serial ratchet
   is green at 20 attempted, 20 classified, 20 materialized, 20 decompiled,
   0 validation failures, 0 empty functions, 0 timeouts, and 0 tracebacks.

5. Report compatibility labels and add corpus coverage.

   Definition of done: `TINY`/`SMALL`/`MEDIUM`/`COMPACT`/`LARGE`/`HUGE` labels
   are emitted only as evidence-backed compatibility diagnostics and never feed
   semantics; synthetic model fixtures plus mixed near/far overrides, LDS/LES,
   unresolved indirect control, and unknown segment loads are covered; MS C
   compile/decompile/recompile/execute checks and the serial SORTD expanded lane
   remain clean.

### 9.4 Recover Coherent Global Objects

Owner: Alias establishes storage identity, Widening establishes extents, and
Types/Lowering materializes object and field views.

Progress:

- Widening joins exact indexed byte fields with a project-proven two-byte object
  extent and exact whole-object copy edges; the current project census closes at
  raw=40, normalized=29, classified=3, materialized=3, failures=0
- the `DS:08F0` and `DS:0B4C` arrays share one binary-proven aggregate family;
  regenerated indexed nodes restore that persistent type before scalar low-byte
  projection; exact runtime-load/site reconciliation now also types the
  `BP-8` carrier, so sidecar-free InsertionSort emits
  `local_8 = g_0B4C[local_2]`, valid `.field_0` accesses, coherent aggregate
  stores, and recompiles
- the dedicated `SORTD.EXE` regression requires portable-flat recompilation,
  clean whole-tail validation, both redraw/time call pairs, and all three
  whole-object assignments; this prevents the previous `struct = unsigned
  short` split from returning even when the similarly named `SORTDEMO.EXE`
  fixture remains green
- byte-only consumers now retain the project-family identity through synthetic
  word evidence. Types/Lowering also collects indexed memory reads consumed
  directly by `CMP`, so PercolateUp emits
  `abarWork[i].field_0 <= abarWork[iParent].field_0`, remains
  `validation=passed`, recompiles, and is whole-tail clean
- caller source-family evidence now joins the callee's two proven near-pointer
  arguments, so `sub_107b8` and all current callsites use the same BAR aggregate
  pointee type without source, COD, or symbol-name proof
- callee binary pointer evidence now materializes a missing contiguous trailing
  argument in the active C interface before aggregate typing. Swaps emits two
  `g_08F0_entry *` arguments, preserves the counter increment and all three
  aggregate assignments, recompiles, and reports `validation=passed`
- exact indexed-call evidence classifies `g_0136` as a pointer table, while
  typed high-word condition provenance classifies `g_0132` as a signed wide
  scalar; both materialize at Types/Lowering and refuse contradictory evidence
- the remaining work is the broad canonical storage/data-image contract in
  9.3 and 9.4.1, not another function-local declaration repair

Work:

- unify each proven `Address(DS, offset)` identity across named and segmented
  uses
- recover coherent array/record declarations and bounds from typed access facts
- keep raw segmented accesses whenever object identity or extent is ambiguous

Definition of done:

- one proven storage identity cannot be emitted with incompatible declarations
- indexed BAR access uses one coherent object view and an evidence-backed extent
- raw segmented accesses decrease only when Alias, Widening, and Types evidence
  closes the full raw/normalized/classified/materialized/failure census
- ambiguity tests preserve honest raw memory instead of guessing an object

#### 9.4.1 Materialize One Canonical Program Data Image

Status: planned. This follows the sound segment-state work in 9.3 and precedes
emitting broad inferred global declarations.

Rationale and current gap:

- `masm2c` can emit one packed byte-exact C++ `Memory` object plus typed
  references shared by separately compiled modules because MASM declarations
  prove each label, size, initializer, array, string, and structure
- binary decompilation lacks that source proof, but still needs one canonical
  storage owner; emitting unrelated inferred C globals can lose address
  identity, adjacency, overlays, near-pointer offsets, and exact initial bytes
- the MZ loader currently maps and relocates the executable image, while the
  general global-object widening contract currently recognizes only a narrow
  DS two-byte family; no typed artifact owns initialized bytes, BSS, relocation
  slots, object intervals, and optional typed views together
- Reko's useful design ideas are a program-wide global type anchor, fields at
  exact offsets, interval checks that prevent duplicate fields inside existing
  arrays/structures, and induction stride/count evidence; Reko is GPL, so use
  these as design references rather than copying implementation code

The canonical truth is byte storage per proven segment identity. Scalar,
array, string, record, pointer-table, and overlay classifications are optional
typed views over that storage. Signedness is an independent evidence result;
an initializer bit pattern does not prove it. Printable bytes plus a terminator
are a string candidate, not proof, and NUL-terminated, DOS `$`-terminated, and
fixed byte sequences remain distinct classifications.

The portable output should follow the `masm2c` module boundary without copying
its C++ reference mechanism: emit one `_data.c` definition and one `_data.h`
contract consumed by every generated function module. Proven non-overlapping
layout should use real named packed fields, with C macros exposing those fields
as ordinary lvalues. C89-compatible little-endian load/store functions are only
the fallback for raw, overlapping, or otherwise unsafe offset views; they avoid
C++ references, unaligned typed dereferences, and pointer-cast strict-aliasing
violations. Relocation slots must be retained as relocation metadata and
initialized for the rebuilt program; original load-segment values must not be
copied as ordinary scalar data.

Deferred optional libdosbox runtime evidence:

- `/home/xor/inertia_player/libdosbox/src/custom/` already records per-code-site
  segment-register sets and execution counts, data read/write widths and
  counts, access-site min/max/GCD stride and samples, observed pointer uses,
  control-flow edges, and image load metadata in `<exe>.json`
- the current dosunit importer retains only priorities and coarse access ranges;
  it drops `Data`, `PointerEvidence`, `GcdDelta`, `DistinctCount`, and detailed
  read/write evidence, while the decompiler runtime-refinement summary expects
  a different generic shape and is not a libdosbox sidecar ingestion path
- `Data.Array` currently means only that one executed instruction touched more
  than one address, and runtime `string`/`data_offset` value classes are
  range/printability candidates; neither may be imported as static type proof
- a positive pointer-use event is strong observed-path evidence, and an observed
  access proves a required storage lower bound, but trace absence cannot prove
  dead storage, exact bounds, a must-state segment value, or behavior on an
  unexecuted path
- traces merge monotonically only when binary identity and address rebasing
  match; conflicting observations widen to an overlay or `UNKNOWN_REFUSE`, and
  runtime data never authorizes DCE or validation success

Immediate priority: consume static evidence already collected by the decompiler
before adding runtime-sidecar evidence or new recovery heuristics. Existing
collection is not progress when facts are only cached, summarized, or reported.

Known internal producer-to-consumer gaps:

- `type_structure_merging.py` loads the existing storage-object bridge and
  typed-IR structure candidates, publishes member/array/refusal fact maps, and
  reports `structs_synthesized`, but explicitly performs no materialization
- `GlobalStorageIdentityFact8616`, access-trait storage objects, segmented-memory
  summaries, and the recompilable storage-map exporter already exist, but the
  complete map is not produced and consumed by the main generated-C artifact
- project global-object layout, source-family, and callee-interface evidence is
  partly consumed for the narrow two-byte family, but does not yet feed one
  persistent program object table shared by every function and export module
- current access traits and typed string effects already contain widths,
  offsets, affine stride candidates, source/destination roles, and segment
  provenance; accepted facts should feed Alias/Widening/Types directly instead
  of being used only for naming, diagnostics, or function-local metadata

Collected does not automatically mean proven. Before materialization, classify
each current fact by its existing provenance and move semantic ownership out of
CLI helpers into `X86_16/`. Ambiguous naming hints remain hints. Exact typed IR,
alias identity, access width, compatible affine induction, copy, string effect,
and segment facts may become semantic inputs. Any fact family reported as
classified with no owning consumer is a pipeline failure, not a successful
diagnostic pass.

Order and per-step definition of done:

1. Close the current internal evidence-utilization census.

   Definition of done: every existing storage/object evidence family records
   its producer, proof level, owning layer, consumer, and closed census; tests
   fail when a classified fact is merely attached to codegen/project metadata
   or counted as synthesized without materialization. Diagnostic-only and
   semantic facts use distinct typed verdicts. The census covers access traits,
   storage-object bridge facts, typed-IR structure candidates, string effects,
   global storage identities, project global-object layouts/source families,
   callee interfaces, segment state, and recompilable storage-map candidates.

2. Materialize existing object and structure facts at Types/Lowering.

   Definition of done: `type_structure_merging.py` no longer reports
   `structs_synthesized` for metadata-only candidates; exact bridge member/array
   facts and typed-IR candidates either materialize one compatible type/object
   view or produce a typed refusal. Refusal facts block materialization,
   overlapping compatible views become an explicit overlay, and incompatible
   widths remain raw storage. Focused before/after fixtures show improved C from
   facts already collected before this work, with no new detector or sidecar.

3. Feed existing storage identities into the production program storage map.

   Definition of done: the main decompilation path exports current
   `GlobalStorageIdentityFact8616`, accepted access-trait object facts, project
   global-object family facts, and sound segmented-state facts into one
   deterministic typed storage-map artifact; the existing recompilable map is
   no longer test/subset-only. Every generated function and the translation-unit
   assembler consume the same identities and refusals. Segment facts wait for
   the sound 9.3 must-state prerequisite; unresolved DS/ES identity is retained
   as an explicit refusal rather than flattened.

4. Complete existing interprocedural evidence joins before broadening recovery.

   Definition of done: caller source-family facts, callee pointer-interface
   facts, indexed load/store evidence, string source/destination effects, and
   global declaration specs join by canonical storage identity rather than C
   name. A proven callee aggregate contract reaches its definition and every
   callsite; current classified facts cannot disappear during AST rebuild or
   per-function export. SORTD's existing BAR-family evidence is the first real
   corpus acceptance case.

5. Add a typed loader-owned data-image artifact.

   Definition of done: the artifact preserves each segment identity, exact
   initialized byte span, zero/BSS span, relocation slots, and unavailable
   regions; byte-for-byte tests reproduce the loaded MZ image after relocation;
   overlapping or unresolved segments remain distinct and explicitly refused
   rather than flattened.

6. Generalize the now-consumed storage map into an interval-based
   Alias/Widening object map over canonical bytes.

   Definition of done: Alias owns `(segment identity, offset interval)` and
   prevents duplicate standalone objects for overlapping bytes; Widening joins
   static access widths, affine stride, proven bounds, copies, and compatible
   runtime observations into typed lower/exact extents; scalar, array, string,
   record, pointer-table, and overlay verdicts have explicit provenance and
   refusal states; signedness conflicts remain unknown.

7. Materialize typed views only in Types/Lowering and render shared storage only
   in export/CLI.

   Definition of done: semantic layers produce the complete object/view
   contract before export; CLI performs no inference; one storage definition is
   shared by all separately compiled generated modules; near pointers remain
   segment-relative offsets and far pointers retain both components; GCC
   portable-flat and MS C DOS builds pass without duplicate globals, unaligned
   typed dereferences, strict-aliasing dependence, or copied absolute relocation
   values.

8. Close the static storage and recompilation test lanes.

   Definition of done: sidecar-free decompilation remains deterministic and
   validation-equivalent; wrong-width, segment-override, overlay, pointer-table,
   NUL-string, DOS-string, and false-printable static fixtures refuse safely; a
   multi-function compile/decompile/recompile/execute fixture proves shared
   initial storage and cross-module mutation; MS C tiny and serial SORTD
   expanded gates do not regress. The static storage milestone is complete
   without requiring or reading libdosbox JSON.

9. Parse the current libdosbox JSON into typed runtime observations.

   Definition of done: an explicit runtime-sidecar input reaches a frontend
   parser under `X86_16/`, not Rewrite or a CLI text repair; it retains `Code`
   segment sets, execution counts, accessed data, edges and self-modification,
   `Data` read/write widths and counts, value targets, `AccessSites` ranges,
   GCD stride, distinct count and samples, `PointerEvidence`, `Jumps`, and `Abi`.
   Missing optional keys are accepted, malformed masks/addresses are typed
   refusals, and the current schema is tagged `LEGACY_UNVERIFIED` unless the
   existing image dump/meta can verify identity. Legacy evidence is still
   usable as observed-path refinement, never as static or must-path proof.

10. Wire optional runtime observations into existing semantic evidence
    consumers.

    Definition of done: runtime CS:IP and physical addresses are rebased to the
    same typed instruction and storage identities as static IR; per-site segment
    sets corroborate or refute segment candidates, `Data` widths corroborate
    access width, `AccessSites` provide observed extent/stride lower bounds,
    `PointerEvidence` strengthens a matching static load-to-use pointer chain,
    edges are accepted only after static decode verifies their endpoints, `Abi`
    cross-checks static call contracts, and observed self-modification forces an
    explicit refusal. At least one focused before/after fixture materializes a
    better typed view from compatible static plus runtime evidence. Every family
    closes separate static and runtime raw/normalized/classified/materialized/
    failure counts; imported evidence that reaches no consumer fails the gate.

11. Harden the runtime producer and promote verified sidecars without abandoning
    legacy input.

   Definition of done: new sidecars add a schema version, binary/image hash,
   load segment, image size, run/scenario identity, termination state, and
   truncation counters; verified and legacy observations share one typed model
   but preserve distinct provenance; mismatched binaries are rejected clearly.
   Collection stays aggregate and bounded and does not materially increase peak
   memory.

12. Close the optional runtime-refined and conflict test lanes.

    Definition of done: matching JSON can strengthen only a compatible static
    candidate and records separate static/runtime evidence counts; wrong-hash,
    partial-run, conflicting runtime width/segment/pointer, and trace-absence
    fixtures refuse safely; sidecar-free output and validation remain unchanged;
    MS C tiny and serial SORTD expanded gates do not regress.

### 9.5 Expand Behavioral Equivalence

Owner: test pipeline and DOS/native harnesses; the harness may adapt runtime and
storage interfaces but must not replace generated function logic.

Work:

- expand the current nine-function gate to every source-selftested function
- add RunMenu ESC, DrawTime, and Beep behavior cases
- retain sanitizer-backed native checks and MS C DOS oracle comparison

Definition of done:

- every source-selftested generated function is compiled and executed unchanged
- RunMenu exits on ESC and still dispatches all tested menu commands
- timing and sound functions consume the same argument values as the source
- missing functions, wrong exit codes, sanitizer findings, and behavior mismatch
  are fatal in the expanded serial pipeline
- whole-program equivalence is claimed only after all externally observable
  source scenarios are represented

Progress:

- CMP32 now preserves complete signed scalar-return facts across Structuring
  C-AST regeneration and consumes them in Types/Lowering only when every final
  return value matches structurally. Sidecar-free `compare_signed` and
  `compare_unsigned` emit signed `int` results with the correct signed/unsigned
  32-bit arguments, stable Structuring/Postprocess validation, and no locals.
  The focused no-sidecar regression passes 4/4; the MS C rebuild and DOS runtime
  sentinel exits with the expected code 255. Changed-file Ruff, Pyright,
  type/docs, architecture, ownership, and 82 focused tests pass.

### 9.6 Make Diagnostics and Performance Actionable

Status: in progress. Validated whole-function reuse is complete; pass-level
profiling and immutable intermediate analysis caches remain open.

Owner: typed pipeline telemetry and serial CLI orchestration.

Work:

- classify angr store-size mismatch warnings as structured evidence outcomes
- profile pass-level time for InitBars, RunMenu, QuickSort, and InitMenu
- persist content-addressed, immutable discovery, exact CFG-slice, call-summary,
  and segment-summary artifacts keyed by binary, tool, configuration, and input
  contract digests
- skip idempotent stage replay only when typed input and output digests prove the
  stage result unchanged and its evidence census is already closed
- cache deterministic discovery and immutable analysis evidence where proven
  safe; keep function fallback rebuilds serial until their mutable shared state
  is isolated, while parallelizing independent tests within the measured 2 GiB
  aggregate RSS budget

Progress:

- serial clean workers now use a bounded content-addressed cache whose key
  covers the binary and sidecars, all production decompiler source, effective
  CLI/environment policy, requested and canonical addresses, timeout, signature
  catalog, exact caller-return evidence, and result protocol schema
- only nonempty `ok` payloads with matching validated/compiler hashes and
  passed structuring and postprocess tail snapshots are reusable; diagnostic
  layer dumps bypass the cache, and pruning is limited to this cache namespace
- display-catalog persistence now stores a versioned typed contract containing
  ordered addresses, closed source-region counters, and exact caller-return
  evidence. Legacy address-only or inconsistent payloads are misses, so cached
  discovery cannot silently drop evidence needed by return typing or calls
- the direct-worker acceptance boundary now transports the compiler-checked
  normalized payload whose hash it reports, closing the prior payload/hash
  mismatch without changing decompiler semantics
- measured 2026-08-01 final-code sidecar-free `SORTD.EXE` cold population:
  `645.38s`, `308252 KiB`, `20/20` validated, no fallback, clean whole-tail
  validation; immediate warm run: `14.19s`, `191640 KiB`, 20 exact worker cache hits,
  `20/20` validated, no fallback, clean whole-tail validation
- cold and warm generated C streams are byte-identical at SHA-256
  `1529f1953ae8f4bb76cf16a2560a3837332c714bc4bc9717a50c589d73db4d8f`;
  measured wall-time improvement is `45.48x` and peak RSS is 37.8 percent lower
- a 2026-08-05 four-clean-process experiment stayed near 1.2 GiB aggregate RSS
  and completed its first phase in about 235 seconds, but InitMenu `0x10060`
  reproducibly lost two arguments at callsite `0x10133`; tail validation rejected
  both the parallel result and a subsequent serial acceptance retry. The same
  function passed alone in 87.55 seconds. Memory is not the blocker: whole-file
  function rebuilds remain serial until order-sensitive recovery is eliminated
- pure-binary whole-file x86-16 runs now select clean serial interpreters by
  default, without `INERTIA_ENABLE_SERIAL_FORK_PER_FUNCTION`; the 2026-08-05
  cold `SORTD.EXE` acceptance ran from 06:30:37 to 06:39:11 and passed `20/20`
  with zero validation failures, timeouts, tracebacks, or ratchet violations
- the 424-test ownership-selected gate, `make quality-fast` with 1,398 tests,
  and the full pipeline with all six MS C tiny round trips pass

Definition of done:

- a size mismatch cannot finish as success unless validation explicitly proves
  it harmless and records that proof
- a profile identifies the dominant pass costs for the four slowest functions
- cold-cache and warm-cache runs emit byte-identical C, validation results, and
  evidence counts; stale binary, tool, configuration, or contract digests force
  recomputation
- an optimization shows a repeatable wall-time reduction without changing C,
  validation, behavior, or evidence counts
- decompilation remains serial, cache size is bounded, and measured peak memory
  does not regress
