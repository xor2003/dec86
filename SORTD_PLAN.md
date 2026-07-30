# Sidecar-Free SORTD Plan

Goal: decompile the executable-only SORTD image to validated, recompilable C
without `.COD`, `.LST`, `.MAP`, appended debug data, or source substitution.

Current baseline (2026-07-30):

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
- forced-serial mode runs one synchronous clean interpreter per function;
  do not parallelize fallback rebuilds until a bounded-memory design and stress
  test prove that it cannot exhaust memory

## 1. Deterministic Binary Discovery

Status: complete.

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
- the lane requires the current floor of 13 accepted C functions, no empty
  function, no timeout signal, and no traceback
- parser, pipeline-contract, ownership, Ruff, and Pyright tests pass

## 4. Remove Noisy Pipeline Exceptions

Status: complete.

Owning layers:

- timeout cleanup: `inertia_decompiler/runtime_support.py` and discovery timeout
  orchestration
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
  caller-use evidence proves `0x106c8` has a void return contract, while CLI
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

- The ordinary `./decompile.py ./SORTD.EXE` path and executable-only report
  accept all 20 functions with `validation=passed` and no fallback, empty
  result, timeout, traceback, discovery failure, or source-contract violation.
- The current expanded pipeline passes 1,369 focused tests, all QuickC fixtures,
  all six MS C tiny compile-decompile-recompile-execute parity cases, and both
  whole-binary lanes; all five serial lanes pass.
- The last broad baseline passed `make quality-fast` and 1,883 mapped tests;
  current worker-policy, command-construction, lint, type, and architecture
  gates pass. The unit lane's 43.086 seconds remains advisory debt.

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
- the full mapped pytest set passes; current independently tracked COD
  integration blockers are `_dos_free`, `_dos_loadProgram`, `_max`,
  `_MousePOS`, `_SetGear`, and `_SetDLC`
- the final ratchet requires 20 accepted C functions, 0 empty functions, and 0
  tracebacks
