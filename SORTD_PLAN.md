# Sidecar-Free SORTD Plan

Goal: decompile the executable-only SORTD image to validated, recompilable C
without `.COD`, `.LST`, `.MAP`, appended debug data, or source substitution.

Current baseline (2026-07-29):

- discovery evidence: raw=20, normalized=20, classified=20, materialized=20,
  failures=0
- selected and attempted: 20/20
- accepted C: 3/20 (`0x10768`, `0x107b8`, and `0x10e70`); the ratchet requires
  4/20
- validation failures: 15/20 in the last full baseline
- empty C: 2/20 in the last measured baseline (`0x102e0` and `0x10560`);
  both contain partial generated C and are now classified as
  `validation_failed`, pending a full baseline refresh
- timeout and traceback counts: 0
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
- the lane requires the current floor of 4 accepted C functions, at most 1
  empty function, and no traceback
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

Status: in progress.

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
- `0x10010`: the return value of the call at `0x10021` is disconnected from
  the subsequent store at `0x10027`
- `0x10f38`: wide `DX:AX` call-result arithmetic and loop-bound transfer lose
  the initial `clock() + delay` relationship

Completed infrastructure:

- near JCC/JMP targets retain relocated linear addresses
- final condition materialization recomputes CFG-proven conditions after AST
  drift
- caller-return evidence crosses recovered-project and clean-process boundaries
- forced serial execution always uses one synchronous clean worker, even when
  telemetry/background threads exist

Definition of done for each fixed family:

- add a minimal typed regression at the earliest owning layer
- add or tighten one real SORTD function regression
- focused function reports `validation=passed`
- required calls survive with correct value/pointer argument classes
- output is closer to `SORTDEMO.C` than the previous baseline
- Ruff `--fix`, Pyright, focused tests, and `make check-files` pass
- increase `minimum_decompiled` or reduce another failure ceiling immediately

## 6. Recover The Empty Function

Status: in progress.

Work:

- retain generated partial C as `validation_failed`, never misreport a pipeline
  contract failure as an empty decompilation
- capture the typed stop/pass/block family for every genuinely empty result
- fix the earliest lift, IR, alias, widening, type, or structuring owner
- do not add address/name/source-sidecar substitutions

Definition of done:

- the full sidecar-free run reports zero genuinely empty functions
- tail validation passes
- required source-level calls survive with correct argument classes
- lower the lane's `maximum_empty` from 1 to 0

## 7. Close The Whole-Binary Goal

Status: pending.

Definition of done:

- sidecar-free evidence remains `20/20/20/20/0`
- all 20 functions emit generated C
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
