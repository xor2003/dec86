# Consumed Stack-Address Setup (2026-09-08)

## Scope And Root Cause

InitBars' LEA at `0x1058e` was published as a numeric AX update before call
arguments were recovered. Later PUSH cleanup did not receive that producer.
After stack storage materialization, the unused numeric update contained a
host pointer and prevented compilation. A pointer-to-integer cast would have
hidden the bad projection instead of proving it redundant.

## Production Repair

- Semantics owns exact register-bit effects and the bounded caller/callee
  proof. The only caller read may be the exact recovered word PUSH; the
  callee must overwrite every incoming bit before any use. Partial writes,
  additional reads, frame changes, unknown effects and control flow refuse.
- Recovery metadata reads bounded original-image bytes without lifting or
  mutating the project. Synthetic targets and invalid image ranges refuse.
- Lowering requires the canonical low-word runtime-register assignment,
  unchanged upper bits, a pure address expression, exact call/PUSH identities,
  and the recovered argument's registered BP storage projection. Other AST
  register uses or ambiguous argument matching refuse.
- The existing final callsite boundary invokes this Lowering consumer. There
  is no semantic recovery in Rewrite or CLI, and no sample-specific address
  or function-name rule in production.
- An owned census records raw, normalized, classified, materialized and failed
  candidates. A proven but unmaterialized deletion is a hard pipeline error.

## Evidence

The normal sidecar-free worker command was:

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 \
INERTIA_SERIAL_CLEAN_WORKER_RESULT=/tmp/inertia-consumed-setup-initbars-worker.json \
./decompile.py SORTD.EXE --addr 0x10560 --ignore-local-sidecar-hints \
  --no-alternate-source-c --timeout 180 -q
```

It completed with `status=ok` in 21.94s of worker analysis. Structuring and
Postprocess whole-tail checks are stable; accepted-C and GCC hashes match:
`b9b70afc7287f726c46e5b3c208ea9a31f00510ecac45700c5dce0bf4c75d670`.
The payload is byte-identical to the earlier isolated diagnostic deletion.
Only the redundant assignment and its orphan declaration differ from the
previous rejected baseline. Source-required time/seed, video configuration,
random selection and final ReInitBars calls remain, including the pointer
argument to the 22-byte video configuration object and the 43-word array.

Fifty focused proof/consumer tests pass. Scoped Ruff `check --fix`, MyPy and
Pyright pass. Full architecture checks pass after correcting ownership headers
and adding the register-proof tests to both QA and pipeline inventories.
Global quality-fast still fails with 99 MyPy diagnostic lines outside these
new owners. Logs use `/tmp/inertia-consumed-setup-` prefixes.

The final default pipeline passes **2,425 tests in 93.32s**, all three lanes,
and all seven MS C tiny build/run/decompile/recompile/exit-code round trips.
It now includes the sidecar-free InitBars regression, which also passed alone
in 69.28s (58.80s test body). This admission is mirrored in QA_PYTEST_TARGETS.
The final architecture admission check passes. The pipeline's warm repeat is
not a controlled speed comparison; its slowest unit cases were indexed-address
inventory (20.44s), layer-boundary checks (16.38s), and pointer outputs (15.53s).

Measured integration interval, local UTC+02:00: production module creation at
12:13:48, final pipeline completion at 12:28:37, about **14m49s**. Final pipeline
log creation/completion: 12:26:20-12:28:37, about **2m17s**. These filesystem
timestamps bound this integration/gating interval, not total investigation or
earlier proof implementation time. The named regression took 281.53s and still
failed; that work is not counted as completion.

## Remaining Scope

Both pre-existing InitBars regressions now pass validation and compilation
before reaching output assertions. The sidecar-free assertion expected decimal
`65535` but the equivalent mask is now emitted as `0xffff`; the assertion now
permits both exact values without weakening the required initialization.
The named-output regression still fails because `fSound` and other source
names are not retained. Its assertions were not relaxed. This remains an open
quality failure; it is not a reason to claim the whole function/plan finished.

InitMenu, other full-suite failures, global typing and remote CI remain open.
Performance Step 10 remains deferred. The 21.94s run is not a controlled speed
measurement or a basis for estimating completion of the remaining plan.
