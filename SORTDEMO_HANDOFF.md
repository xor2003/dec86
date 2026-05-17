# SORTDEMO Handoff

Purpose: reduce cold-start cost for the active `SORTDEMO.EXE` lane.

Last updated: 2026-05-17 (late session)

## Acceptance truth

A function is accepted only if all are true:

- `generated_c=true`
- `tail_validation=passed`
- final quality guard passed
- gcc syntax check passed for `portable-flat`
- `status=ok`

Actual gate:

- [cli_core.py](/home/xor/vextest/inertia_decompiler/cli_core.py:986) `_validated_generated_c_acceptance_8616(...)`

Important: files under `angr_platforms/.cache/tail_validation_details/` are diagnostic artifacts only. They do not imply success and do not override acceptance.

Relevant code:

- [tail_validation.py](/home/xor/vextest/inertia_decompiler/tail_validation.py:174) detail artifact writer
- [work_items.py](/home/xor/vextest/inertia_decompiler/work_items.py:56) has a local `status="ok"` meaning “snapshot exists for summary”, not “function accepted”

## Current live status

### `0x10678 ReInitBars` — ✅ ACCEPTED (status=ok)

Current state after fixing call arg materialization:

- `generated_c=true`
- `tail_validation=passed`
- `status=ok`
- decompiles near-identically to original source

Fix applied: [decompiler_postprocess_calls.py:2465](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py:2465) — when a stack probe helper (aNchkstk) has a callsite summary but no typed stack probe fact, the legacy backtracker must remain enabled. Previously the condition `elif summary is None` skipped this case, causing `probe_seen_without_ss_address=True` which blocked all subsequent call arg materialization.

### `0x10768 SwapBars` — ✅ ACCEPTED (status=ok)

- `generated_c=true`
- `tail_validation=passed`
- `status=ok`
- decompiles correctly: `DrawBar(iRow1); DrawBar(iRow2);`
- unblocked by the same ReInitBars fix

### `0x10970 HeapSort` — ✅ ACCEPTED (status=ok)

- `validation=passed`
- `status=ok`
- Fix: added `PercolateUp`, `PercolateDown`, `SwapBars`, `Swaps` to `KNOWN_HELPER_SIGNATURE_DECLS` in [analysis_helpers.py](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/analysis_helpers.py:37)
- Fix: changed `Swaps` prototype to `void Swaps(void *a, void *b)` to avoid SEG_PTR incompatible-pointer-type error with -Werror
- Decompiles correctly: `PercolateUp(i)`, `Swaps(SEG_PTR(ds, 2892), ...)`, `SwapBars(0, i)`, `PercolateDown(i - 1)`

### `0x10010 main` — status=error

- `validation=passed` but gcc syntax check fails
- Error: `assignment to 'short unsigned int' from 'char *' makes integer from pointer without a cast` — `vvar_20 = &s_8`
- Pre-existing issue, not caused by the fixes in this session

### Other functions

All 19 non-main functions pass (some with missing tail validation stages — not blocking per acceptance rules).

## Important false trails already ruled out

Do not spend tokens re-proving these unless current code regressed:

- `tail_validation_details` cache is not acceptance
- `ReInitBars` is not currently blocked by recurrence admission
- `ReInitBars` is not currently blocked by tail-validation baseline clone creation
- `ReInitBars` is not currently blocked by `clock` wrong arity
- `ReInitBars` is not currently blocked by return-type signature mismatch
- `ReInitBars` is not currently blocked by `DrawBar` missing argument 0 (fixed 2026-05-17)
- Stack probe `aNchkstk` typed-fact gap: summary exists but no typed fact → backtracker blocked. Fixed by always enabling legacy path when typed fact is missing.

## Current recommended execution order

1. ~~Close `0x10678 ReInitBars` compile-readiness.~~ DONE
2. ~~Classify/fix `0x10768 SwapBars` gcc failure.~~ DONE
3. ~~Fix `0x10970 HeapSort` gcc syntax error.~~ DONE
4. Classify/fix `0x10010 main` gcc syntax error (`vvar_20 = &s_8` — pointer-to-int assignment)
5. Run test suite to verify no regressions

## Commands

Single function:

```bash
INERTIA_ENABLE_TAIL_VALIDATION=1 \
./.venv/bin/python ./decompile.py \
  --alternate-source-c \
  --c-target portable-flat \
  --addr 0x10678 \
  ./SORTDEMO.EXE
```

Full sweep:

```bash
INERTIA_ENABLE_TAIL_VALIDATION=1 \
./.venv/bin/python ./decompile.py \
  --alternate-source-c \
  ./SORTDEMO.EXE
```

## Tests that matter for the current lane

- [test_x86_16_sortdemo_regressions.py](/home/xor/vextest/angr_platforms/tests/test_x86_16_sortdemo_regressions.py)
- [test_x86_16_tail_validation_fingerprint.py](/home/xor/vextest/angr_platforms/tests/test_x86_16_tail_validation_fingerprint.py)
- [test_x86_16_decompiler_postprocess_calls.py](/home/xor/vextest/angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py)
- [test_x86_16_decompiler_postprocess_callsites.py](/home/xor/vextest/angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py)
- [test_x86_16_stack_prototype_promotion.py](/home/xor/vextest/angr_platforms/tests/test_x86_16_stack_prototype_promotion.py)

## Rule for the next agent

Facts are not success. Bindings are not success. Only one of these counts:

- emitted output materially improved and passed validation
- emitted output now compiles
- or a more precise blocker replaced a vaguer blocker
