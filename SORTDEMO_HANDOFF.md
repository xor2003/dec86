# SORTDEMO Handoff

Purpose: reduce cold-start cost for the active `SORTDEMO.EXE` lane.

Last updated: 2026-06-12 (current SORTDEMO plan)

## 2026-06-12 restart note

The older per-function status below is stale. The latest visible
`./decompile.py SORTDEMO.EXE | tee SORTDEMO.dec` emitted 20 non-library
functions, but several functions still contain semantic leakage:

- `ReInitBars`: stack/local recurrence and byte-carrier leakage; wrong-looking
  `clock`/temporary materialization; raw segmented memory expressions.
- `QuickSort`: many `vvar_*` carriers and standalone `MK_FP(...)`
  expressions; pointer/index lowering is not materialized.
- `PercolateDown`: loop-carried update is missing/incorrect; emitted empty
  body shape indicates lowering/structuring handoff lost state.
- `BubbleSort`: likely loop-carried switch/update loss.
- `InitBars`: bad signature/prototype shape and global array/segmented memory
  lowering leakage.
- `RunMenu` and `InitMenu`: raw flag/JCC expressions and segmented global
  accesses still leak.

Do not mark any function accepted from this file alone. Acceptance still means:

1. generated C exists,
2. tail validation passes honestly,
3. recompilation passes,
4. source/call semantics are preserved when source evidence exists,
5. output is closer to original source than the previous baseline.

## Source runtime oracle

`SORTDEMO.C` has a source selftest mode. Use it as the behavior oracle while
fixing decompiler output:

```bash
make sortdemo-selftest PYTHON=./.venv/bin/python
```

This builds `SORTDEMO.C` with MS C 5.1 using
`SORTDEMO_FUNCTION_SELFTEST`, writes artifacts under
`examples/build_msc6/sortdemo_selftest/`, runs the result with kvikdos, and
requires DOS exit code `255`.

Selftest failure codes are per implemented SORTDEMO function:

- `1` `InitMenu`
- `2` `DrawFrame`
- `3` `RunMenu`
- `4` `DrawTime`
- `5` `InitBars`
- `6` `ReInitBars`
- `7` `DrawBar`
- `8` `SwapBars`
- `9` `Swaps`
- `10` `InsertionSort`
- `11` `BubbleSort`
- `12` `HeapSort`
- `13` `PercolateUp`
- `14` `PercolateDown`
- `15` `ExchangeSort`
- `16` `ShellSort`
- `17` `QuickSort`
- `18` `Beep`
- `19` `Sleep`

## Current fix plan

Work function-by-function, smallest first, but fix each defect at the owning
layer:

1. **Gate first**: keep `make sortdemo-selftest` passing. For decompiled
   output, require validated/emitted/recompiled source identity where possible.
2. **Signatures and calls**: fix bad prototypes and argument classes in
   type/call lowering, not CLI text postprocess. Scorecards must preserve
   required calls such as `Swaps(POINTER, POINTER)` and `DrawBar(VALUE)`.
3. **Loop-carried state**: fix missing updates like `PercolateDown` and
   `BubbleSort` in lowering/structuring handoff, with focused tiny MS C
   examples when a smaller reproducer is possible.
4. **Segmented globals and arrays**: materialize `abarWork`, `abarPerm`, and
   menu/string globals through typed segmented lowering, not flattened
   `(seg << 4) + off` arithmetic and not standalone carrier expressions.
5. **Widening/materialization**: prove and consume byte/word carrier facts.
   If widening facts are classified but not materialized, fail with a precise
   blocker rather than cleaning it up later.
6. **JCC/flags**: raw flag expressions in `RunMenu`/`InitMenu` belong in
   condition recovery. Emit explicit `if (x < y)` style conditions only when
   the condition proof exists.
7. **DCE**: unknown means keep. DCE must never be used to make gcc pass by
   deleting live setup for calls, loops, or stack/segment provenance.

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

### `0x10010 main` — ✅ ACCEPTED (status=ok)

Fixed at the stack-lowering layer:
- [cli_stack_byte_offsets.py](/home/xor/vextest/inertia_decompiler/cli_stack_byte_offsets.py) — AST alias pass handles dirty virtual carriers (CDirtyExpression) and same-register carrier reuse
- [stack_lowering_impl.py](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_impl.py) — strengthened lowering for direct indexed stack-carrier aliases
- Eliminated the `vvar_20 = &s_8` carrier chain; now emits direct stack-relative expressions

### `0x10f38 Sleep` — status=error (pre-existing)

- `validation=passed` but gcc syntax check fails
- Error: `conflicting types for 'ir_3_2'; have 'char'`
- Pre-existing, not caused by any changes in this session

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
3. ~~Fix `0x10970 HeapSort` gcc syntax error.~~ DONE (prototypes + Swaps void*)
4. ~~Fix `0x10010 main` gcc syntax error.~~ DONE (stack-lowering: cli_stack_byte_offsets.py)
5. ~~Fix `0x10f38 Sleep` gcc syntax error.~~ DONE (dedup + if(false) + gcc flags)
6. Fix `0x109e8 PercolateUp` — `*(vvar_N ± K)` integer-as-pointer, same class as main() fix. Extend stack-lowering to handle this carrier shape in PercolateUp.
7. Run full test suite to verify no regressions

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
