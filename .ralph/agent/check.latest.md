# Check Latest (2026-04-23T12:06:03+02:00)

## Top Failure Families

1. `validation-uncollected`
- Latest bounded scan-safe sweep remains stable and attributable: exit `0`, `8/8` shown functions decompiled, `asm_or_detail_fallback=0`.
- All 8 shown functions still report `validation=uncollected`; under AGENTS.md this is not success and must not close any PLAN item.
- Bounded display coverage remains intentionally partial: `0x102e0 RunMenu` and `0x10ce0 QuickSort` are not shown in the first 8 functions and still depend on exact one-function evidence.
- Existing exact evidence keeps omitted anchors attributable: `0x10ce0 QuickSort` completes under the 30s lane with `validation=uncollected`; `0x102e0 RunMenu` times out at 30s but completes at 60s, still `validation=uncollected`.

2. `stack-segment`
- Current worker/reviewer evidence proves only an ordering/ownership cleanup: typed SS lowering now runs before CLI stack cleanup, and `lowering/stack_lowering.py` no longer uses `globals().update`.
- PLAN #1 remains open because exact-lane output for `0x10010 main` and `0x109e8 PercolateUp` is unchanged and still contains raw `ss << 4` / `vvar_*` stack-carrier stores.
- The next implementation owner should stay in helper/callsite return-state and typed SS stack-address evidence, not postprocess or rendered-text cleanup.

3. `condition-quality`
- Typed condition production remains a focused blocker for `0x10f38 Sleep` and `0x109e8 PercolateUp`.
- Current sweep evidence does not prove branch-condition cleanup complete; condition work must stay tied to typed condition/ALU evidence and exact one-function repros.

4. `slow-exact-lane`
- `0x102e0 RunMenu` remains the deterministic-coverage risk: the 30s exact lane exits `3` with an explicit timeout banner, while the 60s retry exits `0`.
- Treat this as a reporting/validation attribution problem until the 30s lane either completes with explicit attribution or the timeout path itself records sufficient attributable coverage.

## Focused Addresses / Functions

Primary anchors from current `PLAN.md`:
- `0x10010` `main`
- `0x102e0` `RunMenu`
- `0x10768` `SwapBars`
- `0x10970` `HeapSort`
- `0x109e8` `PercolateUp`
- `0x10ce0` `QuickSort`
- `0x10f38` `Sleep`

Support anchors from current sweep/PLAN evidence:
- `0x10678` `ReInitBars`
- `0x107b8` `Swaps`
- `0x10e70` `Beep`

Latest bounded sweep evidence (`2026-04-23 12:03:47-12:03:50 +0200`):
- Command: `./.venv/bin/python -u decompile.py "${PWD}/SORTDEMO.EXE" --timeout 6 --max-functions 8`
- Exit: `0`
- Summary: `shown=8 decompiled=8 asm_or_detail_fallback=0`
- Validation visibility: all 8 shown functions are `validation=uncollected`; no `validation=disabled`
- Functions shown: `0x10010 main`, `0x10678 ReInitBars`, `0x10768 SwapBars`, `0x107b8 Swaps`, `0x10970 HeapSort`, `0x109e8 PercolateUp`, `0x10e70 Beep`, `0x10f38 Sleep`
- Not shown in this bounded lane: `0x102e0 RunMenu`, `0x10ce0 QuickSort`

Exact one-function follow-up evidence already recorded in `.codex_automation/evidence.log`:
- `0x10ce0 QuickSort`: `validation=uncollected`, `exit=0`, completed in `25.34s` with `--timeout 30`
- `0x102e0 RunMenu`: `validation=uncollected`, `exit=3`, explicit timeout banner with `--timeout 30`
- `0x102e0 RunMenu` retry: `validation=uncollected`, `exit=0`, completed in `53.05s` with `--timeout 60`

Planner-facing family to anchor map:
- `validation-uncollected`: `0x10010`, `0x102e0`, `0x10768`, `0x10970`, `0x109e8`, `0x10ce0`, `0x10f38`
- `stack-segment`: `0x10010`, `0x10768`, `0x10970`, `0x109e8`; support checks `0x10678`, `0x10e70`
- `condition-quality`: `0x10f38`, `0x109e8`
- `slow-exact-lane`: `0x102e0`

## Exact One-Function Verification Commands

```bash
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x102e0 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x102e0 --timeout 60 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10678 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10970 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10e70 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c
```

## Evidence Inputs

- `AGENTS.md`
- `PLAN.md`
- `.codex_automation/evidence.log`
- `.ralph/agent/sweep.latest.md`
- `.ralph/agent/worker.latest.md`
- `.ralph/agent/review.latest.md`
