# Check Latest (2026-04-22T15:47:00+02:00)

## Top Failure Families

1. `validation-uncollected`
- Sweep lane records `validation=disabled` per-function.
- Treat semantic status as `uncollected`; do not infer pass/fail.

2. `stack-segment`
- Shown outputs still include raw segmented memory forms (`(ss << 4)`, `(ds << 4)`) on core paths (`main`, `HeapSort`, `PercolateUp`, `SwapBars`, `ReInitBars`, `Beep`, `Swaps`).
- Indicates typed stack/global lowering remains incomplete on these anchors.

3. `condition-quality`
- Condition/value expressions still show low-level artifacts (`ir_*`, mixed-width carry-style compositions), notably in `Sleep` and `PercolateUp`.
- Typed `Condition` coverage is incomplete for these paths.

## Focused Addresses / Functions

Deterministic checker anchors (from current `PLAN.md`):
- `0x10010` `main`
- `0x102e0` `RunMenu`
- `0x10768` `SwapBars`
- `0x10970` `HeapSort`
- `0x109e8` `PercolateUp`
- `0x10ce0` `QuickSort`
- `0x10f38` `Sleep`

Current bounded sweep evidence (`--max-functions 8`, timeout 6s):
- Exit: `0`
- Summary: `shown=8 decompiled=8 asm_or_detail_fallback=0`
- Validation visibility: `disabled` (no `changed/unknown/uncollected` classification emitted by this lane)
- Functions shown: `main`, `Sleep`, `PercolateUp`, `HeapSort`, `Swaps`, `SwapBars`, `ReInitBars`, `Beep`

## Exact One-Function Verification Commands

```bash
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x102e0 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10970 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c
./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c
```

## Evidence Inputs

- `.codex_automation/evidence.log`
- `.ralph/agent/sweep.latest.md`
- `PLAN.md`
- `AGENTS.md`
