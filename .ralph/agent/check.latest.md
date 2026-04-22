# Check Latest (2026-04-22T18:08:00+02:00)

## Top Failure Families

1. `validation-uncollected`
- Latest bounded sweep stayed stable and attributable, but all 8 shown functions still report `validation=uncollected`.
- Coverage gap in the bounded display lane remains explicit rather than silent: `0x102e0 RunMenu` and `0x10ce0 QuickSort` are still omitted from the shown 8-function set and must be checked via exact one-function runs.
- `RunMenu` is still the sharpest planner/checker concern because the deterministic 30s lane times out (`exit=3`) and only the 60s retry completes, even though both lanes preserve `validation=uncollected`.

2. `stack-segment`
- Active plan anchors for helper/alias/object lowering remain clustered around raw segmented stack/global forms: `SwapBars` (`0x10768`), `main` (`0x10010`), `HeapSort` (`0x10970`), `PercolateUp` (`0x109e8`), plus the same sweep-side support anchors `ReInitBars` (`0x10678`) and `Beep` (`0x10e70`).
- This still points at earliest-layer typed stack/object evidence gaps, not rewrite cleanup.

3. `condition-quality`
- Remaining low-level condition artifacts are still concentrated on `Sleep` (`0x10f38`) and `PercolateUp` (`0x109e8`).
- The earlier width-boundary fix removed one blocker, but typed `Condition` production is not complete yet.

## Focused Addresses / Functions

Deterministic planner/checker anchors from current `PLAN.md`:
- `0x10010` `main`
- `0x102e0` `RunMenu`
- `0x10768` `SwapBars`
- `0x10970` `HeapSort`
- `0x109e8` `PercolateUp`
- `0x10ce0` `QuickSort`
- `0x10f38` `Sleep`

Current bounded sweep evidence (`--max-functions 8`, timeout 6s, `2026-04-22 18:02:14-18:02:15 +0200`):
- Exit: `0`
- Summary: `shown=8 decompiled=8 asm_or_detail_fallback=0`
- Validation visibility: `uncollected` for all 8 shown functions
- Functions shown: `0x10010 main`, `0x10678 ReInitBars`, `0x10768 SwapBars`, `0x107b8 Swaps`, `0x10970 HeapSort`, `0x109e8 PercolateUp`, `0x10e70 Beep`, `0x10f38 Sleep`
- Not shown in this bounded lane: `0x102e0 RunMenu`, `0x10ce0 QuickSort`

Exact one-function follow-up evidence already recorded in `.codex_automation/evidence.log`:
- `0x10ce0 QuickSort`: `validation=uncollected`, `exit=0`, completed in `25.34s` with `--timeout 30`
- `0x102e0 RunMenu`: `validation=uncollected`, `exit=3`, explicit timeout banner with `--timeout 30`
- `0x102e0 RunMenu` retry: `validation=uncollected`, `exit=0`, completed in `53.05s` with `--timeout 60`

Planner-facing family to anchor map:
- `validation-uncollected`: `0x10010`, `0x102e0`, `0x10768`, `0x10970`, `0x109e8`, `0x10ce0`, `0x10f38`
- `stack-segment`: `0x10768`, `0x10010`, `0x10970`, `0x109e8`, support checks `0x10678`, `0x10e70`
- `condition-quality`: `0x10f38`, `0x109e8`

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

- `.codex_automation/evidence.log`
- `.ralph/agent/sweep.latest.md`
- `PLAN.md`
- `AGENTS.md`
