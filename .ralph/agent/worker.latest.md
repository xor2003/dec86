# Worker Latest

## Task
- event handled: `plan.ready`
- active PLAN item worked: `#1 Preserve stack-probe/chkstk helper return-state as typed stack-address evidence so SwapBars stops degrading to fake stack carriers and raw segmented arg stores`

## Changes
- Updated `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/analysis_helpers.py`:
  - widened direct-callsite recovery so exact-slice functions can recover callsites from call instructions that sit in the middle of a block, not only block-ending calls
  - made direct target decoding work for a specific callsite address inside a larger block, while preserving the old block-end behavior
  - made `collect_neighbor_call_targets()` self-heal empty direct-call inventories before downstream callsite consumers inspect them
- Added focused regression coverage in `/home/xor/vextest/angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py`:
  - exact-slice target rebasing now covers a mid-block callsite address
  - `_attach_callsite_summaries_8616()` now recovers multiple mid-block direct calls from an empty `_call_sites` inventory

## Verification
- Focused tests run:
  - `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py angr_platforms/tests/test_x86_16_callsite_summary.py angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py`
  - result: `29 passed`
- Required one-function commands from PLAN #1 rerun:
  - `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c` => `exit 0`
  - `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10678 --timeout 30 --alternate-source-c` => `exit 0`
  - `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10e70 --timeout 30 --alternate-source-c` => `exit 0`
- Focused exact-slice probe:
  - `_recover_lst_function(..., 0x10768, "SwapBars")` + `patch_direct_call_sites()` now recovers `0x1006`, `0x100e`, `0x1017`, `0x1020` and `summarize_x86_16_callsite()` resolves `aNchkstk`, both `DrawBar` calls, and `DrawTime`

## DoD status
- PLAN item #1: **advanced, not complete**
- Completed this iteration:
  - earliest-layer exact-slice callsite inventory is no longer empty when direct calls live mid-block
  - downstream callsite summary consumers now have recoverable callsite/target evidence on `SwapBars` exact slices instead of an empty inventory
  - focused regression coverage locks this exact-slice mid-block recovery behavior
- Remaining blocker for closure:
  - live exact-lane output for `SwapBars` (`0x10768`) is still unchanged: fake carrier setup (`s_2 = &s_2 + 2`, `s_2 = vvar_2`) and raw SS argument-store scaffolding remain in emitted C
  - support anchors `ReInitBars` (`0x10678`) and `Beep` (`0x10e70`) also remain unchanged on this iteration, so the recovered callsite inventory is still not surfacing through the live postprocess/codegen output
  - next worker should instrument the live exact-slice postprocess path on `SwapBars` to compare recovered callsite count vs. actual `CFunctionCall` nodes and identify where the recovered summaries stop propagating
