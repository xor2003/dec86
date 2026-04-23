# Worker Latest

## Task
- event handled: direct `/tmp/.tmpY8kARx` execution
- active PLAN item worked: `#1 stack-probe/callsite return-state to typed SS stack-address evidence`
- scope: advance callsite stack-probe cleanup by consuming typed SS stack-address evidence after safe argument materialization, without promoting segment-register metadata as call arguments

## Changes
- Added `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py`:
  - prunes adjacent stack-probe segment metadata stores only after a non-stack-probe call already has materialized non-segment arguments
  - requires stack-probe helper return-state evidence of an SS stack address before pruning
  - handles the carried high-byte `CS >> 8` store only when paired with an immediately preceding SS-addressed segment metadata store
- Updated `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py`:
  - delegates post-materialization segment metadata pruning to the new focused helper
- Updated `/home/xor/vextest/angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py`:
  - added regression coverage proving a real stack argument is materialized while adjacent `CS` / `CS >> 8` metadata stores are pruned

## Verification
- `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py angr_platforms/tests/test_x86_16_segmented_stack_alias.py` => `39 passed`
- `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_callsite_summary.py angr_platforms/tests/test_x86_16_helper_effect_summary.py angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py angr_platforms/tests/test_x86_16_segmented_stack_alias.py` => `23 passed`
- `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_cod_regressions.py -k 'stack_slot or stack_local_pointer_alias'` => `2 passed, 68 deselected`
- `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_package_exports.py -k 'decompiler_postprocess_registry_order or postprocess_passes_for_wrapper'` => `1 passed, 15 deselected`
- `./.venv/bin/python -m compileall -q angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py` => `exit 0`
- `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c` => `exit 0`; `clearscreen(0)`, `displaycursor(0)`, and `setvideomode(65535)` remain, and the previous raw `*((ss << 4) + vvar_*) = cs` / `*(vvar_* + 1) = cs >> 8` metadata stores are gone
- `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c` => `exit 0`; `Swaps(ax_6 + 2892, ax_8 + 2892)` and `SwapBars(iMaxLevel, arg_0)` remain, with no new raw `ss << 4` stack stores
- `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c` => `exit 0`; support anchor still has no raw `ss << 4` store regression

## DoD status
- PLAN item #1: **advanced, not complete**
- No `PLAN.md` pruning is justified because `0x10010`, `0x109e8`, and `0x10768` still retain non-store `vvar_*` stack-state carriers.
- Next work should move from segment metadata-store pruning to typed stack-state carrier identity/liveness so the remaining `vvar_*` stack-position assignments can be represented or removed without text-based cleanup.
