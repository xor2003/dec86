# Worker Latest

## Task
- event handled: direct `/tmp/.tmprtOLiX` execution
- active PLAN item worked: `#1 stack-probe/callsite return-state to typed SS stack-address evidence`
- scope: harden callsite stack-argument materialization so segment-register carriers are refused by typed register identity, not only by rendered register names

## Changes
- Updated `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py`:
  - `_materialize_callsite_stack_arguments_8616` now recognizes `cs`/`ds`/`es`/`ss` arguments through structured `SimRegisterVariable` identity via `_segment_reg_name_8616`
  - this prevents unnamed segment registers from being promoted as recovered call arguments
- Updated `/home/xor/vextest/angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py`:
  - added coverage for refusing an unnamed `cs` carrier as a call argument after stack-probe evidence
- Tried later CLI callsite materialization before stack lowering, but reverted it because it regressed `main` call ordering/coverage (`setvideomode` disappeared and `RunMenu` shifted). The safe follow-up remains earlier typed stack-base identity for `vvar_*` carriers, not late CLI wiring.

## Verification
- `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py` => `23 passed`
- `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py angr_platforms/tests/test_x86_16_segmented_stack_alias.py` => `12 passed`
- `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_package_exports.py -k 'decompiler_postprocess_registry_order or postprocess_passes_for_wrapper'` => `1 passed, 15 deselected`
- `./.venv/bin/python -m compileall -q inertia_decompiler/cli_decompilation.py angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py` => `exit 0`
- `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c` => `exit 0`; raw `ss << 4` / `vvar_*` stack carriers remain; segment-register args are no longer guessed for `displaycursor`/`setvideomode`
- `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c` => `exit 0`; raw `ss << 4` / `vvar_*` stack carriers remain
- `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c` => `exit 0`; no `ss << 4` match in the focused grep

## DoD status
- PLAN item #1: **advanced, not complete**
- No `PLAN.md` pruning is justified because `0x10010` and `0x109e8` still emit raw stack-carrier stores.
- Next worker should continue at the earliest typed evidence layer: derive stack-probe return/base identity for `vvar_*` carriers before attempting any later CLI callsite rewiring.
