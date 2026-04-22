# Review Latest

## Findings

- Blocking: the claimed reviewer acceptance proof does not reproduce deterministically. `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c` exited `3` with the timeout banner on rerun, so the prior close/prune evidence for the width-boundary atomic step is not currently reproducible. Feedback target: `QuickSort` reviewer anchor in `PLAN.md` acceptance evidence; touched code paths remain `angr_platforms/X86_16/ir/vex_condition_lifting.py::build_condition_from_binop` and `angr_platforms/X86_16/semantics/alu_semantics.py::build_compare_condition_8616`.

## Verdict
- changes_requested

## Scope reviewed
- `PLAN.md`
- `.ralph/agent/worker.latest.md`
- `angr_platforms/angr_platforms/X86_16/ir/condition_ir.py`
- `angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py`
- `angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py`
- `angr_platforms/tests/test_x86_16_condition_ir.py`
- `angr_platforms/tests/test_x86_16_alu_helpers.py`

## Evidence
- Focused tests rerun and passed:
  - `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_regs.py angr_platforms/tests/test_x86_16_condition_ir.py angr_platforms/tests/test_x86_16_alu_helpers.py angr_platforms/tests/test_x86_16_runtime_support_traces.py -q`
  - result: `33 passed`
- Focused one-function reruns:
  - `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c` -> `exit 0`
  - `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c` -> `exit 3`
- `QuickSort` rerun ended with:
  - `/* Timed out while recovering a function after 30s after exhausting direct-address fallback budget. */`
  - `/* Tip: try a larger --timeout for larger binaries. */`
- No `clinic:variable-recovery-size-mismatch`, no `Non-constant VexValue has no value property`, and no traceback were observed in the focused reruns.

## Decision
- Architecture-layer placement is acceptable: the patch lives in typed condition production, not rewrite.
- Review still fails because the worker's claimed deterministic one-function acceptance evidence for `QuickSort` did not reproduce under the required reviewer lane.
- Planner should treat the prior width-boundary closure/prune as unsupported by current proof until the exact 30s `QuickSort` lane is made deterministic or the acceptance evidence is re-scoped honestly.

## Blocking checks
- architecture layer violation: none found
- deterministic DoD proof: failed on `0x10ce0 QuickSort --timeout 30`
- hidden fallback presented as success: not observed
- forbidden full SORTDEMO run: not used
