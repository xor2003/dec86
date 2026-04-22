Strictly follow AGENTS.md. Remove completed steps only with proof from focused tests or one-function decompile evidence.
Planner refresh sources: `.ralph/agent/check.latest.md` (2026-04-22T18:08:00+02:00), `.ralph/agent/sweep.latest.md` (bounded sweep refreshed at 2026-04-22 18:02 local), `.codex_automation/evidence.log` (checker follow-up refreshed at 2026-04-22 16:01 local). Current families=`validation-uncollected`, `stack-segment`, `condition-quality`; anchors=`0x10010,0x102e0,0x10768,0x10970,0x109e8,0x10ce0,0x10f38`; checker attribution is explicit for every anchor, with `0x10ce0 QuickSort=uncollected` under `--timeout 30` and `0x102e0 RunMenu=uncollected` under both the 30s timeout lane and the 60s retry lane.
The plan below is deterministic and every checker anchor has a numbered owner:

1. Goal: Preserve stack-probe/chkstk helper return-state as typed stack-address evidence so `SwapBars` stops degrading to fake stack carriers and raw segmented arg stores.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/function_effect_summary.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/helper_effect_summary.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/callsite_summary.py:1-440`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py:1-460`.
Functions/tests/scripts: stack-probe/chkstk effect summarization and callsite consumption; `angr_platforms/tests/test_x86_16_helper_effect_summary.py`; `angr_platforms/tests/test_x86_16_callsite_summary.py`; `angr_platforms/tests/test_x86_16_segmented_stack_alias.py`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10678 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10e70 --timeout 30 --alternate-source-c`.
Definition of done: `SwapBars` focused output materially drops fake stack-carrier setup and raw segmented argument-store scaffolding where helper effects are stable; `ReInitBars` (`0x10678`) and `Beep` (`0x10e70`) do not regress stack/segment emission quality; unresolved helper identity remains explicit refusal.

2. Goal: Run alias-first stack lowering before late CLI cleanup so typed SS stack-slot identity survives to emitted locals.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py:1-460`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py:1-260`, `/home/xor/vextest/inertia_decompiler/cli.py:9440-10040`.
Functions/tests/scripts: stack-slot identity lowering path; `angr_platforms/tests/test_x86_16_segmented_stack_alias.py`; `angr_platforms/tests/test_x86_16_cod_regressions.py -k "stack_slot or stack_local_pointer_alias"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`.
Definition of done: focused anchors reduce stack-carrier artifacts via typed stack facts before rewrite; ambiguous overlap remains conservative and explicit.

3. Goal: Preserve typed SS-address width facts through widening/lowering so stable stack word stores do not split into byte pairs.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/widening/store_width.py:1-300`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/widening/widening_rules.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py:1-260`.
Functions/tests/scripts: SS split-store widening path; `angr_platforms/tests/test_x86_16_cli.py -k "coalesce_direct_ss_local_word_statements"`; `angr_platforms/tests/test_x86_16_cod_regressions.py -k "word_store or byte_pair or stack"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10970 --timeout 30 --alternate-source-c`.
Definition of done: `HeapSort` (`0x10970`) emits at least one stable stack word store/object assignment where adjacency proof exists; unresolved/non-adjacent pairs still refuse widening.

4. Goal: Lower stable DS/SS segmented addresses into typed globals/arrays only when segment identity is proven by object-lowering evidence.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py:1-420`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py:1-380`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/type_storage_object_bridge.py:1-460`.
Functions/tests/scripts: segmented object-lowering path; `angr_platforms/tests/test_x86_16_segmented_memory.py`; `angr_platforms/tests/test_x86_16_storage_objects.py`; `angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "main or HeapSort or PercolateUp"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`.
Definition of done: focused anchors materially reduce raw `(ds << 4)`/`(ss << 4)` output for stable objects (`cRow`, `iCompares`, `abarWork[...]`) without flattening ambiguous segment cases.

5. Goal: Make the compare-width boundary fix deterministic on the required `QuickSort`/`Sleep` exact lanes before treating it as closed.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/condition_ir.py:1-260`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py:1-360`.
Functions/tests/scripts: compare-width harmonization in typed condition production; `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_regs.py angr_platforms/tests/test_x86_16_condition_ir.py angr_platforms/tests/test_x86_16_alu_helpers.py angr_platforms/tests/test_x86_16_runtime_support_traces.py -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c`.
Definition of done: both exact-lane anchors exit `0` reproducibly under `--timeout 30`; neither emits `clinic:variable-recovery-size-mismatch`, `Non-constant VexValue has no value property`, or a traceback; if `QuickSort` still times out, this item stays open and no downstream plan pruning claims the boundary fix is fully proven.

6. Goal: Complete typed `Condition` production so branch meaning is not left in raw flag-temp formulas.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/condition_ir.py:1-260`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/postprocess/flags_cleanup.py:1-400`.
Functions/tests/scripts: typed compare/carry condition emission and consumption; `angr_platforms/tests/test_x86_16_condition_ir.py`; `angr_platforms/tests/test_x86_16_decompiler_postprocess_flags.py`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`.
Definition of done: focused branches use typed condition facts where available and stop emitting raw `flags_*` branch syntax for those proved cases.

7. Goal: Make `RunMenu` exact-lane validation collection deterministic so checker coverage does not depend on an ad hoc 30s/60s retry split.
Target files: `/home/xor/vextest/inertia_decompiler/cli.py:9440-10040`, `/home/xor/vextest/inertia_decompiler/cli_core.py:2400-2760`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/tail_validation.py:1593-1887`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py:1-260`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py:1-260`.
Functions/tests/scripts: exact one-function validation collection/reporting path for slow anchors; `angr_platforms/tests/test_x86_16_tail_validation.py`; `angr_platforms/tests/test_x86_16_structuring_pass_validation.py`; `angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "RunMenu"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x102e0 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x102e0 --timeout 60 --alternate-source-c`.
Definition of done: `0x102e0` has one deterministic exact-lane outcome policy for planner/checker use: either the 30s lane completes with explicit validation attribution, or the timeout path itself emits explicit attributable accounting that makes the 60s retry unnecessary for coverage; no silent partial coverage and no loss of `changed`/`unknown`/`uncollected` identity.

8. Goal: Resume induction-loop recovery only after semantic blockers above are green on focused anchors.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/structuring/loop_recovery.py:1-220`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/structuring/control_flow.py:1-220`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/type_array_matching.py:1-460`.
Functions/tests/scripts: induction summary and loop structuring path; `angr_platforms/tests/test_x86_16_induction_loops.py`; `angr_platforms/tests/test_x86_16_induction_summaries.py`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10970 --timeout 30 --alternate-source-c`.
Definition of done: at least one focused corpus loop is recovered from induction evidence after upstream semantic blockers clear; ambiguous cases remain conservative.

9. Goal: Eliminate compatibility shims and enforce canonical module ownership (no `globals().update`, no proxy modules).
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias_model.py:1-140`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias_domains.py:1-160`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/alias_model.py:1-180`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/domains.py:1-260`.
Functions/tests/scripts: import paths for alias modules; repo-wide grep for `globals().update`; `python -c "import angr_platforms.X86_16.alias.alias_model"`; focused one-function decompile smoke.
Definition of done: no module uses dynamic re-export or `globals().update`; imports resolve to canonical package paths; removing shim modules does not change focused decompile output.

10. Goal: Enforce strict layer import direction and module ownership constraints in CI (IR -> semantics -> alias -> widening -> lowering -> structuring -> postprocess -> cli).
Target files: `/home/xor/vextest/tools/check_import_layers.py`, `/home/xor/vextest/angr_platforms/tests/test_layer_import_rules.py`, `/home/xor/vextest/angr_platforms/tests/test_layer_headers.py`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/*`.
Functions/tests/scripts: import graph validation; header rule validation (`# Layer:` / `# Forbidden:`); CI execution of both tests.
Definition of done: forbidden imports/APIs fail CI deterministically; all current modules pass; new reverse dependencies cannot land silently.

11. Goal: Enforce cleanup-only CLI/postprocess and ban text-based semantic recovery + widening-by-shape outside widening package.
Target files: `/home/xor/vextest/inertia_decompiler/cli_*.py`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/postprocess/*`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/widening/*`, `/home/xor/vextest/angr_platforms/tests/test_cli_no_semantics.py`, `/home/xor/vextest/angr_platforms/tests/test_no_text_semantics.py`.
Functions/tests/scripts: grep for semantic logic in CLI (`ss <<`, `flags_`, stack/object/widening decisions) and text-matching based semantics; verify all byte-pair widening decisions live under widening package.
Definition of done: CLI/postprocess perform formatting/cleanup only; no semantic rule depends on rendered asm/C text; widening decisions are centralized under `widening/`; violations fail CI.

12. Goal: Make pass order explicit and single-entry so no path bypasses required layers.
Target files: `/home/xor/vextest/inertia_decompiler/cli.py`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py`, `/home/xor/vextest/angr_platforms/tests/test_pipeline_order.py`.
Functions/tests/scripts: introduce/validate single `run_pipeline()` orchestration; assert deterministic stage order in tests.
Definition of done: all decompilation paths execute one ordered pipeline; no pass runs out-of-order/standalone; debug output reports deterministic stage sequence.

13. Goal: Complete canonical-path migration and remove dual layout/module shadowing.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/*`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/*`.
Functions/tests/scripts: grep for old flat imports (`X86_16.alias_model`, etc.); remove duplicates/shadows; focused one-function decompile smoke on anchors from item 1.
Definition of done: one canonical module path per concept; no duplicate modules/shadow imports remain; navigation and architecture map are consistent.

Global DoD: focused acceptance anchors show no text-pattern semantic patching, no CLI-stage semantic invention, explicit validation attribution is preserved, and any removed PLAN item has direct focused evidence (tests or one-function decompile output) proving its DoD.
