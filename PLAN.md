Strictly follow AGENTS.md. Remove completed steps only with proof from focused tests or one-function decompile evidence.
Planner refresh source: `.ralph/agent/check.latest.md` (2026-04-22T15:47:00+02:00): families=`validation-uncollected`, `stack-segment`, `condition-quality`; anchors=`0x10010,0x102e0,0x10768,0x10970,0x109e8,0x10ce0,0x10f38`; sweep evidence currently reports `validation=disabled` and must be treated as semantic status `uncollected`.
dig deep.
The plan below should be deterministic:

1. Goal: Re-enable semantic attribution in the one-function checker lane so outcomes are never reported as implicit success when validation is `uncollected`.
Target files: `/home/xor/vextest/.ralph/agent/check.latest.md:1-220`, `/home/xor/vextest/.ralph/agent/sweep.latest.md:1-220`, `/home/xor/vextest/.codex_automation/evidence.log`.
Functions/tests/scripts: one-function lane only (no full SORTDEMO run):
`./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`
`./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x102e0 --timeout 30 --alternate-source-c`
`./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c`
`./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10970 --timeout 30 --alternate-source-c`
`./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`
`./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c`
`./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c`.
Definition of done: checker/sweep artifacts preserve deterministic ordering and explicit verdict attribution (`changed`/`unknown`/`uncollected`) for every checker anchor (`0x10010, 0x102e0, 0x10768, 0x10970, 0x109e8, 0x10ce0, 0x10f38`); sweep lane never infers semantic pass/fail when `validation=disabled`; no missing item is dropped.

2. Goal: Fix recurring 16/32-bit value-width mismatch at the earliest value/condition boundary (`clinic:variable-recovery-size-mismatch`).
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/value.py:1-420`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/regs.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/condition_ir.py:1-260`.
Functions/tests/scripts: value/width coercion + condition lifting paths; `angr_platforms/tests/test_x86_16_regs.py`; `angr_platforms/tests/test_x86_16_condition_ir.py`; `angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "QuickSort or Sleep or width or VexValue"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c`.
Definition of done: focused anchors no longer emit the size-mismatch diagnostic for fixed paths, and no new coercion crash appears at `0x10ce0`.

3. Goal: Preserve stack-probe/chkstk helper return-state as typed stack-address evidence so `SwapBars` stops degrading to fake stack carriers and raw segmented arg stores.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/function_effect_summary.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/helper_effect_summary.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/callsite_summary.py:1-440`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py:1-460`.
Functions/tests/scripts: stack-probe/chkstk effect summarization and callsite consumption; `angr_platforms/tests/test_x86_16_helper_effect_summary.py`; `angr_platforms/tests/test_x86_16_callsite_summary.py`; `angr_platforms/tests/test_x86_16_segmented_stack_alias.py`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10678 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10e70 --timeout 30 --alternate-source-c`.
Definition of done: `SwapBars` focused output materially drops fake stack-carrier setup and raw segmented argument-store scaffolding where helper effects are stable; `ReInitBars` (`0x10678`) and `Beep` (`0x10e70`) do not regress stack/segment emission quality; unresolved helper identity remains explicit refusal.

4. Goal: Run alias-first stack lowering before late CLI cleanup so typed SS stack-slot identity survives to emitted locals.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py:1-460`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py:1-260`, `/home/xor/vextest/inertia_decompiler/cli.py:9440-10040`.
Functions/tests/scripts: stack-slot identity lowering path; `angr_platforms/tests/test_x86_16_segmented_stack_alias.py`; `angr_platforms/tests/test_x86_16_cod_regressions.py -k "stack_slot or stack_local_pointer_alias"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`.
Definition of done: focused anchors reduce stack-carrier artifacts via typed stack facts before rewrite; ambiguous overlap remains conservative and explicit.

5. Goal: Preserve typed SS-address width facts through widening/lowering so stable stack word stores do not split into byte pairs.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/widening/store_width.py:1-300`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/widening/widening_rules.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py:1-260`.
Functions/tests/scripts: SS split-store widening path; `angr_platforms/tests/test_x86_16_cli.py -k "coalesce_direct_ss_local_word_statements"`; `angr_platforms/tests/test_x86_16_cod_regressions.py -k "word_store or byte_pair or stack"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10970 --timeout 30 --alternate-source-c`.
Definition of done: `HeapSort` (`0x10970`) emits at least one stable stack word store/object assignment where adjacency proof exists; unresolved/non-adjacent pairs still refuse widening.

6. Goal: Lower stable DS/SS segmented addresses into typed globals/arrays only when segment identity is proven by object-lowering evidence.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py:1-420`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py:1-380`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/type_storage_object_bridge.py:1-460`.
Functions/tests/scripts: segmented object-lowering path; `angr_platforms/tests/test_x86_16_segmented_memory.py`; `angr_platforms/tests/test_x86_16_storage_objects.py`; `angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "main or HeapSort or PercolateUp"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`.
Definition of done: focused anchors materially reduce raw `(ds << 4)`/`(ss << 4)` output for stable objects (`cRow`, `iCompares`, `abarWork[...]`) without flattening ambiguous segment cases.

7. Goal: Complete typed `Condition` production so branch meaning is not left in raw flag-temp formulas.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/condition_ir.py:1-260`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/postprocess/flags_cleanup.py:1-400`.
Functions/tests/scripts: typed compare/carry condition emission and consumption; `angr_platforms/tests/test_x86_16_condition_ir.py`; `angr_platforms/tests/test_x86_16_decompiler_postprocess_flags.py`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`.
Definition of done: focused branches use typed condition facts where available and stop emitting raw `flags_*` branch syntax for those proved cases.

8. Goal: Reproduce and close `QuickSort` non-constant `VexValue` coercion boundary deterministically after items 2-7.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/value.py:1-420`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/regs.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py:1-360`.
Functions/tests/scripts: `VexValue` coercion/access path; `angr_platforms/tests/test_x86_16_regs.py`; `angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "QuickSort or VexValue"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c`.
Definition of done: run the focused repro at `0x10ce0` and record one deterministic outcome: (a) coercion boundary is fixed with no crash, or (b) blocker remains but is explicitly attributed (`changed`/`unknown`/`uncollected`) with the first failing boundary noted; no silent skip/no-result outcome.

9. Goal: Resume induction-loop recovery only after semantic blockers above are green on focused anchors.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/structuring/loop_recovery.py:1-220`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/structuring/control_flow.py:1-220`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/type_array_matching.py:1-460`.
Functions/tests/scripts: induction summary and loop structuring path; `angr_platforms/tests/test_x86_16_induction_loops.py`; `angr_platforms/tests/test_x86_16_induction_summaries.py`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10970 --timeout 30 --alternate-source-c`.
Definition of done: at least one focused corpus loop is recovered from induction evidence after upstream semantic blockers clear; ambiguous cases remain conservative.

10. Goal: Eliminate compatibility shims and enforce canonical module ownership (no `globals().update`, no proxy modules).
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias_model.py:1-140`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias_domains.py:1-160`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/alias_model.py:1-180`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/domains.py:1-260`.
Functions/tests/scripts: import paths for alias modules; repo-wide grep for `globals().update`; `python -c "import angr_platforms.X86_16.alias.alias_model"`; focused one-function decompile smoke.
Definition of done: no module uses dynamic re-export or `globals().update`; imports resolve to canonical package paths; removing shim modules does not change focused decompile output.

11. Goal: Enforce strict layer import direction and module ownership constraints in CI (IR -> semantics -> alias -> widening -> lowering -> structuring -> postprocess -> cli).
Target files: `/home/xor/vextest/tools/check_import_layers.py`, `/home/xor/vextest/angr_platforms/tests/test_layer_import_rules.py`, `/home/xor/vextest/angr_platforms/tests/test_layer_headers.py`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/*`.
Functions/tests/scripts: import graph validation; header rule validation (`# Layer:` / `# Forbidden:`); CI execution of both tests.
Definition of done: forbidden imports/APIs fail CI deterministically; all current modules pass; new reverse dependencies cannot land silently.

12. Goal: Enforce cleanup-only CLI/postprocess and ban text-based semantic recovery + widening-by-shape outside widening package.
Target files: `/home/xor/vextest/inertia_decompiler/cli_*.py`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/postprocess/*`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/widening/*`, `/home/xor/vextest/angr_platforms/tests/test_cli_no_semantics.py`, `/home/xor/vextest/angr_platforms/tests/test_no_text_semantics.py`.
Functions/tests/scripts: grep for semantic logic in CLI (`ss <<`, `flags_`, stack/object/widening decisions) and text-matching based semantics; verify all byte-pair widening decisions live under widening package.
Definition of done: CLI/postprocess perform formatting/cleanup only; no semantic rule depends on rendered asm/C text; widening decisions are centralized under `widening/`; violations fail CI.

13. Goal: Make pass order explicit and single-entry so no path bypasses required layers.
Target files: `/home/xor/vextest/inertia_decompiler/cli.py`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py`, `/home/xor/vextest/angr_platforms/tests/test_pipeline_order.py`.
Functions/tests/scripts: introduce/validate single `run_pipeline()` orchestration; assert deterministic stage order in tests.
Definition of done: all decompilation paths execute one ordered pipeline; no pass runs out-of-order/standalone; debug output reports deterministic stage sequence.

14. Goal: Complete canonical-path migration and remove dual layout/module shadowing.
Target files: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/*`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/*`.
Functions/tests/scripts: grep for old flat imports (`X86_16.alias_model`, etc.); remove duplicates/shadows; focused one-function decompile smoke on anchors from item 1.
Definition of done: one canonical module path per concept; no duplicate modules/shadow imports remain; navigation and architecture map are consistent.

Global DoD: focused acceptance anchors show no text-pattern semantic patching, no CLI-stage semantic invention, explicit validation attribution is preserved, and any removed PLAN item has direct focused evidence (tests or one-function decompile output) proving its DoD.
