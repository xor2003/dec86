Strictly follow AGENTS.md. Put fixes to the right architectural layer. Remove completed steps only with proof from focused tests and one-function decompile evidence.
I see "validation=uncollected" - enable collection.

0. Goal: Add one deterministic SORTDEMO one-function debug bundle lane so worker cycles can inspect where garbage C appears without rereading `git diff` or repeating blind decompile reruns.
Why now: `.codex_automation/onefn/0x10010.log` still shows garbage around `clearscreen()` and raw SS carriers, and the current harness loop does not preserve enough stage evidence to tell whether the bad output comes from raw angr codegen, callsite fact passes, stack lowering, or final CLI formatting.
Edit targets: `/home/xor/vextest/scripts/capture_sortdemo_debug_bundle.py`, `/home/xor/vextest/meta_harness/prompts.py`, `/home/xor/vextest/meta_harness/README.md`, `/home/xor/vextest/meta_harness/tests/test_prompts.py`, `/home/xor/vextest/meta_harness/tests/test_sortdemo_debug_bundle.py`.
Required edits: Add one focused script that captures for a single `--addr` the raw linear asm, nearby COD assembly and source comments, raw angr codegen, post-callsite snapshot, post-stack-lowering snapshot, and final `decompile.py` stdout/stderr into `.codex_automation/stage_debug/<addr>/`. Update planner/worker prompt rules so the harness uses this bundle before repeating `git diff` or the same one-function decompile loop. Document the lane in the harness README and add focused tests for the prompt contract and COD-window helper.
Required tests: `meta_harness/tests/test_prompts.py`; `meta_harness/tests/test_sortdemo_debug_bundle.py`.
Verification commands: `./.venv/bin/pytest -q meta_harness/tests/test_prompts.py meta_harness/tests/test_sortdemo_debug_bundle.py -q`; `./.venv/bin/python scripts/capture_sortdemo_debug_bundle.py ./SORTDEMO.EXE --addr 0x10010`.
Definition of done: A focused `0x10010` debug bundle lands under `.codex_automation/stage_debug/0x10010/` with stable stage files, and the worker/planner prompts tell the harness to use that bundle instead of repeated diffs or blind reruns.
Stop conditions: Stop if the bundle only captures final rendered C with no earlier stage separation. Stop if the harness guidance still allows repeated `git diff` loops before any new artifact is collected.
Estimated rounds: 1.

1. Goal: Make typed stack-probe arg pickup require a proven SS outgoing-store shape before `_materialize_callsite_stack_arguments_8616` rewrites a call.
Why now: `.codex_automation/onefn/0x10010.log` still shows `clearscreen()` with empty args plus raw `*((ss << 4) + vvar_24 - 2) = 0;`, so correctness is still weak and recompilation is still bad on the live SORTDEMO anchor.
Edit targets: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py:561-980`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_utils.py:51-92`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py:146-337`.
Required edits: Add one structured helper in `decompiler_postprocess_utils.py` that decomposes real-mode SS address expressions into segment plus offset terms instead of only `(seg, linear_const)`. Update `_store_matches_typed_stack_probe_fact` and `_typed_stack_store_rhs_from_statement` in `decompiler_postprocess_calls.py` to accept a store only when the lhs is a real SS dereference that matches the typed fact width/space and when the rhs is not segment metadata. Extend the stack-probe regression tests to cover `clearscreen(0)` materialization and refusal when only metadata stores exist.
Required tests: `angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py -k "materialized_arg_prunes_adjacent_segment_metadata_stores or materialize_refuses_segment_metadata_without_matching_typed_fact"`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py -k "materialized_arg_prunes_adjacent_segment_metadata_stores or materialize_refuses_segment_metadata_without_matching_typed_fact" -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`.
Definition of done: `0x10010` emits `clearscreen(0)` from typed SS evidence, leaves unresolved stores explicit, and no call gains args from metadata-only stores.
Stop conditions: Stop if the only way to match the store is carrier-name shape without SS-address proof. Stop if `0x10010` still prints empty `clearscreen()` after the test passes; use the typed-fact counters already logged before another rerun.
Estimated rounds: 1.

2. Goal: Prune only the exact outgoing SS stores and dead carriers consumed by the current call, not nearby state for later uses.
Why now: `.codex_automation/onefn/0x10768.log` and `.codex_automation/onefn/0x109e8.log` still show empty `DrawBar()`, empty `Swaps()`, empty `SwapBars()`, and leftover `vvar_*` carriers, so the current callsite cleanup is still too weak after item 1.
Edit targets: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py:879-1045`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py:219-340`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py:429-676`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py:427-470`.
Required edits: Thread the exact consumed statement indices from `_collect_backtracked_stack_args` into the metadata-prune path so only stores tied to one call are removed. Make `prune_materialized_callsite_segment_metadata_8616` require the matching typed fact for probe-origin cleanup and keep later reads/live carriers. Add focused tests for repeated `DrawBar` order, dead-carrier pruning, and keeping later reads when a carrier is reused.
Required tests: `angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py -k "dead_carrier or later_reads or materialized_arg_prunes"`; `angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py -k "repeated_non_probe_calls"`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py -k "dead_carrier or later_reads or materialized_arg_prunes or repeated_non_probe_calls" -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10768 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`.
Definition of done: `0x10768` and `0x109e8` replace provable outgoing SS stores with real call args, drop only dead carriers tied to those calls, and keep later reads/live state intact.
Stop conditions: Stop if a removed store cannot be tied to one callsite. Stop if `DrawBar` call order changes or if a later carrier read disappears.
Estimated rounds: 2.

3. Goal: Keep typed SS stack facts visible through lowering stats and stable stack-slot replacement so worker runs can tell if the blocker is arg pickup or later lowering.
Why now: `.codex_automation/evidence.log` reports `stack_arg_materializations=3` and `stable_ss_lowering_replacements=0`, while `0x10010` still prints `g_-8 = cs` and raw SS carriers; we need hard split between correctness gain and recompilation gain.
Edit targets: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py:511-534`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/stack_probe_return_facts.py:14-52`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py:128-143`.
Required edits: Record typed-fact width/space usage in lowering-side stats and log when SS-stack-slot lowering refuses a provable probe-origin address. Keep the fact object lowering-owned. Extend the existing stats assertion to distinguish arg materialization from stable SS lowering replacement.
Required tests: `angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py -k "fact_stats or builder_records_only_typed_ss_width_bearing_facts"`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py -k "fact_stats or builder_records_only_typed_ss_width_bearing_facts" -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`.
Definition of done: The focused `0x10010` run says whether the remaining bad C is blocked in arg materialization or in later SS lowering, and the unit test locks that split.
Stop conditions: Stop if the new stats depend on rendered C text. Stop if the stats merge arg pickup and lowering into one counter again.
Estimated rounds: 1.

4. Goal: Emit stable whole-file compiler/library summary lines for SORTDEMO.EXE in one deterministic order.
Why now: `.codex_automation/evidence.log` shows compiler matches and hidden signature labels, but the repo priority says whole-file compiler/library summaries must stay stable and measurable for SORTDEMO while the live lane stays on this sample.
Edit targets: `/home/xor/vextest/inertia_decompiler/decompile_file_summary.py:7-65`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_sortdemo_regressions.py`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_cli.py`.
Required edits: Sort and dedupe compiler names and signature-source names deterministically before print, keep line order fixed, and add one focused CLI/file-summary regression for SORTDEMO summary text. Do not pull semantic proof from names; this is reporting only.
Required tests: `angr_platforms/tests/test_x86_16_cli.py -k "file_summary or compiler_versions"`; `angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "summary"`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_cli.py angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "file_summary or compiler_versions or summary" -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --max-functions 1 --timeout 30`.
Definition of done: Two same-input SORTDEMO runs print the same compiler/library summary lines in the same order, and the regression test locks the text.
Stop conditions: Stop if the summary depends on previous sweep state or hidden cache order. Stop if reporting changes alter decompilation decisions.
Estimated rounds: 1.

5. Goal: Stop repeated same-family direct-address fallback passes in the live `RunMenu` lane and report one explicit attribution record.
Why now: `.codex_automation/onefn/0x102e0.log` shows the same `decompile_function` family repeated before a 30s timeout, which breaks the repo rule to stop retrying once no new evidence appears.
Edit targets: `/home/xor/vextest/inertia_decompiler/cli_core.py:1684-1870`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/tail_validation.py:1593-1888`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_tail_validation.py`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_tail_validation_routing.py`.
Required edits: Add one deterministic retry-family key for direct-address fallback attempts using addr, timeout budget, and failure family. Refuse a second identical retry in the same lane when no new evidence arrives. Emit one explicit attribution record that preserves `stable`, `changed`, `unknown`, and `uncollected`.
Required tests: `angr_platforms/tests/test_x86_16_tail_validation.py`; `angr_platforms/tests/test_x86_16_tail_validation_routing.py`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_tail_validation.py angr_platforms/tests/test_x86_16_tail_validation_routing.py -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x102e0 --timeout 30 --alternate-source-c`.
Definition of done: The `0x102e0` 30s lane runs at most one retry family per evidence state and exits with explicit attribution for timeout, fallback, or success.
Stop conditions: Stop if the fix needs a broader sweep to classify the family. Stop if attribution drops `unknown` or `uncollected`.
Estimated rounds: 2.

6. Goal: Preserve proven SS word-store width through widening so stable stack stores do not split into byte pairs or raw carrier ladders.
Why now: `.codex_automation/onefn/0x10970.log` and `.codex_automation/onefn/0x109e8.log` still show raw stack carriers after the arg materialization family, so the next visible recompilation defect is width loss in stable SS stores.
Edit targets: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/widening/store_width.py:1-300`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/widening/widening_rules.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py:18-47`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_cli.py`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_cod_regressions.py`.
Required edits: Thread typed SS width evidence into widening, require same segment plus adjacent offsets plus known width before any join, and add one negative test for cross-segment or non-adjacent byte pairs.
Required tests: `angr_platforms/tests/test_x86_16_cli.py -k "coalesce_direct_ss_local_word_statements"`; `angr_platforms/tests/test_x86_16_cod_regressions.py -k "word_store or byte_pair or stack"`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_cli.py -k "coalesce_direct_ss_local_word_statements" -q`; `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_cod_regressions.py -k "word_store or byte_pair or stack" -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10970 --timeout 30 --alternate-source-c`.
Definition of done: `0x10970` shows at least one stable word store where proof exists, and non-adjacent or cross-segment cases stay unjoined.
Stop conditions: Stop if the only proof is expression shape with no alias/segment evidence. Stop if unrelated control flow changes.
Estimated rounds: 2.

7. Goal: Lower stable DS/SS accesses into typed globals, locals, and arrays only when object evidence proves the storage identity.
Why now: `.codex_automation/onefn/0x10010.log` and `.codex_automation/onefn/0x109e8.log` still show raw `(ds << 4)` and `(ss << 4)` output, so correctness is readable enough to inspect but recompilation is still weak.
Edit targets: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py:1-420`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py:1-380`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/type_storage_object_bridge.py:1-460`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_segmented_memory.py`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_storage_objects.py`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_sortdemo_regressions.py`.
Required edits: Consume only stable segmented storage facts from object lowering, keep segment identity attached to typed storage objects, and add refusal paths for over-associated or unknown segment buckets.
Required tests: `angr_platforms/tests/test_x86_16_segmented_memory.py`; `angr_platforms/tests/test_x86_16_storage_objects.py`; `angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "main or HeapSort or PercolateUp"`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_segmented_memory.py angr_platforms/tests/test_x86_16_storage_objects.py -q`; `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_sortdemo_regressions.py -k "main or HeapSort or PercolateUp" -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x109e8 --timeout 30 --alternate-source-c`.
Definition of done: Focused anchors reduce raw segmented arithmetic for stable objects such as `cRow`, `iCompares`, and `abarWork[...]`, while ambiguous segment cases stay explicit.
Stop conditions: Stop if the only proof is a symbol name or same-stem source sidecar. Stop if unknown segment cases flatten into globals.
Estimated rounds: 3.

8. Goal: Normalize compare operand widths in typed condition production before branch lowering for the `QuickSort` and `Sleep` family.
Why now: `.codex_automation/onefn/0x10ce0.log` still times out in the direct-address lane, and `.codex_automation/onefn/0x10f38.log` returns C with weak compare/loop shape; the next live correctness blocker after stack args is condition meaning.
Edit targets: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/condition_ir.py:1-260`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py:1-360`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py:1-360`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_condition_ir.py`.
Required edits: Normalize mixed byte/word compare operands in typed `Condition` objects, keep VEX temps as evidence only, and add mixed-width tests for zero/carry consumers that hit the current `Sleep` and `QuickSort` family.
Required tests: `angr_platforms/tests/test_x86_16_regs.py`; `angr_platforms/tests/test_x86_16_condition_ir.py`; `angr_platforms/tests/test_x86_16_alu_helpers.py`; `angr_platforms/tests/test_x86_16_runtime_support_traces.py`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_regs.py angr_platforms/tests/test_x86_16_condition_ir.py angr_platforms/tests/test_x86_16_alu_helpers.py angr_platforms/tests/test_x86_16_runtime_support_traces.py -q`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10f38 --timeout 30 --alternate-source-c`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c`.
Definition of done: `Sleep` gets a typed compare/loop improvement without control-flow regression, and `QuickSort` either improves or emits a more precise failure family with no repeated same-family retry.
Stop conditions: Stop if the only fix path is late rewrite or rendered-text matching. Stop if `QuickSort` still repeats the same failure family with no new typed condition evidence.
Estimated rounds: 3.

9. Goal: Remove alias-module compatibility shims and keep one canonical import path per alias concept.
Why now: The repo split rules still ban long-lived proxy modules, and later layer checks are noisy until alias ownership is canonical.
Edit targets: `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias_model.py:1-140`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias_domains.py:1-160`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/alias_model.py:1-180`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/alias/domains.py:1-260`.
Required edits: Update callers to canonical package imports, replace dynamic re-export shims with explicit static imports or remove them, and add one import smoke test for the canonical alias modules.
Required tests: Canonical alias import smoke.
Verification commands: `rg -n "globals\\(\\)\\.update|import \\*" angr_platforms/angr_platforms/X86_16`; `PYTHONPATH=/home/xor/vextest/angr_platforms ./.venv/bin/python -c "import angr_platforms.X86_16.alias.alias_model; import angr_platforms.X86_16.alias.domains"`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`.
Definition of done: No dynamic re-export remains in the alias area, imports resolve to canonical paths, and focused SORTDEMO smoke still works.
Stop conditions: Stop if removal breaks broad imports; first add a caller map test before more deletes.
Estimated rounds: 2.

10. Goal: Enforce one ordered x86-16 pipeline and layer-boundary checks so future fixes stay in the earliest correct layer.
Why now: The live SORTDEMO stack-probe work touches summaries, lowering, widening, and postprocess; we need one deterministic path so no alternate entry skips the typed-fact stages.
Edit targets: `/home/xor/vextest/inertia_decompiler/cli.py`, `/home/xor/vextest/inertia_decompiler/cli_decompilation.py:821-915`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py:1-260`, `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py:1-260`, `/home/xor/vextest/tools/check_import_layers.py`, `/home/xor/vextest/angr_platforms/tests/test_pipeline_order.py`, `/home/xor/vextest/angr_platforms/tests/test_x86_16_layer_boundaries.py`.
Required edits: Add one ordered orchestration path for callsite summary attach, typed stack-probe fact build, stack lowering, widening, structuring, postprocess, and validation. Add import-layer rules for `IR -> semantics -> alias -> widening -> lowering -> structuring -> postprocess -> cli`.
Required tests: `angr_platforms/tests/test_pipeline_order.py`; `angr_platforms/tests/test_x86_16_layer_boundaries.py`; `angr_platforms/tests/test_x86_16_decompiler_profile.py`.
Verification commands: `./.venv/bin/pytest -q angr_platforms/tests/test_pipeline_order.py angr_platforms/tests/test_x86_16_layer_boundaries.py angr_platforms/tests/test_x86_16_decompiler_profile.py -q`; `./.venv/bin/python tools/check_import_layers.py`; `./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10010 --timeout 30 --alternate-source-c`.
Definition of done: All decompilation paths run the same stage order, forbidden reverse imports fail in tests, and the focused SORTDEMO anchor still decompiles through the canonical pipeline.
Stop conditions: Stop if this turns into a broad CLI rewrite; split an adapter-only item first. Stop if the check needs unrelated large-file refactors before the live blockers are green.
Estimated rounds: 3.
