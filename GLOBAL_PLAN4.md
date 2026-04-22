# GLOBAL_PLAN4: Inertia Dream Decompiler Execution Specification

This file is an execution specification, not a brainstorming note.

Use it like a runbook.

If an agent cannot point to a listed file, function, test, command, or DoD item, it is not ready to claim progress.

This file also defines the required style for planner output.

If a planner, checker, harness, or sub-agent writes a new plan, that plan must look like this file in substance:

- execution specification
- strict step order
- concrete edit targets
- concrete verification commands
- definition of done for each step
- explicit stop conditions
- no vague “investigate”, “improve”, “polish”, or “refine” steps without named files/functions/tests

## 0. Mission

Build the x86-16 Inertia decompiler into a:

1. correctness-first decompiler
2. evidence-driven decompiler
3. recompilable-output decompiler where practical
4. bounded scan-safe decompiler for real corpus work
5. dream decompiler only after all listed gates are green at the same time

This repo must continue to obey:

- `IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`
- solve problems at the earliest correct layer
- do not hide alias or widening debt inside rewrite
- do not flatten segmented memory for convenience
- correctness over prettiness

Read before executing any step:

- `AGENTS.md`
- `README.md`

## 0.1 Planner Harness Contract

The planner harness agent must produce the same kind of plan as this file.

“Same kind of plan” means:

1. flat numbered execution order
2. deterministic steps
3. each step names exact files and functions when known
4. each step names exact tests to run
5. each step gives verification commands
6. each step gives a definition of done
7. each step gives stop conditions
8. no mixing strategic goals and immediate work in the same bullet
9. no aspirational prose pretending to be a plan
10. no hidden dependency on agent intuition

The planner harness agent must not output:

- a theme list
- a phase name without concrete edit targets
- a research memo
- a changelog
- a prose essay about architecture
- a checklist item that cannot be verified mechanically

The planner harness agent must emit steps using this exact schema:

- Goal
- Why now
- Edit targets
- Required edits
- Required tests
- Verification commands
- Definition of done
- Stop conditions

If the planner harness agent writes `PLAN.md` instead of a global plan, it must still preserve this execution style.

If the planner harness agent cannot fill in all fields for a step, it must first inspect the codebase and tests until it can.

## 1. Global Rules

These rules apply to every step below.

### 1.1 Order

- Execute steps strictly in numeric order.
- Do not skip ahead because a later step looks easier.
- Do not work on multiple numbered steps at once.
- A later step may only begin when the current step DoD is fully satisfied.

### 1.2 Allowed outputs per step

Each step must produce all of:

- code changes in the listed target files
- tests added or updated at the smallest useful level
- verification by running the listed command set
- a short note in commit message or work log saying which step was completed

### 1.3 Forbidden behavior

- Do not “complete” a step by only editing this file.
- Do not mark a step complete if the pass still returns `False` unconditionally.
- Do not add late rewrite hacks for problems explicitly assigned to alias, widening, segmented memory, or types.
- Do not guess structs, arrays, helpers, or pointer lowering without evidence.
- Do not weaken scan-safe behavior to get prettier output.

### 1.4 If blocked

If a step cannot be completed:

1. stop at that step
2. add the smallest missing test or diagnostic to expose the blocker
3. do not start the next step
4. document the exact blocker in `PLAN.md` with concrete files/functions/tests

## 2. Standard Verification Set

Run these unless a step gives a smaller focused subset first.

Focused correctness set:

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_recompilable_subset.py \
  tests/test_x86_16_cod_samples.py \
  tests/test_x86_16_cod_regressions.py \
  tests/test_x86_16_sample_matrix.py \
  tests/test_x86_16_runtime_samples.py
```

Focused structuring/type set:

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_structuring_switch.py \
  tests/test_x86_16_structuring_cyclic.py \
  tests/test_x86_16_structuring_integration.py \
  tests/test_x86_16_structuring_codegen.py \
  tests/test_x86_16_array_matching.py \
  tests/test_x86_16_struct_merging.py \
  tests/test_x86_16_segment_association.py \
  tests/test_x86_16_segmented_memory.py \
  tests/test_x86_16_type_equivalence_classes.py
```

Scan-safe corpus set:

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/scan_cod_dir.py ../cod --mode scan-safe --timeout-sec 5 --max-memory-mb 1024
```

## 3. Current State Summary

This section exists so agents stop lying to themselves about what is already built.

### 3.1 Real implementation already present

- `angr_platforms/angr_platforms/X86_16/structuring_analysis.py`
  - iterative region analysis exists
  - natural loop detection exists
  - goto fallback exists
  - switch and if schema support is incomplete
- `angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py`
  - x86-16 structuring pass pipeline exists
- `decompile.py`
  - timeout, worker, memory, and bounded recovery controls already exist
- `angr_platforms/angr_platforms/X86_16/recompilable_subset.py`
  - recompilation ratchet already exists
- `angr_platforms/angr_platforms/X86_16/confidence_and_assumptions.py`
  - confidence reporting framework exists
- `angr_platforms/angr_platforms/X86_16/structuring_diagnostics.py`
  - diagnostics framework exists

### 3.2 Framework-only or mostly-placeholder areas

- `angr_platforms/angr_platforms/X86_16/structuring_analysis.py`
  - `RegionBasedStructuringPass.__call__`
- `angr_platforms/angr_platforms/X86_16/structuring_analysis.py`
  - `_try_if_then`
  - `_try_if_then_else`
  - weak switch candidate detection
- `angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py`
  - metadata shell
- `angr_platforms/angr_platforms/X86_16/type_array_matching.py`
  - metadata shell
- `angr_platforms/angr_platforms/X86_16/type_structure_merging.py`
  - toy synthesis, not decompiler-integrated evidence flow
- `angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py`
  - metadata shell, not alias-driven

## 5. Step Execution Template

Every step below follows the same required structure:

- Goal
- Why now
- Edit targets
- Required edits
- Required tests
- Verification commands
- Definition of done
- Stop conditions

Do not invent your own format.

## 6. Step 1: Freeze The Baseline

### Goal

Make regressions impossible to ignore.

### Why now

All later steps are risky. Without a fixed ratchet, agents will trade correctness for output prettiness.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/recompilable_subset.py`
  - `_RECOMPILABLE_SUBSET_CASES`
  - `_compat_syntax_prelude`
  - `run_x86_16_recompilable_subset_syntax_checks`
- `decompile.py`
  - `_decompile_function_with_stats`
  - `_choose_function_parallelism`
- `README.md`
  - add or tighten the command set if needed

### Required edits

- Make the baseline command set explicit and stable.
- Ensure recompilable subset cases cover current key anchors and stay deterministic.
- If any baseline command is missing from docs, add it.
- Do not change behavior for prettiness in this step.

### Required tests

- `angr_platforms/tests/test_x86_16_recompilable_subset.py`
- `angr_platforms/tests/test_x86_16_cod_samples.py`
- `angr_platforms/tests/test_x86_16_sample_matrix.py`
- `angr_platforms/tests/test_x86_16_runtime_samples.py`

### Verification commands

Run the focused correctness set from Section 2.

### Definition of done

- baseline commands are documented
- baseline tests pass
- recompilable subset remains deterministic
- no behavior change outside ratchet/documentation unless needed for determinism

### Stop conditions

- if any baseline test is flaky
- if subset anchors depend on nondeterministic output

## 7. Step 2: Wire Region Structuring Into Real Codegen

### Goal

Replace the current no-op structuring pass with a real pass that operates on actual decompiler state.

### Why now

Everything later depends on structuring being real, not just algorithm code on the shelf.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/structuring_analysis.py`
  - `RegionBasedStructuringPass.__call__`
  - `apply_region_based_structuring`
- `angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py`
  - `_build_decompiler_structuring_passes`
  - `_structuring_codegen_8616`
  - `_decompile_structuring_8616`
- `angr_platforms/angr_platforms/X86_16/structuring_region.py`
  - only if needed for region graph extraction from real codegen

### Required edits

- Build a real region graph from current decompiler/AST state.
- Run `StructureAnalysis` against it.
- Feed the result back into codegen or emitted AST.
- Record actual stats on `cfunc` or related metadata.
- The pass must stop being an unconditional no-op.

### Required tests

- `angr_platforms/tests/test_x86_16_structuring_integration.py`
- `angr_platforms/tests/test_x86_16_structuring_codegen.py`

### Verification commands

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_structuring_integration.py \
  tests/test_x86_16_structuring_codegen.py
```

Then run the focused correctness set.

### Definition of done

- the pass changes real output for at least one fixture
- it records non-placeholder stats
- it does not always return `False`
- integration and codegen tests pass

### Stop conditions

- if the only output is stats bookkeeping
- if the pass mutates text only and skips AST/codegen state

## 8. Step 3: Implement Acyclic Schema Reduction

### Goal

Implement real `if`, `if-else`, and safe switch-candidate formation.

### Why now

Current stubs block meaningful structuring progress and create false switch positives.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/structuring_analysis.py`
  - `_try_if_switch_cascade`
  - `_try_if_then`
  - `_try_if_then_else`

### Required edits

- detect actual two-way condition structure
- merge real `if` and `if-else` regions
- only mark switch candidates when branches are same-expression constant tests
- do not use successor count alone as switch proof

### Required tests

- `angr_platforms/tests/test_x86_16_structuring_switch.py`
- `angr_platforms/tests/test_x86_16_structuring_integration.py`

### Verification commands

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_structuring_switch.py \
  tests/test_x86_16_structuring_integration.py
```

### Definition of done

- plain binary branches become structured condition regions
- switch candidate detection rejects false positives
- tests cover both positive and negative cases

### Stop conditions

- if switch formation still keys only on branch fanout
- if `if` support depends on late text rewrite instead of region reduction

## 9. Step 4: Finish Cyclic Structuring

### Goal

Make loop formation honest and deterministic, including fallback gotos for irreducible cases.

### Why now

Loop correctness is more important than nice syntax.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/structuring_analysis.py`
  - `NaturalLoopInfo`
  - `LoopExitClassification`
  - `_try_natural_loop`
  - `_detect_natural_loop`
  - `_compute_loop_body`
  - `_is_well_structured_multi_exit`
  - `_compute_loop_confidence`
  - `_process_unresolved_regions`
  - `_refine_to_gotos`

### Required edits

- classify loop exits as continue, break, or unresolved
- preserve explicit goto exits when proof is insufficient
- prefer honesty over over-structuring
- support single-header loops first
- keep multi-exit loops conservative

### Required tests

- `angr_platforms/tests/test_x86_16_structuring_cyclic.py`
- `angr_platforms/tests/test_x86_16_structuring_integration.py`

### Verification commands

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_structuring_cyclic.py \
  tests/test_x86_16_structuring_integration.py
```

### Definition of done

- reducible loops structure as loops
- irreducible loops retain deterministic labeled fallback exits
- confidence scoring affects fallback behavior

### Stop conditions

- if multi-exit loops are guessed into pretty structures without proof
- if goto fallback is removed instead of improved

## 10. Step 5: Bounded Switch And Jump-Table Recovery

### Goal

Support safe switch lowering for both cascades and bounded indirect jump patterns.

### Why now

Without hard bounds, this will hurt scan-safe performance and correctness.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/structuring_analysis.py`
- `decompile.py`
  - `_run_with_timeout_in_daemon_thread`
  - `_preferred_decompiler_options`
  - `_recover_blob_entry_function`

### Required edits

- add max jump-table size policy
- collect evidence used to recover jump destinations
- degrade safely when recovery is weak or too expensive
- ensure scan-safe mode keeps hard limits

### Required tests

- `angr_platforms/tests/test_x86_16_structuring_switch.py`
- `angr_platforms/tests/test_x86_16_cli.py`
- `angr_platforms/tests/test_x86_16_cod_regressions.py`

### Verification commands

Run:

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_structuring_switch.py \
  tests/test_x86_16_cli.py \
  tests/test_x86_16_cod_regressions.py
```

Then run the scan-safe corpus set.

### Definition of done

- bounded jump-table policy exists
- failed recovery falls back honestly
- scan-safe corpus still completes within bounds

### Stop conditions

- if a failed jump-table becomes guessed structured code
- if scan-safe regresses materially

## 11. Step 6: Post-Structuring Cleanup Only

### Goal

Add readability cleanup after, and only after, core structure is correct.

### Why now

These passes are useful only once structuring is trustworthy.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py`
- `angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py`
- new x86-16 cleanup pass files if needed

### Required edits

- add or refine passes for
  - for-loop normalization
  - tail-return removal
  - declaration cleanup
  - prettification
- keep them late
- forbid them from changing alias, widening, or object facts

### Required tests

- add focused cleanup tests
- extend structuring codegen/integration tests where useful

### Verification commands

Run the focused structuring/type set.

### Definition of done

- cleanup passes improve readability
- no cleanup pass invents semantics
- correctness anchors stay unchanged

### Stop conditions

- if any cleanup pass starts compensating for earlier-layer bugs

## 12. Step 7: Real Segmented Memory Reasoning

### Goal

Make segmented reasoning consume alias facts and call boundaries instead of toy placeholders.

### Why now

Real-mode correctness depends on segment-space discipline.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py`
- `angr_platforms/angr_platforms/X86_16/alias_model.py`
- `decompile.py`
  - helper and annotation surfaces if needed

### Required edits

- derive segment associations from real storage evidence
- distinguish stable association from over-associated cases
- lower to `MK_FP` only when evidence is strong
- keep DS, ES, SS distinct

### Required tests

- `angr_platforms/tests/test_x86_16_segment_association.py`
- `angr_platforms/tests/test_x86_16_segmented_memory.py`
- extend recompilable subset when new far-pointer cases are ready

### Verification commands

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_segment_association.py \
  tests/test_x86_16_segmented_memory.py \
  tests/test_x86_16_recompilable_subset.py
```

### Definition of done

- segment associations come from real evidence
- unstable cases stay explicit and marked uncertain
- far-pointer lowering is conservative

### Stop conditions

- if segment spaces are flattened
- if `MK_FP` is emitted by pattern familiarity alone

## 13. Step 8: Real Type Equivalence Analysis

### Goal

Replace metadata-only type equivalence with actual evidence propagation.

### Why now

Array, struct, and union recovery depend on a real type evidence layer.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py`
- `angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py`

### Required edits

- normalize real expressions, not raw placeholder strings
- build equivalence classes from actual dependencies
- collect real constraints
- expose results for downstream consumers

### Required tests

- `angr_platforms/tests/test_x86_16_type_equivalence_classes.py`

### Verification commands

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_type_equivalence_classes.py
```

Then run the focused structuring/type set.

### Definition of done

- pass no longer acts as metadata-only shell
- downstream passes can consume resolved evidence
- tests cover allowed and forbidden merges

### Stop conditions

- if the pass still returns `False` with only counters attached

## 14. Step 9: Evidence-Driven Array Recovery

### Goal

Make array recovery depend on induction, stride, bounds, and alias-compatible base proof.

### Why now

Array prettiness without proof is exactly the kind of wrong abstraction this project must avoid.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/type_array_matching.py`

### Required edits

- collect induction variables from real loop state
- match actual access forms
- require stable base plus stride plus width
- support multidimensional output only with separate proof

### Required tests

- `angr_platforms/tests/test_x86_16_array_matching.py`
- `angr_platforms/tests/test_x86_16_access_trait_arrays.py`
- `angr_platforms/tests/test_x86_16_access_trait_strides.py`

### Verification commands

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_array_matching.py \
  tests/test_x86_16_access_trait_arrays.py \
  tests/test_x86_16_access_trait_strides.py
```

### Definition of done

- recovered arrays are evidence-driven
- unsafe cases stay explicit pointer arithmetic
- tests include negative cases

### Stop conditions

- if array syntax is emitted from string heuristics alone

## 15. Step 10: Cross-Function Struct Recovery

### Goal

Recover structs and unions from stable cross-function object evidence.

### Why now

Single-function toy synthesis is not enough for real corpus correctness.

### Edit targets

- `angr_platforms/angr_platforms/X86_16/type_structure_merging.py`
- `angr_platforms/angr_platforms/X86_16/confidence_and_assumptions.py`

### Required edits

- group accesses by stable base identity
- merge compatible field layouts across functions
- normalize overlapping layouts to union-containing structures
- score confidence from independent evidence

### Required tests

- `angr_platforms/tests/test_x86_16_struct_merging.py`

### Verification commands

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_x86_16_struct_merging.py
```

Then run the focused structuring/type set.

### Definition of done

- struct recovery is cross-function
- overlap handling is deterministic
- confidence is evidence-based

### Stop conditions

- if struct naming or merging depends on guessy convenience

## 16. Step 11: Union Alternative Selection

### Goal

Choose union members conservatively from real offset and type context.

### Why now

Without this, recovered structs and helper unions remain noisy or wrong.

### Edit targets

- add a new x86-16 union-choice pass
- integrate it in `angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py`
- update downstream confidence reporting

### Required edits

- choose alternatives based on
  - access width
  - offset
  - enclosing pointer state
  - resolved result type
- ambiguous cases remain explicit and low-confidence

### Required tests

- add focused union-choice tests
- extend existing struct/type/recompilation tests where needed

### Verification commands

Run the focused structuring/type set and recompilable subset test.

### Definition of done

- common union cases improve
- uncertain cases are not guessed away

### Stop conditions

- if member choice becomes name-based or prettiness-based

## 17. Step 12: Recompilation Hardening

### Goal

Expand and harden recompilable output so important recovered samples compile without manual rescue.

### Why now

Recompilation is a concrete external quality bar.

### Edit targets

- `decompile.py`
- `angr_platforms/angr_platforms/X86_16/recompilable_subset.py`
- relevant helper/annotation modules

### Required edits

- improve helper signatures and emitted declarations
- eliminate forbidden anchors only when replaced by proven forms
- add more real subset cases

### Required tests

- `angr_platforms/tests/test_x86_16_recompilable_subset.py`
- `angr_platforms/tests/test_x86_16_cod_regressions.py`
- `angr_platforms/tests/test_x86_16_cod_source_rewrites.py`

### Verification commands

Run the focused correctness set.

### Definition of done

- subset includes loop-heavy, DOS-helper, BIOS-helper, and far-pointer cases
- subset remains deterministic
- recompilable output improves without semantic regression

### Stop conditions

- if recompilation is improved by fake helper semantics or guessed pointer lowering

## 18. Step 13: MartyPC Oracle Lane

### Goal

Add a bounded semantic validation lane against MartyPC-style execution traces.

### Why now

Dream-decompiler claims need an oracle beyond text inspection.

### Edit targets

- new scripts under `scripts/` or `angr_platforms/scripts/`
- validation/report code under `reports/` or test harnesses
- integration points in `decompile.py` if needed

### Required edits

- define bounded checkpoints
- capture register/memory/interrupt state deltas
- compare recovered output execution against oracle traces
- store failures as regression artifacts

### Required tests

- extend `angr_platforms/tests/test_x86_16_runtime_samples.py`
- add validation harness tests

### Verification commands

Run runtime sample tests plus the new oracle lane command once created.

### Definition of done

- bounded oracle lane exists
- failures are reproducible and classified
- it can be used as a release gate

### Stop conditions

- if the oracle lane is ad hoc and not repeatable

## 19. Step 14: Scan-Safe Performance Lane

### Goal

Make bounded decompilation speed and memory use an explicit maintained feature.

### Why now

Otherwise later readability passes will slowly destroy real-corpus usability.

### Edit targets

- `decompile.py`
  - timeout
  - worker parallelism
  - memory budgeting
  - recovery windows
- performance tests and profile tests

### Required edits

- document scan-safe knobs
- keep risky passes gateable
- enforce bounded worker count from memory
- make benchmark/reporting repeatable

### Required tests

- `angr_platforms/tests/test_decompile_cod_dir_parallelism.py`
- `angr_platforms/tests/test_x86_16_decompiler_profile.py`
- `angr_platforms/tests/test_x86_16_cli.py`

### Verification commands

Run:

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q \
  tests/test_decompile_cod_dir_parallelism.py \
  tests/test_x86_16_decompiler_profile.py \
  tests/test_x86_16_cli.py
```

Then run the scan-safe corpus set.

### Definition of done

- scan-safe mode is documented
- bounded performance is measurable
- risky passes can be isolated

### Stop conditions

- if readability wins are accepted while scan-safe regresses

## 20. Step 15: Dream Decompiler Release Gate

### Goal

Declare success only when all required correctness, recompilation, structure, and performance gates are green together.

### Required green gates

- `tests/test_x86_16_recompilable_subset.py`
- `tests/test_x86_16_cod_samples.py`
- `tests/test_x86_16_cod_regressions.py`
- `tests/test_x86_16_sample_matrix.py`
- `tests/test_x86_16_runtime_samples.py`
- structuring tests
- segment tests
- array/struct/type tests
- scan-safe corpus lane
- MartyPC oracle lane

### Definition of done

- all gates are green at the same time
- no critical unknown blocks default scan-safe output
- remaining uncertainty is explicitly reported, not hidden

## 21. One-Line Execution Order

If you are an agent and do not know what to do next, do this:

1. finish Step 1
2. finish Step 2
3. finish Step 3
4. finish Step 4
5. finish Step 5
6. finish Step 6
7. finish Step 7
8. finish Step 8
9. finish Step 9
10. finish Step 10
11. finish Step 11
12. finish Step 12
13. finish Step 13
14. finish Step 14
15. finish Step 15

No shortcuts.
