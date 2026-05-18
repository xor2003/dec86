# Architecture: vextest-x86-16

angr-based decompiler for 16-bit x86 real-mode (DOS) binaries → portable C.

## Layers

```
decompile.py                  entry point: venv bootstrap, CLI dispatch
inertia_decompiler/           business logic: pipeline, caching, validation (~80 modules)
angr_platforms/               angr platform extensions
  angr_platforms/X86_16/      primary platform (~140 files in 9 subdirectories)
  angr_platforms/<arch>/      9 other architectures (avr, bf, bpf, ct64, ebpf, msp430, risc_v, sparc, tricore)
  tests/                      test suite (~155 test files)
meta_harness/                 LLM-based automated iterative improvement harness
scripts/                      batch tools (decompile_cod_dir.py, build_signature_catalog.py)
reference/                    ground-truth reference C for test binaries
angr_platforms/docs/          12 design docs covering 80286 verification, coverage plans, interrupt lowering
```

## Runtime topology

```
decompile.py
  → inertia_decompiler.cli.main()
    → cli_core.main()
      → _run_function_work_item()         per-function work loop
        → cli_decompilation._decompile_function()    single-function pipeline
        → _validated_generated_c_acceptance_8616()   final gate
```

## Decompilation pipeline (single function)

### Phase 1: Setup
- `_prepare_function_for_decompilation()` — COV metadata, signature catalog
- `seed_calling_conventions(cfg)` — jumps, interrupts, helper stubs
- `_apply_binary_specific_annotations()` — per-binary annotations

### Phase 2: angr decompilation
- `project.analyses.Decompiler(function, cfg, options)` — angr's Clinic + Structurer
- Surrounded by ~12 guards for angr internal assertions and timeouts
- Falls back to isolated project retry on failure

### Phase 3: AST rewrite passes (structured codegen stage)
Executed in up to 2 rounds on the `dec.codegen` AST:

1. **Fact transfer**: `transfer_semantic_alias_facts_to_codegen_8616` / `lower_stack_accesses_from_alias_facts_8616` — alias facts from semantic analysis
2. **Interrupt/helper modeling**: DOS pseudocallees, interrupt wrappers
3. **Register naming**: segment registers, general registers, byte type normalization
4. **Condition handling**: typed conditions, flag rewrites, flag pruning
5. **Stack lowering**: `run_stack_lowering_pass_8616` — SS-based stack access → named stack locals
6. **Widening**: byte→word coalescing, typed widening
7. **Declaration management**: prune unused, materialize missing, deduplicate
8. **Segmented memory**: far pointer stack, segmented word loads/stores, COD globals
9. **Access traits**: field naming for struct-like access patterns
10. **Expression simplification**: algebraic identities, structured C simplification
11. **Linear recurrence**: loop variable detection and coalescing

Small functions and COD outliers get reduced pass sets.

### Phase 4: Text postprocessing
30+ text-level passes on the rendered C string:
- Boolean condition normalization
- Cod metadata annotation, global declaration materialization
- Known helper signature rewriting
- Blind-spot fixes (binary-specific edge cases)
- Stack byte pointer simplification
- Type keyword collapse, duplicate dedup, autonym sanitization

### Phase 5: Validation gates
Applied in `_validated_generated_c_acceptance_8616()`:
1. Status must be "ok"
2. Payload must be non-empty
3. Quality guard: `assess_decompiled_c_text()` must not reject
4. Tail validation: snapshot stages must not show failed/changed
5. gcc syntax check: `-std=c99 -Wall -Werror -fsyntax-only`

## Key modules — inertia_decompiler

| Module | Purpose |
|---------|---------|
| `cli.py` | Module proxy — re-exports from all submodules for backcompat |
| `cli_core.py` | Main entry, work-item loop, caching, acceptance gate (172K) |
| `cli_decompilation.py` | Single-function pipeline orchestration — ~50 rewrite passes (82K) |
| `cli_c_ast_rewrites.py` | AST-level rewrite passes on structured codegen (172K) |
| `cli_c_text_postprocess.py` | Text-level C cleanup passes — blind-spot fixes, dedup, normalization (125K) |
| `cli_function_discovery.py` | Function identification from CFG, call-site scanning, ranking (111K) |
| `cli_fallback_decompilation.py` | Non-optimal fallback decomp paths (35K) |
| `cli_interrupt_modeling.py` | DOS int 21h / BIOS interrupt modeling and lowering (32K) |
| `cli_stack_byte_offsets.py` | SP-relative byte-offset alias resolution and carrier chain elimination (27K) |
| `cli_linear_recurrence.py` | Loop induction variable detection and coalescing (30K) |
| `cli_linear_recurrence_state.py` | Recurrence state tracking across passes (19K) |
| `cli_local_rewrites.py` | Local variable rewrite coordination (16K) |
| `cli_access_traits.py` / `cli_access_profiles.py` | Struct-like field access pattern detection (11K each) |
| `tail_validation.py` | Tail-validation orchestration, env flags, snapshot caching |
| `project_loading.py` | angr Project construction with LRU caching |
| `cache.py` | JSON-based decompilation result cache (sha256 keys) |
| `runtime_support.py` | Timeout guards, fork/thread pools, angr monkey-patches, memory limits (45K) |
| `work_items.py` | FunctionWorkItem / FunctionWorkResult data types, tail-validation emission |
| `sidecar_metadata.py` | LST/COD metadata extraction and code region mapping (19K) |
| `sidecar_parsers.py` | IDA MAP file and TDINFO parsing (21K) |
| `recompile_check.py` | gcc -std=c99 -Wall -Werror -fsyntax-only runner |
| `acceptance_scorecard.py` | Per-function acceptance tracking |
| `slice_recovery.py` | Bounded slice recovery for partial decompilation |
| `decompilation_quality.py` | C text quality assessment (rejects unresolved IR-shaped output) |
| `debugger_gdb.py` / `gdb_client.py` / `gdb_tui.py` | GDB remote debugging with Textual TUI |
| `cli_cod_globals.py` / `cli_cod_global_statements.py` | CodeView debug global variable recovery |
| `cli_far_pointer_stack.py` | Far pointer stack expression coalescing |
| `cli_segmented_*.py` | Segmented memory lowering shims (6 modules) |
| `cli_dead_local_prune.py` | Dead local assignment elimination (13K) |

## Key modules — angr_platforms/X86_16

### Core platform
| Area | Key files |
|------|-----------|
| Architecture | `arch_86_16.py` (register defs, memory spaces), `regs.py`, `processor.py`, `parse.py` |
| Lifting | `lift_86_16.py` (39K — VEX→IR), `instr16.py` (51K), `instr32.py` (29K), `instr_base.py` (41K) |
| Loader | `load_dos_mz.py` (MZ EXE), `load_dos_ne.py` (NE EXE), `ne_exe_parse.py` |
| OS simulation | `simos_86_16.py` (DOS memory map, interrupt vectors) |

### Lowering pipeline (`lowering/` — 15 files)
| File | Purpose |
|------|---------|
| `stack_lowering.py` | Top-level orchestrator — SS-based stack access → named locals |
| `stack_lowering_impl.py` (48K) | Core lowering from typed alias evidence — carrier chain resolution |
| `stack_lowering_from_facts.py` (12K) | Materializes stack variables from semantic alias facts |
| `fact_transfer.py` (13K) | Propagates alias/condition facts through IR to codegen |
| `segmented_lowering.py` (15K) | Segment:offset address lowering |
| `segmented_memory_lowering.py` (7K) | Memory model lowering for segmented accesses |
| `real_mode_linear.py` (44K) | Real-mode linear address computation |
| `condition_transfer.py` | Condition expression lowering |
| `object_lowering.py` (8K) | Object/structure lowering |
| `stack_variable_binding.py` / `ss_bp_substitution.py` | BP/SS register substitution |
| `c_runtime_header.py` | Generates `SEG_PTR`/`SEG_U8`/`MK_FP`/`inertia_memory[]` preamble |

### Postprocessing
| File | Purpose |
|------|---------|
| `decompiler_postprocess.py` (63K) | Top-level postprocessing orchestrator |
| `decompiler_postprocess_calls.py` (131K) | Call-site summaries, stack arg materialization, prototype promotion |
| `decompiler_postprocess_stage.py` (57K) | Staging orchestrator for multi-pass postprocessing |
| `decompiler_postprocess_flags.py` | Flag assignment pruning and rewriting |
| `decompiler_postprocess_jcc.py` (11K) | Conditional jump condition lowering |
| `decompiler_postprocess_typed_conditions.py` | Typed condition materialization |
| `decompiler_postprocess_simplify.py` (22K) | Expression simplification |
| `decompiler_postprocess_globals.py` (10K) | Global variable declaration materialization |
| `decompiler_postprocess_loads.py` | Load instruction lowering |

### Structuring (`structuring/` — 20+ files)
| File | Purpose |
|------|---------|
| `structuring_analysis.py` (22K) | CFG structural analysis |
| `structuring_region.py` (20K) | Region tree construction |
| `structuring_diagnostics.py` (14K) | Structuring quality diagnostics |
| `structuring_grouped_pass.py` | Grouped block pass orchestration |
| `structuring_loops.py` / `structuring_sequences.py` | Loop and sequence detection |
| `structuring_cfg_*.py` | CFG grouping, ownership, indirect edge handling |

### Validation
| File | Purpose |
|------|---------|
| `tail_validation.py` (85K) | Semantic comparison of pre/post-process IR |
| `tail_validation_fingerprint.py` (56K) | Stable fingerprint computation across runs |
| `milestone_report.py` (31K) | Console summary and detail artifact rendering |
| `validation_semantics.py` (11K) | Semantic equivalence checking |
| `verification_80286.py` (27K) | 80286 real-mode verification harness |

### Other subsystems
| Area | Key files |
|------|-----------|
| Semantics | `segmented_memory_reasoning.py` (22K), `eflags.py` (20K), `emu.py`, `fast_tracer.py` |
| Analysis | `analysis_helpers.py` (66K) — calling conventions, helper signatures (54 DOS/BGI helpers), function ranking |
| COD/CodeView | `cod_extract.py` (21K), `cod_source_rewrites.py` (33K), `cod_known_objects.py`, `codeview_nb00.py`, `codeview_nb02_nb04.py` |
| Type system | `type_array_matching.py` (25K), `type_structure_merging.py` (13K), `type_equivalence_classes.py` (12K) |
| Recovery | `corpus_scan.py` (49K), `recovery_confidence.py` (15K), `recovery_manifest.py` |
| Recompilable | `recompilable_cases.py`, `recompilable_storage_map.py` (7 modules) |
| String instr | `string_instruction_lowering.py` (14K), `string_instruction_artifact.py` |
| Pipeline | `pipeline/contracts.py` (closed-loop enforcement), `pipeline/errors.py` (PipelineHardError) |
| Alias/Widening | `alias/` (model, domains, state, transfer), `widening/` (register, stack, store-width) |

## Data flow

```
DOS binary (.exe/.com/.cod)
  → angr Project (via load_dos_mz / blob loader)
  → CFG + Function recovery
  → angr Decompiler (Clinic → Structurer → codegen)
  → AST (CStructuredCodegen object)
  → 30+ AST rewrite passes
  → C text string
  → 30+ text postprocessing passes
  → tail_validation snapshot
  → gcc -fsyntax-only
  → emitted C (accepted or rejected)
```

## Caching

Two-level cache in `angr_platforms/.cache/`:
- `decompile_cli/` — per-function decompilation results (JSON)
- `tail_validation_details/` — diagnostic artifacts (not acceptance)

Cache key: binary path + function addr + api_style + simplify flag.

## Tail validation

Compares structured codegen fingerprints across runs. Controlled by `INERTIA_ENABLE_TAIL_VALIDATION` env var. Always enabled for COD files and under pytest.

Stages: `codegen`, `postprocess`, `text` — each can be `stable`, `changed`, `failed`, or `uncollected`. Acceptance is lenient: missing stages pass; only present failures block.

## Parallelism

- Function-level parallelism via `DaemonThreadPoolExecutor` or `PreforkJobPool`
- Controlled by `INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION`
- Per-function timeouts with adaptive per-byte model
- Fork isolation available for problematic functions on Linux

## Multi-architecture support

The `angr_platforms/` package hosts 10 architectures, though only X86_16 is heavily developed:

| Arch | Status |
|------|--------|
| X86_16 | Primary — full lifter, loader, lowering, structuring, validation |
| msp430 | MCU support — smoke tests for hanoi, new_orleans, sydney, cusco |
| tricore | Infineon TriCore — ~11K test file |
| avr, bf, bpf, ct64, ebpf, risc_v, sparc | Experimental / smoke-level |

The `inertia_decompiler` layer is X86_16-specific. Multi-arch support lives entirely in `angr_platforms/<arch>/`.

## Existing design docs

In `angr_platforms/docs/` (12 files):
- `80286_real_mode_verification.md` — 80286 real-mode verification plan
- `x86_16_80286_real_mode_coverage.md` — instruction coverage tracking
- `x86_16_cod_corpus_completion_plan.md` — COD corpus roadmap
- `x86_16_decompiler_readability.md` — readability goals and metrics
- `x86_16_example_matrix.md` — test corpus matrix
- `x86_16_interrupt_api_lowering_plan.md` — interrupt lowering design
- `x86_16_mnemonic_coverage.md` — mnemonic coverage tracking
- `x86_16_reference_priority.md` — reference binary priority ordering
- `x86_16_snake_recompilation_plan.md` — SNAKE recompilation roadmap
- `x86_16_tricks_and_checklist.md` — tips and common pitfalls
- `dream_decompiler_execution_plan.md` + `_plan2.md` — long-term vision

Handoff docs at repo root: `SORTDEMO_HANDOFF.md` (live per-function status), `AGENTS.md` (concise rules ~4.6K), `AGENTS_too_big.md` (extended diagnostics ~25K).
