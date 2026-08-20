# Developer Guide

## Quick start

```bash
# Create venv and install
python3 -m venv .venv
.venv/bin/pip install -e ".[test,dev]"

# Decompile a single function
INERTIA_ENABLE_TAIL_VALIDATION=1 \
  ./.venv/bin/python ./decompile.py \
  --alternate-source-c \
  --c-target portable-flat \
  --addr 0x10678 \
  ./SORTDEMO.EXE

# Decompile all functions in a binary
INERTIA_ENABLE_TAIL_VALIDATION=1 \
  ./.venv/bin/python ./decompile.py \
  --alternate-source-c \
  ./SORTDEMO.EXE

# Run full test suite
.venv/bin/python -m pytest angr_platforms/tests/ -x -v

# Run specific test file
.venv/bin/python -m pytest angr_platforms/tests/test_x86_16_sortdemo_regressions.py -x -v

# Run single test
.venv/bin/python -m pytest angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_name -x -v
```

## Project structure

```
vextest/
  decompile.py                     entry point
  inertia_decompiler/              pipeline business logic
    cli_core.py                    main loop, caching, acceptance gate
    cli_decompilation.py           single-function decomp pipeline
    cli_c_ast_rewrites.py          AST-level rewrite passes
    cli_c_text_postprocess.py      C text cleanup passes
    runtime_support.py             timeouts, parallelism, angr guards
    tail_validation.py             tail validation orchestration
    project_loading.py             angr Project construction
    recompile_check.py             gcc syntax check
    work_items.py                  data types for work items
    cli_function_discovery.py      function identification
    cli_fallback_decompilation.py  fallback decompilation paths
  angr_platforms/                  X86_16 arch module
    angr_platforms/X86_16/         platform code
      lowering/                    stack lowering, alias facts
      postprocess/                 (empty — code in parent dir)
      pipeline/                    contracts, error handling
      structuring/                 region/loop structuring
      semantics/                   alias queries, segmented memory
      validation/                  (empty — code in parent dir)
    tests/                         test suite
  SORTDEMO.EXE, SORTDEMO.dec       test binaries
  reference/                       ground-truth reference C
```

## Architecture principles

**Two-layer design**: `inertia_decompiler` is the business-logic layer (pipelines, caching, validation). `angr_platforms/X86_16` is the domain layer (architecture-specific lowering, structuring, postprocessing). The platform layer is angr-aware; the inertia layer orchestrates.

**AST then text**: Rewrites happen in two phases. First on the structured codegen AST (`cli_c_ast_rewrites.py`), then on the rendered C string (`cli_c_text_postprocess.py`). Text passes are only for presentation/compile-hygiene — if the output is missing stack variables or carries raw pointer chains, the fix belongs in AST rewrites or stack lowering, not text cleanup.

**Acceptance gate**: A function is accepted only when `_validated_generated_c_acceptance_8616()` returns `("ok", None)`. This requires: status=ok, non-empty C, quality guard passed, tail validation passed, gcc syntax check passed (portable-flat target), and the MS C 5.1 msc-dos syntax check unless `--msc-dos-check optional|off` relaxes it on hosts without kvikdos/MS C 5.1.

**Facts are not success, bindings are not success**: Only these count:
- emitted output materially improved and passed validation
- emitted output now compiles
- a more precise blocker replaced a vaguer blocker

## Where to fix common problems

| Symptom | Look in |
|---------|---------|
| Stack variable not named | `cli_c_ast_rewrites.py` — `_attach_ss_stack_variables`, `_rewrite_ss_stack_byte_offsets` |
| `*(vvar_N ± K)` in output | `lowering/stack_lowering_impl.py` — carrier chain not resolved; or `cli_stack_byte_offsets.py` |
| Wrong callee name/ariry | `analysis_helpers.py` — `KNOWN_HELPER_SIGNATURE_DECLS`; or `decompiler_postprocess_calls.py` |
| Call argument not materialized | `decompiler_postprocess_calls.py` — `_materialize_callsite_stack_arguments_8616` |
| Tail validation false failure | `tail_validation.py` — snapshot comparison; check if stage is truly `failed` vs `uncollected` |
| gcc syntax error | Run the emitted C through gcc manually; check `recompile_check.py` for flags; common causes: `ir_3_2` autonames, `SEG_PTR` type mismatches, missing prototypes |
| Segmentation in output (`ss << 4`, `SEG_U8`) | `lowering/stack_lowering_impl.py` — stack lowering didn't complete; or `segmented_memory_reasoning.py` |
| Recurrence not coalesced | `cli_linear_recurrence.py`, `cli_linear_recurrence_state.py` |

## Debugging

```bash
# Enable trace output for all C stages
INERTIA_DEBUG_C_TRACE=1

# Watch specific rewrites for ReInitBars-like issues
INERTIA_DEBUG_REINITBARS_REWRITE=1

# Dump call-site mutations
INERTIA_DEBUG_CALL_MUTATION=1

# Inspect tail validation snapshot at runtime
INERTIA_DEBUG_TAIL_SNAPSHOT=1
```

## Key env vars

| Variable | Effect |
|----------|--------|
| `INERTIA_ENABLE_TAIL_VALIDATION` | Force-enable/disable tail validation |
| `INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION` | Disable parallel decompilation |
| `INERTIA_MSC_DOS_CHECK` | `required` (default), `optional`, or `off`: how a missing kvikdos/MS C 5.1 toolchain affects the msc-dos recompile check (`--msc-dos-check`) |
| `INERTIA_KVIKDOS_PATH` / `INERTIA_MSC51_ROOT` | Location of the kvikdos DOS runner and the Microsoft C 5.1 tree used by the msc-dos recompile check |
| `INERTIA_RECOMPILE_TIMEOUT_SEC` | Per-compiler timeout of the recompile checks (default 20) |
| `INERTIA_CATALOG_TIMEOUT` | Quick function-catalog budget for whole-binary EXE runs (`--catalog-timeout`) |
| `INERTIA_DECOMPILE_CACHE` | Cache directory override |
| `INERTIA_DEBUG_C_TRACE` | Dump C stage traces to stderr |
| `INERTIA_DEBUG_CALL_MUTATION` | Dump call-site before/after each pass |
| `INERTIA_DEBUG_REINITBARS_REWRITE` | Trace stack lines for specific function |

## Test organization

- `test_x86_16_sortdemo_regressions.py` — SORTDEMO.EXE end-to-end acceptance
- `test_x86_16_tail_validation_fingerprint.py` — tail validation snapshot stability
- `test_x86_16_decompiler_postprocess_calls.py` — call-site rewriting
- `test_x86_16_decompiler_postprocess_callsites.py` — call-site discovery
- `test_x86_16_cli.py` — main integration test (440K)
- `test_x86_16_cod_regressions.py` — COD file decompilation
- `test_x86_16_stack_prototype_promotion.py` — stack lowering
- `test_x86_16_*.py` — unit tests for specific subsystems

Tests use pytest. The conftest.py sets up angr logging suppression. Fixtures in `tests/fixtures/`.

## Acceptance rules (SORTDEMO lane)

See `SORTDEMO_HANDOFF.md` for current per-function status. A function is accepted when:
- `generated_c=true`
- `tail_validation=passed`
- final quality guard passed
- gcc syntax check passed (portable-flat)
- `status=ok`

The definitive gate is `_validated_generated_c_acceptance_8616()` in `cli_core.py:986`.

## Committing

Follow existing commit style: short imperative messages, function addresses in hex where relevant. Co-authored-by trailer is added automatically.
