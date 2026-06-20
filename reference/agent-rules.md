# Agent Rules And Internal Glossary

This file holds internal guidance that should not live in the user-facing README.

## Mission

Correctness first. Evidence-driven C. No guessing. Readable only when proven.

Priority order:

1. All functions must decompile to generated C with no crashes and no silent disappearance.
2. Tail validation must pass: `validation=passed` means semantic equivalence.
3. Generated C must be recompilable where practical: portable-flat gcc first, MS C DOS after that.

Readability, names, structs, and arrays are secondary unless they are required for correctness.

## Core Pipeline

```text
IR -> Alias -> Widening -> Types -> Structuring -> Rewrite
```

Semantics must be introduced as early as possible. Rewrite is cleanup-only.

Core model:

- `Value`: data.
- `Address`: segmented memory identity.
- `Condition`: branch meaning.

Layer ownership:

- `frontend`: `angr_platforms/angr_platforms/X86_16/`
- `IR`: `X86_16/ir/`
- `semantics`: `X86_16/semantics/`
- `alias`: `X86_16/alias/`
- `widening`: `X86_16/widening/`
- `traits/summaries/confidence`: `X86_16/*.py`
- `types/lowering/object recovery`: `X86_16/lowering/` and `type_*.py`
- `structuring`: `X86_16/structuring/` and `decompiler_structuring_stage.py`
- `rewrite/cleanup`: `X86_16/postprocess/` and `decompiler_postprocess_stage.py`
- `tail validation`: `X86_16/tail_validation*.py`, `validation_*.py`
- `CLI/fallback/reporting`: `inertia_decompiler/`

Semantic recovery belongs in `X86_16/`. Cleanup-only work belongs in `postprocess/`. Do not add new semantic work to root compatibility files such as `alias_model.py` or `alias_domains.py`.

## Hard Rules

1. Solve at the correct layer: alias in alias, types in types, never in rewrite.
2. Alias first: storage identity comes from alias evidence only; widening follows alias proof.
3. Segmented memory: SS, DS, and ES are distinct spaces. Use `Address(space=SS, offset=...)`, not flattened `(seg << 4) + offset`.
4. Stack to variable: `SS:BP+offset` becomes `local_*` or `arg_*`, not `stack[x]` or raw pointer arithmetic.
5. Explicit conditions: emit `if (x < y)`, not `if (tmp_14)` or `if (flags & ...)`.
6. No text-based recovery: use IR, CFG, alias, typed structures, and structured metadata. Do not recover semantics with regex over asm or rendered C.
7. Rewrite boundary: formatting, simplification, and cleanup only. No alias, type, call-argument, signature, or body repair.
8. Validation is truth: compare register effects, memory writes, return values, and control flow. Do not hide `changed` or `uncollected`.
9. No guessing: insufficient evidence means honest ugly output.
10. Determinism: same input produces same output.
11. Typed status/state: new work should use enums or structured fields instead of string parsing.

If a fix makes output prettier without improving underlying semantics, it is wrong.

## Execution Discipline

Every semantic improvement needs a closed evidence loop:

- `raw_fact_count`
- `normalized_fact_count`
- `classified_fact_count`
- `materialized_count`
- `failure_count`

If `classified > 0` and `materialized == 0`, the pipeline must fail.

DCE is allowed only when evidence is collected and consumed. Unknown classification means `UNKNOWN_REFUSE` and the code must be kept. Passing gcc by deleting semantically live code is a hard failure.

For each function being fixed, run a focused function regression before and after changes. If original C or COD source exists, compare output shape and call semantics against source. Do not mark a function fixed unless validation passes, semantic calls survive with correct argument classes, and output is closer to the original C than the previous baseline.

## Glossary

Execution semantics: low-level instruction meaning during execution. `DS << 4` may exist internally for real-mode execution but must not leak into normal emitted C.

Semantic recovery: reconstruction of stack variables, loops, conditions, pointer types, function calls, structs, and arrays from machine code before cosmetic rewrites.

Materialization: the point where a recovered semantic concept becomes emitted C, such as a stack slot becoming `local_2`, a recurrence becoming `i++`, or segmented access becoming `SEG_U16(ds, off)`.

Canonicalization: normalization of equivalent expressions into a stable form without inventing semantics.

Tail validation: semantic comparison between recovered/pre-postprocess representation and final emitted representation. Semantic drift is failure.

Semantic honesty: the decompiler fails explicitly instead of emitting misleading C.

Segmented memory model: 16-bit real-mode DOS memory with CS, DS, SS, and ES segment registers plus offsets. Physical address is `(segment << 4) + offset`, but normal output uses segmented helpers.

Laundered segment linearization: hidden linearization such as `tmp = ss; ptr = tmp << 4;`. Validation should reject it like direct `ss << 4`.

Runtime helper: a portable abstraction such as `SEG_U8`, `SEG_U16`, `SEG_PTR`, and `MK_FP`.

Stable stack slot: a proven persistent stack location such as `SS:BP-0x2:size2`.

Stack carrier: a low-level temporary stack representation before materialization, such as `s_0`, `s_4`, or `s_fffd`.

Byte carrier: a temporary representing one byte of a wider stack/local value. It should usually disappear after widening and materialization.

Widening: combining proven low-level pieces into a larger semantic value, such as low/high bytes or split pointer pieces.

Stack alias: proof that multiple expressions refer to the same stack location.

Stack canonicalization bridge: validation metadata proving two stack expressions represent the same stable slot.

ConditionIR: intermediate representation for equality, ordering, signed/unsigned comparisons, and zero checks.

Typed condition materialization: conversion of flag logic into typed C conditions.

Linear recurrence: a loop-update pattern such as `i = i + 1`, `i += 1`, or `i++`.

Recurrence rebinding: replacing low-level recurrence carriers with the materialized semantic local.

Callsite materialization: recovery of actual function arguments from pushes and call setup patterns.

Stale pushed arguments: previous stack state incorrectly surviving into a recovered call.

Prototype stabilization: recovery and enforcement of consistent function signatures from call usage, helpers, sidecars, annotations, and ABI facts.

Honest fallback prototype: safe fallback signature when exact prototype recovery is impossible.

PipelineHardError: fatal semantic pipeline error used when semantics are corrupted, validation fails, forbidden constructs remain, or materialization invariants fail.

Rewrite lane: late cosmetic transformation phase. It may format and simplify, but must not infer semantics.

Semantic consumer: a pass that converts proven semantic facts into higher-level representations.

Acceptance gate: final correctness gate requiring generated C, validation where enabled, recompilation where requested, and no unresolved semantic blockers.

Compile-readiness: syntactically valid generated C, typically checked with `gcc -std=c99 -Wall -Werror -fsyntax-only`.

Dead setup artifact: a low-level temporary emitted after semantic materialization already consumed it.

Semantic ownership: the rule defining which layer is responsible for each transformation.

## Diagnostics And Profiling

Focused SORTDEMO regression:

```bash
INERTIA_ENABLE_TAIL_VALIDATION=1 ./decompile.py --alternate-source-c ./SORTDEMO.EXE
```

Compact telemetry for slow decompilation:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_SPAN_FILE=angr_platforms/.cache/otel.trace.txt \
./decompile.py ./SORTDEMO.EXE
```

Use JSON/JSONL traces only for parsers. Human and agent handoff should use compact text or slow-span summaries. Details are in `reference/telemetry.md`.

## Resume Loop

For long autonomous repair sessions:

```bash
./.venv/bin/python scripts/codex_resume_loop.py \
  --prompt "go on. fix function by function. Finish only when all functions are fixed." \
  --goal-cmd 'jq -e ".stop_reason==\"goals_met\"" angr_platforms/.cache/auto_decomp_loop/DONE.marker.json >/dev/null 2>&1' \
  --status-cmd 'test -f angr_platforms/.cache/auto_decomp_loop/DONE.marker.json' \
  --max-iterations 200 \
  --stagnation-limit 30
```

Prefer the default resume behavior, use `--goal-marker-file` or `--goal-cmd` as the hard stop, and keep a manual stop file such as `/tmp/STOP_CODEX_LOOP` available.
