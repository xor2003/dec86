# Inertia Decompiler

## Mission

Correctness first. Evidence-driven C. No guessing. Readable only when proven.

## Priority order

1. All functions must decompile to generated C (no crashes, no silent disappear)
2. Tail validation must pass (`validation=passed` = semantic equivalence)
3. Generated C must be recompilable (portable-flat gcc → MS C DOS)

Readability, names, structs, arrays: P1/P2 unless required for above.

## Core pipeline (DO NOT BREAK)

```text
IR → Alias → Widening → Types → Structuring → Rewrite
```

Semantics must be introduced as early as possible, never in rewrite.

## Core model

All reasoning on: `Value` (data), `Address` (memory segment+offset), `Condition` (branch meaning).

## Layer ownership

- `frontend`: `angr_platforms/angr_platforms/X86_16/` (arch, loader, lift, SimOS, sidecar)
- `IR`: `X86_16/ir/`
- `semantics`: `X86_16/semantics/`
- `alias`: `X86_16/alias/`
- `widening`: `X86_16/widening/`
- `traits/summaries/confidence`: `X86_16/*.py`
- `types/lowering/object recovery`: `X86_16/lowering/` + `type_*.py`
- `structuring`: `X86_16/structuring/` + `decompiler_structuring_stage.py`
- `rewrite/cleanup`: `X86_16/postprocess/` + `decompiler_postprocess_stage.py`
- `tail validation`: `X86_16/tail_validation*.py`, `validation_*.py`
- `CLI/fallback/reporting`: `inertia_decompiler/`

Semantic recovery → `X86_16/`. Cleanup-only → `postprocess/`. Do not add to root compatibility files (`alias_model.py`, `alias_domains.py`, etc.).

## Hard rules

1. **Solve at correct layer** — alias in alias, types in types, never in rewrite
2. **Alias-first** — storage identity from alias only, widening after alias proof
3. **Segmented memory** — SS/DS/ES are distinct spaces. `Address(space=SS, offset=...)` not `(seg<<4)+offset`
4. **Stack → Variable** — `SS:BP+offset` → `local_*`/`arg_*`. Not stack[x], not raw pointer arithmetic
5. **Explicit conditions** — `if (x < y)` not `if (tmp_14)` or `if (flags & ...)`
6. **No text-based recovery** — only IR, CFG, alias, typed structures. No regex on asm or rendered C.
7. **Rewrite boundary** — cleanup/naming/formatting only. No alias/type/semantic recovery, no call-argument/signature/body repair.
8. **Validation is truth** — compare register effects, memory writes, return values, control flow. No hiding `changed`/`uncollected`.
9. **No guessing** — insufficient evidence → honest ugly output.
10. **Determinism** — same input → same output.
11. **Typed status/state, not text matching** — for any new work, represent statuses/verdicts with enums or structured fields instead of string matching/parsing.

## Golden rules

```text
1. Semantics early, not late
2. Alias is the source of truth
3. Never flatten memory
4. Stack → variables (never stack[x])
5. Conditions must be explicit
6. No text-based reasoning
7. Rewrite does not solve semantics
8. Validation must be honest
9. Never guess
10. Deterministic output
```

> If a fix makes output prettier without improving underlying semantics, it is wrong.

## Agent execution rules

DO: push semantics earlier, prefer generic typed effects, make register/segment/flag/condition/memory impact explicit, track liveness across branches/loops/calls, prefer static recovery with runtime only as refinement.

DON'T: build recovery around compiler/library names, assume nice frames/conventions/loops, leave semantics in raw VEX tmps, treat timeout fallback as final architecture, solve live flag/segment/loop state in rewrite, use text-pattern recovery over rendered asm/C, depend on runtime traces as sole semantics source.

Sidecars/COD/debug listings are optional evidence only. They may provide labels, function bounds, and names, but must not be required for argument values, types, control-flow semantics, stack recovery, memory modeling, or validation success. The decompiler must work from binary IR/CFG/alias/typed effects for general 16-bit segmented binaries.

## Anti-patterns (never, unless explicitly marked temporary rescue)

- sample-specific address hacks, symbol-name hacks as proof, shape-only widening
- binary/function-specific C postprocess fixes, missing-argument fill-ins, signature rewrites, or whole-body replacements
- flatten-segment-for-convenience, guessed structs/arrays/helpers
- rewrite-stage semantic repairs, silent fallback as success
- `if "...substring..." in asm_text`, regex over assembly lines
- name-based helper substitution as recovered semantics
- corpus-specific allowlists, address-specific helper substitution

## Execution discipline

Every semantic improvement needs closed evidence loop: `raw_fact_count`, `normalized_fact_count`, `classified_fact_count`, `materialized_count`, `failure_count`. If `classified > 0` and `materialized == 0`, pipeline must fail.

### Persistent startup contract (do not relax)

- Inertia is an **evidence-based decompiler in every layer**.
- DCE is allowed only when evidence is collected and consumed (not guessed).
- Unknown classification means **refuse and keep code**, never delete.
- Passing gcc by deleting semantically live code is a hard failure.

### Function-fix acceptance contract (mandatory)

- For every function being fixed, run a focused function regression before and after changes.
- If original C/COD source exists, compare output shape and call semantics against source:
  required calls must survive with correct argument classes (value vs pointer).
- Do not mark a function “fixed” unless:
  1) `validation=passed`,
  2) no semantic call loss,
  3) output is closer to original C than previous baseline.
- Any DCE candidate without full evidence is `UNKNOWN_REFUSE` and must be kept.

## Review checklist

1. What layer? Why earliest correct layer?
2. What invariant does it fix? What test proves it?
3. What corpus result improved? What might regress?
4. Architectural or temporary rescue? If temporary, what replaces it?

## Improving code

```bash
INERTIA_ENABLE_TAIL_VALIDATION=1 ./decompile.py --alternate-source-c ./SORTDEMO.EXE
```

When decompilation is slow, turn on compact OpenTelemetry spans before profiling:

```bash
INERTIA_OTEL_SPANS=1 INERTIA_OTEL_SPAN_FILE=angr_platforms/.cache/otel.json ./decompile.py ./SORTDEMO.EXE
```

The compact summary shows top slow spans by duration and is designed for token-efficient agent handoff. Details: `reference/telemetry.md`.

Current `SORTDEMO.EXE` handoff: read `SORTDEMO_HANDOFF.md` before restarting work on ReInitBars/SwapBars/HeapSort.

## Reference files

Detailed rules, diagnostics, testing, CLI quickstart → `reference/`. Agent execution details → `reference/agent-rules.md`.
