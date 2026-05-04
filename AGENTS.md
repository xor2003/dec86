# Inertia Decompiler

## Mission

* correctness first
* evidence-driven C
* no guessing
* readable only when proven

---

## Core pipeline (DO NOT BREAK)

```text
IR → Alias → Widening → Types → Structuring → Rewrite
```

Rule:

> Semantics must be introduced as early as possible, never in rewrite.

---

## Core model

All reasoning must operate on:

```text
Value      — data
Address    — memory (segment + offset)
Condition  — branch meaning
```

Interpretation:

- `IR`: normalized lifted input
- `Alias model`: storage identity
- `Widening`: proven-safe joins of narrow pieces
- `Traits`: evidence only
- `Types`: downstream object/type decisions from stable evidence
- `Rewrite`: final cleanup only

---

## Layer ownership map

Land new work in the earliest correct layer.

- `frontend`: `angr_platforms/angr_platforms/X86_16/`
  - arch, loader, lift, SimOS, sidecar/signature ingestion
- `IR`: `angr_platforms/angr_platforms/X86_16/ir/`
- `semantics`: `angr_platforms/angr_platforms/X86_16/semantics/`
- `alias`: `angr_platforms/angr_platforms/X86_16/alias/`
- `widening`: `angr_platforms/angr_platforms/X86_16/widening/`
- `traits / summaries / confidence`: package-root `angr_platforms/angr_platforms/X86_16/*.py`
- `types / lowering / object recovery`: `angr_platforms/angr_platforms/X86_16/lowering/` plus package-root `type_*.py`
- `structuring`: `angr_platforms/angr_platforms/X86_16/structuring/` plus `decompiler_structuring_stage.py`
- `rewrite / cleanup`: `angr_platforms/angr_platforms/X86_16/postprocess/` plus `decompiler_postprocess_stage.py`
- `tail validation`: `angr_platforms/angr_platforms/X86_16/tail_validation*.py`, `validation_*.py`
- `CLI / fallback / reporting`: `inertia_decompiler/`

Placement rules:

- semantic recovery belongs under `angr_platforms/angr_platforms/X86_16/`, not `inertia_decompiler/`
- cleanup-only late rewrites belong under `postprocess/`
- do not add new ownership to root-level compatibility files such as `alias_model.py`, `alias_domains.py`, `alias_state.py`, `alias_transfer.py`
- when both a subpackage and a root-level `X86_16/*.py` file exist for the same concern, prefer the subpackage unless the root file is already the clear owner

## Hard rules

### 1. Solve at the correct layer

❌ Do not:

* fix alias in rewrite
* fix types using text
* guess objects

✅ Always:

* solve problems at the earliest correct layer

---

### 2. Alias-first

* storage identity comes only from alias
* widening only after alias proof
* no shape-based assumptions

---

### 3. Segmented memory (CRITICAL)

```text
SS, DS, ES are distinct memory spaces
```

❌ Forbidden:

```text
(seg << 4) + offset as IR
flattened memory model
```

✅ Required:

```text
Address(space=SS, offset=...)
```

👉 linear addresses allowed only for:

* execution
* debugging

---

### 4. Stack → Variable (REQUIRED)

```text
SS:BP+offset → stack slot → variable
```

❌ Forbidden:

```text
stack[x]
*(ss << 4)
raw pointer arithmetic for stack
```

✅ Required:

```text
local_*
arg_*
```

---

### 5. Conditions must be explicit

❌ Forbidden:

```text
if (tmp_14)
if (flags & ...)
```

✅ Required:

```text
if (x < y)
if (x == 0)
```

---

### 6. No text-based recovery

❌ Forbidden:

* regex on assembly
* substring matching
* analyzing generated C

✅ Only use:

```text
IR
CFG
alias
typed structures
```

---

### 7. Rewrite boundary (STRICT)

Rewrite is only for:

* cleanup
* naming
* formatting

❌ Rewrite must NOT do:

* alias reasoning
* type inference
* semantic recovery
* condition reconstruction

---

### 8. Validation is truth

Compare:

```text
- register effects
- memory writes
- return values
- control flow
```

❌ Forbidden:

* hiding `changed`
* treating `uncollected` as success

---

### 9. No guessing

If evidence is insufficient:

```text
→ produce honest, possibly ugly output
```

❌ Forbidden:

* guessing structs
* guessing arrays
* guessing intent

---

### 10. Determinism

```text
same input → same output
```

---

## Canonicalization policy

Canonicalization is **validation-only**, not semantic recovery.

Allowed:

* local algebraic normalization
* symbolic simplification for equivalence
* SMT equivalence as fallback

Forbidden:

* modifying IR
* introducing new semantics
* hiding validation differences

---

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

---

## Final rule

> If a fix makes output prettier without improving underlying semantics, it is wrong.

---

## Execution discipline

Every semantic improvement must include a closed evidence loop:

```text
capture → normalize → classify → materialize → verify → report
```

A patch is incomplete if it only captures or transfers facts without proving that downstream output consumed them.

Required counters for every new semantic lane:

* `raw_fact_count`
* `normalized_fact_count`
* `classified_fact_count`
* `materialized_count`
* `failure_count`

If `classified_fact_count > 0` and `materialized_count == 0`, the pipeline must fail.

Silent fallback is forbidden unless explicitly enabled by a debug flag.

Legacy fallback must never be used in normal acceptance runs.

### Acceptance routine

For each target function, report:

```text
function: 0x...
raw_accesses:
normalized_accesses:
alias_facts:
stack_facts:
stack_bindings:
stack_materialized:
condition_facts:
condition_materialized:
validation_verdict:
primary_blocker:
```

A change is accepted only if one of these is true:

1. Output improves and validation remains honest
2. Output refuses with a more precise blocker
3. Diagnostic counters identify the next missing layer

A change is rejected if:

* Counters are missing
* Fallback hides the failure
* Facts are produced but not consumed
* Output changes only in rewrite
* Generated C is inspected to recover semantics

### Agent fixing loop

For every agent task:

```text
1. Pick exactly one target function.
2. Record baseline counters.
3. Change one layer only.
4. Run the same target.
5. Compare counters.
6. Accept only if the counter moved at the intended layer.
7. If output unchanged, identify first zero/bad counter.
```

Example counter-driven diagnosis:

```text
raw_accesses = 0
→ fix lifter/context/cache

raw_accesses > 0, normalized = 0
→ fix stack_frame_recovery

normalized > 0, stack_facts = 0
→ fix alias classification

stack_facts > 0, stack_materialized = 0
→ fix lowering/materialization

condition_facts > 0, condition_materialized = 0
→ fix condition consumption

materialized > 0, output still bad
→ fix structuring/codegen integration
```

---

### Materialization is not binding

Creating metadata objects such as `StackVariableBinding`, `ConditionIR`, or alias facts is not materialization.

Materialization means the downstream representation used for code generation has changed:

- AIL expression replaced
- SimVariable registered and used
- C emission uses `local_*`, `arg_*`, or explicit condition

Counters must distinguish:

```text
classified_count
binding_count
materialized_count
```

`binding_count > 0` and `materialized_count == 0` is failure, not progress.

## Bottom line

The agent followed the previous plan enough to create better evidence, but it still reports **evidence creation as success**. The next fix must force actual consumption:

```text
facts are not success
bindings are not success
only materialized output or precise blocker is success
