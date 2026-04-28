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
