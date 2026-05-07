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

### 4.1 Stack activity vs stack variables

Not all SS accesses are stack variables.

The following are distinct concepts:

stack activity
stable stack slot
materialized variable

Examples:

```text
push/pop/call/ret
dynamic SP movement
temporary spill traffic

are stack activity, but are NOT automatically variables.
```

A stack variable may only be created when:

1. stack space is proven
2. frame model is proven
3. offset is stable
4. alias identity is stable

Forbidden:

SS access → automatic local_*
SP provisional access → automatic variable
invented BP/SP offsets

Required diagnostics:

ss_stack_accesses
bp_stable_accesses
sp_provisional_accesses
stack_materialized
primary_blocker

Blocker taxonomy (see `classify_stack_blocker_8616` in pipeline/invariants.py):

```text
ss_stack_accesses > 0 AND stack_facts == 0 AND bp_stable_accesses == 0
    → "stack activity detected but no stable frame"

stack_facts > 0 AND stack_materialized == 0
    → "stack facts not materialized"
```

Frame evidence must come from IR only:
- BP must be proven from IR-level frame analysis (not text disassembly)
- SP delta must be tracked and proven stable before SP-relative offsets become facts
- Dynamic SP traffic (push/pop/call/ret, spills before BP setup) is stack activity,
  NOT a variable — it must remain PROVISIONAL

Never collapse SP/BP/SS identities. ("sp",) alone in the base tuple does not
guarantee a stack variable — proven SP delta AND a stable offset are additionally
required. Code that tests `addr.base in {("bp",), ("sp",)}` must also gate on
stable offset; dynamic SP traffic without a proven delta must stay PROVISIONAL.

Why this matters:

Right now your team/agents still think:

SS access == local variable

which is architecturally wrong.

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

### 6.1 Frame evidence must come from IR, never text

Frame recovery may use:

```text
VEX IR
AIL
CFG
decoded instruction metadata
```

Forbidden:

```text
regex on assembly
generated C inspection
instruction text parsing
```

Examples of allowed evidence:

push bp
mov bp, sp
enter
sp adjustment tracking

only when recovered from IR/instruction metadata.

This prevents future "parse asm text" regressions.

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

### Stable stack slot requirement

A stack slot is materializable only if:

```text
space = SS
AND
frame model is proven
AND
offset is stable
```

The following are NOT materializable:

```text
SS:SP dynamic transient accesses
push/pop traffic
call frame setup before stabilization
symbolic SP without proven delta
```

Required behavior:

stack activity may exist
while stack_facts = 0

This is valid and must not be treated as failure.

This is the single most important clarification missing from your current AGENTS.

## Bottom line

The agent followed the previous plan enough to create better evidence, but it still reports **evidence creation as success**. The next fix must force actual consumption:

```text
facts are not success
bindings are not success
only materialized output or precise blocker is success
