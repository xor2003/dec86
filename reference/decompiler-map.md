# Decompiler Map

This is the short map for agents. `AGENTS.md` is the canonical rulebook;
`reference/agent-rules.md` is supplemental glossary and long-running-agent
guidance. This file exists so the correct layer is visible before editing.

## Core Order

```text
IR -> Alias -> Widening -> Types -> Structuring -> Rewrite
```

Semantic facts move left to right.  Do not introduce new semantics in rewrite.
If a late pass proves a fact, migrate that proof to the owning earlier layer and
leave the late pass as a temporary consumer only.

## Layer Owners

| Layer | Owner paths | Owns |
| --- | --- | --- |
| Frontend | `angr_platforms/angr_platforms/X86_16/`, `angr_platforms/angr_platforms/X86_16/lift_86_16.py` | arch, loader/lift hooks, instruction facts |
| IR | `X86_16/ir/` | typed `Value`, `Address`, `Condition`, instruction facts |
| Semantics | `X86_16/semantics/` | instruction effects, flags, branch meaning |
| Alias | `X86_16/alias/` | storage identity, stack/global alias proof |
| Widening | `X86_16/widening/` | proven byte/word/pointer joins after alias |
| Types and Lowering | `X86_16/lowering/`, `type_*.py` | stack/global object materialization, callsite facts, segmented memory lowering |
| Structuring | `X86_16/structuring/`, `decompiler_structuring_stage.py` | CFG shape, loops, switches, structured condition lowering |
| Rewrite/Postprocess | `X86_16/postprocess/`, `decompiler_postprocess_*.py`, `decompiler_postprocess_stage.py` | formatting, cleanup, validation-gated compatibility consumers |
| Validation | `X86_16/tail_validation*.py`, `validation_*.py` | semantic equivalence checks and honest failure reporting |
| CLI | `inertia_decompiler/` | orchestration, fallback choice, reports, timeouts |

Typed branch evidence is an IR/frontend fact even when angr returns a cached
IRSB. `X86_16/ir/condition_cache_relift.py` owns the temporary exact-byte
publication bridge: an empty condition cache is complete only when a typed
pending `ConditionSource` still owns that block; otherwise the custom lifter is
run under isolated state and must close all five evidence counters. Lowering may
transfer the resulting `ConditionIR`, but must not recreate operands or branch
meaning. The eventual replacement is direct cross-block condition-source
provenance in `IRFunctionArtifact`, after which the cache bridge can be removed.
Stored call-return ownership is specified in [`stored-call-return-contract.md`](stored-call-return-contract.md).
Selector returns have two owners: Structuring's
`structuring/single_branch_return_orientation.py` maps a no-else return body to
its edge from target-return expressions and CFG reachability; Tail Validation's
`tail_validation_selector_returns.py` fingerprints condition and both outcomes.
Only swapping outcomes makes inverted conditions equivalent; neither owner may
infer from rendered C or repair semantics in Rewrite.
Indexed segmented addresses are IR facts. `IRAddress.base_values` retains exact
versioned terms; `X86_16/ir/indexed_address_evidence.py` traces each supported
term to SSA and stable stack storage, producing a typed fact or refusal. Alias
owns storage identity in `alias/indexed_address_projection.py`, access roles,
copy endpoint identity, and the closed discovered-function census in
`alias/indexed_address_program.py`. `widening/indexed_global_object_layout.py`
alone joins proven byte/word views and whole-value copy families; Lowering only
consumes its closed artifact and materializes accepted objects. The CLI module
`inertia_decompiler/indexed_alias_program_context.py` transports a complete
discovery catalog into Alias once and never classifies semantic evidence.
`lowering/global_object_program_requirement.py` owns that typed need decision from local Alias roles and proven outgoing pointer-call sources; CLI only sequences it.
Legacy instruction-backed collectors are per-function rendering/parity debt, not an alternate project-layout owner. The read-only parity modules in Lowering may
report divergence but never select evidence or change C; the inventory script
isolates the executable from sidecars and reports non-library functions.
Near-offset call arguments follow the same chain: IR owns exact affine proof,
and Lowering joins it with callee-owned pointer output evidence atomically.
Target projection, object grouping, type proof, and direct/indirect ownership
are specified in `reference/pointer-parameter-output-pipeline.md`.
Alias accepts only unambiguous unscaled pointer-relative or scaled global forms; IR owns exact LOAD-to-STORE SSA lanes, Alias endpoint/index identity, and Widening families and bounds without defaults or numeric proximity.
Loop bounds follow the same chain: IR carries exact-byte conditions into SSA and owns immutable CFG, dominators, single-entry loops, and byte-backed zero/plus-one induction writes; Alias owns canonical index identity, and Widening maps one segmented layout before proving an extent. The final Widening layout/range bundle is serialized atomically through the project cache and clean-worker transport. Types/Lowering may only strengthen an existing declaration with an accepted exact range and matching indexed identity; dynamic bounds such as SORTD InitBars, external entries, ambiguous overlaps, missing names, and declaration conflicts remain typed refusals.
For interprocedural global-memory outputs, Semantics owns terminal stores, Alias
owns segmented ranges, Widening owns exact caller-load views, and Types/Lowering
owns CFG/use trials. Contained views require an exact offset into one maximal
range; crossing or ambiguous views refuse. Function contracts keep all views
under that Alias object, reserve `outputs` for register/sequence returns, and
validate matching effects and `LIVE_OUT` trials before atomic publication.

## Never Fix Here

- Do not add semantic recovery to `decompiler_postprocess_jcc.py`.
- Do not add call argument/signature/body repair to postprocess or CLI.
- Do not add stack identity, global identity, or type recovery to rewrite.
- Do not add behavior to root compatibility shims such as `alias_model.py` and
  `alias_domains.py`.
- Do not recover semantics from rendered C, assembly text, or regex matches.

## Compatibility Debt

Root `decompiler_postprocess_*.py` files are guarded compatibility bridges.
Their headers say what they may consume and where their debt must move.  The
current debt is also visible through:

- `angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py`
- `reference/layer-module-status.md`
- `reference/decompiler-fix-plan.md`

Adding a new semantic-looking postprocess pass must also update the inventory,
evidence counters, owner layer, and tests.  Unknown proof means keep the ugly
code and let validation report the missing fact.

## Gate Tiers

Run the fast tier while editing and before handing off ordinary decompiler
changes. The fast tier is unit-focused only; external compiler/decompiler smoke
lanes belong to the default and expanded tiers:

```bash
make check-files PYTHON=./.venv/bin/python FILES="path/to/file.py path/to/test.py"
make quality-fast PYTHON=./.venv/bin/python
make test-pipeline-fast PYTHON=./.venv/bin/python
```

Run the default tier before claiming a semantic decompiler improvement:

```bash
make test-pipeline PYTHON=./.venv/bin/python
```

Run the expanded tier for broad architecture/status audits and slower SORTDEMO
or corpus work:

```bash
make test-pipeline-expanded PYTHON=./.venv/bin/python
```

`make architecture-check PYTHON=./.venv/bin/python` is the ratchet for future
agents. It checks postprocess guard headers, protected import exceptions, root
compatibility shims, CLI imports, runtime guard entrypoints, documentation
markers, ownership manifests, and docs/types/dot-access ratchets. If it fails,
either move the work to the correct layer or explicitly update the architecture
allowlist with a documented migration reason and regression.

## Function Fix DoD
A fixed function needs all of:

- focused before/after regression evidence;
- `validation=passed`;
- no semantic call loss;
- output closer to original C/COD source when source exists;
- MS C tiny/full pipeline coverage when the case is represented there.

Passing recompilation by deleting live code is a failure, not a fix.
