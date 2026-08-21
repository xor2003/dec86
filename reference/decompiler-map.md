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

Indexed segmented addresses are also IR facts. `IRAddress.base_values` retains
their exact versioned dynamic terms, and `X86_16/ir/indexed_address_evidence.py`
owns tracing a supported term to its SSA definition and stable stack source.
That producer must publish either a typed fact or a typed refusal; it must not
infer aliases, bounds, arrays, structures, or C types. Alias owns storage/range
identity in `X86_16/alias/indexed_address_projection.py` without collapsing the
dynamic term to a direct-memory displacement. Widening owns proven aggregate
views, and Types/Lowering owns object materialization. During migration,
`X86_16/lowering/indexed_address_collector_parity.py` may compare identities
from both producers but may not select evidence or change C. The legacy
instruction-backed global collectors remain migration debt until each consumer
has switched to the earlier typed evidence with an exact corpus parity census.
`X86_16/lowering/indexed_address_parity_inventory.py` and its contracts extend
that read-only census across a discovered function set. The tooling entry point
`scripts/indexed_address_parity_inventory.py` always isolates the executable
from local sidecars and reports non-library functions by default; divergence is
diagnostic evidence, never permission for Lowering to choose whichever producer
looks more convenient.
`X86_16/alias/indexed_address_access_classification.py` classifies only two
unambiguous post-Alias forms: zero-displacement unscaled pointer-relative access
and scaled, nonzero-base global-index candidates. Mixed forms are typed refusals;
bounds/layouts need separate proof, as do load-to-store paths for family joins.
For interprocedural global-memory outputs, Semantics owns exact store and
terminal-path facts, Alias owns segmented range identity and overlapping-view
ownership, Widening owns exact caller-load projections into those ranges, and
Types/Lowering owns caller CFG/use trials. A contained caller view may be
materialized only with its exact byte offset into a unique maximal Alias range;
crossing, width-conflicting, or unproven views must refuse before Lowering.
Function contracts retain those projections under one Alias-owned memory
object. They must not flatten whole and contained views into independent scalar
return slots; `outputs` is reserved for register/sequence returns. Atomic
publication revalidates that every object view has exactly one matching effect
and optional `LIVE_OUT` trial in the same caller/callsite binding; stale,
duplicate, missing, or orphaned projections fail before project mutation.

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
