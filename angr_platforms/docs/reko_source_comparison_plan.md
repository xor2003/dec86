# Reko vs Inertia Source Comparison Plan

This note compares the local `reko/` source tree against Inertia's current
x86-16 decompiler path.

It is meant to answer three practical questions:

- where Reko is still ahead
- what Inertia has already implemented successfully
- what is still worth borrowing for this project

This is based on source code and design documents, not only on earlier summary
notes.

## Scope

The comparison is intentionally limited to the parts that matter most for
Inertia's current x86-16 goals:

- segmented memory recovery
- byte-pair to word recovery
- alias-aware value recovery
- address-trait collection
- source-like memory-object rewriting
- decompilation stability and speed

It is not an argument for copying Reko code directly.

## Source References

The most relevant Reko source and design files for this comparison are:

- `reko/src/Decompiler/Analysis/ProjectionPropagator.cs`
- `reko/src/Decompiler/Analysis/SegmentedAccessClassifier.cs`
- `reko/src/Decompiler/Typing/AddressTraitCollector.cs`
- `reko/doc/dev/projection.md`
- `reko/doc/dev/ssa-aliasing.md`

The most relevant Inertia implementation surface right now is:

- [decompile.py](/home/xor/vextest/decompile.py)
- [reko_borrow_execution_plan.md](/home/xor/vextest/angr_platforms/docs/reko_borrow_execution_plan.md)
- [reko_reuse_notes.md](/home/xor/vextest/angr_platforms/docs/reko_reuse_notes.md)

## Where Reko Is Better

### 1. Segmented addresses are treated as first-class values

In `SegmentedAccessClassifier.cs`, Reko does not immediately flatten segmented
memory into generic linear arithmetic. It first classifies whether a segment
register is stably associated with:

- one identifier
- a constant
- or multiple competing associations

That is stronger than ad hoc tree matching because it lets later passes make a
yes-or-no decision about whether a segmented access can safely become a
pointer-like object.

Why this is still better than Inertia:

- Reko's association model is explicitly dataflow-aware
- Inertia still relies mostly on expression-shape classification inside
  `decompile.py`
- Inertia is already safer than before, but it is not yet a full association
  analysis

### 2. Projection propagation is more systematic

In `ProjectionPropagator.cs`, Reko handles widening and narrowing as one family
of transformations:

- `SEQ(reg_hi, reg_lo)` to a wider value
- adjacent stack pieces to a wider stack object
- adjacent memory pieces to wider memory access
- `SLICE` and cast propagation in the opposite direction

Why this is better:

- the widening logic is part of a coherent transform instead of many local
  rewrites
- it works over SSA-backed statements, not only over final codegen trees
- it naturally supports both register and memory reconstructions

Inertia has several successful local versions of this idea, but not yet one
unified widening framework.

### 3. Alias handling is more principled

`ssa-aliasing.md` describes a real storage-domain model:

- separate identifier from storage
- group aliases by storage domain
- synthesize alias assignments only when needed
- rebuild larger values from overlapping subparts only when justified

Why this is better:

- it attacks correctness at the source of the problem
- it explains when to generate `SLICE` and `SEQ` style rebuilds
- it scales better than one-off temp cleanup heuristics

Inertia has landed a lot of narrow alias-aware rewrites, but it still does not
have a true storage-domain alias model.

### 4. Address-trait collection is closer to a real type pipeline

`AddressTraitCollector.cs` is stronger than our current trait cache because it
connects address shape directly to later type inference:

- `base + const`
- induction-variable forms
- array context
- field access context

Why this is better:

- it is built to feed a type store
- it distinguishes arrays from fields more explicitly
- it is less "naming-oriented" and more "type-evidence-oriented"

Inertia already collects repeated offsets and some stride evidence, but it is
still much narrower.

### 5. Reko's stages are more connected

Reko's classifier, projection pass, alias logic, and trait collection were
clearly designed to cooperate.

Inertia today has:

- a good central classifier
- many useful local rewrites
- better caching and safer fixed-point cleanup

But it still behaves more like a careful stack of targeted passes than one
integrated recovery pipeline.

## What Inertia Already Implemented

These are the parts of the Reko-inspired direction that are already real in
Inertia today.

### 1. Central segmented access classification

In `decompile.py`, Inertia now has a central segment-space classifier that
separates:

- `ss`
- `ds`
- `es`

and caches the results per decompilation run.

This is already a meaningful translation of the `SegmentedAccessClassifier`
idea, even if it is not yet as dataflow-rich as Reko's version.

### 2. Projection-style widening for real targets

Inertia already folds several high-value x86-16 patterns:

- adjacent byte loads to word-like expressions
- adjacent byte stores to word-like statements
- selected high-byte preserving updates
- repeated `>> 1` chains into wider `>> n`
- segmented byte-pointer cleanup in `snake`

These are real wins, not just plan items. They already improved:

- `snake.EXE:0x13b2`
- `snake.EXE:0x1287`
- `_rotate_pt`
- `_TIDShowRange`
- `_ChangeWeather`

### 3. Access traits and field-like naming

Inertia now collects access traits and uses them for narrow field-style output:

- repeated offsets
- simple `base + const`
- some `base + index * stride` evidence
- some stable `base + index * stride` cases are good candidates for future
  array-like object naming, but that remains a guarded extension rather than a
  currently enabled rewrite

This already feeds visible improvements like `field_30e`-style recovery and is
a real partial implementation of the `AddressTraitCollector` direction.

### 4. Alias-aware cleanup is already helping

Even without a full storage-domain SSA model, Inertia has landed useful narrow
alias/value recovery for:

- one-use expression aliases
- recurrence cleanup
- temp-chain folding
- tiny always-on algebraic identities like `x ^ x -> 0`, `x - 0 -> x`,
  `0 + x -> x`, and `0 | x -> x`
- boolean cleanup like `!(x - c) -> x == c`
- some high-byte and byte-pair guard recovery

This has already improved `snake` guards and some `.COD` functions without
breaking whole-binary stability.

### 5. Typed rewrites have started

Inertia now performs some real typed/object-like rewrites:

- `ss` accesses can become stack locals
- promoted stack objects now get `arg_` / `local_` names
- promoted stack objects now preserve their recovered byte/word width instead of
  being forced through one generic promoted shape
- synthetic globals from `.COD` metadata can become named memory variables
- some declaration widths are already recovered to `unsigned short`

This is not complete, but it is already beyond pure pretty-printing.

### 6. Inertia is stronger on corpus-driven validation

For this project specifically, Inertia already has a better practical loop than
Reko for our target corpus:

- focused `.COD` oracles
- `snake.EXE` whole-binary regression
- CLI-level checks for visible source-like C

That makes Inertia better at "did this help our real binaries?" even if Reko is
still ahead architecturally in some areas.

## What Is Still Applicable For Inertia

These are the Reko ideas that are still worth implementing next.

### 1. Stronger association analysis for segment+offset

Best Reko source:

- `SegmentedAccessClassifier.cs`

What to borrow:

- explicit notion of over-associated segment bases
- distinction between segment associated with one offset source vs many
- promote to pointer-like form only when that association is stable

Why it still matters:

- it would make later typed rewrites safer
- it would help move more `ds:const` and `ss:frameoff` cases into true objects

### 2. A unified widening pass

Best Reko source:

- `ProjectionPropagator.cs`

What to borrow:

- one coherent widening/narrowing stage
- memory and register widening in the same conceptual pass
- slice/sequence reconstruction that works before final C cleanup

Why it still matters:

- it should reduce the number of special-case local rewrites in `decompile.py`
- it is the cleanest path to killing more `low | high * 0x100` output

### 3. A storage-domain alias model

Best Reko source:

- `ssa-aliasing.md`

What to borrow:

- storage domains
- alias states
- synthesize alias values only when the use actually needs them

Why it still matters:

- this is the biggest remaining correctness upgrade, not just a readability one
- it is the right long-term answer for `_InBox`-class conditions and harder
  `snake`/`.COD` flag logic

### 4. Stronger trait-to-type bridge

Best Reko source:

- `AddressTraitCollector.cs`

What to borrow:

- more explicit array context
- induction-variable recognition
- better separation between field evidence and array evidence

Why it still matters:

- Inertia's current trait layer is good groundwork but still under-connected to
  type recovery
- this is the next step from `field_30e` toward actual member/array objects

### 5. Typed object rewriting after evidence, not before

Best Reko source:

- `AddressTraitCollector.cs`
- related typing passes noted in `reko_reuse_notes.md`

What to borrow:

- keep object rewriting downstream of classification and evidence
- do not guess struct/array objects too early
- only rewrite to source-like objects when evidence is stable

Why it still matters:

- this matches Inertia's current safety-first direction
- it would let us extend object recovery without reopening earlier regressions

## What Is Not A Good Fit

These Reko strengths should stay inspirational, not become direct goals.

### 1. Whole type-system transplantation

Why not:

- too invasive
- too tied to Reko internals
- too much risk of turning Inertia into a second decompiler project

### 2. Direct code ports

Why not:

- GPL
- architectural mismatch with angr and our current x86-16 path

### 3. Early collapse of all segmented memory to one pointer model

Why not:

- `ss`, `ds`, and `es` really are different spaces in our corpus
- correctness would get worse before readability got better

## Recommended Next Plan

This is the practical next plan after comparing the source trees.

### Stage 1. Finish the typed rewrite lane

Focus:

- make `ss:frameoff` recovery more source-like
- preserve byte vs word widths on stack and global objects
- extend `arg_` / `local_` naming only when the current name is still generic

Primary targets:

- `_TIDShowRange`
- `_SetGear`
- `_DrawRadarAlt`

### Stage 2. Strengthen trait-to-object recovery

Focus:

- use repeated offset + stride evidence for more than field naming
- introduce narrow array/member rewrites only where evidence is stable

Primary targets:

- cockpit/UI helpers
- `rotate_pt`
- `ConfigCrts`

### Stage 3. Build a stronger alias model

Focus:

- start with x86-16 subregister and byte-pair storage domains
- use it only for the cases already proven useful in `snake` and `.COD`

Primary targets:

- `_InBox`
- `_SetGear`
- harder `snake` guard logic

### Stage 4. Unify widening

Focus:

- replace more local byte-pair special cases with one wider projection pass

Primary targets:

- `snake.EXE:0x13b2`
- `_rotate_pt`
- `_ChangeWeather`

### Stage 5. Keep the validation style

Do not change this part:

- keep `snake.EXE` whole-binary runs
- keep focused `.COD` CLI oracles
- keep accepting only changes that prove themselves on real outputs

## Bottom Line

Reko is still better architecturally in three big areas:

- systematic projection propagation
- storage-domain alias reasoning
- address traits that feed type inference directly

Inertia already implemented a useful subset of those ideas:

- central segmented classification
- several projection-style widenings
- access-trait collection
- narrow alias/value cleanup
- early typed object rewrites

The best path forward is not to copy Reko more literally.
The best path is to keep borrowing its architecture in small, test-backed
pieces that improve real `snake` and `.COD` outputs.
