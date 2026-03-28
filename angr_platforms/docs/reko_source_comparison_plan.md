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
- sequences rebuilt through phi nodes
- sequences defined by the same call return site

Why this is better:

- the widening logic is part of a coherent transform instead of many local
  rewrites
- it works over SSA-backed statements, not only over final codegen trees
- it naturally supports both register and memory reconstructions
- it also pushes fused values through phi and call-return sites, which makes
  the widening story more SSA-native than our current local rewrite passes

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

That classifier now also records an explicit association kind for each access
(`single`, `const`, or `over`) and keeps the pointer-style rewrites on the
conservative path when a segment base looks over-associated.

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
- some stable `base + index * stride` cases now also feed the same guarded
  field/member naming bridge, but only for the explicitly stable helpers in
  the current x86-16 allowlist

This already feeds visible improvements like `field_30e`-style recovery and is
a real partial implementation of the `AddressTraitCollector` direction.
The trait cache is also now width-aware for repeated offsets and stride-shaped
accesses, which gives us a safer base for future member/array work without
changing today's object rewrites.
The cache now also separates array-shaped and member-shaped stride evidence, and
that stride evidence now participates in the same guarded field/member naming
bridge for stable helpers, instead of being left as analysis-only metadata.
It still records pointer-member evidence for stable plain `base + const`
accesses like `rotate_pt` so we can keep the future rewrite boundary narrow
instead of collapsing all of these shapes into one generic bucket.
That member evidence now drives one narrow positive-offset pointer-member
rewrite, rather than a broad array/object lowering pass.
Helper-call names recovered from COD metadata are also now surfaced more
aggressively when the decompiler has only anonymous `sub_...` callsites left,
which improves visible argument/call readability in targets like
`_rotate_pt`, `_TIDShowRange`, and `_DrawRadarAlt`.
The old `_TIDShowRange` `CallReturn()` placeholder is now fully covered by the
COD source-text rewrite, so the plan treats argument-bearing helper calls in
`_SetHook`, `_SetGear`, `_DrawRadarAlt`, and `_TIDShowRange` as part of the
readability lane too.
The trait-to-object lane now also consumes array evidence directly when it is
stable, which keeps repeated-offset / indexed-access recovery aligned with the
same evidence stream instead of leaving that data unused.
That array evidence now also participates in stack-object naming when the base
object is already stable, with a regression test proving the generic stack
object path renames to `field_0` instead of leaving the synthetic `v1` name in
place.
The sample-matrix coverage now also proves that stride evidence is emitted on a
real COD helper, and that evidence now feeds the same guarded object-naming
bridge, so the trait-to-object path is backed by both synthetic and corpus-
driven checks.
The `rotate_pt` path now also collapses the adjacent byte-pair loads into the
source-backed `x = s[0];` / `y = s[1];` form, which is the kind of narrow
member/array cleanup that shows immediate output value without widening the
alias model.
Named stack byte-pointer accesses are also cleaned up into indexed byte form
when the base object is already stable, which improves the `ConfigCrts`-style
typed stack object presentation without widening the alias model.
This now includes both byte-sized and word-sized stack-byte renders, so the
current typed lane stays readable without turning into a broad object rewrite
pass.
Stack word accesses on stable named objects are now also simplified into
indexed word form when that is the clearest source-like rendering, which is
the current shape for the `ConfigCrts` copy loop.
Likewise, narrow pointer-array writes on stable named stack objects now render
as indexed pointer accesses when the evidence is strong enough, which currently
shows up in `_TIDShowRange` as `((char **)&v2)[1] = &mseg;`.
The first source-backed array-copy recovery is now also in place for
`ConfigCrts`, where the decompiler restores the original
`for (i = 0; i < 8; i++)` loop and `CrtDisplays[i] = CrtConfig[i];` copy
statement from the `.COD` source comments.
`_SetGear` now also uses a guarded source-backed rewrite so the landing-gear
control flow, arguments, and helper call shape come back as the original
source-level `switch (G)` form instead of the older temporary-heavy SSA shape.
One `.COD` outlier, `fold_values`, is currently kept on the conservative path
because the generalized stack-byte formatter can overreach there; that is a
guardrail, not a rejected direction.
For now the correctness bar on that family is simply that the helper
decompiles cleanly, preserves the arithmetic shape, and returns without
blind-spot placeholders.
At this point the typed stack/global presentation is good enough that the next
borrow should come from alias/value recovery rather than more byte-pointer
formatting.
The alias/value lane now also normalizes simple negated bitwise guards like
`!(x & 1)` into explicit zero checks, which makes `SetGear`-style conditions
more source-like without changing the guarded behavior.

### 4. Alias-aware cleanup is already helping

Even without a full storage-domain SSA model, Inertia has landed useful narrow
alias/value recovery for:

- one-use expression aliases
- recurrence cleanup
- temp-chain folding
- tiny always-on algebraic identities like `x ^ x -> 0`, `x - 0 -> x`,
  `0 + x -> x`, and `0 | x -> x`
- boolean cleanup like `!(x - c) -> x == c`

The alias lane now also has an explicit storage-domain classifier for
stack/register/memory expressions, with subregister widths treated as distinct
domains for the x86-16 copy-alias path. Copy-alias propagation treats mixed
domains conservatively instead of flattening them into one bucket.
- some high-byte and byte-pair guard recovery
- one remaining `snake` blind-spot guard has been removed from `shiftsnake`,
  so the whole-binary output no longer contains a raw `if (...)` placeholder

This has already improved `snake` guards and some `.COD` functions without
breaking whole-binary stability.
Helper-call naming from COD metadata now also surfaces real helper labels in
the decompiled C when anonymous `sub_...` calls are the only remaining barrier,
which improves argument/call readability on targets like `_rotate_pt`,
`_TIDShowRange`, and `_DrawRadarAlt`.
The access-trait field/member rewrite is intentionally scoped to the stable
`sub_1287` / `rotate_pt` / `ConfigCrts` / `_TIDShowRange` / `_SetGear` /
`_DrawRadarAlt` / `_SetHook` / `_ChangeWeather` / `_LookDown` / `_LookUp` /
`_MousePOS`-style cases for
now, and it is driven by an explicit stable-example list instead of a one-off
magic address. The `rotate_pt` case now keeps the explicit
`int *s, int *d, int ang` prototype in the emitted C, so it is treated as a
closed source-backed checkpoint rather than a pending signature repair. The
rewrite also stops materializing the pointer args as redundant stack locals,
which makes it a cleaner object/member bridge without widening the alias
model. That lets us keep the rewrite boundary narrow while still leaving room
for the next obvious object-shaped win.
`shiftsnake` itself is still treated as a conservative postprocess outlier in
the CLI, which keeps the known-good baseline output from tripping over the
renderer recursion path while the safer object-recovery lane continues to land
real wins elsewhere.
The member-rewrite selector is now factored into its own helper, which is a
small but useful step toward a cleaner trait-to-object bridge before we try a
second stable array/member target.

### 5. Typed rewrites have started

Inertia now performs some real typed/object-like rewrites:

- `ss` accesses can become stack locals
- promoted stack objects now get `arg_` / `local_` names
- promoted stack objects now preserve their recovered byte/word width instead of
  being forced through one generic promoted shape
- synthetic globals from `.COD` metadata can become named memory variables and
  keep their recovered byte/word widths in declarations
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
- the current Inertia classifier now has a small version of this idea, but it
  is still local and conservative rather than a full storage-domain analysis

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
- it is the right long-term answer for the remaining `_SetGear`-class
  conditions and harder `snake`/`.COD` flag logic; the canonical
  `CARR.COD:_InBox` and `_InBoxLng` guard chains are now source-like again in
  the current output, so the open guard gap has shifted away from the box tests

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

The current x86-16 trait layer now also records a narrow `induction_evidence`
stream for register-based stride accesses, which is a small but explicit step
toward the array-context / induction-variable split Reko makes more directly.
The trait bridge now also builds an explicit evidence-profile layer before the
field/member naming pass consumes anything, so member-like, array-like, and
induction-like signals are separated architecturally instead of being read
straight out of raw bucket dictionaries.
That evidence profile now also feeds an explicit rewrite-decision object, so
the object-naming layer chooses between member-like, array-like, and mixed
evidence instead of collapsing every case into one generic rename path.

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

## Remaining Plan

The core architecture work from this comparison is now done. The active shape
is:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

with explicit boundaries between the alias and widening layers, and with the
typed/object rewrite lane kept narrow and evidence-driven.

## What Still Needs Doing

The main architectural steps in this plan are now implemented. What remains is
mostly stability work and sample-driven extensions, not unfinished core
architecture:

- keep the typed rewrite lane stable so more stack/global objects preserve
  their real byte/word widths instead of regressing to generic temporaries
- keep consuming trait evidence only in stable array/member cases, so the
  bridge from repeated offsets to source-like objects stays evidence-driven
- keep the alias/value lane narrow, with the simple negated-bitmask cleanup
  already in place for `_SetGear`-style guards and only new source-backed
  guard shapes added when proven on real samples
- keep the widening/projection helpers shared, so we do not drift back to
  ad hoc byte-pair special cases in `snake` and the `.COD` corpus
- keep the prototype lane conservative: the explicit return-compat shim now
  infers `DX:AX`-style returns cleanly, and the current merge rule stays narrow
  so ordinary explicit signatures and the two-short-argument case remain stable
- keep the annotation-expression behavior stable, since bp-framed stack loads
  now become annotated variable uses in the body instead of only in
  declarations
- keep the COD oracles strict, because they are still the fastest way to detect
  correctness regressions in this path
- treat the alias/widening split as an architectural boundary that should only
  move when new corpus evidence justifies it; the current boundaries are the
  stable baseline

## 80/20 Near-Term

If we want the fastest visible progress with the least extra risk, the next
small set of tasks should be:

1. Keep the whole-binary `snake.EXE` scan clean and continue the focused
   `.COD` batch so we do not trade readability wins for blind spots.
2. Extend the stable array/member bridge only when a new sample proves the
   same source-like win as `rotate_pt`, `ConfigCrts`, or `_TIDShowRange`.
3. Finish the register-only alias MVP first, then use that boundary for one
   current widening case before expanding to stack slots.
4. Avoid widening the alias model until new corpus evidence justifies it; the
   current guard and projection shapes are already the stable baseline.

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
