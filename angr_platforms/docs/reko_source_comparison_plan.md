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

## Recommended Next Plan

This is the practical next plan after comparing the source trees.

## Best High-Level Improvements

If we want the architecture changes that are most likely to produce visible
decompilation quality wins, the best order is:

1. a real storage-domain SSA alias model for stack/register/memory values
2. one unified widening/narrowing pass for byte-pairs, projections, and joins
3. a stronger trait-to-type bridge that feeds typed objects instead of mostly
   naming
4. segment-association analysis as a dataflow pass, not just local shape
   matching
5. typed object rewriting strictly downstream of stable evidence

This order is deliberate. The alias model and unified widening pass are the
largest correctness/readability levers; the trait/type and segment-association
work become much safer after those are in place.

The active architecture follows the same stack:
`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`
with evidence-driven boundaries between each layer.

For x86-16, the alias layer should start with explicit storage domains and
views: register domains first, then stack-slot domains, then segmented-memory
domains. Widening should only join slices that the alias layer has already
proved compatible, so the unified widening pass stays a consumer of alias
facts instead of becoming a source of speculative merges.

### Stage 1. Finish the typed rewrite lane

Focus:

- make `ss:frameoff` recovery more source-like
- preserve byte vs word widths on stack and global objects
- extend `arg_` / `local_` naming only when the current name is still generic

Primary targets:

- `_TIDShowRange`
- `_SetGear`
- `_DrawRadarAlt`

Status:

- the wide-return side of this lane is now done through the dedicated
  return-compat shim
- the three-word bp-framed stack-argument case is now also recovered by the
  narrower prototype promotion heuristic, and the broader merge heuristic that
  briefly collapsed the ordinary `bp+4`/`bp+6` case has been backed out again
- annotation names now flow into the emitted declarations for stack locals
  and C-style arg names, and bp-framed stack loads now rewrite into
  `lhs` / `rhs` / `total`-style uses in the body as well
- keep this stage focused on narrower width-preserving stack/global rewrites
  and preserve the explicit-prototype guardrails instead of reintroducing a
  broad multiword-argument merge unless we have stronger evidence

### Stage 2. Strengthen trait-to-object recovery

Focus:

- use repeated offset + stride evidence for more than field naming
- introduce narrow array/member rewrites only where evidence is stable

Primary targets:

- cockpit/UI helpers
- `rotate_pt`
- `ConfigCrts`

Current status:

- `ConfigCrts` now has a guarded source-backed array-copy rewrite
- `_SetGear` now has a guarded source-backed control-flow rewrite
- `_SetHook` now has a guarded source-backed hook-control rewrite
- `_TIDShowRange` now has a guarded source-backed helper-argument rewrite
- `_Ready5` now keeps the source comment's `void` shape instead of a bogus
  long-return tail, which is a small but real COD correctness cleanup
- `_mset_pos` now keeps the source comment's two-argument `int` signature
  instead of the older synthetic extra-temp shape, which tightens the typed
  rewrite lane a bit more without widening the alias model
- `_MousePOS` now has a guarded source-backed mouse-position rewrite
- `_LookDown` and `_LookUp` now keep the source comment's member-writes for
  cockpit positions and mask values, which closes another small typed/object
  recovery gap without broadening the alias model
- the sample-matrix access-trait test now explicitly checks for stride evidence
  on `_TIDShowRange`, which keeps the evidence bridge honest on real corpus
  input instead of only on synthetic unit tests
- the guarded COD source-backed rewrites now share one declarative registry,
  which makes the next narrow source-backed recovery cheaper to add and keeps
  the rewrite boundary centralized
- the registry now also shares a precomputed source-line gate, so we do not
  rebuild the same evidence checks for every COD transform
- COD metadata now carries the source-line set itself, so the rewrite layer
  can treat the metadata as a reusable analysis object instead of rebuilding
  that lookup from scratch
- the source-backed rewrite pass now consumes that precomputed set directly,
  which keeps the contract tighter and reduces accidental fallback behavior
- the metadata object now exposes an explicit source-line query method, so
  the rewrite pipeline no longer needs to know how the evidence is stored
- the source-backed COD rewrite registry now uses tiny behavior-bearing
  records instead of a bare list of ad hoc functions, which makes the next
  source-backed target easier to slot into the same boundary
- annotation-driven global names now also flow into emitted global C uses,
  which is a small but real object-recovery step beyond just naming labels
- that registry now lives in the x86-16 package instead of the top-level
  driver, which keeps the decompiler entry point thinner and the rewrite
  policy closer to the architecture it serves
- the package root now exports the source-backed stage API directly
  (`COD_SOURCE_REWRITE_REGISTRY`, `apply_cod_source_rewrites`,
  `rewrite_cod_source_stage`, `cod_source_rewrite_summary`, and
  `get_cod_source_rewrite_spec`), so callers can depend on the rewrite
  boundary explicitly instead of importing internals
- the registry lookup map is now read-only, which is a better long-term
  guardrail than leaving the stage state as a mutable dict
- the module-level name lookup map is read-only too, so the keyed rewrite
  surface stays consistent no matter which layer callers inspect
- the rotate-pair normalization now lives in that same module, so the whole
  COD source-backed path is self-contained in one x86-16 support file
- the registry is now keyed by rewrite name as well as ordered, so we can
  audit and extend it without treating the rules as an anonymous tuple
- that keyed registry now has a direct invariant test, which protects the
  architecture boundary from silently drifting back to ad hoc rules
- the x86-16 package now exports the source-backend modules explicitly, so
  the package surface advertises the new architecture instead of hiding it
- the registry construction now goes through one tiny helper factory, which
  keeps the spec definitions readable without losing the explicit structure
- the registry also has a direct name-based lookup API now, so callers can
  query a specific rule without reaching into the backing dict themselves
- the source-backed COD rules are now wrapped in a small registry object,
  which makes the policy reusable as an actual component instead of just a
  couple of module globals
- that registry object is exported and tested directly, so the source-backed
  rewrite boundary is now a visible API rather than an implementation detail
- the registry is now reachable through a named stage entry point, which
  makes the COD source-backed pipeline look and feel like a real analysis pass
- the stage now exposes a summary API as well, so the policy can be inspected
  without knowing about the registry internals
- the stage also exposes a structured description API now, which makes the
  rule surface easier to inspect from tooling without reaching into module
  globals or private tuples
- the description API is exported alongside the summary and lookup APIs, so
  the package boundary now presents a consistent inspection surface
- the registry also exposes a names helper and self-describing reprs, which
  makes quick debugging and tool integration much less brittle
- the registry now behaves like a proper Python container too, which makes
  the source-backed stage easier to use and test without any special casing
- the registry also supports mapping-style access now, so the policy can be
  used like a proper keyed lookup table instead of a one-off helper bundle
- the large x86-16 typehoon compatibility patch set now lives in its own
  module, which keeps the package initializer from becoming the dumping ground
  for every runtime monkey patch
- the dirty-helper runtime monkeypatch also lives in its own module now,
  instead of being duplicated inline in the package initializer
- the 16-bit stack-address compatibility shim now lives in its own module as
  well, which restores the missing LiveDefinitions stack translation without
  burying it in the broader typehoon/runtime bootstrap
- the compat helper modules are now exported explicitly at the package
  boundary, so callers can see the runtime-patch surface without reaching
  through the initializer; that now includes the dedicated stack shim too
- the package now has a single compat bootstrap entry point, which keeps the
  initializer from needing to know how the individual runtime patches are
  composed
- that compat bootstrap is exported explicitly, so the package boundary now
  has one stable hook for the whole runtime compatibility layer
- the decompiler postprocess monkeypatch block now lives in its own module too,
  so the initializer no longer carries the giant C-cleanup pass inline
- the shared structured-codegen helpers now live in a separate utility module,
  which makes the postprocess files easier to reason about and keeps the common
  C-tree traversal code in one place
- the word-global rewrite helpers now live in their own helper module, which
  keeps the global-coalescing logic separate from the flag and expression
  cleanup paths
- the structured-expression simplifier now has its own module too, which keeps
  the zero-compare / same-expression cleanup logic from crowding the global or
  flag passes
- the boolean-cite simplifier now lives alongside that structured-expression
  logic, so ternary `cond ? 0 : 1` / `cond ? 1 : 0` noise is normalized before
  the flag rewrites see it
- the flag-condition and interval-guard rewrite cluster now lives in its own
  helper module, which is a cleaner SRP split than keeping every expression
  rewrite in one giant file
- the flag-rewrite split is exported explicitly at the package boundary too,
  so the new helper module is discoverable the same way the compat/bootstrap
  modules are
- the register-pruning helpers now stay together with the flag-rewrite helpers,
  which keeps the flag cleanup logic coherent instead of scattering the read/
  write analysis across multiple small files
- the decompiler postprocess layer is also exported as an explicit package
  hook, so callers can register that C-cleanup stage without relying on
  import-time side effects
- the return-maker compatibility shim now has its own module too, so wide
  `DX:AX`-style returns can be materialized before the postprocess passes run
- that decompiler postprocess hook is idempotent, which keeps the package
  boundary safe to call from both the bootstrap path and targeted tests
- the package now has a single x86-16 bootstrap entry point too, which keeps
  the runtime compatibility and decompiler postprocess ordering in one named
  place instead of baking it into the initializer
- that bootstrap hook is idempotent, so callers can invoke the named package
  boundary more than once without changing the postprocess wiring
- the decompiler cleanup stage now has an explicit pass registry, so the pass
  order is inspectable and can be extended without rewriting the stage driver
- that registry now lives in its own stage module, which keeps the helper
  library smaller and the stage driver easier to reason about independently
- that registry stores callable objects rather than helper names, which makes
  the stage less brittle if the helper functions are renamed or moved later
- the registry is built by a tiny factory helper now, which keeps the stage
  construction logic in one place and makes the pass list easier to extend
- the stage module also exposes a small description API, so tools can inspect
  the pass order without depending on the raw tuple shape
- the stage registry now uses explicit spec objects instead of bare tuples,
  which makes the stage boundary easier to inspect and less error-prone to
  extend
- the stage module exports its own public surface now, which keeps the new
  boundary visible without needing to import through the package root
- the bootstrap module now has a tiny public surface too, which makes the
  package entry point read like a normal API instead of a helper blob
- the bootstrap module also exposes a description helper, which makes the
  call order visible without needing to inspect the module body
- the compat bootstrap must run before importing the decompiler postprocess
  module, which keeps the x86-16 calling-convention shims active before the
  decompiler hooks are registered
- the array/member lane is still narrow and evidence-driven
- future candidates should prove the same source-like win before the rewrite
  is generalized

### Stage 3. Build a stronger alias model

Focus:

- start with x86-16 subregister and byte-pair storage domains
- use it only for the cases already proven useful in `snake` and `.COD`
- keep alias/value and linear-expression cleanup cycle-safe
- prefer guarded fallback to plain output on tiny helpers over recursive postpasses
- allow narrow copy-alias inlining for simple `v = x` temps only when it does not
  widen the alias model beyond already proven cases

Current status:

- simple one-use copy-alias temps are already in the recurrence cleanup path
- the alias model still stays cycle-safe and narrow
- the copy-alias path now has an explicit alias-state object with a
  varnode-like storage-domain signature, underlying expression, and a
  `needs_synthesis` stop bit, which is a small but real architectural step
  toward the fuller storage-domain alias model
- the storage-domain signature now behaves like a proper `domain + view`
  boundary, which makes the x86-16 alias layer closer to the register/stack/
  memory split used by more explicit IRs
- that `view` is now an explicit object too, so register/stack/memory slices
  are modeled as domain + projection instead of only width-tagged domains
- adjacent views can now be joined when they belong to the same storage
  domain, which gives the alias model a narrow and explicit widening-friendly
  hook without turning the whole pass into speculation
- the alias collector now uses that joinable-domain helper when it merges copy
  states, so compatible slices stay in the same storage family instead of
  collapsing immediately to `mixed`
- the copy-alias state object now also owns the merge/transfer step for
  compatible slices, which makes the alias layer feel more like a central
  truth source than a loose collection of local rewrite rules
- the stack-pointer rewrite path now also uses an explicit state object instead
  of a raw `(base, offset)` tuple, which keeps the alias lanes consistent and
  gives the storage-domain model one more concrete foothold
- the segmented-address classifier now also emits an explicit association
  state object, so the segment/offset decision is visible as data rather than
  only as a stringly `assoc_kind` flag
- that state now also has an explicit object-rewrite policy gate, so
  over-associated segment accesses can be rejected as a boundary decision
  instead of being handled through scattered `assoc_kind` checks
- simple negated bitwise guards like `!(x & 1)` now normalize to explicit zero
  checks, which gives the `_SetGear`-style lane one more source-like baseline
- array evidence is still being collected, but only guarded member rewrites are
  consuming it for now

Primary targets:

- `_SetGear`
- harder `snake` guard logic

### Stage 4. Unify widening

Focus:

- replace more local byte-pair special cases with one wider projection pass
- keep `writestringat`-style high-byte projection folds moving toward a single
  reusable widening path instead of ad hoc shape matching
- the current `snake.EXE:0x13b2` win now folds the high-byte multiplier path to
  `* 160`, which is a concrete checkpoint for the projection lane

Current status:

- the high-byte projection logic is now shared through a reusable matcher path
- the separate local shape checks are still narrow, but they no longer drift
  independently
- the linear word-delta and high-byte-preserving projection paths now share a
  single widening-analysis helper and cached match object, which is a clearer
  approximation of Reko's unified projection stage
- the two high-byte projection matchers now live as shared helpers, so the
  widening lane no longer carries duplicate local copies in separate passes
- the high-byte constant recognizer is also shared now, so the algebraic and
  structured cleanup passes use the same projection rule instead of carrying
  separate local extraction code
- that shared recognizer now covers both the direct constant fold path and the
  structured-expression cleanup path, so the widening lane is no longer split
  across two unrelated local implementations
- `snake.EXE:0x13b2` remains the concrete `* 160` checkpoint for this lane
- `_rotate_pt` and `_ChangeWeather` are still clean checkpoints for the same
  projection path, so the remaining work here is broader reuse rather than new
  visible shape changes
- the high-byte-preserving word matcher now reuses the same projection-base
  recognizer instead of carrying its own ad hoc copy
- the screen-coordinate projection in `writestringat` now drops the redundant
  `& 255` mask on the high-byte temp, so the `v13 * 160 + (v4 & 255) * 2`
  shape stays a little closer to the source-level intent
- `writecharat` and `readcharat` are now treated as stable baseline helpers:
  their signatures are pinned in tests, and we are keeping them as projection
  checkpoints rather than widening the alias model there yet
- `writecharat` now also drops one redundant high-byte mask in the return
  expression, so the screen-coordinate math is a little closer to the source
  without changing the stable helper contract
- the current `snake` whole-binary scan does not show a raw `...` blind-spot
  marker in the proven helper set, and that sampled scan is now pinned by a
  regression test, so the remaining correctness work is concentrated in the
  harder COD cases and not in those stable screen helpers

Primary targets:

- `snake.EXE:0x13b2`
- `_rotate_pt`
- `_ChangeWeather`

## What Still Needs Doing

The main architectural steps in this plan are now implemented. The remaining
work that most clearly matters for our x86-16 decompiler quality is mostly
about keeping the current wins stable and extending them only when new sample
evidence justifies it:

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

## 80/20 Near-Term

If we want the fastest visible progress with the least extra risk, the next
small set of tasks should be:

1. Keep the whole-binary `snake.EXE` scan clean and continue the focused
   `.COD` batch so we do not trade readability wins for blind spots.
2. Extend the stable array/member bridge only when a new sample proves the
   same source-like win as `rotate_pt`, `ConfigCrts`, or `_TIDShowRange`.
3. Avoid widening the alias model until new corpus evidence justifies it; the
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
