# Reko Reuse Notes For Inertia

This note captures useful ideas from the local `reko/` tree that are relevant to Inertia's current x86-16 decompiler blockers.

It is intentionally focused on:

- segmented memory recovery
- stack/global recovery
- byte-pair to word recovery
- alias-aware SSA
- typed expression rewriting

It is not a proposal to copy Reko code directly.

## Licensing note

The local `reko/` tree is GPL-licensed (`reko/COPYING`).

That means:

- algorithmic ideas, test shapes, and high-level designs are safe inspiration
- direct code copying or close ports need a separate license review

For Inertia, the safest path is to reuse the ideas and rebuild them in the angr/x86-16 pipeline.

## Most useful ideas

## 1. Treat segment+offset as a first-class value

Best reference:

- `reko/doc/dev/projection.md`
- `reko/src/Decompiler/Analysis/ProjectionPropagator.cs`
- `reko/src/Decompiler/Analysis/SegmentedAccessClassifier.cs`

Relevant idea:

- do not "zero out" segments
- carry `(segment, offset)` as a meaningful composite value
- only fuse it into a pointer-like object when the segment is stably associated with one offset source

Why this matters for Inertia:

- our current `v6 * 16 + off` forms are too low-level for recompilable C
- blindly flattening segments would break correctness for `ds:xx` vs `ss:xx`
- Reko's model matches what we need: preserve segment semantics first, then simplify when safe

Immediate Inertia translation:

- add a segmented-access classifier for x86-16 AIL/C-tree expressions
- classify accesses as:
  - stack-like: `ss + off`
  - data/global-like: `ds + off`
  - separate space: `es + off`
- only collapse to locals/globals/member-pointers after that classification

## 2. Projection propagation for `SEQ` / `SLICE`

Best reference:

- `reko/doc/dev/projection.md`
- `reko/src/Decompiler/Analysis/ProjectionPropagator.cs`
- `reko/src/UnitTests/Decompiler/Analysis/ProjectionPropagatorTests.cs`

Relevant idea:

- if two pieces provably come from the same wider value, rebuild the wider value
- push the widened value both upward and downward through SSA when safe

This directly matches several Inertia pain points:

- byte-pair loads becoming `low | high * 0x100`
- byte-pair stores emitted as two separate writes
- register-pair or segment-register slices polluting conditions and addressing

Immediate Inertia translation:

- add a small x86-16 "widen paired slices" pass before final codegen
- support these narrow patterns first:
  - adjacent byte loads from same base -> word load
  - adjacent byte stores to same base -> word store
  - `segment` + `offset` slices from same origin -> segmented pointer value

This is already partly what we have been doing manually in `decompile.py`, but Reko suggests the right generalization: make it a dataflow-backed widening pass, not a bag of local rewrites.

## 3. Alias-aware SSA by storage domain

Best reference:

- `reko/doc/dev/ssa-aliasing.md`

Relevant idea:

- reason about values using storage domains, not just register names
- synthesize alias assignments only when needed
- allow partial-register and register-pair reconstruction without turning every use into noise

Why this matters for Inertia:

- many of our x86-16 correctness issues are really alias issues:
  - `ah/al`, `bh/bl`, `ax/eax`-style patterns in translated form
  - flags broken into temporary pieces
  - `es:bx`, `dx:ax`, stack-slot byte pairs

Immediate Inertia translation:

- do not copy Reko's SSA framework
- do borrow the concept of a storage-domain map for:
  - x86 subregisters
  - flag groups / individual flags
  - word values reconstructed from byte defs

This is likely the most useful long-term idea for reducing both wrong conditions and `...` artifacts.

## 4. Typed address-trait collection

Best reference:

- `reko/src/Decompiler/Typing/AddressTraitCollector.cs`
- `reko/src/Decompiler/Typing/DataTypeBuilder.cs`
- `reko/src/UnitTests/Fragments/RepeatedLoadsFragment.cs`

Relevant idea:

- infer structure/array/member evidence from address expressions
- treat `base + const`, `base + i * stride`, repeated loads, and induction-variable forms as type evidence

Why this matters for Inertia:

- today we often stop at "cleaner pointer math"
- for recompilable C, we need the next step:
  - globals
  - locals
  - arrays
  - struct fields

Immediate Inertia translation:

- once `ds` / `ss` accesses are normalized, collect offset usage evidence:
  - repeated `base + const`
  - repeated `base + index * stride + const`
  - grouped low/high byte accesses to same location
- feed that into name/type recovery:
  - `word16` field
  - `byte` field
  - array element size
  - simple struct layout candidates

This looks especially promising for `.COD` examples like `_TIDShowRange`, `_rotate_pt`, `_MousePOS`, and cockpit UI helpers.

## 5. Typed rewrite from segment constants to named segment objects

Best reference:

- `reko/src/Decompiler/Typing/TypedConstantRewriter.cs`
- `reko/src/tests/Typing/TerSegmentedMemoryPointer.exp`
- `reko/src/tests/Typing/TerSegMem3.exp`

Relevant idea:

- once segment selectors are typed, rewrite constants and accesses into named segment/global objects
- examples in Reko move from:
  - `Mem0[0x800:0x5420:word16]`
  - to `0x800<16>->w5420`
  - or `cs->w1234`

Why this matters for Inertia:

- this is the missing bridge between our current "correct low-level memory expression" and source-like C
- we already have synthetic globals from `.COD`
- we can push them one step further into typed global/member access

Immediate Inertia translation:

- after segmented classification, rewrite:
  - `ds:const` -> named global
  - `ss:frameoff` -> local/arg
  - `seg:const` for literal segment selectors -> segment-owned object/table

## Best concrete things to borrow

These are the highest-value things to copy as ideas, not code:

1. `projection.md` as the design model for widening paired values.
2. `ssa-aliasing.md` as the design model for x86 alias correctness.
3. `SegmentedAccessClassifier` as the design model for "simplify only when segment association is stable".
4. `AddressTraitCollector` as the design model for turning pointer math into field/array evidence.
5. The expected-output tests under:
   - `reko/src/tests/Typing/TerSegmentedMemoryPointer.exp`
   - `reko/src/tests/Typing/TerSegMem3.exp`
   - `reko/src/tests/Typing/TtranRepeatedLoads.exp`

Those tests are especially useful because they describe the shape we want, independent of Reko's internal implementation.

## What not to reuse directly

## 1. Do not copy code directly

Reason:

- GPL licensing
- deep mismatch with angr internals

## 2. Do not copy the entire type system architecture

Reason:

- Reko's typing pipeline is rich but tightly integrated
- porting it wholesale would likely become a second decompiler project inside Inertia

## 3. Do not force all x86-16 memory into a generic far-pointer model

Reason:

- for our corpus, `ss`, `ds`, and `es` often play clearly different roles
- collapsing them too early would hurt correctness

## Recommended order for Inertia

## Stage 1. Add a segment-space classifier

Goal:

- reliably distinguish `ss`, `ds`, and `es` memory classes in recovered expressions

Expected payoff:

- fewer raw `seg * 16 + off` expressions
- safer local/global rewrites

## Stage 2. Add a projection-style widening pass

Goal:

- fold adjacent byte pairs into word loads/stores
- fold split segment/offset uses into one pointer-like value

Expected payoff:

- less byte scaffolding
- fewer useless temporaries
- better chances of removing `...`

## Stage 3. Add address-trait collection

Goal:

- infer field offsets and array shapes from normalized memory expressions

Expected payoff:

- move from "clean pointer math" to "member access"

## Stage 4. Use `.COD` metadata only as a naming/type hint layer

Goal:

- once the memory object is structurally correct, attach the source name

Expected payoff:

- source-like globals and locals without text patching

## Best near-term experiments

If we want to test these ideas quickly on current blockers, the best targets are:

- `cod/f14/COCKPIT.COD --proc _TIDShowRange`
  - good for stack-slot byte-pair and table/field recovery
- `cod/f14/BILLASM.COD --proc _rotate_pt`
  - good for segmented table loads and word-load widening
- `cod/f14/BILLASM.COD --proc _MousePOS`
  - good for `ds` globals vs `ss` locals
- `examples/snake.EXE --addr 0x13b2`
  - good for reducing residual low-level address math in a non-COD real EXE example

## Bottom line

The most reusable parts of Reko for Inertia are:

- the idea of segment-aware pointer recovery
- projection propagation for widened values
- alias-aware SSA concepts
- address-based type evidence collection
- expected output shapes from their segmented typing tests

The least reusable part is the code itself.

For Inertia, the right move is to reproduce those ideas inside the angr/x86-16 recovery path, not to import or mimic Reko mechanically.
