# Pointer-Parameter Output Pipeline

Semantics owns each exact direct STORE and each versioned indirect STORE site,
segmented relative range, and terminal-path disposition. An indirect STORE in
the same segment neither disproves an independently proven direct STORE nor
proves that the two effects are disjoint. Semantics must retain the direct fact;
Alias and interprocedural Lowering own the relationship between the effects.
Alias may bind an indirect base only when every STORE site resolves to one exact
positive-BP parameter source. Competing or unknown sources refuse atomically.

Widening joins touching or overlapping lanes only when parameter ownership,
segment, and terminal-path coverage agree. Gaps and adjacent lanes with
different coverage remain separate views; overlapping incompatible coverage
refuses. Adjacency does not prove a pointee type, array, struct, or extent.

Types/Lowering maps each view to one exact logical callee input and publishes
that contract before legacy input collection.
IR now traces a call argument's 16-bit near-offset arithmetic as an exact
modular affine expression with stack-source ranges, coefficients, and SSA
definition paths. Types/Lowering cross-checks that proof against the structured
callsite source and retains the physical outgoing byte definitions. The offset
expression alone has no segment or pointee width.

The caller-target Lowering publisher separately joins that exact near-offset
expression with the callee output view's proven segment, relative offset, and
width for every direct callsite. Publication is all-or-nothing per callee;
missing expression provenance, carry-dependent arithmetic, target or width
conflicts, unmatched parameter storage, incomplete callsite census, and
publication conflicts remain typed refusals. The published target is evidence
for later object/effect materialization, not a pointee-type decision. A dynamic
target must not be misrepresented as an exact direct
`StorageIdentity8616.MEMORY`.

The interprocedural storage collector partitions those targets by exact
caller/callsite and retains them as `pointer_effects` alongside, but distinct
from, direct Alias-owned memory effects. Types/Lowering groups all views for one
callee output source into a `PointerParameterMemoryOutputObject8616`. The
accepted function contract carries those objects and their original effects;
it does not fabricate scalar `LIVE_OUT` trials for dynamic targets. Atomic
publication revalidates every source, view, callsite identity, and retained
effect and rejects duplicate, missing, conflicting, or orphaned projections.

Rendered C, assembly text, names, sidecars, and postprocess output are never
evidence for this pipeline.
