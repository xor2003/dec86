# Global Plan

## Global mission

Build a decompiler that is:

- evidence-driven
- correctness-first
- honest under uncertainty
- recompilable where practical
- especially strong on x86 real-mode segmented binaries

## Phase 0. Observability and honest corpus accounting

Goal:

- Know exactly where the pipeline is correct, uncertain, or missing results.

Tasks:

- Finish the full no-skip COD sweep.
- Preserve `uncollected` identities.
- Ensure summaries and detail artifacts agree.
- Group changed cases into named families.

Deliverables:

- one reproducible full-corpus artifact
- one reproducible console summary
- a named family list of remaining deltas

Definition of done:

- Every PROC in the target corpus is accounted for as `passed`, `changed`, `unknown`, or `uncollected`.
- No silent drops remain in the reporting path.

## Phase 1. Tail-validation quality and localization

Goal:

- Make validation results actionable, not just alarming.

Tasks:

- Improve aggregate detail so changed families are easy to cluster.
- Add focused explanations for:
  - helper call delta
  - live-out register delta
  - segmented/global write delta
  - control-flow/guard delta
- Ensure validation can point to the likely responsible late pass or family.

Deliverables:

- better diff surfacing
- test cases for every major delta kind
- family-level issue reports

Definition of done:

- For each changed family, the report says what changed in observable semantics and why it is probably one family rather than many unrelated issues.

## Phase 2. Fix family A: DS global / segmented-write alias mismatch

Goal:

- Resolve the DS-global-vs-segmented-write family at the earliest correct layer.

Tasks:

- Investigate whether validator snapshot naming is too strict or postprocess really changes semantic storage identity.
- Compare representative members:
  - `COCKPIT.COD:_DoCRT`
  - `NHORZ.COD:_DrawAAA`
  - `PLANES3.COD:_DoOClockCall`
  - `PLANES3.COD:_Ready5`
  - `PLANES3.COD:_SARWait`
- Decide whether the issue belongs in:
  - alias normalization
  - validator canonicalization
  - late-pass semantic repair only if a real bug exists there
- Add a focused regression test covering the exact family.

Deliverables:

- one root-cause fix
- one regression test family
- reduced changed set on the affected corpus subset

Definition of done:

- The named family disappears from the affected corpus subset.
- The fix is not sample-specific.
- The regression test proves the family stays fixed.

## Phase 3. Fix family B: `_DisplayMaster` condition/control-flow delta

Goal:

- Determine whether `_DisplayMaster` belongs to family A or a distinct compare/flag normalization defect.

Tasks:

- Localize the exact semantic change:
  - segmented DS-word compare
  - rewritten `global:0x7000` compare
  - matching control-flow delta
- Check whether fixing family A removes this case automatically.
- If not, isolate it as a separate issue in:
  - compare normalization
  - flags handling
  - control-flow postprocess

Deliverables:

- either closure through family A
- or a dedicated family-B fix and regression

Definition of done:

- `_DisplayMaster` is no longer ambiguous.
- It is either fixed by the common alias solution or by a targeted, test-backed dedicated fix.

## Phase 4. Alias model hardening

Goal:

- Make storage identity the stable foundation for the whole pipeline.

Scope:

- registers and subregisters
- stack slots
- segmented memory spaces
- stable storage identity across late transformations

Tasks:

- Strengthen storage-domain representation.
- Ensure `DS`, `SS`, and `ES` remain distinct by default.
- Allow canonicalization only when association is actually proven.
- Ensure widening eligibility depends on alias compatibility.
- Add tests for:
  - allowed joins
  - forbidden joins
  - stable segmented/global equivalence when proven
  - non-equivalence when not proven

Deliverables:

- stronger alias invariants
- unit tests for storage identity
- corpus improvement on known DS/global mismatch families

Definition of done:

- Storage identity is decided by the alias model, not inferred later from expression shape.
- Known misjoins and false canonicalizations no longer occur.

## Phase 4.5. Reasoning IR maturation

Goal:

- Make Inertia-owned typed IR the semantic substrate for alias, widening, and
  control-flow reasoning while keeping `angr` as frontend infrastructure.

Tasks:

- split `Value` vs `Address` in the x86-16 IR layer
- keep segment identity on typed addresses rather than generic values
- model address bases as tuples/expressions rather than single-name heuristics only
- model branch meaning as typed conditions instead of raw lifted flag temporaries
- move at least one real downstream consumer from generic IR summaries to typed
  address/condition artifacts

Deliverables:

- typed `Address` objects with explicit segment space and width
- typed condition artifacts for control-flow reasoning
- one bounded downstream consumer that uses those artifacts

Definition of done:

- memory and control-flow reasoning no longer depend on generic values plus
  heuristics alone
- at least one real alias or structuring decision is expressed in terms of
  typed address/condition IR

## Phase 5. Widening correctness

Goal:

- Ensure widening is evidence-based and alias-gated.

Tasks:

- Audit current adjacent-slice joins.
- Remove or block shape-only joins.
- Require alias compatibility before widening.
- Add unit tests for:
  - register slices
  - stack slices
  - segmented memory slices
  - forbidden “looks adjacent so merge it” cases

Deliverables:

- widened storage only where alias proof exists
- a test matrix of allowed and forbidden joins

Definition of done:

- No widening rule survives that depends only on final expression shape.
- Widening cannot manufacture false object-like structure.

## Phase 6. Segmented-memory model maturation

Goal:

- Make real-mode segmented memory a first-class model rather than a late rewrite problem.

Tasks:

- Keep `ss`, `ds`, and `es` distinct in analysis and validation.
- Track association strength explicitly.
- Separate:
  - stable association
  - over-associated guesses
  - unknown association
- Lower to object/pointer form only after evidence is strong.

Deliverables:

- better segmented snapshot canonicalization
- more stable pointer/object lowering
- fewer validator deltas caused by premature flattening

Definition of done:

- Segmented memory is not flattened for convenience.
- Pointer lowering happens only under strong evidence.
- Corpus cases involving segmented writes become more stable.

## Phase 7. Traits -> types -> objects

Goal:

- Move from raw evidence to stable types and object recovery without guessing.

Tasks:

- Keep traits as annotations and classifiers only.
- Build stable evidence profiles before type decisions.
- Introduce object/type recovery only from stable evidence.
- Add tests for:
  - conservative typing
  - delayed object creation
  - no speculative struct invention

Deliverables:

- clearer separation between observed facts and inferred object model
- more readable but still honest C

Definition of done:

- Types and objects are downstream consequences of evidence, not speculative conveniences.
- Structs, arrays, and pointers are not invented merely to make output look pretty.

## Phase 8. Readability improvements after correctness

Goal:

- Improve human readability without changing semantics.

Tasks:

- Keep late rewrite limited to:
  - algebraic cleanup
  - boolean cleanup
  - declaration cleanup
  - naming polish
  - structured C cleanup
- Reject correctness-bearing fixes at this stage.
- Add focused readability tests that do not alter semantic snapshots.

Deliverables:

- nicer generated C
- no semantic regressions caused by readability passes

Definition of done:

- Every late rewrite is provably non-semantic according to validation or by construction.
- Readability gains do not mask architectural debt.

## Phase 9. Corpus-first scaling and robustness

Goal:

- Make the decompiler robust across a broad real corpus, not just famous samples.

Tasks:

- Re-run the full corpus after each nontrivial fix.
- Track:
  - crashes
  - timeouts
  - fallback rates
  - changed-family shrinkage
- Preserve scan-safe behavior.
- Keep experimental beautification out of the default scan-safe lane.

Deliverables:

- trendable corpus metrics
- shrinking explicit exception list
- stable scan-safe defaults

Definition of done:

- Each architectural fix is validated against the corpus.
- Remaining failures are explicit, named, and test-backed.

## Phase 10. Dream decompiler milestone

Goal:

- Reach the point where the project is clearly beyond “interesting prototype” and into “serious decompiler with a unique architecture.”

Required properties:

- automatic function discovery works broadly without debug info
- late-pipeline validation catches semantic drift
- segmented real-mode handling is a genuine strength
- output is evidence-driven and recompilable where practical
- remaining exceptions are narrow, explicit, and justified

Final definition of done:

- the full corpus sweep is reproducible and honest
- changed families are few, explicit, and shrinking
- no major alias or widening mistakes remain in the known corpus
- segmented-memory handling is architectural rather than heuristic
- readable C is produced without speculative semantics
- the demo can truthfully show automatic recovery, attempted decompilation, and validation-backed honesty
