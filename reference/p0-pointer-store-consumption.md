# Pointer-Store Consumption Safety

## Scope and Reason

The Types/Lowering pointer-store fold previously checked carrier uses only in
later statements of the same sequence. Removing its setup could therefore lose
a value used by an outer block, sibling, loop condition, or overlapping byte
register. Counting unique AST nodes also misses repeated edges to shared nodes.
Replacing the carrier with its source is unsafe if that source changes first.

The authoritative guard is `lowering/pointer_store_consumption.py`. It consumes
the existing physical-register and typed store evidence. It does not recover
storage identity, introduce semantics in Rewrite, or use rendered text.

## Definition of Done

- Require whole-function occurrence evidence before deleting a carrier setup.
- Include overlapping physical register bytes and repeated AST edges.
- Refuse source changes, opaque intervening effects, cycles, and incomplete
  placement. Unconsumed register occurrences forbid setup deletion. An
  independently proven store projection may proceed while retaining setup.
- Publish a typed verdict with closed evidence counters. The materialized
  counter describes the guard decision, not an assertion that mutation occurred.
- Keep a positive uniquely consumed nested projection working.
- Pass focused positive/refusal tests, scoped Ruff and typing, architecture
  enrollment, and the mandatory compile/decompile/recompile/execute pipeline.

## Definition of Failure

Deleting a live carrier, accepting incomplete evidence, hiding validation
failures, weakening architecture gates, or repairing output text instead of
the owning Lowering proof is a failure. A narrower test pass does not close P0.

## Verification Checkpoint: 2026-09-07

- Fail-before tests: 8 failed and 5 passed.
- Final pointer-store and segmented-runtime surface: 260 passed in 21.87s.
- Intermediate live DOS wrapper regression and focused surface: 14 passed;
  the wrapper checks validation, store semantics, and strict recompilation.
- Final live DOS wrapper rerun: 1 passed in 33.99s, with the same validation
  and strict recompilation assertions enabled.
- Scoped Ruff `check --fix`, MyPy, and type ratchet passed.
- Architecture check passed after explicitly enrolling the proof module and
  restoring omitted typed-module and regression-test inventory entries.
- Mandatory `test-pipeline` exited zero: 2,004 pytest cases passed, followed by
  the configured external executable gates.
- `quality-dev` exited zero: 2,004 pytest cases passed in 126.32s, the external
  executable case passed, and CMP16, LOOPS, and FPTR optimization parity guards
  passed. Their baseline/candidate import surfaces were identical; those
  checks are not independent evidence of a performance improvement.

This is not a speedup claim. The guard conservatively retains code for physical
register reuse that would require a separate liveness/dominance proof.

The follow-up in [logical-memory width](p0-logical-memory-width.md) separates
`PROVEN_SOURCE_PRESERVED` from `PROVEN_CONSUMED`. The first permits only the
already-proven store's value substitution; `.complete` remains false and setup
must survive. Only complete whole-function consumption permits setup deletion.
Tests preserve outer/sibling/loop-condition/byte-alias uses, shared AST edges,
and independent same-register setups with distinct pointer arguments.

The concurrent full diagnostic audit reported 10,116 passed, 62 failed, and 170
skipped. Source mutations and CPU contention invalidate it as a stable acceptance
or performance baseline. Global MyPy reported 164 error lines, not 164 proven
independent causes. Neither result is superseded by the focused green checks.

## Next Acceptance Work

Reproduce failures by shared owner on stable source. Prioritize semantic call,
storage, return, and condition loss;
repair stale fixture contracts without deleting their behavioral assertions.
Run the complete suite again before claiming P0 closure. Performance Step 10
still requires fresh controlled measurements and must not repeat rejected
experiments without new evidence.

Timing: focused development and verification occurred on 2026-09-07. Exact
engineering start/end timestamps were not captured; test wall times above must
not be presented as engineering duration or a full-plan finish estimate.
