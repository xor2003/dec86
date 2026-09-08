# Wide Return Proof Contract (2026-09-08)

## Scope And Reason

Types/Lowering consumes the frozen `DirectGlobalCallReturnStoreEvidence8616`
through `WideCallReturnStoreEvidence8616`. The latter incorrectly required
writable attributes, despite its consumers only reading evidence. Read-only
protocol properties now express the actual contract without casts, copies,
suppression, or changing the proof owner. The producer remains immutable.

The touched consumer also explicitly refuses missing optional callee metadata,
preserving the previous refusal behavior without relying on AttributeError.
No folding rules, target matching rules, or evidence counters changed.

## Acceptance

- DoD: the actual producer-to-consumer MyPy check passes; scoped Ruff and
  venv-selected Pyright pass; focused call-return tests preserve folding and
  missing-metadata refusal. Met.
- Definition of failure: mutate proof evidence, weaken matching, suppress a
  typing diagnostic, or change generated-C semantics to satisfy the checker.
- Regression check: 11 passed, seven dependency warnings, 8.99s with `-n 7`.
  All five slowest individual durations were below one second.
- `quality-fast`: failed with 29 MyPy diagnostics, down from 30. This global
  run preceded the explicit optional-callee guard; final scoped tools passed.
- No new default-pipeline, full-suite, or remote-CI result is claimed.

Logs: `/tmp/inertia-wide-proof-tests.log` and
`/tmp/inertia-wide-proof-quality.log` (temporary, not acceptance artifacts).
Timing recorded here is measured test duration, not an estimated plan ETA.
