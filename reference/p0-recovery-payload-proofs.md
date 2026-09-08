# Recovered Payload Proof Publication

## Root Cause And Layer

The direct CLI accepted regenerated binary-evidence C or a recovered partial
payload, then replaced the worker payload without replacing its validation
and compiler hashes. The immutable result therefore combined new C with old
proof identity. The final integrity checker correctly refused that record.

Both promotion branches in `cli_core.py` now copy the two hashes from the same
acceptance result that supplies `gcc_checked_payload`. This is CLI reporting
and accepted-result transport, not semantic recovery. No validation condition,
fingerprint, compiler gate, or integrity rejection was weakened.

The signed-long CMP32 diagnostic's initial condition-signedness delta is not
normalized away by this repair. Its separately accepted recovery must supply
the output and its own proofs coherently.

## Acceptance

Reason: one accepted artifact must retain matching payload and proof identity
through fallback promotion and final emission.

DoD: both promotion branches replace hashes with the accepted payload, stale
payload substitutions remain rejected, and the real sidecar-free signed-long
comparison validates and recompiles with its required signed comparisons and
return cases intact.

Definition of failure: marking a candidate successful using another payload's
hashes; recomputing hashes without validation/compiler acceptance; bypassing
integrity checks; losing comparison calls, branches or return values.

## Focused Evidence And Timing

2026-09-08, local UTC+02:00; intervals are log creation to final update:

| Check | Start | End | Pytest time | Result |
| --- | --- | --- | ---: | --- |
| Signed-long regression before | 10:24:47 | 10:24:59 | 11.00s | 1 failed |
| CMP32 corpus + integrity tests after | 10:25:26 | 10:25:58 | 31.96s | 16 passed |
| Both promotion expressions + integrity guards | 10:26:20 | 10:26:30 | 9.24s | 10 passed |

The focused corpus covers signed/unsigned comparisons, max selection and clamp
returns; its assertions require successful CLI acceptance, clean whole-tail
validation, strict recompilation, scalar signatures and preserved branches.
The two promotion tests execute the actual nested `replace` expressions over
immutable work results, covering the binary-evidence and partial-payload paths.

Scoped Ruff `check --fix`, MyPy and Pyright pass for `cli_core.py`. The integrity
file was also added to the default pipeline (it was already in QA). Broad gates
are recorded when terminal, not inferred from focused acceptance.

Logs: `/tmp/inertia-cmp32-acceptance-before.log`,
`/tmp/inertia-cmp32-acceptance-after.log`,
`/tmp/inertia-cmp32-promotion-tests.log`,
`/tmp/inertia-recovery-proof-quality.log`,
`/tmp/inertia-recovery-proof-pipeline.log`.

## Broad Gates

Default pipeline passed all three lanes: 2,269 unit tests in 155.82s and all
seven MS C tiny compile/run/decompile/recompile/run cases. This run started
before the integrity file was added to the default target list; its ten tests
passed separately above. The inventory update passed 50 tests in 4.81s.
Global quality-fast remains red with 116 MyPy diagnostic lines. The full
10,569-test census was not repeated; its 48 failures remain the recorded audit,
with this specific comparison failure now repaired under focused verification.

## Remaining Direct Promotions

An AST-directed audit of accepted-payload substitutions in the direct CLI
found four more transitions retaining old hashes: helper-model promotion,
robust retry, retry normalization, and late partial recovery. The parameterized
regression now executes all six direct promotion expressions. Before the
follow-up, four cases failed and ten passed in 11.09s. Each affected transition
now copies both hashes from its acceptance result with the accepted payload.

Afterward, all 22 combined integrity and CMP32 corpus tests pass in 34.19s.
Scoped Ruff `check --fix`, MyPy and Pyright pass. The default pipeline and
global quality gate were not repeated for this bookkeeping-only follow-up;
their preceding results above are not represented as fresh whole-tree results.
No proof is synthesized from unvalidated C and the final refusal guard remains
unchanged. This closes the six tested direct promotion paths, not every possible
cache/worker transport path or the full decompiler goal.

Evidence: `/tmp/inertia-recovery-proof-all-before.log` and
`/tmp/inertia-recovery-proof-all-after.log`.
