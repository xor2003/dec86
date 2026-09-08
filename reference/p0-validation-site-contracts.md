# Validation Site Contracts (2026-09-08)

## Scope

Close optional-value typing gaps without weakening validation or inferring
missing instruction provenance. This is IR/Validation work, not Rewrite
recovery or an InitBars acceptance claim.

## Repair

The logical-reload condition proof compared optional instruction addresses
without proving they existed. New variants of the existing stable-path
regression reproduced two `TypeError` failures: a missing condition source
address and an unlocated instruction in the condition block.

Validation now refuses that alternative fingerprint when the condition block
or source instruction is absent, or when ordering an instruction in the
condition block cannot be established. Named register operands are narrowed
locally. Known, dominating reloads still produce the same fingerprint; no
missing address is guessed and no branch is deleted.

The module also imports the return-use enum from its authoritative contract
owner and carries checked `SimStackVariable` objects directly out of its
filter instead of relying on a later attribute access to recover narrowing.
No cast or suppression was added.

IR call-memory liveness now explicitly excludes a `None` range key before
indexing the typed range map. This makes an existing exclusion visible to the
type checker; it does not introduce DCE or alter call-clobber propagation.
The existing tests retain both complete-store lifetime recovery and refusal
when calls can reach a load through branches or loop backedges.

- Reason: optional provenance cannot support an instruction-order proof, and
  checked owned contracts should remain typed at their consumers.
- DoD: reproduce missing-site crashes, refuse incomplete reload proof, preserve
  the known-site projection and call-clobber refusal cases, pass focused tests
  and scoped tools, and record global quality plus default pipeline outcomes.
- Definition of failure: invented addresses, accepted unproven fingerprints,
  relaxed validation, suppressed type errors, or calling this full-function
  semantic acceptance.

## Evidence

Before: 2 failed, 20 passed in 12.90s. After: 131 focused tests passed in 13.86s,
including branch validation, IR call-memory liveness, pipeline and ownership
checks. Scoped Ruff `check --fix`, MyPy and Pyright pass. Both behavior test
modules now run in the default pipeline; IR call liveness was also added to
its existing changed-file ownership group.

Logs: `/tmp/inertia-validation-site-types-` with `before.log`, `final.log`,
`mypy-final.log`, `pyright-final.log`, `quality.log`, and `pipeline.log`.
Full-suite and remote CI remain open.

Broad checks: global quality-fast still exits two, with MyPy diagnostics reduced
from 111 to 99. Default test-pipeline passes all three lanes: 2,367 unit tests
in 169.98s and all seven MS C tiny compile/run/decompile/recompile/run cases.
The slowest unit tests were sidecar-free RunMenu ESC preservation at 62.63s
and the reviewed indexed-address inventory at 36.84s. No timing improvement
or full-suite acceptance is inferred from this run.

Local timeline (2026-09-08, UTC+02:00): failing regressions 11:21:06-11:21:19;
final focused tests 11:23:28-11:23:42; default pipeline 11:24:17-11:29:01.
From first regression execution to terminal pipeline: about 7m55s, excluding
the preceding investigation. The main LEA/InitBars blocker remains open.
