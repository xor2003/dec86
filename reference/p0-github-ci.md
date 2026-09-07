# P0 GitHub CI Closure

## Evidence (2026-09-07)

The eight latest workflow runs are failed. The latest two were inspected:
Pyright fails, and subsequent Vulture, Lizard, and pytest steps are skipped.
The latest run, 34131575884 on e7b84fe8b, reports 49 Pyright errors in the
first Make batch. This is not a full typing census or a pytest failure count.

Run: https://github.com/xor2003/inertia_decompiler/actions/runs/34131575884

The project requires Python >=3.14 and CI installs 3.14.7, but the shared
Pyright configuration still targeted 3.11. The local correction targets 3.14.
Independent workflow checks now run after successful dependency installation
even if another check fails. Cancellation still stops them; failed checks
still fail the job. No continue-on-error or diagnostic suppression is added.
The edited workflow passes actionlint 1.7.7.

## Remaining Task

Local instruction-contract repair: provenance now consumes the existing
`DecodedInstructionFactSurface8616` instead of maintaining an incompatible
duplicate hierarchy. Protocol methods explicitly declare abstract bodies.
Scoped Pyright improves from eight errors to zero; Ruff and scoped MyPy pass.
The 16 register-reaching-source regressions pass before (8.19s) and after
(8.40s). No instruction semantics or typing suppressions were changed.
The current local first Make Pyright batch reports 37 errors after this repair;
it still stops before later batches. This is not directly interchangeable with
the remote count because installed dependency surfaces differ.
`quality-dev` passes on the shared working tree, including 2,119 tests in
100.42s and the executable guards. This gate includes pending unrelated
changes and is not a clean-commit or remote full-suite acceptance result.

- Reason: skipped tests provide no regression evidence, and local narrow
  gates do not establish remote acceptance.
- Order: align tool configuration; collect every CI check result; repair
  actual typing, lint, and test failures in their owning layers; rerun CI.
- DoD: all required checks pass on the pushed commit, including executed
  pytest. Record the run URL and actual test totals. Preserve the separate
  full-suite and DOS round-trip acceptance requirements in the main plan.
- Definition of failure: skipped checks reported as passing, relaxed typing
  rules, hidden diagnostics, removed behavioral coverage, or a local-only
  result substituted for remote CI success.

Status: open. The configuration correction does not resolve existing typing
debt. Run 34133441640 on 704dc5688 confirms the changed execution conditions:
Ruff and Lizard passed, Pyright and Vulture failed, and pytest subsequently
ran: **4,384 passed, 44 failed in 477.50s**, with 10 warnings. This focused CI
selection is not the full suite. Pyright reported 28 errors in its first batch.
Vulture reported unused `propagator` in stack_compat.py and `timeout_millis`
in telemetry.py. Run 34133444219 is a separate
Dependabot job, not the focused test workflow.

The next local typing repair preserves the segmented-byte access methods and
declares their existing active-instruction field and PyVEX decorated result
types. The decorator returns VexValue even when the wrapped implementation
returns RdTmp. `access.py` now passes Pyright, MyPy, and Ruff, with no new
suppression; 34 access/emulator/stack-helper tests pass in 9.00s. The current
first Make Pyright batch has 30 errors. Remaining batches are still uncounted.
The default test pipeline passes all three lanes on this shared tree, with
2,119 unit tests in 105.02s and successful external compiler round trips
(`/tmp/inertia-ci-access-pipeline.log`). This does not close named InitMenu or
the source-stable full audit.

Pending follow-up: the direct-call stack-effect helper now declares its actual
Capstone `CsInsn` input rather than `object`. Its caller feeds decoded Capstone
instructions; no instruction processing changes. `analysis_helpers.py` passes
Ruff, scoped MyPy, and Pyright. Eleven interrupt/AST regressions pass before
(8.44s) and after (10.61s). Broad gates have not been repeated for this
annotation-only follow-up.

## Interpreter Resolution And Next Failure Groups

Pyright's verbose log proved that invoking `.venv/bin/python -m pyright`
without `--pythonpath` still inspected system Python 3.12 packages on this
host. Earlier local first-batch counts therefore mixed real source errors and
environment mismatches; do not use them as a clean typing progress census.
Make now selects its `PYTHON` explicitly for every Pyright invocation,
including the separately timed DCE batch. The regression dry-runs all three
Pyright targets: one failure before, three passes after (1.29s).
For direct use, pass `--pythonpath ./.venv/bin/python` as well.

Callsite None checks and the abstract tag-map method are now explicit;
108 callsite/register-source tests pass before (8.66s) and after (9.74s).
Scoped MyPy and Ruff pass; Pyright passes for callsite_summary.py when it uses
the actual project environment. The corrected first Make batch has 17 errors.

Prioritize the newly visible CI failures as follows, without deleting checks:
1. Clean-checkout setup: two partition-controller tests assume `.cache/pytest`
   exists; COMP32 tests need their generated binary; DOS recompilation needs
   kvikdos. Reproduce without local artifacts and establish explicit fixture
   creation/toolchain prerequisites, not success-by-skip.
2. Test contract drift: the frame-push inventory-cache test calls a changed
   helper signature without `request_cache`. Verify its intended cache behavior
   against the current owner before repairing the test.
3. Real decompiler failures: inspect exact tail-validation and call-effect
   diagnostics, separate timeouts from semantic failures, and retain the
   sidecar-free acceptance contract. Environment fixes alone cannot close them.

Detailed remote log: `/tmp/inertia-ci-704dc-failed.log`.

Follow-up `quality-dev` passes on the current shared tree: 2,119 tests in
101.37s, architecture/ownership checks, and generated-C guards. The three
Makefile output/interpreter tests were also run separately and pass. These
local results form a partial checkpoint; remote CI and full-suite closure remain
open.

Clean-cache follow-up: both controller cases reproduce the remote
FileNotFoundError with REPO_ROOT redirected to an empty temporary directory.
The runner now creates its cache parent; all 21 partition-runner tests pass
in 1.93s, including cleanup of per-run temporary files. Ruff, scoped MyPy,
and Pyright pass. The stale frame-push cache test now passes `callsite_addr`
and uses keyword arguments, retaining the result and single-collection
assertions: one failed/four passed before, five passed after in 7.72s.
These three CI failure cases are fixed under focused checks; remote acceptance
is not yet rerun. The Vulture findings are protocol parameter declarations,
not established dead runtime code.

COMP32 fixture follow-up: preserved the existing 4,187-byte executable, matching
C source and COD/MAP files under `angr_platforms/tests/fixtures/msc6/compare32`.
The address-specific tests now use this versioned input instead of the ignored
build directory. Four SHA-256 checks protect its identity; the original four
decompiler assertions are unchanged. Before: four passed in 11.83s. After:
eight passed in 5.40s (warm caches; not a performance comparison). Ruff passes.
This removes the clean-checkout missing-input dependency, not the separate
requirement to run the MS C compiler round-trip pipeline. Exact historical
binary rebuild reproducibility is not claimed. Broad/remote gates have not
yet been repeated for this fixture-only change.

Typing follow-up: explicit architecture-binding result types remove
four more diagnostics. The installed angr implementations return concrete
SimTypeFunction/SimTypePointer objects, although the public with_arch return
annotation is SimType. The casts preserve those existing classes, not new
semantic recovery; two redundant pointer capability checks are removed.
Eight annotation regressions pass before (17.25s); 63 smoke/prototype tests
pass after (27.61s). Ruff and scoped MyPy pass. The corrected first Pyright
batch at that point reported 13 errors.

The AIL OUT compatibility consumer now declares exact block, dirty-statement,
helper-expression, and constant-payload fields instead of reading them through
`object` or assigning through `Any`. Runtime class guards and conversion
semantics are unchanged. The existing I/O regression now covers 8/16/32-bit
OUT instructions: seven tests pass before (8.04s) and after (9.26s).
Scoped Ruff, MyPy, and Pyright pass for compat.py. The first broader Pyright
batch has 11 errors; later batches remain uncounted.

Combined `quality-dev` passes with 2,119 tests in 147.61s, compiled-import and
architecture/ownership checks, and generated-C guards. This checkpoint is
local/shared-tree evidence, not full-suite or remote CI closure.
