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
debt, and the modified workflow has not yet been verified on GitHub.
