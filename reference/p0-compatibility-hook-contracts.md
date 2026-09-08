# Compatibility Hook Contracts (2026-09-08)

## Scope And Reason

Close the stack compatibility and telemetry Vulture findings without suppressing
diagnostics or weakening production typing. Installed angr hooks must accept
the actual angr receiver types; patch-name inspection does not require a second
callable contract.

## Changes

- Stack hooks now use `LiveDefinitions` and `SPropagator` receiver types.
  A narrow model-boundary protocol describes the replacements and Inertia
  evidence metadata. Duplicate architecture and receiver protocols are removed.
- Missing SP/BP offsets for an architecture claiming `86_16` raise an explicit
  error. No incomplete register inventory is silently used for normalization.
- Telemetry keeps the provider's `timeout_millis` keyword and uses the same
  name for its local value. Tests verify zero and negative limits clamp to one,
  and positive limits are preserved. This is not a runtime performance fix.

## Acceptance

DoD: focused runtime regressions, scoped Ruff/MyPy/Pyright, global Vulture and
startup architecture checks pass without diagnostic suppression.

Definition of failure: changed valid stack normalization, lost propagation
evidence, non-idempotent hook installation, wrong telemetry timeout, or an
unresolved scoped typing/dead-code finding.

Evidence: 23 tests passed before the receiver correction; 25 passed afterward
in 10.02s under `PYTHON_JIT=1 PYTHONHASHSEED=0 pytest -n 7`. The seven warnings
are the existing upstream `uefi_firmware` layout deprecation. The five slowest
test durations were each below one second. Scoped `ruff check --fix`, MyPy,
and Pyright pass; startup architecture checks pass. Pyright must use
`--pythonpath ./.venv/bin/python`, as the Makefile already specifies.

The global Vulture gate passes. Full quality-fast, full-suite and remote CI
were not rerun for this checkpoint. InitBars strict-C acceptance remains open;
this compatibility repair does not close the semantic plan.
