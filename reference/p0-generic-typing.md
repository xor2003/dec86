# Generic Typing Checkpoint

## Reason

Several helpers declared PEP 695 parameters but referenced separate legacy
TypeVar/ParamSpec objects. This left their contracts internally inconsistent
and blocked the global typing gate. These are annotation-owner fixes, not
decompiler semantic recovery or performance changes.

## Definition of Done

- Bind generic annotations to the parameters declared by their function.
- Preserve argument and result types for direct, configured, and
  attribute-factory telemetry decorators. An absent attribute factory must not
  infer the wrapped callable's arguments as `Never`.
- Keep fork execution, result transport, timeout cleanup, and enum coercion
  behavior unchanged.
- Reuse the array helper's checked third-party `cfunc` reference rather than
  casting after an untyped attribute access.
- Pass focused runtime tests, explicit static-inference checks, scoped linters,
  ownership checks, and the changed-surface aggregate.
- Measure the global MyPy diagnostic reduction without claiming full closure.

## Definition of Failure

Replacing precise contracts with Any, suppressing diagnostics, weakening type
assertions, changing execution semantics to satisfy typing, or claiming mypyc
speedup without compilation and a controlled benchmark is failure.

## Implementation and Evidence

Owners: `fork_timeout.py`, `telemetry.py`, `X86_16/regs.py`, and
`X86_16/type_array_matching.py`. The telemetry overload distinguishes absent
and present attribute factories without changing its runtime implementation.

`test_generic_annotation_contracts.py` checks declaration identity and verifies
call-site inference with MyPy under the project configuration. The MyPy check
uses an isolated temporary cache, not altered warning rules. It is enrolled
in the routine pipeline, Ruff/pytest inventories, and changed-file ownership.

- Before: 17 existing timeout/telemetry runtime tests passed despite annotation
  errors. Runtime-only coverage was insufficient.
- After: 41 focused runtime/annotation/array tests passed in 11.03s; the static
  inference regression took 1.88s.
- Scoped Ruff `check --fix`, MyPy, and the type ratchet passed for the four
  implementation owners.
- Global `make linters`: MyPy error lines decreased from 164 to 155. The global
  gate remains red; this is nine diagnostics removed, not nine independent
  semantic defects fixed.
- `quality-dev` exited zero: 2,030 tests passed in 80.20s, its external
  executable case passed, and CMP16/LOOPS/FPTR optimization parity guards
  passed. Identical import surfaces do not constitute a speedup measurement.

Residual diagnostic: the aggregate's live SORTD pointer-output test emitted a
CPython multi-threaded-fork warning from `fork_timeout.py`. It passed, but the
warning is not suppressed or treated as proof of safe native-thread isolation.
The current guard checks Python thread inventory; investigate the discrepancy
with CPython's process-thread detection in a separate runtime-safety step.
That step's DoD is a typed refusal/fallback before unsafe fork, with timeout
and descendant-cleanup tests preserved; failure means suppressing the warning,
ignoring native threads, or weakening timeouts. No worker-reuse optimization is
implied by this diagnostic.

Full P0, remaining typing debt, and the complete-suite audit remain open. No
decompilation speedup or complete mypyc coverage is claimed.

Timing: work occurred on 2026-09-07 after the pointer-store checkpoint. Exact
engineering start time was not captured; the recorded test durations are not
an engineering-effort estimate.
