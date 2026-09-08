# Validation Type Contract Checkpoint

## Reason And Owners

The canonical tail-validation summary lost its type across runtime
configuration, the collector callback, cached codegen metadata and mutable
transaction state. These contracts now retain `X86_16TailValidationSummary`
end to end, including baseline replacement. Type-only imports avoid adding
runtime initialization dependencies. The existing baseline collector now
declares its actual return type.

Types/Lowering consumes its checked callee address and known declaration
directly. The postprocess compatibility guard keeps dynamic count inputs as
`object` until its existing integer checks prove them usable. No semantic
recovery or new validation exception was added to postprocess.

The two development-only `Any` return errors were import-scope artifacts:
`follow_imports="skip"` hid already-typed cache I/O and callsite-summary
providers. Global MyPy configuration now follows these two providers normally.
Neither consumer was cast or weakened, and the strict warning rules remain.

## Acceptance And Failure

- DoD: cached and fresh summaries retain object identity through configuration
  and transaction state; disabled validation does not invoke the collector.
- DoD: baseline replacement does not mutate the previous immutable summary or
  advance accepted mutation generation on rollback.
- DoD: focused tools and default DOS round trips pass, and the global and
  development Make MyPy scopes have no errors.
- Failure: erase evidence to `Any`, bypass a validation comparison, infer a
  missing callee/count, alter baseline policy, or weaken typing diagnostics.

## Evidence

- Before: 78 focused tests passed in 8.84s; Make's global MyPy scope had four
  errors, and its development scope had two additional import-derived errors.
- After: 311 focused/rollback/admission tests passed in 21.82s. This includes
  the four new runtime-to-transaction baseline cases.
- Final configuration/ownership/inventory tests: 120 passed in 6.76s. This
  overlaps the preceding run and must not be added as a unique test count.
- Scoped Ruff `--fix`, MyPy and Pyright pass. Global Make MyPy reached zero;
  `make mypy-dev` also passes after the import-scope correction.
- `quality-fast` and `quality-dev` both completed successfully. The development
  unit lane includes the final **2,632 tests**, passed in 128.15s. All three
  executable quality guards passed in each command. They reported one shared
  active import surface, not independent Python/native parity or a speedup.
- Final `quality-hard` passes full architecture, the type/doc ratchet, 2,632
  unit tests in 117.72s and all three executable quality guards. Its initial
  attempt found a missing adjacent explanation on an existing optional
  third-party CLI attribute access; that comment was corrected without a rule
  exemption. The six CLI boundary tests and scoped tools still pass.
- Global Vulture passes. A final global Make MyPy repeat also passes with the
  updated import configuration.
- Default pipeline: 2,630 tests passed in 147.30s plus QuickC and all seven
  MS C tiny round trips. Two later static configuration tests are separately
  verified above and included in the routine selection.
- Startup architecture, types/docs and ownership guards pass.
- The broader CI-mode Pyright command remains red: 31 errors in return
  compatibility, structuring, function evidence inventory and helper ABI.
  The full pytest suite, remote CI and numeric-frame defect remain open.

Logs: `/tmp/inertia-validation-contract-{before,tests,admission,mypy,pyright,mypy-dev,quality,dev,pipeline,global-pyright}.log`.

## Timing

Baseline completed 2026-09-09 00:48:17 +02:00; expanded focused tests completed
00:52:37 +02:00 (4m20s later). Development MyPy completed by 00:55:00 +02:00.
These elapsed checkpoints exclude earlier investigation and are not an ETA.
`quality-fast` completed 01:00:56 +02:00 and `quality-dev` completed
01:01:12 +02:00, 12m55s after the baseline checkpoint.
Final `quality-hard` completed 01:10:10 +02:00, 21m53s after the baseline.
The repeated broad gates account for part of this elapsed time; it is not
21m53s of implementation work.
