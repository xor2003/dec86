# Access-Trait Runtime Factory

## Reason and Ownership

The legacy CLI adapter supplied a PEP 695 `TypeAliasType` as the access-trait
evidence factory. The collector needs a runtime class for both `isinstance`
and construction. A positive stack access therefore raised `TypeError` before
publishing its record. Existing unproven-base refusal tests did not enter this
branch.

Use an explicit import alias of the existing evidence class. This repairs
compatibility wiring only: no additional evidence, semantic recovery, or
cleanup rules are introduced in CLI. The annotation-only profile alias stays
unchanged. Migration of legacy semantic owners remains separate work.

## Definition of Done

- A real structured-C stack access creates the existing typed evidence record.
- Repeated collection recognizes that record and increments its count.
- The width, segment, and stack identity remain exact, without AST mutation.
- Existing unproven-base refusal tests stay green.
- Register the positive regression in routine tests, Ruff, and ownership checks.
- Run scoped Ruff/MyPy, quality-dev, quality-fast, and the executable pipeline;
  report unrelated global failures rather than hiding them.

## Definition of Failure

Suppressing the exception, replacing records with untyped dictionaries,
weakening proof requirements, or adding CLI semantic recovery is failure.
Passing only a mocked constructor check without exercising the real collector
does not establish this checkpoint.

## Evidence

- Before correction: the positive regression fails at the real collector's
  `isinstance(existing, AccessTraitStrideEvidence)` with `TypeError`.
- After correction: 19 focused tests pass in 9.19s, including segment refusal.
- Scoped Ruff `check --fix` passes.
- `quality-dev` exits zero: 2,047 tests pass in 88.66s, one external case passes,
  and the CMP16, LOOPS, and FPTR optimization quality guards pass.
- `quality-fast` exits two with 149 global MyPy diagnostic lines (previously
  150). The runtime-factory argument error is removed. No global green claim.
- Standalone MyPy on the legacy adapter still reports 34 unused-ignore
  diagnostics under its narrower import scope. No suppressions were added;
  this invocation is not green even though the factory mismatch is corrected.
- Mandatory `test-pipeline` exits zero: 2,047 pytest cases pass in 105.75s,
  followed by three passing selected external cases, with zero failures,
  skips, or timeouts. This is not full P0 closure, a full-suite count, or an
  end-to-end performance claim.

## Timing

Focused reproduction started 2026-09-07 13:19 +02:00. Verification finished
13:26 +02:00, approximately seven minutes elapsed including gate waits.
