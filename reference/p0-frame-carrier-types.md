# Frame-Carrier Type Contract

## Reason and Ownership

Types/Lowering constructs BP/SP views from architecture `(offset, width)` tuples.
A comprehension assignment expression bound `register` in the enclosing scope;
the later collection loop reused it for `PhysicalRegisterView8616 | None`.
This produced three MyPy errors when the actual register-view owner was checked.

Rename the raw tuple binding to `register_span` and explicitly reject `None`
before membership testing. No accepted physical register, width, instruction
address, temporary identity, evidence count, or frame-proof rule changes.

## Definition of Done

- MyPy checks collection and the physical-register owner together without errors.
- Exact BP/SP snapshots remain accepted; AX, wider BP, and non-register sources
  remain refused, with unchanged evidence counters and source expressions.
- Ambiguous definitions and candidates without canonical frame proof remain
  refused by existing focused regressions.
- Enroll the paired static check and runtime cases in routine checks and ownership.
- Pass Ruff and quality-dev; record the global quality-fast result honestly.

## Definition of Failure

Adding casts, ignores, or dynamic attribute access to conceal the mismatch;
accepting a wider or unrelated register; deleting an unproven carrier; or claiming
that single-file MyPy checks the imported owned contract is failure.

## Evidence

- Existing canonical frame tests: 4 passed in 7.88s before changes.
- New valid fixture before correction: 5 runtime cases passed; the paired MyPy
  test failed with all three original typing errors.
- After correction: 18 focused tests passed in 10.00s. The paired static
  regression took 1.44s and uses an isolated temporary cache.
- Scoped Ruff `check --fix` passed.
- `quality-dev` exits zero: 2,053 tests pass in 88.59s, one external case passes,
  and all three CMP16/LOOPS/FPTR optimization guards pass.
- `quality-fast` exits two: global MyPy diagnostic lines decrease from 149 to
  146, with all three frame-carrier errors removed. Global typing remains open.

Project MyPy uses `follow_imports = "skip"`; checking only the collector appears
green because the imported view becomes opaque. The regression explicitly
includes both owners under the existing project configuration, without weakening
any options. This is a typing checkpoint, not a new semantic recovery mechanism
or full-suite acceptance result.

## Timing

Started 2026-09-07 13:27 +02:00; aggregate verification finished 13:32 +02:00.
Approximately five minutes elapsed, including gate waits.
