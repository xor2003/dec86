# Segment-Register Membership

## Reason and Ownership

Alias stack-fragment helpers required `frozenset[str]`, but their default
segment inventory was an ordered tuple. Constant restoration also compared
the caller's frozenset to that tuple. Equivalent register membership therefore
produced different proof verdicts and five global MyPy diagnostics.

IR retains the authoritative ordered `SEGMENT_REGISTERS` inventory and derives
`SEGMENT_REGISTER_SET` from it. Alias uses the derived immutable membership
view. No register ordering, frontend execution, stack identity rule, or Rewrite
behavior changes.

## Definition of Done

- Explicit segment membership and the specialized default produce identical
  exact constant-restoration facts and balanced evidence counters.
- Cover all six segment registers; retain refusal for unrelated general
  register tracking instead of extending segment-specific rules by accident.
- Preserve save/restore behavior, conflicting-predecessor refusal, and unknown
  stack-alias invalidation in existing regressions.
- Correct the stale live-VEX assertion to require the already-proven `0xb800`
  intermediate DS value, while retaining the subsequent original-DS restore
  assertions. Do not merely remove the intermediate-state check.
- Pass focused tests, scoped Ruff/MyPy, the mandatory executable pipeline, and
  the changed-surface aggregate. Enroll both test modules in routine checks.

## Definition of Failure

Changing the ordered inventory into an unordered output source, dropping FS/GS,
guessing stack bytes, permitting general-register constant recovery without
its own proof, suppressing type errors, or replacing exact assertions with a
weaker success check is failure.

## Evidence

- Initial existing suite: 8 passed, 1 failed. The failure expected unknown DS
  after `mov ax, 0xb800; mov ds, ax`; current IR correctly proves that value.
- New membership regression before the fix: 6 failed, 1 passed. Every explicit
  segment-set case lost the constant proof; the general-register refusal held.
- After correction: all 16 selected tests passed in 8.54s.
- Scoped Ruff `check --fix`, MyPy, and type ratchet passed.
- Global MyPy error lines decreased from 155 to 150; the global gate is still red.
- Mandatory pipeline exited zero: 2,046 pytest cases passed in 80.00s, followed
  by the configured executable gates.
- `quality-dev` exited zero: 2,046 tests passed in 87.95s, its external
  executable case passed, and all three optimization parity guards passed.

This closes a bounded collection-contract defect and corrects one stale test,
not the full-suite acceptance requirement. No end-to-end speedup is claimed.

## Timing

First recorded existing-suite run: 2026-09-07 13:02:14 +02:00. New fail-before
run: 13:03:41 +02:00. These timestamps come from diagnostic-log creation times;
initial exploration preceded them. Verification completed at 13:11:50 +02:00.
The recorded wall span is approximately 9m36s, including test and build waits,
not just engineering work.
