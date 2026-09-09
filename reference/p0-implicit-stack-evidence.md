# Implicit Stack Evidence And Address Size (2026-09-09)

## Scope And Acceptance

- Reason: optimized stack operations executed symbolic SS accesses without
  recording their logical operands. A closed ledger over captured inputs did
  not prove complete memory coverage.
- DoD: capture each stack word once, retain instruction-entry SP/BP coordinates,
  segment, width and byte-slice ownership; preserve execution and DOS round trips.
- Definition of failure: duplicate or omit a memory effect, confuse SP and BP,
  let a data-address prefix change implicit stack addressing, or claim this
  evidence repair fixes numeric generated C.

The earliest owner is the frontend: `lift_86_16.py`, `access.py`, and
`stack_helpers.py`. No recovery was added to Rewrite, postprocess or CLI.

## Changes

The optimized stack helpers previously recorded an operand only when its
offset was constant. They now receive explicit instruction-entry coordinates:
PUSH/CALL stores use SP-2, POP/RET reads SP+0, and LEAVE reads BP+0.
Nested ENTER retains distinct BP-relative reads and descending SP stores.
The existing byte-safe execution helpers are unchanged.

Regression tests also exposed an execution defect in the full frontend:
67h-prefixed stack operations inherited 32-bit data addressing, allowing bytes
past FFFFh to reach the adjacent linear segment instead of wrapping within SS.
The segmented access API now accepts an explicit address size. Stack helpers
request 16 bits for word and dword operations, including nested ENTER reads;
ordinary data operands still use their instruction's address size. Independent
byte resolution and the single typed semantic access record are preserved.

The 16-byte numeric-frame reproducer now has four complete logical accesses,
up from one: counters `(4, 4, 4, 4, 0)`. The existing word-transfer owner proves
the BP spill at 1000h and reload at 100Eh. The RET read is complete memory
evidence but is not classified as a full-register reload, as expected.
Generated C remains unchanged and invalid; numeric entry-SP materialization
and Alias-backed paired byte-carrier consumption remain open.

## Verification

- Nine optimized/full capture cases failed before the repair. Retained tests
  require every raw load/store in each tested block to have one logical owner.
- Four concrete prefixed PUSH/POP and two nested ENTER wrap cases failed before
  their fixes and pass afterward, including adjacent-segment sentinel checks.
- Focused frontend/access/stack tests: 82 passed, seven warnings, 9.25s.
- Broad 80386 tests: 1,278 passed, one existing exhaustive opt-in skip, seven
  warnings, 99.08s. Slowest test: invalid LOCK hardware oracle, 4.67s.
- Ruff `check --fix`, scoped MyPy and scoped Pyright pass on changed production
  files. These are not a new whole-production Pyright audit.
- Combined `quality-hard quality-fast test-pipeline` passed. Fast lane:
  2,840 passed in 119.47s; default unit lane: 2,840 passed in 96.97s.
  All three executable quality guards, QuickC and seven MS C tiny round trips
  passed; every original/rebuilt DOS exit code was 255. No default lane was
  failed, skipped or timed out. Guards share the active import surface and do
  not establish independent Python/native parity.
- Global Make MyPy/Ruff pass; existing Lizard warnings remain visible.

Full-suite refresh started at 03:27:42 local with seven workers, JIT enabled,
hash seed zero and the existing timeout scale of four: **10,773 passed, 45
failed, 170 skipped, 88 warnings in 756.14s**. Production code and tests remained
frozen throughout, verified by the same source diff SHA-256 before and after:
`2a1cd3b83c8666fabf6478492027a4447c401bddd8f46ec451a9afd2ff1f2ff4`.
Compared by exact test identities with the preceding 48-failure audit, 14 cases
no longer failed and 11 newly failed. This is not a clean full-suite result.

Seven new failures assumed RET had no logical record or built inconsistent
fault-injection ledgers after RET became visible. Corrections retain the RET
access, verify its separate byte ownership and account for its explicit refusal
as a BP-relative local. The two corrected modules pass **21 tests**, seven
warnings, 19.21s; Ruff `check --fix` passes. Production code was not changed
after the full audit. The full suite was not rerun after these fixture changes.

The remaining four cases pass at unchanged `e71c189b6` in a detached worktree
(107.66s). Patched-checkout replay of existing caches passes two and fails two
DOSFUNC assertions (36.63s). The call is present, but its return has an EAX merge
and an extra GP-state write absent from fresh output. An isolated cache identity
(`INERTIA_STACK_CAPTURE_AUDIT=20260909`, included by the existing environment
cache contract) produces the same clean `err = intdosx(&rin, &rout, &sreg);`
body as HEAD, with validation passed and clean whole-tail validation. All four
focused tests then pass, seven warnings, 37.12s. The cache tag has no production
behavior and was not installed as a default. Existing entries were not deleted.
Their creation provenance and the cold/warm discrepancy remain to be explained;
fresh success does not prove cache correctness or erase the full-run failures.

Slowest full-suite cases: TID show-range 239.31s; EGAME2 helper signature 129.53s;
EGAME2 direct forwarding 125.76s; InitMenu pause guard 117.55s; quicksort 114.93s.
These timings identify investigation targets, not proven duplicate tests or
evidence that coverage should be removed.

Evidence logs: `/tmp/inertia-implicit-stack-*` and
`/tmp/inertia-full-20260909-implicit-stack.{log,xml}`. These are temporary
verification artifacts, not files to commit.

## Next Boundary

Follow-up: the two DOSFUNC assertions are now backed by compiled behavioral
checks, which both cached and fresh bodies pass. See the
[behavioral-oracle report](p0-dosfunc-behavior-oracle.md); the original producer's
text variation remains unexplained, but no call loss was found in those bodies.

Consume the now-available logical word facts through Alias to prove paired
frame storage, then preserve numeric entry-SP definitions across SSA's
stack-variable Reference projection. Do not retry the rejected origin filter
unchanged or substitute host-pointer truncation for guest stack semantics.
InitMenu, complete-suite acceptance and remote CI remain open. Investigate the
cache provenance discrepancy before claiming deterministic acceptance. The user
now permits measured code/test performance fixes when useful; the broad Step 10
campaign remains secondary to correctness.
