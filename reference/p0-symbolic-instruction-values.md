# Symbolic Instruction Value Boundary (2026-09-09)

## Change And Ownership

Frontend instruction handlers now check for native `VexValue` objects before
using symbolic-only attributes. BOUND retains integer or symbolic offsets;
IDIV retains its original constant widths, signed comparisons, and fault exits.
LOOP checks its register value before decrementing or writing the counter.
JCXZ keeps the existing missing-lifter refusal. No concrete control-flow
support was added, and the byte-safe segmented memory helpers were untouched.

The check was initially beside the frontend value adapter in `instr_base.py`.
It is now shared through `vex_value_contract.py`, retaining the instruction
alias; see [checked wrapper contracts](p0-vex-wrapper-contracts.md).
It raises a clear TypeError for unsupported values instead of adding unchecked
Any casts. The shared concrete-or-symbolic Processor contract is unchanged.

## Acceptance

- Reason: symbolic-only operations must not consume concrete values or leave
  partial register mutations when the execution context is unsupported.
- DoD: refusal precedes counter mutation, existing JCXZ refusal survives,
  native division/BOUND/loop behavior passes instruction regressions, scoped
  types/docs/linters pass, and all default DOS lanes pass. Met for this boundary.
- Definition of failure: assume every Processor result is symbolic, coerce
  concrete booleans into guessed VEX values, change register/offset widths,
  alter flags/fault exits, or bypass tail validation.
- With the original counter helper, the final refusal regressions report
  eight failures and six passes in 8.16s. The corrected tests pass.
- Frame/IMUL/BOUND edge run: 182 passed in 29.55s. Separate instruction corpus:
  1,209 passed, one skipped, in 67.52s. The skip is the existing opt-in full
  deduplicated 80386 audit, not a new skip; these runs overlap on 14 tests.
- Fast ownership selects the ordinary sampled 80386, width, and division
  cases explicitly, not the opt-in audit. Admission: 109 passed in 4.65s.
- Scoped Ruff `check --fix`, MyPy, and venv Pyright pass. Global quality still
  fails, now with 14 MyPy diagnostics instead of 22.

Default pipeline: 2,550 unit tests passed in 148.59s; QuickC and all MS C tiny
round trips passed. Three lanes passed, none failed/skipped/timed out. Lane
wall times: 149.260s, 44.222s, and 63.081s. No full-suite or remote CI closure,
SORTD numeric-frame repair, or performance improvement is claimed.

Evidence logs: `/tmp/inertia-loop-refusal-baseline.log`,
`/tmp/inertia-lifted-value-tests.log`, `/tmp/inertia-lifted-value-corpus.log`,
`/tmp/inertia-lifted-value-admission.log`, `/tmp/inertia-lifted-value-quality.log`,
and `/tmp/inertia-lifted-value-pipeline.log`.

Recorded verification window: 00:03:54 (first baseline log creation) through
00:15:32 (final pipeline completion), Europe/Belgrade, 2026-09-09: 11m38s
including waits. Earlier investigation and active-only effort were not timed.
