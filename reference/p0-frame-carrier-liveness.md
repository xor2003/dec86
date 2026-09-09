# Live Frame Carrier Preservation (2026-09-09)

## Root Cause

The minimal numeric-frame diagnostic retained `vvar_11 = entry_sp - 2` through
native SSA level 0, SSA level 1, variable recovery, and structured C generation.
The disappearing definition was not caused by those native stages. Disabling
GP runtime lowering did not restore it, ruling out that owner as the cause of
this particular missing definition (not as a general correctness audit).

An exact-object removal observer identified this path:

```text
_apply_structuring_direct_stack_materialization_8616
  materialize_direct_stack_mov_instructions_8616
    execute_direct_stack_replay_8616
      prune_frame_prologue_stack_assignments_8616
        statements[:] = retained
```

The frame consumer proved a canonical entry sequence, then deleted all
assignments tagged with its instruction addresses. It never checked whether
their register/temporary definitions still had consumers outside the frame group. The
numeric expression `vvar_11 - 2` survived after its definition was deleted.
Canonical instruction ownership is not evidence of deadness.

## Repair And Acceptance Boundary

The Types/Lowering frame consumer now requires a whole-function use proof
before removing any member of the canonical group. Exact AIL virtual IDs join
dirty and recovered C variable views. Different known SSA versions remain
distinct; unknown scalar identities and overlapping physical-register views
without sufficient SSA identity refuse. External writes with the same identity
also conservatively refuse; this is not a new general liveness engine.
This proof does not classify reused stack objects as immutable register values;
their memory lifetime remains the storage owner's responsibility.

- Reason: preserve numeric guest values and prevent uninitialized reads when
  frame bookkeeping is also used as ordinary data.
- DoD: preserve the complete group on an external scalar use, across nested
  statements and dirty/recovered views; retain removal of closed groups; admit
  regressions to routine gates and keep mandatory docs/types.
- Definition of failure: remove only part of a live frame group, merge distinct
  SSA versions, guess an unknown identity, weaken validation, or treat this
  guard as complete numeric-frame materialization.

Six new integration regressions fail before the guard and pass afterward.
With additional unknown-identity/version cases, **69 focused tests pass**,
seven dependency warnings, 10.40s. Scoped Ruff `--fix`, MyPy and Pyright pass.
The helper is a focused new module; the large existing consumer only imports
and calls it. Existing instruction/frame classification remains its prerequisite.

The first fast gate caught an overbroad version of the check: treating reused
stack objects as scalar register definitions retained obsolete frame stores in
DOS loadProgram, InitBars and RunMenu. The production check now restricts its
definition census to registers, temporaries and owned runtime-register state.
All three executable regressions pass again alongside the new tests:
**14 passed, seven warnings, 59.74s**. Separate tests cover reused stack storage
and observable runtime-register state. No assertion or validation gate was weakened.

Final hard/fast/default gates pass, combined exit 0: **2,923 unit tests** in
the fast lane (124.99s) and default lane (108.56s), seven dependency warnings
each, three executable quality guards and all seven MS C tiny cases. Final
scoped Ruff `--fix`, MyPy and Pyright pass. Existing global complexity warnings
remain visible. Log: `/tmp/inertia-frame-live-final-gates.log`.
This does not refresh the broader full-suite or remote CI failure counts.

The complete default `SORTDEMO.EXE` rerun confirms **19/20 accepted**, exit 2,
200.03s wall, 477.25s user CPU, 8.79s system CPU, and 355,484 KiB peak process
RSS. PercolateDown and QuickSort still validate; InitMenu remains rejected.
Generated stdout is byte-identical to the preceding checkpoint, SHA-256
`e3f8970e13403ace02bb95f77c2c20cf5bfeac6ea81a723020411c6518fc3936`.
This is non-degradation evidence, not numeric-frame acceptance or a controlled
performance comparison. Logs: `/tmp/inertia-sortdemo-frame-live.{c,log}`.
The final executable run finished at 12:29:02 local. Investigation started
before the first retained diagnostic at 11:58:59; those timestamps bound an
observed window, not a measured total of active engineering time.

Re-running the process-local numeric-use filter with this production guard
now retains the SP decrement before the scalar store. Its store expression
therefore corresponds to entry SP minus four instead of minus two. This is
diagnostic expression evidence, not execution of accepted recompiled C.
The return still contains `MEM_U16(inertia_ss * 16 + &local_2)` and frame
restoration remains invalid. The numeric-use filter is still NOT installed.

## Next Work

Preserve incoming BP, guest frame-memory identity, and numeric return-value
definitions across native projection and paired save/restore consumption.
The stage observer also records a concrete return-definition lifetime problem:
before SSA conversion the return already contains `BP - 2`, but BP is restored
before return. SSA then correctly binds that expression to the restored BP
load, not the earlier LEA value held in AX. Investigate return construction at
the `ReturnMaker` compatibility boundary; do not repair this in rendered C.
The minimal oracle must execute correctly for wrapped and nonwrapped SP;
then InitMenu must pass validation and strict recompilation. Do not reintroduce
a bare StackBaseOffset bypass, truncate host pointers, or substitute current
register state for an earlier SSA value.

Evidence logs in `/tmp`: `inertia-frame-without-gp.log`,
`inertia-frame-stage-probe.log`, `inertia-frame-c-assignment-probe.log`,
`inertia-frame-removal-probe.log`, `inertia-frame-live-before.log`,
`inertia-frame-live-focused.log`, and `inertia-frame-live-context.log`.
All observers and altered propagation/GP behavior were process-local only.
InitMenu, full-suite failures and CI remain open.
