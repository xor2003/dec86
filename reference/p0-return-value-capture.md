# Scalar Return Value Capture (2026-09-09)

## Root Cause And Repair

ReturnMaker's compatibility hook found an earlier AX producer, expanded its
temporaries/register dependencies, and moved that expression to RET. That is
not a valid substitution when its inputs change in between. In the minimal
frame reproducer, `AX = BP - 2` preceded BP restoration. The generated return
used restored BP instead of the value already held in AX.

The frontend/angr compatibility boundary now emits a read of the actual scalar
return register at RET. Native SSA owns binding and propagation of its value.
Producer evidence still controls whether an inferred return should exist;
known, ignored and unknown caller-observation decisions remain unchanged.
The same rule applies to constants: a later partial-register write can
invalidate an earlier constant-producing full-register assignment.

- Reason: preserve value lifetimes before SSA rather than repair incorrect C.
- DoD: scalar return construction reads the correct architectural register at
  RET, retaining its width and instruction provenance; BP restoration, partial
  register writes and memory mutations cannot change an earlier captured value;
  existing literal-return semantics and routine pipelines remain valid.
- Definition of failure: move state-dependent producer expressions to RET,
  accept a stale full-register constant after a partial write, invent a return
  without the existing evidence/prototype decision, weaken validation, or
  patch rendered C.

Three BP-restoration cases fail before the repair. The expanded focused module
passes **10 tests**, seven dependency warnings, 8.66s. The existing literal-75
test now checks an AX capture backed by the unchanged AX assignment, rather
than requiring premature constant inlining. The module is admitted to routine
Make/pipeline selection. Existing source-finder APIs remain available to their
other evidence consumers; they are no longer used as scalar return expressions
at this transport boundary. Combined-register return construction is not
covered by this scalar repair and still needs a separate lifetime audit.

## Live Diagnostic And Remaining Work

With the still-process-local numeric-use propagation experiment, the minimal
body now stores the numeric value and returns that same C variable:

```c
inertia_esp = inertia_esp & 0xffff0000 | (inertia_esp & 0xffff) - 2 & 0xffff;
v8 = 0xfffe + (inertia_esp & 0xffff);
SEG_U16(inertia_ds, 0x200) = v8;
return v8;
```

The previous return through a host-address-derived frame-memory read is gone
in this diagnostic. This does not prove the complete guest frame ABI: runtime
SP lifetime and frame entry/exit effects still require coherent handling.
The experimental propagation filter is NOT installed. InitMenu and the broad
full-suite/CI goal remain open until executable acceptance proves otherwise.

Scoped Ruff `--fix` and MyPy pass. Pyright passes with the project interpreter
explicitly selected via `--pythonpath .venv/bin/python`. Without it, this
checkout's Pyright resolves an incompatible Register constructor signature;
the same source then reports a spurious missing-argument error. No type ignore
or constructor cast was added to conceal that environment mismatch.

The combined `quality-hard quality-dev quality-fast test-pipeline` invocation
completed with exit 0. Fast and default unit lanes each passed 2,933 tests
(142.15s and 126.77s respectively); three executable quality guards and all
seven MS C tiny compile/decompile/recompile/run cases passed. This is curated
pipeline evidence, not a green full-suite or remote-CI claim.

Whole-executable verification rejected this checkpoint: the exact default
SORTDEMO command accepted **18/20**, versus 19/20 at `c7fe4e0c0`.
It exited 2 after 219.72s (561.47s user, 9.87s system, peak process RSS
403,560 KiB). DrawBar `0x106c8` is newly rejected: the primary attempt reports
stack-local call-argument dependency mismatches during widening copy
propagation; retries report an unexpected return for a proven-empty result
and GCC rejecting a void-valued return. InitMenu remains rejected.
PercolateDown and QuickSort still pass. This patch is therefore NOT ready to
land, despite green curated gates. Investigate the return/stack-value boundary
and add executable regression coverage before claiming acceptance.
Evidence: `/tmp/inertia-sortdemo-return-capture.{c,log}`; run completed around
12:54 local. Do not suppress these failures or treat a clean aggregate tail
summary as acceptance when individual functions were rejected.

## Width-Aware Output Follow-Up (Open)

Most target code uses only 16-bit registers; mixed 16/32-bit code must remain
supported. Reason: upper-register preservation should not clutter generated C
when those bits are proven unobservable. IR register effects/liveness must
provide the proof, and lowering must consume it; the frontend must retain
correct partial-register execution semantics. DoD: proven 16-bit-only uses
lower to word-valued operations, SP arithmetic still wraps at 16 bits, and
mixed-width reads plus call/return boundaries preserve all observable bits.
Tests must cover both simplification and refusal when upper-bit liveness is
unknown. Failure: infer safety merely from absent 32-bit instructions, erase
unknown call effects, drop wraparound, or repair rendered C with patterns.
This is not implemented by the scalar-return repair.

Stack-address size is independent of operand size. For an ordinary real-mode
16-bit stack, a 32-bit PUSH/POP operand changes SP by four, not the stack-address
width. Lowering should represent that as a word-sized SP update, not infer an
ESP merge from 32-bit operand use. Explicit wider-register observations still
require coherent overlapping state. Include this distinction in acceptance
tests; do not change the existing byte-safe frontend execution helpers.

The existing sidecar-free DrawBar executable regression reproduces the new
failure in 18.37s (one failed, seven dependency warnings):
`test_sortd_drawbar_sidecar_free_materializes_stack_buffer_and_conservative_return`.
It reports BP-0x2e instead of BP-0x2c argument dependencies and the empty-result
return contract violation. Reuse this focused loop rather than repeatedly
running all 20 functions. Log: `/tmp/inertia-return-drawbar-focused.log`.

The debug repeat confirms ReturnMaker enters the guessed-prototype,
caller-return-unused branch for DrawBar (`SimTypeShort`, empty incoming return
list). Capturing AX there ultimately exposes a returned void `outtext` call.
Investigate whether the existing producer-evidence decision incorrectly treats
incidental terminal AX state as a value return; caller non-observation alone
is not proof of a void return. Do not restore unsafe expression transport or
delete the call in lowering to silence the failure. The primary stack offset
mismatch also remains an independent acceptance obligation.
Debug evidence: `/tmp/inertia-return-drawbar-debug.log`.

## Call-Barrier Follow-Up

Terminal producer evidence crossed a later call. The source finder and its
predecessor path now refuse across side-effect statements and direct calls,
including assignment-wrapped calls. This does not infer void from caller
non-observation; it refuses the stale producer proof. Prototype-driven scalar
return capture remains in place.

The new intervening-call regression failed before the guard (one failed,
10 passed, 8.42s). Afterward it and the existing sidecar-free DrawBar regression
pass: **12 passed**, seven dependency warnings, 19.97s; DrawBar itself took
11.81s. Ruff `--fix`, scoped MyPy and interpreter-selected Pyright pass.
The executable test retains its stack-buffer, call-argument, recompilation and
tail-validation assertions. Logs: `/tmp/inertia-return-call-barrier-{before,after}.log`.
The preceding 18/20 result is historical evidence from before this guard;
broader gates and the whole executable must be rerun before landing. Additional
call shapes and predecessor/current-block boundaries still need focused audit.

Expanded call-form coverage now checks direct, side-effect-wrapped and
assignment-wrapped intervening calls: 13 unit cases pass in 8.52s. The
assignment fixture writes DX, not AX, to distinguish a stale AX producer from
a new definition of the return register. The first AX-assignment fixture had
the wrong refusal expectation and was corrected, not used to change production
semantics.

The post-guard combined hard/dev/fast/default run completed with exit 0:
2,936 tests per unit lane (126.32s fast, 114.93s default), three executable
quality guards, seven MS C tiny round trips and the pipeline's three selected
final checks. Log: `/tmp/inertia-return-call-barrier-gates.log`.

Final default executable run after the guard: **19/20 accepted**, exit 2,
191.08s wall, 443.03s user, 8.35s system, peak process RSS 356,040 KiB.
DrawBar, PercolateDown and QuickSort pass; InitMenu remains rejected.
Generated C is byte-identical to `c7fe4e0c0`:
`e3f8970e13403ace02bb95f77c2c20cf5bfeac6ea81a723020411c6518fc3936`.
Evidence: `/tmp/inertia-sortdemo-call-barrier.{c,log}`; completion 13:14:08 local.
This verifies the repaired checkpoint, not InitMenu, a green full suite, or
whole-plan completion. Timing is a single verification run, not a speedup claim.

Evidence in `/tmp`: `inertia-return-register-probe.log`,
`inertia-return-capture-before.log`, `inertia-return-capture-focused.log`,
`inertia-return-capture-context.log`, and `inertia-return-capture-pyright-venv.log`.
Observed timestamps from newly created log files: diagnostic start 12:32:47,
failing-before tests 12:34:59, broad verification start 12:38:57 local.
These exclude the preceding source investigation and are not a full active-work total.
