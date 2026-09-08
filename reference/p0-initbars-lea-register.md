# InitBars LEA Register Projection

## Verified Boundary (2026-09-07)

Status: investigation, not a completed fix. The current sidecar-free InitBars
payload has a correctly typed configuration struct and clean whole-tail
validation, but strict GCC rejects pointer arithmetic in an AX publication.

Direct Capstone decoding of the MZ image establishes:

```text
1058e: lea ax, [bp - 0x70]
10591: push ss
10592: push ax
10593: nop
10594: push cs
10595: call 0x12ac8
10598: add sp, 4
```

These addresses identify the diagnostic input, not a production allowlist.
No sidecar or callee name was used as semantic proof.

The observation wrapper around `lowering/gp_register_state.py`'s
`_runtime_gp_subview_write_8616` recorded the original instruction tag
`ins_addr=66958` (`0x1058e`), width 2, bit shift 0, and this typed input:

```text
Add(Sub(Const(0), Const(112)),
    CTypeCast(unsigned short, Reference(SimStackVariable)))
```

The stack carrier has raw offset -2, size 1, base `bp`, and no exact
`stack_variable_coordinate_registry_8616(...).for_variable(...)` projection.
The missing registry entry does not prove that all other frame evidence is
absent. Inspect the authoritative frame/SSA evidence before drawing that claim.

Call path: `run_segment_global_materialization_8616` ->
`apply_runtime_segment_lowering_8616` ->
`lower_architectural_gp_register_state_8616` ->
`_runtime_gp_subview_write_8616`.
The writer preserves the upper EAX word and masks the supplied value into AX.
An ordinary cast in that value is later hidden during rendering, exposing
`-112 + &v6 & 0xffff`. Forcing a host-pointer cast alone does not establish
the original machine offset.

Evidence: `/tmp/inertia-lea-register-events.log`,
`/tmp/inertia-lea-register-worker.json` (`status=validation_failed`). The
diagnostic worker completed; transport exit zero is not semantic acceptance.
No production code changed during this investigation.

## Next Repair

- Reason: one machine address currently crosses the boundary between numeric
  register state and host C object pointers without a proven conversion.
- Order: inspect the original IR/SSA definition and frame-base evidence;
  preserve the numeric near-offset view separately from the object-pointer
  call-argument view; materialize those views in Types/Lowering. Consider
  removing call setup only after exact use/liveness and callee-input evidence
  proves that all observable uses are consumed.
- DoD: regression cases retain the numeric result when read, stored, branched
  on, or passed onward; preserve high EAX bits and 16-bit wrap semantics;
  refuse unknown frame evidence. The InitBars call must retain the pointer
  argument and segment class, strict GCC and whole-tail must pass, and the
  executable MS C round trips and relevant full-suite cases remain green.
- Definition of failure: a host-pointer-to-integer cast used as machine-offset
  proof; guessed BP/SP values; deleting a register write merely because its
  explicit C argument was recovered; address/name-specific replacement; or
  introducing semantic recovery in CLI/Rewrite.

The separate SI/ESI publication audit remains open. This investigation does not
prove those indexed reads redundant or repair their reaching definitions.

## IR/SSA Follow-Up (2026-09-08)

The bounded follow-up worker completed with the same acceptance failure.
`registered_function_ssa_artifact_8616` reports `PROVEN`, and
`proven_bp_entry_sp_delta_8616` returns -2. The original numeric definition is
still present at the LEA instruction:

```text
t123 = Add16(0, 65424)
t124 = bp
t125 = Add16(t123, bp)
ax = t125
```

Here 65424 is the 16-bit encoding of -112. The source temporary references
retain 123/124/125; the entry block also retains `bp = sp` at 0x10561.
Thus the absent exact C-variable registry entry is not absent frame proof,
and the IR has not replaced the numeric address with a host pointer. The next
repair belongs at the IR/SSA-to-C numeric-register projection, or at a proven
consumed-definition boundary, not in the lifter or rendered-C cleanup.

The current GP pass selects architectural register names and then lowers
narrow writes to those names. This alone is not per-definition liveness.
The call-setup deletion consumer uses whole-variable identity sets, which do
not by themselves distinguish preserved high EAX bits from overwritten low
AX bits. These are investigation targets, not proof that this particular
setup is removable. A call being caller-saved does not prove it ignores the
incoming register value.

For the numeric path, determine how an entry-frame value survives runtime
SP/BP changes before using a runtime register as its replacement. For the
consumed-setup path, require exact producer/use provenance, bit-range liveness,
and callee-input evidence. Do not introduce a disconnected proof module that
the actual materializer does not consume.

Evidence: `/tmp/inertia-lea-ssa-events.log` and
`/tmp/inertia-lea-ssa-worker.json`. No production changes or new green-test
claims accompany this diagnostic step.

## Consumed-Setup Probe (2026-09-08)

A fresh sidecar-free direct worker observed the actual calls to
`_delete_consumed_indices_8616`, without changing its arguments or result.
There were two deletion calls for InitBars. At the configuration call, the
LEA-tagged assignment (`ins_addr=0x1058e`) was statement index 6 and was **not**
in the candidate indices. The candidates were assignments 13 and 14, both
tagged with the call instruction at `0x10595`.

Consequently, improving the bound whole-variable liveness classifier alone
cannot remove this LEA in the observed path. Do not build a bit-liveness
module and claim it fixes InitBars without proving that the real producer
reaches its consumer. Prioritize the numeric register projection; alternatively,
establish exact consumed-producer ownership earlier before considering DCE.

The instrumented worker finished in 42.54s with `status=validation_failed`,
both whole-tail stages stable, and no validated or GCC-checked payload hash.
The pointer-valued AX expression and the typed pointer/segment call both
remain. This is diagnostic timing, not a performance baseline: Python
profiling was enabled to observe the nested cleanup boundary.

Evidence: `/tmp/inertia-lea-candidates.jsonl`,
`/tmp/inertia-lea-candidates-worker.json`, and
`/tmp/inertia-lea-candidates-run.log`. The graph had an August 27 generation
with changed/untracked source coverage; exact source and the live worker were
used for these bounded claims. No production semantic change was made.

## Runtime Projection Boundary

Source inspection rules out two tempting substitutions:

- `lowering/stack_pointer_snapshot.py` consumes `NearPointerArgumentFact8616`
  and preserves a saved pointer loaded from a BP-relative argument slot across
  updates. It is not an entry-SP/BP numeric frame snapshot. Reusing its name
  as evidence for the LEA would conflate pointer versions with frame values.
- `lowering/c_runtime_header.py` defines portable `PTR_U16` by truncating
  `uintptr_t`. Its segmented helpers index `inertia_memory`, whereas generated
  local objects are host C locals. That cast does not map a local object's
  address back into guest SS offsets. It cannot establish numeric LEA semantics.

Before introducing an entry-frame snapshot, prove the runtime SP value at
function entry and its caller/callee transport; an immutable copy of an
unproven runtime register remains unproven. Stack execution carriers may
already have been consumed into ordinary C calls and locals. The numeric and
object views therefore need a coherent frame contract, not just an additional
local declaration. Do not add a new runtime pointer-conversion helper without
the corresponding guest/object mapping and executable validation.

The existing synthetic-call register classifier explicitly refuses real
callee bodies. `FunctionStateSummary.gp_register_inputs` partitions supplied
metadata; it does not itself prove a callee ignores AX. Neither can justify
dead-setup deletion for this real callee. Continue with exact IR producer/use
and real-callee input evidence if choosing the consumed-definition route.

## InitMenu Comparison (2026-09-08)

The full audit also reproduced pointer-valued AX writes in sidecar-free
InitMenu. A diagnostic worker replaced only
`gp_live_in_names_from_ssa_8616` and its helper with their HEAD implementations,
loaded from Python AST into an isolated runtime namespace. No worktree source
was reverted. This tests the old name-level classifier against the new
bit-aware classifier without changing the surrounding pipeline.

The old classifier still yielded `validation_failed`, stable structuring and
postprocess tails, and no accepted/GCC-checked payload hashes after 28.91s.
Its AX publications still contain `-18 + &local_2 & 0xff & 0xffff`.
Thus the bit-aware live-in change alone does not cause or repair the observed
InitMenu pointer/register failure. This diagnostic does not prove all other
recent changes harmless or establish a timing comparison.

Evidence: `/tmp/inertia-initmenu-previous-live-in.json` and
`/tmp/inertia-initmenu-previous-live-in.log`. The next repair must cover both
InitMenu and InitBars projections; do not downgrade live-in correctness to
hide the missing numeric/object boundary.
