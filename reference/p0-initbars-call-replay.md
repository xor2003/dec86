# InitBars Call Replay

## Scope And Acceptance

Reason: current InitBars fails validation in named and sidecar-free modes with
one duplicate call and an uninitialized stack read. This blocks P0 generated-C
acceptance independently of the repaired InitMenu guards.

DoD: both InitBars regressions validate and strictly recompile; preserve one
execution of each binary callsite, source-equivalent seed argument flow,
initialized array/loop storage, and required calls. Add a generic regression
at the earliest producer of the duplicate or incorrect read. Scoped docs/types
and lint, followed by regular semantic gates, must pass.

Definition of Failure: deleting a potentially live register write without
evidence, treating two calls as interchangeable by name, suppressing duplicate
call validation, inventing a local initializer, or editing rendered C.

## Initial Reproduction

2026-09-07, current shared tree: `pytest -n 7 -k initbars` on
`test_x86_16_sortdemo_regressions.py` yields **3 failed, 1 passed in 65.83s**.
This selection includes ReInitBars as well as InitBars.

- Named and sidecar-free InitBars fail on `SS:BP-0x2:size2` uninitialized read
  and duplicate callsite `0x1056f`, target `0x1132c`, expected one, actual two.
- Named ReInitBars passes validation but fails an assertion requiring a `for`
  header. Its output has a `while` loop. Whether that fixture is obsolete
  requires checking initialization, guard, update, and call effects first.
- Sidecar-free ReInitBars passes its indexed-global-copy regression.

Source InitBars seeds with `srand((unsigned)time(NULL))` exactly once before
initializing sound/pause state, getting video configuration, and filling the
row arrays. Current partial output instead assigns `sub_1132c(...)` to the
EAX runtime lane, assigns the uninitialized `local_2` to that lane, then calls
`sub_11402(sub_1132c(...))`. The duplicate call and wrong read coexist before
the final rejected cleanup. The duplicate's producer is now isolated below;
the uninitialized read's producer and bounded repair are recorded below.
Do not attribute them to GP-state lowering merely because its runtime lane
appears in the output.

Baseline log: `/tmp/inertia-initbars-current.log`.
Read-only boundary probe: `/tmp/inertia-initbars-call-boundary.log`.
That probe terminated with exit 4 but captured no pass hooks: execution was
delegated to a canonical clean worker, outside the instrumented parent. It
confirms the failure, not a pass boundary. Instrument the worker itself or use
an existing worker-aware diagnostic path next; do not repeat parent-only
monkeypatches as if they traced child execution.
No InitBars semantic fix is claimed at this checkpoint.

## Diagnostic Boundaries And Existing Debt

Native worker-forwarded `--trace-c-stages --dump-layers` produced only
`0001_failed-core-partial-c.c` for this failure, not the earlier AST surfaces.
The first worker-inherited `sys.setprofile` probe also captured no watched
boundaries. Clean workers disable fork timeout lanes and execute analysis in
a thread; a probe must cover those threads as well as the parent interpreter.
These unsuccessful probes must not be cited as evidence that a pass did not run.
The subsequent `threading.setprofile` probe also terminated with exit 4 and
captured no watched boundaries. Thread coverage alone did not solve observation;
do not repeat either profiling setup unchanged. The stage functions are Python
functions in the expected source module (checked by runtime import), not
compiled replacements. Next, invoke the exact clean-worker entry under an
explicit instrumented launcher and verify hook installation inside its analysis
context before paying for another full decompilation.

`decompiler_postprocess_calls.py::_materialize_stdlib_call_chains_8616` contains
legacy name-based `time`/`srand` producer-consumer repair. That is incompatible
with generic evidence ownership and must eventually be replaced by typed
call-result/argument linkage. It is not yet proven responsible for the current
duplicate: its matching logic expects standalone call statements, whereas the
observed duplicate includes a runtime-register assignment. Do not simply delete
or extend that repair without preserving binary-proven call effects.

## ReInitBars Fixture Correction

The named ReInitBars failure is now resolved as a fixture issue, not a
production semantic repair. Its actual generated body initializes `iRow`,
tests `cRow > (short)iRow`, copies the indexed entry, draws it, and increments
once in a `while` loop. Requiring the `for` spelling rejected that valid form.

The regression now compiles and executes the extracted generated body for
zero, one, and three rows. It checks exactly one clock call, stored clock
value, copy-before-draw ordering, row order/count, and untouched entries beyond
the selected range. The harness uses the generated unsigned row-count contract;
it is not a proof for arbitrary signed or overflowing row counts. Existing
validation, compilation, storage/call, and scorecard assertions remain.

Focused result: one passed in 9.31s with `pytest -n 7`. Ruff `check --fix` and
helper MyPy pass. Log: `/tmp/inertia-reinitbars-executable-test.log`.
InitBars itself remains unresolved. Those initial collector/profile attempts
captured no usable boundaries; the subsequent direct-worker probe below does.

## Proven Duplicate Producer

The exact clean-worker entry, instrumented inside its analysis call, captures
one callsite `0x1056f` before `_materialize_callsite_stack_arguments_8616` and
two afterward. `_materialize_stdlib_call_chains_8616` runs later and preserves
that duplicate unchanged. It is migration debt, not this defect's producer.

The inner trace establishes the branch, not merely the outer pass:

- `_find_unique_standalone_return_call_ref_8616` finds zero consumable calls.
- `_nearest_standalone_return_call_8616` returns None.
- `_return_call_arg_from_ret_sources_8616` uses its recorded AX-result branch
  with a cached call expression and returns no consumed statement reference.
- The original call remains inside a masked EAX assignment. Direct-call shell
  matching does not recognize this carrier, but failure to match does not prove
  that the original execution disappeared. Replaying the cached expression
  introduces a second execution of the same machine callsite.

Worker logs: `/tmp/inertia-initbars-events-3658714.log` and
`/tmp/inertia-initbars-return-*.log`. The worker captures stderr internally;
probe events must use a separate file. Missing stderr hooks in the earlier
attempts were not evidence that those passes did not execute.

Next semantic repair belongs in typed call-result Lowering: preserve one
producer execution and bind each consumer to its proven result, accounting for
intervening register writes. Do not just delete the masked assignment, reuse a
possibly overwritten EAX value, or extend name-based stdlib repair. The existing
callsite multiplicity gate correctly rejects the duplicate and must remain.

## Recorded Argument Crash Checkpoint

A separate branch defect in the same recorded-return path returned a two-word
result even when the following source was not a matching AX/DX pair. A generic
numeric-callee regression with an AX result followed by immediate 7 reproduces
`UnboundLocalError` at the premature return. The return now stays inside the
existing proven-pair branch; scalar replay retains the second argument.
This changes no recovery rule and adds no semantic recovery to the legacy shim.

Focused evidence: 181 tests passed in 9.08s, including the full call-materializer
module and callsite-multiplicity shields. Ruff `check --fix` passes. The new
regression is enrolled in Make, the default pipeline, and changed-file ownership.
Scoped MyPy and Pyright pass for the changed compatibility module, and the
full architecture check passes. `quality-fast` still fails on 125 MyPy
diagnostic lines across the project (fresh run, not a subtraction estimate).
This bounded crash repair does not fix InitBars.

Default `test-pipeline` completes with exit zero: all three lanes pass,
2,180 unit tests pass in 121.14s, and all seven MS C tiny examples pass
build/run/decompile/recompile/decompiled-run. Slowest unit case: sidecar-free
RunMenu ESC preservation, 49.64s. Evidence logs are
`/tmp/inertia-recorded-return-{after,quality-fast,pipeline,architecture,mypy,pyright}.log`.
The full suite and remote CI have not been rerun for this change.

## Reload Instruction Ownership

The direct-worker constructor trace proves that
`real_mode_linear._insert_before_first_register_cvar_use_8616` creates the
early uninitialized read. Its caller has an exact `DirectStackReloadFact8616`,
but the insertion helper discarded that instruction identity and selected the
first read of the same physical register anywhere in the function. A later
reload was therefore placed between the time result and its push to srand.
The stable-stack pass preserves the original call/push flow; direct-stack MOV
replay inserts the bad read before GP-state lowering.

Evidence: `/tmp/inertia-initbars-assignments-3666063.log` and
`/tmp/inertia-initbars-constructors-3667143.log`. The constructor shows that the
variable displayed as `local_2` has a backing BP offset of -4; display names
must not substitute for canonical storage identity.

Repair: Lowering now requires the candidate consumer's exact instruction
origin (including the existing relocated-origin contract), carries the reload
instruction tag onto the inserted assignment, and refuses missing/mismatched
origins. Register-name matching alone is no longer placement evidence. It
also no longer treats an unrelated equal assignment elsewhere in the statement
list as proof that this reload is already represented.

Reason: a proven load value does not prove its execution point. Moving it
before an earlier consumer changes register and call effects.
DoD for this bounded placement repair: preserve earlier consumers, insert at
the proven reload, refuse unknown origins, retain storage identity and replay
idempotence, and remove the early BP-2 uninitialized-read failure in InitBars.
Failure: numerical address ordering or register spelling used as dominance,
invented initialization, removed potentially live code, or hidden validation.

Generic regression: fails before on an inserted assignment preceding the
earlier call. Afterward, 247 stack-lowering tests pass in 19.78s, plus 19
replay/idempotence tests in 9.37s. One older storage-identity fixture now tags
its modeled folded reload explicitly; its value/storage assertions remain.
New missing/mismatched-origin cases verify refusal.

Live InitBars/ReInitBars selection: **2 failed, 2 passed in 84.29s**.
The early `SS:BP-0x2` uninitialized read is no longer reported. InitBars still
fails callsite multiplicity; rejected cleanup additionally reports the
`SS:BP-0x5a:size86` array initialization issue. Both ReInitBars cases pass.
This is a narrower verified improvement, not whole-function acceptance.
Log: `/tmp/inertia-initbars-reload-origin.log`.

Default `test-pipeline` passes all three lanes: 2,183 unit tests in 122.93s
and all seven MS C tiny build/run/decompile/recompile/decompiled-run checks.
`quality-dev` completes with exit zero, including its 2,183-test unit lane in
114.93s and all executable guards. Global `quality-fast` fails with 125
MyPy diagnostic lines. Scoped Ruff/MyPy/Pyright pass, including the concrete
near-function-pointer binding annotation corrected in the touched module.

Timing: first instrumented worker started at 2026-09-07 19:45:35 +02:00
(log creation timestamp); the completed gates were checked at 20:01:24
+02:00, approximately 16 minutes elapsed including waits. This is measured
checkpoint wall time, not a forecast for the remaining call/array repairs.

## Runtime Result Read Checkpoint

The new `lowering/runtime_call_results.py` owns a read-only proof for an exact
tagged callsite already published through the GP-state owner's low-word write.
It requires a unique producer in the current straight-line prefix and only
disjoint, explicitly modeled intervening writes. Calls, branches, overwritten
AX/AL, unsupported destinations/expressions, and mismatched write shapes refuse
reuse. It preserves the producer assignment and reads the low word of EAX;
it does not move/delete a statement or create another call.

The legacy call bridge consumes the typed verdict before considering its old
cached-expression path. A live producer that cannot be reused is refused, not
cloned. The compatibility import is explicitly documented and admitted by the
architecture guard; the proof itself remains in Lowering. The new owner and
tests are enrolled in architecture, Make typing/lint, pipeline, and ownership
inventories. The startup guard initially caught the unregistered edge, as
intended; that failed setup run is not a semantic regression result.

Reason: cached expression identity does not grant permission to repeat an
observable call. A physical return-register source needs a proven value read.
Bounded DoD: preserve one producer execution and its GP write; materialize the
correct low-word argument only with uninterrupted evidence; reject clobbers and
ambiguity; keep multiplicity validation enabled; pass local regression/gates.
Failure: use a stale register value, delete a live assignment, infer from a
callee name, or relax callsite multiplicity or storage validation.

The generic integration regression fails before with two executions of the
same callsite and passes afterward with exactly one, the original assignment,
and the exact AX/EAX low-word view as the consumer argument. Combined focused
tests: **193 passed in 16.22s**, including the call-materializer suite and
multiplicity shields. Scoped Ruff, MyPy, Pyright, and full architecture pass.

Live named/sidecar-free InitBars and ReInitBars selection: **2 failed, 2 passed
in 90.33s**. Output now contains one seed-producing call followed by
`sub_11402(inertia_eax & 0xffff)`; the duplicate-call diagnostic is gone.
InitBars is still rejected, not fixed: the primary final guard now reports
three uninitialized `SS:BP-0x72:size2` reads in the initial condition. The
partial output passes `&local_70` and SS to `sub_12ac8`, while its condition
reads fields of `stack_sp_m72_2`. Next inspect their typed call-output/object
identity and coordinate projections before assuming the array loop is the
remaining root cause. Other rejected candidates also report array/local reads.
Do not initialize these objects speculatively or teach the validator to ignore
them. The first, early BP-2 overwrite remains removed; later BP-2 diagnostics
do not establish that the seed-sequence defect returned.

Logs: `/tmp/inertia-runtime-result-{before,proof-tests2,mypy,pyright,architecture}.log`
and `/tmp/inertia-initbars-runtime-result2.log`.

Final gates: `quality-dev` passes, including 2,196 unit tests in 102.47s and
all three executable quality guards. Default `test-pipeline` passes all three
lanes, with 2,196 unit tests in 131.96s and all seven MS C tiny round trips
passing build/run/decompile/recompile/decompiled-run. Global `quality-fast`
still fails with 125 MyPy diagnostic lines. These are local shared-tree
checkpoints, not a full-suite or remote CI acceptance result.

Timing: the first generic-regression log was created at 2026-09-07 20:04:56
+02:00; completed gates were verified at 20:25:20 +02:00. That measured
interval is approximately 20 minutes including waits, excluding earlier design
inspection. Logs: `/tmp/inertia-runtime-result-{quality-dev,quality-fast,pipeline}.log`.

## Configuration Object Coordinate Publication

Checkpoint verified 2026-09-07 20:46 +02:00. Exact worker instrumentation
shows a call-source BP offset of -112 and fields at -98/-94, but the initial
field carrier has raw entry-SP offset -114 and no coordinate projection.
Later call argument lowering creates a different, correctly projected carrier.
The original field therefore resolves two bytes away from its proven address.

Lowering now publishes the call-addressed object's exact coordinate and closed
extent before applying its struct type or emitting fields. The focused owner
preserves physical carrier size, attaches aliases to existing canonical storage,
and refuses conflicting coordinates. This is storage identity evidence, not
proof of initialization by the callee. No validator exception was added.

- Reason: call arguments and field accesses must describe the same proven storage.
- DoD: generic biased-carrier, replay, and refusal regressions pass; scoped
  types/lints pass; live output loses this coordinate diagnostic without losing
  calls or introducing guessed writes. Full function acceptance still requires
  validation and strict recompilation.
- Definition of failure: accepting conflicting storage coordinates, treating
  layout as initialization, or declaring InitBars fixed from a focused pass.

The initial regression failed at BP -114 versus expected -112. After the fix,
36 focused tests pass. Scoped Ruff (check --fix), MyPy, Pyright, and the full
architecture check pass. Four typing errors in the touched recovery owner were
also corrected without suppressions.

Live selection: two passed, two failed in 94.07s. The configuration-field read
diagnostic disappears; the final sidecar-free guard now reports two reads of
the BP-90 array (size 86). A forbidden `ss << 4` expression also remains.
InitBars is not accepted. Next trace those array reads and their preceding
writes through typed storage/effect evidence, without speculative initialization.

Evidence: `/tmp/inertia-config-object-3688610.log`,
`/tmp/inertia-config-projection-tests.log`,
`/tmp/inertia-config-projection-final.log`, and
`/tmp/inertia-initbars-config-projection.log`. The earlier broad gates above
predate this coordinate change and are not its acceptance evidence.

Fresh broad checks for this change: default `test-pipeline` exits zero with
2,202 unit tests passing in 114.04s and all three lanes passing, including
seven MS C tiny compile/run/decompile/recompile/run cases. Global `quality-fast`
still exits two with 121 MyPy error lines. The focused final rerun passes 36
tests in 10.74s. Logs: `/tmp/inertia-config-projection-pipeline.log` and
`/tmp/inertia-config-projection-quality-fast.log`. No new full-suite or remote
CI acceptance is claimed.

## Generated Read Helper Effects

The next exact-worker trace proves the prefix initialization loop is recognized
and the random-call contract preserves the count at DS:2978. Two subsequent
`MEM_U16` nodes, each carrying `inertia_x86_16_runtime_pointer_helper=MEM_U16`,
were nevertheless treated as unknown calls. Their invalidation erased the
prefix and bounded-index facts immediately before both indexed array reads.
This is not missing initialization or a failure to recognize the loop.

Lowering now exposes a proof-bearing reader for that existing generated tag:
the node must have the matching exact helper target, one pointer argument,
and no machine callee object. Structuring consumes that typed identity and
still walks nested argument calls. Untagged, mismatched, and nested unknown-call
cases refuse. No name-only exemption, deletion, or validation policy change
was added; the large Structuring owner receives only the small consumer hook.

- Reason: generated reads must not masquerade as unknown memory-writing calls.
- DoD: reproduce lost proofs, preserve both exact read proofs for tagged reads,
  retain unknown-call invalidation, pass focused and broad gates, and check
  live validation separately from generated-C recompilation.
- Definition of failure: accepting a name alone, ignoring argument effects,
  changing memory or calls, or calling a forbidden-address payload accepted C.

Before: one generic regression fails, three refusal cases pass. After: all
26 helper/range tests pass in 9.09s; scoped Ruff/MyPy/Pyright pass. Both test
modules are now explicitly included in the default test pipeline.

Live selection: two pass, two fail in 96.75s. The sidecar-free run now reports
whole-tail validation clean across one function, with both stages stable;
the output contract still rejects `ss << 4`. Named-mode rejected candidates
retain additional local-read diagnostics. InitBars and P0 remain open.
Next repair the indexed stack-address materialization at its typed Lowering
owner; do not remove the raw loads merely because another statement looks similar.

Logs: `/tmp/inertia-indexed-range-events.log`,
`/tmp/inertia-helper-prefix-{before2,after}.log`, and
`/tmp/inertia-initbars-helper-prefix.log`. The live run completed around
2026-09-07 20:58 +02:00; broad gate results are recorded separately below.

Fresh gates: `quality-dev` passes 2,228 unit tests in 135.22s and all three
executable guards. Default `test-pipeline` passes all three lanes, including
2,228 unit tests in 113.85s and all seven MS C tiny round trips. Global
`quality-fast` remains failing with 121 MyPy error lines. Logs:
`/tmp/inertia-helper-prefix-{quality-dev,quality-fast,pipeline}.log`.
These are local results; the full-suite failures and remote CI remain open.

## Indexed Frame Consumption

The indexed fallback selects the binary BP displacement (-90), substitutes a
local C pointer, and previously retained the original SS base and BP anchor
in its residual terms. Exact-worker diagnostics show residuals consisting of
SS shifted by four, zero, a reference to an unprojected entry-SP -2 carrier,
and SI (with an optional high-byte lane offset). Combining those residuals
with a local pointer counted the frame twice.

The ordinary legacy stack resolver reports -2 for that unprojected carrier;
the existing entry-SP anchor contract is the correct owner for translating it
using proven frame evidence. Lowering now consumes exactly one positive SS
base and one proven BP-zero anchor, preserving index and byte-lane terms.
Foreign segments, ambiguous anchors, and unknown frame coordinates refuse.
Already offset-only input retains its existing indexed-proof path.

- Reason: replacing a linear address with a C local must consume its proven
  frame, and matching a displacement must never convert DS storage into SS.
- DoD: reproduce frame duplication and foreign-segment misclassification;
  pass generic positive/refusal regressions and scoped gates; verify live
  removal of the forbidden flattening while retaining tail validation.
  Full InitBars acceptance additionally requires valid declared C storage.
- Definition of failure: dropping an unproven term, mixing segments, losing
  index/lane offsets, or reporting clean tail validation as recompilation.

Before: two generic tests failed (SS duplication and DS-to-stack conversion),
one unknown-frame refusal passed. After: 81 stack/coordinate tests pass in
17.04s. A separately exposed GP-lowering boundary crash was repaired: opaque
third-party dirty expressions without a category now provide no register
proof instead of raising AttributeError. The existing unknown-offset test
retains both refusal and expression-identity assertions.

Live selection: two pass, two fail in 98.26s. Sidecar-free whole-tail remains
clean and `ss << 4` is gone; the final payload instead refuses unresolved
stack locals. The indexed pointer still uses a separate byte carrier rather
than the declared array. Next reconcile that carrier with the authoritative
aggregate object in Lowering; do not repair it by renaming rendered C.

Evidence: `/tmp/inertia-indexed-address-events.log`,
`/tmp/inertia-indexed-frame-{before,after,focused}.log`, and
`/tmp/inertia-initbars-indexed-frame.log`. Broad checks follow below.

Final checkpoint verified 2026-09-07 21:18:52 +02:00: `quality-dev` passes
2,231 tests in 113.80s and all three executable guards. Default pipeline
passes all three lanes, with 2,231 unit tests in 163.96s and all seven MS C
tiny round trips. Global `quality-fast` still reports 121 MyPy errors.
Scoped Ruff/MyPy/Pyright pass for the touched coordinate and GP modules;
GP architecture/return/expression annotations were also corrected without
suppressions. The first quality-dev attempt refused undocumented dynamic
access; explicit dynamic-angr-boundary comments satisfy the unchanged ratchet.
Logs: `/tmp/inertia-indexed-frame-{quality-dev2,quality-fast,pipeline}.log`.
Full-suite and remote CI acceptance remain open, as does InitBars final C.
