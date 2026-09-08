# InitMenu Local-Read Preservation

## Scope And Status

2026-09-07: correctness repair in progress; **InitMenu is not fully fixed**.
Performance work remains deferred under `SORTD_GHIDRA_PLAN.md`.

The late dead-local pruner removed the zero initializer before the loop.
Its hand-maintained read traversal omitted indexed-variable base/index fields
and for-loop initializer/iterator fields. The shared structured-C child
inventory already includes those fields.

Read-key collection now lives in
`X86_16/postprocess/optimization/local_read_keys.py`, consuming the shared child
inventory and existing alias/liveness identities. The CLI delegates to it.
This is cleanup correctness, not new semantic recovery or a speed optimization.
The CLI module loses about 100 lines; no large production file was expanded.

## Acceptance

Reason: no assignment may be declared unread because a consumer omitted an
existing structured expression or control-node child.

DoD for this repair: fail-before/pass-after tests for indexed bases, indexed
subscripts, and for-loop iterator reads; existing dead-local regressions pass;
live InitMenu retains the binary-proven initializer; scoped typing/docs/lint
and regular quality/executable pipelines pass. Full InitMenu closure separately
requires clean validation, compilation, calls, and source-comparison acceptance.

Definition of Failure: deleting a live initializer, treating an assignment's
plain destination as a value read, disabling pruning indiscriminately, adding
source/address-specific protection, or claiming function acceptance while
buffer storage and argument validation still fail.

## Evidence

- Three new structured-read regressions fail before the repair in 10.27s.
- After repair, all 14 new/existing dead-local tests pass in 9.15s with `-n 7`.
- Scoped Ruff `check --fix` and MyPy pass. Initial quality-dev attempts exposed
  missing future annotations and insufficient dynamic-boundary comments;
  those documentation/type-ratchet issues were corrected, not suppressed.
- Live InitMenu pair: **1 passed, 1 failed in 109.03s**. Sidecar-free passes.
  Named output now contains `i = 0;` before the loop, and the four final
  uninitialized-loop reads disappear. Separate buffer mismatches remain:
  expected `BP-0x12`, observed `BP-0x10`, and missing 16-byte stack object.
  The initializer need not be inside the `for` header to execute correctly.
- Default pipeline unit lane: **2,117 passed**, 7 warnings in 105.43s.
  All three default lanes pass, including Ultra QuickC and the seven MS C tiny
  compile/decompile/recompile round trips. Final `quality-dev` also passes,
  including the changed-file type/doc ratchet and its required test lane.
  The separate full architecture check also passes.

Temporary logs: `/tmp/inertia-dead-local-structured-before.log`,
`/tmp/inertia-dead-local-structured-after.log`,
`/tmp/inertia-initmenu-read-fix.log`, `/tmp/inertia-local-read-quality-dev.log`,
and `/tmp/inertia-local-read-pipeline.log`.

## Investigation Lessons

The decisive probe observed the zero assignment disappear exactly across
`_prune_dead_local_assignments` during late finalization. Earlier setter traces
showed lowering clearing a for-loop initializer fragment, but path capture
proved it retained the zero write before the loop. Do not undo that instruction
fragment deduplication on this evidence. Broad rollback inventories and mixed
process log order did not locate the final loss and must not be treated as a
proven rollback bug. Use active-root, bounded-pass diagnostics.
The confirming boundary trace is `/tmp/inertia-initmenu-cli.log`; instruction
fragment locations are in `/tmp/inertia-initmenu-path.log`. These are temporary
diagnostics, not required source artifacts or acceptance shortcuts.

Next: resolve the buffer's machine-BP/entry-SP identity mismatch at its earliest
owner. Do not patch buffer names, argument text, or rendered loop formatting.

### Buffer Replay Regression (Open)

Live publication tracing now records the same 16-byte object as machine BP
`-18` / entry SP `-20`, first with `variable.offset=-20`, then with
`variable.offset=-18`. Both publications come from
`stack_aggregate_objects.py::_materialize_fact`.

The new focused `test_x86_16_stack_aggregate_coordinate_replay.py` reproduces
this with no executable addresses or source-name recovery: an existing exact
projection and its explicitly reconciled byte-fragment alias are both on the
declaration surface, with the fragment first. Replay chooses that fragment by
list order and replaces the canonical 16-byte projection, dropping its aliases.
Before repair the test fails at canonical-variable identity: **1 failed in
8.10s**. The pending projection-selection helper now preserves the existing
canonical view and aliases; its focused aggregate tests pass **31 in 8.50s**.
This is not function acceptance: the live pair remains **1 failed, 1 passed
in 81.64s** (`/tmp/inertia-initmenu-aggregate-fix.log`). Named InitMenu still
has expected BP-0x12 versus actual BP-0x10 call-buffer mismatches and a missing
16-byte object; sidecar-free passes. The next investigation must trace the
remaining consumer identity rather than assume publication replay alone fixes
the live failure.

Reason: replay must preserve an authoritative coordinate projection instead
of changing storage identity according to declaration order.
DoD: preserve the active canonical projection and reconciled views across
replay/cloning; keep narrow-storage/wide-value tests valid; both live InitMenu
paths validate and compile with correct buffer arguments. Add refusal or
fallback coverage when the canonical view is genuinely absent.
Definition of Failure: shifting raw offsets without coordinate proof, relying
on buffer names, dropping live aliases, or accepting shifted call arguments.
Temporary evidence: `/tmp/inertia-initmenu-coordinates.log` and
`/tmp/inertia-aggregate-replay-before.log`.

### Current Consumer Trace (2026-09-07)

After the INC/DEC repair and subsequent typing work, the live pair still
reports **1 failed, 1 passed in 124.66s**: named InitMenu takes 68.60s and
fails; sidecar-free InitMenu takes 46.54s and passes. The final named failures
remain shifted call buffers (expected BP-0x12, actual BP-0x10) and the missing
16-byte object. This is not closed by the green regular development gate.

A read-only consumer/publication probe narrows the ownership sequence:

- Variable identifier `is_13`, raw offset -18, size 1, is first published by
  `stack_lowering_from_facts.materialize_stack_cvar_at_offset_from_facts_8616`
  as machine BP -16 / entry SP -18. Its candidate selection matches the raw
  entry-SP offset and promotes/reconciles matching declarations.
- A separate raw -20 view is published as BP -18 / entry SP -20, then used
  for the 16-byte aggregate.
- Later aggregate publication and restored-registry rebinding publish an
  `is_13` raw -18 view for the BP -18 / entry SP -20 aggregate as well.
- The consumer trace observes the earlier BP -16 binding as an exact registry
  match. Thus blaming only the containing-entry-SP fallback is unsupported.

Next: distinguish object clones from same-object reuse (the current compact
trace records identifiers but not every variable object's identity), then
reproduce the first conflicting binding across materialization and restored
registry replay. Numeric offset equality alone must not reconcile different
coordinate domains; conversely an unregistered angr variable must not simply
be assumed machine-BP-relative. Fix that proven boundary, not call argument
text or validation diagnostics. No new production repair is claimed here.
Temporary logs: `/tmp/inertia-initmenu-current-pair.log`,
`/tmp/inertia-initmenu-consumer-trace.log`, and
`/tmp/inertia-initmenu-publication-trace.log`.

### Same-Object Replay And Multiple Views

The identity-extended trace confirms that the first BP -16 scalar and the later
BP -18 aggregate reuse the same `SimStackVariable` object, not just the same
`is_13` identifier. At the later aggregate publication, `for_variable` reports
no prior projection, narrowing the transition to the local-registry reset and
replay interval. Restored-registry retention subsequently carries that aggregate
with raw offset -18, narrow size 1, and declared entry-SP offset -20/size 16.

A separate focused selection hole was reproduced: multiple caller-proven
entry-SP views caused the pending helper to fall back to the first raw-BP
candidate. The helper now retains entry-SP preference regardless of multiplicity.
Before: 1 failed, 2 passed in 8.28s. After: all 38 aggregate/rebinding tests pass
in 16.39s; Ruff/MyPy/Pyright pass for the helper. Explicit annotations preserve
the concrete CVariable contract through identity-based candidate selection.

This does **not** resolve named InitMenu: the live pair remains 1 failed,
1 passed in 91.53s, with the same three shifted buffer arguments and missing
16-byte object. Do not repeat the multiple-entry-view experiment as the live
root cause. Next trace candidate membership and live AST references across
registry reset/rebinding, particularly narrow backing variables retained for
wide aggregate projections. The helper and its regression remain uncommitted
with the larger aggregate repair; full function acceptance is still required.
Logs: `/tmp/inertia-initmenu-identity-trace.log`,
`/tmp/inertia-aggregate-multiple-before.log`,
`/tmp/inertia-aggregate-multiple-after.log`,
`/tmp/inertia-initmenu-multiple-pair.log`.

### Narrow-Backing Rebinding And Exposed Guard Loss

Restored-registry selection required both the full aggregate width and its
entry-SP offset. It therefore could not bind a cloned narrow backing view,
even with the exact recorded identifier, base, offset, and width. Rebinding now
accepts that explicit backing identity in addition to full entry-SP views;
different identifiers remain rejected. The focused regression has two failures
before (8.21s); all 42 aggregate/rebinding tests pass after (9.04s). The fixture
now uses a real 16-byte array and checks its semantic value width; its complete
module passes 10 tests in 8.98s. Scoped Ruff/MyPy/Pyright pass.

This clears the live named InitMenu buffer failures: direct output now has one
`ach[16]` object, matching buffer arguments, successful compilation and tail
validation. The old test then failed only on obsolete formatting requirements:
an extra inner loop guard absent from source and rejection of an equivalent
nonzero-pause early return. The loop assertion now rejects that redundant guard;
the zero-pause assertion checks either exact source-compatible control form and
its required output calls. At this point both live tests pass (12.37s).

However, source/binary comparison exposes a separate semantic failure that
tail validation currently misses. The binary instructions at 0x10174 compare
DS:0132 to 900; at 0x1017f they compare DS:0134 to zero. Either mismatch skips
the limit-output block. Generated C instead tests only
`(clPause & 0xffff) == 900`.

The new executable helper `x86_16_initmenu_execution.py`, called by the existing
named regression, compiles the actual generated function with strict GCC
warnings and observes output calls for pauses 0, 900, and 0x10384. The last case
incorrectly produces limit output. Expected versus actual:

```text
pause       expected(limit,zero) actual(limit,zero)
0           (0,1)                (0,1)
900         (1,0)                (1,0)
66436       (0,0)                (1,0)
```

The live regression now fails on that behavior (12.39s), rather than on an
arbitrary C spelling. An isolated diagnostic control using the full-width
comparison passes the same harness; no rendered-C repair is used in production.
Next P0 work: locate the high-word condition's loss in IR/structuring and add
a generic validation regression so this cannot receive `validation=passed`.
InitMenu is **not fully accepted**. The rebinding repair remains uncommitted,
and broad gates must be rerun before claiming completion of the combined fix.
Logs: `/tmp/inertia-narrow-rebind-before.log`,
`/tmp/inertia-narrow-rebind-after.log`, `/tmp/inertia-initmenu-rebound.log`,
`/tmp/inertia-initmenu-high-word-before.log`.

## High-Word Loss: Proven Pass Boundary

Read-only uncached tracing on 2026-09-07 narrows the loss to
`structuring/condition_materialization.py::materialize_structuring_condition_chains_8616`.
The preceding typed-condition and decoded-JCC passes preserve the compound
predicate. Chain materialization changes it to the low-word comparison alone,
inside validation priming and before the first tail-validation summary.

The typed facts still contain both comparisons. In normalized CFG coordinates,
the low-word branch is block 4369, instruction 4378; its false target is 4380.
The high-word branch is block 4383, instruction 4388; its false target is 4390.
Both 4380 and 4390 lead to continuation 4425. The chain builder uses the first
false target as an exact terminal, follows the other failure path beyond the
shared continuation, reaches exit 4469, and refuses reconstruction. The
single-branch implementation then permits root-predicate fallback. Thus a
failed compound proof can still produce a narrower predicate.

Next repair belongs in Structuring's CFG condition proof, not the legacy JCC
compatibility file or rendered-C cleanup. Prove equivalent branch exits with
appropriate effect preservation, and refuse root-only substitution when the
existing compound condition is not fully accounted for. Add a generic
two-guard/shared-continuation regression and an incomplete-proof refusal case.

Reason: failure to reconstruct a condition chain must never authorize dropping
one of its guards. DoD: both guards survive, the executable InitMenu high-word
case passes, incomplete proof retains code, and focused plus regular semantic
gates pass. Definition of Failure: accepting the root comparison alone,
equating paths that contain different effects, or moving the validation
baseline after the loss and reporting success.

Probe logs: `/tmp/inertia-initmenu-inner-passes.log` and
`/tmp/inertia-initmenu-chain-proof.log`. Both commands terminated successfully;
that is diagnostic execution success, not function acceptance. Native layer
dump flags alone hit a lower function cache in an earlier probe; live tracing
used `INERTIA_DEBUG_TIMING=1` to bypass it. Do not repeat cached probes as
evidence of pass execution.

### Compound Refusal Guard (Pending)

The single-branch fallback now refuses root-only substitution if its existing
expression contains a logical conjunction or disjunction and CFG chain
reconstruction failed. It does not disable successful compound reconstruction.
New generic tests cover AND, OR, negation, single-comparison controls, successful
proofs, and absence of replay publication after refusal. Before: four semantic
failures and two passing controls (8.16s). After, including successful-proof
cases and the existing condition-materialization module: 47 passed (9.26s),
using `pytest -n 7`. The new module is enrolled in Make, the regular pipeline,
and test ownership. Ruff `check --fix` and scoped MyPy pass. Pyright still has
one separate arm-body type mismatch at `node.condition_and_nodes`; it is not
silenced. Broad semantic gates have not been rerun for this partial repair.

Live named InitMenu now retains the high-word byte checks, but fails strict
GCC compilation with `-Werror=int-in-bool-context` on the retained byte
expression (one failed test, 58.50s). This is not final function acceptance.
Complete shared-exit reconstruction remains necessary; do not delete the
preserved guards or weaken GCC to make this test pass. Logs:
`/tmp/inertia-chain-refusal-before.log`, `/tmp/inertia-chain-refusal-after.log`,
and `/tmp/inertia-initmenu-refusal-live.log`.

### Shared-Exit Evidence And Body-Type Closure

The next live probe reads the registered semantic SSA artifact, rather than
inferring transparency from CFG topology. Blocks 4380 and 4390 both have
empty instruction and refusal tuples. Continuation 4425 contains instructions.
This supports normalizing these empty failure-path blocks to their shared
continuation, while stopping before its effects. The next implementation must
require matching authoritative edges and refuse missing/refused/effectful
blocks or cycles; no generic single-successor shortcut is justified.
Evidence: `/tmp/inertia-initmenu-exit-ssa.log`. The probe exits 4 because strict
generated-C compilation remains unresolved, not because SSA collection failed.

The separate Pyright mismatch is now resolved without a consumer suppression:
`MultiArmConditionMaterializationResult8616` preserves its input arm-body type
through a generic contract. Its consumer no longer casts those bodies to
`object`. Existing tests now assert exact body identity. Scoped Ruff, MyPy,
and Pyright pass for both Structuring owners. The combined three-module
regression run passes 50 tests (9.71s); the added body-identity assertions also
pass in a subsequent focused run. This does not close live InitMenu or CI.

## Shared-Exit Implementation Checkpoint

`structuring/condition_exit_normalization.py` now normalizes the false terminal
through empty SSA blocks with matching predecessor/successor evidence. It
stops before instructions, bindings, and phi nodes; missing blocks, cycles,
refusals on the path, unknown-location memory refusals, and crossing the true
terminal all retain the original target. This proof is consumed by condition
chain construction, not postprocess or CLI. The compound-refusal guard remains.

The initial implementation refused all functions with memory refusals anywhere.
A live probe found 158 unrelated refusals in InitMenu. Refusal checks are now
scoped to the path, while unknown-location refusals remain global blockers.
Eleven focused exit-normalization cases pass (20.18s); the preceding combined
condition suite passed 57 tests (10.03s). Scoped Ruff, MyPy, and Pyright pass.
The helper and tests are enrolled in Make QA/pipeline and ownership inventories.
Full architecture checks pass after correcting header and enrollment omissions.

The named live regression now passes strict generated-C compilation and its
executable high-word behavior checks (52.41s). A subsequent named/sidecar-free
pair passes both tests (117.29s), preserving required calls and arguments.
`quality-dev` exits zero with 2175 unit tests and generated-C guards, but began
before the final scoped-refusal refinement. `quality-fast` exits 2 on 129
global MyPy diagnostics; this is not a green-project claim. The default
pipeline passes all three selected lanes with no skips or timeouts; its unit
lane passes 2179 tests (136.70s), and the external round trips pass. Full goal
and CI closure remain open. All verification processes have terminated.

Logs: `/tmp/inertia-initmenu-final-pair.log`,
`/tmp/inertia-exit-normalization-quality-dev.log`,
`/tmp/inertia-exit-normalization-quality-fast.log`,
`/tmp/inertia-exit-normalization-pipeline.log`, and
`/tmp/inertia-exit-normalization-architecture.log`.

## Timing

Approximate elapsed spans on 2026-09-07 (+02:00), including test/tool waits:

| Work | Start | End | Wall span |
| --- | --- | --- | --- |
| Reproduction and diagnostic narrowing | 15:34 | 15:56 | 22m |
| Failing regressions, collector repair, focused checks | 15:56 | 16:02 | 6m |
| Broad gates, scheduling update, checkpoint documentation | 16:02 | 16:10 | 8m |

These are wall spans, not measured focused engineering time. Broad/ambiguous
probes consumed avoidable time; future estimates must not assume that every
remaining semantic failure can be resolved in a short local edit.
