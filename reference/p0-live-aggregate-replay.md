# Live Aggregate Replay (2026-09-08)

## Root Cause

The four text-output buffer arguments were not clones of the registered
aggregate. Constructor tracing showed two separate creations by
`stack_aggregate_objects._materialize_fact` during direct-stack replay.
The first buffer remained live and declared, but its coordinate projection
was lost. Candidate collection then interpreted its entry-SP offset without
that projection, missed the tracked owner, and allocated another aggregate.

Both buffers lacked durable identifiers. Matching them by name or raw offset
would have concealed the ownership failure. The normal AST clone helper was
not responsible and was not changed.

## Repair And Acceptance

Lowering's aggregate-projection owner restores an existing tracked object's
declaration or coordinate projection only when:

- that exact object is present in the current AST or its exact C-variable
  declaration is current;
- function region, full storage width and the current producer's proven
  entry-SP coordinate match;
- the normal coordinate publication owner accepts the projection.

A private cached object alone is insufficient. No alias is invented between
lookalike variables. The large materializer has a small orchestration hook;
the focused projection module owns the checks. Restoration reports a change
so downstream consumers refresh their metadata.

Reason: replay must retain a proven aggregate rather than split one storage
object into unrelated identities. DoD for this repair: reproduce declaration
loss and coordinate-only loss; preserve exact live/declared objects; refuse
stale, foreign-region, wrong-width, wrong-coordinate and lookalike objects;
restore all seven InitMenu setup-to-buffer matches without weakening deletion.
Definition of Failure: matching names/offsets as identity proof, accepting a
stale private cache, or deleting a setup after the machine proof refuses.

## Evidence

The initial proven-frame regression failed on live-object replacement. The
extended coordinate-only cases failed separately. After the repair, 59 focused
aggregate/setup tests pass in 9.04s. Scoped Ruff `check --fix`, MyPy and Pyright
pass for both touched production modules. Full architecture checks pass.
Global quality-fast remains red with 99 MyPy diagnostic lines.

The default pipeline passes **2,440 unit tests in 156.45s**, all three lanes,
and all seven MS C tiny build/run/decompile/recompile/exit-code round trips.
This does not replace the still-open full-suite census or remote CI check.
Final pipeline interval: 13:00:25-13:05:25 UTC+02:00, about five minutes.
Slowest unit cases were RunMenu ESC preservation (60.80s), sidecar-free InitBars
(51.93s), and indexed-address inventory (31.27s). These concurrent development
timings are not a controlled performance comparison.

Live InitMenu census improves from raw 7 / normalized 3 / classified 3 /
materialized 3 / refused 4 to **raw 7 / normalized 7 / classified 3 /
materialized 3 / refused 4**. The four text-output cases now reach the machine
proof and correctly refuse at the first nested call. InitMenu's rejected
partial C is unchanged; there is no accepted-C/GCC hash and no function-closure
claim. This is repaired identity transport, not an emitted-C improvement yet.

## Next Boundary

The prefix at `0x12756` reaches a call to `0x12e1a` at `0x1275b` before AX is
overwritten. That routine begins by calling `0x15390`, which contains a
conditional stack check. Do not merely allow CALL or ignore these branches
in the straight-line proof. Reuse authoritative binary callee-effect evidence
where available; distinguish no observable input, preservation, overwrite and
unknown. Prove every relevant path or retain the setup.

Temporary evidence: `/tmp/inertia-live-aggregate-*`,
`/tmp/inertia-republished-aggregate-*`, `/tmp/inertia-aggregate-restore-probe-*`,
and `/tmp/inertia-setup-proof-probe.jsonl`. Probe construction/copy hooks only
observed objects and returned original results. No diagnostic patch is in
production. Proven-frame failing regression: 12:53:15-12:53:23 UTC+02:00;
earlier tracing and later gates are separate work, not included in that span.
