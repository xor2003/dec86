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
