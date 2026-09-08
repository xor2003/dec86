# Register Argument Provenance (2026-09-08)

## Status

Historical investigation checkpoint. The subsequent
[production repair](p0-consumed-stack-setup.md) now accepts sidecar-free InitBars
and passes its regression; it supersedes the open producer-removal work below.
Named-output quality, InitMenu and overall goal acceptance remain open.
The shared InitMenu/InitBars problem is numeric register state receiving a
host C object reference. Do not cast that reference to a machine offset or
delete its assignment merely because a recovered call also has a pointer.

## Fresh Boundary Evidence

Two observation-only, sidecar-free InitBars clean-worker runs inspected the
current worktree. Both retained `status=validation_failed`, stable Structuring
and Postprocess tails, and null accepted-payload and GCC proof hashes.
Stable tails do not establish recompilability or final acceptance.

At `_runtime_gp_subview_write_8616` for instruction `0x1058e`:

- The active lowering codegen and the source node's codegen are identical.
  A stale node carrier is therefore not the explanation in this observation.
- The active callsite summary inventory is empty.
- The AST call at `0x10595` has zero arguments and no typed target tag yet.
  This is before call recovery, not evidence that binary arguments are absent.

At the later `_delete_consumed_indices_8616` boundary:

- The typed summary identifies call `0x10595`, target `0x12ac8`.
- Physical argument sources are `SEGMENT(ss)` and `BP_ADDRESS(-112)`;
  the exact PUSH addresses are `0x10591` and `0x10592`.
- Stack cleanup is four bytes at `0x10598`. Logical argument classes are
  still empty in this observed summary; do not infer a completed pointer-class
  proof from that field.
- The LEA assignment tagged `0x1058e` is statement index 6 and is **not** a
  consumed-setup candidate. Candidates 13 and 14 are tagged `0x10595`.

Consequently, changing only the existing consumed-setup liveness classifier
cannot remove this LEA: it is never asked to classify that assignment.
Likewise, consulting the call inventory at early GP publication cannot prove
the setup already consumed: that inventory has not been populated yet.

The summary retains the physical PUSH origins and symbolic BP address, not an
explicit register-producer-to-materialized-argument proof. The next trace must
use instruction/SSA identities to connect these facts, not statement proximity.

## Ordered Repair Requirements

1. **Connect producer and consumed argument in IR and Types/Lowering.**
   Reason: a recovered argument does not itself prove its original register
   setup dead. Reuse instruction identities and SSA reaching definitions;
   preserve Alias ownership of stack storage. DoD: the actual materializer
   consumes typed producer, register-view, PUSH, callsite and storage evidence;
   tests cover intervening writes, ambiguous CFG joins, segment mismatch,
   duplicate arguments and missing provenance. Failure: address-specific
   matching, rendered-text recovery, or an unused proof-only module.
2. **Prove remaining register uses, including callee inputs.**
   Reason: caller-saved is not equivalent to no incoming-register reads, and
   AL/AX writes do not kill AH/EAX indiscriminately. Use Semantics/IR evidence
   for real callees and bit-aware CFG liveness; keep unknown candidates.
   DoD: a proven consumed producer can be removed only when no retained caller
   or callee use remains, with closed evidence counters and validation
   consumption. Failure: guessed ABI, skipped callee reads, or whole-parent
   kills from partial writes. Do not add this proof to Rewrite or the legacy
   postprocess compatibility owner.
3. **Close both live functions and the project gates.**
   Reason: a smaller standalone proof test is not function acceptance.
   DoD: named and sidecar-free InitBars/InitMenu pass validation and strict C
   recompilation, preserve source-required calls and argument classes, and
   improve output without pointer-to-integer concealment. Run focused tests
   before/after, then quality-fast and test-pipeline, including MS C round trips.
   Failure: accepting only stable intermediate tails, retaining compiler errors,
   suppressing global quality failures, or claiming full-suite closure from
   focused passes.

If the original register value is genuinely live, keep it and repair the
numeric frame/address representation through a proven machine-state contract.
Do not force the consumed-producer approach to succeed by weakening liveness.

## Evidence And Scope

Observation logs: `/tmp/inertia-lea-active-call-provenance.jsonl` and
`/tmp/inertia-lea-late-provenance.jsonl`. Corresponding worker results use the
same prefixes with `-worker.json`; run logs use `-run.log`.
Worker-reported analysis elapsed times were 17.50s and 46.54s. The second used
Python profiling callbacks; these are not comparable performance benchmarks.
No production code or gate policy changed during these observations.

Source checks: `lowering/gp_register_state.py`, `callsite_summary.py`,
`decompiler_postprocess_calls.py`, `semantics/call_register_effects.py`, and
`ir/register_live_in.py`. Graph generation was `2026-08-27T11:51:06Z`;
coverage reported changed/untracked source, so exact current source was read.
This is bounded evidence for the observed call, not an exhaustive call audit.

## Compound Memory Dependency Repair

While checking the existing Alias reaching-source owner, a prerequisite safety
bug was reproduced: `callsite_source_reads_memory_8616` descended through an
expression's base source but stopped at the grouping tuple around its operation
operands. Thus `("expr", ("imm", 1), (("add_source", ("bp", -2, 2)),))`
was incorrectly classified as independent of mutable memory. The Alias solver
uses this classification to invalidate source replay across memory clobbers.

The classifier now descends through nested tuple containers, including operation
operands. The same solver retains constants and address-only expressions across
memory writes, retains memory-dependent expressions when no clobber occurs,
and refuses stale memory-dependent expressions after a clobber. No DCE or
call-argument substitution was added. No live InitBars improvement is claimed.

- Reason: source identity alone is insufficient when re-evaluating its nested
  operands reads memory that has changed.
- DoD: reproduce nested-operand dependency failures, test the actual Alias
  resolver's refusal and evidence counters, preserve address-only controls,
  admit regression coverage to the default pipeline and changed-file ownership,
  and run scoped typing/lint plus broad gates.
- Definition of failure: replaying a changed memory operand, treating taking an
  address as a read of its contents, losing the unchanged-memory case, or
  presenting this prerequisite as final InitBars acceptance.

Before: 10 failed, 12 passed in 8.55s. After: 147 focused tests passed in 10.16s,
including existing register-reaching-source and pipeline/ownership regressions.
Scoped Ruff `check --fix`, MyPy and Pyright passed. The new 22-case regression
is `test_x86_16_register_source_memory_dependencies.py`; it is included in the
default test pipeline, QA tests, and the corresponding ownership rule.

Evidence logs use `/tmp/inertia-register-source-memory-` with suffixes
`before.log`, `after.log`, `mypy.log`, `pyright.log`, `quality.log`, and
`pipeline.log`. Default pipeline passed all three lanes: 2,305 unit tests in
143.97s and all seven MS C tiny compile/run/decompile/recompile/run cases.
The slowest unit test was the sidecar-free RunMenu ESC regression at 56.22s;
the reviewed indexed-address inventory followed at 36.65s. Global quality-fast
still exits two with 116 MyPy diagnostic lines. This is not full-suite or
remote CI closure.

## Next Existing Owner

The generic decoded register-source collector in
`callsite_register_instruction_facts.py` handles MOV replacements and self-clear
idioms, but its inspected replacement function does not handle LEA. A direct
Capstone probe of bytes `8d 46 90` at an arbitrary address decoded
`lea ax, [bp - 0x70]`; `register_replacement_source_8616(..., "ax")` returned
`None`. By contrast, the local `_push_arg_source_from_context` scanner has an
explicit LEA case. This is a concrete difference between the local and CFG
reaching-source paths, not evidence that the lifter cannot execute LEA.

Do not create another reaching-source implementation. If extending this
collector, first add binary-backed positive/refusal tests for frame-address
production and intervening partial writes. This extension is not a prerequisite
for the observed InitBars consumed-setup repair: its existing local call summary
already carries the exact BP address. Symbolic address recovery is not itself
a consumed-producer or deadness proof; the ordered requirements still apply.

## Wide Register Clobber Prerequisite

Before extending LEA recovery, binary-backed partial-write checks exposed a
second invalidation bug. `register_value_family_8616` had a separate 16-bit
inventory, so `instruction_writes_register_8616` missed an EAX write when
tracking AX (likewise ESI/SI and EBP/BP). With bytes for
`MOV AX,0x1234; MOV EAX,0x76543210; PUSH AX`, the actual CFG reaching-source
consumer incorrectly retained immediate `0x1234`.

Semantics now derives register views and storage families from Frontend's
`Arch86_16.register_list`. A separate directional projection answers whether
one write covers every requested bit; storage overlap is not full coverage.
The decoded replacement collector consumes that projection for immediate
writes, recovering the proven AX value `0x3210` rather than merely refusing.
An AL write after an EAX constant invalidates the stale full-register source;
partial-value composition is not guessed. Zero-idiom coverage uses the same
directional projection, retaining the AX-does-not-clear-EAX and
AL-does-not-clear-AH refusal tests.

- Reason: producer provenance is unsound if intervening wider or narrower
  writes can be missed by a separate register inventory.
- DoD: binary-backed recovery replaces stale word constants after dword writes,
  refuses stale parent constants after byte writes, preserves directional
  zero-clear semantics, consumes the shared architectural layout, and passes
  focused tests and scoped tools with broad gate results explicitly recorded.
- Definition of failure: treating family membership as full coverage, keeping
  the overwritten value, adding another register layout, or calling LEA/DCE
  complete on the strength of this prerequisite repair.

Before: all nine initial overlap/stale-source regressions failed in 8.55s.
After the fix and additional projection/refusal coverage: 167 focused tests
passed in 10.35s. Scoped Ruff `check --fix`, MyPy and Pyright passed. The new
test module is included in default pipeline, QA and changed-file ownership.
Logs use `/tmp/inertia-register-wide-clobber-` with `before.log`, `after.log`,
`final.log`, `mypy.log`, `pyright.log`, `quality.log`, and `pipeline.log`.
LEA source recovery and consumed-producer proof remain open.

Broad gates for this repair: all three default pipeline lanes pass, including
2,323 unit tests in 117.11s and all seven MS C tiny round trips. The slowest
unit test was sidecar-free RunMenu ESC preservation at 41.85s. Global
quality-fast still fails with 116 MyPy diagnostic lines; no full-suite or
remote CI closure is claimed.

The fresh sidecar-free InitBars worker reports `validation_failed`, with stable
Structuring/Postprocess tails and neither accepted-payload nor GCC proof hash.
Its partial C and complete tail-validation record are identical to the earlier
active-call-provenance baseline. This confirms no observed change to that
rejected partial C, not function acceptance. Evidence:
`/tmp/inertia-wide-clobber-initbars-worker.json` and
`/tmp/inertia-wide-clobber-initbars.log`.

Measured local timeline (2026-09-08, UTC+02:00): initial failing test run
11:01:14-11:01:23; final focused run 11:03:52-11:04:02; default pipeline
11:04:06-11:07:52. From first regression execution to the terminal broad
pipeline result: about 6m38s. This excludes the preceding investigation and
must not be extrapolated into an ETA for the remaining semantic blockers.

## Live Callee And Storage Checkpoint

The active clean worker's loader contains original bytes at `0x12ac8`, and
`is_synthetic_call_stub_8616` returns false for that target. Its first 32 bytes:
`558bec57c47e06fc33c08bd88bd0b92000a24607e81b097414a00f02f6261002`.
The entry sequence reaches `XOR AX,AX` before the first call or branch.
These facts support a bounded no-input/overwrite proof; an ABI clobber label
alone would not establish that proof.

At argument materialization, the referenced stack variable has entry-SP offset
-114 and an exact registered BP offset -112. At final callsite closure the
same reference has a registered 22-byte extent. Thus the final closure provides
the existing storage-coordinate evidence required to match this argument to
the summary's `BP_ADDRESS(-112)`; the early GP publication point does not.

An **isolated address-specific diagnostic intervention**, outside the repo,
removed only the assignment tagged `0x1058e` after final callsite closure.
It did not change worker statuses, validation, compiler gates, call arguments,
or production source. Result: worker `status=ok`, both tail stages stable, and
matching validated/GCC payload hashes:
`b9b70afc7287f726c46e5b3c208ea9a31f00510ecac45700c5dce0bf4c75d670`.
The C diff against the prior partial payload contains only the removed LEA
assignment and the automatically removed unused `v6` declaration. Calls,
arguments, and control-flow text are unchanged. Worker analysis took 16.75s;
this is not a controlled performance measurement.

This isolates the remaining acceptance blocker; **it is not a production fix
or a generic deletion proof**. Do not land the diagnostic's hardcoded address.
The next implementation must combine the exact consumed PUSH/call identity,
registered argument storage, original producer effect, no other caller read,
and real-callee overwrite-before-read evidence. Preserve other register bits
and refuse unknown decode, control flow, or provenance. Lowering consumes this
proof at the existing final callsite boundary; Rewrite/CLI must not infer it.
No new independent reaching-source framework is needed merely to reproduce
the local summary already present here.

Evidence: `/tmp/inertia-lea-callee-image.jsonl`,
`/tmp/inertia-lea-call-storage.jsonl`, and
`/tmp/inertia-lea-removal-experiment-worker.json`; their corresponding run logs
and the diagnostic script remain in `/tmp`. All diagnostic processes finished.
Normal production InitBars acceptance remains open until the generic repair
and its positive/refusal tests land and pass the required gates.

## Entry Overwrite Proof In Progress (2026-09-08)

The Semantics owner now exposes exact incoming-read and written-bit masks and
a bounded, contiguous entry-prefix overwrite proof. Partial AL/AH writes are
tracked independently, AX cannot kill the upper EAX word, and an incoming
read, branch, call, return, missing detail, or exhausted prefix refuses.
The detail-disabled regression exposed a Capstone `CsError` escaping from the
instruction normalizer; this now returns unknown evidence instead of crashing.

Focused register/provenance tests: **81 passed in 10.53s**. Scoped Ruff
`check --fix`, MyPy and Pyright pass. The new test module is admitted to Make,
the default pipeline, and the call-semantics ownership inventory. Global
quality-fast still fails with **99 MyPy diagnostic lines**; its complete log
is `/tmp/inertia-entry-overwrite-quality.log`.

This is an intermediate implementation, not InitBars acceptance. The new
entry-prefix proof has no production deletion consumer yet. Remaining work:
verify real-image/non-synthetic provenance, prove the exact caller LEA/PUSH
use chain, match the recovered argument's authoritative storage projection,
and let Lowering remove only the fully proven redundant assignment. The
normal sidecar-free function regression and whole-tail/recompile acceptance
must then be rerun. Do not mark the function fixed from these unit tests.

Default pipeline verification finished successfully: **2,394 unit tests passed
in 171.54s**, all three lanes passed, and all seven MS C tiny examples built,
ran, decompiled, recompiled, and passed their decompiled-run checks. The slowest
unit case was RunMenu ESC preservation (71.66s), followed by indexed-address
inventory (36.55s) and pointer-output recovery (24.57s). Full evidence is in
`/tmp/inertia-entry-overwrite-pipeline.log`. No full-suite or CI closure is
claimed, and no live InitBars acceptance claim is derived from this result.

### Caller Chain Proof Follow-Up

`ConsumedStackAddressSetup8616` now records exact producer/PUSH/call/target
addresses, the destination register, and the BP displacement. The Semantics
owner validates a contiguous, bounded word-LEA chain, permits the tracked value
to be read only by the designated PUSH, rejects BP changes and any other
register read/write, and then consumes the entry-prefix overwrite proof.
Seventeen additional tests cover the combined positive case, callee input use,
wrong identities, partial register writes, repeated PUSH use, operand widths,
frame changes, branches, and exhausted/incomplete caller prefixes.

The combined focused run passes **98 tests in 9.49s**; scoped Ruff, MyPy and
Pyright pass. The broad pipeline result above predates this follow-up. This
proof is still not wired to a production deletion path: real-image provenance,
registered argument-storage matching and the Lowering consumer remain open.
