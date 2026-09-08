# InitBars Aggregate Binding

This continues [the replay investigation](p0-initbars-call-replay.md).
InitBars and P0 remain open until final C passes strict recompilation and
function acceptance, not merely whole-tail validation.

## Address Versus Value

Exact indexed-address instrumentation showed the first byte carrier created
before aggregate facts exist. Subsequent requests called the stack *value*
projector and received a cast of that carrier. The pointer builder then took
the address of the cast, rather than of an addressable storage object.

The pointer builder now requests the existing lvalue contract. A generic
two-load regression reproduces the invalid reference before the change and
verifies that both references retain one addressable variable afterward.

- Reason: a converted value is not a storage address.
- DoD: repeated indexed loads use the same addressable owner; focused tests,
  scoped types/lints, and live function checks establish the result.
- Failure: taking the address of a cast or inventing another stack object to
  avoid an owner mismatch.

## Canonical Aggregate Views

The live replay trace then showed two array-typed views of machine BP-90:
an 86-byte `local_5a` and a two-byte backing carrier `stack_sp_m5c_2`.
Both occurred in AST and declaration inventories. Aggregate recovery selected
the canonical view and applied types, but did not reconcile AST references.

Lowering now replaces only exact caller-proven candidate variable identities
with the canonical variable, preserves reference-site tags, and removes only
consumed alias declarations. Typed counters record the rebinding. A regression
checks canonical identity, unrelated-storage preservation, and idempotence.

- Reason: one proven aggregate must not become two independent C objects.
- DoD: alias references and declarations agree with the canonical owner;
  unrelated storage is untouched and replay is idempotent.
- Failure: matching names instead of proven identities, changing another
  stack range, or keeping unresolved carriers in accepted C.

## Byte Stride Shield

Inspecting emitted C exposed an additional correctness issue: ordinary casts
were hidden by codegen. After array typing, a byte offset was interpreted as
an unsigned-short element index. Whole-tail validation did not detect this
rendering error, because the AST still contained the optional cast.

Both the byte-pointer and access-width casts now use `CSemanticCast8616`.
A regression renders with cosmetic casts hidden, compiles the expression
using strict GCC warnings, and executes a byte-offset check. Before the fix,
the compiled program returned failure; afterward it passes.
High-byte cases exposed a separate rendering issue: `SimTypeChar(False)`
renders as plain `char` in this angr version. The indexed byte-pointer and
byte-load types now explicitly render as `unsigned char`. Executable cases
cover 0x56, 0x80, and 0xFF; strict GCC rejected the latter two before the fix.

- Reason: hiding a cast must not change pointer scaling or load width.
- DoD: the compiled byte-offset regression passes after array-type replay,
  and emitted live C retains the required pointer conversions.
- Failure: a syntactically valid expression reads a different byte, or a
  clean AST tail verdict substitutes for checking rendered behavior.

## Evidence And Remaining Work

Focused final selection: 115 passed in 32.26s. The earlier live aggregate
selection reached strict GCC with clean sidecar-free whole-tail validation,
but failed on the configuration object's declaration/type and a pointer
masked as an integer. Its two passes and two failures took 268.97s under
concurrent gates; this is not a controlled performance measurement.

Logs: `/tmp/inertia-indexed-owner-events.log`,
`/tmp/inertia-aggregate-replay-events.log`,
`/tmp/inertia-aggregate-bind-before.log`,
`/tmp/inertia-byte-stride-before3.log`, and
`/tmp/inertia-aggregate-final-focused2.log`, and
`/tmp/inertia-byte-unsigned-before.log`.

Next: reconcile configuration-object declarations with their typed field and
call-argument views; separately lower the pointer-to-register conversion.
Do not repair either through rendered-C substitution or delete live register
publication to make GCC pass. Final broad and live results follow below.

Additional open provenance audit: the latest rejected payload references
`inertia_esi` in raw indexed loads without the publications visible in an
earlier candidate. The named-pass diagnostic saw no such writes at entry;
it does not establish that DCE removed them or that the cast change caused
their absence. Trace earlier IR/SSA and Lowering before deciding whether these
loads lack required definitions or duplicate already-materialized reads.
Do not reconstruct writes from rendered C or assume the reads are harmless.
Logs: `/tmp/inertia-register-pass-events.log` and
`/tmp/inertia-initbars-aggregate-final.log`.

## Completed Local Gates (2026-09-07)

The source-stable combined `quality-dev test-pipeline` command exited zero.
Development gate: 2,236 passed in 194.33s, with executable guards and scoped
quality checks. Default unit lane: 2,236 passed in 164.31s. All seven MS C tiny
cases passed build, original execution, decompilation, recompilation, and
generated-program execution; all three pipeline lanes passed with no skips
or timeouts. Log: `/tmp/inertia-aggregate-final-gates.log`.

These overlapping selections do not establish full-suite or remote CI success.
The last global quality-fast evidence still reports 121 MyPy diagnostic lines.
InitBars final-C acceptance and the provenance audit above remain open.

## Call-Output Declaration Cache (2026-09-07)

Investigation: approximately 22:17-22:30 +02, including four bounded diagnostic
worker runs and before/after live checks; broad gates recorded separately below.
The problem was not missing struct recovery. The AST, variable manager, and
earlier renderer knew the struct, but later replay left a stale scalar entry
in `CFunction.unified_local_vars`. Actual rendering switched from the struct
to `unsigned short` before text cleanup. Diagnostic logs:
`/tmp/inertia-config-type-manager-events.log` and
`/tmp/inertia-config-render-transition.log`.

- Reason: the declaration cache must consume the same proven object type as
  field accesses and call arguments.
- DoD: restore exact object declaration entries, preserve unrelated entries,
  report declaration-only changes, and make repeated replay idempotent. The
  live declaration must be a struct with clean whole-tail validation; retain
  the separate final-C acceptance requirement.
- Definition of failure: guessed identity/type, global declaration damage,
  hidden validation deltas, or a C-text repair replacing typed publication.

Rejected experiment: calling `CFunction.refresh()` after type publication
rebuilt unrelated declarations and triggered live-out rejection in the live
regression (77.48s). It is removed. The retained helper in
`lowering/call_output_object_projection.py` updates only entries whose
`CVariable.variable` is the exact proven object. The existing Lowering owner
calls it and replay propagates its changed result.

The new regression uses angr's actual `CFunction` cache, not a no-op fixture
refresh. Before: one failure/six passes, 20.51s; AST and manager types were
correct while the cached declaration stayed scalar. Final focused tests:
32 passed, 22.13s, including unchanged unrelated entries, declaration-only
repair, and idempotence. Scoped Ruff `check --fix`, MyPy, and Pyright pass.

Live scoped repair: the struct declaration is restored, whole-tail validation
is clean, and the configuration-field and call-pointer GCC errors disappear.
The run still fails (93.52s): GCC rejects the remaining pointer-to-register
expression. This live run precedes the final changed-result/idempotence
bookkeeping; it does not establish whole-function acceptance.
Logs: `/tmp/inertia-config-declarations-final.log` and
`/tmp/inertia-initbars-config-scoped.log`.

Fresh global `quality-fast` exited 2 with 121 MyPy diagnostic lines; no global
typing closure is claimed. The default pipeline unit lane passed 2,241 tests
in 244.55s. Startup architecture checks passed. All seven MS C tiny cases
passed build, original execution, decompilation, recompilation, and generated
execution. The default pipeline exited zero: three lanes passed, none skipped
or timed out. This remains a curated gate, not the full-suite census or remote
CI acceptance. After gates, only the helper's module responsibility docstring
was clarified; Ruff was rerun. Logs: `/tmp/inertia-config-declarations-quality-fast.log`,
`/tmp/inertia-config-declarations-pipeline.log`, and
`/tmp/inertia-config-declarations-architecture.log`.
