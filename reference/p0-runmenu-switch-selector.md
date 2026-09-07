# RunMenu Switch Selector Closure

## Scope

Repair the selector identity discarded while converting a proven comparison
ladder into a switch. This follows the binary callee flag-summary checkpoint
in `p0-runmenu-callee-flags.md`; neither checkpoint closes the full SORTD plan.

## Root Causes And Correct Layer

1. `typed_switch_seqnode.py` created a new raw AIL Register from a physical
   register hint after variable recovery. It discarded the existing SSA value
   and variable-map binding, producing the non-C selector `reg0<16>`.
2. The runtime invokes the Structuring materializer at multiple lifecycle
   boundaries. Once the selector retained its SSA value, simplification could
   fold the case-conversion call into it. Reapplying the old plan replaced that
   already structured switch and discarded its side-effecting selector. The
   emitted call then appeared after the return instead of before dispatch.

The repair remains in **Structuring**, where the original comparison ladder is
replaced. Runtime/CLI remains a lifecycle bridge. No rendered-C repair, call
relocation, argument recovery, or semantic postprocess pass was added.

The focused `switch_selector_binding.py` owner consumes existing AIL storage
and SSA identities. It requires an unconditional predecessor sequence, an
exact reaching register definition, and an entry predicate reading that same
SSA version. It retains the existing read atom rather than inventing storage.
Overlapping writes, intervening calls, opaque predicates, and ambiguous paths
refuse binding. In particular, CMP followed by MOV must not confuse the value
captured by FLAGS with the latest value in the same physical register.

An already structured switch is left intact. Its selector may legitimately
contain a folded call and must not be reconstructed from an older register
hint. The typed `ALREADY_STRUCTURED` result records a non-attempt, not failure.
Runtime diagnostics publish closed per-plan selector-binding counters.

## Reason, DoD, And Failure

Reason: preserve the value actually controlling dispatch, call evaluation
order, and portable generated C when structuring and simplification compose.

DoD: fail-before/pass-after SSA and replay regressions; refusal coverage for
partial/full overlapping register writes, older predicate versions, calls,
opaque predicates, missing definitions, and branch boundaries; both RunMenu
paths validate and recompile; the case-conversion call executes exactly once
inside the loop before dispatch; ESC returns; required calls and argument
classes survive; scoped Ruff/MyPy and development/executable gates pass.

Definition of Failure: selecting the latest physical register value without
matching the predicate's SSA version, replacing a folded call selector,
introducing a raw/unbound selector, losing or moving a call across a return,
changing case values or exits, or suppressing a validation failure.

## Evidence And Regression Shields

- The original focused selector test failed because `reg0<16>` replaced
  `vvar_74`. The repeated-materialization test separately failed because the
  existing switch and its call selector were replaced.
- Changing only the AIL read occurrence did not repair call loss. Repeated
  switch materialization was the separate cause; do not repeat an idx-only
  repair experiment for this failure.
- An intermediate implementation correctly refused an unknown predecessor
  statement. Live diagnosis identified angr's `SideEffectStatement` wrapper;
  explicit call-before-definition and call-after-definition tests now cover it.
- The first successful live sidecar-free run and 17 focused tests passed:
  18 passed in 36.83s. Overall validation and portable-flat recompilation passed,
  with clean whole-tail validation and ESC preserved.
- The normal path emits `switch (toupper(ch))`, matching `SORTDEMO.C`. Its old
  test required the obsolete `ax = toupper(ch); switch (ax)` staging form. That
  assertion now requires the source-like direct selector, while retaining all
  call-count, case, argument, acceptance-scorecard, and validation assertions.
- The sidecar-free test additionally requires exactly one `sub_11278(local_2)`
  call inside the loop before the case bodies. It is now in the regular fast
  pipeline, alongside all selector identity/refusal/replay unit cases.
- The new owner is enrolled in typing, Ruff, architecture promotion, and test
  ownership inventories. New production modules retain types, docstrings, and
  layer ownership headers; the two touched Structuring modules remain below
  350 lines.

- Final focused run: **21 passed** in 139.57s, including both normal and
  isolated sidecar-free RunMenu paths. It overlapped broader gate and global
  typing work; this timing is not an isolated performance measurement.
- Scoped Ruff (`check --fix`) and MyPy pass. The non-incremental global MyPy
  check still reports **146 errors**, unchanged from the previous checkpoint.

- Final `quality-hard`: **2,114 passed**, 7 warnings in 96.37s; full
  architecture, scoped quality checks, and all three executable guards passed.
- Final `test-pipeline`: all three lanes passed. The unit lane reports
  **2,114 passed**, 7 warnings in 213.63s (214.348s lane wall); Ultra QuickC
  fixtures took 39.862s and the seven MS C tiny round trips took 69.556s.
  The unit lane exceeds its 30s budget; functional success does not close that
  performance debt. Runs overlapped other verification work.

No refreshed full-suite census or end-to-end speedup is inferred from these
results. Logs: `/tmp/inertia-runmenu-quality-hard-complete.log` and
`/tmp/inertia-runmenu-pipeline-complete.log` (temporary diagnostic artifacts).

## Follow-up Validation Shield

Reason: the intermediate lost-selector experiment passed whole-tail collection
but failed the final unreachable-call guard. Call presence alone must not count
an unreachable producer as preserved behavior.

DoD: add a generic typed validation regression where the sole selector-producing
call is moved after a return; validation must reject it. Preserve acceptance
for the equivalent call folded into the switch selector, with correct argument
classes, control dependence, and call order. Repair the validation/CFG owner,
not rendered-C cleanup.

Definition of Failure: a call after a return satisfies the semantic preservation
check, or a valid folded selector is rejected only because its AST shape changed.
This remains open; the current checkpoint prevents this specific loss at its
Structuring owner and adds executable coverage, but does not claim the generic
validation gap is closed.

## Timing

Approximate wall-clock ledger, 2026-09-07, +02:00:

| Step | Start | End | Spent | Outcome |
| --- | --- | --- | --- | --- |
| Trace selector identity | 14:42 | 14:49 | 7m | Raw register replaced existing SSA value |
| Bind SSA and investigate refusal | 14:49 | 14:57 | 8m | Side-effect statement boundary covered |
| Diagnose repeated materialization | 14:57 | 15:08 | 11m | Replay regression and live RunMenu pass |
| Safety checks and acceptance gates | 15:08 | 15:33 | 25m | Predicate-version proof, final gates, and report closure |

These are elapsed spans including tests and tool waits, not invented focused
engineering totals. The next plan boundary remains the full-audit failures,
particularly InitMenu initialization and InitBars call/control-flow evidence.
