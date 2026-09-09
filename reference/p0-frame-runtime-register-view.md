# Frame Runtime Register View (2026-09-09)

## Accepted Change

`lowering/frame_prologue_carriers.py` now consumes the exact GP-state owner's
register view when a physical-register or temporary view is unavailable.
The canonical `inertia_ebp & 0xffff` expression retains BP identity; a
32-bit EBP value, another register, a byte destination, and an unowned
same-name variable do not satisfy the word-save proof.

This is Types/Lowering representation coherence, not semantic recovery in
Rewrite or CLI. The classifier also accepts an exact physical-register
C variable, rather than unnecessarily requiring a dirty-expression wrapper.
Decoded entry/teardown requirements and destination-width checks remain.

- Reason: lowering a register to its owned runtime state must not lose the
  identity required by the canonical frame consumer.
- DoD: recognize only the exact BP word, consume save and restore together
  in the canonical-frame regression, and preserve accepted DOS round trips.
- Definition of failure: guess register identity from a name, treat a byte
  carrier as a proven word, remove only one side of the frame, or enable the
  previously rejected origin filter without its missing downstream proofs.

With corrected `Arch86_16` fixtures, the unchanged production classifier
fails three tests: direct matching, matching with the temporary resolver, and
paired save/restore consumption. After the change, all **48 focused tests
pass**, seven dependency warnings, **10.20s**, under `pytest -n 7`.
The slowest is the scoped frame-owner typing test at 1.46s; the other four
reported durations are below the one-second display threshold.
The original fixture used 32-bit `ArchX86`, whose BP alias width made the
new exact-width expectation invalid; the retained before/after result above
uses the corrected architecture, not that first trial.

Ruff `check --fix` and scoped MyPy/Pyright pass. The initial combined
`quality-hard quality-fast test-pipeline` run passes: 2,818 selected unit
tests, all three executable quality guards, QuickC, and all seven MS C tiny
round trips. Each original/rebuilt DOS exit code is 255. `add_sc` retains
`validation=passed` and clean whole-tail validation. Quality guards use one
shared active import surface, not an independent Python/native comparison.

The paired-frame module is also admitted to the routine pipeline, with a
regression checking that admission. It was already in Make's broader test
selection. The final combined `quality-hard quality-fast test-pipeline` run
passes after admission: **2,825 tests** in the fast lane (95.92s) and default
unit lane (101.94s), seven dependency warnings each. All three executable
quality guards, QuickC and all seven DOS round trips pass again, with no
failed, skipped or timed-out default lanes. Scoped MyPy/Pyright and global
Make MyPy/Ruff pass; existing Lizard complexity warnings remain visible.
The routine selection grows by 32 tests versus `29bc06e26`.

Timing: corrected failing-before tests completed at 02:42:24 local; final
gates were verified complete at 02:57:42, a 15m18s verification window that
includes repeated gates and excludes the earlier investigation. This is not
an estimate for the remaining numeric-frame or whole-plan work.

## Remaining Root Cause

Historical investigation below: the missing frontend capture and prefixed
stack-wrap boundaries have since been repaired in the
[implicit-stack checkpoint](p0-implicit-stack-evidence.md). Numeric frame
materialization remains open; the origin-filter probe was not installed.

A process-local origin-filter probe with the repaired classifier still emits
a one-byte saved-BP destination in the 16-byte reproducer. Frame pruning
correctly refuses it: all five carrier counters remain zero. The probe
examined 107 stack-register replacements and refused 11 unproven origins.
Its DS store is still pointer-valued, and DCE changes are rejected/restored.
No origin filter or observer hook is installed by this change.

The owned logical-memory artifact for the same bytes contains only the
DS:0200 word write: counters `(1, 1, 1, 1, 0)`, no refusals. It is closed
over its captured inputs, but that does **not** prove that every implicit
stack access was captured.

The optimized frontend's `_stack_load16` and `_stack_store16` in
`lift_86_16.py` record a semantic access only when `off16.constant` is an
integer. Ordinary SP-derived expressions are symbolic, so this path executes
the frame memory operations without corresponding logical word records.
The existing word/register transfer owner can prove the captured AX-to-DS
spill, but cannot supply missing frame operands from this artifact.

Next step: provide explicit typed base/displacement evidence at the optimized
stack-operation sites, including distinct BP-relative ENTER/LEAVE accesses,
without changing their byte-safe execution helpers. Use the existing logical
memory and Alias owners to prove the frame pair before consuming byte carriers.
Coordinates must describe the instruction-entry register value: PUSH/CALL
stores are SP-2, ordinary POP/RET reads are SP+0, and LEAVE reads BP+0.
Nested ENTER needs separate BP-relative reads and successively decremented
SP-relative writes. Do not label every access as SP-relative or copy a data
operand's address-size prefix into implicit stack addressing without proof.

- Reason: missing implicit operands must be fixed at the frontend/IR evidence
  boundary, not reconstructed from rendered C or carrier widths.
- DoD: capture each logical stack word once with exact instruction, segment,
  width, address-size and byte-slice provenance; retain wrap behavior; verify
  PUSH/POP, CALL/RET and ENTER/LEAVE paths and the DOS pipeline.
- Definition of failure: double-count accesses, confuse SP and BP origins,
  guess symbolic addresses, change 16-bit wrapping, or call a capture-only
  fix accepted numeric generated C.

Numeric entry-SP materialization, InitMenu, complete pytest and remote CI
remain open. Optimization remains deferred.

Evidence: `/tmp/inertia-frame-runtime-view-` logs (`before-corrected`, `after`,
`origin-trial`, `gates`, `final-mypy`, `final-pyright`, `final-gates`),
`/tmp/inertia-frame-register-transfers.log`, and
`/tmp/inertia-frame-logical-refusals.log`.
