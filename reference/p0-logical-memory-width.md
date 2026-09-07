# Logical Operand and Execution-Slice Width

## Reason and Owner

The isolated ALU-effect suite reproduced two full-decompiler failures on
2026-09-07: 13 passed, 2 failed in 29.77s. Carry/borrow pipeline evidence passed,
but generated memory expressions no longer matched the single low-word
operation. This was not an ALU effect-ordering regression.

`lowering/segmented_memory_lowering.py` joined C accesses to logical memory
facts by instruction address and segment. A logical word may execute as two
byte accesses at that same instruction. Overriding each fragment's width with
the logical operand width emitted `SEG_U16` for a byte fragment, interfering
with the existing word materialization.

Disabling only this override in a diagnostic process restored
`v9 = g_2000 + g_2004` and the expected high-word carry expression. That
experiment was not retained as a bypass.

The correction is at Types/Lowering: this width constraint cannot increase
the matched C access width. Promotion requires a separate complete consumption
proof, not shared instruction tags. Existing proven byte-width narrowing and
ambiguous-width failure accounting remain intact. Frontend byte-safe segmented
execution in `access.py` and `lift_86_16.py` is unchanged.

## Definition of Done

- A byte fragment of a logical word remains byte-sized.
- A proven logical byte still corrects an incorrectly word-typed C access.
- Ambiguous widths remain visible to the pipeline contract.
- Both low/high carry and borrow regressions retain their existing semantic
  evidence assertions and expected single low-word operation.
- Related tests, scoped Ruff/MyPy/type ratchet, and mandatory external pipeline
  pass after the change.

## Definition of Failure

Changing instruction execution to satisfy C shape, weakening assertions,
promoting bytes by instruction/segment tags alone, or claiming that this guard
proves general operand identity is failure. Do not treat a successful helper
substitution as complete Alias/Widening evidence.

## Initial Evidence

- New fail-before case: expected `SEG_U8`, received `SEG_U16`; 1 failed, 1 passed.
- After correction: 276 related tests passed in 21.23s.
- Scoped Ruff `check --fix`, MyPy, and type ratchet passed.
- Mandatory pipeline exited zero: 2,005 pytest cases passed in 86.19s, followed
  by the configured external executable gates.
- Additional DOS recheck: 6 passed, 1 failed in 102.80s. The previously passing
  `test_cod_dos_loadprogram_wrapper_keeps_err_guard_and_segment_stores` no longer
  finds `cs[0] = exeLoadParams[10];`. Generated output retains split byte stores.
  This prevents acceptance of this checkpoint despite the green curated lane.

Intermediate checkpoint: the mixed typed-low/raw-high
path now admits a byte-sized high helper under its existing exact pointer,
index, provenance, and value checks. Its expanded 21-test surface passes,
including mismatched index, provenance, and value refusals. Scoped linters pass.

A live trace with `INERTIA_DEBUG_TIMING=1` established the next blocker: both
raw byte pairs reach the whole-function carrier-consumption guard and refuse.
BX is reused by distinct pointer setups. The conservative physical-register
inventory includes both lifetimes, preventing not only setup deletion but also
the otherwise independently provable store projection. The live wrapper still
fails; the synthetic mixed-projection fix is not the full corpus correction.

Required follow-up: separate typed source-preservation/store-projection evidence from
whole-function setup-deletion evidence. A proven store projection may retain
the setup; removing setup must still require the complete consumption proof.
Do not interpret `UNKNOWN_REFUSE` as permission to delete, weaken the outer-use
tests, restore incorrect byte widths, or use register names as lifetime proof.
Add a two-setup same-register regression and preserve externally read carrier
values before rerunning the live wrapper and mandatory pipeline.

Diagnostic caution: `--trace-c-stages` alone bypassed the direct-request cache
but still reused a function result in one diagnostic run. Live timing mode was
required here to observe current Lowering execution. A cache hit alone cannot
establish that a changed proof executed.

## Source-Preservation Correction

Implemented the separate typed source-preservation proof. A closed
`PROVEN_SOURCE_PRESERVED` result can support store projection but never makes
the setup-deletion `.complete` property true. Whole-function consumption is
still mandatory for deleting setup. Unconsumed physical-register occurrences
can therefore retain the setup without preventing a separately proven store
fold. Opaque effects, source changes, cycles, and incomplete placement still
refuse the transformation.

The live DOS wrapper now passes with final-result caches bypassed. Its
regression no longer accepts timeout/unvalidated partial results: return code
zero, `validation=passed`, expected calls/stores/guard, and strict portable-flat
recompilation are required. The arithmetic suite and this exact live wrapper
node are enrolled in the routine pipeline, with enrollment assertions.

Verification: 282 related tests passed; the final distinct-pointer and
proof-separation surface has 23 passing tests; 50 pipeline tests pass. The
strict live wrapper passes in 33.38s. The mandatory pipeline exited zero with
2,011 pytest cases and the configured external gates; its collection preceded
the added 16 routine regressions. Final `quality-dev` passed: 2,027 pytest
cases in 111.20s, one external executable case, and CMP16/LOOPS/FPTR optimization
parity guards. Their import surfaces were identical, not independent speedup
evidence. Global `quality-fast` still fails with 164 MyPy error lines, so full
P0 is not closed. This bounded width/store correction is verified; the broader
full-suite failure inventory still needs a source-stable rerun.

General width projection still needs exact access identity, kind, address, and
execution-slice coverage before any future promotion. The existing IR logical
memory contract already records operand ordinal and per-byte execution slices;
do not invent a competing identity in Rewrite. Full P0 and global typing debt
remain open.

Timing: the initial width correction occurred on 2026-09-07 before
12:24 +02:00; live tracing continued through 12:35 +02:00, followed by the
source-preservation correction and gates. Exact engineering start time was not captured. Recorded test
durations exclude neither concurrent load nor all startup costs and are not
performance benchmarks.
