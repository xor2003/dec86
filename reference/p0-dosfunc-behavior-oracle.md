# DOSFUNC Behavioral Acceptance (2026-09-09)

## Decision

Two full-suite failures required the literal substring
`intdosx(&rin, &rout, &sreg);`. The cached body retains that call but merges its
low word with preserved EAX bits before assigning an unsigned short. The
semicolon assertion rejected the expression without checking its behavior.

Both original test workflows remain. Their call-shape assertion is replaced
by strict generated-C compilation and execution; return/header/local-name
assertions remain. No generated C is rewritten and no cache entry is deleted.

- Reason: enforce the required call and result semantics rather than one
  incidental spelling of an equivalent 16-bit assignment.
- DoD: compile the actual emitted translation unit and verify all 65,536 return
  words with carry clear and set; retain the exact pointers, service byte,
  segment value, one-call rule, error path, and returned value. Demonstrate that
  deliberately broken bodies fail the oracle.
- Definition of failure: suppress compilation diagnostics, skip missing GCC,
  accept a lost or duplicated call, wrong argument or return, rewrite emitted
  C before execution, or describe this bounded wrapper oracle as whole-machine
  equivalence or proof that output determinism is fixed.

## Evidence

The cached direct result was written at 03:34:13 local during the frozen-source
full audit. Its key is
`e43baa0a1246f2bfb46ec72552cac15690fe4d8540b27566fc9b9d51d41dfac8`.
It reports validation passed and a GCC-checked payload hash. A read-only cache
observation confirms that the ordinary request hits this final-result entry.

`INERTIA_DEBUG_TIMING=1` bypasses final-result caches while retaining normal
semantic cache identity. The first analysis run misses/stores function IR/SSA;
the repeat hits that same IR/SSA key. Both emit the same clean low-word call
assignment. Reproducing the pytest diagnostic context and 40-second function
budget also emits the clean body. These probes rule out the tested IR/SSA replay
as the cause; they do not identify why the original producer retained EAX state.

Both the cached and fresh translation units compile with GCC
`-std=c11 -Werror -O2` and pass 131,072 cases against the same stubbed call oracle.
The test varies the segment with each result, seeds nonzero upper EAX bits,
checks exact pointer arguments and AH=49h, and verifies carry-dependent error
reporting and return values. This checks source-level wrapper behavior, not
all architectural registers, all independent segment/result combinations, or
the implementation of the external DOS service.

The durable oracle has two positive expression cases and seven negative cases:
missing call, duplicate call, wrong pointer, wrong return, wrong service byte,
wrong segment, and omitted error reporting. All nine tests pass in **1.45s**.
Both previously failing integration tests pass against the existing cache:
**2 passed, seven warnings, 16.63s**. Their call durations are 4.82s and 4.77s.
The nine oracle tests are admitted to Make's routine/broad selections and the
default pipeline. They add no extra decompiler process; the integration tests
compile and execute the output they already obtained.

Ruff `check --fix` and scoped MyPy/Pyright on the pipeline script pass. Combined
`quality-hard quality-fast test-pipeline` passes after admission: **2,849 tests**
in the fast lane (98.49s) and default unit lane (109.69s), seven warnings each.
The executable quality guards, QuickC and all seven MS C tiny round trips pass;
every original/rebuilt DOS exit code is 255. No default lane failed, skipped
or timed out. Global Make MyPy/Ruff pass, with existing Lizard warnings visible.
No new full-suite total is inferred from focused reruns.

## Remaining Work

Generated-text variation and the original producer's context still require
investigation. Neither cache freshness nor global determinism is declared fixed.
The extra GP-state expression remains a readability/projection diagnostic, not
evidence of a missing `intdosx` call. Keep numeric-frame semantics, InitMenu,
other full-suite failures and remote CI open.

Evidence: `/tmp/inertia-dosfunc-*` logs, emitted C, cache-event JSONL and the
compiled cold/cached behavioral probes. Temporary artifacts are not committed.
