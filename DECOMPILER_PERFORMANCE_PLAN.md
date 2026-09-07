# Inertia Decompiler Performance Plan

## Scheduling Status (2026-09-07)

Deferred by user request until the other remaining steps in
`SORTD_GHIDRA_PLAN.md` are complete. Do not start new profiling, parallel-worker,
scheduling, or mypyc speed experiments in the meantime. Preserve accepted work
and the experiment ledger. Required correctness, lint, typing, and existing
compiled-import gates continue; fixing an optimization pass that deletes live
code is correctness work and is not deferred. On resumption, re-profile the
current HEAD before relying on the historical measurements below.

## Objective

Reduce cold and incremental decompilation time without changing recovered
semantics, hiding validation failures, deleting uncertain code, or moving
semantic recovery into Rewrite, postprocess, CLI, or export assembly.

Correctness remains the hard boundary:

1. every selected function produces generated C;
2. `validation=passed` and whole-tail validation remain clean;
3. required calls, argument classes, memory effects, return values, and control
   flow are unchanged;
4. generated C remains recompilable;
5. identical inputs produce deterministic output and evidence hashes.

An optimization that skips required evidence, accepts stale facts, weakens a
gate, or reduces decompilation quality is a regression.

## Current Evidence

An in-process profile of sidecar-free `SORTD.EXE` function `sub_109e8` ranked
the current cumulative costs as follows:

| Work | Profiled time |
| --- | ---: |
| direct indexed-Alias program context | 33.26 s |
| custom X86-16 lifting | 20.39 s |
| indexed Alias evidence construction | 19.65 s |
| direct function decompilation | 17.37 s |
| function discovery | 6.72 s |
| project-wide callee callsite collection | 6.29 s |

The accepted cache-layer fix decoupled persisted indexed Alias/Widening
evidence from the program-callsite cache. With a valid indexed-global cache and
only the callsite cache missing, the same function improved from 26.42 seconds
to 14.74 seconds (44.2%), and peak RSS fell from about 315 MiB to 261 MiB. The
generated-C SHA-256 remained
`fadb65bd183f41258336fffaf7515d7762491e36c5d98047b7d11f7ff8634727`, and
function and whole-tail validation passed.

Function-scoped raw IR and IR-stage SSA persistence is now implemented at the
CLI cache boundary. Exact block bytes, CFG edges, frontend/runtime identity,
schema, Python ABI, and owning source hashes form each key; restricted,
size-bounded decoding verifies both payload and typed public-projection hashes
before publishing artifacts back to the owning IR registries. Focused tests
prove function-local invalidation, CFG sensitivity, malformed-class refusal,
fresh-project hydration, no VEX/SSA rebuild on a hit, and no rewrite of an
unchanged hydrated entry.

The isolated indexed-Alias input stage improved from 6.203 seconds to 0.268
seconds (23.1x). Three controlled sidecar-free `SORTD.EXE` `sub_109e8` pairs,
with only function IR/SSA entries and the indexed-global result withheld on the
cold side, measured 22.89/16.07, 23.70/16.97, and 25.75/17.47 seconds. The
median improved from 23.70 to 16.97 seconds (28.4%); median peak RSS fell from
314,556 KiB to 310,936 KiB. All six outputs had SHA-256
`caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`,
and function plus whole-tail validation passed.

Nested status-flag publication is now reentrant for the same typed function
identity. Before the change, one profiled direct decompilation entered the
context four times, rebuilt the CFG projection twice, and spent 2.705 profiled
seconds in projection. After the change, the four entries share one session,
build one projection, and spend 0.649 seconds there. A nested different-function
request fails explicitly. Generated C remained byte-identical at SHA-256
`caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`,
focused tests pass, and the fast pipeline passes 1,913 tests plus its external
lane. Concurrent source edits invalidated program-callsite caches during the
wall-time series, so no end-to-end percentage is claimed from those samples.

The persisted program-callsite artifact now tracks only its four consumed
Alias owners instead of every file in the Alias package. Its source manifest
fell from 322 files, including 38 Alias files, to 288 files with four Alias
files; edits to the other 34 Alias owners no longer discard the independent
callsite census. The focused cache and cache-surface suites pass 22 tests,
types and architecture checks pass, the fast pipeline passes 1,914 tests plus
its external lane, and sidecar-free `sub_109e8` still emits the exact C SHA-256
`caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`
with validation clean. An end-to-end percentage is intentionally not claimed:
concurrent Alias work also invalidates the separately correct indexed-Alias
artifact, masking the isolated callsite invalidation saving.

The persisted indexed-global Alias/Widening bundle now has the same bounded
dependency treatment. Its manifest fell from 351 files to 303: Alias owners
from 38 to the 12 consumed by indexed-address projection, and Widening owners
from 33 to the eight layout/range builders and codecs. The manifest also now
includes the previously omitted indexed-global cache and recovery orchestration
owners. Forty-one focused cache, Alias, and indexed-range tests pass, and the
cold replacement artifact emits the same validated `sub_109e8` C hash. This is
an invalidation-radius improvement; hot-hit execution is unchanged by design.

The first bounded typed-worklist substep now shares a lazy, mutation-aware AST
query session between logical-word copy and direct-register global
materialization. Consumers request the index only when typed facts exist, and
every RHS mutation invalidates it before the next consumer. On sidecar-free
`sub_109e8`, recursive structured-C walker calls fell from 96,076 to 94,299
(1.85%) and query-index builds remained at 55 instead of the rejected eager
prototype's 70. The generated C stayed byte-identical at SHA-256
`c4f832cc3e6e73a343462121ea48ae54af6bdeb469bd53fbe4ae1d2f2eaef314`,
with function and whole-tail validation clean. Profile totals were affected by
concurrent load, so this is a scan-count acceptance only and does not satisfy
the remaining Step 2 end-to-end 10% requirement.

Direct-register global update facts now use the authoritative function-evidence
inventory instead of rescanning every function block on each Lowering replay.
On the same representative function, binary collection calls fell from 15 to
one and cumulative direct-register materialization cost fell from 0.0736 to
0.0097 profiled seconds (86.8% isolated). The typed fact contracts were moved
to a dedicated Lowering module, reducing the implementation from 349 to 325
lines. One obsolete counted-loop fallback decode was also removed after proving
that the primary inventory already contains a strict byte-range superset; it
removed only one of 29 decodes and is recorded as simplification, not a
material speedup. Generated C remained byte-identical at the hash above and
both validation gates stayed clean.

Project-wide direct-global object-layout evidence now has its own typed,
cross-process Widening cache. Its source identity includes complete function
discovery plus only the Lowering, Structuring, and Widening owners consumed by
the direct-global collector; changing those owners does not invalidate the
independent indexed Alias/Widening bundle. On the profiled `sub_109e8` path,
the collector fell from 21 calls and 0.339 seconds to zero calls, the 34
project-layout lookups fell from 0.342 seconds to about 0.001 seconds, and
segment-global materialization fell from 1.218 to 0.891 seconds (26.8%). Total
profiled time improved from 13.607 to 13.428 seconds (1.3%), so this is accepted
as a bounded duplicate-scan removal rather than the remaining Step 2 10%
end-to-end result. Generated C remained byte-identical at SHA-256
`caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`;
function and whole-tail validation passed. Missing or malformed cache evidence
is opportunistic only and cannot turn valid transported Widening evidence into
a decompilation failure.

Exact file fingerprints now reuse SHA-256 digests for unchanged file generations
within a bounded process-local memo. Device, inode, size, `mtime`, and `ctime`
admit reuse only; persisted keys remain content-addressed, and pre/post-read
identity checks retry or refuse concurrent mutation. Three fingerprints of the
47.9 MiB signature catalog improved from 0.592 seconds to 0.159 seconds (73.2%
isolated), with one physical read instead of three. A sidecar-free `sub_109e8`
acceptance run completed in 27.32 seconds, emitted the established C SHA-256
`caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`,
and passed function plus whole-tail validation. No end-to-end percentage is
claimed because unrelated shared-worktree changes landed between reference and
acceptance runs.

The direct local Alias requirement query now hydrates the selected function's
exact raw IR/SSA pair before Alias construction and stores a newly built pair
immediately afterward. A fresh-project regression proves that the first project
invokes the raw IR builder once and an exact second project invokes it zero
times, while both Alias censuses close. After one cache-fill run, three normal
sidecar-free `sub_109e8` samples completed in 10.74, 10.67, and 10.93 seconds
(10.74-second median); every run emitted C SHA-256
`caaf606face2a9c0c041768d6bd1b6fc8a5216809f219795ebed1e7cfea02a00`
and passed function plus whole-tail validation. The hard development gate
passed 1,949 tests plus its external and generated-C quality lanes. No isolated
end-to-end percentage is claimed because the fill run also populated discovery
and program-evidence caches.

Cache-focused and indexed-Alias integration tests pass, and
`architecture-check-fast` passes. An isolated run at committed HEAD
`a7be59572` passed all 1,951 focused pytest cases in 159.22 seconds and all
seven MS C 6 tiny compile/decompile/recompile/execute construct families. The
Ultra QuickC lane still failed two of four required fixtures: `WHSUM` changed
Structuring control-flow evidence and omitted the `sub_105e6` declaration;
`ARGS` retained a pointer/value parameter-class mismatch and one unbound
`instruction_bp_stack_access` fact. These are semantic acceptance failures,
not cache-test failures, so final broad acceptance remains pending.

Rejected experiments:

- lazy-loading the corpus scanner and recovery-artifact package exports had no
  controlled startup gain: three interleaved fresh-process pairs measured a
  2.947-second lazy median versus a 2.874-second eager median; the earlier
  4.418-second baseline was import/filesystem warm-up variance;
- stat-qualified per-file source-manifest digest reuse passed correctness tests
  but improved the controlled six-manifest median only from 0.1965 seconds to
  0.1789 seconds (8.9%); the apparent 0.797-second baseline was contention;
- broad typed IR/SSA mypyc compilation improved the median by only 8.3% and
  introduced a large cold outlier;
- whole-lifter mypyc compilation was 3.9% slower;
- an exact Capstone instruction cache improved repeated lifting by only 2.6%;
- codegen-lifetime immutable tail-validation atom reuse reduced uncached atom
  expansions from 11,572 to 373, but generation improved only from 0.616 to
  0.592 seconds while recursive immutability proof cost 0.062 seconds;
- default fork-based Alias parallelism was unstable under Python 3.14, emitted
  unsafe-fork warnings, and did not provide a repeatable production gain.

These experiments must not be restored without new profile evidence and a
design that addresses their recorded failure mode.

## Remaining Ordered Plan

### 1. Close Function IR/SSA Cache Acceptance

Reason: implementation, focused correctness tests, and the controlled
cold/hit benchmark are complete, but the broad external gate is not. The two
remaining Ultra QuickC semantic failures must close on a stable committed HEAD;
removing this gate would turn a measured development result into an unsupported
production claim.

Definition of Done:

- three stable-tree cold/hit pairs improve the representative median by at
  least 10%, with CPU, RSS, cache state, and exact commands recorded;
- every pair has byte-identical generated C and `validation=passed` with clean
  whole-tail validation;
- `make architecture-check-fast`, `make test-pipeline`, and the required
  external MS C constructs pass without concurrent resource contention;
- focused gates and `make quality-dev PYTHON=./.venv/bin/python` pass.

Definition of Failure:

- the repeated median gain falls below 10%;
- output, validation, recompilation, or external execution differs;
- a cache-focused failure remains after unrelated worktree failures are
  removed;
- acceptance requires bypassing the architecture guard, validator, or test.

### 2. Replace Repeated Global Scans With A Typed Dependency Worklist

Reason: direct function decompilation still owns 17.37 profiled seconds, with
repeated AST scans, fact normalization, and dependency fingerprinting. A typed
worklist should settle only consumers of changed IR, Alias, Widening, type,
condition, and call-contract facts.

Definition of Done:

- repeated full-function and full-AST scan counts decrease measurably;
- unchanged facts do not rerun downstream analysis;
- each queued item has a typed identity, upstream versions, and stable order;
- fixed-point behavior is deterministic across repeats and worker counts;
- non-settling facts produce an explicit typed failure with their identities;
- the representative end-to-end benchmark improves by at least 10%;
- generated C, required calls, validation, and recompilation remain correct.

Definition of Failure:

- two layers become competing authorities for the same fact;
- work is skipped without a complete typed dependency proof;
- an iteration limit silently returns incomplete output;
- order or worker count changes output or evidence;
- scan counts move but end-to-end runtime or correctness regresses.

### 3. Introduce Safe Prefork Worker Reuse

Reason: repeated process startup, imports, project construction, and immutable
binary loading remain avoidable. The earlier default fork experiment was
rejected because it forked after threads existed and was unstable; this task
requires an explicit safe lifecycle rather than reusing that implementation.

Rejected experiment (2026-09-01): an import-warm fork server that still used a
fresh grandchild and fresh project for every function produced byte-identical C
(`8ebb397779ad9c8637965aab0b246e2cdf7700122669f6ae88de05d2242c4107`) but took
92.17s versus 89.53s for the existing exec lane on
`SORTD.EXE --max-functions 1 --timeout 10 --trace-c-stages`, about 3% slower.
Both runs timed out with validation uncollected, so this triggered the
Definition of Failure and the CLI integration was removed. Do not repeat an
import-only fork-server experiment; any future work on this step must eliminate
measured project/analysis reconstruction while preserving clean-state proof.

Definition of Done:

- the multiprocessing context and prefork point are explicit and emit no
  Python 3.14 unsafe-fork warning;
- immutable project state is documented and function-local state is reset;
- clean-worker and reused-worker outputs and evidence hashes are identical;
- shuffled task order and first/middle/last repetitions remain deterministic;
- aggregate worker memory remains below 2 GiB with controlled recycling;
- worker failure cannot poison later tasks or hide a failed function;
- the representative full-program benchmark improves by at least 10%.

Definition of Failure:

- workers inherit active threads or mutable analysis state;
- RSS grows without a bound or the run risks OOM;
- task order changes semantics, validation, or output ordering;
- a worker failure is converted into silent fallback or success;
- startup savings do not improve the end-to-end run materially.

### 4. Schedule Expensive Functions First

Reason: cost-aware scheduling can shorten the serial tail after safe reusable
workers and trustworthy stage timings exist. It should follow worker reuse so
the scheduler is optimized against the final execution lifecycle.

Definition of Done:

- generic block, edge, instruction, loop, call, and valid historical timing
  features predict expensive functions without corpus-specific identities;
- longest-processing-time-first scheduling reduces measured straggler time;
- output order and hashes remain deterministic;
- stale estimates are invalidated by input and implementation hashes;
- serial, four-worker, and seven-worker correctness gates pass;
- the full-program benchmark shows a repeatable end-to-end gain.

Definition of Failure:

- scheduling uses names, fixed addresses, or corpus-specific allowlists;
- estimates influence semantics, validation, or timeout policy;
- completion order changes rendered output or diagnostics;
- utilization changes without a repeatable full-run improvement.

### 5. Compile Only Residual Measured Kernels With mypyc

Reason: broad native-compilation candidates have already failed the acceptance
threshold. Native compilation is justified only after algorithmic reuse removes
duplicated work and a remaining owned Python kernel still dominates CPU time.

Definition of Done:

- every target owns a documented material fraction of end-to-end CPU time;
- the compilation unit has typed owned data and avoids dynamic angr/AST
  boundary traffic in its hot loop;
- interpreted and compiled modes have identical facts, generated C, hashes,
  validation verdicts, and tests;
- build time, import time, boundary conversion, cold time, and warm time are
  reported separately;
- the representative end-to-end benchmark improves by at least 10% without a
  cold-start outlier;
- interpreted development remains usable without a native rebuild.

Definition of Failure:

- only a microbenchmark improves;
- conversion or dynamic-object traffic consumes the native gain;
- architecture or typed contracts are distorted to satisfy mypyc;
- output, evidence, validation, or deterministic behavior differs;
- ordinary interpreted development requires rebuilding native extensions.

## Benchmark Protocol

Every claim must use the same binary, options, checkout, cache state, worker
count, host, and output destination. Record the exact command and environment,
cold versus warm cache, wall and CPU time, utilization, peak aggregate RSS,
per-stage timing, generated-output hash, and validation summary. Use at least
three measured repeats after one untimed warmup when the shared worktree is
stable.

Primary full-program benchmark:

```text
PYTHON_JIT=1 PYTHONHASHSEED=0 ./decompile.py SORTD.EXE \
  --ignore-local-sidecar-hints --no-alternate-source-c -q
```

Focused work should also benchmark representative small, medium, and large
functions so startup, algorithmic work, and validation can be separated.

## Acceptance Gate

For every accepted optimization:

1. run focused before/after function regressions;
2. require `validation=passed` and no semantic call loss;
3. compare register effects, memory writes, return values, control flow, and
   value-versus-pointer argument classes;
4. require output no farther from original source when source exists as an
   optional oracle;
5. run strict generated-C recompilation;
6. run `make quality-fast PYTHON=./.venv/bin/python`;
7. run `make test-pipeline PYTHON=./.venv/bin/python` before claiming a
   decompiler speedup;
8. use `make test-pipeline-expanded PYTHON=./.venv/bin/python` for broad or
   cross-layer changes;
9. compare deterministic output and evidence hashes across repeats and worker
   counts.

No timeout increase, cache bypass, disabled validator, reduced corpus, removed
test, silent fallback, uncertain-code deletion, or weaker quality gate counts
as performance work.
