# Inertia Decompiler Performance Plan

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

An optimization that makes the tool faster by skipping required evidence,
weakening a gate, accepting stale facts, or reducing decompilation quality is a
regression.

## Current Evidence And Limits

The recorded sidecar-free SORTD run in `SORTD_GHIDRA_PLAN.md` took 4:36.36
(about 274 seconds), averaged 478% CPU utilization, and peaked near 302 MiB RSS
with seven clean function workers.

The saved `cmp16.prof` profile is not a valid profile of core decompilation. Of
its 8.8 seconds, about 6.4 seconds is the parent waiting in `select()` and about
1.8 seconds is imports. Expensive work runs in child processes and is mostly
absent from that profile. Precise native-compilation gain cannot be claimed
until child work is measured.

The current mypyc builder in `scripts/build_mypyc.py` compiles only
`inertia_decompiler.decompile_file_summary`. That module is unlikely to own a
material fraction of decompilation CPU time, so the present mypyc configuration
should not be expected to improve the 274-second run significantly.

Planning estimates, to be replaced by measurements:

| Improvement | Possible overall gain |
| --- | ---: |
| eliminate repeated analysis with a dependency worklist | 20-50% |
| persistent project and bounded worker reuse | 5-20% |
| incremental layer/function caching | 2-10x on unchanged warm runs |
| improved cost-aware scheduling | 10-30% |
| mypyc on measured owned Python kernels | 5-25% |
| Cython/Rust for compact typed kernels | additional 5-30% |

These estimates are not additive. Every result must report cold and warm wall
time, CPU time, utilization, peak RSS, cache status, and output/validation
identity.

## Ordered Implementation Plan

### 1. Profile Work Inside Function Workers

Status: pending and mandatory before native compilation expansion.

Measure CPU and wall time separately for:

- worker startup and imports;
- project/binary loading;
- function discovery and CFG construction;
- VEX lifting and typed IR import;
- Alias;
- Widening;
- Types/Lowering and interprocedural contracts;
- Structuring;
- Rewrite/cleanup;
- tail validation;
- C rendering and recompilation;
- serialization and parent/child transport.

Profile at least:

1. a small wrapper-like SORTD function;
2. a medium function;
3. the slowest SORTD function;
4. one function dominated by validation;
5. one function dominated by recovery/structuring.

Use wall-clock spans for blocking/native/child work and a sampling or child
`cProfile` run for Python ownership. Profile interpreted Python before mypyc;
compiled frames are less useful to `cProfile`.

Definition of done:

- parent waiting time is separated from child CPU time;
- top functions and modules are ranked by self and cumulative CPU time;
- repeated stages and repeated scans are counted;
- per-function stage data is emitted in deterministic JSON;
- profiling disabled has negligible overhead;
- the baseline output, validation verdicts, and behavior gates are unchanged.

### 2. Replace Repeated Global Passes With A Typed Dependency Worklist

Status: pending; expected highest cold-run impact.

Use the existing pipeline ownership order:

```text
IR -> Alias -> Widening -> Types -> Structuring -> Rewrite
```

Only enqueue dependents of changed facts:

```text
changed Address/storage fact
  -> dependent Alias joins
  -> dependent wide Values
  -> dependent type and call contracts
  -> dependent Conditions and CFG regions
  -> dependent validation obligations
```

Every queued item must have a typed identity containing the function, exact
storage or CFG identity, upstream fact versions, and analysis version. Worklist
ordering must be stable. A bounded fixed-point limit must report the exact facts
that failed to settle and fail explicitly rather than silently accepting the
last iteration.

Do not maintain two semantic authorities for one fact. Introduce an earlier
typed producer, migrate one consumer, prove parity, then remove the superseded
late producer.

Definition of done:

- repeated full-function/full-AST scans decrease by a measured amount;
- unchanged facts do not rerun downstream analysis;
- fixed-point order is deterministic across runs and worker counts;
- non-settling analysis is an explicit typed failure;
- SORTD output and validation identities remain equal or decompilation quality
  improves under the acceptance contract;
- cold wall time improves by a measured amount.

### 3. Make Cache Invalidation Layered And Function-Scoped

Status: pending.

The existing broad source fingerprint is safe but invalidates too much. Split
cache ownership into content-addressed layers:

```text
binary and loader configuration
  -> discovery/CFG
  -> lifted typed IR
  -> Alias
  -> Widening
  -> Types/contracts
  -> Structuring
  -> rendered C
  -> validation result
```

Each key includes only:

- binary/function input hashes;
- relevant configuration;
- exact upstream artifact hashes;
- the owning analysis implementation/schema version.

Changing rendering must not invalidate IR. Changing Widening may invalidate
Widening and downstream layers but should retain discovery, IR, and Alias.
Interprocedural facts must include caller/callee dependency hashes so a callee
contract change invalidates every affected caller and no others.

Cache hits are reusable artifacts, not semantic proof. Validation either reruns
or uses its own complete content-addressed key covering every validated effect
and validator implementation version.

Definition of done:

- unchanged warm decompilation has a documented hit rate and speedup;
- changing one layer invalidates only that layer and dependents;
- changing one function invalidates only its dependency closure;
- corrupt, partial, old-schema, and conflicting entries are rejected;
- cache-on and cache-off outputs and validation verdicts are identical;
- atomic writes and deterministic serialization survive interrupted workers.

### 4. Reuse Loaded Projects And Bounded Worker Processes

Status: pending after profiling.

Persistent workers should load Python, angr, the X86-16 architecture, and
immutable binary/project data once, then process multiple functions. Function
analysis state must remain isolated and be discarded after each task.

Requirements:

- choose the Python 3.14 multiprocessing context explicitly;
- define which project components are immutable and shareable;
- reset or reconstruct every mutable function-local analysis owner;
- cap tasks per worker and restart on RSS growth or state-integrity failure;
- keep deterministic output ordering independent of completion order;
- fall back to clean workers when isolation cannot be proven.

Definition of done:

- repeated import/project construction time decreases measurably;
- clean-worker and reused-worker output hashes are identical;
- running the same function first, middle, and last produces identical evidence;
- shuffled task ordering produces identical results;
- memory remains below the 2 GiB aggregate budget;
- fault injection proves one broken worker cannot poison later tasks.

### 5. Schedule Expensive Functions First

Status: pending after stage timing exists.

Estimate cost using only generic properties and historical timings:

- block and edge count;
- lifted instruction/byte count;
- loop/SCC count;
- call count;
- prior stage timings keyed by valid implementation/input hashes.

Use longest-processing-time-first scheduling with deterministic tie-breaking.
Do not use source names, function names, corpus-specific address lists, or
quality-altering shortcuts. Preserve bounded process parallelism and memory
limits.

Definition of done:

- reduced end-of-run straggler time is measured;
- CPU utilization improves without exceeding memory limits;
- output order and output hashes remain deterministic;
- slow-function estimates cannot affect analysis semantics or timeout policy;
- seven-worker, four-worker, and serial comparison runs remain correct.

### 6. Compile Only Measured Hot Owned Kernels With mypyc

Status: infrastructure exists; target selection pending profiling.

Likely candidates, only if profiles confirm them:

- SSA predecessor, definition, and phi construction;
- Alias state transfer and exact range operations;
- widening candidate collection and proof matching;
- deterministic worklist processing;
- dominator, natural-loop, and SCC algorithms;
- typed fact normalization and comparison;
- validation fingerprints and effect-set comparison.

Poor targets:

- CLI argument parsing and reporting;
- subprocess orchestration and waiting;
- filesystem operations;
- import time;
- functions dominated by angr/solver/native-library calls;
- dynamic angr/codegen/AST boundary manipulation.

Compile strongly connected hot modules in coherent mypyc compilation units so
calls do not repeatedly cross interpreted/compiled boundaries. Prefer precise
owned dataclasses, enums, primitive fields, `Final` constants, and direct calls.
Do not distort correct architecture merely to satisfy mypyc.

Use Amdahl's law for every proposal. If a target owns fraction `p` of runtime
and becomes `s` times faster, maximum overall speedup is:

```text
1 / ((1 - p) + p / s)
```

Example: compiling 30% of runtime to run 3x faster yields only 1.25x overall.

Definition of done:

- each target owns at least a documented minimum fraction of CPU time;
- interpreted and compiled modes pass the same focused and pipeline gates;
- generated C, evidence counters, validation verdicts, and deterministic hashes
  are identical;
- cold and warm benchmarks include mypyc build time separately;
- incremental builds compile only stale units;
- development remains usable in interpreted mode without a native rebuild.

### 7. (don't do it. skip this) Use Cython Or Rust Only For Compact Residual Kernels

Status: deferred until mypyc and algorithmic work are measured.

Consider a lower-level extension only when a remaining hotspot has:

- fixed-width integer or bit-vector operations;
- compact arrays/ranges/bitsets;
- tight loops with few Python object interactions;
- a small, typed, testable API;
- enough measured CPU ownership to justify maintenance.

Potential kernels include interval operations, dominance/SCC calculations,
compact dataflow sets, masks, and hashing. Do not translate large decompiler
layers or dynamic angr-facing code. The Python/native boundary must carry owned
typed data, never AST text or guessed semantics.

Definition of done:

- a pure-Python reference implementation remains available for differential
  tests;
- randomized and corpus tests prove exact result parity;
- sanitizer/native tests pass;
- boundary conversion time is included in the benchmark;
- the overall, not merely microbenchmark, gain is material;
- packaging and debugging cost is documented and accepted.

## Benchmark Protocol

Every performance claim must use the same binary, options, checkout, cache
state, worker count, CPU host, and output destination. Record:

- commit/worktree fingerprint;
- Python, angr, mypyc/Cython/native compiler versions;
- exact command and environment;
- cold versus warm cache;
- three or more runs after one untimed warmup when applicable;
- median and range for wall and CPU time;
- average CPU utilization and peak aggregate RSS;
- per-stage and per-function timing;
- generated output hash;
- validation summary and behavior-gate result.

Primary benchmark:

```text
./decompile.py SORTD.EXE --ignore-local-sidecar-hints --no-alternate-source-c -q
```

Also include focused small/medium/large functions so startup, algorithmic work,
and validation can be distinguished. Do not benchmark a stale cache hit against
a cold baseline without labeling both states.

## Acceptance Gate For Every Optimization

Before accepting any performance change:

1. run focused before/after function regressions;
2. require `validation=passed` and no semantic call loss;
3. compare required calls and value-versus-pointer argument classes;
4. compare register effects, memory writes, return values, and control flow;
5. require output no farther from `SORTDEMO.C` than the baseline when source is
   available as an optional oracle;
6. run strict generated-C recompilation;
7. run `make quality-fast PYTHON=./.venv/bin/python`;
8. run `make test-pipeline PYTHON=./.venv/bin/python` before claiming a
   decompiler speedup;
9. run `make test-pipeline-expanded PYTHON=./.venv/bin/python` for broad or
   cross-layer changes;
10. compare deterministic output and evidence hashes across repeats and worker
    counts.

No timeout increase, cache bypass, disabled validator, reduced corpus, removed
test, silent fallback, or DCE of uncertain code counts as performance work.

## Performance Targets

Targets are provisional until child profiling establishes the real ownership
distribution:

| Stage | SORTD target |
| --- | ---: |
| current recorded cold run | about 274 s |
| worklist, scheduling, and safe worker reuse | 180-220 s |
| layered incremental analysis and measured hotspot acceleration | 90-150 s cold |
| unchanged validated warm repeat | 30-60 s or better |

The preferred outcome is not maximum native code. It is minimum necessary work,
reused immutable evidence, bounded parallel execution, and native compilation
only where profiles prove Python interpreter overhead is material.

## External Technical References

- mypyc introduction and expected compiled-code ranges:
  <https://mypyc.readthedocs.io/en/stable/introduction.html>
- mypyc performance guidance and profiling/Amdahl warning:
  <https://mypyc.readthedocs.io/en/stable/performance_tips_and_tricks.html>
- Python 3.14 `ProcessPoolExecutor`, multiprocessing context, and bounded worker
  lifetime:
  <https://docs.python.org/3.14/library/concurrent.futures.html>
