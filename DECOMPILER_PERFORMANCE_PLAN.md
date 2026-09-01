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

Rejected experiments:

- broad typed IR/SSA mypyc compilation improved the median by only 8.3% and
  introduced a large cold outlier;
- whole-lifter mypyc compilation was 3.9% slower;
- an exact Capstone instruction cache improved repeated lifting by only 2.6%;
- default fork-based Alias parallelism was unstable under Python 3.14, emitted
  unsafe-fork warnings, and did not provide a repeatable production gain.

These experiments must not be restored without new profile evidence and a
design that addresses their recorded failure mode.

## Remaining Ordered Plan

### 1. Persist Function-Scoped Typed IR And SSA

Reason: a cold indexed-Alias rebuild still spends about 19.65 profiled seconds
building project-wide evidence, with 29 typed-IR function builds in the
measured run. Reusing proven per-function IR/SSA can remove this cost before
more invasive scheduling or native-code work.

Definition of Done:

- unchanged functions perform no VEX relift or SSA rebuild on a valid hit;
- cache keys include binary/function input, frontend configuration, exact
  upstream hashes, schema version, and owning implementation version;
- changing one function invalidates only its typed dependency closure;
- live and restored artifacts produce identical typed facts, generated C,
  validation verdicts, and deterministic hashes;
- corrupt, partial, stale-schema, and conflicting entries are rejected;
- the representative end-to-end benchmark improves by at least 10%;
- focused gates and `make quality-dev PYTHON=./.venv/bin/python` pass.

Definition of Failure:

- a key omits semantic inputs or accepts stale evidence;
- restored and live artifacts differ;
- a reported hit still performs material relifting or SSA reconstruction;
- measured gain is below 10% or validation/output quality changes;
- cache ownership leaks into Rewrite, postprocess, or the CLI.

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
