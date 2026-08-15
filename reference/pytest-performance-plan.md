# Pytest Performance Investigation and Plan

## Goal

Keep the same correctness and development gates while making the normal pytest
feedback loop fast, deterministic, and measurable. No test may be deleted,
weakened, skipped, or made order-dependent to meet a time budget.

## Baseline (2026-08-08)

Environment: `./.venv/bin/python`, pytest 9.0.3, pytest-xdist 3.8.0.

| Measurement | Result |
|---|---:|
| Full test-tree collection | 2,759 tests in 15.36 s |
| Focused pipeline lane, `-n 7 --dist loadgroup` | 1,806 passed in 60.26 s |
| Focused lane budget | 30 s |
| Architecture-contract test | 26.27 s |
| Ownership-manifest test | 14.41 s |
| Remaining focused tests and pytest overhead | about 19.58 s |

The two repository-wide static tests consume 40.68 seconds, about 67.5% of the
focused lane wall time.

## Current measured state (2026-08-15)

The broad xdist collection issue is closed on this checkout. The full suite
completed with `6628 passed, 170 skipped, 79 warnings` in `1312.14s` using
`-n 7 --dist loadgroup`; peak RSS was `1,442,748 KiB`. The focused unit lane
completed with `1448 passed in 38.92s`, and the external MS C tiny-example
contracts remain green.

Architecture and ownership scans are mandatory hard-gate prerequisites and are
no longer duplicated inside the focused pytest target list. Pytest now reports
the ten slowest tests globally through `pyproject.toml`; the focused pipeline
keeps its more detailed 25-test report.

The decompilation cache now writes records atomically and uses path-independent
binary content identity (`schema=6`), while sidecar fingerprints remain part of
the key. This is safe for equivalent temporary binaries, but direct-address
CLI runs still need an end-to-end warm-cache measurement before being counted
as optimized. The measured full-suite bottleneck remains the sidecar-free
SortDemo subprocess tests, which can take about 205-255 seconds under the
scale-4 contention audit. The ten-slowest report is dominated by
InitMenu/RunMenu/QuickSort and one MS C runtime contract, rather than
collection or worker startup.

The historical mandatory `make pytest` target supplied 230 unique targets (201
files and 29 explicit node IDs). A measured `-n 7 --dist loadgroup` run reached
worker startup but collected/executed no tests and exited with pytest status 5
after 23.43 seconds. A small xdist test works, so broad parallel collection has
a separate stability/diagnostics problem. It must be understood before changing
the default scheduler.

## Profile evidence

### Architecture contract

`scripts/check_decompiler_architecture.py` under `cProfile`:

- 64.09 s profiler time;
- 117,619,314 calls;
- `_parse_python`: 7,857 calls, 9.41 s cumulative;
- `ast.walk`: 4,818,825 calls, 23.27 s cumulative;
- repeated narrow-field scans: more than 20 s cumulative;
- `_check_terminal_call_result_structuring_ownership` is accidentally invoked
  twice by `check_decompiler_architecture`.

The checker runs many independent rules over the same files, reparsing and
rewalking the same syntax trees. Disk I/O is not the main cost; repeated AST
construction and traversal are.

### Ownership manifest

`scripts/test_ownership_manifest.py --check` under `cProfile`:

- 11.09 s profiler time;
- 325 `ast.parse` calls;
- only 49 node-specific targets require node existence checks;
- `_target_skip_xfail_lines` reparses files for 276 targets;
- AST parsing alone costs 5.97 s, with repeated walks adding several seconds.

The manifest should parse each distinct test file once and derive both its node
index and skip/xfail index from that tree.

## Acceptance criteria

1. Identical violations, ordering, exit status, and pytest selection before and
   after each optimization.
2. Mutation tests prove cached scans notice changed file contents within a new
   invocation and never reuse stale results.
3. Focused pipeline remains 1,806 passing tests or increases when new tests are
   added; no new skip/xfail is permitted in the fast lane.
4. Warm-cache and cold-cache timings are reported separately.
5. Three consecutive runs are measured; use the median and retain the maximum.
6. Initial target: focused pipeline median below 30 s. Stretch target: below
   20 s on this machine.
7. Full mandatory pytest must collect and run tests reliably under xdist before
   its timing is accepted.

## Implementation plan

### P0: Make timing and failures explainable

- Add a `pytest-profile` target that records collection time, setup/call/teardown
  durations, worker crashes, and the 25 slowest tests without changing the
  normal pass/fail rules.
- Preserve per-worker stderr and enable pytest faulthandler for the broad xdist
  collection failure. Record worker exit codes and memory pressure.
- Re-run the same 230-target command serially and with `-n 1`, `-n 2`, `-n 4`,
  and `-n 7`. Find the smallest failing worker count or target subset by
  deterministic bisection.
- Compare `load`, `loadgroup`, and `worksteal` only after collection is stable.
  Select from measured median wall time and peak aggregate RSS, not intuition.

Deliverable: a reproducible failure or a stable broad baseline, plus a compact
machine-readable timing artifact under the existing cache directory.

### P1: Cache ownership-manifest AST work inside one invocation

- Build one immutable index per distinct test path: parsed AST, pytest node IDs,
  and skip/xfail line numbers by node.
- Reuse that index for all ownership rules and repeated targets.
- Keep cache lifetime limited to one validation invocation, or key it by path
  plus content fingerprint. Do not use a path-only process-global cache.
- Add equivalence tests comparing indexed and uncached validation on valid and
  deliberately broken temporary manifests.

Expected result: reduce the 14.41 s pytest test to roughly 1-3 s.

### P1: Give the architecture checker one scan context

- Introduce a request-owned scan context containing file text, parsed AST, module
  docstring, and reusable per-file indexes.
- Route every architecture rule through that context so each file is read and
  parsed once per invocation.
- Replace repeated full `ast.walk` calls with indexes built during one visitor:
  definitions, calls, imports, assignments, attributes, constants, and relevant
  source locations.
- Fuse rules that inspect the same node kind while keeping rule ownership and
  violation messages separate.
- Remove the duplicate terminal-call ownership check.
- First preserve an uncached reference path in tests and assert exact tuple
  equality for all violations on synthetic fixtures and the current tree.

Expected result: reduce the 26.27 s pytest test to roughly 5-10 s. The exact
target must be revised after the first request-local cache benchmark.

### P2: Remove repository-wide scans from the xdist critical path

- Keep architecture and manifest validation mandatory, but run each exactly once
  as explicit quality-gate jobs alongside the parallel unit-test lane.
- Do not make every xdist worker import and collect repository scanners merely to
  execute one global assertion.
- Keep small unit tests for scanner behavior in pytest. The whole-repository
  assertions remain hard gates in `quality-fast` and `quality-hard`.
- Have the orchestrator wait for every concurrent gate and combine all failures;
  never cancel or hide one failure because another job failed first.

This changes scheduling, not coverage. It shortens the critical path because the
global scans and ordinary tests can run concurrently.

### P2: Reduce collection and import cost

- Profile collection per module and import time before editing tests.
- Move expensive executable loading, compiler probing, and decompiler setup out
  of module import scope into explicit fixtures.
- Split collection-safe unit modules from corpus/integration modules using
  registered markers and explicit Makefile lanes. Marker assignment must not
  remove any test from `quality-hard`.
- Keep test selection in one structured manifest and generate Makefile targets
  from it, avoiding a second manually maintained authority.

Target: full-tree collection below 5 s and focused-lane collection below 2 s.

### P3: Cache expensive test artifacts safely

- Inventory tests that rebuild MS C fixtures, rediscover functions, load angr
  projects, lift identical bytes, or regenerate decompiled C.
- Use content-addressed artifacts keyed by all semantic inputs: binary digest,
  code/config digest, tool version, Python ABI, and decompiler options.
- Use atomic writes and per-key locks so xdist workers cannot consume partial
  artifacts.
- Cache facts and generated artifacts, never pass/fail verdicts. Assertions must
  execute every run against the cached facts.
- Add corruption, stale-key, concurrent-writer, and cold-cache equivalence tests.

### P3: Balance xdist by measured workload

- Emit historical duration data by node ID and use it to keep long integration
  tests from landing on one final worker.
- Mark tests that must share an expensive fixture with `xdist_group`; leave
  independent fast tests distributable.
- Cap workers from measured aggregate memory, not CPU count alone. Seven workers
  are a hypothesis, not a permanent constant.
- Benchmark three uninterrupted repetitions for each candidate scheduler and
  worker count after caches are correct.

## Recommended order

1. Diagnose the broad xdist no-tests failure.
2. Implement ownership-manifest request-local indexing.
3. Implement architecture scan context and remove the duplicate check.
4. Re-measure the focused lane three times.
5. Separate global scans from the xdist critical path while retaining hard-gate
   coverage.
6. Profile collection imports and expensive artifact producers.
7. Add content-addressed artifact caching and tune xdist scheduling.

The first two caching changes are the highest-confidence work: they attack the
measured bottlenecks directly and do not alter decompiler semantics or reduce
test quality.
