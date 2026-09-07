# Source-Stable Full-Suite Audit

## Result and Scope

2026-09-07: **10,166 passed, 49 failed, 170 skipped**, 96 warnings, zero collection
errors. Total: **10,385 tests**. Pytest elapsed: **901.38s** (15m01s), exit 1.
This supersedes the older mixed-source diagnostic counts, not the requirement
for zero failures. The earlier 20/20 SORTD acceptance is historical: this run
reproduces current SORTD compilation and semantic-validation failures.

Source: `c4f03b577`, plus the two pre-existing uncommitted loop-break files:
`structuring/loop_break_jcc.py` and `test_x86_16_loop_break_initial_surface.py`.
The tracked source diff SHA-256 before and after was identical:
`646531c4a3c068848d51264aa8f871c1892e085fff9b2338fc9ba3610f471c46`.
This is evidence for that worktree, not pristine master. No source edits,
concurrent lint builds, profiling, or retried test selection during the audit.

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=4 \
  .venv/bin/python -m pytest -n 7 --dist loadgroup --durations=10 \
  --tb=short --no-header -q --junitxml=/tmp/inertia-full-20260907-1333.xml
```

Timeout scale 4 is the existing Makefile full-suite setting. This was the full
configured pytest collection, with no marker or node selection. Temporary raw
evidence: `/tmp/inertia-full-20260907-1333.log` and the XML above. Do not treat
the timing as cold-cache decompiler performance: caches were not cleared.
One process snapshot showed roughly 5.5 GB combined worker RSS, not aggregate
PSS or a measured peak. Seven-worker suite memory exceeds the earlier informal
2 GB expectation. Skips were retained, not newly added or individually re-audited.

## Failure Census

All modules below are under `angr_platforms/tests/`.

| Module | Failures |
| --- | ---: |
| test_x86_16_cli.py | 15 |
| test_x86_16_sortdemo_regressions.py | 15 |
| test_x86_16_sample_matrix.py | 4 |
| test_x86_16_heapsort_widening_regression.py | 2 |
| test_x86_16_layer_boundaries.py | 2 |
| test_cli_function_discovery_isolation.py | 1 |
| test_decompiler_architecture_check.py | 1 |
| test_test_ownership_manifest.py | 1 |
| test_x86_16_callsite_block_inventory_reuse.py | 1 |
| test_x86_16_debug_info_real_compilers.py | 1 |
| test_x86_16_msc_caller_cleanup.py | 1 |
| test_x86_16_segmented_stack_alias.py | 1 |
| test_x86_16_signed_global_declarations.py | 1 |
| test_x86_16_sortdemo_positive_bp_acceptance.py | 1 |
| test_x86_16_string_corpus_anchors.py | 1 |
| test_x86_16_tail_callsite_inventory.py | 1 |

## Observed Semantic Failures

- RunMenu, named and sidecar-free: gcc rejects pointer shifts/XORs in surviving
  flag equations. The sidecar-free ESC test's partial C **contains case 27 and
  return**; its failure is compilation, not demonstrated loss of ESC here.
- InitMenu: final validation reports four reads of an uninitialized loop local.
  Partial C has `for (; ...; ...)`, without the expected initializer.
- Sidecar-free InitBars: validation reports an uninitialized stack local and
  duplicate callsite `0x1056f`, expected one call but observed two.
- ExchangeSort: validation reports a missing loop guard.
- PercolateDown: validation reports a predicate mismatch involving a signed
  cast of a stack value. Do not erase the cast merely to match a fixture.
- TIDShowRange: validation reports uninitialized locals and a call argument
  class mismatch; the final unassigned-local guard rejects output.
- Small COD byte-condition case: gcc rejects an undeclared `int33` helper.
- DrawTime: two tests reject the forwarded wide-delay argument shape.
  HeapSort, SwapBars, InsertionSort, and main also have shape/scorecard failures;
  these require comparison against typed facts before being called semantic
  loss or obsolete naming expectations.

These are observed failures, not proof of their earliest faulty producer.
Trace IR/SSA, Alias, Types, and Structuring before editing. A validation report
at postprocess is not permission to introduce semantic recovery there.

## Contract and Fixture Findings

- Architecture checker misses Makefile `+=` entries: `_makefile_variable_words`
  reads only the first `:=` block. ALU tests are appended to QA_PYTEST_TARGETS,
  despite the reported absence. The exact live DOS LoadProgram node really is
  absent from that variable. Repair the inventory reader and real omission;
  do not just duplicate the ALU entry to silence a false diagnostic.
- Ownership expectation for `type_array_matching.py` predates its added generic
  annotation regression. Preserve selection of both required test modules.
- Two layer-boundary tests report `quality` as production-wired without an
  importer. Verify actual import wiring before changing admission status.
- Several discovery/CLI fixtures lack `project.loader`; other CLI assertions
  expect status text or legacy timeout wording. Verify stdout/stderr separation
  and error paths before changing them. These are triage candidates, not
  permission to relax production contracts.
- Callsite inventory fixture omits the now-required request-local cache.
- Synthetic DOS argument tests expect raw BP notation but observe typed SEG_U8
  or SEG_U16 helper expressions. Verify width and value/pointer semantics before
  replacing text assertions.
- The real-compiler corpus reports an MSC8 build failure. Investigate its tool
  diagnostics separately from decompiler semantics; do not add a skip.

## Next Batches in Order

### 1. Make Acceptance Checks Trustworthy

Reason: misleading gate inventories obscure which checks actually execute.
DoD: handle literal Make assignments/appends correctly with focused positive
and negative tests; enroll the real missing node; preserve duplicate/missing
target detection; fix the ownership expectation; resolve the quality-module
wiring discrepancy with evidence. Whole architecture and affected tests pass.
Failure: ignoring appended inventories, silencing violations, adding a false
production allowlist, or removing a required regression.

### 2. Repair RunMenu Flag and Address Semantics

Reason: multiple current SORTD cases cannot compile; retained flag equations
also expand analysis work. Inspect flag liveness in IR and Value/Address
projection in Types before deciding which owner is faulty.
DoD: named and sidecar-free RunMenu pass validation and strict compilation;
binary-proven calls, branch cases including ESC, and effects survive. Any DCE
uses complete consumed evidence; live integer values never become C pointers.
Failure: rendered-C edits, guessed dead flags, casts added only to appease gcc,
or acceptance based only on disappearance of the equations.

### 3. Restore Initializers, Unique Calls, and Guards

Reason: validation detects missing data/control effects, not cosmetic issues.
DoD: InitMenu/InitBars/ExchangeSort/PercolateDown and TIDShowRange regressions
pass at their owning layers, with exact initialized storage, call multiplicity,
signed predicates, and loop guards. Keep refusal coverage and source comparisons.
Failure: bypassing validation, guessing an initializer, deleting a live call,
or dropping a signed-width distinction.

### 4. Close Remaining Contracts and Classify Fixtures

Reason: the rest mixes interprocedural/ABI issues, diagnostic compatibility,
external-tool failures, and potentially obsolete shape expectations.
DoD: classify every remaining node; preserve semantic assertions while updating
only demonstrably stale fixtures. Check DrawTime wide arguments, HeapSort/SwapBars
pointer classes, DOS helper declaration ownership, and tail-call kind explicitly.
Delete a test only with documented duplicate/superseded/invalid proof.
Failure: treating all 49 failures as formatting debt, blessing changed semantics,
or changing stdout/stderr policy merely to satisfy old capture expectations.

### 5. Repeat Full Acceptance, Then Optimize Measured Costs

Reason: curated green did not establish full acceptance; repeated expensive
failing decompilations should not define the final performance design.
DoD: stable complete collection reaches zero failures, global typing/linters
pass, and required executable gates remain green. Re-profile residual costs
under Step 10's repeatable end-to-end acceptance criteria; preserve coverage.
Failure: presenting a focused rerun as a full census, timeout inflation, skipped
coverage, or claiming a speedup from cache state or fewer tests alone.

## Ten Slowest Cases

JUnit durations include case setup/call/teardown. Names are unique in this audit.

| Seconds | Test |
| ---: | --- |
| 266.970 | test_decompile_cli_recovers_tidshowrange_layout_logic |
| 139.983 | test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants |
| 138.311 | test_sortdemo_runmenu_default_direct_path_validates_without_temp_carrier_fallback |
| 135.693 | test_initmenu_pause_zero_guard_has_no_raw_flag_carrier@sortd-initmenu |
| 123.392 | test_sortdemo_runmenu_typed_switch_artifacts_are_safe_and_materialized |
| 109.139 | test_sortd_initmenu_materializes_indexed_near_pointer_table@sortd-initmenu |
| 101.603 | test_cod_known_helper_signatures_are_declared[EGAME2.COD-_openFileWrapper-anchors2] |
| 96.663 | test_sortd_runmenu_signed_wide_global_is_sidecar_free_and_validated |
| 95.684 | test_cod_openfilewrapper_direct_forwarding |
| 93.743 | test_sortd_runmenu_sidecar_free_preserves_binary_escape_exit |

The ten slowest cases exercise live corpus decompilation; multiple tests revisit
RunMenu/InitMenu. This is evidence to investigate shared immutable artifacts,
not proof those tests are duplicates. Their semantic assertions differ.

## Timing

Audit began 13:33:10 +02:00 and finished about 13:48:12 +02:00. No whole-suite
failure is closed by this report. Global MyPy remains at 146 diagnostic lines
from the preceding quality-fast run. The prior weighted 75%/80-115h figures
remain historical estimates, not revalidated completion or delivery forecasts.
