# SORTDEMO Condition Views (2026-09-09)

## Executable Acceptance

The exact default command `./decompile.py ./SORTDEMO.EXE` improves from
17/20 accepted functions to **19/20**. PercolateDown (`0x10a88`) and QuickSort
(`0x10ce0`) now pass. InitMenu (`0x10060`) still fails generated-C compilation
because numeric DOS frame offsets became host pointers. Exit status remains 2;
neither the executable nor the full plan is complete.

The latest command completed at 10:59:09 local time: 198.47s wall, 445.57s user
CPU, 8.44s system CPU, maximum process RSS 356144 KiB. The preceding default
run took 280.28s, but this is not a controlled performance comparison or an
aggregate-memory measurement. Fewer failed-function retries explain a plausible
portion of the reduction; no timeout or worker policy changed.

## Root Causes And Ownership

The preceding checkpoint corrected additive fingerprint flattening, which
discarded required signedness casts inside Add/Sub. That fixed PercolateDown
and exposed QuickSort's later predicate mismatch at original JCC `0x10e17`
(rebased `0x1137`).

QuickSort's final `iUp` declaration is signed, while its retained cast and
inner C-variable view still describe the earlier unsigned type. Rematerializing
the typed condition therefore yields a plain signed variable, whereas the
retained AST fingerprints as an explicit signed cast of unsigned storage.
Historical Structuring evidence contains more than one representation.

`lowering/semantic_cast.py` now proves an integer cast is an identity using the
exact variable's unique declaration type, with equal positive source,
destination and declaration widths. This uses argument/local inventories and
variable identity, never names or guessed stack offsets. Conflicting types,
missing widths, pointer types and width-changing casts refuse. Without a native
function declaration surface, the typed expression itself is the boundary.

`validation_condition_identity.py` consumes that proof only for a temporary
final-predicate comparison view. It preserves every operator and non-identity
cast, requires the comparison's signedness, and never mutates the live AST.
The projected predicate must still match the exact typed condition fingerprint.
Ordinary historical fingerprints and fingerprint schema 39 remain unchanged.

## Rejected Experiment

Do not globally erase identity casts from `_expr_fingerprint`. That eliminated
the absolute predicate mismatch but introduced new whole-tail snapshot deltas
as declarations changed between stages. The global-normalization experiment
was removed; current-declaration reasoning belongs in the final comparison.
Also do not accept any historical precision candidate merely because its JCC
matches. Conflicting historical versions are not proof of final equivalence.

## Acceptance Contract

- Reason: representation refinement must not turn an equivalent predicate into
  a false validation failure or hide a genuinely wrong conversion.
- DoD: both failing cast predicates are accepted in the default executable;
  focused QuickSort checks retain pivot loads, swaps and recursive arguments;
  adversarial cast/declaration tests refuse; routine typing, lint and DOS gates
  pass; the original AST and historical fingerprints remain intact.
- Definition of failure: lose a call/effect, accept a wrong signedness or width,
  match a variable by name, mutate C to satisfy validation, normalize historical
  snapshots using later declaration state, or claim InitMenu is fixed.

The initial identity regression failed before the change (one failed, seven
passed in 8.10s). Final focused validation reports 32 passed, seven warnings,
8.82s. The live QuickSort regression passed in the combined diagnostic run;
three fake-codegen boundary failures introduced by the first implementation
were corrected and their focused tests rerun. Scoped MyPy and Pyright pass (two production files,
zero Pyright errors/warnings); Ruff `check --fix` passes.

Evidence logs: `/tmp/inertia-quicksort-precision-diagnostic.log`,
`/tmp/inertia-current-view-focused.log`, `/tmp/inertia-sortdemo-current-view.log`
and `/tmp/inertia-current-view-gates.log`. Diagnostic observations span at least
10:42:23 through 10:59:09 local time, including live reruns, not an estimate of
active coding time or of the remaining InitMenu work.

Final `quality-hard quality-fast test-pipeline` exits zero. Fast/default unit
lanes pass 2,888 tests in 122.66s / 117.53s, with seven / eight warnings.
All three executable guards pass. QuickC passes in 42.220s and all seven MS C
tiny round trips pass in 62.067s. Global Make Ruff/MyPy, architecture checks and
mypyc import checks pass; existing complexity warnings remain visible. These
results do not refresh the full pytest audit or remote CI status.

## Additional Gate Observation

The default unit lane also exposed one `PytestUnraisableExceptionWarning` in
the InitBars topology test: `AnalysisTimeout` arrived inside a weakref callback.
The test passed, but timeout delivery in cleanup remains an open investigation.
Reason: a swallowed soft timeout could undermine execution-budget enforcement.
DoD: reproduce and verify bounded execution and cleanup through the timeout
owner, with a focused regression. Failure: suppress the warning or increase
timeouts without proving the delivery/cleanup contract. This observation does
not establish a new full-suite failure count.
