# Checked VEX Wrapper Contracts

## Reason And Layer

PyVEX's `vvifyresults` decorator returns `VexValue` wrappers at runtime, while
static inference can expose its underlying raw-expression return type.
Frontend memory and direction-step code mixed these inferred values with
concrete integers, producing five diagnostics across memory, processor and
relative-branch handling.

`vex_value_contract.py` now owns the existing concrete wrapper check extracted
from `instr_base.py`. Its instruction-facing alias and exception remain intact.
The 32-bit instruction consumer imports directly from the shared owner;
global MyPy caught the initial indirect private re-export, which was corrected.
Memory retains separate typed address and byte-value variables. Direction-step
logic checks wrapper results without changing its constants, widths, bit test
or ITE. Relative branches keep their existing capability check and consume the
already-declared expression field contract.

No semantic recovery moved into Rewrite or the CLI. Byte-safe segmented access
methods in `access.py` and `lift_86_16.py` were not changed. Existing dirty-input
handling was not changed or repaired by this checkpoint.

## Acceptance And Failure

- DoD: real VEX execution preserves one 8-bit store through a 32-bit address,
  including truncation from a wrapped 16-bit value.
- DoD: DF alone selects the 32-bit +1/-1 step for integer and wrapped FLAGS;
  other flag bits do not change that decision. Concrete mode remains integer.
- DoD: unknown wrapper inputs refuse before IR mutation, and existing LOOP
  refusal, segmented memory and 80386 behavior still pass.
- DoD: native wrapper identity and the instruction-facing alias survive;
  focused tools, quality gates and default DOS round trips pass.
- Failure: accept raw expressions or lookalike objects as proven wrappers,
  lose low-byte/word widths, use stale derived direction instead of FLAGS,
  add guessed state, suppress diagnostics or report a partial typing count
  as a complete repository audit.

## Evidence

- Baseline: 35 tests passed in 9.01s.
- First expanded run: 53 tests passed in 9.27s. Additional non-DF flag-bit
  and concrete-mode controls were added afterward.
- Final frontend/80386 run: 273 tests passed in 81.70s, seven dependency
  warnings. Slowest cases: invalid LOCK fault matching (12.97s), prefixed
  stack/short control flow (10.73s), and near/far transfers (10.19s).
- Scoped Ruff `--fix`, MyPy and Pyright pass. Global Vulture passes.
- After the direct 32-bit import change, all 42 wrapper/LOOP/DF tests pass in
  9.57s, and scoped MyPy/Pyright pass for all six touched production modules.
- A completed production audit of X86_16 and `inertia_decompiler` reports
  **176 errors and 37 warnings: 148 X86_16 errors and 28 CLI errors**.
  This is five fewer errors than the previous complete production count of
  181, not a subtraction offered instead of a fresh run. Tests and auxiliary
  scripts are outside this particular audit scope.
- `quality-hard` passes full architecture, type/doc and ownership guards,
  2,793 unit tests in 177.38s, and three executable quality guards. The latter
  share one active import surface; they are not independent native/Python
  comparisons. Typing/edge audits ran concurrently, so timings are not a
  controlled performance comparison.
- Final gates run as `make quality-hard quality-fast test-pipeline` so Make
  shares unchanged prerequisites without dropping checks. The final shared
  unit lane passes 2,793 tests in 119.61s and all three executable quality
  guards pass. Global Make MyPy/Ruff pass; existing Lizard warnings remain
  visible. The combined Make invocation completes successfully.
- The default pipeline passes all three lanes without skips or timeouts:
  2,793 unit tests in 101.20s, QuickC and all seven MS C tiny round trips.
  Each tiny report confirms build/run/decompile/recompile/rebuilt-run success
  and matching original/rebuilt exit codes of 255. The routine selection grew
  by 57 tests in this checkpoint.
- Numeric-frame semantics,
  full-suite and remote CI closure remain open; optimization stays deferred.

Logs: `/tmp/inertia-symbolic-boundary-{before,tests,edges,mypy,pyright,production-pyright,hard,fast,vulture,final-tests,final-mypy,final-pyright,final-gates}.log`.

## Timing

Baseline log completed 2026-09-09 01:59:11 +02:00. By 02:08:53 +02:00 the
273-test edge run and complete production typing audit had finished, 9m42s
after the baseline completion. This excludes initial investigation and is
not an ETA for the remaining plan.
Final combined gates and all tiny reports were verified at 02:19:52 +02:00,
20m41s after the baseline log completed. This includes repeated verification
after the private-import correction and is not active-only coding time.
