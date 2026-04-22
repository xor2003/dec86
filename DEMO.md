# Demo Plan

## Demo goal

Show three things clearly:

1. The decompiler automatically recovers functions even without debug info.
2. It attempts decompilation for every recovered function it chooses to show, not just hand-picked examples.
3. It reports fallbacks, timeouts, and validation outcomes honestly instead of pretending everything is clean.

The demo should leave a viewer with one conclusion: this is already a real decompiler with an architecture worth contributing to.

## Stage A. CLI proof of automatic recovery and per-function attempts

### A1. Finish LIFE2 direct decompile visibility

Status:

- in progress

Target files:

- `/home/xor/vextest/inertia_decompiler/cli.py`
- `/home/xor/vextest/angr_platforms/tests/test_x86_16_cli.py`

Required changes:

- Adjust merged display ordering using only general signals:
  - recovery score
  - truncation/body-size preference
  - body-seed priority
  - callee relevance where already justified by general graph behavior
- Keep the function-discovery story honest:
  - `flair_pat` / `flair_sig` can label library functions, but they do not discover binary-owned functions
  - binary-owned functions must be counted and ranked from direct binary evidence such as near/far call targets, prologues, terminal follow-ons, and later relocation-backed hints when available
  - relocations may point to data or code, so they should be treated as evidence to rank or confirm candidates, not as unconditional function starts
- Do not use peer-EXE catalog import in the demo path. LIFE2 demo recovery must stay honest to direct binary/sidecar evidence for that binary.
- Do not add sample-specific address checks.
- Do not add sample-specific symbol-name hacks.
- Do not add LIFE2-only special casing.

Required tests:

- `rank_function_cfg_pairs_for_display_prefers_body_seed_and_its_callees`
- `rank_function_cfg_pairs_for_display_prefers_truncated_body_seed_over_wrapper_paths`
- `test_daemon_thread_pool_executor_detaches_non_waiting_workers_from_atexit_registry`

Verification commands:

```bash
uv run pytest /home/xor/vextest/angr_platforms/tests/test_x86_16_cli.py -k 'rank_function_cfg_pairs_for_display_prefers_body_seed_and_its_callees or rank_function_cfg_pairs_for_display_prefers_truncated_body_seed_over_wrapper_paths or main_parallel_uses_late_success_after_deadline'
uv run python /home/xor/vextest/decompile.py /home/xor/vextest/LIFE2.EXE --timeout 6 --max-functions 2
```

Definition of done:

- The honest whole-binary LIFE2 path recovers roughly the real function inventory for the binary, on the order of 100 functions, without peer-EXE catalog import.
- On the capped LIFE2 run, the larger startup body is visible ahead of wrapper/runtime entries.
- The ordering is explained by general ranking logic.
- No sample-specific hacks exist in code or tests.

Progress so far:

- Whole-binary EXE reporting now exposes the larger direct-binary discovery inventory separately from the smaller immediately materialized function list.
- Seeded recovery now keeps top-ranked initial seeds ahead of later neighbor follow-ons, so the demo subset stays aligned with the honest seed ranking instead of drifting into wrapper-adjacent callees too early.
- CLI wording now makes it explicit that signature matches are only bounded library hints; non-library function recovery still comes from binary evidence.
- The current-project discovery path now reuses the best part of the Reko-style approach: recursive entry/call tracing first, heuristic scan second, and relocation-backed targets only as extra evidence. DOS MZ relocation entries are now exposed by the loader and feed the seed ranking as strong hints for far call/jump targets and weaker hints for generic far pointers.
- The CLI now has a fast opcode-level tracer pre-pass that contributes direct `CALL`/`JMP`/`RET` seed evidence without replacing the broader x86-16 recovery pipeline.
- The tracer and seed ranker now treat post-`RET` follow-ons conservatively: after `ret` and any `0x90`/padding bytes, they only treat the next address as a weak function seed if it begins with a real 16-bit frame prologue such as `push bp; mov bp, sp`.
- Whole-binary EXE demo runs no longer depend on fully materializing the entire catalog up front. When broad discovery finds many ranked candidate addresses but bounded recovery is incomplete, the CLI now falls back to those ranked direct-binary addresses and recovers only the shown subset lazily.
- Capped EXE demo runs now probe a bounded prefix of ranked binary addresses and prefer the highest-ranked seeds that are actually recoverable quickly, instead of blindly previewing the first raw seed list entries.
- Hidden-sidecar EXE runs now report the final supplemented display count honestly. The `selected N` line is emitted after seeded/preview supplementation and final capping, so the demo summary no longer understates how many functions the CLI will actually attempt to show.
- Hidden-sidecar EXE runs now fill display slots from ranked preview items instead of stopping at the tiny upfront materialized set. This makes `--max-functions` behave more honestly on `LIFE2.EXE`.
- The capped hidden-sidecar demo lane now orders already recovered preview functions for throughput, not just discovery interest. For very small caps it still keeps the entry in view, but wider capped runs now spend their slots on the cheapest recoverable bodies first so the demo emits more real C before the wall-clock budget expires.
- The hidden-sidecar capped display lane now preserves that throughput-friendly order all the way into actual decompilation, instead of letting the generic EXE display reranker overwrite it later. In the current `LIFE2.EXE --timeout 6 --max-functions 4` smoke, the first emitted bodies are now `sub_115d8` and `sub_1157c`, and their C reaches `stdout` before the outer `28s` watchdog kills the run.
- Deeper diagnosis on `LIFE2.EXE` showed that the main demo bottleneck was not seed discovery itself. The top ranked seeds are largely recoverable and often decompile successfully in about 1-2 seconds, but the capped hidden-sidecar path was spending too much wall-clock in broad recovery before it reached them. The demo lane now short-circuits to ranked direct-binary preview for capped hidden-sidecar EXE runs instead of paying that broad-recovery cost first.
- CLI and sidecar/project-loading lifecycle logs now carry timestamps in real runs and move to `stderr`, which keeps `stdout` much closer to compilable C output.
- Timeout reporting is now more explicit: summaries distinguish “function was discovered but timed out during decompilation” from discovery failure, and non-optimized fallback retries are bounded more aggressively after a timeout so the demo does not linger as long in post-timeout recovery.
- Whole-binary runs no longer auto-cap by default when `--max-functions` is omitted. `decompile.py` now tries to decompile the full non-library recovery set unless the user explicitly asks for a cap.
- The post-summary hang root cause was localized to background `ThreadPoolExecutor` workers staying registered in Python's atexit thread registry. The custom daemon executor now detaches non-waiting workers from that registry on shutdown, so `LIFE2.EXE --timeout 6 --max-functions 2` now exits immediately after the summary instead of lingering for tens of seconds.
- `cProfile` on the real `LIFE2.EXE` demo path showed that `flair_pat+flair_sig` loading was a bigger bottleneck than the decompiler itself. Adding cache coverage for PAT regex/hyperscan preparation reduced one measured whole-run profile from about 21.6s to about 17.4s, and cut sidecar metadata load from about 11.8s to about 8.6s.
- Direct-binary candidate inflation was traced to accepting too many weak call/jump targets as function starts. The seed path now keeps strict filtering for weak jump and post-`RET` candidates, but direct `CALL` targets may still be admitted without a classic frame prologue when they decode as plausible helper entries. This preserves helpers like `chkstk`, `atol`, `astart`, and `cintDIV` without reopening the old broad overcount.
- On the current honest `LIFE2.EXE` path, the raw seed inventory is now much tighter than before: about 204 direct-binary candidate starts on `LIFE2.EXE` versus about 211 on `LIFE.EXE`, instead of the earlier ~300 range.
- Audit against `LIFE.EXE` is now sharper: `LIFE.EXE` exposes about 108 visible labeled functions, and the remaining `LIFE2` misses are down to a small helper/outlier set rather than a broad detector failure. The current missing peer-oracle labels are mostly far/runtime helpers such as `FISRQQ`, `FICRQQ`, `FIERQQ`, `FJARQQ`, `FJSRQQ`, `FJCRQQ`, `FIARQQ`, `FIWRQQ`, `fltused`, `fpemulator`, `fpmath`, `fpsignal`, `dosret0`, `dosretax`, `cltoasub`, `cxtoa`, `cintDIV`, and `astart`.

Next concrete work:

- Tighten the recovered-function display ranking so the capped LIFE2 path consistently surfaces the strongest startup body ahead of wrappers/runtime helpers in the real emitted function list, not just in the seed inventory.
- Decide whether the remaining far/helper misses belong in the demo-facing discovery path or should stay outside the default count as explicit runtime/library helpers.
- Extend relocation-backed candidate evidence beyond DOS MZ where equivalent fixup data is available, while keeping direct call/prologue proof above relocation-only hints.

## Stage B. Corpus-level proof that this is not a toy

### B1. Complete the honest full-COD tail-validation sweep

Target files:

- `/home/xor/vextest/scripts/decompile_cod_dir.py`
- `/home/xor/vextest/angr_platforms/tests/test_decompile_cod_dir_parallelism.py`
- `/home/xor/vextest/PLAN2.md`

Required changes:

- Keep bounded child-timeout behavior.
- Keep placeholder records for missing child results.
- Run the whole `cod/` corpus without `--skip-existing`.
- Produce one final full artifact that covers all 432 PROC work items and includes:
  - `changed`
  - `unknown`
  - `uncollected`

Definition of done:

- There is one reproducible no-skip artifact and one matching summary for the full corpus.
- It is not a partial rerun.
- Missing PROC outcomes are not silently dropped.

### B2. Ensure timeout/fallback PROC outcomes remain attributable

Target files:

- `/home/xor/vextest/scripts/decompile_cod_dir.py`
- `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/tail_validation.py`
- `/home/xor/vextest/angr_platforms/tests/test_decompile_cod_dir_parallelism.py`
- `/home/xor/vextest/PLAN2.md`

Required changes:

- Confirm placeholder results survive the aggregate/report path.
- If attribution is lost, extend aggregate/reporting to preserve:
  - `cod_file`
  - `proc_name`
  - `proc_kind`

Definition of done:

- The final report can name which PROC items are `uncollected`.
- The report is not limited to counts only.

## Stage C. Build the repeatable demo script

### C1. Prepare the exact demo sequence

Suggested flow:

1. Run `decompile.py` on `LIFE2.EXE` with capped output.
2. Point out:
   - no debug info
   - recovered function count
   - top functions selected
   - real startup body shown before wrappers
   - each displayed function attempted
3. Show one or two recovered C outputs.
4. Show one fallback, timeout, or validation-delta example.
5. Run `decompile_cod_dir.py` over the corpus or show the final artifact summary.
6. Explain that the architecture is designed to reject semantic drift, not just print pretty C.

Required artifact:

- `/home/xor/vextest/docs/demo_script.md`

Definition of done:

- Someone else can follow the script and reproduce the same story without oral clarification.

### C2. Capture stable demo outputs

Required artifacts:

- one sample terminal transcript
- one saved corpus summary
- one example validation delta
- one example successful body-heavy decompile

Suggested location:

- `/home/xor/vextest/docs/demo_outputs/`

Definition of done:

- The project can still be presented if a live run times out or varies slightly.
- The captured outputs match current code behavior.

## Demo plan final DoD

The demo plan is complete when all of the following are true:

- A capped `LIFE2.EXE` run visibly shows the real startup body ahead of wrappers by general ranking logic.
- The CLI explicitly states that functions were automatically recovered and that decompilation was attempted per displayed function.
- The CLI distinguishes decompiled, fallback, timeout, and validation outcomes honestly.
- There is one full no-skip COD corpus artifact with attributable `changed`, `unknown`, and `uncollected` PROC results.
- There is a repeatable demo script with saved outputs that another developer could present.
