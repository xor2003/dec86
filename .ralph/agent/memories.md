# Memories

## Patterns

## Decisions

## Fixes

### mem-1776944201-5f4b
> failure: cmd=./.venv/bin/python - <<'PY' from angr.sim_variable import SimRegisterVariable ... print(v.__dict__) PY, exit=1, error=SimRegisterVariable has no __dict__ during local attribute introspection, next=use dir/getattr for SimRegisterVariable fields
<!-- tags: tooling, error-handling, python | created: 2026-04-23 -->

### mem-1776942714-fcf5
> failure: cmd=./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_package_exports.py -k 'decompiler_postprocess_registry_order or postprocess_passes_for_wrapper', exit=1, error=test_x86_16_decompiler_postprocess_registry_order still expects old pass order with _lower_stable_ss_stack_accesses_8616 before callsite passes, next=update the registry-order expectation and any wrapper pass-order assertions to match the intentional canonical ordering change
<!-- tags: testing, error-handling, postprocess | created: 2026-04-23 -->

### mem-1776940577-fc69
> failure: cmd=rg -n 'postprocess|validation|changed|unknown|failed|warning|WARNING' /tmp/inertia_109e8.after.out /tmp/inertia_109e8.after.err, exit=1, error=no postprocess/validation diagnostics in exact-lane stderr/stdout, next=inspect function info or pass behavior via focused tests instead of relying on console diagnostics
<!-- tags: tooling, error-handling, decompile | created: 2026-04-23 -->

### mem-1776940365-61a8
> failure: cmd=rg -n '_attach_callsite_summaries_8616|_materialize_callsite_stack_arguments_8616|_materialize_callsite_prototypes_8616' inertia_decompiler/cli_decompilation.py -S, exit=1, error=no direct callsite postprocess pass names in cli_decompilation.py, next=inspect decompiler_postprocess_stage integration and CLI wrapper imports before assuming pass is unused
<!-- tags: tooling, error-handling, search | created: 2026-04-23 -->

### mem-1776940277-e7ac
> failure: cmd=sed -n '1,220p' inertia_decompiler/decompiler_postprocess_calls.py, exit=2, error=file does not exist; next=read angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py canonical module
<!-- tags: tooling, error-handling, paths | created: 2026-04-23 -->

### mem-1776939556-de97
> failure: cmd=rg -n "run_stack_lowering_pass|lower_stable_ss_stack_accesses|_run_stack_lowering_pass" angr_platforms/tests inertia_decompiler tests -S, exit=2, error=rg: tests: No such file or directory, next=search existing angr_platforms/tests path and omit missing repository-root tests directory
<!-- tags: tooling, error-handling, paths | created: 2026-04-23 -->

### mem-1776939556-8d9b
> failure: cmd=./.venv/bin/pytest -q angr_platforms/tests/test_x86_16_callsite_summary.py angr_platforms/tests/test_x86_16_helper_effect_summary.py angr_platforms/tests/test_x86_16_stack_probe_return_state_regression.py angr_platforms/tests/test_x86_16_segmented_stack_alias.py, exit=1, error=stack_probe_return_state_regression exposed oversized summary fallback returned False, next=allow stack-probe SS return-state fallback to use concrete collected stack stores when strict oversized summary shape fails
<!-- tags: testing, error-handling, stack-segment | created: 2026-04-23 -->

### mem-1776939556-84b9
> failure: cmd=./.venv/bin/python decompile.py --help | rg -n "cache|no-cache|fresh", exit=1, error=no cache-related help matches, next=inspect inertia_decompiler/cache.py source directly for cache invalidation inputs
<!-- tags: tooling, error-handling, cache | created: 2026-04-23 -->

### mem-1776939556-bebf
> failure: cmd=rg -n "postprocess|validation|Skipping|warning|WARNING|tail|materialize|rewrite" /tmp/inertia_109e8.err /tmp/inertia_109e8.out, exit=1, error=no matches while checking diagnostics, next=treat as absence of warnings and continue with focused code inspection
<!-- tags: tooling, error-handling, decompile | created: 2026-04-23 -->

### mem-1776938378-c3dd
> failure: cmd=rg -n "_attach_callsite|_materialize_callsite" inertia_decompiler/cli_decompilation.py inertia_decompiler/cli_c_ast_rewrites.py, exit=1, error=no matches, next=broaden search to repository callsite symbols before assuming pass is unused
<!-- tags: tooling, error-handling, search | created: 2026-04-23 -->

### mem-1776938378-6354
> failure: cmd=rg -n "aNchkstk|chkstk|stack-probe|stack probe|Nchk" -S inertia_decompiler angr_platforms tests *.py *.md, exit=2, error=rg: tests: No such file or directory, next=rerun repository-root searches with existing paths only (for tests use angr_platforms/tests)
<!-- tags: tooling, error-handling, paths | created: 2026-04-23 -->

### mem-1776937281-eb48
> failure: cmd=sed -n '1,260p' angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py from /home/xor/vextest/angr_platforms, exit=2, error=duplicated submodule path; cmd=./.venv/bin/pytest from /home/xor/vextest/angr_platforms, exit=127, error=.venv absent in submodule root; next=run repository-root paths from /home/xor/vextest or submodule-relative paths from /home/xor/vextest/angr_platforms
<!-- tags: tooling, error-handling, paths | created: 2026-04-23 -->

### mem-1776936694-c039
> failure: cmd=sed -n '1,220p' .ralph/agent/scratchpad.md, exit=2, error=no such file or directory, next=create .ralph/agent/scratchpad.md and continue sweep protocol
<!-- tags: tooling, error-handling, ralph | created: 2026-04-23 -->

### mem-1776890236-c637
> failure: cmd=sed -n '1,220p' .ralph/urgent-steer.json, exit=2, error=no such file or directory, next=locate the active urgent steer artifact and read that path before rerunning ralph emit
<!-- tags: tooling, error-handling, ralph | created: 2026-04-22 -->

### mem-1776890229-8fb4
> failure: cmd=ralph emit "LOOP_COMPLETE" "finalizer: primary task still in_progress; worker says PLAN #1 advanced not complete; latest review artifact is changes_requested", exit=1, error=Urgent steer is pending. Do not hand off yet., next=read .ralph/urgent-steer.json, address steer, then rerun ralph emit once handoff is ready
<!-- tags: tooling, error-handling, ralph | created: 2026-04-22 -->

### mem-1776873850-2101
> failure: cmd=tail -n 3 .ralph/events.jsonl, exit=1, error=no such file or directory, next=verify emitted events via .ralph/events-*.jsonl or ralph events instead of assuming the default path exists
<!-- tags: tooling, error-handling, ralph | created: 2026-04-22 -->

### mem-1776873725-a42c
> failure: cmd=sed -n '1,220p' .ralph/agent/scratchpad.md, exit=2, error=no such file or directory, next=create .ralph/agent/scratchpad.md and continue sweep protocol
<!-- tags: tooling, error-handling, ralph | created: 2026-04-22 -->

### mem-1776871998-2b2b
> failure: cmd=./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x10ce0 --timeout 30 --alternate-source-c, exit=3, error=reviewer rerun timed out despite prior claimed exit 0 proof, next=do not treat width-boundary step as closed until QuickSort 30s lane is reproducible or acceptance evidence is re-scoped
<!-- tags: decompile, error-handling, review | created: 2026-04-22 -->

### mem-1776861981-4aff
> failure: cmd=printf append scratchpad note with backticks, exit=127, error=command substitution on backticked text, next=append scratchpad note using a quoted heredoc
<!-- tags: tooling, error-handling, ralph | created: 2026-04-22 -->

### mem-1776861137-a13b
> failure: cmd=sed -n '1,220p' .ralph/agent/scratchpad.md, exit=2, error=no such file or directory, next=create .ralph/agent/scratchpad.md and continue finalizer protocol
<!-- tags: tooling, error-handling, ralph | created: 2026-04-22 -->

### mem-1776859247-f02a
> failure: cmd=sed -n '1,220p' .ralph/tasks/task-0001.md, exit=2, error=no such file, next=read .ralph/tasks/task-0001-complete-plan.code-task.md
<!-- tags: tooling, error-handling, ralph | created: 2026-04-22 -->

### mem-1776859201-f6a8
> failure: cmd=apply_patch update .ralph/agent/final.latest.md, exit=context-mismatch, error=expected line not found, next=reload file and patch with exact context
<!-- tags: tooling, error-handling | created: 2026-04-22 -->

### mem-1776858214-ba42
> failure: cmd=ralph tools task ensure "Fix fallback NameError in non-optimized known-function path" --key fix:sidecar-cod-metadata-nameerror -p 2 -d "...", exit=2, error=unexpected argument -d for task ensure, next=rerun ensure with only key/priority/title
<!-- tags: tooling, error-handling, ralph | created: 2026-04-22 -->

### mem-1776858200-3fd9
> failure: cmd=./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --addr 0x102e0 --timeout 6 --alternate-source-c, exit=python-traceback, error=NameError: name '_sidecar_cod_metadata_for_function' is not defined in inertia_decompiler/cli_fallback_decompilation.py:706, next=restore/import _sidecar_cod_metadata_for_function in fallback non-optimized known-function path
<!-- tags: tooling, error-handling, decompile | created: 2026-04-22 -->

### mem-1776857676-4558
> failure: cmd=./.venv/bin/python -u decompile.py /home/xor/vextest/SORTDEMO.EXE --timeout 6 --max-functions 8, exit=python-traceback, error=NameError: name 'angr' is not defined in inertia_decompiler/cli_core.py:2542, next=import/resolve angr in cli_core runtime path and rerun bounded sweep
<!-- tags: tooling, error-handling, decompile | created: 2026-04-22 -->

## Context
