# Memories

## Patterns

## Decisions

## Fixes

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
