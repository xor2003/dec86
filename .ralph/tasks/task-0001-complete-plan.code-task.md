---
status: open
created: 2026-04-22
---
# Code Task: Complete PLAN.md Under AGENTS.md Architecture Rules

## Objective

Execute `PLAN.md` to completion using Codex with strict architectural compliance from `AGENTS.md`.

## Scope

- Target plan: `PLAN.md`
- Architecture contract: `AGENTS.md`
- Primary corpus lane: `SORTDEMO.EXE`
- Validation mode: focused tests + one-function decompilation runs

## Required Rules

1. Solve issues at earliest correct layer (`IR -> Alias -> Widening -> Traits -> Types -> Rewrite`).
2. Do not run full SORTDEMO decompilation; use one-function `--addr` commands only.
3. Do not perform semantic recovery from rendered C/ASM text.
4. Do not remove plan items without deterministic DoD proof.
5. Remove finished goals only after tests or focused `decompile.py` evidence confirms DoD.

## Execution Steps

1. Read `PLAN.md` and identify the first unfinished item.
2. Implement changes with architecture-first placement.
3. Run targeted `pytest` and focused `decompile.py --addr ... --alternate-source-c` checks from that item.
4. Record evidence artifacts in `.ralph/agent/worker.latest.md`.
5. If DoD is met, remove the finished item from `PLAN.md`; otherwise keep it and refine into smaller deterministic substeps.
6. Repeat until no unfinished `PLAN.md` items remain.

## Deterministic Completion Criteria

- `PLAN.md` contains no unfinished items.
- Every removed item has linked verification evidence in `.ralph/agent/*.latest.md`.
- No validation state is hidden (`changed`, `unknown`, `uncollected` must remain explicit).
- No full SORTDEMO run was used.

## Output Artifacts

- `.ralph/agent/sweep.latest.md`
- `.ralph/agent/check.latest.md`
- `.ralph/agent/worker.latest.md`
- `.ralph/agent/review.latest.md`
- `.ralph/agent/final.latest.md`
