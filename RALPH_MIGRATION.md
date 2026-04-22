# Ralph Migration (Meta-Harness Parity)

This repo keeps `meta_harness/` unchanged.  
Ralph migration artifacts are now added and mapped from current harness behavior/config.

## Added Files

- `ralph.yml`
- `.ralph/agent/tasks.jsonl`
- `.ralph/tasks/task-0001-complete-plan.code-task.md`

## First Ralph Task

`task-0001`: complete `PLAN.md` with Codex, strictly following `AGENTS.md`, and removing plan items only after deterministic DoD evidence.

## Config Mapping

| Meta-harness source | Ralph destination | Notes |
|---|---|---|
| `.codex_harness.conf: SWEEP_CMD` | `hats.sweeper.instructions` | Same focused SORTDEMO lane, bounded command. |
| `.codex_harness.conf: SWEEP_LABEL` | `hats.sweeper.description`/instructions | Preserved as focused sweep intent. |
| `.codex_harness.conf: PROJECT_NAME/PROJECT_DESCRIPTION` | `core.guardrails` context | Preserved in task + guardrails. |
| `.codex_harness.conf: PRIMARY_PRIORITY/SECONDARY_PRIORITY` | `core.guardrails` | Encoded as primary-lane constraints. |
| `.codex_harness.conf: GENERAL_IMPROVEMENT_RULE` | `core.guardrails` | Preserved verbatim intent (general-purpose fixes only). |
| `.codex_harness.conf: REPO_STANDING_TASKS` | `hats.*.instructions` | Applied to checker/planner/worker roles. |
| `.codex_harness.conf: EVIDENCE_INPUT_FILES` | `checker/planner instructions` | Inputs explicitly listed in role instructions. |
| `meta_harness step flow: sweep->checker->planner->worker->reviewer->crash-reviewer` | `hats` event chain | Same order encoded by trigger/publish events. |
| `meta_harness: worker_finish_token` | `event_loop.completion_promise` + `finalizer` | Ralph uses `LOOP_COMPLETE`. |
| `meta_harness compact state files under .codex_automation/` | `.ralph/agent/*.latest.md` + tasks/memories | Ralph-native runtime state path. |

## What Is Intentionally Not Mirrored 1:1

- `meta_harness` web UI and maintenance JSON schemas remain local-only.
- `run.lock`, `STOP`, and auto-commit policy are not reimplemented in this first Ralph config.
- Exact provider/model split per role (`planner/checker/worker/reviewer`) is left to Ralph backend runtime settings; `ralph.yml` currently uses `cli.backend=codex`.

## Run Ralph with This Migration

```bash
# inside this repo, with ralph installed
ralph run -c ralph.yml -p "Execute task-0001 from .ralph/tasks and complete PLAN.md under AGENTS.md rules."
```

Optional:

```bash
ralph tools task list
ralph tools task ready
```
