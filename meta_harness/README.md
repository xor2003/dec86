# Meta Harness

Small reusable autonomous-improvement harness for repository work.

## Recommended step order

1. `sweep`
   Gather fresh project evidence and generated artifacts.
2. `checker`
   Validate the current evidence only. No code changes.
3. `planner`
   Update `PLAN.md` using the checked evidence. No implementation.
4. `worker`
   Implement unfinished plan items. This is the only role that should spend most of the time changing code.
5. `reviewer`
   Audit completed work, prune finished plan items, and improve the harness itself when useful.
6. `crash-reviewer`
   Runs only when the harness crashes or fails unexpectedly.

This separation helps reduce role confusion:

- `checker` avoids premature planning drift.
- `planner` avoids mixing planning with implementation.
- `worker` stays focused on code and verification.
- `reviewer` keeps the plan honest and can improve the harness loop itself.

## Layout

- `config.py`
  Runtime and backend configuration.
- `prompts.py`
  Role prompts and step responsibilities.
- `llm.py`
  Backend adapters and local-model validation.
- `orchestrator.py`
  Main cycle orchestration, resources, artifacts, restarts.
- `cli.py`
  Main entry point used by `python -m meta_harness`.

## Tests

Run:

```bash
python -m pytest -q meta_harness/tests
```

## Resume

If a cycle is interrupted, the harness writes `cycle.state.json` inside the
latest cycle directory. Re-run with:

```bash
python -m meta_harness --resume
```

to continue from the first unfinished step, or `--fresh` to ignore the saved
state and start a new cycle.
