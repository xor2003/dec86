# Decompiler Telemetry

Purpose: quickly find slow decompilation stages without dumping huge logs.

Enable compact spans:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_SPAN_FILE=angr_platforms/.cache/otel.json \
./.venv/bin/python ./decompile.py ./SORTDEMO.EXE
```

Useful knobs:

- `INERTIA_OTEL_SPANS=1` enables tracing. Default is off.
- `INERTIA_OTEL_SPAN_FILE=path.json` writes one compact JSON summary.
- `INERTIA_OTEL_TOP_N=16` controls how many slow spans/aggregates are kept.
- `INERTIA_OTEL_MIN_MS=1` hides tiny spans from the `top` list.
- `INERTIA_OTEL_STDERR=0` suppresses the `[otel-compact]` stderr line when writing a file.
- `INERTIA_OTEL_FULL_JSONL=1` writes summary plus every span as JSONL.

Output shape is intentionally compact:

```json
{"span_count":8,"total_ms":1907.4,"top":[["direct.decompile_job",909.7,{"addr":"0x1000","name":"_start"}]],"agg":[["direct.decompile_job",1,909.7,909.7]],"errors":[]}
```

Implementation:

- Use `@trace_function(name="...")` on normal functions. It auto-extracts common attributes from arguments: `binary`, `addr`, `function`, `project`, `timeout`, `status`, `window`, and related fields.
- Use `with span("operation.name", ...)` only for local closures, timeout wrappers, and operations that are not functions.
- Use `with span_here(...)` when the calling function name is a good span name.
- Use `annotate_current_span(...)` only for values known after work completes, such as `status`, `elapsed_ms`, `blocks`, and `bytes`.

Keep spans high-level first: project build, sidecar load, discovery, per-function work, decompile, tail validation, recompilation/acceptance. Avoid adding spans inside tight loops unless a specific profiler run proves the loop is the problem.
