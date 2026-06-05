# Decompiler Telemetry

Purpose: quickly find slow decompilation stages without dumping huge logs.

Enable compact spans:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_SPAN_FILE=angr_platforms/.cache/otel.trace.txt \
./.venv/bin/python ./decompile.py ./SORTDEMO.EXE
```

Useful knobs:

- `INERTIA_OTEL_SPANS=1` enables tracing. Default is off.
- `INERTIA_OTEL_SPAN_FILE=path` writes compact agent text by default, even for `.json` suffixes.
- `INERTIA_OTEL_SPAN_FORMAT=text|slow|json|jsonl` overrides file format. Use `json`/`jsonl` only for parsers.
- `INERTIA_OTEL_TEXT_MAX_SPANS=200` caps rows in agent-text output.
- `INERTIA_OTEL_TOP_N=16` controls how many slow spans/aggregates are kept.
- `INERTIA_OTEL_MIN_MS=1` hides tiny spans from the `top` list.
- `INERTIA_OTEL_STDERR=0` suppresses the `[otel-compact]` stderr line when writing a file.
- `INERTIA_OTEL_FULL_JSONL=1` writes summary plus every span as JSONL.
- `INERTIA_OTEL_EXPORT_OTLP=1` also exports spans through OTLP HTTP/protobuf.
- `INERTIA_OTEL_SERVICE_NAME=inertia-decompiler` overrides the OpenTelemetry service name.
- `INERTIA_OTEL_FORCE_FLUSH_MS=3000` controls exporter flush timeout at process exit.

Use text for agent handoff:

```text
summary total_ms=8562.5 spans=6 otel=off errors=0
schema: id|parent|ms|name|attrs
5|2|7372.118|direct.decompile_job|addr=0x1000 blocks=11 bytes=65 name=cmp_i16 status=ok timeout=73
```

Use slow mode when only the longest spans matter:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_SPAN_FORMAT=slow \
INERTIA_OTEL_SPAN_FILE=angr_platforms/.cache/otel.slow.txt \
./.venv/bin/python ./decompile.py examples/build_msc6/CMP16.EXE
```

Example:

```text
trace total=8562.5ms spans=6 otel=off errors=0
7372.118 direct.decompile_job addr=0x1000 blocks=11 bytes=65 name=cmp_i16 status=ok timeout=73
126.63 validation.acceptance status=ok target=portable-flat
```

Use `.json`/`.jsonl` only when a parser requires it. OTLP export uses standard OpenTelemetry endpoint variables:

```bash
INERTIA_OTEL_SPANS=1 \
INERTIA_OTEL_EXPORT_OTLP=1 \
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
./.venv/bin/python ./decompile.py examples/build_msc6/CMP16.EXE
```

If `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is already set, OTLP export is enabled automatically unless `INERTIA_OTEL_EXPORT_OTLP=0` is set. Exporter configuration or collector failures must not fail decompilation; check `otel_export` in the compact summary for status.

JSON output remains available for tools:

```json
{"span_count":8,"total_ms":1907.4,"top":[["direct.decompile_job",909.7,{"addr":"0x1000","name":"_start"}]],"agg":[["direct.decompile_job",1,909.7,909.7]],"errors":[]}
```

Convert existing full JSONL traces before giving them to an agent:

```bash
./.venv/bin/python scripts/compact_trace.py otlp.jsonl > trace.agent.txt
```

Implementation:

- Use `@trace_function(name="...")` on normal functions. It auto-extracts common attributes from arguments: `binary`, `addr`, `function`, `project`, `timeout`, `status`, `window`, and related fields.
- Use `with span("operation.name", ...)` only for local closures, timeout wrappers, and operations that are not functions.
- Use `with span_here(...)` when the calling function name is a good span name.
- Use `annotate_current_span(...)` only for values known after work completes, such as `status`, `elapsed_ms`, `blocks`, and `bytes`.

Keep spans high-level first: project build, sidecar load, discovery, per-function work, decompile, tail validation, recompilation/acceptance. Avoid adding spans inside tight loops unless a specific profiler run proves the loop is the problem.
