from __future__ import annotations

import time

import inertia_decompiler.telemetry as telemetry
from inertia_decompiler.telemetry import (
    build_compact_summary,
    configure_telemetry_from_env,
    emit_compact_summary,
    reset_telemetry_for_tests,
    span,
    span_here,
    trace_function,
)


def test_compact_telemetry_summary_records_decorator_and_nested_spans(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")
    monkeypatch.setenv("INERTIA_OTEL_TOP_N", "4")

    assert configure_telemetry_from_env()

    @trace_function(name="test.decorated")
    def _work():
        with span("test.child", addr="0x1000"):
            time.sleep(0.001)

    _work()

    summary = build_compact_summary()
    names = {row[0] for row in summary["top"]}
    aggregate_names = {row[0] for row in summary["agg"]}

    assert summary["span_count"] == 2
    assert "test.decorated" in names
    assert "test.child" in names
    assert "test.decorated" in aggregate_names
    assert "test.child" in aggregate_names

    reset_telemetry_for_tests()


def test_span_here_uses_calling_function_name(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")

    assert configure_telemetry_from_env()

    def _caller():
        with span_here():
            pass

    _caller()

    summary = build_compact_summary()
    names = {row[0] for row in summary["top"]}

    assert any(name.endswith("._caller") for name in names)

    reset_telemetry_for_tests()


def test_trace_function_disabled_records_nothing(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.delenv("INERTIA_OTEL_SPANS", raising=False)

    @trace_function(name="test.disabled")
    def _work():
        return 7

    assert _work() == 7
    assert build_compact_summary()["span_count"] == 0

    reset_telemetry_for_tests()


def test_span_records_error_without_swallowing_exception(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")

    assert configure_telemetry_from_env()

    try:
        with span("test.error"):
            raise ValueError("boom")
    except ValueError:
        pass

    summary = build_compact_summary()

    assert summary["span_count"] == 1
    assert summary["errors"]
    assert summary["errors"][0][0] == "test.error"
    assert summary["errors"][0][2]["exception"] == "ValueError"

    reset_telemetry_for_tests()


def test_otlp_export_uses_provider_without_collector(monkeypatch, tmp_path):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_EXPORT_OTLP", "1")
    monkeypatch.setenv("INERTIA_OTEL_STDERR", "0")
    monkeypatch.setenv("INERTIA_OTEL_MIN_MS", "0")

    class _Provider:
        def __init__(self):
            self.flushed = False
            self.shutdown_called = False

        def force_flush(self, *, timeout_millis):
            self.flushed = timeout_millis > 0

        def shutdown(self):
            self.shutdown_called = True

    provider = _Provider()
    monkeypatch.setattr(telemetry, "_configure_otlp_exporter", lambda: (provider, "configured"))

    assert configure_telemetry_from_env(file_path=tmp_path / "otel.json")
    with span("test.otlp"):
        pass

    summary = build_compact_summary()
    assert summary["otel_export"] == "configured"

    emit_compact_summary()
    assert provider.flushed
    assert provider.shutdown_called

    reset_telemetry_for_tests()


def test_otlp_endpoint_can_be_explicitly_disabled(monkeypatch):
    reset_telemetry_for_tests()
    monkeypatch.setenv("INERTIA_OTEL_SPANS", "1")
    monkeypatch.setenv("INERTIA_OTEL_EXPORT_OTLP", "0")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")

    assert configure_telemetry_from_env()
    with span("test.no_otlp"):
        pass

    assert build_compact_summary()["otel_export"] == "disabled"

    reset_telemetry_for_tests()
