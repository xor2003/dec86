from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler.cli_decompilation import _emit_c_stage_trace, _get_layer_dump_state


def test_emit_c_stage_trace_prints_labeled_snapshot(capsys):
    project = SimpleNamespace(_inertia_trace_c_stages=True)
    function = SimpleNamespace(addr=0x1234, name="demo")

    _emit_c_stage_trace(project, function, "post-helper-call-format", "int demo(void)\n{\n    return 0;\n}\n")

    captured = capsys.readouterr()
    assert "/* -- c trace: 0x1234 demo :: post-helper-call-format -- */" in captured.err
    assert "int demo(void)" not in captured.err


def test_emit_c_stage_trace_stays_silent_when_disabled(capsys):
    project = SimpleNamespace(_inertia_trace_c_stages=False)
    function = SimpleNamespace(addr=0x1234, name="demo")

    _emit_c_stage_trace(project, function, "final-emitted-c", "int demo(void) { return 0; }\n")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_emit_c_stage_trace_writes_layer_dump(tmp_path):
    manifest_root = tmp_path / "decompilation_layers"
    project = SimpleNamespace(
        _inertia_dump_layers=True,
        _inertia_dump_layer_root=manifest_root,
        _inertia_dump_layer_filter="",
    )
    function = SimpleNamespace(addr=0x1234, name="demo")
    state = _get_layer_dump_state(project, function)
    assert state is not None

    _emit_c_stage_trace(
        project,
        function,
        "post-structured-codegen",
        "int demo(void)\n{\n    return 0;\n}\n",
        layer_dump_state=state,
    )

    manifest_path = manifest_root / "0x1234_demo_01" / "manifest.jsonl"
    assert manifest_path.exists()
    assert manifest_path.read_text().count("\n") >= 1
    manifest_line = manifest_path.read_text().splitlines()[-1]
    assert '"layer": "post-structured-codegen"' in manifest_line
    assert (manifest_root / "0x1234_demo_01" / "0001_post-structured-codegen.c").exists()


def test_dump_layer_state_uses_next_attempt_when_present(tmp_path):
    project = SimpleNamespace(
        _inertia_dump_layers=True,
        _inertia_dump_layer_root=tmp_path,
        _inertia_dump_layer_filter="",
    )
    function = SimpleNamespace(addr=0x1234, name="demo")

    first_state = _get_layer_dump_state(project, function)
    second_state = _get_layer_dump_state(project, function)

    assert first_state is not None
    assert second_state is not None
    assert first_state["root"] != second_state["root"]
