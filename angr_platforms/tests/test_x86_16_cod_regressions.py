from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import decompile
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
COD_DIR = REPO_ROOT / "cod"


def _run_cod_proc(path: Path, proc: str, *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(path),
            "--proc",
            proc,
            "--timeout",
            str(timeout),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=max(90, timeout * 6),
        check=False,
    )


def _assert_has_all(text: str, anchors: tuple[str, ...]) -> None:
    for anchor in anchors:
        assert anchor in text, anchor


def _assert_has_none(text: str, anchors: tuple[str, ...]) -> None:
    for anchor in anchors:
        assert anchor not in text, anchor


@pytest.mark.parametrize(
    ("cod_name", "proc_name", "timeout"),
    (
        ("BIOSFUNC.COD", "_bios_clearkeyflags", 20),
        ("DOSFUNC.COD", "_dos_alloc", 20),
        ("DOSFUNC.COD", "_dos_resize", 20),
        ("DOSFUNC.COD", "_dos_getfree", 20),
        ("DOSFUNC.COD", "loadprog", 20),
        ("DOSFUNC.COD", "_dos_loadOverlay", 20),
        ("DOSFUNC.COD", "_dos_getReturnCode", 20),
        ("DOSFUNC.COD", "_dos_mcbInfo", 20),
        ("OVERLAY.COD", "_overlay_load", 20),
        ("EGAME2.COD", "_openFileWrapper", 20),
    ),
)
def test_cod_regression_targets_are_recoverable(cod_name: str, proc_name: str, timeout: int):
    result = _run_cod_proc(COD_DIR / cod_name, proc_name, timeout=timeout)

    assert result.returncode == 0, result.stderr + result.stdout
    assert f"function: 0x1000 {proc_name}" in result.stdout
    assert "Decompilation empty" not in result.stdout


def test_cod_timeout_target_is_classified_deterministically():
    result = _run_cod_proc(COD_DIR / "EGAME11.COD", "_drawCockpit", timeout=20)

    assert result.returncode != 0
    _assert_has_all(
        result.stdout,
        (
            "Timed out while recovering a function after 20s.",
            "Tip: try a larger --timeout for larger binaries.",
        ),
    )


def test_cod_biosfunc_clearkeyflags_far_word_store():
    result = _run_cod_proc(COD_DIR / "BIOSFUNC.COD", "_bios_clearkeyflags")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(result.stdout, ("function: 0x1000 _bios_clearkeyflags",))
    assert any(anchor in result.stdout for anchor in ("MK_FP(0x0000, 0x0417)", "bios_keyflags", "bda_keyflags"))
    _assert_has_none(result.stdout, ("*((char *)(es * 16 + 1047))", "*((char *)(es * 16 + 1048))"))


def test_cod_dos_getfree_call_and_return_recovered():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_getfree")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_getfree",
            "intdos(&rin, &rout)",
            "rin.h.ah",
            "rin.x.bx",
            "rout.x.cflag",
        ),
    )
    _assert_has_none(
        result.stdout,
        (
            "rin = 72;",
            "rin = 65535;",
            "s_2 = &",
            "s_8 = 28675;",
            "err = 28673;",
            "return rout.x.bx",
        ),
    )


def test_cod_strlen_stack_local_copy_is_declared():
    result = _run_cod_proc(COD_DIR / "default" / "STRLEN.COD", "_strlen")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _strlen",
            "unsigned short _strlen(unsigned short s)",
            "unsigned short a1;",
        ),
    )


def test_cod_known_object_catalog_is_exposed():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import angr_platforms.X86_16 as x; "
            "print(x.describe_x86_16_cod_known_objects()['names'])",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "rin",
            "rout",
            "sreg",
            "exeLoadParams",
            "ovlLoadParams",
        ),
    )


def test_cod_dos_loadoverlay_wrapper_returns_loadprog():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_loadOverlay")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_loadOverlay",
            "loadprog",
            "file",
            "segment",
        ),
    )
    assert any(
        anchor in result.stdout
        for anchor in (
            "return loadprog(file, segment, DOS_LOAD_OVL, NULL);",
            "return loadprog(file, segment, 3, 0);",
        )
    )
    _assert_has_none(
        result.stdout,
        (
            "3823()",
            "v12 << 16",
            "s_4 =",
            "s_6 =",
        ),
    )


def test_cod_openfilewrapper_direct_forwarding():
    result = _run_cod_proc(COD_DIR / "EGAME2.COD", "_openFileWrapper")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(result.stdout, ("function: 0x1000 _openFileWrapper", "openFile(path, mode);"))
    _assert_has_none(
        result.stdout,
        (
            "s_2 = &",
            "s_4 = mode",
            "s_6 = path",
        ),
    )


def test_cod_dos_getreturncode_returns_value():
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_getReturnCode")

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(
        result.stdout,
        (
            "function: 0x1000 _dos_getReturnCode",
            "intdos(&rin, &rout)",
            "return",
        ),
    )


@pytest.mark.parametrize(
    ("cod_name", "proc_name", "anchors"),
    (
        ("DOSFUNC.COD", "_dos_getfree", ("int _intdos(union REGS *in, union REGS *out);", "int _ERROR(const char *fmt, ...);")),
        ("DOSFUNC.COD", "_dos_loadOverlay", ("int loadprog(const char *file, unsigned short segment, unsigned short mode, unsigned short flags);",)),
        ("EGAME2.COD", "_openFileWrapper", ("int _openFile(const char *path, unsigned short mode);",)),
    ),
)
def test_cod_known_helper_signatures_are_declared(cod_name: str, proc_name: str, anchors: tuple[str, ...]):
    result = _run_cod_proc(COD_DIR / cod_name, proc_name)

    assert result.returncode == 0, result.stderr + result.stdout
    _assert_has_all(result.stdout, anchors)


def test_regenerate_codegen_text_falls_back_on_failure():
    class DummyCodegen:
        def __init__(self) -> None:
            self.text = "fallback text"
            self.cfunc = object()

        def regenerate_text(self) -> None:
            raise RecursionError("maximum recursion depth exceeded")

        def render_text(self, _cfunc) -> tuple[str, object]:
            return "rendered text", object()

    text, changed = decompile._regenerate_codegen_text_safely(DummyCodegen(), context="dummy")

    assert text == "rendered text"
    assert changed is False


def test_dedupe_duplicate_local_declarations_text_prefers_annotated_slot():
    c_text = (
        "void _dos_free(unsigned short segment)\n"
        "{\n"
        "    char err;  // [bp-0x6]\n"
        "    char err;  // [bp-0x2] err\n"
        "    return;\n"
        "}\n"
    )

    deduped = decompile._dedupe_duplicate_local_declarations_text(c_text)

    assert "char err_2; // [bp-0x6]" in deduped
    assert deduped.count("char err;  // [bp-0x2] err") == 1


def test_prune_dead_local_assignments_removes_unused_constant_stores():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    dead_var = SimStackVariable(4, 2, base="bp", name="dead", region=0x1000)
    live_var = SimStackVariable(6, 2, base="bp", name="live", region=0x1000)
    dead_cvar = structured_c.CVariable(dead_var, variable_type=SimTypeShort(False), codegen=codegen)
    live_cvar = structured_c.CVariable(live_var, variable_type=SimTypeShort(False), codegen=codegen)
    statements = structured_c.CStatements(
        [
            structured_c.CAssignment(dead_cvar, structured_c.CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen),
            structured_c.CAssignment(
                live_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    live_cvar,
                    structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=statements,
        variables_in_use={
            dead_var: dead_cvar,
            live_var: live_cvar,
        },
    )

    changed = decompile._prune_dead_local_assignments(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 1
    assert codegen.cfunc.statements.statements[0].lhs.variable is live_var


def test_materialize_missing_stack_local_declarations_adds_live_stack_slots():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0
            self.project = SimpleNamespace(arch=Arch86_16())
            self.cstyle_null_cmp = False

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    arg_var = SimStackVariable(2, 2, base="bp", name="arg", region=0x1000)
    local_var = SimStackVariable(4, 2, base="bp", name="local", region=0x1000)
    arg_cvar = structured_c.CVariable(arg_var, variable_type=SimTypeShort(False), codegen=codegen)
    local_cvar = structured_c.CVariable(local_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        arg_list=[SimpleNamespace(variable=arg_var)],
        statements=structured_c.CStatements([], codegen=codegen),
        unified_local_vars={},
        variables_in_use={
            arg_var: arg_cvar,
            local_var: local_cvar,
        },
        sort_local_vars=lambda: None,
    )

    changed = decompile._materialize_missing_stack_local_declarations(codegen)

    assert changed is True
    assert local_var in codegen.cfunc.unified_local_vars
    assert codegen.cfunc.unified_local_vars[local_var] == {(local_cvar, local_cvar.variable_type)}
    assert arg_var not in codegen.cfunc.unified_local_vars


def test_binary_specific_annotations_apply_generic_metadata(monkeypatch):
    calls: list[dict[str, object]] = []

    def fake_apply(project, **kwargs):
        calls.append(kwargs)
        return True

    monkeypatch.setattr(decompile, "apply_x86_16_metadata_annotations", fake_apply)
    project = SimpleNamespace()
    lst_metadata = SimpleNamespace()
    cod_metadata = SimpleNamespace()
    synthetic_globals = {0x10: ("foo", 1)}

    changed = decompile._apply_binary_specific_annotations(
        project,
        Path("sample.cod"),
        lst_metadata,
        func_addr=0x1000,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )

    assert changed is True
    assert calls == [
        {
            "func_addr": 0x1000,
            "cod_metadata": cod_metadata,
            "lst_metadata": lst_metadata,
            "synthetic_globals": synthetic_globals,
        }
    ]


def test_tiny_wrapper_staging_locals_are_pruned_structurally():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000, statements=None, variables_in_use={}, unified_local_vars={}),
        project=SimpleNamespace(arch=decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )

    source_value = decompile.structured_c.CVariable(
        decompile.SimStackVariable(4, 2, base="bp", name="path", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )
    staging_value = decompile.structured_c.CVariable(
        decompile.SimStackVariable(0, 2, base="bp", name="s_2", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )
    staging_mode = decompile.structured_c.CVariable(
        decompile.SimStackVariable(2, 2, base="bp", name="s_4", region=0),
        variable_type=decompile.SimTypeShort(False),
        codegen=codegen,
    )

    call = decompile.structured_c.CExpressionStatement(
        decompile.structured_c.CFunctionCall(
            "openFile",
            SimpleNamespace(name="openFile"),
            [staging_value, staging_mode],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = decompile.structured_c.CStatements(
        [
            decompile.structured_c.CAssignment(
                staging_value,
                decompile.structured_c.CConstant(0x1234, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            decompile.structured_c.CAssignment(
                staging_mode,
                decompile.structured_c.CConstant(3, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            decompile.structured_c.CAssignment(
                source_value,
                decompile.structured_c.CConstant(0x5678, decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            call,
        ],
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {
        staging_value.variable: SimpleNamespace(),
        staging_mode.variable: SimpleNamespace(),
        source_value.variable: SimpleNamespace(),
    }

    changed = decompile._prune_tiny_wrapper_staging_locals(codegen)

    assert changed is True
    assert len(codegen.cfunc.statements.statements) == 2
    assert isinstance(codegen.cfunc.statements.statements[0], decompile.structured_c.CAssignment)
    assert isinstance(codegen.cfunc.statements.statements[1], decompile.structured_c.CExpressionStatement)
    assert codegen.cfunc.statements.statements[1].expr.args[0].value == 0x1234
    assert codegen.cfunc.statements.statements[1].expr.args[1].value == 3
    assert staging_value.variable not in codegen.cfunc.variables_in_use
    assert staging_mode.variable not in codegen.cfunc.variables_in_use
