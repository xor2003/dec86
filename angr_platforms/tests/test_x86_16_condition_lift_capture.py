from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.condition_lift_capture import (
    isolated_condition_lift_session_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY
from pytest import MonkeyPatch

from inertia_decompiler.project_loading import _build_project
from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"
SLEEP_BLOCK_ADDRS = frozenset(
    {
        0x10F38,
        0x10F41,
        0x10F46,
        0x10F52,
        0x10F55,
        0x10F5A,
        0x10F5D,
        0x10F5F,
        0x10F62,
        0x10F67,
        0x10F6A,
        0x10F6D,
    }
)


def test_condition_lift_capture_closes_typed_evidence_and_restores_state() -> None:
    condition = ConditionIR(
        "ne",
        "ax",
        0,
        source=("cmp", "jne"),
        src_insn=0x1002,
        block_addr=0x1000,
    )
    original_condition_cache = Instruction_ANY._inertia_module_condition_cache
    original_pending_sources = Instruction_ANY._inertia_pending_condition_sources_by_addr
    original_affine_state = Instruction_ANY._inertia_condition_reg_affine_state_8616
    original_affine_snapshots = Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616
    original_index_state = Instruction_ANY._inertia_condition_index_reg_state_8616
    original_value_state = Instruction_ANY._inertia_condition_reg_value_state_8616

    with isolated_condition_lift_session_8616() as capture:
        Instruction_ANY._inertia_module_condition_cache[0x1000] = [condition]
        capture.record_successful_block(0x1000)
        artifact = capture.complete_artifact(
            frozenset({0x1000}),
            frozenset({0x1000}),
        )

    assert artifact is not None
    assert artifact.stats.complete
    assert artifact.conditions_by_block == ((0x1000, (condition,)),)
    assert Instruction_ANY._inertia_module_condition_cache is original_condition_cache
    assert Instruction_ANY._inertia_pending_condition_sources_by_addr is original_pending_sources
    assert Instruction_ANY._inertia_condition_reg_affine_state_8616 is original_affine_state
    assert Instruction_ANY._inertia_condition_reg_affine_state_snapshots_8616 is original_affine_snapshots
    assert Instruction_ANY._inertia_condition_index_reg_state_8616 is original_index_state
    assert Instruction_ANY._inertia_condition_reg_value_state_8616 is original_value_state


def test_condition_lift_capture_refuses_missing_expected_owner() -> None:
    with isolated_condition_lift_session_8616() as capture:
        capture.record_successful_block(0x1000)
        artifact = capture.complete_artifact(
            frozenset({0x1000}),
            frozenset({0x1000}),
        )

    assert artifact is None


def test_sortd_ir_build_reuses_complete_frontend_condition_capture(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    from angr_platforms.X86_16.ir import function_condition_artifact as owner

    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))
    project = _build_project(
        isolated_binary,
        force_blob=False,
        base_addr=0x1000,
        entry_point=0x1000,
    )
    function = SimpleNamespace(
        addr=0x10F38,
        block_addrs_set=SLEEP_BLOCK_ADDRS,
        graph=None,
        info={},
    )

    def unexpected_relift(*_args: object) -> None:
        raise AssertionError("complete frontend capture must avoid exact-byte relift")

    monkeypatch.setattr(owner, "relift_function_condition_cache_8616", unexpected_relift)
    artifact = build_x86_16_ir_function_artifact(project, function)

    assert artifact.condition_evidence is not None
    assert artifact.condition_evidence.complete
    assert artifact.condition_evidence.source.stats.materialized_count == 3
