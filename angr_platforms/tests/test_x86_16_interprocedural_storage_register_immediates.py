"""SSA proofs for register-mediated immediate call arguments."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)
from angr_platforms.X86_16.ir.ssa_function import (
    build_x86_16_function_ssa,
)
from angr_platforms.X86_16.ir.vex_import import (
    build_x86_16_ir_function_artifact,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.interprocedural_storage_reaching_defs import (
    CallArgumentDefinitionFailure8616,
    CallArgumentDefinitionVerdict8616,
    resolve_call_argument_reaching_definition_8616,
)


def _resolve_register_immediate(value: int):
    code = bytes((0xB8, value & 0xFF, value >> 8, 0x50, 0xE8, 0, 0))
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    boundary = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    assert not artifact.refusals
    summary = CallsiteSummary8616(
        callsite_addr=0x1004,
        target_addr=0x1007,
        return_addr=0x1007,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=None,
        return_register=None,
        return_used=None,
        push_arg_sources=((CallsitePushSourceKind8616.IMMEDIATE.value, 0),),
        push_arg_instruction_addrs=(0x1003,),
    )
    return resolve_call_argument_reaching_definition_8616(
        build_x86_16_function_ssa(artifact),
        summary,
        0,
    )


def test_register_mediated_immediate_resolves_exact_push_stores() -> None:
    result = _resolve_register_immediate(0)

    assert result.verdict is CallArgumentDefinitionVerdict8616.PROVEN
    assert result.failure is None
    assert result.stats.complete
    assert tuple(definition.value.size for definition in result.definitions) == (1, 1)


def test_register_mediated_immediate_contradiction_refuses() -> None:
    result = _resolve_register_immediate(1)

    assert result.verdict is CallArgumentDefinitionVerdict8616.UNKNOWN_REFUSE
    assert result.failure is CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    assert result.stats.materialized_count == 0
