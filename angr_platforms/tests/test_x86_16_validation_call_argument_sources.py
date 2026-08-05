from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.validation_calls import validate_call_argument_classes_8616
from archinfo import ArchX86


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self._inertia_callsite_summaries: dict[int, CallsiteSummary8616] = {}
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index


def _summary() -> CallsiteSummary8616:
    address_source = (
        "expr",
        ("bp", 6),
        (("add_source", ("expr", ("bp", -2), (("shl", 1),))),),
    )
    return CallsiteSummary8616(
        callsite_addr=0x1010,
        target_addr=0x2000,
        return_addr=0x1013,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("imm", 104), ("seg_indirect", "ds", 2, address_source)),
        logical_arg_classes=(),
    )


def _call_with_first_argument(codegen: _Codegen, first_argument: object) -> CFunctionCall:
    call = CFunctionCall(
        "consume",
        None,
        [first_argument, CConstant(104, SimTypeShort(False), codegen=codegen)],
        tags={"ins_addr": 0x1010},
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries[id(call)] = _summary()
    return call


def test_call_argument_source_validation_accepts_exact_stack_dependencies() -> None:
    codegen = _Codegen()
    short_type = SimTypeShort(False)
    pointer_type = SimTypePointer(short_type).with_arch(codegen.project.arch)
    argument = CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_5"),
        variable_type=pointer_type,
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=short_type,
        codegen=codegen,
    )
    indexed = CIndexedVariable(argument, index, variable_type=short_type, codegen=codegen)
    call = _call_with_first_argument(codegen, indexed)

    report = validate_call_argument_classes_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_call_argument_source_validation_refuses_recycled_constant_pointer() -> None:
    codegen = _Codegen()
    wrong_argument = CConstant(104, SimTypeShort(False), codegen=codegen)
    call = _call_with_first_argument(codegen, wrong_argument)

    report = validate_call_argument_classes_8616(codegen, CStatements([call], codegen=codegen))

    assert report.passed is False
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.issue_tokens() == (
        "call-argument-source:stack-dependency-mismatch:callsite=0x1010:"
        "target=0x2000:arg=0:expected-bp=-0x2,+0x6:actual-bp=none",
    )
