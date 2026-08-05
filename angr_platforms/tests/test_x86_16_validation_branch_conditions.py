from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDoWhileLoop,
    CFunctionCall,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRValue, MemSpace
from angr_platforms.X86_16.tail_validation import (
    _canonicalize_final_branch_condition_fingerprint_8616,
)
from angr_platforms.X86_16.validation_branch_conditions import (
    BranchConditionIssueKind8616,
    validate_materialized_branch_conditions_8616,
)
from angr_platforms.X86_16.validation_condition_precision import (
    ConditionPrecisionEvidence8616,
)
from archinfo import ArchX86


class _Codegen:
    def __init__(self, condition: ConditionIR | None) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False
        self._inertia_typed_conditions = (
            (condition,) if condition is not None else ()
        )
        self._inertia_condition_precision_evidence_8616 = ()

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index


def _fact() -> ConditionIR:
    local = IRValue(MemSpace.SS, name="bp", offset=-4, size=2)
    one = IRValue(MemSpace.CONST, const=1, size=2)
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    return ConditionIR(
        "sle",
        IRBinaryValue("add", local, one, size=2),
        argument,
        src_insn=0x4015,
        block_addr=0x4010,
        producer_insn=0x4012,
        taken_target=0x4020,
        fallthrough_target=0x4017,
    )


def _variable(codegen: _Codegen, offset: int, name: str) -> CVariable:
    return CVariable(
        SimStackVariable(offset, 2, base="bp", name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _root(codegen: _Codegen, *, keep_increment: bool) -> CStatements:
    local = _variable(codegen, -4, "local_4")
    argument = _variable(codegen, 4, "arg")
    lhs = (
        CBinaryOp(
            "Add",
            local,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
        if keep_increment
        else local
    )
    condition = CBinaryOp(
        "CmpLE",
        lhs,
        argument,
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        },
    )
    body = CStatements(
        [
            CAssignment(
                local,
                CConstant(2, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    return CStatements(
        [
            CIfElse(
                [(condition, body)],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )


def _fingerprint(expression: object) -> str:
    if isinstance(expression, CBinaryOp):
        return (
            f"{expression.op}("
            f"{_fingerprint(expression.lhs)},"
            f"{_fingerprint(expression.rhs)})"
        )
    if isinstance(expression, CVariable):
        return f"var:{expression.variable.name}"
    if isinstance(expression, CConstant):
        return f"const:{expression.value}"
    raise TypeError(type(expression).__name__)


def _fact_fingerprint(_condition: ConditionIR) -> str:
    return "CmpLE(Add(var:local_4,const:1),var:arg)"


def test_materialized_branch_condition_accepts_exact_typed_predicate() -> None:
    codegen = _Codegen(_fact())

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=True),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1


def test_materialized_branch_condition_refuses_dropped_additive_operand() -> None:
    codegen = _Codegen(_fact())

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=False),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert not report.passed
    assert report.materialized_count == 0
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH
    assert report.issues[0].expected == _fact_fingerprint(_fact())
    assert report.issues[0].actual == "CmpLE(var:local_4,var:arg)"


def test_bound_loop_condition_refuses_wrong_stack_slot() -> None:
    """Validation must cover uniquely bound loops even before replacement."""
    codegen = _Codegen(_fact())
    condition = CBinaryOp(
        "CmpLE",
        _variable(codegen, -6, "local_6"),
        _variable(codegen, 4, "arg"),
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": (0x4015, 0x4010),
        },
    )
    root = CStatements(
        [
            CDoWhileLoop(
                condition,
                CStatements([], codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH
    assert report.issues[0].actual == "CmpLE(var:local_6,var:arg)"


def test_materialized_branch_accepts_exact_bound_call_return_predicate() -> None:
    """An exact callsite binding proves replacement of its AX zero test."""
    fact = ConditionIR(
        "ne",
        IRValue(MemSpace.REG, name="ax", offset=8, size=2),
        IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=0x4015,
        block_addr=0x4010,
    )
    codegen = _Codegen(fact)
    callee = SimpleNamespace(addr=0x4000, name="sub_4000", prototype=None)
    call = CFunctionCall("sub_4000", callee, [], codegen=codegen)
    summary = CallsiteSummary8616(
        callsite_addr=0x400D,
        target_addr=0x4000,
        return_addr=0x4010,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.CONDITION,
    )
    bind_structured_callsite_identity_8616(call, summary)
    codegen._inertia_callsite_summaries = {id(call): summary}
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": 0x4015,
            "vex_block_addr": 0x4010,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        },
    )
    root = CStatements(
        [CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        root,
        condition_fingerprint=lambda expression: (
            "CmpNE(call:addr:0x4000,const:0)" if expression is condition else _fingerprint(expression)
        ),
        condition_ir_fingerprint=lambda _condition: "CmpNE(reg:ax,const:0)",
    )

    assert report.passed
    assert report.materialized_count == 1


def test_materialized_branch_condition_accepts_exact_jcc_precision_evidence() -> None:
    codegen = _Codegen(_fact())
    codegen._inertia_condition_precision_evidence_8616 = (
        ConditionPrecisionEvidence8616(
            "CmpLE(Add(var:local_4,const:1),var:arg)",
            "CmpLE(var:local_4,var:arg)",
            0x4015,
        ),
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=False),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert report.passed
    assert report.materialized_count == 1


def test_materialized_branch_condition_refuses_wrong_jcc_precision_evidence() -> None:
    codegen = _Codegen(_fact())
    codegen._inertia_condition_precision_evidence_8616 = (
        ConditionPrecisionEvidence8616(
            "CmpLE(Add(var:local_4,const:1),var:arg)",
            "CmpLE(var:local_4,var:arg)",
            0x4016,
        ),
    )

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=False),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.PREDICATE_MISMATCH


def test_materialized_branch_condition_refuses_missing_typed_fact() -> None:
    codegen = _Codegen(None)

    report = validate_materialized_branch_conditions_8616(
        codegen,
        _root(codegen, keep_increment=True),
        condition_fingerprint=_fingerprint,
        condition_ir_fingerprint=_fact_fingerprint,
    )

    assert not report.passed
    assert report.issues[0].kind is BranchConditionIssueKind8616.MISSING_FACT


def test_final_branch_condition_normalizes_proven_dword_storage_views() -> None:
    normalize = _canonicalize_final_branch_condition_fingerprint_8616

    assert normalize("And(ds_global:0x132,const:65535)") == "ds_global:0x132"
    assert normalize("Shr(ds_global:0x132,const:16)") == "ds_global:0x134"
    assert normalize("CmpEQ(Or(ds_global:0x134,ds_global:0x132),const:0)") == (
        "CmpEQ(ds_global:0x132,const:0)"
    )
    assert normalize(
        "CmpEQ(Or("
        "Dereference(Add(Mul(reg:ds,const:16),const:308)),"
        "Dereference(Add(Mul(reg:ds,const:16),const:306))"
        "),const:0)"
    ) == "CmpEQ(ds_global:0x132,const:0)"
