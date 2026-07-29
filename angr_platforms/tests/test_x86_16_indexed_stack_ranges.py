from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeFixedSizeArray, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from angr_platforms.X86_16.semantics.call_contracts import (
    runtime_call_return_contract_8616,
)
from angr_platforms.X86_16.structuring.indexed_stack_ranges import (
    IndexedStackReadProofKind8616,
    collect_indexed_stack_read_proofs_8616,
)
from angr_platforms.X86_16.validation_dataflow import (
    validate_structured_def_use_8616,
)
from archinfo import ArchX86


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index


def _const(value: int, codegen: _Codegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _stack(offset: int, codegen: _Codegen, name: str) -> CVariable:
    return CVariable(
        SimStackVariable(offset, 2, base="bp", name=name, region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _global(addr: int, codegen: _Codegen, name: str) -> CVariable:
    return CVariable(
        SimMemoryVariable(addr, 2, name=name, region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _array(codegen: _Codegen) -> CVariable:
    return CVariable(
        SimStackVariable(-8, 8, base="bp", name="items", region=0x4010),
        variable_type=SimTypeFixedSizeArray(SimTypeShort(False), 4),
        codegen=codegen,
    )


def _loop(
    codegen: _Codegen,
    induction: CVariable,
    bound: CVariable,
    body: CStatements,
) -> CForLoop:
    return CForLoop(
        CAssignment(induction, _const(0, codegen), codegen=codegen),
        CBinaryOp("CmpGT", bound, induction, codegen=codegen),
        CAssignment(
            induction,
            CBinaryOp("Add", induction, _const(1, codegen), codegen=codegen),
            codegen=codegen,
        ),
        body,
        codegen=codegen,
    )


def _signed_remainder_fact() -> DirectStackMoveFact8616:
    return DirectStackMoveFact8616(
        dst_offset=-14,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER,
        ins_addr=0x4020,
        source_offset=-12,
        source_immediate=1,
        source_call_name="rand",
        source_call_ins_addr=0x4010,
        source_call_return_contract=runtime_call_return_contract_8616("rand"),
    )


def _two_loop_fixture(
    *,
    conditional_decrement: bool = False,
    control_before_prefix_write: bool = False,
    nested_straight_line: bool = False,
    unknown_call_contract: bool = False,
    read_high_after_decrement: bool = False,
) -> tuple[CStatements, CIndexedVariable, CIndexedVariable]:
    codegen = _Codegen()
    array = _array(codegen)
    count = _global(0x2000, codegen, "count")
    first_index = _stack(-10, codegen, "first_index")
    prefix_assignment = CAssignment(
        CIndexedVariable(
            array,
            first_index,
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        CBinaryOp("Add", first_index, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    prefix_statements: list[object] = [prefix_assignment]
    if control_before_prefix_write:
        prefix_statements.insert(
            0,
            CIfElse(
                [
                    (
                        CBinaryOp(
                            "CmpEQ",
                            first_index,
                            _const(0, codegen),
                            codegen=codegen,
                        ),
                        CStatements([], codegen=codegen),
                    )
                ],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            ),
        )
    if nested_straight_line:
        prefix_statements = [
            CStatements(prefix_statements, codegen=codegen),
            CStatements([], codegen=codegen),
        ]
    prefix_loop = _loop(
        codegen,
        first_index,
        count,
        CStatements(prefix_statements, codegen=codegen),
    )
    high = _stack(-12, codegen, "high")
    random_index = _stack(-14, codegen, "random_index")
    second_index = _stack(-16, codegen, "second_index")
    random_call = CFunctionCall(
        "rand" if not unknown_call_contract else "unknown",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    random_assignment = CAssignment(
        random_index,
        CBinaryOp(
            "Mod",
            random_call,
            CBinaryOp("Add", high, _const(1, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    random_read = CIndexedVariable(
        array,
        random_index,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high_read = CIndexedVariable(
        array,
        high,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    decrement = CAssignment(
        high,
        CBinaryOp("Sub", high, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    decrement_statement: object = decrement
    if conditional_decrement:
        decrement_statement = CIfElse(
            [
                (
                    CBinaryOp(
                        "CmpEQ",
                        second_index,
                        _const(0, codegen),
                        codegen=codegen,
                    ),
                    CStatements([decrement], codegen=codegen),
                )
            ],
            else_node=None,
            cstyle_ifs=True,
            codegen=codegen,
        )
    reads = [random_assignment, random_read]
    if read_high_after_decrement:
        reads.extend([decrement_statement, high_read])
    else:
        reads.extend([high_read, decrement_statement])
    second_body: list[object]
    if nested_straight_line:
        second_body = [
            CStatements(reads[:2], codegen=codegen),
            CStatements(reads[2:], codegen=codegen),
        ]
    else:
        second_body = reads
    second_loop = _loop(
        codegen,
        second_index,
        count,
        CStatements(second_body, codegen=codegen),
    )
    root = CStatements(
        [
            prefix_loop,
            CAssignment(
                high,
                CBinaryOp("Sub", count, _const(1, codegen), codegen=codegen),
                codegen=codegen,
            ),
            second_loop,
        ],
        codegen=codegen,
    )
    return root, random_read, high_read


def test_structuring_proves_prefix_reads_for_remainder_and_countdown_indices() -> None:
    root, random_read, high_read = _two_loop_fixture()

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 2
    assert report.classified_fact_count == 2
    assert report.materialized_count == 2
    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }
    assert {
        proof.kind for proof in report.proofs
    } == {IndexedStackReadProofKind8616.INITIALIZED_PREFIX_BOUNDED_INDEX}


def test_structuring_proves_transparently_nested_straight_line_bodies() -> None:
    root, random_read, high_read = _two_loop_fixture(nested_straight_line=True)

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.failure_count == 0
    assert {proof.read_node_id for proof in report.proofs} == {
        id(random_read),
        id(high_read),
    }


def test_structuring_refuses_prefix_write_after_control_split() -> None:
    root, _random_read, _high_read = _two_loop_fixture(
        control_before_prefix_write=True,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert report.materialized_count == 0
    assert report.failure_count == 2


def test_structuring_refuses_conditionally_executed_countdown_decrement() -> None:
    root, random_read, high_read = _two_loop_fixture(conditional_decrement=True)

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert id(random_read) not in report.by_read_node_id()
    assert id(high_read) not in report.by_read_node_id()
    assert report.failure_count == 2


def test_structuring_refuses_remainder_without_nonnegative_call_contract() -> None:
    root, random_read, high_read = _two_loop_fixture(unknown_call_contract=True)
    fact = _signed_remainder_fact()
    fact = DirectStackMoveFact8616(
        dst_offset=fact.dst_offset,
        width=fact.width,
        source_kind=fact.source_kind,
        ins_addr=fact.ins_addr,
        source_offset=fact.source_offset,
        source_immediate=fact.source_immediate,
        source_call_name="unknown",
        source_call_ins_addr=fact.source_call_ins_addr,
    )

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(fact,),
    )

    assert id(random_read) not in report.by_read_node_id()
    assert id(high_read) not in report.by_read_node_id()
    assert report.failure_count == 2


def test_structuring_refuses_countdown_read_after_decrement() -> None:
    root, random_read, high_read = _two_loop_fixture(read_high_after_decrement=True)

    report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    assert id(random_read) in report.by_read_node_id()
    assert id(high_read) not in report.by_read_node_id()
    assert report.failure_count == 1


def test_tail_validation_consumes_only_exact_structuring_read_proofs() -> None:
    root, _random_read, _high_read = _two_loop_fixture()
    proof_report = collect_indexed_stack_read_proofs_8616(
        root,
        direct_stack_move_facts=(_signed_remainder_fact(),),
    )

    without_proofs = validate_structured_def_use_8616(root)
    with_proofs = validate_structured_def_use_8616(
        root,
        indexed_stack_read_proofs=proof_report.by_read_node_id(),
    )

    assert without_proofs.failure_count == 2
    assert with_proofs.passed
    assert with_proofs.materialized_count == without_proofs.materialized_count + 2
