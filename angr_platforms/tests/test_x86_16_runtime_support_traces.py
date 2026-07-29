from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from angr.ailment.expression import BasePointerOffset
from angr.analyses.decompiler.structuring.structurer_nodes import BreakNode, LoopNode
from angr.analyses.decompiler.structuring.structurer_nodes import SequenceNode as AngrSequenceNode

from inertia_decompiler.runtime_support import (
    _expanded_root_body_shape_status_8616,
    _materialize_loop_break_default_switch_8616,
    _maybe_materialize_pre_codegen_typed_switch_8616,
    _seqnode_switch_artifact_mappings_8616,
    install_angr_basepointeroffset_codegen_guard,
    install_angr_peephole_expr_bitwidth_guard,
    install_angr_pre_codegen_seqnode_probe_guard,
    install_angr_variable_recovery_binop_sub_size_guard,
)


@dataclass
class _Expr:
    bits: int
    text: str

    def __str__(self) -> str:
        return self.text


@dataclass
class _Block:
    addr: int


class _IdentityHandleExpr:
    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):  # noqa: ANN001
        return expr


class _ExprOpt:
    expr_classes = (_Expr,)

    def optimize(self, expr, stmt_idx=None, block=None):  # noqa: ANN001
        return BasePointerOffset(None, 32, "stack_base", 0)


class _Walker(_IdentityHandleExpr):
    def __init__(self) -> None:
        self.expr_opts = [_ExprOpt()]
        self.any_update = False

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):  # noqa: ANN001
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def test_expanded_root_body_shape_status_classifies_external_default_sibling() -> None:
    assert (
        _expanded_root_body_shape_status_8616(
            case_paths=((0, 0), (0, 1, 0), (0, 1, 1, 0)),
            common_parent_path=(),
            default_paths=((1,), (0, 1, 1, 1)),
            direct_sibling_span=False,
        )
        == "ladder_subtree_with_external_default_sibling"
    )


def test_expanded_root_body_shape_status_keeps_generic_non_sibling_blocker() -> None:
    assert (
        _expanded_root_body_shape_status_8616(
            case_paths=((0, 0), (2, 0)),
            common_parent_path=(),
            default_paths=((1,),),
            direct_sibling_span=False,
        )
        == "non_sibling_subtrees"
    )


def test_peephole_bitwidth_guard_logs_mismatch(capsys) -> None:
    original = install_angr_peephole_expr_bitwidth_guard(_Walker)
    try:
        walker = _Walker()
        expr = _Expr(bits=16, text="(stack_base-2 + 0x2<16>)")
        result = walker._handle_expr(1, expr, 0, "t0 = ...", _Block(addr=0x11732))
    finally:
        _Walker._handle_expr = original

    captured = capsys.readouterr()
    assert isinstance(result, BasePointerOffset)
    assert result.bits == 16
    assert result.offset == 0
    assert "clinic:peephole-bits-mismatch" not in captured.err


class _GenericExprOpt:
    expr_classes = (_Expr,)

    def optimize(self, expr, stmt_idx=None, block=None):  # noqa: ANN001
        return _Expr(bits=32, text="wide_tmp")


class _GenericWalker(_IdentityHandleExpr):
    def __init__(self) -> None:
        self.expr_opts = [_GenericExprOpt()]
        self.any_update = False

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):  # noqa: ANN001
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def test_peephole_bitwidth_guard_keeps_generic_mismatch_as_log_only(capsys, monkeypatch) -> None:
    monkeypatch.setenv("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR", "1")
    original = install_angr_peephole_expr_bitwidth_guard(_GenericWalker)
    try:
        walker = _GenericWalker()
        expr = _Expr(bits=16, text="(stack_base-2 + 0x2<16>)")
        result = walker._handle_expr(1, expr, 0, "t0 = ...", _Block(addr=0x11732))
    finally:
        _GenericWalker._handle_expr = original

    captured = capsys.readouterr()
    assert result is expr
    assert "clinic:peephole-bits-mismatch" in captured.err
    assert "opt=_GenericExprOpt" in captured.err


class _FakeBV:
    def __init__(self, bits: int, concrete_value: int | None = None) -> None:
        self._bits = bits
        self.concrete_value = concrete_value
        self.concrete = concrete_value is not None

    def size(self) -> int:
        return self._bits

    def zero_extend(self, nbits: int) -> _FakeBV:
        return _FakeBV(self._bits + nbits, self.concrete_value)

    def sign_extend(self, nbits: int) -> _FakeBV:
        if self.concrete_value is None:
            return _FakeBV(self._bits + nbits)
        sign_bit = 1 << (self._bits - 1)
        value = self.concrete_value
        if value & sign_bit:
            value |= ((1 << nbits) - 1) << self._bits
        return _FakeBV(self._bits + nbits, value)

    def __getitem__(self, item) -> _FakeBV:  # noqa: ANN001
        hi, lo = item.start, item.stop
        width = hi - lo + 1
        if self.concrete_value is None:
            return _FakeBV(width)
        mask = (1 << width) - 1
        return _FakeBV(width, (self.concrete_value >> lo) & mask)

    def __sub__(self, other: _FakeBV) -> _FakeBV:
        width = max(self._bits, other._bits)
        if self.concrete_value is None or other.concrete_value is None:
            return _FakeBV(width)
        mask = (1 << width) - 1
        return _FakeBV(width, (self.concrete_value - other.concrete_value) & mask)


class _FakeRichR:
    def __init__(self, data, typevar=None, type_constraints=None):  # noqa: ANN001
        self.data = data
        self.typevar = typevar
        self.type_constraints = type_constraints or set()


class _FakeStructuredCodegen:
    def _handle(self, node, **kwargs):  # noqa: ANN001
        raise TypeError(type(node).__name__)

    def _handle_Expr_StackBaseOffset(self, node, **kwargs):  # noqa: ANN001
        return ("stackbase", node.offset, kwargs.get("lvalue", False))


def test_basepointeroffset_codegen_guard_reuses_stackbase_handler():
    original = install_angr_basepointeroffset_codegen_guard(_FakeStructuredCodegen)
    try:
        codegen = _FakeStructuredCodegen()
        result = codegen._handle(BasePointerOffset(None, 16, "stack_base", -8), lvalue=True)
    finally:
        _FakeStructuredCodegen._handle = original

    assert result == ("stackbase", -8, True)


class _FakeCodegenWithInit:
    def __init__(self, func, sequence, **kwargs):  # noqa: ANN001
        self.func = func
        self.sequence = sequence
        self.kwargs = kwargs


class _FakeFunction:
    addr = 0x401000
    name = "fake_func"


class _FakeProject:
    pass


class SequenceNode:
    def __init__(self, addr, nodes):  # noqa: ANN001
        self.addr = addr
        self.nodes = nodes


class SwitchCaseNode:
    def __init__(self, addr, cases, default_node=None):  # noqa: ANN001
        self.addr = addr
        self.cases = cases
        self.default_node = default_node


class ConditionNode:
    def __init__(self, addr, true_node=None, false_node=None):  # noqa: ANN001
        self.addr = addr
        self.true_node = true_node
        self.false_node = false_node


class CodeNode:
    def __init__(self, node):  # noqa: ANN001
        self.node = node


def test_pre_codegen_seqnode_probe_records_switch_nodes():
    project = _FakeProject()
    sequence = SequenceNode(
        0x1000,
        [
            ConditionNode(0x1010),
            SwitchCaseNode(
                0x1020,
                {
                    1: SequenceNode(0x1030, []),
                    2: SequenceNode(0x1040, []),
                },
                default_node=SequenceNode(0x1050, []),
            ),
        ],
    )
    original = install_angr_pre_codegen_seqnode_probe_guard(_FakeCodegenWithInit, project=project)
    try:
        codegen = _FakeCodegenWithInit(_FakeFunction(), sequence, marker=True)
    finally:
        _FakeCodegenWithInit.__init__ = original

    assert codegen.kwargs == {"marker": True}
    [record] = project._inertia_pre_codegen_seqnode_probe_8616
    assert record["function_addr"] == 0x401000
    assert record["function_name"] == "fake_func"
    assert record["root_type"] == "SequenceNode"
    assert record["switch_case_node_count"] == 1
    assert record["condition_node_count"] == 1
    assert record["condition_fact_count"] == 0
    assert record["condition_edge_evidence_count"] == 0
    assert record["condition_edge_block_addrs"] == []
    assert record["condition_edge_summaries"] == []
    assert "pre_codegen_grouped_switch_artifact_count" not in record
    assert record["addr_samples"][:3] == [0x1000, 0x1010, 0x1020]


def test_seqnode_switch_artifact_mapping_reports_exact_case_subtrees():
    sequence = SequenceNode(
        0x1000,
        [
            SequenceNode(0x1100, [CodeNode(_Block(0x1101))]),
            SequenceNode(0x1200, []),
            SequenceNode(0x1300, []),
        ],
    )

    [mapping] = _seqnode_switch_artifact_mappings_8616(
        sequence,
        (
            {
                "case_region_ids": [0x1100, 0x1200],
                "case_values": [1, 2],
                "decision_tree_summary": {"case_count": 2, "range_split_count": 0},
                "default_region_id": 0x1300,
                "region_id": 0x1000,
            },
        ),
    )

    assert mapping["status"] == "mapped_exact"
    assert mapping["decision_tree_summary"] == {"case_count": 2, "range_split_count": 0}
    assert mapping["mapped_case_count"] == 2
    assert mapping["unmapped_case_region_ids"] == []
    assert mapping["default_mapping"]["status"] == "exact"


def test_seqnode_switch_artifact_mapping_reports_contained_or_missing_regions():
    sequence = SequenceNode(0x1000, [SequenceNode(0x1100, [CodeNode(_Block(0x1101))])])

    [mapping] = _seqnode_switch_artifact_mappings_8616(
        sequence,
        (
            {
                "case_region_ids": [0x1101, 0x1200],
                "case_values": [1, 2],
                "default_region_id": None,
                "region_id": 0x1000,
            },
        ),
    )

    assert mapping["status"] == "blocked_missing_region"
    assert mapping["mapped_case_count"] == 1
    assert mapping["unmapped_case_region_ids"] == [0x1200]


def test_seqnode_switch_artifact_mapping_prefers_sequence_wrapper_over_block():
    sequence = SequenceNode(
        0x1000,
        [
            SequenceNode(0x1100, [_Block(0x1100)]),
            SequenceNode(0x1200, [_Block(0x1200)]),
            SequenceNode(0x1300, [_Block(0x1300)]),
        ],
    )

    [mapping] = _seqnode_switch_artifact_mappings_8616(
        sequence,
        (
            {
                "case_region_ids": [0x1100, 0x1200],
                "case_values": [1, 2],
                "default_region_id": 0x1300,
                "region_id": 0x1000,
            },
        ),
    )

    assert mapping["status"] == "mapped_exact"
    assert [case_mapping["type"] for case_mapping in mapping["case_mappings"]] == ["SequenceNode", "SequenceNode"]
    assert mapping["default_mapping"]["type"] == "SequenceNode"


def test_seqnode_switch_artifact_mapping_blocks_partial_switch_ladder():
    sequence = SequenceNode(
        0x1000,
        [
            SequenceNode(
                0x2000,
                [
                    _Block(0x2000),
                    SequenceNode(0x2100, [_Block(0x2100)]),
                ],
            )
        ],
    )

    [mapping] = _seqnode_switch_artifact_mappings_8616(
        sequence,
        (
            {
                "case_region_ids": [0x2100],
                "case_values": [1],
                "default_region_id": 0x2000,
                "region_id": 0x1000,
            },
        ),
    )

    assert mapping["status"] == "blocked_partial_switch_ladder"
    assert mapping["default_contains_case_count"] == 1
    assert mapping["common_parent_path"] == [0]
    assert mapping["transform_ready"] is False
    assert mapping["transform_blocker_reason"] == "default_subtree_contains_more_switch_cases"


def test_seqnode_switch_artifact_mapping_reports_expanded_root_body_coverage():
    sequence = SequenceNode(
        0x1000,
        [
            SequenceNode(0x2100, [_Block(0x2100)]),
            SequenceNode(0x2200, [_Block(0x2200)]),
            SequenceNode(0x2300, [_Block(0x2300)]),
            SequenceNode(0x2400, [_Block(0x2400)]),
        ],
    )

    [mapping] = _seqnode_switch_artifact_mappings_8616(
        sequence,
        (
            {
                "case_region_ids": [0x2200],
                "case_values": [2],
                "decision_tree_summary": {
                    "expanded_root_normalization_branch_subtrees": [
                        {
                            "current_case_region_ids": [0x2100],
                            "current_case_values": [1],
                            "subtrees": [
                                {
                                    "default_candidate_region_ids": [0x2400],
                                    "normalized_case_region_ids": [0x2200, 0x2300],
                                    "normalized_case_values": [2, 3],
                                }
                            ],
                        }
                    ],
                    "expanded_root_normalization_readiness": {
                        "ready": True,
                        "status": "branch_splits_ready",
                    },
                },
                "default_region_id": 0x2400,
                "region_id": 0x1000,
            },
        ),
    )

    assert mapping["expanded_root_body_mapping_status"] == "mapped_exact"
    assert mapping["expanded_root_common_parent_path"] == []
    assert mapping["expanded_root_default_region_ids"] == [0x2400]
    assert mapping["expanded_root_direct_sibling_span"] is True
    assert mapping["expanded_root_mapped_case_count"] == 3
    assert mapping["expanded_root_normalization_ready"] is True
    assert mapping["expanded_root_normalization_status"] == "branch_splits_ready"
    assert mapping["expanded_root_normalized_case_region_ids"] == [0x2100, 0x2200, 0x2300]
    assert mapping["expanded_root_normalized_case_values"] == [1, 2, 3]
    assert mapping["expanded_root_transform_ready"] is True
    assert mapping["expanded_root_unmapped_case_region_ids"] == []


def test_seqnode_switch_artifact_mapping_prefers_small_case_body_sequence_over_entry_block():
    class Block:
        def __init__(self, addr: int) -> None:
            self.addr = addr

    case_body = AngrSequenceNode(
        0x2000,
        [
            Block(0x2100),
            Block(0x2108),
            Block(0x2110),
        ],
    )
    sequence = AngrSequenceNode(
        0x1000,
        [
            case_body,
            AngrSequenceNode(0x2200, [Block(0x2200)]),
            AngrSequenceNode(0x2300, [Block(0x2300)]),
        ],
    )

    [mapping] = _seqnode_switch_artifact_mappings_8616(
        sequence,
        (
            {
                "case_region_ids": [0x2100, 0x2200],
                "case_values": [1, 2],
                "default_region_id": 0x2300,
                "region_id": 0x1000,
            },
        ),
    )

    [case_mapping, _] = mapping["case_mappings"]
    assert case_mapping["status"] == "contained"
    assert case_mapping["type"] == "SequenceNode"
    assert case_mapping["path"] == [0]


def test_loop_break_default_switch_materializer_replaces_only_in_loop_ladder() -> None:
    case_a = AngrSequenceNode(0x2100, [_Block(0x2100)])
    case_b = AngrSequenceNode(0x2200, [_Block(0x2200)])
    default_break = BreakNode(0x4451, 0x4523)
    ladder = AngrSequenceNode(0x4400, [case_a, case_b, default_break])
    loop_sequence = AngrSequenceNode(
        0x4107,
        [
            AngrSequenceNode(0x3000, []),
            AngrSequenceNode(0x3001, []),
            AngrSequenceNode(0x3002, []),
            AngrSequenceNode(0x3003, []),
            AngrSequenceNode(0x3004, []),
            AngrSequenceNode(0x3005, []),
            AngrSequenceNode(0x3006, []),
            ladder,
        ],
    )
    loop_node = LoopNode("while", None, loop_sequence, addr=0x4107)
    external_default = AngrSequenceNode(0x4523, [_Block(0x4523)])
    root = AngrSequenceNode(
        0x1000,
        [
            AngrSequenceNode(0x1001, []),
            AngrSequenceNode(0x1002, []),
            loop_node,
            external_default,
        ],
    )
    project = SimpleNamespace(arch=SimpleNamespace(registers={"ax": (0, 2)}))

    result = _materialize_loop_break_default_switch_8616(
        project,
        root,
        (
            {
                "case_region_ids": [0x2100],
                "case_values": [1],
                "decision_tree_summary": {
                    "expanded_root_normalization_branch_subtrees": [
                        {
                            "current_case_region_ids": [0x2100],
                            "current_case_values": [1],
                            "subtrees": [
                                {
                                    "default_candidate_region_ids": [0x4523],
                                    "normalized_case_region_ids": [0x2200],
                                    "normalized_case_values": [2],
                                }
                            ],
                        }
                    ],
                    "expanded_root_normalization_readiness": {
                        "ready": True,
                        "status": "branch_splits_ready",
                    },
                },
                "default_region_id": 0x4523,
                "region_id": 0x4400,
                "status": "partial_ladder",
                "switch_condition_lhs": {
                    "name": "ax",
                    "offset": 0,
                    "size": 2,
                    "space": "reg",
                },
            },
        ),
    )

    replacement = loop_sequence.nodes[7]
    assert result["changed"] is True
    assert result["replaced_count"] == 1
    assert type(replacement).__name__ == "SwitchCaseNode"
    assert list(replacement.cases) == [1, 2]
    assert replacement.cases[1] is case_a
    assert replacement.cases[2] is case_b
    assert replacement.default_node is default_break
    assert root.nodes[3] is external_default


def test_pre_codegen_typed_switch_materializer_refuses_without_typed_artifacts() -> None:
    root = AngrSequenceNode(0x1000, [])

    result = _maybe_materialize_pre_codegen_typed_switch_8616(None, root, ())

    assert result == {
        "attempted_count": 0,
        "changed": False,
        "refusal_reasons": ("missing_grouped_switch_artifacts",),
        "replaced_count": 0,
    }


def test_pre_codegen_typed_switch_materializer_does_not_require_project_enablement() -> None:
    root = AngrSequenceNode(0x1000, [])
    project = SimpleNamespace()

    result = _maybe_materialize_pre_codegen_typed_switch_8616(project, root, ())

    assert result == {
        "attempted_count": 0,
        "changed": False,
        "refusal_reasons": ("missing_grouped_switch_artifacts",),
        "replaced_count": 0,
    }


def test_pre_codegen_typed_switch_materializer_uses_loop_break_default_evidence() -> None:
    case_a = AngrSequenceNode(0x2100, [_Block(0x2100)])
    case_b = AngrSequenceNode(0x2200, [_Block(0x2200)])
    default_break = BreakNode(0x4451, 0x4523)
    ladder = AngrSequenceNode(0x4400, [case_a, case_b, default_break])
    loop_sequence = AngrSequenceNode(
        0x4107,
        [
            AngrSequenceNode(0x3000, []),
            AngrSequenceNode(0x3001, []),
            AngrSequenceNode(0x3002, []),
            AngrSequenceNode(0x3003, []),
            AngrSequenceNode(0x3004, []),
            AngrSequenceNode(0x3005, []),
            AngrSequenceNode(0x3006, []),
            ladder,
        ],
    )
    loop_node = LoopNode("while", None, loop_sequence, addr=0x4107)
    root = AngrSequenceNode(
        0x1000,
        [
            AngrSequenceNode(0x1001, []),
            AngrSequenceNode(0x1002, []),
            loop_node,
            AngrSequenceNode(0x4523, [_Block(0x4523)]),
        ],
    )
    project = SimpleNamespace(arch=SimpleNamespace(registers={"ax": (0, 2)}))

    result = _maybe_materialize_pre_codegen_typed_switch_8616(
        project,
        root,
        (
            {
                "case_region_ids": [0x2100],
                "case_values": [1],
                "decision_tree_summary": {
                    "expanded_root_normalization_branch_subtrees": [
                        {
                            "current_case_region_ids": [0x2100],
                            "current_case_values": [1],
                            "subtrees": [
                                {
                                    "default_candidate_region_ids": [0x4523],
                                    "normalized_case_region_ids": [0x2200],
                                    "normalized_case_values": [2],
                                }
                            ],
                        }
                    ],
                    "expanded_root_normalization_readiness": {
                        "ready": True,
                        "status": "branch_splits_ready",
                    },
                },
                "default_region_id": 0x4523,
                "region_id": 0x4400,
                "status": "partial_ladder",
                "switch_condition_lhs": {
                    "name": "ax",
                    "offset": 0,
                    "size": 2,
                    "space": "reg",
                },
            },
        ),
    )

    replacement = loop_sequence.nodes[7]
    assert result["changed"] is True
    assert result["replaced_count"] == 1
    assert type(replacement).__name__ == "SwitchCaseNode"
    assert list(replacement.cases) == [1, 2]
    assert replacement.default_node is default_break


class _FakeState:
    def top(self, bits: int) -> _FakeBV:
        return _FakeBV(bits)


class _FakeTypevars:
    class TypeVariable:
        pass

    @staticmethod
    def new_dtv(typevar, label=None):  # noqa: ANN001
        return ("dtv", typevar, label)

    @staticmethod
    def SubN(value):  # noqa: ANN001
        return ("SubN", value)

    @staticmethod
    def Sub(lhs, rhs, out):  # noqa: ANN001
        return ("Sub", lhs, rhs, out)


class _FakeExpr:
    bits = 16
    operands = ("lhs", "rhs")


class _Engine:
    def __init__(self) -> None:
        self.state = _FakeState()

    def _expr_pair(self, arg0, arg1):  # noqa: ANN001
        lhs = _FakeRichR(_FakeBV(16), typevar=None)
        rhs = _FakeRichR(_FakeBV(32), typevar=None)
        return lhs, rhs

    def _handle_binop_Sub(self, expr):  # noqa: ANN001
        raise AssertionError("guard not installed")


def test_variable_recovery_guard_skips_size_mismatch_log_when_width_coercion_succeeds(capsys) -> None:
    original = install_angr_variable_recovery_binop_sub_size_guard(
        _Engine,
        richr_cls=_FakeRichR,
        typevars_module=_FakeTypevars,
    )
    try:
        engine = _Engine()
        result = engine._handle_binop_Sub(_FakeExpr())
    finally:
        _Engine._handle_binop_Sub = original

    captured = capsys.readouterr()
    assert isinstance(result, _FakeRichR)
    assert result.data.size() == 16
    assert "clinic:variable-recovery-size-mismatch" not in captured.err


class _SignedOffsetEngine(_Engine):
    def _expr_pair(self, arg0, arg1):  # noqa: ANN001
        lhs = _FakeRichR(_FakeBV(32, 0x00010020), typevar=None)
        rhs = _FakeRichR(_FakeBV(16, 0xFFEC), typevar=None)
        return lhs, rhs


def test_variable_recovery_guard_sign_extends_negative_16bit_sub_operand() -> None:
    original = install_angr_variable_recovery_binop_sub_size_guard(
        _SignedOffsetEngine,
        richr_cls=_FakeRichR,
        typevars_module=_FakeTypevars,
    )
    try:
        engine = _SignedOffsetEngine()
        result = engine._handle_binop_Sub(_FakeExpr())
    finally:
        _SignedOffsetEngine._handle_binop_Sub = original

    assert isinstance(result, _FakeRichR)
    assert result.data.size() == 16
    assert result.data.concrete_value == 0x0034


class _BrokenBV(_FakeBV):
    def zero_extend(self, nbits: int) -> _FakeBV:  # noqa: ARG002
        raise RuntimeError("cannot widen")

    def __getitem__(self, item) -> _FakeBV:  # noqa: ANN001
        raise RuntimeError("cannot slice")


class _BrokenWidthEngine(_Engine):
    def _expr_pair(self, arg0, arg1):  # noqa: ANN001
        lhs = _FakeRichR(_BrokenBV(16), typevar=None)
        rhs = _FakeRichR(_FakeBV(32), typevar=None)
        return lhs, rhs


def test_variable_recovery_guard_logs_size_mismatch_when_width_coercion_fails(capsys) -> None:
    original = install_angr_variable_recovery_binop_sub_size_guard(
        _BrokenWidthEngine,
        richr_cls=_FakeRichR,
        typevars_module=_FakeTypevars,
    )
    try:
        engine = _BrokenWidthEngine()
        result = engine._handle_binop_Sub(_FakeExpr())
    finally:
        _BrokenWidthEngine._handle_binop_Sub = original

    captured = capsys.readouterr()
    assert isinstance(result, _FakeRichR)
    assert result.data.size() == 16
    assert "clinic:variable-recovery-size-mismatch" in captured.err
    assert "lhs_bits=16 rhs_bits=32 expr_bits=16" in captured.err
