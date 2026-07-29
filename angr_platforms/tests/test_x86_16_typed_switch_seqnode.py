from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from angr.analyses.decompiler.structuring.structurer_nodes import (
    BreakNode,
    ConditionNode,
    LoopNode,
    SequenceNode,
)
from angr_platforms.X86_16.structuring.typed_switch_seqnode import (
    TypedSwitchSeqNodeRefusal8616,
    materialize_typed_switch_seqnode_8616,
)


@dataclass(frozen=True)
class _Block:
    addr: int


def _switch_tree() -> tuple[SimpleNamespace, SequenceNode, SequenceNode, SequenceNode, SequenceNode, BreakNode]:
    case_a = SequenceNode(0x2100, [_Block(0x2100)])
    case_b = SequenceNode(0x2200, [_Block(0x2200)])
    default_break = BreakNode(0x2300, 0x3000)
    ladder = SequenceNode(0x2000, [case_a, case_b, default_break])
    loop_sequence = SequenceNode(0x1000, [ladder])
    loop_node = LoopNode("while", None, loop_sequence, addr=0x1000)
    root = SequenceNode(0x0800, [loop_node, SequenceNode(0x3000, [_Block(0x3000)])])
    project = SimpleNamespace(arch=SimpleNamespace(registers={"ax": (0, 2)}))
    return project, root, loop_sequence, case_a, case_b, default_break


def _nested_switch_tree() -> tuple[SimpleNamespace, SequenceNode, SequenceNode, SequenceNode, SequenceNode, BreakNode]:
    case_a = SequenceNode(0x2100, [_Block(0x2100)])
    case_b = SequenceNode(0x2200, [_Block(0x2200)])
    default_break = BreakNode(0x2300, 0x3000)
    condition = ConditionNode(0x2050, None, None, case_a, case_b)
    ladder = SequenceNode(0x2000, [condition, default_break])
    loop_sequence = SequenceNode(0x1000, [ladder])
    loop_node = LoopNode("while", None, loop_sequence, addr=0x1000)
    root = SequenceNode(0x0800, [loop_node, SequenceNode(0x3000, [_Block(0x3000)])])
    project = SimpleNamespace(arch=SimpleNamespace(registers={"ax": (0, 2)}))
    return project, root, loop_sequence, case_a, case_b, default_break


def _materialize(
    project: SimpleNamespace,
    root: SequenceNode,
    *,
    case_values: list[object] | None = None,
    break_paths: list[list[int]] | None = None,
):
    return materialize_typed_switch_seqnode_8616(
        project,
        root,
        first_mapping={
            "switch_condition_lhs": {
                "name": "ax",
                "offset": 0,
                "size": 2,
                "space": "reg",
            }
        },
        owner_paths={"ready": True, "ladder_owner_path": [0]},
        loop_mapping={
            "expanded_root_normalized_case_values": case_values if case_values is not None else [1, 2]
        },
        materialization_plan={
            "break_paths": break_paths if break_paths is not None else [[0, 2]],
            "case_path_common_parent": [0],
            "case_paths": [[0, 0], [0, 1]],
            "external_default_addr": 0x3000,
            "status": "candidate_loop_break_default_switch",
        },
    )


def test_typed_switch_seqnode_materializes_complete_structuring_evidence() -> None:
    project, root, loop_sequence, case_a, case_b, default_break = _switch_tree()

    result = _materialize(project, root)

    replacement = loop_sequence.nodes[0]
    assert result.changed is True
    assert result.refusal is None
    assert result.case_count == 2
    assert result.default_target_addr == 0x3000
    assert type(replacement).__name__ == "SwitchCaseNode"
    assert list(replacement.cases) == [1, 2]
    assert replacement.cases[1] is case_a
    assert replacement.cases[2] is case_b
    assert replacement.default_node is default_break


def test_typed_switch_seqnode_refuses_duplicate_case_values_without_mutation() -> None:
    project, root, loop_sequence, *_ = _switch_tree()
    original_ladder = loop_sequence.nodes[0]

    result = _materialize(project, root, case_values=[1, 1])

    assert result.changed is False
    assert result.refusal is TypedSwitchSeqNodeRefusal8616.DUPLICATE_CASE_VALUE
    assert loop_sequence.nodes[0] is original_ladder


def test_typed_switch_seqnode_refuses_non_unique_default_without_mutation() -> None:
    project, root, loop_sequence, *_ = _switch_tree()
    original_ladder = loop_sequence.nodes[0]

    result = _materialize(project, root, break_paths=[[0, 2], [0, 2]])

    assert result.changed is False
    assert result.refusal is TypedSwitchSeqNodeRefusal8616.MISSING_UNIQUE_DEFAULT_BREAK_PATH
    assert loop_sequence.nodes[0] is original_ladder


def test_typed_switch_seqnode_resolves_condition_branch_paths() -> None:
    project, root, loop_sequence, case_a, case_b, default_break = _nested_switch_tree()

    result = materialize_typed_switch_seqnode_8616(
        project,
        root,
        first_mapping={
            "switch_condition_lhs": {
                "name": "ax",
                "offset": 0,
                "size": 2,
                "space": "reg",
            }
        },
        owner_paths={"ready": True, "ladder_owner_path": [0]},
        loop_mapping={"expanded_root_normalized_case_values": [1, 2]},
        materialization_plan={
            "break_paths": [[0, 1]],
            "case_path_common_parent": [0],
            "case_paths": [[0, 0, 0], [0, 0, 1]],
            "external_default_addr": 0x3000,
            "status": "candidate_loop_break_default_switch",
        },
    )

    replacement = loop_sequence.nodes[0]
    assert result.changed is True
    assert replacement.cases[1] is case_a
    assert replacement.cases[2] is case_b
    assert replacement.default_node is default_break
