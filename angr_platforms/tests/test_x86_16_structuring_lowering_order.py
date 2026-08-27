from __future__ import annotations

import ast
import inspect
import textwrap
from types import SimpleNamespace

from angr_platforms.X86_16 import decompiler_structuring_stage as stage


def test_direct_stack_ownership_observes_typed_conditions(monkeypatch) -> None:
    """Transfer ConditionIR before choosing a structured stack-move owner."""
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x4010)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x4010))
    events: list[str] = []

    monkeypatch.setattr(
        stage,
        "_current_structuring_function_8616",
        lambda *_args: function,
    )

    def transfer(_project, func_addr, transferred_codegen) -> None:
        assert _project is project
        assert func_addr == 0x4010
        assert transferred_codegen is codegen
        events.append("condition-transfer")

    def bind(_project, bound_codegen, bound_function) -> None:
        assert _project is project
        assert bound_codegen is codegen
        assert bound_function is function
        assert codegen._inertia_typed_conditions_transferred is True
        events.append("stack-owner-bind")

    monkeypatch.setattr(stage, "transfer_typed_conditions_to_codegen_8616", transfer)
    monkeypatch.setattr(stage, "_bind_direct_stack_move_branch_ownership_8616", bind)
    for name in (
        "prune_callee_saved_stack_spills_8616",
        "materialize_direct_stack_mov_instructions_8616",
        "materialize_direct_stack_incdec_instructions_8616",
        "materialize_direct_global_incdec_instructions_8616",
        "materialize_direct_stack_move_branch_ownership_8616",
        "materialize_direct_stack_move_loop_entry_ownership_8616",
    ):
        monkeypatch.setattr(stage, name, lambda *_args, **_kwargs: False)

    assert not stage._apply_structuring_direct_stack_materialization_8616(
        project,
        codegen,
    )
    assert events == ["condition-transfer", "stack-owner-bind"]


def test_call_return_conditions_are_rebound_after_all_lowering(monkeypatch) -> None:
    """Keep call conditions bound when a later Lowering pass rebuilds their AST."""
    no_change_passes = (
        "materialize_annotated_stack_prototype_8616",
        "_materialize_structuring_callsite_prototypes_8616",
        "_materialize_structuring_callsite_stack_arguments_8616",
        "replay_call_return_switch_selectors_8616",
        "_materialize_structuring_pointer_arg_indirect_loads_8616",
        "_materialize_structuring_stdlib_call_chains_8616",
        "_apply_structuring_stable_stack_semantics_8616",
        "materialize_software_interrupt_calls_8616",
        "_prime_structuring_segment_global_semantics_8616",
        "prune_frame_prologue_stack_assignments_8616",
        "_replay_materialized_call_stack_metadata_8616",
        "prune_unused_structured_insert_intrinsics_8616",
        "lower_structured_insert_intrinsics_8616",
        "materialize_signed_global_declarations_8616",
        "apply_condition_scalar_types_8616",
        "materialize_explicit_scalar_char_types_8616",
    )
    for name in no_change_passes:
        monkeypatch.setattr(stage, name, lambda *args, **kwargs: False)
    monkeypatch.setattr(stage, "_current_structuring_function_8616", lambda *args: None)
    monkeypatch.setattr(
        stage,
        "materialize_loop_carried_terminal_return_8616",
        lambda *args, **kwargs: SimpleNamespace(changed=False),
    )

    events: list[str] = []

    def materialize_call_return(*args, **kwargs) -> bool:
        events.append("call-return")
        return False

    def rebuild_direct_stack(*args, **kwargs) -> bool:
        events.append("direct-stack")
        return False

    monkeypatch.setattr(stage, "materialize_call_return_conditions_8616", materialize_call_return)
    monkeypatch.setattr(stage, "_apply_structuring_direct_stack_materialization_8616", rebuild_direct_stack)

    assert not stage._replay_structuring_lowering_before_validation_8616(object(), object())
    assert events == ["call-return", "direct-stack", "call-return"]


def test_shared_tail_ownership_closes_the_final_structuring_ast() -> None:
    """Keep shared-tail ownership after every pass that can rebuild call nodes."""
    source = textwrap.dedent(inspect.getsource(stage._decompile_structuring_8616))
    span_lines: dict[str, int] = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            expression = item.context_expr
            if (
                isinstance(expression, ast.Call)
                and isinstance(expression.func, ast.Name)
                and expression.func.id == "span"
                and expression.args
                and isinstance(expression.args[0], ast.Constant)
                and isinstance(expression.args[0].value, str)
            ):
                span_lines[expression.args[0].value] = node.lineno

    final_shared_tail = span_lines["x86_16.structuring.final_shared_call_ownership"]
    assert span_lines["x86_16.structuring.terminal_call_result_return"] < final_shared_tail
    assert span_lines["x86_16.structuring.final_lowering_replay"] < final_shared_tail
    assert span_lines["x86_16.structuring.final_selector_return_projection"] < final_shared_tail
    assert final_shared_tail < span_lines["x86_16.structuring.return_chain_integrity"]
    assert final_shared_tail < span_lines["x86_16.structuring.validation.after_fingerprint"]
