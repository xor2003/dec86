from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CForLoop, CIfElse, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.lowering.call_output_stack_objects import (
    WideCallReturnConditionResult8616,
    WideCallReturnConditionStats8616,
)
from angr_platforms.X86_16.structuring import condition_materialization


class _Codegen:
    def __init__(self):
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name):
        self._next_idx += 1
        return self._next_idx


class _Project:
    pass


def test_structuring_condition_materialization_delegates_legacy_consumers_in_order(monkeypatch):
    calls = []

    def _typed(project, codegen):
        calls.append(("typed", project, codegen))
        return True

    def _jcc(project, codegen):
        calls.append(("jcc", project, codegen))
        return False

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_apply_typed_conditions_to_codegen_8616",
        _typed,
    )
    monkeypatch.setattr(
        condition_materialization._legacy_jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        _jcc,
    )
    project = _Project()
    codegen = _Codegen()

    result = condition_materialization.materialize_structuring_conditions_8616(project, codegen)

    assert result.changed is True
    assert result.typed_conditions_changed is True
    assert result.condition_chains_changed is False
    assert result.decoded_jcc_changed is False
    assert calls == [("typed", project, codegen), ("jcc", project, codegen)]
    assert codegen._inertia_structuring_condition_materialization_8616 == {
        "typed_conditions_changed": True,
        "condition_chains_changed": False,
        "decoded_jcc_changed": False,
        "changed": True,
        "owner": "structuring.condition_materialization",
    }
    assert codegen._inertia_condition_materialization_structuring_pass_ran_8616 is True
    assert project._inertia_decompiler_stage == "structuring:condition_materialization:chains"


def test_structuring_condition_materialization_bool_entrypoint(monkeypatch):
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_apply_typed_conditions_to_codegen_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        condition_materialization._legacy_jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        lambda _project, _codegen: True,
    )

    assert condition_materialization.apply_structuring_condition_materialization_8616(_Project(), _Codegen()) is True


def test_structuring_condition_replay_cleanup_delegates_flag_cleanup_in_order(monkeypatch):
    calls = []

    def _typed(project, codegen):
        calls.append(("typed", project, codegen))
        return False

    def _jcc(project, codegen):
        calls.append(("jcc", project, codegen))
        return True

    def _flag_pairs(codegen):
        calls.append(("flag_pairs", codegen))
        return True

    def _flag_bits(codegen):
        calls.append(("flag_bits", codegen))
        return False

    def _interval(codegen):
        calls.append(("interval", codegen))
        return True

    def _unused(project, codegen):
        calls.append(("unused", project, codegen))
        return True

    def _overwritten(project, codegen):
        calls.append(("overwritten", project, codegen))
        return False

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_apply_typed_conditions_to_codegen_8616",
        _typed,
    )
    monkeypatch.setattr(
        condition_materialization._legacy_jcc,
        "_rewrite_decoded_jcc_conditions_8616",
        _jcc,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_rewrite_flag_condition_pairs_8616",
        _flag_pairs,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_rewrite_flag_bit_value_uses_8616",
        _flag_bits,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_fix_interval_guard_conditions_8616",
        _interval,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_prune_unused_flag_assignments_8616",
        _unused,
    )
    monkeypatch.setattr(
        condition_materialization._flags_cleanup,
        "_prune_overwritten_flag_assignments_8616",
        _overwritten,
    )
    project = _Project()
    codegen = _Codegen()

    result = condition_materialization.cleanup_structuring_conditions_after_replay_8616(project, codegen)

    assert result.changed is True
    assert result.materialization.typed_conditions_changed is False
    assert result.materialization.condition_chains_changed is False
    assert result.materialization.decoded_jcc_changed is True
    assert result.flag_condition_pairs_changed is True
    assert result.flag_bit_values_changed is False
    assert result.interval_guards_changed is True
    assert result.unused_flag_assignments_pruned is True
    assert result.overwritten_flag_assignments_pruned is False
    assert calls == [
        ("typed", project, codegen),
        ("jcc", project, codegen),
        ("flag_pairs", codegen),
        ("flag_bits", codegen),
        ("interval", codegen),
        ("unused", project, codegen),
        ("overwritten", project, codegen),
    ]
    assert codegen._inertia_structuring_condition_replay_cleanup_8616 == {
        "typed_conditions_changed": False,
        "condition_chains_changed": False,
        "decoded_jcc_changed": True,
        "flag_condition_pairs_changed": True,
        "flag_bit_values_changed": False,
        "interval_guards_changed": True,
        "unused_flag_assignments_pruned": True,
        "overwritten_flag_assignments_pruned": False,
        "changed": True,
        "owner": "structuring.condition_materialization",
    }


def test_structuring_condition_replay_cleanup_bool_entrypoint(monkeypatch):
    monkeypatch.setattr(
        condition_materialization,
        "cleanup_structuring_conditions_after_replay_8616",
        lambda _project, _codegen: type("Result", (), {"changed": True})(),
    )

    assert condition_materialization.apply_structuring_condition_replay_cleanup_8616(object(), _Codegen()) is True


class _Graph:
    def __init__(self, edges):
        self._successors = {}
        for source, target in edges:
            self._successors.setdefault(source, []).append(target)
            self._successors.setdefault(target, [])
        self.nodes = tuple(self._successors)

    def successors(self, node):
        return tuple(self._successors[node])


def _tagged_statements(ins_addr, codegen):
    statements = CStatements([], codegen=codegen)
    statements.tags = {"ins_addr": ins_addr}
    return statements


def _targeted_condition(src_insn, block_addr, taken_target, fallthrough_target):
    return ConditionIR(
        op="ne",
        lhs=src_insn,
        rhs=0,
        src_insn=src_insn,
        block_addr=block_addr,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
    )


def test_structuring_condition_surface_token_detects_in_place_branch_reownership():
    codegen = _Codegen()
    condition = CBinaryOp(
        "CmpEQ",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1002, "vex_block_addr": 0x1000},
    )
    return_body = _tagged_statements(0x1020, codegen)
    guarded_body = _tagged_statements(0x1010, codegen)
    branch = CIfElse(
        [(condition, return_body)],
        else_node=guarded_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)

    before = condition_materialization.structuring_condition_surface_token_8616(codegen)
    branch.condition_and_nodes = [(condition, guarded_body)]
    branch.else_node = None
    after = condition_materialization.structuring_condition_surface_token_8616(codegen)

    assert before != after


def test_structuring_condition_surface_token_detects_rebuilt_loop_condition():
    codegen = _Codegen()
    original_condition = CBinaryOp(
        "CmpLT",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1002, "vex_block_addr": 0x1000},
    )
    loop = CForLoop(
        None,
        original_condition,
        None,
        _tagged_statements(0x1010, codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([loop], codegen=codegen)
    )

    before = condition_materialization.structuring_condition_surface_token_8616(
        codegen
    )
    loop.condition = CBinaryOp(
        "CmpLT",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(3, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1002, "vex_block_addr": 0x1000},
    )
    after = condition_materialization.structuring_condition_surface_token_8616(
        codegen
    )

    assert before != after


def test_structuring_condition_chain_materializes_three_branch_short_circuit(monkeypatch):
    codegen = _Codegen()
    root_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    root_condition.tags = {"ins_addr": 0x103F, "vex_block_addr": 0x103B}
    true_body = _tagged_statements(0x1056, codegen)
    false_body = _tagged_statements(0x105E, codegen)
    branch = CIfElse(
        [(root_condition, true_body)],
        else_node=false_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    branch.tags = {"ins_addr": 0x103B}
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x103F, 0x103B, 0x1044, 0x1041),
        _targeted_condition(0x1048, 0x1044, 0x104D, 0x104A),
        ConditionIR(
            op="eq",
            lhs=0x1051,
            rhs=0,
            src_insn=0x1051,
            block_addr=0x104D,
            taken_target=0x1056,
            fallthrough_target=0x1053,
        ),
    )
    graph = _Graph(((0x1041, 0x1056), (0x104A, 0x1056), (0x1053, 0x105E)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x103B, 0x1044, 0x104D})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = conditions

    def _materialize(_project, condition, _codegen):
        value = CConstant(condition.src_insn, SimTypeShort(False), codegen=codegen)
        zero = CConstant(0, SimTypeShort(False), codegen=codegen)
        return CBinaryOp("CmpEQ" if condition.op == "eq" else "CmpNE", value, zero, codegen=codegen)

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = root.statements[0].condition_and_nodes[0][0]
    assert replacement.op == "LogicalOr"
    assert replacement.lhs.op == "CmpEQ"
    assert replacement.lhs.lhs.value == 0x103F
    assert replacement.rhs.op == "LogicalOr"
    assert replacement.rhs.lhs.op == "CmpEQ"
    assert replacement.rhs.lhs.lhs.value == 0x1048
    assert replacement.rhs.rhs.op == "CmpEQ"
    assert replacement.rhs.rhs.lhs.value == 0x1051
    assert replacement.tags["inertia_structuring_condition_chain_materialized_8616"] is True
    assert codegen._inertia_structuring_condition_chain_stats_8616 == (
        condition_materialization.StructuringConditionChainStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        )
    )


def test_structuring_shared_body_chain_materializes_all_cfg_conditions(monkeypatch):
    codegen = _Codegen()
    first_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    first_condition.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    last_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    last_condition.tags = {"ins_addr": 0x1022, "vex_block_addr": 0x1020}
    shared_body = _tagged_statements(0x1040, codegen)
    shared_body.tags["vex_block_addr"] = 0x1040
    branch = CIfElse(
        [(first_condition, shared_body), (last_condition, shared_body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    branch.tags = {"ins_addr": 0x1000}
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x1002, 0x1000, 0x1010, 0x1004),
        _targeted_condition(0x1012, 0x1010, 0x1020, 0x1014),
        _targeted_condition(0x1022, 0x1020, 0x1030, 0x1024),
    )
    graph = _Graph(
        (
            (0x1000, 0x1010),
            (0x1000, 0x1004),
            (0x1004, 0x1040),
            (0x1010, 0x1020),
            (0x1010, 0x1014),
            (0x1014, 0x1000),
            (0x1020, 0x1030),
            (0x1020, 0x1024),
            (0x1030, 0x1000),
            (0x1024, 0x1040),
        )
    )
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes))
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = conditions

    def _materialize(_project, condition, _codegen):
        value = CConstant(condition.src_insn, SimTypeShort(False), codegen=codegen)
        zero = CConstant(0, SimTypeShort(False), codegen=codegen)
        return CBinaryOp("CmpNE", value, zero, codegen=codegen)

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    refused = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert refused is False
    assert len(branch.condition_and_nodes) == 2
    assert codegen._inertia_structuring_condition_chain_stats_8616 == (
        condition_materialization.StructuringConditionChainStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )
    )

    def _lower_wide(_codegen, expression, _conditions):
        return WideCallReturnConditionResult8616(
            expression=expression,
            stats=WideCallReturnConditionStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
            ),
        )

    monkeypatch.setattr(
        condition_materialization,
        "lower_wide_call_return_condition_chain_8616",
        _lower_wide,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    assert len(branch.condition_and_nodes) == 1
    replacement, body = branch.condition_and_nodes[0]
    assert body is shared_body
    assert replacement.op == "LogicalOr"
    assert replacement.lhs.op == "CmpEQ"
    assert replacement.lhs.lhs.value == 0x1002
    assert replacement.rhs.op == "LogicalAnd"
    assert replacement.rhs.lhs.op == "CmpNE"
    assert replacement.rhs.lhs.lhs.value == 0x1012
    assert replacement.rhs.rhs.op == "CmpEQ"
    assert replacement.rhs.rhs.lhs.value == 0x1022
    assert replacement.tags["inertia_structuring_shared_body_condition_chain_materialized_8616"] is True
    assert codegen._inertia_structuring_condition_chain_stats_8616 == (
        condition_materialization.StructuringConditionChainStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        )
    )

    changed_again = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed_again is False
    assert branch.condition_and_nodes[0][0] is replacement


def test_structuring_shared_body_chain_refuses_missing_middle_condition(monkeypatch):
    codegen = _Codegen()
    first_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    first_condition.tags = {"ins_addr": 0x2002, "vex_block_addr": 0x2000}
    last_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    last_condition.tags = {"ins_addr": 0x2022, "vex_block_addr": 0x2020}
    shared_body = _tagged_statements(0x2040, codegen)
    shared_body.tags["vex_block_addr"] = 0x2040
    branch = CIfElse(
        [(first_condition, shared_body), (last_condition, shared_body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x2002, 0x2000, 0x2010, 0x2004),
        _targeted_condition(0x2022, 0x2020, 0x2030, 0x2024),
    )
    graph = _Graph(
        (
            (0x2000, 0x2010),
            (0x2000, 0x2004),
            (0x2004, 0x2040),
            (0x2010, 0x2020),
            (0x2010, 0x2014),
            (0x2014, 0x2000),
            (0x2020, 0x2030),
            (0x2020, 0x2024),
            (0x2030, 0x2000),
            (0x2024, 0x2040),
        )
    )
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes))
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x2000, statements=root)
    codegen._inertia_typed_conditions = conditions
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert len(branch.condition_and_nodes) == 2
    assert codegen._inertia_structuring_condition_chain_stats_8616.failure_count == 1


def test_structuring_shared_body_chain_refuses_different_body_targets():
    codegen = _Codegen()
    first_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    first_condition.tags = {"ins_addr": 0x3002, "vex_block_addr": 0x3000}
    second_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    second_condition.tags = {"ins_addr": 0x3012, "vex_block_addr": 0x3010}
    first_body = _tagged_statements(0x3040, codegen)
    first_body.tags["vex_block_addr"] = 0x3040
    second_body = _tagged_statements(0x3050, codegen)
    second_body.tags["vex_block_addr"] = 0x3050
    branch = CIfElse(
        [(first_condition, first_body), (second_condition, second_body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    conditions = (
        _targeted_condition(0x3002, 0x3000, 0x3010, 0x3004),
        _targeted_condition(0x3012, 0x3010, 0x3040, 0x3014),
    )
    graph = _Graph(((0x3000, 0x3010), (0x3000, 0x3004), (0x3010, 0x3040), (0x3010, 0x3014)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x3050})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x3000, statements=root)
    codegen._inertia_typed_conditions = conditions

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert len(branch.condition_and_nodes) == 2
    assert codegen._inertia_structuring_condition_chain_stats_8616.failure_count == 1


def test_structuring_condition_owner_refuses_unrelated_container_tag():
    fact = _targeted_condition(0x103F, 0x103B, 0x1044, 0x1041)

    assert condition_materialization._structured_node_owns_condition_fact_8616(0x103F, fact)
    assert condition_materialization._structured_node_owns_condition_fact_8616(0x103B, fact)
    assert condition_materialization._structured_node_owns_condition_fact_8616(None, fact)
    assert not condition_materialization._structured_node_owns_condition_fact_8616(0x9999, fact)


def test_structuring_condition_chain_refuses_unproven_leaf(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x2002, "vex_block_addr": 0x2000}
    true_body = _tagged_statements(0x2010, codegen)
    false_body = _tagged_statements(0x2020, codegen)
    root = CStatements(
        [CIfElse([(condition, true_body)], else_node=false_body, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x2002, 0x2000, 0x2004, 0x2006)
    graph = _Graph(((0x2004, 0x2010),))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x2000, 0x2006, 0x2020})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x2000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert root.statements[0].condition_and_nodes[0][0] is condition
    assert codegen._inertia_structuring_condition_chain_stats_8616.failure_count == 1


def test_structuring_single_branch_uses_taken_condition_for_taken_owned_body(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    body = _tagged_statements(0x1012, codegen)
    body.tags["vex_block_addr"] = 0x1010
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x1002, 0x1000, 0x1010, 0x1004)
    graph = _Graph(((0x1004, 0x1020), (0x1010, 0x1018), (0x1018, 0x1020)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x1000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = root.statements[0].condition_and_nodes[0][0]
    assert replacement.op == "CmpNE"
    assert replacement.tags["inertia_structuring_single_branch_materialized_8616"] is True
    assert replacement.tags["inertia_structuring_condition_cfg_materialized_8616"] is True

    changed_again = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed_again is False
    assert root.statements[0].condition_and_nodes[0][0] is replacement
    assert codegen._inertia_structuring_condition_chain_stats_8616.materialized_count == 1


def test_structuring_single_branch_refuses_to_rebind_tagged_condition_by_body_shape(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x4092, "vex_block_addr": 0x4090}
    body = _tagged_statements(0x4012, codegen)
    body.tags["vex_block_addr"] = 0x4010
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    correct_fact = _targeted_condition(0x4002, 0x4000, 0x4010, 0x4004)
    stale_fact = _targeted_condition(0x4092, 0x4090, 0x40A0, 0x4094)
    graph = _Graph(
        (
            (0x4004, 0x4020),
            (0x4010, 0x4020),
            (0x4094, 0x40B0),
            (0x40A0, 0x40B0),
        )
    )
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes) | {0x4000, 0x4090},
    )
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root)
    codegen._inertia_typed_conditions = (correct_fact, stale_fact)

    def _materialize(_project, typed_condition, _codegen):
        return CBinaryOp(
            "CmpNE",
            CConstant(typed_condition.src_insn, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert root.statements[0].condition_and_nodes[0][0] is condition
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_structuring_single_branch_prefers_exact_container_owner_over_stale_condition(
    monkeypatch,
):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x4092, "vex_block_addr": 0x4090}
    body = _tagged_statements(0x4012, codegen)
    body.tags["vex_block_addr"] = 0x4010
    branch = CIfElse(
        [(condition, body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    branch.tags = {"ins_addr": 0x4002, "vex_block_addr": 0x4000}
    root = CStatements([branch], codegen=codegen)
    correct_fact = _targeted_condition(0x4002, 0x4000, 0x4010, 0x4004)
    stale_fact = _targeted_condition(0x4092, 0x4090, 0x40A0, 0x4094)
    graph = _Graph(
        (
            (0x4004, 0x4020),
            (0x4010, 0x4020),
            (0x4094, 0x40B0),
            (0x40A0, 0x40B0),
        )
    )
    function = SimpleNamespace(
        transition_graph=graph,
        block_addrs_set=set(graph.nodes) | {0x4000, 0x4090},
    )
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x4000, statements=root)
    codegen._inertia_typed_conditions = (correct_fact, stale_fact)

    def _materialize(_project, typed_condition, _codegen):
        return CBinaryOp(
            "CmpNE",
            CConstant(typed_condition.src_insn, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )

    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        _materialize,
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = branch.condition_and_nodes[0][0]
    assert replacement.op == "CmpNE"
    assert replacement.lhs.value == 0x4002
    assert replacement.tags["ins_addr"] == 0x4002
    assert replacement.tags["vex_block_addr"] == 0x4000
    assert replacement.tags["inertia_structuring_single_branch_materialized_8616"] is True
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_structuring_single_branch_binds_untagged_condition_to_unique_body_owner(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    body = _tagged_statements(0x5012, codegen)
    body.tags["vex_block_addr"] = 0x5010
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x5002, 0x5000, 0x5010, 0x5004)
    graph = _Graph(((0x5004, 0x5020), (0x5010, 0x5020)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x5000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x5000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = root.statements[0].condition_and_nodes[0][0]
    assert replacement.op == "CmpNE"
    assert replacement.tags["inertia_structuring_single_branch_materialized_8616"] is True


def test_structuring_single_branch_inverts_condition_for_fallthrough_owned_body(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x2002, "vex_block_addr": 0x2000}
    body = _tagged_statements(0x2012, codegen)
    body.tags["vex_block_addr"] = 0x2010
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x2002, 0x2000, 0x2020, 0x2010)
    graph = _Graph(((0x2010, 0x2018), (0x2018, 0x2030), (0x2020, 0x2030)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x2000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x2000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is True
    replacement = root.statements[0].condition_and_nodes[0][0]
    assert replacement.op == "CmpEQ"


def test_structuring_single_branch_refuses_shared_body_reachability(monkeypatch):
    codegen = _Codegen()
    condition = CConstant(0, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x3002, "vex_block_addr": 0x3000}
    body = _tagged_statements(0x3032, codegen)
    body.tags["vex_block_addr"] = 0x3030
    root = CStatements(
        [CIfElse([(condition, body)], else_node=None, cstyle_ifs=True, codegen=codegen)],
        codegen=codegen,
    )
    fact = _targeted_condition(0x3002, 0x3000, 0x3010, 0x3020)
    graph = _Graph(((0x3010, 0x3030), (0x3020, 0x3030)))
    function = SimpleNamespace(transition_graph=graph, block_addrs_set=set(graph.nodes) | {0x3000})
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)))
    codegen.cfunc = SimpleNamespace(addr=0x3000, statements=root)
    codegen._inertia_typed_conditions = (fact,)
    monkeypatch.setattr(
        condition_materialization._legacy_typed_conditions,
        "_build_c_condition_expr",
        lambda *_args: CBinaryOp(
            "CmpNE",
            CConstant(1, SimTypeShort(False), codegen=codegen),
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
    )

    changed = condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)

    assert changed is False
    assert root.statements[0].condition_and_nodes[0][0] is condition
    stats = codegen._inertia_structuring_condition_chain_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
