"""Structuring-owned condition materialization boundary.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

Condition semantics belong before rewrite.  This module is the migration
surface for applying already-proven ``ConditionIR`` facts while the historical
AST consumers still live in ``decompiler_postprocess_*`` compatibility modules.

Allowed work here:
- consume ``ConditionIR`` facts already transferred to codegen;
- orient a structured branch only from target-bearing ``ConditionIR`` and
  exclusive CFG ownership of its body;
- call legacy consumers only as a temporary implementation detail;
- record structured per-consumer materialization status for validation/debugging.

Do not add fresh instruction decoding, operand recovery, condition inference,
or text-based repair here. Branch orientation must consume explicit
``taken_target``/``fallthrough_target`` facts and refuse non-exclusive CFG
ownership. Those facts must be produced by lift/IR, alias/lowering, or
structuring analysis before this materialization boundary. When the legacy
consumers are migrated, keep this API and replace the delegates.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CIfElse,
    CUnaryOp,
    CWhileLoop,
)

from .. import decompiler_postprocess_jcc as _legacy_jcc
from .. import decompiler_postprocess_typed_conditions as _legacy_typed_conditions
from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..ir.condition_ir import ConditionIR
from ..lowering.call_output_stack_objects import (
    lower_call_output_stack_fields_in_condition_8616,
    lower_wide_call_return_condition_chain_8616,
    prune_materialized_call_output_stack_carriers_8616,
)
from ..pipeline.errors import PipelineHardError
from ..postprocess import flags_cleanup as _flags_cleanup

log: logging.Logger = logging.getLogger(__name__)


def materialize_condition_ir_expression_8616(
    project: object,
    codegen: object,
    condition: ConditionIR,
) -> CExpression | None:
    """Lower one proven ConditionIR through the Structuring-owned boundary.

    The historical expression builder remains a compatibility implementation
    detail while its register-expression lookup moves into Structuring. Callers
    must provide the exact typed condition selected from CFG ownership; this
    function performs no condition discovery or instruction decoding.
    """
    expression = _legacy_typed_conditions._build_c_condition_expr(project, condition, codegen)
    return expression if isinstance(expression, CExpression) else None


def _debug_condition_chain_8616(event: str, **fields: object) -> None:
    """Log one structuring condition-chain decision when diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_CONDITION_MATERIALIZATION") != "1":
        return
    details = " ".join(f"{key}={value!r}" for key, value in sorted(fields.items()))
    log.warning("[condition-materialization] event=%s %s", event, details)


class _ConditionMaterializationCodegen8616(Protocol):
    """Dynamic codegen metadata slots written by structuring condition materialization."""

    _inertia_structuring_condition_materialization_8616: dict[str, object]
    _inertia_structuring_condition_replay_cleanup_8616: dict[str, object]
    _inertia_condition_materialization_structuring_pass_ran_8616: bool
    _inertia_structuring_condition_chain_stats_8616: StructuringConditionChainStats8616
    _inertia_typed_conditions: object
    cfunc: object


class _ConditionMaterializationProject8616(Protocol):
    """Project diagnostics written while condition consumers run."""

    _inertia_decompiler_stage: str
    kb: object


class _ConditionMaterializationCFunction8616(Protocol):
    """Dynamic angr CFunction fields consumed at the structuring boundary."""

    addr: int
    statements: object


class _ConditionMaterializationKnowledgeBase8616(Protocol):
    """Dynamic angr knowledge-base fields consumed at the structuring boundary."""

    functions: object


class _ConditionMaterializationFunctionManager8616(Protocol):
    """Dynamic angr function lookup used by structuring condition chains."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Return one function without creating it."""


class _ConditionMaterializationFunction8616(Protocol):
    """Dynamic angr Function fields consumed by CFG condition materialization."""

    transition_graph: object
    block_addrs_set: set[int]


class _ConditionMaterializationGraph8616(Protocol):
    """Minimal networkx-compatible graph contract used by structuring."""

    nodes: object

    def successors(self, node: object) -> object:
        """Return graph successors for one node."""


class _ConditionMaterializationGraphNode8616(Protocol):
    """Dynamic angr CFG node address."""

    addr: int


class _ConditionMaterializationTaggedNode8616(Protocol):
    """Dynamic angr C-AST tag dictionary."""

    tags: dict[str, object]


@dataclass(frozen=True, slots=True)
class StructuringConditionChainStats8616:
    """Evidence accounting for CFG-proven short-circuit condition chains."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class StructuringConditionMaterializationResult8616:
    """Structured result for condition materialization during structuring."""

    typed_conditions_changed: bool
    condition_chains_changed: bool
    decoded_jcc_changed: bool

    @property
    def changed(self) -> bool:
        """Return True when any delegated materializer changed the AST."""
        return self.typed_conditions_changed or self.condition_chains_changed or self.decoded_jcc_changed


@dataclass(frozen=True, slots=True)
class StructuringConditionReplayCleanupResult8616:
    """Structured result for late condition replay cleanup."""

    materialization: StructuringConditionMaterializationResult8616
    flag_condition_pairs_changed: bool
    flag_bit_values_changed: bool
    interval_guards_changed: bool
    unused_flag_assignments_pruned: bool
    overwritten_flag_assignments_pruned: bool

    @property
    def changed(self) -> bool:
        """Return True when materialization or cleanup changed the AST."""
        return (
            self.materialization.changed
            or self.flag_condition_pairs_changed
            or self.flag_bit_values_changed
            or self.interval_guards_changed
            or self.unused_flag_assignments_pruned
            or self.overwritten_flag_assignments_pruned
        )


def _cfg_node_addr_8616(node: object) -> int | None:
    """Return one address from a dynamic angr CFG node."""
    if isinstance(node, int):
        return node
    boundary = cast(_ConditionMaterializationGraphNode8616, node)
    try:
        return boundary.addr if isinstance(boundary.addr, int) else None
    except AttributeError:
        return None


def _condition_chain_successors_8616(project: object, codegen: object) -> dict[int, tuple[int, ...]]:
    """Return in-function CFG successors keyed by block address."""
    try:
        cfunc = cast(_ConditionMaterializationCFunction8616, cast(_ConditionMaterializationCodegen8616, codegen).cfunc)
        function_manager = cast(
            _ConditionMaterializationFunctionManager8616,
            cast(
                _ConditionMaterializationKnowledgeBase8616,
                cast(_ConditionMaterializationProject8616, project).kb,
            ).functions,
        )
        function = cast(_ConditionMaterializationFunction8616, function_manager.function(addr=cfunc.addr, create=False))
        graph = cast(_ConditionMaterializationGraph8616, function.transition_graph)
        block_addrs = set(function.block_addrs_set)
    except (AttributeError, TypeError):
        return {}
    successors: dict[int, tuple[int, ...]] = {}
    try:
        nodes = tuple(cast(Any, graph.nodes))
    except (AttributeError, TypeError):
        return {}
    for node in nodes:
        addr = _cfg_node_addr_8616(node)
        if addr not in block_addrs:
            continue
        try:
            target_addrs = tuple(
                target_addr
                for successor in cast(Any, graph.successors(node))
                if (target_addr := _cfg_node_addr_8616(successor)) in block_addrs
            )
        except (AttributeError, TypeError):
            continue
        successors[addr] = tuple(dict.fromkeys(target_addrs))
    return successors


def _first_tagged_ins_addr_8616(node: object) -> int | None:
    """Return the first binary instruction tag in one structured C subtree."""
    addresses: list[int] = []
    for current in _iter_c_nodes_deep_8616(node):
        boundary = cast(_ConditionMaterializationTaggedNode8616, current)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        ins_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
        if isinstance(ins_addr, int):
            addresses.append(ins_addr)
    return min(addresses) if addresses else None


def _first_tagged_block_addr_8616(node: object) -> int | None:
    """Return the first VEX block tag in one structured C subtree."""
    addresses: list[int] = []
    for current in _iter_c_nodes_deep_8616(node):
        boundary = cast(_ConditionMaterializationTaggedNode8616, current)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        block_addr = tags.get("vex_block_addr") if isinstance(tags, dict) else None
        if isinstance(block_addr, int):
            addresses.append(block_addr)
    return min(addresses) if addresses else None


def _cfg_reaches_address_8616(
    successors: dict[int, tuple[int, ...]],
    start: int,
    target: int,
) -> bool:
    """Return whether one bounded in-function CFG path reaches ``target``."""
    pending = [start]
    visited: set[int] = set()
    while pending and len(visited) < 64:
        address = pending.pop()
        if address == target:
            return True
        if address in visited:
            continue
        visited.add(address)
        pending.extend(successors.get(address, ()))
    return False


def _condition_key_from_tags_8616(node: object) -> tuple[int, int] | None:
    """Return the first complete instruction/block tag pair in a C expression."""
    for current in _iter_c_nodes_deep_8616(node):
        boundary = cast(_ConditionMaterializationTaggedNode8616, current)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        if not isinstance(tags, dict):
            continue
        ins_addr = tags.get("ins_addr")
        block_addr = tags.get("vex_block_addr")
        if isinstance(ins_addr, int) and isinstance(block_addr, int):
            return ins_addr, block_addr
    return None


def _direct_tagged_ins_addr_8616(node: object) -> int | None:
    """Return the instruction tag owned directly by one structured node."""
    boundary = cast(_ConditionMaterializationTaggedNode8616, node)
    try:
        tags = boundary.tags
    except AttributeError:
        return None
    if not isinstance(tags, dict):
        return None
    ins_addr = tags.get("ins_addr")
    return ins_addr if isinstance(ins_addr, int) else None


def _structured_node_owns_condition_fact_8616(
    node_addr: int | None,
    condition: ConditionIR,
) -> bool:
    """Accept an exact branch-instruction or containing-block ownership tag."""
    if node_addr is None:
        return True
    return node_addr == condition.src_insn or node_addr == condition.block_addr


def _copied_condition_tags_8616(node: object) -> dict[str, object]:
    """Copy C-expression tags at the dynamic angr boundary."""
    boundary = cast(_ConditionMaterializationTaggedNode8616, node)
    try:
        tags = boundary.tags
    except AttributeError:
        return {}
    return dict(tags) if isinstance(tags, dict) else {}


def _condition_structure_token_8616(condition: object) -> tuple[object, ...]:
    """Return a bounded semantic-shape token for one structured condition."""
    if isinstance(condition, CUnaryOp):
        return ("unary", condition.op, _condition_structure_token_8616(condition.operand))
    if isinstance(condition, CBinaryOp):
        return ("binary", condition.op)
    return (type(condition).__name__,)


def _condition_debug_tree_8616(condition: object, *, depth: int = 0) -> tuple[object, ...]:
    """Return a bounded operator tree for opt-in condition diagnostics."""
    if depth >= 8:
        return ("depth-limit",)
    if isinstance(condition, CUnaryOp):
        return (
            "unary",
            condition.op,
            _condition_debug_tree_8616(condition.operand, depth=depth + 1),
        )
    if isinstance(condition, CBinaryOp):
        return (
            "binary",
            condition.op,
            _condition_debug_tree_8616(condition.lhs, depth=depth + 1),
            _condition_debug_tree_8616(condition.rhs, depth=depth + 1),
        )
    return (type(condition).__name__,)


def structuring_condition_surface_token_8616(codegen: object) -> tuple[tuple[object, ...], ...]:
    """Describe branch ownership so later AST mutation invalidates materialization."""
    try:
        cfunc = cast(
            _ConditionMaterializationCFunction8616,
            cast(_ConditionMaterializationCodegen8616, codegen).cfunc,
        )
        statements = cfunc.statements
    except AttributeError:
        return ()
    surface: list[tuple[object, ...]] = []
    for node in _iter_c_nodes_deep_8616(statements):
        if isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            condition = node.condition
            tags = _copied_condition_tags_8616(condition)
            surface.append(
                (
                    "loop",
                    type(node).__name__,
                    id(condition),
                    _condition_key_from_tags_8616(condition),
                    _condition_structure_token_8616(condition),
                    _first_tagged_block_addr_8616(node.body),
                    _first_tagged_ins_addr_8616(node.body),
                    tags.get("inertia_jcc_polarity_evidence_8616"),
                    tags.get(
                        "inertia_structuring_condition_cfg_materialized_8616"
                    )
                    is True,
                )
            )
            continue
        if not isinstance(node, CIfElse):
            continue
        pairs = tuple(node.condition_and_nodes)
        for condition, body in pairs:
            tags = _copied_condition_tags_8616(condition)
            surface.append(
                (
                    "ifelse",
                    id(condition),
                    _condition_key_from_tags_8616(condition),
                    _condition_structure_token_8616(condition),
                    len(pairs),
                    node.else_node is not None,
                    _first_tagged_block_addr_8616(body),
                    _first_tagged_ins_addr_8616(body),
                    _first_tagged_block_addr_8616(node.else_node),
                    _first_tagged_ins_addr_8616(node.else_node),
                    tags.get("inertia_jcc_polarity_evidence_8616"),
                    tags.get("inertia_structuring_condition_cfg_materialized_8616") is True,
                )
            )
    return tuple(surface)


def _invert_structured_condition_8616(condition: CExpression, codegen: object) -> CExpression:
    """Invert one materialized comparison without recovering new semantics."""
    inverted_ops = {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
    }
    if isinstance(condition, CBinaryOp) and condition.op in inverted_ops:
        return CBinaryOp(inverted_ops[condition.op], condition.lhs, condition.rhs, codegen=codegen)
    if isinstance(condition, CUnaryOp) and condition.op == "Not":
        return condition.operand
    return CUnaryOp("Not", condition, codegen=codegen)


def _combine_condition_outcomes_8616(
    condition: CExpression,
    taken: CExpression | bool,
    fallthrough: CExpression | bool,
    codegen: object,
) -> CExpression | bool:
    """Build the predicate that reaches the selected CFG leaf."""
    if isinstance(taken, bool) and isinstance(fallthrough, bool):
        if taken == fallthrough:
            return taken
        return condition if taken else _invert_structured_condition_8616(condition, codegen)
    if taken is True:
        return CBinaryOp("LogicalOr", condition, cast(CExpression, fallthrough), codegen=codegen)
    if fallthrough is True:
        return CBinaryOp(
            "LogicalOr",
            _invert_structured_condition_8616(condition, codegen),
            cast(CExpression, taken),
            codegen=codegen,
        )
    if taken is False:
        return CBinaryOp(
            "LogicalAnd",
            _invert_structured_condition_8616(condition, codegen),
            cast(CExpression, fallthrough),
            codegen=codegen,
        )
    if fallthrough is False:
        return CBinaryOp("LogicalAnd", condition, cast(CExpression, taken), codegen=codegen)
    return CBinaryOp(
        "LogicalOr",
        CBinaryOp("LogicalAnd", condition, cast(CExpression, taken), codegen=codegen),
        CBinaryOp(
            "LogicalAnd",
            _invert_structured_condition_8616(condition, codegen),
            cast(CExpression, fallthrough),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _materialize_cfg_condition_chain_expr_8616(
    project: object,
    codegen: object,
    root_condition: ConditionIR,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    true_target: int,
    false_target: int,
) -> CExpression | None:
    """Materialize one target-directed predicate from typed conditions and CFG."""
    consumed_conditions: list[ConditionIR] = []

    def build_from_address(address: int, visited: frozenset[int]) -> CExpression | bool | None:
        if address == true_target:
            return True
        if address == false_target:
            return False
        if address in visited or len(visited) >= 24:
            _debug_condition_chain_8616(
                "cfg-chain-address-cycle",
                address=address,
                visited=tuple(sorted(visited)),
            )
            return None
        condition = conditions_by_block.get(address)
        if condition is not None:
            return build_from_condition(condition, visited | {address})
        next_addrs = successors.get(address, ())
        if len(next_addrs) != 1:
            _debug_condition_chain_8616(
                "cfg-chain-successor-refused",
                address=address,
                successors=next_addrs,
                visited=tuple(sorted(visited)),
            )
            return None
        return build_from_address(next_addrs[0], visited | {address})

    def build_from_condition(condition: ConditionIR, visited: frozenset[int]) -> CExpression | bool | None:
        if not isinstance(condition.taken_target, int) or not isinstance(condition.fallthrough_target, int):
            _debug_condition_chain_8616(
                "cfg-chain-target-refused",
                block_addr=condition.block_addr,
                src_insn=condition.src_insn,
                taken_target=condition.taken_target,
                fallthrough_target=condition.fallthrough_target,
            )
            return None
        if condition not in consumed_conditions:
            consumed_conditions.append(condition)
        materialized = _legacy_typed_conditions._build_c_condition_expr(project, condition, codegen)
        if materialized is None:
            _debug_condition_chain_8616(
                "cfg-chain-expression-refused",
                block_addr=condition.block_addr,
                src_insn=condition.src_insn,
            )
            return None
        taken = build_from_address(condition.taken_target, visited)
        fallthrough = build_from_address(condition.fallthrough_target, visited)
        if taken is None or fallthrough is None:
            _debug_condition_chain_8616(
                "cfg-chain-outcome-refused",
                block_addr=condition.block_addr,
                src_insn=condition.src_insn,
                taken_available=taken is not None,
                fallthrough_available=fallthrough is not None,
            )
            return None
        return _combine_condition_outcomes_8616(materialized, taken, fallthrough, codegen)

    result = build_from_condition(root_condition, frozenset())
    if not isinstance(result, CExpression):
        _debug_condition_chain_8616(
            "cfg-chain-result-refused",
            result_type=type(result).__name__,
            root_block=root_condition.block_addr,
            root_src=root_condition.src_insn,
        )
        return None
    lowering = lower_call_output_stack_fields_in_condition_8616(codegen, result, tuple(consumed_conditions))
    return lowering.expression


def _materialize_cfg_shared_body_condition_chain_expr_8616(
    project: object,
    codegen: object,
    root_condition: ConditionIR,
    required_conditions: tuple[ConditionIR, ...],
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    body_target: int,
) -> CExpression | None:
    """Build the predicate that reaches one body before repeating the condition chain.

    A repeated CFG address is the outer control-flow backedge for this
    structured decision, so it means that the shared body is not reached by
    the current evaluation. Unknown untyped forks remain a refusal.
    """
    consumed_conditions: list[ConditionIR] = []

    def build_from_address(address: int, visited: frozenset[int]) -> CExpression | bool | None:
        if address == body_target:
            return True
        if address in visited or len(visited) >= 24:
            return False
        condition = conditions_by_block.get(address)
        if condition is not None:
            return build_from_condition(condition, visited | {address})
        next_addrs = successors.get(address, ())
        if not next_addrs:
            return False
        if len(next_addrs) != 1:
            return None
        return build_from_address(next_addrs[0], visited | {address})

    def build_from_condition(condition: ConditionIR, visited: frozenset[int]) -> CExpression | bool | None:
        if not isinstance(condition.taken_target, int) or not isinstance(condition.fallthrough_target, int):
            return None
        if all(existing is not condition for existing in consumed_conditions):
            consumed_conditions.append(condition)
        materialized = _legacy_typed_conditions._build_c_condition_expr(project, condition, codegen)
        if not isinstance(materialized, CExpression):
            return None
        taken = build_from_address(condition.taken_target, visited)
        fallthrough = build_from_address(condition.fallthrough_target, visited)
        if taken is None or fallthrough is None:
            return None
        return _combine_condition_outcomes_8616(materialized, taken, fallthrough, codegen)

    initial_visited = (
        frozenset({root_condition.block_addr})
        if isinstance(root_condition.block_addr, int)
        else frozenset()
    )
    result = build_from_condition(root_condition, initial_visited)
    if not isinstance(result, CExpression):
        return None
    if any(
        all(consumed is not required for consumed in consumed_conditions)
        for required in required_conditions
    ):
        return None
    _debug_condition_chain_8616(
        "shared-body-expression-built",
        conditions=tuple(
            (
                condition.src_insn,
                condition.op,
                condition.lhs,
                condition.rhs,
                condition.taken_target,
                condition.fallthrough_target,
            )
            for condition in consumed_conditions
        ),
        consumed_sources=tuple(condition.src_insn for condition in consumed_conditions),
        expression_tree=_condition_debug_tree_8616(result),
    )
    lowering = lower_call_output_stack_fields_in_condition_8616(codegen, result, tuple(consumed_conditions))
    try:
        wide_lowering = lower_wide_call_return_condition_chain_8616(
            codegen,
            lowering.expression,
            tuple(consumed_conditions),
        )
    except Exception:
        if os.environ.get("INERTIA_DEBUG_CONDITION_MATERIALIZATION") == "1":
            log.exception("wide call-return condition lowering failed")
        raise
    _debug_condition_chain_8616(
        "shared-body-expression-lowered",
        expression_tree=_condition_debug_tree_8616(wide_lowering.expression),
        lowering_stats=lowering.stats,
        wide_lowering_stats=wide_lowering.stats,
    )
    wide_stats = wide_lowering.stats
    if (
        wide_stats.raw_fact_count != 1
        or wide_stats.normalized_fact_count != 1
        or wide_stats.classified_fact_count != 1
        or wide_stats.materialized_count != 1
        or wide_stats.failure_count != 0
    ):
        _debug_condition_chain_8616(
            "shared-body-wide-proof-refused",
            wide_lowering_stats=wide_stats,
        )
        return None
    return wide_lowering.expression


def _shared_body_target_8616(
    condition_and_nodes: tuple[tuple[object, object], ...],
) -> int | None:
    """Return one exact CFG entry shared by every structured branch body."""
    targets: list[int] = []
    for _condition, body in condition_and_nodes:
        target = _first_tagged_block_addr_8616(body)
        if target is None:
            target = _first_tagged_ins_addr_8616(body)
        if target is None:
            return None
        targets.append(target)
    return targets[0] if targets and all(target == targets[0] for target in targets) else None


def _materialize_cfg_single_branch_expr_8616(
    project: object,
    codegen: object,
    condition: ConditionIR,
    body: object,
    successors: dict[int, tuple[int, ...]],
) -> CExpression | None:
    """Orient one no-else branch from typed targets and exclusive CFG reachability."""
    orientation = _single_branch_body_orientation_8616(condition, body, successors)
    if orientation is None:
        return None
    materialized = materialize_condition_ir_expression_8616(project, codegen, condition)
    if materialized is None:
        return None
    oriented = materialized if orientation else _invert_structured_condition_8616(materialized, codegen)
    lowering = lower_call_output_stack_fields_in_condition_8616(codegen, oriented, (condition,))
    return lowering.expression


def _single_branch_orientation_8616(
    condition: ConditionIR,
    body_target: int,
    successors: dict[int, tuple[int, ...]],
) -> bool | None:
    """Return whether the taken side uniquely owns one structured body."""
    if not isinstance(condition.taken_target, int) or not isinstance(condition.fallthrough_target, int):
        return None
    taken_reaches = _cfg_reaches_address_8616(successors, condition.taken_target, body_target)
    fallthrough_reaches = _cfg_reaches_address_8616(successors, condition.fallthrough_target, body_target)
    if taken_reaches == fallthrough_reaches:
        return None
    return taken_reaches


def _single_branch_body_orientation_8616(
    condition: ConditionIR,
    body: object,
    successors: dict[int, tuple[int, ...]],
) -> bool | None:
    """Return one orientation for the structured body's earliest tagged entry."""
    body_target = _first_tagged_block_addr_8616(body)
    if body_target is None:
        body_target = _first_tagged_ins_addr_8616(body)
    if body_target is None:
        return None
    return _single_branch_orientation_8616(condition, body_target, successors)


def _select_single_branch_condition_8616(
    preferred: ConditionIR | None,
    conditions: tuple[ConditionIR, ...],
    body: object,
    successors: dict[int, tuple[int, ...]],
) -> ConditionIR | None:
    """Preserve a tagged owner, or infer one from exclusive CFG body ownership."""
    if preferred is not None:
        return preferred
    owners = tuple(
        condition
        for condition in conditions
        if _single_branch_body_orientation_8616(condition, body, successors) is not None
    )
    return owners[0] if len(owners) == 1 else None


def materialize_structuring_condition_chains_8616(project: object, codegen: object) -> bool:
    """Materialize CFG-proven branch predicates from target-bearing ConditionIR."""
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    try:
        conditions_value = metadata_codegen._inertia_typed_conditions
        cfunc = cast(_ConditionMaterializationCFunction8616, metadata_codegen.cfunc)
        root = cfunc.statements
    except AttributeError:
        return False
    try:
        conditions = tuple(item for item in cast(Any, conditions_value) if isinstance(item, ConditionIR))
    except TypeError:
        return False
    targeted = tuple(
        item
        for item in conditions
        if isinstance(item.src_insn, int)
        and isinstance(item.block_addr, int)
        and isinstance(item.taken_target, int)
        and isinstance(item.fallthrough_target, int)
    )
    successors = _condition_chain_successors_8616(project, codegen)
    _debug_condition_chain_8616(
        "typed-cfg-surface",
        conditions=tuple(
            (
                item.block_addr,
                item.src_insn,
                item.taken_target,
                item.fallthrough_target,
                item.op,
            )
            for item in targeted
        ),
        successors=tuple(sorted(successors.items())),
    )
    conditions_by_src = {item.src_insn: item for item in targeted}
    conditions_by_block_candidates: dict[int, list[ConditionIR]] = {}
    for item in targeted:
        if isinstance(item.block_addr, int):
            conditions_by_block_candidates.setdefault(item.block_addr, []).append(item)
    conditions_by_block = {
        block_addr: candidates[0]
        for block_addr, candidates in conditions_by_block_candidates.items()
        if len(candidates) == 1
    }
    raw_count = 0
    classified_count = 0
    materialized_count = 0
    failure_count = 0
    changed = False
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse):
            continue
        if len(node.condition_and_nodes) != 1:
            condition_and_nodes = tuple(node.condition_and_nodes)
            keys = tuple(_condition_key_from_tags_8616(condition) for condition, _body in condition_and_nodes)
            source_facts = tuple(
                conditions_by_src.get(key[0]) if key is not None else None
                for key in keys
            )
            _debug_condition_chain_8616(
                "multi-arm-candidate",
                arm_count=len(condition_and_nodes),
                arm_condition_addrs=keys,
                arm_body_addrs=tuple(
                    _first_tagged_ins_addr_8616(arm_body)
                    for _condition, arm_body in condition_and_nodes
                ),
                else_body_addr=_first_tagged_ins_addr_8616(node.else_node),
            )
            if not any(fact is not None for fact in source_facts):
                continue
            raw_count += 1
            exact_facts = tuple(
                fact
                if fact is not None
                and key is not None
                and fact.src_insn == key[0]
                and fact.block_addr == key[1]
                else None
                for key, fact in zip(keys, source_facts, strict=True)
            )
            body_target = _shared_body_target_8616(condition_and_nodes)
            if (
                node.else_node is not None
                or not successors
                or body_target is None
                or any(fact is None for fact in exact_facts)
            ):
                _debug_condition_chain_8616(
                    "multi-arm-proof-refused",
                    body_target=body_target,
                    else_present=node.else_node is not None,
                    exact_fact_count=sum(fact is not None for fact in exact_facts),
                    successor_count=len(successors),
                )
                failure_count += 1
                continue
            proven_facts = cast(tuple[ConditionIR, ...], exact_facts)
            root_fact = proven_facts[0]
            node_ins_addr = _direct_tagged_ins_addr_8616(node)
            if not _structured_node_owns_condition_fact_8616(node_ins_addr, root_fact):
                _debug_condition_chain_8616(
                    "multi-arm-owner-mismatch",
                    fact_block=root_fact.block_addr,
                    fact_src=root_fact.src_insn,
                    node_ins_addr=node_ins_addr,
                )
                failure_count += 1
                continue
            first_condition, first_body = condition_and_nodes[0]
            replacement = _materialize_cfg_shared_body_condition_chain_expr_8616(
                project,
                codegen,
                root_fact,
                proven_facts,
                conditions_by_block,
                successors,
                body_target,
            )
            if replacement is None:
                _debug_condition_chain_8616(
                    "multi-arm-replacement-refused",
                    body_target=body_target,
                    fact_block=root_fact.block_addr,
                    fact_src=root_fact.src_insn,
                )
                failure_count += 1
                continue
            classified_count += 1
            tags = _copied_condition_tags_8616(first_condition)
            if isinstance(root_fact.src_insn, int):
                tags["ins_addr"] = root_fact.src_insn
            if isinstance(root_fact.block_addr, int):
                tags["vex_block_addr"] = root_fact.block_addr
            if isinstance(root_fact.producer_insn, int):
                tags["condition_producer_insn"] = root_fact.producer_insn
            tags["inertia_structuring_condition_cfg_materialized_8616"] = True
            tags["inertia_structuring_shared_body_condition_chain_materialized_8616"] = True
            replacement.tags = tags
            node.condition_and_nodes = [(replacement, first_body)]
            prune_materialized_call_output_stack_carriers_8616(codegen)
            materialized_count += 1
            changed = True
            _debug_condition_chain_8616(
                "multi-arm-materialized",
                body_target=body_target,
                fact_block=root_fact.block_addr,
                fact_src=root_fact.src_insn,
            )
            continue
        condition, body = node.condition_and_nodes[0]
        key = _condition_key_from_tags_8616(condition)
        node_ins_addr = _direct_tagged_ins_addr_8616(node)
        condition_ins_addr = key[0] if key is not None else None
        condition_fact = conditions_by_src.get(condition_ins_addr) if condition_ins_addr is not None else None
        node_fact = conditions_by_src.get(node_ins_addr) if node_ins_addr is not None else None
        node_owner_overrode_condition_origin = False
        if node_fact is not None and node_fact is not condition_fact:
            node_owner_overrode_condition_origin = True
            root_fact = node_fact
            _debug_condition_chain_8616(
                "node-owner-overrode-condition-origin",
                condition_ins_addr=condition_ins_addr,
                fact_block=node_fact.block_addr,
                fact_src=node_fact.src_insn,
                node_ins_addr=node_ins_addr,
            )
        else:
            root_fact = condition_fact or node_fact
        if node.else_node is None:
            tagged_fact = root_fact
            has_tagged_owner = condition_ins_addr is not None or node_ins_addr is not None
            if root_fact is None and not has_tagged_owner:
                root_fact = _select_single_branch_condition_8616(
                    None,
                    targeted,
                    body,
                    successors,
                )
            if root_fact is None and tagged_fact is not None:
                raw_count += 1
                failure_count += 1
                continue
        if root_fact is None:
            _debug_condition_chain_8616(
                "no-root-fact",
                condition_ins_addr=condition_ins_addr,
                node_ins_addr=node_ins_addr,
            )
            continue
        raw_count += 1
        if not _structured_node_owns_condition_fact_8616(node_ins_addr, root_fact):
            _debug_condition_chain_8616(
                "owner-mismatch",
                fact_block=root_fact.block_addr,
                fact_src=root_fact.src_insn,
                node_ins_addr=node_ins_addr,
            )
            failure_count += 1
            continue
        if (
            condition_ins_addr is not None
            and root_fact.src_insn != condition_ins_addr
            and not node_owner_overrode_condition_origin
        ):
            _debug_condition_chain_8616(
                "condition-origin-mismatch",
                condition_ins_addr=condition_ins_addr,
                fact_src=root_fact.src_insn,
            )
            failure_count += 1
            continue
        tags = _copied_condition_tags_8616(condition)
        if not successors:
            _debug_condition_chain_8616("no-successors", fact_src=root_fact.src_insn)
            failure_count += 1
            continue
        if node.else_node is None:
            replacement = _materialize_cfg_single_branch_expr_8616(
                project,
                codegen,
                root_fact,
                body,
                successors,
            )
            marker = "inertia_structuring_single_branch_materialized_8616"
        else:
            true_target = _first_tagged_ins_addr_8616(body)
            false_target = _first_tagged_ins_addr_8616(node.else_node)
            replacement = (
                _materialize_cfg_condition_chain_expr_8616(
                    project,
                    codegen,
                    root_fact,
                    conditions_by_block,
                    successors,
                    true_target,
                    false_target,
                )
                if true_target is not None and false_target is not None
                else None
            )
            marker = "inertia_structuring_condition_chain_materialized_8616"
        if replacement is None:
            _debug_condition_chain_8616(
                "replacement-refused",
                else_present=node.else_node is not None,
                fact_block=root_fact.block_addr,
                fact_src=root_fact.src_insn,
                false_target=(
                    _first_tagged_ins_addr_8616(node.else_node)
                    if node.else_node is not None
                    else None
                ),
                true_target=_first_tagged_ins_addr_8616(body),
            )
            failure_count += 1
            continue
        classified_count += 1
        if (
            tags.get("inertia_structuring_condition_cfg_materialized_8616") is True
            and _same_c_expression_8616(condition, replacement)
        ):
            materialized_count += 1
            continue
        if tags.get("inertia_structuring_condition_cfg_materialized_8616") is True:
            _debug_condition_chain_8616(
                "tagged-condition-drift-rematerialized",
                fact_block=root_fact.block_addr,
                fact_src=root_fact.src_insn,
            )
        if isinstance(root_fact.src_insn, int):
            tags["ins_addr"] = root_fact.src_insn
        if isinstance(root_fact.block_addr, int):
            tags["vex_block_addr"] = root_fact.block_addr
        if isinstance(root_fact.producer_insn, int):
            tags["condition_producer_insn"] = root_fact.producer_insn
        tags["inertia_structuring_condition_cfg_materialized_8616"] = True
        tags[marker] = True
        replacement.tags = tags
        node.condition_and_nodes = [(replacement, body)]
        prune_materialized_call_output_stack_carriers_8616(codegen)
        materialized_count += 1
        changed = True
        _debug_condition_chain_8616(
            "materialized",
            fact_block=root_fact.block_addr,
            fact_src=root_fact.src_insn,
            marker=marker,
        )
    stats = StructuringConditionChainStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
    metadata_codegen._inertia_structuring_condition_chain_stats_8616 = stats
    _debug_condition_chain_8616("stats", stats=stats)
    if classified_count > 0 and materialized_count == 0:
        raise PipelineHardError("classified structuring condition chain was not materialized")
    return changed


def materialize_structuring_conditions_8616(
    project: object,
    codegen: object,
) -> StructuringConditionMaterializationResult8616:
    """Apply already-proven condition facts at the structuring boundary."""
    legacy_project = cast(SimpleNamespace, project)
    legacy_codegen = cast(SimpleNamespace, codegen)
    stage_project = cast(_ConditionMaterializationProject8616, project)
    stage_project._inertia_decompiler_stage = "structuring:condition_materialization:typed"
    typed_changed = bool(_legacy_typed_conditions._apply_typed_conditions_to_codegen_8616(legacy_project, legacy_codegen))
    stage_project._inertia_decompiler_stage = "structuring:condition_materialization:jcc"
    jcc_changed = bool(_legacy_jcc._rewrite_decoded_jcc_conditions_8616(legacy_project, legacy_codegen))
    stage_project._inertia_decompiler_stage = "structuring:condition_materialization:chains"
    chains_changed = materialize_structuring_condition_chains_8616(project, codegen)
    result = StructuringConditionMaterializationResult8616(
        typed_conditions_changed=typed_changed,
        condition_chains_changed=chains_changed,
        decoded_jcc_changed=jcc_changed,
    )
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    metadata_codegen._inertia_condition_materialization_structuring_pass_ran_8616 = True
    metadata_codegen._inertia_structuring_condition_materialization_8616 = {
        "typed_conditions_changed": result.typed_conditions_changed,
        "condition_chains_changed": result.condition_chains_changed,
        "decoded_jcc_changed": result.decoded_jcc_changed,
        "changed": result.changed,
        "owner": "structuring.condition_materialization",
    }
    return result


def apply_structuring_condition_materialization_8616(project: object, codegen: object) -> bool:
    """Compatibility bool-returning entry point for structuring passes."""
    return materialize_structuring_conditions_8616(project, codegen).changed


def cleanup_structuring_conditions_after_replay_8616(
    project: object,
    codegen: object,
) -> StructuringConditionReplayCleanupResult8616:
    """Apply proven condition materialization plus late flag-expression cleanup.

    This is the migration facade for late SeqNode switch replay.  It delegates
    to the historical flag cleanup implementation as a temporary implementation
    detail, but keeps the sequencing and evidence accounting at the
    structuring condition boundary instead of in CLI orchestration.
    """
    materialization = materialize_structuring_conditions_8616(project, codegen)
    legacy_project = cast(SimpleNamespace, project)
    legacy_codegen = cast(SimpleNamespace, codegen)
    flag_condition_pairs_changed = bool(_flags_cleanup._rewrite_flag_condition_pairs_8616(legacy_codegen))
    flag_bit_values_changed = bool(_flags_cleanup._rewrite_flag_bit_value_uses_8616(legacy_codegen))
    interval_guards_changed = bool(_flags_cleanup._fix_interval_guard_conditions_8616(legacy_codegen))
    unused_flag_assignments_pruned = bool(_flags_cleanup._prune_unused_flag_assignments_8616(legacy_project, legacy_codegen))
    overwritten_flag_assignments_pruned = bool(
        _flags_cleanup._prune_overwritten_flag_assignments_8616(legacy_project, legacy_codegen)
    )
    result = StructuringConditionReplayCleanupResult8616(
        materialization=materialization,
        flag_condition_pairs_changed=flag_condition_pairs_changed,
        flag_bit_values_changed=flag_bit_values_changed,
        interval_guards_changed=interval_guards_changed,
        unused_flag_assignments_pruned=unused_flag_assignments_pruned,
        overwritten_flag_assignments_pruned=overwritten_flag_assignments_pruned,
    )
    metadata_codegen = cast(_ConditionMaterializationCodegen8616, codegen)
    metadata_codegen._inertia_structuring_condition_replay_cleanup_8616 = {
        "typed_conditions_changed": materialization.typed_conditions_changed,
        "condition_chains_changed": materialization.condition_chains_changed,
        "decoded_jcc_changed": materialization.decoded_jcc_changed,
        "flag_condition_pairs_changed": result.flag_condition_pairs_changed,
        "flag_bit_values_changed": result.flag_bit_values_changed,
        "interval_guards_changed": result.interval_guards_changed,
        "unused_flag_assignments_pruned": result.unused_flag_assignments_pruned,
        "overwritten_flag_assignments_pruned": result.overwritten_flag_assignments_pruned,
        "changed": result.changed,
        "owner": "structuring.condition_materialization",
    }
    return result


def apply_structuring_condition_replay_cleanup_8616(project: object, codegen: object) -> bool:
    """Compatibility bool-returning entry point for late condition replay."""
    return cleanup_structuring_conditions_after_replay_8616(project, codegen).changed
