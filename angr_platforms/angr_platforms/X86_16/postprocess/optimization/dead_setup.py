"""Layer: Rewrite/Postprocess cleanup.

Responsibility: prune setup/carrier assignments only when typed evidence proves they are dead.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

import enum
import os
import re
import typing
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol, TypeGuard

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CUnaryOp,
    CVariable,
)

from ...callsite_stack_metadata import (
    _callsite_materialization_complete_8616,
)
from ...callsite_stack_metadata import (
    _prune_dead_stack_carrier_assignments_8616 as _prune_dead_stack_carrier_assignments_core_8616,
)
from ...decompiler_postprocess_utils import _iter_c_nodes_deep_8616

__all__ = [
    "DeadSetupDecision8616",
    "_count_dead_setup_escaped_8616",
    "_prune_dead_setup_carriers_8616",
]


_STAGING_NAME_RE = re.compile(r"^(?:vvar_\d+|s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|tmp_\d+|ir_\d+|arg_[0-9a-fA-F]+)$")


@dataclass(frozen=True, slots=True)
class _Candidate:
    stmt_index: int
    key: tuple[str, int | str]
    lhs: CVariable
    rhs: object


class _StatementBlockLike8616(Protocol):
    """Structural view of a dynamic angr/codegen statement block."""

    statements: list[object]


def _is_statement_block_like_8616(node: object) -> TypeGuard[_StatementBlockLike8616]:
    """Return whether a dynamic angr/codegen boundary node has mutable statements."""
    return isinstance(getattr(node, "statements", None), list)


class DeadSetupDecision8616(enum.Enum):
    """Structured pruning decision for a setup/carrier candidate."""

    DEFINITELY_DEAD = "definitely_dead"
    LIVE_CALL_ARG_SETUP = "live_call_arg_setup"
    LIVE_MEMORY_WRITE = "live_memory_write"
    LIVE_CONDITION_SOURCE = "live_condition_source"
    LIVE_STACK_CARRIER = "live_stack_carrier"
    LIVE_WIDENING_CARRIER = "live_widening_carrier"
    UNKNOWN_REFUSE = "unknown_refuse"


class DeadSetupMode8616(enum.Enum):
    """Execution mode for dead setup pruning."""

    DISABLED = "disabled"
    DIAGNOSTIC = "diagnostic"
    PRODUCTION = "production"


def _resolve_dead_setup_mode_8616(codegen: object) -> DeadSetupMode8616:
    """Resolve pruning mode from environment and dynamic codegen compatibility boundary flags."""

    def _impl() -> DeadSetupMode8616:
        """Read mode from dynamic codegen compatibility boundary flags."""
        env_mode = os.environ.get("INERTIA_DEAD_SETUP_PRUNE_MODE", "").strip().lower()
        if env_mode in {"diag", "diagnostic"}:
            return DeadSetupMode8616.DIAGNOSTIC
        if env_mode in {"disabled", "off", "0", "false", "no"}:
            return DeadSetupMode8616.DISABLED
        if env_mode == "production":
            return DeadSetupMode8616.PRODUCTION
        legacy_disable = os.environ.get("INERTIA_DISABLE_DEAD_SETUP_PRUNE", "").strip().lower()
        if legacy_disable in {"1", "true", "yes", "on"}:
            return DeadSetupMode8616.DISABLED

        attr = getattr(codegen, "_inertia_dead_setup_prune_mode", None)
        if isinstance(attr, DeadSetupMode8616):
            return attr
        if isinstance(attr, str):
            normalized = attr.strip().lower()
            if normalized in {"disabled", "off", "0", "false", "no"}:
                return DeadSetupMode8616.DISABLED
            if normalized in {"diagnostic", "diag"}:
                return DeadSetupMode8616.DIAGNOSTIC
            if normalized in {"production", "prod", "on", "1", "true", "yes"}:
                return DeadSetupMode8616.PRODUCTION

        safe_attr = getattr(codegen, "_inertia_enable_safe_dead_setup_prune", None)
        if safe_attr is False:
            return DeadSetupMode8616.DISABLED
        if safe_attr is True:
            return DeadSetupMode8616.PRODUCTION
        # Default to conservative diagnostics-only mode. Production mutation must
        # be explicitly requested via mode/env after evidence gates are green.
        return DeadSetupMode8616.DIAGNOSTIC

    return _impl()


def _setup_counter_defaults(codegen: object) -> None:
    """Initialize dynamic codegen compatibility boundary diagnostic counters."""
    for name in (
        "dead_setup_candidates",
        "dead_setup_pruned",
        "dead_setup_refused",
        "dead_setup_escaped",
        "dead_setup_live_call_arg",
        "dead_setup_live_stack_carrier",
        "dead_setup_live_widening_carrier",
        "dead_setup_live_condition_source",
        "dead_setup_unknown_refuse",
        "dead_setup_prune_disabled",
        "dead_setup_raw_fact_count",
        "dead_setup_normalized_fact_count",
        "dead_setup_classified_fact_count",
        "dead_setup_materialized_count",
        "dead_setup_failure_count",
    ):
        if not isinstance(getattr(codegen, name, None), int):
            setattr(codegen, name, 0)


def _var_name(node: CVariable) -> str:
    """Return a variable name from dynamic angr/codegen boundary CVariable metadata."""
    var = getattr(node, "variable", None)
    name = getattr(var, "name", None)
    if isinstance(name, str) and name:
        return name
    node_name = getattr(node, "name", None)
    if isinstance(node_name, str) and node_name:
        return node_name
    return ""


def _var_key(node: CVariable) -> tuple[str, int | str]:
    """Return a stable key from dynamic angr/codegen boundary CVariable metadata."""
    var = getattr(node, "variable", None)
    if var is not None:
        ident = getattr(var, "ident", None)
        if isinstance(ident, str) and ident:
            return ("ident", ident)
        return ("varid", id(var))
    return ("nodeid", id(node))


def _is_observable_storage(lhs: CVariable) -> bool:
    """Return whether dynamic angr/codegen boundary metadata names observable storage."""
    var = getattr(lhs, "variable", None)
    region = getattr(var, "region", None)
    # Local stack/register carriers are removable when def-use proves dead.
    # Keep globals/args conservative.
    return bool(isinstance(region, str) and region.lower() in {"global", "argument", "arg"})


def _is_candidate_lhs(lhs: object) -> TypeGuard[CVariable]:
    if not isinstance(lhs, CVariable):
        return False
    name = _var_name(lhs)
    return bool(name and _STAGING_NAME_RE.match(name))


def _is_setup_rhs(rhs: object) -> bool:
    """Classify setup expressions across a dynamic angr/codegen C AST boundary."""

    def _impl() -> bool:
        """Inspect setup expressions across a dynamic angr/codegen C AST boundary."""
        if rhs is None:
            return False
        if isinstance(rhs, CUnaryOp) and getattr(rhs, "op", None) in {"Reference", "AddressOf"}:
            return True
        if isinstance(rhs, CBinaryOp):
            op = rhs.op
            if op in {"Add", "Sub"}:
                lhs = rhs.lhs
                r = rhs.rhs
                if isinstance(lhs, CConstant) or isinstance(r, CConstant):
                    return True
                if isinstance(lhs, CVariable) or isinstance(r, CVariable):
                    return True
        # Deep fallback: if expression tree contains address-taking or simple const offset arithmetic.
        for node in _iter_c_nodes_deep_8616(rhs):
            if isinstance(node, CUnaryOp) and getattr(node, "op", None) in {"Reference", "AddressOf"}:
                return True
            if isinstance(node, CBinaryOp) and getattr(node, "op", None) in {"Add", "Sub"}:
                lhs = node.lhs
                r = node.rhs
                if isinstance(lhs, CConstant) or isinstance(r, CConstant):
                    return True
        return False

    return _impl()


def _rhs_has_side_effects(rhs: object) -> bool:
    if rhs is None:
        return False
    return any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(rhs))


def _collect_read_counts(root: object) -> dict[tuple[str, int | str], int]:
    """Count CVariable reads across dynamic angr/codegen boundary statement blocks."""

    def _impl() -> dict[tuple[str, int | str], int]:
        """Traverse dynamic angr/codegen boundary statement blocks for reads."""
        reads: dict[tuple[str, int | str], int] = {}
        # Traverse by statement blocks to avoid double-counting that occurs when
        # walking the full tree and then re-walking each nested node.
        for block in _iter_statement_blocks(root):
            for stmt in list(getattr(block, "statements", ()) or ()):
                if isinstance(stmt, CAssignment):
                    lhs = stmt.lhs
                    rhs = stmt.rhs
                    if isinstance(rhs, CVariable):
                        key = _var_key(rhs)
                        reads[key] = reads.get(key, 0) + 1
                    for rhs_node in _iter_c_nodes_deep_8616(rhs):
                        if isinstance(rhs_node, CVariable):
                            key = _var_key(rhs_node)
                            reads[key] = reads.get(key, 0) + 1
                    # count nested lvalue uses only for address forms, not direct def lhs
                    if isinstance(lhs, CUnaryOp) and getattr(lhs, "op", None) in {"Dereference", "Reference"}:
                        for lhs_node in _iter_c_nodes_deep_8616(lhs):
                            if isinstance(lhs_node, CVariable):
                                key = _var_key(lhs_node)
                                reads[key] = reads.get(key, 0) + 1
                    continue

                for sub in _iter_c_nodes_deep_8616(stmt):
                    if isinstance(sub, CVariable):
                        key = _var_key(sub)
                        reads[key] = reads.get(key, 0) + 1
        return reads

    return _impl()


def _iter_statement_blocks(root: object) -> Iterator[object]:
    """Yield nested statement blocks from a dynamic angr/codegen C AST boundary."""

    def _impl() -> Iterator[object]:
        """Walk nested dynamic angr/codegen C AST boundary nodes."""
        seen: set[int] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            nid = id(node)
            if nid in seen:
                continue
            seen.add(nid)
            if hasattr(node, "statements"):
                yield node
                for stmt in list(getattr(node, "statements", ()) or ()):
                    stack.append(stmt)  # noqa: PERF402
            for attr in (
                "condition",
                "cond",
                "body",
                "else_node",
                "iftrue",
                "iffalse",
                "true_node",
                "false_node",
                "expr",
                "retval",
            ):
                child = getattr(node, attr, None)
                if child is not None:
                    stack.append(child)
            condition_and_nodes = getattr(node, "condition_and_nodes", None)
            if condition_and_nodes:
                for cond, body in condition_and_nodes:
                    stack.append(cond)
                    stack.append(body)
            cases = getattr(node, "cases", None)
            if isinstance(cases, dict):
                for body in cases.values():
                    stack.append(body)  # noqa: PERF402
            default = getattr(node, "default", None)
            if default is not None:
                stack.append(default)

    return _impl()


def _gather_candidates(statements: object) -> list[_Candidate]:
    """Collect setup candidates from a dynamic angr/codegen boundary statement block."""
    stmts: list[object] = list(getattr(statements, "statements", ()) or ())
    out: list[_Candidate] = []
    for idx, stmt in enumerate(stmts):
        if not isinstance(stmt, CAssignment):
            continue
        lhs = stmt.lhs
        rhs = stmt.rhs
        if not _is_candidate_lhs(lhs):
            continue
        if not _is_setup_rhs(rhs):
            continue
        out.append(_Candidate(idx, _var_key(lhs), lhs, rhs))
    return out


def _rhs_mentions_flag_like_state(rhs: object) -> bool:
    for node in _iter_c_nodes_deep_8616(rhs):
        if not isinstance(node, CVariable):
            continue
        name = _var_name(node).lower()
        if name.startswith(("flags", "eflags")):
            return True
    return False


def _rhs_looks_like_stack_carrier(rhs: object) -> bool:
    """Return whether a dynamic angr/codegen boundary RHS looks like a stack carrier."""
    for node in _iter_c_nodes_deep_8616(rhs):
        if not isinstance(node, CVariable):
            continue
        name = _var_name(node)
        if name.startswith(("s_", "arg_")):
            return True
    return False


def _classify_candidate_8616(
    cand: _Candidate,
    reads: dict[tuple[str, int | str], int],
    *,
    call_indices: set[int] | None = None,
) -> DeadSetupDecision8616:
    if _is_observable_storage(cand.lhs):
        return DeadSetupDecision8616.LIVE_CALL_ARG_SETUP
    if call_indices:  # noqa: SIM102
        # Conservative production rule: setup/carrier statements in call-bearing
        # regions can encode outgoing argument staging. Refuse pruning unless
        # we have stronger evidence than local shape/liveness.
        if any(cand.stmt_index <= idx for idx in call_indices):
            return DeadSetupDecision8616.LIVE_CALL_ARG_SETUP
    if _rhs_has_side_effects(cand.rhs):
        return DeadSetupDecision8616.UNKNOWN_REFUSE
    if _rhs_mentions_flag_like_state(cand.rhs):
        return DeadSetupDecision8616.LIVE_CONDITION_SOURCE
    if _rhs_looks_like_stack_carrier(cand.rhs):
        return DeadSetupDecision8616.LIVE_STACK_CARRIER
    if reads.get(cand.key, 0) > 0:
        return DeadSetupDecision8616.UNKNOWN_REFUSE
    return DeadSetupDecision8616.DEFINITELY_DEAD


def _bump_counter_8616(codegen: object, name: str, inc: int = 1) -> None:
    """Increment a dynamic codegen compatibility boundary diagnostic counter."""
    setattr(codegen, name, int(getattr(codegen, name, 0)) + int(inc))


def _record_decision_counter_8616(codegen: object, decision: DeadSetupDecision8616) -> None:
    """Record a pruning decision into dynamic codegen compatibility boundary counters."""
    if decision == DeadSetupDecision8616.LIVE_CALL_ARG_SETUP:
        typing.cast(typing.Any, codegen).dead_setup_live_call_arg = int(getattr(codegen, "dead_setup_live_call_arg", 0)) + 1
    elif decision == DeadSetupDecision8616.LIVE_STACK_CARRIER:
        typing.cast(typing.Any, codegen).dead_setup_live_stack_carrier = int(getattr(codegen, "dead_setup_live_stack_carrier", 0)) + 1
    elif decision == DeadSetupDecision8616.LIVE_WIDENING_CARRIER:
        typing.cast(typing.Any, codegen).dead_setup_live_widening_carrier = int(getattr(codegen, "dead_setup_live_widening_carrier", 0)) + 1
    elif decision == DeadSetupDecision8616.LIVE_CONDITION_SOURCE:
        typing.cast(typing.Any, codegen).dead_setup_live_condition_source = int(getattr(codegen, "dead_setup_live_condition_source", 0)) + 1
    elif decision == DeadSetupDecision8616.UNKNOWN_REFUSE:
        typing.cast(typing.Any, codegen).dead_setup_unknown_refuse = int(getattr(codegen, "dead_setup_unknown_refuse", 0)) + 1


def _prune_dead_setup_carriers_8616(codegen: object) -> bool:
    """Prune dead setup carriers across a dynamic angr/codegen C AST boundary."""

    def _impl() -> bool:
        """Mutate dynamic angr/codegen C AST boundary statement blocks."""
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return False
        statements = getattr(cfunc, "statements", None)
        if statements is None or not hasattr(statements, "statements"):
            return False

        _setup_counter_defaults(codegen)
        mode = _resolve_dead_setup_mode_8616(codegen)
        if mode == DeadSetupMode8616.DISABLED:
            typing.cast(typing.Any, codegen).dead_setup_prune_disabled = int(getattr(codegen, "dead_setup_prune_disabled", 0)) + 1
            return False

        # Evidence gate: never prune until callsite argument materialization is complete
        # when callsite statistics are available.
        if hasattr(codegen, "_inertia_callsite_materialization_stats") and not _callsite_materialization_complete_8616(
            codegen
        ):
            typing.cast(typing.Any, codegen).dead_setup_refused = int(getattr(codegen, "dead_setup_refused", 0)) + 1
            typing.cast(typing.Any, codegen).dead_setup_live_call_arg = int(getattr(codegen, "dead_setup_live_call_arg", 0)) + 1
            return False

        if mode == DeadSetupMode8616.DIAGNOSTIC:
            reads = _collect_read_counts(statements)
            total_candidates = 0
            total_refused = 0
            for block in _iter_statement_blocks(statements):
                candidates = _gather_candidates(block)
                if not candidates:
                    continue
                total_candidates += len(candidates)
                _bump_counter_8616(codegen, "dead_setup_raw_fact_count", len(candidates))
                _bump_counter_8616(codegen, "dead_setup_normalized_fact_count", len(candidates))
                for cand in candidates:
                    try:
                        decision = _classify_candidate_8616(cand, reads, call_indices=None)
                    except Exception:
                        _bump_counter_8616(codegen, "dead_setup_failure_count")
                        decision = DeadSetupDecision8616.UNKNOWN_REFUSE
                    _bump_counter_8616(codegen, "dead_setup_classified_fact_count")
                    if decision != DeadSetupDecision8616.DEFINITELY_DEAD:
                        total_refused += 1
                        _record_decision_counter_8616(codegen, decision)
            if total_candidates:
                _bump_counter_8616(codegen, "dead_setup_candidates", total_candidates)
            if total_refused:
                _bump_counter_8616(codegen, "dead_setup_refused", total_refused)
            return False

        legacy_prune = os.environ.get("INERTIA_ENABLE_LEGACY_DEAD_STACK_CARRIER_PRUNE", "").strip().lower()
        if legacy_prune in {"1", "true", "yes", "on"} and _prune_dead_stack_carrier_assignments_core_8616(
            statements, codegen=codegen
        ):
            return True

        changed = False

        while True:
            reads = _collect_read_counts(statements)
            pass_changed = False
            total_refused = 0
            total_candidates = 0
            total_pruned = 0
            for block in _iter_statement_blocks(statements):
                # Dynamic angr/codegen statement-block boundary.
                stmts: list[object] = list(getattr(block, "statements", ()) or ())
                if not stmts:
                    continue
                call_indices = {
                    idx
                    for idx, stmt in enumerate(stmts)
                    if any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(stmt))
                }
                candidates = _gather_candidates(block)
                if not candidates:
                    continue
                total_candidates += len(candidates)
                _bump_counter_8616(codegen, "dead_setup_raw_fact_count", len(candidates))
                _bump_counter_8616(codegen, "dead_setup_normalized_fact_count", len(candidates))
                to_remove: set[int] = set()
                refused = 0
                for cand in candidates:
                    try:
                        decision = _classify_candidate_8616(cand, reads, call_indices=call_indices)
                    except Exception:
                        _bump_counter_8616(codegen, "dead_setup_failure_count")
                        decision = DeadSetupDecision8616.UNKNOWN_REFUSE
                    _bump_counter_8616(codegen, "dead_setup_classified_fact_count")
                    if decision == DeadSetupDecision8616.DEFINITELY_DEAD:
                        to_remove.add(cand.stmt_index)
                        continue
                    refused += 1
                    _record_decision_counter_8616(codegen, decision)
                total_refused += refused
                if not to_remove:
                    continue
                pruned = 0
                for idx in sorted(to_remove, reverse=True):
                    if 0 <= idx < len(stmts):
                        del stmts[idx]
                        pruned += 1
                        _bump_counter_8616(codegen, "dead_setup_materialized_count")
                if pruned and _is_statement_block_like_8616(block):
                    block.statements = stmts
                    total_pruned += pruned
                    pass_changed = True

            if total_candidates:
                typing.cast(typing.Any, codegen).dead_setup_candidates = int(getattr(codegen, "dead_setup_candidates", 0)) + total_candidates
            if total_refused:
                typing.cast(typing.Any, codegen).dead_setup_refused = int(getattr(codegen, "dead_setup_refused", 0)) + total_refused
            if total_pruned:
                typing.cast(typing.Any, codegen).dead_setup_pruned = int(getattr(codegen, "dead_setup_pruned", 0)) + total_pruned
                changed = True
            if not pass_changed:
                break

        return changed

    return _impl()


def _count_dead_setup_escaped_8616(codegen: object) -> int:
    """Count escaped setup carriers across a dynamic angr/codegen C AST boundary."""

    def _impl() -> int:
        """Inspect dynamic angr/codegen C AST boundary statement blocks."""
        mode = _resolve_dead_setup_mode_8616(codegen)
        if mode != DeadSetupMode8616.PRODUCTION:
            return 0
        if hasattr(codegen, "_inertia_callsite_materialization_stats") and not _callsite_materialization_complete_8616(
            codegen
        ):
            return 0
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return 0
        statements = getattr(cfunc, "statements", None)
        if statements is None:
            return 0
        # Count only true escapes: assignments classified as DEFINITELY_DEAD by the
        # current evidence pipeline are considered escaped if they are still present
        # after all passes.
        reads = _collect_read_counts(statements)
        escaped: set[str] = set()
        for block in _iter_statement_blocks(statements):
            stmts = list(getattr(block, "statements", ()) or ())
            if not stmts:
                continue
            call_indices = {
                idx
                for idx, stmt in enumerate(stmts)
                if any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(stmt))
            }
            for cand in _gather_candidates(block):
                decision = _classify_candidate_8616(cand, reads, call_indices=call_indices)
                if decision != DeadSetupDecision8616.DEFINITELY_DEAD:
                    continue
                name = _var_name(cand.lhs)
                if name:
                    escaped.add(name)
        return len(escaped)

    return _impl()
