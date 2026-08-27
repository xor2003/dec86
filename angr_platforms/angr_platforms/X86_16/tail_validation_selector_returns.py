"""Fingerprint selector-return edge semantics for tail validation.

Layer: Tail Validation.
Responsibility: bind one structured branch condition to its proven true and
false return values so condition polarity cannot change independently of the
selected result. This module validates recovered C AST behavior; it does not
recover or mutate semantics.
Forbidden: source, COD, assembly, sidecar, or rendered-C inference.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CIfElse, CReturn, CStatements

from .c_ast_utils import _iter_c_nodes_deep_8616
from .ir.condition_ir import (
    invert_condition_fingerprint_string_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)

__all__ = [
    "SelectorReturnFingerprintResult8616",
    "SelectorReturnFingerprintStats8616",
    "collect_selector_return_fingerprints_8616",
]

type FingerprintCallback8616 = Callable[[object], str]


@dataclass(frozen=True, slots=True)
class SelectorReturnFingerprintStats8616:
    """Closed evidence counters for selector-return validation fingerprints."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class SelectorReturnFingerprintResult8616:
    """Immutable selector-return fingerprints and their evidence census."""

    fingerprints: tuple[str, ...]
    stats: SelectorReturnFingerprintStats8616


def _terminal_return_fingerprints_8616(
    body: object,
    return_fingerprint: FingerprintCallback8616,
) -> tuple[str, ...]:
    """Fingerprint a non-void return that terminates one structured arm."""
    if isinstance(body, CReturn):
        return () if body.retval is None else (return_fingerprint(body.retval),)
    if not isinstance(body, CStatements):
        return ()
    statements = tuple(body.statements or ())
    if not statements or not isinstance(statements[-1], CReturn):
        return ()
    terminal = statements[-1]
    return () if terminal.retval is None else (return_fingerprint(terminal.retval),)


def _normalize_condition_8616(condition: str) -> str:
    """Canonicalize one condition without changing branch polarity."""
    return str(
        normalize_condition_fingerprint_algebraic_8616(
            normalize_condition_fingerprint_string_8616(condition)
        )
    )


def _selector_return_token_8616(
    condition: str,
    true_returns: tuple[str, ...],
    false_returns: tuple[str, ...],
) -> str:
    """Encode one selector, canonicalizing exact inverse-and-swapped arms."""

    def encode(cond: str, true_values: tuple[str, ...], false_values: tuple[str, ...]) -> str:
        payload = {
            "condition": cond,
            "false_returns": sorted(false_values),
            "true_returns": sorted(true_values),
        }
        return "selector-return:" + json.dumps(payload, sort_keys=True, separators=(",", ":"))

    normalized = _normalize_condition_8616(condition)
    candidates = [encode(normalized, true_returns, false_returns)]
    inverted = invert_condition_fingerprint_string_8616(normalized)
    if inverted is not None:
        candidates.append(encode(_normalize_condition_8616(inverted), false_returns, true_returns))
    return min(candidates)


def collect_selector_return_fingerprints_8616(
    root: object,
    *,
    condition_fingerprint: FingerprintCallback8616,
    return_fingerprint: FingerprintCallback8616,
) -> SelectorReturnFingerprintResult8616:
    """Collect exact two-outcome return selectors from structured statements."""
    raw_count = normalized_count = classified_count = materialized_count = 0
    fingerprints: set[str] = set()
    for parent in _iter_c_nodes_deep_8616(root):
        if not isinstance(parent, CStatements):
            continue
        statements = tuple(parent.statements or ())
        for index, statement in enumerate(statements):
            if not isinstance(statement, CIfElse):
                continue
            raw_count += 1
            pairs = tuple(statement.condition_and_nodes or ())
            if len(pairs) != 1 or len(pairs[0]) != 2:
                continue
            normalized_count += 1
            condition, true_body = pairs[0]
            true_returns = _terminal_return_fingerprints_8616(true_body, return_fingerprint)
            if statement.else_node is not None:
                false_body = statement.else_node
            elif index + 1 < len(statements):
                false_body = statements[index + 1]
            else:
                false_body = None
            false_returns = _terminal_return_fingerprints_8616(false_body, return_fingerprint)
            if not true_returns or not false_returns:
                continue
            classified_count += 1
            fingerprints.add(
                _selector_return_token_8616(
                    condition_fingerprint(condition),
                    true_returns,
                    false_returns,
                )
            )
            materialized_count += 1
    failure_count = max(classified_count - materialized_count, 0)
    return SelectorReturnFingerprintResult8616(
        fingerprints=tuple(sorted(fingerprints)),
        stats=SelectorReturnFingerprintStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
        ),
    )
