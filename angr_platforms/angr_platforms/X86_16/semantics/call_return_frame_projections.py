"""Publish exact value-producer projections of CALL return-frame stores.

Layer: Semantics. Responsibility: derive store-to-producer relationships from
VEX data dependencies under exact CALL IMarks. Producers remain projections,
never stores. C/AIL shape, values, names, text, and address dependencies are out.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeGuard, cast

from ..pipeline.errors import PipelineHardError

type DynamicValue = Any


@dataclass(frozen=True, slots=True, order=True)
class CallReturnFrameEffectKey8616:
    """Stable identity of one statement under one exact decoded CALL IMark."""

    callsite_addr: int
    vex_block_addr: int
    vex_stmt_idx: int


class CallReturnFrameProjectionRole8616(StrEnum):
    """Semantic role of one structured projection of a machine frame store."""

    STORE_STATEMENT = "store_statement"
    VALUE_PRODUCER = "value_producer"


class CallReturnFrameProjectionRefusalReason8616(StrEnum):
    """Typed reason that producer ancestry was unsafe to publish."""

    IMARK_NOT_EXACT = "imark_not_exact"
    STORE_NOT_EXACT = "store_not_exact"
    INCOMPLETE_DEPENDENCY = "incomplete_dependency"
    AMBIGUOUS_DEFINITION = "ambiguous_definition"
    CYCLIC_DEPENDENCY = "cyclic_dependency"
    CROSS_CALLSITE_DEPENDENCY = "cross_callsite_dependency"
    SHARED_PRODUCER = "shared_producer"


_Reason8616 = CallReturnFrameProjectionRefusalReason8616
_Role8616 = CallReturnFrameProjectionRole8616


@dataclass(frozen=True, slots=True)
class CallReturnFrameProjectionFact8616:
    """Exact relationship from a machine store to one surviving projection."""

    store_key: CallReturnFrameEffectKey8616
    projection_key: CallReturnFrameEffectKey8616
    role: CallReturnFrameProjectionRole8616


@dataclass(frozen=True, slots=True)
class CallReturnFrameProjectionRefusal8616:
    """One store ancestry refusal with every implicated producer statement."""

    store_key: CallReturnFrameEffectKey8616
    reason: CallReturnFrameProjectionRefusalReason8616
    producer_keys: tuple[CallReturnFrameEffectKey8616, ...]


@dataclass(frozen=True, slots=True)
class CallReturnFrameProjectionCollection8616:
    """Closed Semantics census for exact CALL-frame store projections."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    projections: tuple[CallReturnFrameProjectionFact8616, ...]
    refusals: tuple[CallReturnFrameProjectionRefusal8616, ...]

    @property
    def closed(self) -> bool:
        """Return whether all store ancestries and published facts are counted."""
        return (
            0 <= self.normalized_fact_count <= self.raw_fact_count
            and self.normalized_fact_count + self.failure_count == self.raw_fact_count
            and self.classified_fact_count == len(self.projections)
            and self.materialized_count == self.classified_fact_count
        )


@dataclass(frozen=True, slots=True)
class _DependencyResult8616:
    producers: tuple[int, ...]
    reason: _Reason8616 | None
    implicated: tuple[int, ...]


class _DependencyRefusal8616(Exception):
    def __init__(
        self,
        reason: _Reason8616,
        indices: Iterable[int] = (),
    ) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.indices = tuple(sorted(set(indices)))


def _is_int_8616(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _inventory_8616(
    statements: tuple[DynamicValue, ...],
) -> tuple[tuple[int | None, ...], dict[int, tuple[int, ...]], dict[int, int]]:
    owners: list[int | None] = []
    definitions: dict[int, list[int]] = {}
    imark_counts: dict[int, int] = {}
    owner: int | None = None
    for index, statement in enumerate(statements):
        try:
            tag = statement.tag
        except AttributeError:
            owners.append(owner)
            continue
        if tag == "Ist_IMark":
            try:
                address = statement.addr
            except AttributeError:
                address = None
            owner = address if _is_int_8616(address) else None
            if owner is not None:
                imark_counts[owner] = imark_counts.get(owner, 0) + 1
        owners.append(owner)
        if tag == "Ist_WrTmp":
            try:
                temporary = statement.tmp
            except AttributeError:
                temporary = None
            if _is_int_8616(temporary):
                definitions.setdefault(temporary, []).append(index)
    return tuple(owners), {tmp: tuple(indices) for tmp, indices in definitions.items()}, imark_counts


def _dependencies_8616(
    statements: tuple[DynamicValue, ...],
    owners: tuple[int | None, ...],
    definitions: dict[int, tuple[int, ...]],
    *,
    callsite_addr: int,
    store_index: int,
) -> _DependencyResult8616:
    producers: set[int] = set()
    visiting: list[int] = []

    def refuse(
        reason: _Reason8616,
        indices: Iterable[int] = (),
    ) -> None:
        raise _DependencyRefusal8616(reason, indices)

    def visit(expression_value: object, consumer_index: int) -> None:
        expression = cast(DynamicValue, expression_value)
        try:
            tag = expression.tag
        except AttributeError:
            refuse(_Reason8616.INCOMPLETE_DEPENDENCY, visiting)
        if tag == "Iex_RdTmp":
            try:
                temporary = expression.tmp
            except AttributeError:
                temporary = None
            if not _is_int_8616(temporary):
                refuse(_Reason8616.INCOMPLETE_DEPENDENCY, visiting)
            indices = definitions.get(temporary, ())
            if not indices:
                refuse(_Reason8616.INCOMPLETE_DEPENDENCY, visiting)
            if len(indices) != 1:
                refuse(_Reason8616.AMBIGUOUS_DEFINITION, indices)
            producer_index = indices[0]
            if owners[producer_index] != callsite_addr:
                refuse(_Reason8616.CROSS_CALLSITE_DEPENDENCY, indices)
            if producer_index in visiting:
                start = visiting.index(producer_index)
                refuse(
                    _Reason8616.CYCLIC_DEPENDENCY,
                    (*visiting[start:], producer_index),
                )
            try:
                producer_data = statements[producer_index].data
            except (AttributeError, IndexError):
                refuse(_Reason8616.INCOMPLETE_DEPENDENCY, indices)
            producers.add(producer_index)
            visiting.append(producer_index)
            visit(producer_data, producer_index)
            visiting.pop()
            if producer_index >= consumer_index:
                refuse(_Reason8616.INCOMPLETE_DEPENDENCY, indices)
            return
        try:
            children = tuple(expression.child_expressions)
        except (AttributeError, TypeError):
            refuse(_Reason8616.INCOMPLETE_DEPENDENCY, visiting)
        for child in children:
            visit(child, consumer_index)

    try:
        visit(statements[store_index].data, store_index)
    except (AttributeError, IndexError):
        return _DependencyResult8616((), _Reason8616.INCOMPLETE_DEPENDENCY, (store_index,))
    except _DependencyRefusal8616 as refusal:
        return _DependencyResult8616((), refusal.reason, refusal.indices)
    return _DependencyResult8616(tuple(sorted(producers)), None, ())


def _finalize_8616(
    raw_count: int,
    normalized_count: int,
    projections: Iterable[CallReturnFrameProjectionFact8616],
    refusals: Iterable[CallReturnFrameProjectionRefusal8616],
) -> CallReturnFrameProjectionCollection8616:
    facts = tuple(
        sorted(
            projections,
            key=lambda fact: (
                fact.store_key,
                fact.role is _Role8616.VALUE_PRODUCER,
                fact.projection_key,
            ),
        )
    )
    refused = tuple(sorted(refusals, key=lambda item: (item.store_key, item.reason.value, item.producer_keys)))
    result = CallReturnFrameProjectionCollection8616(
        raw_count,
        normalized_count,
        len(facts),
        len(facts),
        max(raw_count - normalized_count, 0),
        facts,
        refused,
    )
    if not result.closed or (result.classified_fact_count > 0 and result.materialized_count == 0):
        raise PipelineHardError("CALL-frame Semantics projection evidence did not close")
    return result


def collect_call_return_frame_store_projections_8616(
    vex: object,
    *,
    callsite_addr: int,
    vex_block_addr: int,
    store_statement_indices: Iterable[int],
) -> CallReturnFrameProjectionCollection8616:
    """Publish exact data-producer projections for stores under one CALL IMark."""
    try:
        statements = tuple(cast(DynamicValue, vex).statements or ())
    except (AttributeError, TypeError):
        statements = ()
    store_indices = tuple(sorted({index for index in store_statement_indices if _is_int_8616(index)}))
    owners, definitions, imark_counts = _inventory_8616(statements)
    self_facts: list[CallReturnFrameProjectionFact8616] = []
    dependencies: dict[int, _DependencyResult8616] = {}
    refusals: list[CallReturnFrameProjectionRefusal8616] = []
    for store_index in store_indices:
        store_key = CallReturnFrameEffectKey8616(callsite_addr, vex_block_addr, store_index)
        reason: _Reason8616 | None = None
        if imark_counts.get(callsite_addr, 0) != 1:
            reason = _Reason8616.IMARK_NOT_EXACT
        elif not 0 <= store_index < len(statements):
            reason = _Reason8616.STORE_NOT_EXACT
        else:
            try:
                exact_store = statements[store_index].tag == "Ist_Store" and owners[store_index] == callsite_addr
            except AttributeError:
                exact_store = False
            if not exact_store:
                reason = _Reason8616.STORE_NOT_EXACT
        if reason is not None:
            refusals.append(CallReturnFrameProjectionRefusal8616(store_key, reason, ()))
            continue
        self_facts.append(
            CallReturnFrameProjectionFact8616(
                store_key,
                store_key,
                _Role8616.STORE_STATEMENT,
            )
        )
        dependencies[store_index] = _dependencies_8616(
            statements,
            owners,
            definitions,
            callsite_addr=callsite_addr,
            store_index=store_index,
        )

    stores_by_producer: dict[int, set[int]] = {}
    for store_index, dependency in dependencies.items():
        if dependency.reason is None:
            for producer_index in dependency.producers:
                stores_by_producer.setdefault(producer_index, set()).add(store_index)
    shared_by_store: dict[int, set[int]] = {}
    for producer_index, stores in stores_by_producer.items():
        if len(stores) > 1:
            for store_index in stores:
                shared_by_store.setdefault(store_index, set()).add(producer_index)

    producer_facts: list[CallReturnFrameProjectionFact8616] = []
    normalized_count = 0
    for store_index, dependency in sorted(dependencies.items()):
        store_key = CallReturnFrameEffectKey8616(callsite_addr, vex_block_addr, store_index)
        reason = dependency.reason
        implicated = dependency.implicated
        if reason is None and store_index in shared_by_store:
            reason = _Reason8616.SHARED_PRODUCER
            implicated = tuple(sorted(shared_by_store[store_index]))
        if reason is not None:
            refusals.append(
                CallReturnFrameProjectionRefusal8616(
                    store_key,
                    reason,
                    tuple(
                        CallReturnFrameEffectKey8616(
                            cast(int, owners[index]) if owners[index] is not None else callsite_addr,
                            vex_block_addr,
                            index,
                        )
                        for index in implicated
                    ),
                )
            )
            continue
        normalized_count += 1
        producer_facts.extend(
            CallReturnFrameProjectionFact8616(
                store_key,
                CallReturnFrameEffectKey8616(callsite_addr, vex_block_addr, producer_index),
                _Role8616.VALUE_PRODUCER,
            )
            for producer_index in dependency.producers
        )
    return _finalize_8616(
        len(store_indices),
        normalized_count,
        (*self_facts, *producer_facts),
        refusals,
    )
