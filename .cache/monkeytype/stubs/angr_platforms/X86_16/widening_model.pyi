from angr.analyses.decompiler.structured_codegen.c import CVariable
from typing import Optional


def _register_version_for_expr(expr: object, state: AliasState | None) -> int | None: ...


def analyze_adjacent_storage_slices(
    low_expr: CVariable,
    high_expr: CVariable,
    *,
    alias_state: <class 'Union'>['AliasState | None', None] = ...
) -> StorageJoinAnalysis: ...


def can_join_adjacent_storage_slices(
    low_expr: <class 'Union'>[angr.analyses.decompiler.structured_codegen.c.CVariable, angr.analyses.decompiler.structured_codegen.c.CBinaryOp],
    high_expr: <class 'Union'>[angr.analyses.decompiler.structured_codegen.c.CVariable, angr.analyses.decompiler.structured_codegen.c.CBinaryOp],
    *,
    alias_state: <class 'Union'>['AliasState | None', None] = ...
) -> bool: ...


def merge_storage_slice_domains(
    low_expr: CVariable,
    high_expr: CVariable
) -> _StorageDomainSignature: ...


def prove_adjacent_storage_slices(
    low_expr: <class 'Union'>[angr.analyses.decompiler.structured_codegen.c.CVariable, angr.analyses.decompiler.structured_codegen.c.CBinaryOp],
    high_expr: <class 'Union'>[angr.analyses.decompiler.structured_codegen.c.CVariable, angr.analyses.decompiler.structured_codegen.c.CBinaryOp],
    *,
    alias_state: <class 'Union'>['AliasState | None', None] = ...
) -> WideningProof: ...


class StorageJoinAnalysis:
    def compatible_view(self) -> bool: ...
    @property
    def left(self) -> AliasStorageFacts: ...
    @property
    def ok(self) -> bool: ...
    @property
    def reason(self) -> str: ...
    @property
    def right(self) -> AliasStorageFacts: ...
    def same_domain(self) -> bool: ...


class WideningCandidate:
    @classmethod
    def from_expr(cls, expr: object) -> 'WideningCandidate': ...
    def is_joinable_with(self, other: 'WideningCandidate') -> bool: ...
