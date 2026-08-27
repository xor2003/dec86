"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c

from .cli_access_object_hints import AccessTraitObjectHint, BaseKey
from .cli_storage_objects import (
    EvidenceProfiles,
    build_storage_object_artifact,
    storage_object_record_for_key,
)

type StableHints = dict[BaseKey, AccessTraitObjectHint]
type ReplaceCChildren = Callable[[object, Callable[[object], object]], bool]


class _CFunctionLike(Protocol):
    """C function shape needed by this legacy CLI cleanup helper."""

    addr: int
    statements: object


class _CodegenLike(Protocol):
    """Structured codegen shape needed by this legacy CLI cleanup helper."""

    cfunc: _CFunctionLike | None


def _coalesce_cod_word_global_loads(
    project: object,
    codegen: _CodegenLike,
    synthetic_globals: object,
    *,
    collect_access_traits: Callable[[object, _CodegenLike], object],
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
    global_load_addr: Callable[[object, object], int | None],
    match_scaled_high_byte: Callable[[object, object], int | None],
    synthetic_word_global_variable: Callable[
        [_CodegenLike, object, int, dict[int, structured_c.CVariable]], structured_c.CVariable | None
    ],
    replace_c_children: ReplaceCChildren,
) -> bool:
    cfunc = codegen.cfunc
    if not synthetic_globals or cfunc is None:
        return False

    # dynamic angr boundary: access traits are attached to Project by earlier passes.
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict) or cfunc.addr not in traits_cache:
        collect_access_traits(project, codegen)
        # dynamic angr boundary: collect_access_traits refreshes the Project cache.
        traits_cache = getattr(project, "_inertia_access_traits", None)

    storage_object_artifact = None
    if isinstance(traits_cache, dict):
        traits = traits_cache.get(cfunc.addr)
        if isinstance(traits, dict):
            storage_object_artifact = build_storage_object_artifact(
                traits,
                build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
                build_stable_access_object_hints=build_stable_access_object_hints,
            )

    created: dict[int, structured_c.CVariable] = {}

    def transform(node: object) -> object:
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr = global_load_addr(low_expr, project)
            if low_addr is None:
                continue

            if storage_object_artifact is not None:
                record = storage_object_record_for_key(storage_object_artifact, ("mem", low_addr))
                if record is not None and record.object_kind == "member":
                    continue

            cvar = synthetic_word_global_variable(codegen, synthetic_globals, low_addr, created)
            if cvar is None:
                continue

            high_addr = match_scaled_high_byte(high_expr, project)
            if high_addr != low_addr + 1:
                continue

            return cvar

        return node

    root = cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if replace_c_children(root, transform):
        changed = True
    return changed
