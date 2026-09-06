"""Connect direct local Alias input construction to persisted raw IR/SSA.

Layer: CLI/fallback/reporting orchestration.
Responsibility: hydrate exact function IR/SSA before the owning Alias builder
runs, then persist any newly built pair without classifying semantic facts.
"""

from __future__ import annotations

from angr_platforms.X86_16.alias.indexed_address_program import (
    IndexedAliasProgramEvidence8616,
    build_indexed_alias_program_evidence_8616,
)

from . import indexed_alias_program_parallel as _alias_program_parallel
from .function_ir_ssa_cache import (
    hydrate_function_ir_ssa_catalog_8616,
    store_function_ir_ssa_catalog_8616,
)


def build_cached_direct_indexed_alias_local_evidence_8616(
    project: object,
    function: object,
) -> IndexedAliasProgramEvidence8616:
    """Build local Alias evidence after exact IR/SSA hydration and persistence."""
    functions = (function,)
    hydrated = hydrate_function_ir_ssa_catalog_8616(project, functions)
    if not hydrated.stats.closed:
        raise RuntimeError("direct function IR/SSA cache hydration accounting is not closed")
    selection = _alias_program_parallel.indexed_alias_function_selection_8616(
        function
    )
    local_program = build_indexed_alias_program_evidence_8616(
        project,
        (selection,),
    )
    stored = store_function_ir_ssa_catalog_8616(
        project,
        functions,
        already_hydrated=hydrated,
    )
    if not stored.stats.closed:
        raise RuntimeError("direct function IR/SSA cache store accounting is not closed")
    return local_program


__all__ = ["build_cached_direct_indexed_alias_local_evidence_8616"]

