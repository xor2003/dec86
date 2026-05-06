from __future__ import annotations

# Layer: Lowering
# Responsibility: canonical stack/local lowering from typed alias evidence.
# Forbidden: rendered-text parsing and CLI guessing.

from collections.abc import Callable

from .stack_lowering_impl import (
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _materialize_stack_cvar_at_offset,
    _resolve_stack_cvar_at_offset,
    _resolve_stack_cvar_from_addr_expr,
)
from .stack_lowering_result import (
    StackLoweringResult,
    StackSlotFailure,
    materialization_diagnostics_8616,
)
from .real_mode_linear import (
    lower_stable_ss_linear_stack_dereferences_8616,
    lower_stable_ds_es_linear_global_dereferences_8616,
)
from .stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from ..stack_probe_fact_trace import (
    record_stable_ss_lowering_refusal_8616,
    record_stable_ss_lowering_replacement_8616,
)


def run_stack_lowering_pass_8616(
    *,
    rewrite_ss_stack_byte_offsets: Callable[[], bool],
    canonicalize_stack_cvars: Callable[[], bool],
    lower_stable_ss_stack_accesses: Callable[[], bool] | None = None,
    codegen=None,
    project=None,
    typed_stack_probe_return_facts: dict[int, TypedStackProbeReturnFact8616] | None = None,
    max_rounds: int = 2,
) -> bool:
    if codegen is not None:
        codegen._inertia_typed_stack_probe_return_facts = (
            build_typed_stack_probe_return_facts_8616(codegen)
            if typed_stack_probe_return_facts is None
            else typed_stack_probe_return_facts
        )
        codegen._inertia_ss_lowering_refusal_log = []
    typed_fact_count = len(getattr(codegen, "_inertia_typed_stack_probe_return_facts", {}) or {}) if codegen is not None else 0
    changed = False
    for _ in range(max(max_rounds, 1)):
        round_changed = False
        # ── Legacy SS linear lowering ──
        # This path does (seg << 4) + offset arithmetic — forbidden by AGENTS.md
        # rule "never flatten memory".  Disabled in normal path; kept behind
        # debug flag for emergency compatibility testing.
        if codegen is not None and getattr(codegen, "_inertia_allow_legacy_ss_linear_lowering", False):
            if lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project):
                record_stable_ss_lowering_replacement_8616(codegen)
        if codegen is not None and lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project):
            record_stable_ss_lowering_replacement_8616(codegen)
            round_changed = True
        if lower_stable_ss_stack_accesses is not None:
            lowered = lower_stable_ss_stack_accesses()
            if lowered:
                if codegen is not None:
                    record_stable_ss_lowering_replacement_8616(codegen)
                round_changed = True
            elif codegen is not None and typed_fact_count > 0:
                record_stable_ss_lowering_refusal_8616(codegen)
        if rewrite_ss_stack_byte_offsets():
            round_changed = True
        if canonicalize_stack_cvars():
            round_changed = True
        if not round_changed:
            break
        changed = True
    # Diagnostic: dump refusal log
    if codegen is not None:
        refusal_log = getattr(codegen, "_inertia_ss_lowering_refusal_log", None)
        if isinstance(refusal_log, list) and refusal_log:
            if not hasattr(codegen, "_inertia_ss_lowering_refusal_summary"):
                codegen._inertia_ss_lowering_refusal_summary = []
            codegen._inertia_ss_lowering_refusal_summary.extend(refusal_log)
    return changed


__all__ = (
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_materialize_stack_cvar_at_offset",
    "_resolve_stack_cvar_at_offset",
    "_resolve_stack_cvar_from_addr_expr",
    "TypedStackProbeReturnFact8616",
    "build_typed_stack_probe_return_facts_8616",
    "run_stack_lowering_pass_8616",
)
