from __future__ import annotations

# Layer: Lowering (bridge)
# Responsibility: transfer typed conditions from the emulator to codegen.
# Input: ConditionIR from IR lifting
# Output: materialized C condition nodes (CBinaryOp/CUnaryOp in C AST)
# Forbidden:
# - semantic recovery
# - text-pattern semantics
# - generated-C inspection
# - regex recovery
# - rewrite-only fixes
# Contract:
# classified_count > 0 requires materialized_count > 0
#
# During lifting, _emit_simple_jcc() records ConditionIR objects onto
# self.emu._inertia_typed_conditions.  This module collects those records
# and transfers them to codegen before the invariant gate runs.

__all__ = [
    "transfer_typed_conditions_to_codegen_8616",
    "collect_typed_conditions_from_emulator_8616",
    "transfer_typed_conditions_from_emulator_8616",
]

from ..ir.condition_ir import (
    ConditionIR,
    ConditionFailure,
    deduplicate_conditions_8616,
)


def collect_typed_conditions_from_emulator_8616(
    project,
    func_addr: int,
) -> list[ConditionIR]:
    """Collect ConditionIR objects from the module-level cache in lift_86_16.

    During lifting, _record_typed_condition_8616() writes ConditionIR objects
    into Instruction_ANY._inertia_module_condition_cache (keyed by block address).
    This function reads from that cache instead of re-lifting.

    Returns a deduplicated, deterministically sorted list of ConditionIR.
    """
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is None:
        return []

    func = kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return []

    block_addrs = sorted(getattr(func, "block_addrs_set", set()) or set())
    if not block_addrs:
        return []

    # Read from the module-level cache populated during the initial lift
    try:
        from ..lift_86_16 import Instruction_ANY
        module_cache = Instruction_ANY._inertia_module_condition_cache
    except Exception:
        module_cache = {}

    all_conditions: list[ConditionIR] = []
    for block_addr in block_addrs:
        block_conds = module_cache.get(block_addr, None)
        if isinstance(block_conds, list):
            for cond in block_conds:
                if isinstance(cond, ConditionIR):
                    all_conditions.append(cond)

    return deduplicate_conditions_8616(all_conditions)


def transfer_typed_conditions_from_emulator_8616(
    instructions: list,
    codegen,
) -> int:
    """Transfer typed conditions from lifted instruction emulators to codegen.

    After block lifting, each instruction's emulator may have
    _inertia_typed_conditions recorded.  This function aggregates them
    and sets codegen._inertia_typed_conditions.

    Returns the number of ConditionIR objects transferred.
    """
    all_conditions: list[ConditionIR] = []
    for instr in instructions:
        emu = getattr(instr, "emu", None)
        if emu is not None:
            conds = getattr(emu, "_inertia_typed_conditions", None)
            if isinstance(conds, list):
                for cond in conds:
                    if isinstance(cond, ConditionIR):
                        all_conditions.append(cond)

    unique = deduplicate_conditions_8616(all_conditions)
    codegen._inertia_typed_conditions = unique
    codegen._inertia_condition_facts = unique  # compatibility alias
    return len(unique)


def transfer_typed_conditions_to_codegen_8616(
    project,
    func_addr: int,
    codegen,
) -> int:
    """Full pipeline: collect conditions by re-lifting, then transfer to codegen.

    Sets:
        codegen._inertia_typed_conditions
        codegen._inertia_condition_facts
        codegen._inertia_condition_lane (SemanticLaneState for CONDITION lane)

    Returns the number of ConditionIR objects transferred.
    """
    from ..pipeline.contracts import SemanticLaneState

    conditions = collect_typed_conditions_from_emulator_8616(project, func_addr)
    codegen._inertia_typed_conditions = conditions
    codegen._inertia_condition_facts = conditions  # compatibility alias

    # ── Initialize CONDITION lane contract ──
    # classified = number of ConditionIR facts
    # bound = 0 (no equivalent of StackVariableBinding for conditions yet)
    # materialized = 0 (filled by postprocess typed conditions pass)
    codegen._inertia_condition_lane = SemanticLaneState(
        name="condition",
        raw=len(conditions),       # raw facts = all ConditionIR from lifting
        normalized=len(conditions),
        classified=len(conditions),
        bound=0,
        materialized=0,
        verified=0,
        failures=0,
    )

    return len(conditions)
