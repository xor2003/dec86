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

import logging
import os

from ..condition_trace import record_classified_conditions_trace_8616
from ..ir.condition_ir import (
    JCC_TO_COND_8616,
    ConditionEdgeEvidence,
    ConditionIR,
    ConditionSource,
    build_condition_from_cmp_8616,
    build_condition_from_test_8616,
    deduplicate_conditions_8616,
)

log = logging.getLogger(__name__)

_INVERTED_JCC_MNEMONICS_8616: dict[str, str] = {
    "je": "jne",
    "jz": "jnz",
    "jne": "je",
    "jnz": "jz",
    "jb": "jae",
    "jnae": "jae",
    "jc": "jnc",
    "jae": "jb",
    "jnb": "jb",
    "jnc": "jc",
    "jbe": "ja",
    "jna": "ja",
    "ja": "jbe",
    "jnbe": "jbe",
    "jl": "jge",
    "jnge": "jge",
    "jge": "jl",
    "jnl": "jl",
    "jle": "jg",
    "jng": "jg",
    "jg": "jle",
    "jnle": "jle",
}


def _relift_blocks_for_condition_cache_8616(project: object, block_addrs: list[int]) -> None:
    factory = getattr(project, "factory", None) if project is not None else None
    block_lifter = getattr(factory, "block", None)
    if not callable(block_lifter):
        return
    for block_addr in block_addrs:
        try:
            block_lifter(block_addr, opt_level=0)
        except TypeError:
            try:
                block_lifter(block_addr)
            except Exception:
                continue
        except Exception:
            continue


def _decode_first_insn_at_addr_8616(project: object, addr: int) -> object | None:
    factory = getattr(project, "factory", None) if project is not None else None
    block_lifter = getattr(factory, "block", None)
    if not callable(block_lifter):
        return None

    block = None
    for kwargs in ({"num_inst": 1, "opt_level": 0}, {"size": 2, "opt_level": 0}, {"opt_level": 0}, {}):
        try:
            block = block_lifter(addr, **kwargs)
            break
        except TypeError:
            continue
        except Exception:
            return None
    if block is None:
        return None
    insns = tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())
    if not insns:
        return None
    return insns[0]


def _condition_from_pending_source_8616(
    source: ConditionSource,
    jcc_mnemonic: str,
    *,
    src_insn: int,
    block_addr: int,
) -> ConditionIR | None:
    if source.kind == "cmp":
        if source.lhs is None or source.rhs is None:
            return None
        cond = build_condition_from_cmp_8616(
            source.lhs,
            source.rhs,
            jcc_mnemonic,
            width_bits=source.width_bits,
            src_insn=src_insn,
            block_addr=block_addr,
            producer_insn=source.addr,
        )
    elif source.kind == "test":
        if source.lhs is None:
            return None
        cond = build_condition_from_test_8616(
            source.lhs,
            jcc_mnemonic,
            width_bits=source.width_bits,
            src_insn=src_insn,
            block_addr=block_addr,
            producer_insn=source.addr,
        )
    else:
        return None
    return cond if isinstance(cond, ConditionIR) else None


def _edge_evidence_from_pending_source_8616(
    source: ConditionSource,
    mnemonic: str | None,
    *,
    edge_block_addr: int,
) -> ConditionEdgeEvidence | None:
    if mnemonic not in {"jmp", "jmpw"}:
        return None
    source_jcc = str(getattr(source, "fallthrough_from_jcc", "") or "").lower()
    inverted_jcc = _INVERTED_JCC_MNEMONICS_8616.get(source_jcc)
    if inverted_jcc is None:
        return None
    condition = _condition_from_pending_source_8616(source, inverted_jcc, src_insn=edge_block_addr, block_addr=edge_block_addr)
    if condition is None:
        return None
    return ConditionEdgeEvidence(
        edge_block_addr=edge_block_addr,
        condition=condition,
        edge_kind="fallthrough_jmp",
        source_jcc=source_jcc,
        producer_insn=source.addr,
    )


def _collect_pending_fallthrough_conditions_8616(
    project: object,
    block_addrs: list[int],
    pending_sources: dict[int, ConditionSource],
) -> tuple[list[ConditionIR], list[ConditionEdgeEvidence]]:
    """Materialize cached fallthrough JCC facts missed by block lift order.

    The lifter owns operand recovery and records ConditionSource objects.  This
    bridge only proves that a pending function block begins with a supported JCC
    instruction, then converts that already-typed source into ConditionIR.
    """
    block_addr_set = set(block_addrs)
    conditions: list[ConditionIR] = []
    edge_evidence: list[ConditionEdgeEvidence] = []
    processed: set[int] = set()
    while True:
        candidates = sorted(
            addr
            for addr, source in pending_sources.items()
            if addr in block_addr_set and addr not in processed and isinstance(source, ConditionSource)
        )
        if not candidates:
            break
        for addr in candidates:
            processed.add(addr)
            source = pending_sources.get(addr)
            if not isinstance(source, ConditionSource):
                pending_sources.pop(addr, None)
                continue
            insn = _decode_first_insn_at_addr_8616(project, addr)
            mnemonic = str(getattr(insn, "mnemonic", "") or "").strip().lower() if insn is not None else None
            pending_sources.pop(addr, None)
            if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                log.warning(
                    "[condition-transfer] pending_decode addr=%#x mnemonic=%r source_kind=%s",
                    addr,
                    mnemonic,
                    source.kind,
                )
            if mnemonic not in JCC_TO_COND_8616:
                edge = _edge_evidence_from_pending_source_8616(source, mnemonic, edge_block_addr=addr)
                if edge is not None:
                    edge_evidence.append(edge)
                    if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                        log.warning(
                            "[condition-transfer] edge pending src_insn=%#x block=%#x op=%s source_jcc=%s lhs=%r rhs=%r",
                            addr,
                            edge.edge_block_addr,
                            edge.condition.op,
                            edge.source_jcc,
                            edge.condition.lhs,
                            edge.condition.rhs,
                        )
                continue
            cond = _condition_from_pending_source_8616(source, mnemonic, src_insn=addr, block_addr=addr)
            if isinstance(cond, ConditionIR):
                conditions.append(cond)
                if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                    log.warning(
                        "[condition-transfer] cond pending src_insn=%#x block=%#x op=%s source=%s lhs=%r rhs=%r",
                        addr,
                        addr,
                        cond.op,
                        cond.source,
                        cond.lhs,
                        cond.rhs,
                    )
    return conditions, edge_evidence


def _collect_typed_condition_artifacts_8616(
    project,
    func_addr: int,
) -> tuple[list[ConditionIR], list[ConditionEdgeEvidence]]:
    def _impl():
        """Collect ConditionIR objects from the module-level cache in lift_86_16.

        During lifting, _record_typed_condition_8616() writes ConditionIR objects
        into Instruction_ANY._inertia_module_condition_cache (keyed by block address).
        This function reads from that cache instead of re-lifting.

        Returns a deduplicated, deterministically sorted list of ConditionIR.
        """
        kb = getattr(project, "kb", None) if project is not None else None
        if kb is None:
            return [], []

        func = kb.functions.function(addr=func_addr, create=False)
        if func is None:
            return [], []

        block_addrs = sorted(getattr(func, "block_addrs_set", set()) or set())
        if not block_addrs:
            return [], []

        # Read from the module-level cache populated during the initial lift
        try:
            from ..lift_86_16 import Instruction_ANY

            module_cache = Instruction_ANY._inertia_module_condition_cache
            pending_sources = Instruction_ANY._inertia_pending_condition_sources_by_addr
        except Exception as ex:
            import logging

            logging.getLogger(__name__).warning(
                "condition transfer import failed: %s: %s",
                type(ex).__name__,
                ex,
            )
            module_cache = {}
            pending_sources = {}

        if not any(isinstance(module_cache.get(block_addr, None), list) for block_addr in block_addrs):
            _relift_blocks_for_condition_cache_8616(project, block_addrs)
        if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
            cache_keys = tuple(sorted(k for k in module_cache.keys() if isinstance(k, int)))
            pending_keys = tuple(sorted(k for k in pending_sources.keys() if isinstance(k, int)))
            log.warning(
                "[condition-transfer] func=%#x blocks=%s cache_keys=%s pending_keys=%s",
                func_addr,
                tuple(hex(a) for a in block_addrs),
                tuple(hex(a) for a in cache_keys),
                tuple(hex(a) for a in pending_keys),
            )

        all_conditions: list[ConditionIR] = []
        edge_evidence: list[ConditionEdgeEvidence] = []
        for block_addr in block_addrs:
            block_conds = module_cache.get(block_addr, None)
            if isinstance(block_conds, list):
                for cond in block_conds:
                    if isinstance(cond, ConditionIR):
                        all_conditions.append(cond)
                        if os.environ.get("INERTIA_DEBUG_CONDITION_TRANSFER"):
                            log.warning(
                                "[condition-transfer] cond cache_block=%#x src_insn=%r block=%r op=%s source=%s lhs=%r rhs=%r",
                                block_addr,
                                cond.src_insn,
                                cond.block_addr,
                                cond.op,
                                cond.source,
                                cond.lhs,
                                cond.rhs,
                        )

        if isinstance(pending_sources, dict):
            pending_conditions, pending_edges = _collect_pending_fallthrough_conditions_8616(
                project, block_addrs, pending_sources
            )
            all_conditions.extend(pending_conditions)
            edge_evidence.extend(pending_edges)

        return deduplicate_conditions_8616(all_conditions), edge_evidence

    return _impl()


def collect_typed_conditions_from_emulator_8616(
    project,
    func_addr: int,
) -> list[ConditionIR]:
    """Collect ConditionIR objects from the module-level lifter cache."""
    conditions, _edge_evidence = _collect_typed_condition_artifacts_8616(project, func_addr)
    return conditions


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

    conditions, edge_evidence = _collect_typed_condition_artifacts_8616(project, func_addr)
    codegen._inertia_typed_conditions = conditions
    codegen._inertia_condition_facts = conditions  # compatibility alias
    codegen._inertia_condition_edge_evidence = edge_evidence
    record_classified_conditions_trace_8616(project, codegen, conditions)

    # ── Initialize CONDITION lane contract ──
    # classified is filled by consumers once a fact is matched to an AST guard.
    # Transfer owns raw/normalized evidence only; claiming classification here
    # would hard-fail functions whose conditions are collected but not yet
    # consumed by a materializer.
    # materialized = 0 (filled by postprocess typed conditions pass)
    codegen._inertia_condition_lane = SemanticLaneState(
        name="condition",
        raw=len(conditions),  # raw facts = all ConditionIR from lifting
        normalized=len(conditions),
        classified=0,
        bound=0,
        materialized=0,
        verified=0,
        failures=0,
    )

    return len(conditions)
