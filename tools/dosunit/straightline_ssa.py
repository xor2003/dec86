from __future__ import annotations

from collections import defaultdict
import copy
from dataclasses import dataclass
import hashlib
import os
import pickle
import re
from pathlib import Path
from typing import Any

from tools.dosunit.ir_edges import _load_lifter_project
from tools.dosunit.model import DosUnitError, normalize_hex, parse_int, stable_id


REG_BY_OFFSET = {
    0: ("ax", 16),
    2: ("cx", 16),
    4: ("dx", 16),
    6: ("bx", 16),
    8: ("sp", 16),
    10: ("bp", 16),
    12: ("si", 16),
    14: ("di", 16),
    16: ("ip", 16),
    18: ("flags", 16),
    20: ("cs", 16),
    22: ("ds", 16),
    24: ("es", 16),
    30: ("ss", 16),
}
RAW_OUTPUT_REGS = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")
ABI_OUTPUT_REGS = {
    "msc16-near": ("ax", "dx", "sp"),
    "raw-all": RAW_OUTPUT_REGS,
}
DEFAULT_ABI = "msc16-near"
DEFAULT_OUTPUT_REGS = ABI_OUTPUT_REGS[DEFAULT_ABI]
SUPPORTED_SOURCE_IRS = {"vex", "ail"}
LIFTER_CACHE_SCHEMA = "dosunit.lifter_cache.v2"
CALL_TARGET_PREVIEW_INSTRUCTION_LIMIT = 4
CONTROL_MNEMONICS = {
    "call",
    "lcall",
    "int",
    "jmp",
    "ljmp",
    "jo",
    "jno",
    "jb",
    "jnae",
    "jc",
    "jnb",
    "jae",
    "jnc",
    "je",
    "jz",
    "jne",
    "jnz",
    "jbe",
    "jna",
    "ja",
    "jnbe",
    "js",
    "jns",
    "jp",
    "jpe",
    "jnp",
    "jpo",
    "jl",
    "jnge",
    "jge",
    "jnl",
    "jle",
    "jng",
    "jg",
    "jnle",
    "jcxz",
    "loop",
    "loope",
    "loopne",
    "loopz",
    "loopnz",
}
CONDITIONAL_JUMP_MNEMONICS = CONTROL_MNEMONICS - {"call", "lcall", "int", "jmp", "ljmp"}
SUPPORTED_BINOPS = {
    "Add": "add",
    "Sub": "sub",
    "Mul": "mul",
    "MullU": "umull",
    "MullS": "smull",
    "DivU": "udiv",
    "DivS": "sdiv",
    "Mod": "urem",
    "ModU": "urem",
    "ModS": "srem",
    "And": "and",
    "Or": "or",
    "Xor": "xor",
    "Shl": "shl",
    "Shr": "lshr",
    "Sar": "ashr",
    "CmpEQ": "eq",
    "CmpNE": "ne",
    "CmpLTU": "ult",
    "CmpLEU": "ule",
    "CmpGTU": "ugt",
    "CmpGEU": "uge",
    "CmpLTS": "slt",
    "CmpLES": "sle",
    "CmpGTS": "sgt",
    "CmpGES": "sge",
}


@dataclass(frozen=True)
class SsaExpr:
    op: str
    width: int
    args: tuple["SsaExpr", ...] = ()
    value: int | None = None
    name: str | None = None

    def key(self) -> tuple[Any, ...]:
        return (self.op, self.width, self.value, self.name, tuple(arg.key() for arg in self.args))


@dataclass(frozen=True)
class LowerFailure(Exception):
    reason: str
    message: str


@dataclass(frozen=True)
class LiftedBlock:
    irsb: Any
    instructions: list[dict[str, Any]]
    lifted: bool


def lower_straightline_ssa_document(
    *,
    exe_path: Path,
    functions_catalog: dict[str, Any],
    output_regs: tuple[str, ...] = DEFAULT_OUTPUT_REGS,
    source_ir: str = "vex",
    max_blocks_per_function: int = 8,
    max_insns_per_function: int = 24,
    max_assignments_per_function: int = 512,
    scan_limit: int = 0x100,
    cache_dir: Path | None = None,
) -> dict[str, Any]:
    if source_ir not in SUPPORTED_SOURCE_IRS:
        raise DosUnitError(f"unsupported SSA source IR: {source_ir}")
    functions = list(functions_catalog.get("functions", []) or [])
    project = _load_lifter_project(exe_path)
    linked_base = int(getattr(project.loader.main_object, "linked_base", 0))
    exe_digest = _file_sha256(exe_path)
    cache_document = _load_vex_cache(cache_dir=cache_dir, exe_digest=exe_digest) if cache_dir is not None else None
    cache_stats = {"hits": 0, "misses": 0, "writes": 0, "errors": 0}
    lowered: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    counters = {
        "functions_seen": len(functions),
        "functions_attempted": 0,
        "functions_lowered": 0,
        "functions_refused": 0,
        "ssa_parts_lowered": 0,
        "ssa_parts_refused": 0,
        "lifter_blocks_lifted": 0,
        "lifter_cache_hits": 0,
        "lifter_cache_misses": 0,
        "lifter_cache_writes": 0,
        "lifter_cache_errors": 0,
        "assignments_emitted": 0,
        "refusals_by_reason": {},
    }

    for function in functions:
        counters["functions_attempted"] += 1
        results, function_refusals, blocks_lifted = _lower_function(
            project=project,
            linked_base=linked_base,
            exe_path=exe_path,
            exe_digest=exe_digest,
            cache_document=cache_document,
            cache_stats=cache_stats,
            function=function,
            output_regs=output_regs,
            source_ir=source_ir,
            max_blocks_per_function=max_blocks_per_function,
            max_insns_per_function=max_insns_per_function,
            max_assignments_per_function=max_assignments_per_function,
            scan_limit=scan_limit,
        )
        counters["lifter_blocks_lifted"] += blocks_lifted
        if not results:
            counters["functions_refused"] += 1
            if function_refusals:
                refusals.extend(function_refusals)
            else:
                refusals.append(_refusal(function, "unsupported_ir", "lowering failed without detail"))
        else:
            counters["functions_lowered"] += 1
            lowered.extend(results)
            counters["ssa_parts_lowered"] += len(results)
            counters["assignments_emitted"] += sum(len(result.get("assignments", []) or []) for result in results)
            if function_refusals:
                refusals.extend(function_refusals)
        counters["ssa_parts_refused"] += len(function_refusals)

    if cache_dir is not None and cache_document is not None and cache_document.pop("_dirty", False):
        try:
            _save_vex_cache(cache_dir=cache_dir, exe_digest=exe_digest, cache_document=cache_document)
        except Exception:  # noqa: BLE001
            cache_stats["errors"] += 1

    counters["lifter_cache_hits"] = cache_stats["hits"]
    counters["lifter_cache_misses"] = cache_stats["misses"]
    counters["lifter_cache_writes"] = cache_stats["writes"]
    counters["lifter_cache_errors"] = cache_stats["errors"]
    counters["refusals_by_reason"] = _refusal_counts(refusals)
    document_without_id = {
        "schema": "dosunit.ssa.v1",
        "exe": str(exe_path),
        "source_ir": source_ir,
        "module": str(functions_catalog.get("module", exe_path.name)),
        "parameters": {
            "output_regs": list(output_regs),
            "source_ir": source_ir,
            "max_blocks_per_function": max_blocks_per_function,
            "max_insns_per_function": max_insns_per_function,
            "max_assignments_per_function": max_assignments_per_function,
            "scan_limit": scan_limit,
            "cache_dir": None if cache_dir is None else str(cache_dir),
        },
        "functions": lowered,
        "refusals": refusals,
        "counters": counters,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("ssa", document_without_id)
    return document


def compare_ssa_documents(
    *,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    mapping_document: dict[str, Any] | None = None,
    include_unmapped: bool = True,
    timeout_ms: int = 60000,
    max_solver_assignments: int = 128,
    max_solver_inputs: int = 16,
    max_solver_memory_stores: int = 15,
    skip_binary_equal: bool = True,
    allow_aliased_call_targets: bool = True,
) -> dict[str, Any]:
    oracle_functions = list(oracle.get("functions", []) or [])
    candidate_functions = list(candidate.get("functions", []) or [])
    candidate_by_key = _functions_by_name_and_part(list(candidate.get("functions", []) or []))
    candidate_by_id = _functions_by_id_and_part(list(candidate.get("functions", []) or []))
    candidate_by_key_delta = _functions_by_name_and_delta(list(candidate.get("functions", []) or []))
    candidate_by_id_delta = _functions_by_id_and_delta(list(candidate.get("functions", []) or []))
    mapped_candidates = _ssa_candidate_mapping(mapping_document) if mapping_document is not None else {}
    oracle_index = _ssa_function_index(oracle_functions)
    candidate_index = _ssa_function_index(candidate_functions)
    ordinals: dict[str, int] = defaultdict(int)
    results: list[dict[str, Any]] = []
    solver_time_ms = 0
    skipped_unmapped = 0
    for oracle_function in oracle_functions:
        function = oracle_function.get("function", {}) if isinstance(oracle_function, dict) else {}
        function_id = str(function.get("id", ""))
        function_name = str(function.get("name", function_id))
        mapped: dict[str, Any] | None = None
        if mapping_document is not None:
            mapped = mapped_candidates.get(function_id) or mapped_candidates.get(function_name)
            if mapped is None:
                skipped_unmapped += 1
                if not include_unmapped:
                    continue
                candidate_function = None
            else:
                part_index = _ssa_part_index(oracle_function)
                part_delta = _ssa_part_delta(oracle_function)
                candidate_function = None
                if part_delta:
                    candidate_function = candidate_by_id_delta.get((str(mapped.get("candidate_id")), part_delta))
                if candidate_function is None:
                    candidate_function = candidate_by_id.get((str(mapped.get("candidate_id")), part_index))
                if candidate_function is None:
                    candidate_name = str(mapped.get("candidate_name", ""))
                    if part_delta:
                        candidate_function = candidate_by_key_delta.get((candidate_name, part_delta))
                    if candidate_function is None:
                        candidate_function = candidate_by_key.get((candidate_name, part_index))
        else:
            function_key = function_name or function_id
            part_index = _ssa_part_index(oracle_function)
            part_delta = _ssa_part_delta(oracle_function)
            candidate_function = None
            if part_delta:
                candidate_function = candidate_by_key_delta.get((function_key, part_delta))
            if candidate_function is None:
                candidate_function = candidate_by_key.get((function_key, part_index))
            if candidate_function is None:
                ordinal = ordinals[function_key]
                ordinals[function_key] += 1
                candidate_function = candidate_by_key.get((function_key, ordinal))
        if candidate_function is None:
            missing_reason = "mapping_missing" if mapped is None else "candidate_ssa_missing"
            missing_detail = (
                "no candidate mapping for oracle SSA function"
                if mapped is None
                else "mapping exists but candidate function was not lowered to SSA"
            )
            results.append(
                {
                    "status": "refused",
                    "reason": missing_reason,
                    "function": {"id": function_id, "name": function_name},
                    "oracle_function": oracle_function.get("id"),
                    "candidate_function": None,
                    "mapped_candidate": _mapped_candidate_detail(mapped),
                    "oracle_detail": _ssa_function_report_detail(oracle_function),
                    "candidate_detail": None,
                    "mismatches": [{"kind": "function_missing", "detail": missing_detail}],
                }
            )
            continue
        call_compare = _compare_call_targets(
            oracle_function,
            candidate_function,
            mapping_document=mapping_document,
            oracle_index=oracle_index,
            candidate_index=candidate_index,
            allow_aliased_call_targets=allow_aliased_call_targets,
        )
        oracle_for_z3, candidate_for_z3, call_compare = _prepare_call_normalized_functions(
            oracle_function,
            candidate_function,
            call_compare=call_compare,
        )
        oracle_for_z3, candidate_for_z3, layout_normalization = _prepare_layout_normalized_functions(
            oracle_for_z3,
            candidate_for_z3,
        )
        quick = _quick_compare_functions(oracle_for_z3, candidate_for_z3, skip_binary_equal=skip_binary_equal)
        if quick is not None:
            results.append(
                {
                    "status": quick["status"],
                    "reason": quick.get("reason"),
                    "function": {"id": function_id, "name": function_name},
                    "oracle_function": oracle_function.get("id"),
                    "candidate_function": candidate_function.get("id"),
                    "mapped_candidate": _mapped_candidate_detail(mapped),
                    "oracle_detail": _ssa_function_report_detail(oracle_function),
                    "candidate_detail": _ssa_function_report_detail(candidate_function),
                    "call_compare": call_compare,
                    "layout_normalization": layout_normalization,
                    "mismatches": quick.get("mismatches", []),
                }
            )
            continue
        gate = _ssa_solver_gate(
            oracle_for_z3,
            candidate_for_z3,
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
        )
        if gate is not None:
            results.append(
                {
                    "status": "refused",
                    "reason": gate["reason"],
                    "function": {"id": function_id, "name": function_name},
                    "oracle_function": oracle_function.get("id"),
                    "candidate_function": candidate_function.get("id"),
                    "mapped_candidate": _mapped_candidate_detail(mapped),
                    "oracle_detail": _ssa_function_report_detail(oracle_function),
                    "candidate_detail": _ssa_function_report_detail(candidate_function),
                    "call_compare": call_compare,
                    "layout_normalization": layout_normalization,
                    "mismatches": [gate],
                }
            )
            continue
        comparison = _compare_functions(oracle_for_z3, candidate_for_z3, timeout_ms=timeout_ms)
        solver_time_ms += int(comparison.pop("solver_time_ms", 0))
        results.append(
            {
                "status": comparison["status"],
                "reason": comparison.get("reason"),
                "function": {"id": function_id, "name": function_name},
                "oracle_function": oracle_function.get("id"),
                "candidate_function": candidate_function.get("id"),
                "mapped_candidate": _mapped_candidate_detail(mapped),
                "oracle_detail": _ssa_function_report_detail(oracle_function),
                "candidate_detail": _ssa_function_report_detail(candidate_function),
                "call_compare": call_compare,
                "layout_normalization": layout_normalization,
                "mismatches": comparison.get("mismatches", []),
            }
        )

    summary = {
        "total": len(results),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "refused": sum(1 for result in results if result.get("status") == "refused"),
        "skipped_unmapped": skipped_unmapped,
        "solver_time_ms": solver_time_ms,
    }
    document_without_id = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": oracle.get("exe"),
        "candidate": candidate.get("exe"),
        "mapping": None if mapping_document is None else mapping_document.get("id"),
        "include_unmapped": include_unmapped,
        "alias_call_targets": allow_aliased_call_targets,
        "solver_gates": {
            "max_solver_assignments": max_solver_assignments,
            "max_solver_inputs": max_solver_inputs,
            "max_solver_memory_stores": max_solver_memory_stores,
        },
        "skip_binary_equal": skip_binary_equal,
        "summary": summary,
        "results": results,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("ssa-compare", document_without_id)
    return document


def compare_ssa_abi_documents(
    *,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    abi_manifest: dict[str, Any],
    mapping_document: dict[str, Any] | None = None,
    timeout_ms: int = 60000,
    max_solver_assignments: int = 512,
    max_solver_inputs: int = 32,
    max_solver_memory_stores: int = 32,
) -> dict[str, Any]:
    oracle_groups = _ssa_function_groups(list(oracle.get("functions", []) or []))
    candidate_groups = _ssa_function_groups(list(candidate.get("functions", []) or []))
    mapped_candidates = _ssa_candidate_mapping(mapping_document) if mapping_document is not None else {}
    data_segment_para = _abi_data_segment_para(abi_manifest)
    results: list[dict[str, Any]] = []
    solver_time_ms = 0

    for abi_function in _abi_functions(abi_manifest):
        function_name = str(abi_function.get("name") or "")
        oracle_group = _ssa_group_for_abi_function(oracle_groups, abi_function, side="oracle")
        mapped = mapped_candidates.get(str(abi_function.get("id") or "")) or mapped_candidates.get(function_name)
        candidate_group = _ssa_group_for_abi_function(candidate_groups, abi_function, side="candidate", mapped=mapped)
        observables = _abi_observables(abi_function)
        base_result = {
            "function": {
                "name": function_name,
                "kind": abi_function.get("kind"),
                "calling_convention": abi_function.get("calling_convention"),
                "inputs": abi_function.get("inputs", []),
                "stack_args": abi_function.get("stack_args", []),
                "returns": abi_function.get("returns", []),
                "preserved": abi_function.get("preserved", []),
                "clobbers": abi_function.get("clobbers", []),
                "effects": abi_function.get("effects", []),
            },
            "mapped_candidate": _mapped_candidate_detail(mapped),
            "observables": observables,
        }
        if not oracle_group or not candidate_group:
            missing = "oracle" if not oracle_group else "candidate"
            results.append(
                {
                    **base_result,
                    "status": "refused",
                    "reason": "function_missing",
                    "mismatches": [{"kind": "function_missing", "side": missing}],
                }
            )
            continue
        if not observables["regs"] and not observables["memory"]:
            results.append(
                {
                    **base_result,
                    "status": "refused",
                    "reason": "no_declared_observables",
                    "mismatches": [{"kind": "no_declared_observables"}],
                }
            )
            continue
        oracle_summary = _summarize_abi_function(oracle_group, abi_function=abi_function, observables=observables, data_segment_para=data_segment_para)
        candidate_summary = _summarize_abi_function(candidate_group, abi_function=abi_function, observables=observables, data_segment_para=data_segment_para)
        if oracle_summary.get("status") != "passed" or candidate_summary.get("status") != "passed":
            side = "oracle" if oracle_summary.get("status") != "passed" else "candidate"
            summary = oracle_summary if side == "oracle" else candidate_summary
            results.append(
                {
                    **base_result,
                    "status": "refused",
                    "reason": summary.get("reason", "unsupported_ir"),
                    "side": side,
                    "oracle_summary": _summary_detail(oracle_summary),
                    "candidate_summary": _summary_detail(candidate_summary),
                    "mismatches": summary.get("mismatches", []),
                }
            )
            continue
        gate = _ssa_solver_gate(
            oracle_summary["function"],
            candidate_summary["function"],
            max_solver_assignments=max_solver_assignments,
            max_solver_inputs=max_solver_inputs,
            max_solver_memory_stores=max_solver_memory_stores,
        )
        if gate is not None:
            results.append(
                {
                    **base_result,
                    "status": "refused",
                    "reason": gate["reason"],
                    "oracle_summary": _summary_detail(oracle_summary),
                    "candidate_summary": _summary_detail(candidate_summary),
                    "mismatches": [gate],
                }
            )
            continue
        comparison = _compare_functions(oracle_summary["function"], candidate_summary["function"], timeout_ms=timeout_ms)
        solver_time_ms += int(comparison.pop("solver_time_ms", 0))
        results.append(
            {
                **base_result,
                "status": comparison["status"],
                "reason": comparison.get("reason"),
                "oracle_summary": _summary_detail(oracle_summary),
                "candidate_summary": _summary_detail(candidate_summary),
                "mismatches": comparison.get("mismatches", []),
            }
        )

    summary = {
        "total": len(results),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "refused": sum(1 for result in results if result.get("status") == "refused"),
        "solver_time_ms": solver_time_ms,
    }
    document_without_id = {
        "schema": "dosunit.ssa_abi_compare.v1",
        "oracle": oracle.get("exe"),
        "candidate": candidate.get("exe"),
        "mapping": None if mapping_document is None else mapping_document.get("id"),
        "abi_manifest": abi_manifest.get("schema"),
        "data_segment_para": normalize_hex(data_segment_para, width=4),
        "solver_gates": {
            "max_solver_assignments": max_solver_assignments,
            "max_solver_inputs": max_solver_inputs,
            "max_solver_memory_stores": max_solver_memory_stores,
        },
        "summary": summary,
        "results": results,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("ssa-abi-compare", document_without_id)
    return document


def _lower_function(
    *,
    project: Any,
    linked_base: int,
    exe_path: Path,
    exe_digest: str,
    cache_document: dict[str, Any] | None,
    cache_stats: dict[str, int],
    function: dict[str, Any],
    output_regs: tuple[str, ...],
    source_ir: str,
    max_blocks_per_function: int,
    max_insns_per_function: int,
    max_assignments_per_function: int,
    scan_limit: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    function_id = str(function.get("id", "<unknown>"))
    names = function.get("names", []) if isinstance(function.get("names"), list) else []
    function_name = str(names[0]) if names else function_id
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        return [], [_refusal(function, "unsupported_ir", "function entry is missing")], 0
    try:
        segment_para = parse_int(entry.get("segment_para"), field="function.entry.segment_para")
        entry_ip = parse_int(entry.get("offset"), field="function.entry.offset")
    except DosUnitError as ex:
        return [], [_refusal(function, "unsupported_ir", str(ex))], 0
    function_base = linked_base + (segment_para << 4)
    start = function_base + entry_ip
    size = function.get("size")
    limit = int(size) if isinstance(size, int) and size > 0 else scan_limit
    limit = max(1, min(limit, scan_limit))
    end = start + limit
    function_machine_code = _loader_bytes(project, start, limit)
    pending = [start]
    seen: set[int] = set()
    lowered_parts: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    blocks_lifted = 0

    while pending and len(seen) < max_blocks_per_function:
        at = pending.pop(0)
        if at < start or at >= end or at in seen:
            continue
        seen.add(at)
        try:
            lifted = _lift_vex_block_cached(
                project=project,
                exe_path=exe_path,
                exe_digest=exe_digest,
                start=at,
                size=max(1, min(limit, end - at)),
                opt_level=0,
                cache_document=cache_document,
                cache_stats=cache_stats,
            )
            irsb = lifted.irsb
        except Exception as ex:  # noqa: BLE001
            refusals.append(_refusal(function, "unsupported_ir", f"lifter block failed at {normalize_hex(at)}: {type(ex).__name__}: {ex}"))
            continue
        blocks_lifted += int(lifted.lifted)

        instructions = [_instruction_text_from_record(record, function_base=function_base) for record in lifted.instructions if start <= parse_int(record.get("linear", 0), field="instruction.linear") < end]
        if not instructions:
            refusals.append(_refusal(function, "unsupported_ir", f"lifter produced no instructions at {normalize_hex(at)}"))
            continue
        if len(instructions) > max_insns_per_function:
            refusals.append(_refusal(function, "unsupported_ir", f"instruction limit reached at {normalize_hex(at)}: {len(instructions)} > {max_insns_per_function}"))
            continue
        if _is_incomplete_noncontrol_block(irsb, instructions):
            last = instructions[-1]
            refusals.append(_refusal(function, "incomplete_block", f"lifter stopped before a control transfer at {last.get('address', {}).get('linear')}: {last.get('disassembly')}"))
            continue

        if source_ir == "vex":
            lowered = _lower_irsb(irsb, output_regs=output_regs, max_assignments_per_function=max_assignments_per_function)
        elif source_ir == "ail":
            try:
                ail_block = _vex_irsb_to_ail_block(project=project, irsb=irsb)
            except Exception as ex:  # noqa: BLE001
                refusals.append(_refusal(function, "unsupported_ir", f"AIL conversion failed at {normalize_hex(at)}: {type(ex).__name__}: {ex}"))
                continue
            lowered = _lower_ail_block(ail_block, output_regs=output_regs, max_assignments_per_function=max_assignments_per_function)
        else:
            refusals.append(_refusal(function, "unsupported_ir", f"unsupported SSA source IR: {source_ir}"))
            continue
        if isinstance(lowered, LowerFailure):
            refusals.append(_refusal(function, lowered.reason, f"{lowered.message} at {normalize_hex(at)}"))
            continue

        part_index = len(lowered_parts)
        body_without_id = {
            "function": {"id": function_id, "name": function_name},
            "part": {
                "kind": "block",
                "index": part_index,
                "entry_delta": normalize_hex((at - start) & 0xFFFF, width=4),
            },
            "function_entry": {
                "cs": normalize_hex(segment_para, width=4),
                "ip": normalize_hex(entry_ip, width=4),
                "linear": normalize_hex(start),
            },
            "entry": {
                "cs": normalize_hex(segment_para, width=4),
                "ip": normalize_hex((at - function_base) & 0xFFFF, width=4),
                "linear": normalize_hex(at),
            },
            "source": {
                "ir": source_ir,
                "jumpkind": str(irsb.jumpkind),
                "instruction_count": len(instructions),
                "instructions": instructions,
                "function_machine_code_sha256": _bytes_sha256(function_machine_code),
                "function_machine_code_size": len(function_machine_code) if function_machine_code is not None else None,
                "machine_code_sha256": _machine_code_sha256(instructions),
                "machine_code_size": _machine_code_size(instructions),
                "transfer": _transfer_info(irsb, instructions),
            },
            **lowered,
        }
        body = dict(body_without_id)
        body["id"] = stable_id("ssa-function", body_without_id)
        lowered_parts.append(body)

        for successor in _ssa_block_successors(irsb, instructions):
            if start <= successor < end and successor not in seen and successor not in pending:
                pending.append(successor)

    if pending and len(seen) >= max_blocks_per_function:
        refusals.append(_refusal(function, "unsupported_ir", f"block limit reached: {max_blocks_per_function}"))
    if not lowered_parts and not refusals:
        refusals.append(_refusal(function, "unsupported_ir", "no SSA blocks lowered"))
    return lowered_parts, refusals, blocks_lifted


def _lower_irsb(irsb: Any, *, output_regs: tuple[str, ...], max_assignments_per_function: int) -> dict[str, Any] | LowerFailure:
    temp_defs: dict[int, SsaExpr] = {}
    temp_failures: dict[int, LowerFailure] = {}
    reg_versions: dict[str, SsaExpr] = {name: SsaExpr("input", width, name=name) for _offset, (name, width) in REG_BY_OFFSET.items()}
    mem_version = SsaExpr("mem_input", 0, name="mem")
    memory_touched = False
    exits: list[tuple[SsaExpr, SsaExpr]] = []

    for statement in irsb.statements:
        tag = statement.tag
        if tag == "Ist_IMark":
            continue
        if tag == "Ist_WrTmp":
            expr = _lower_expr(statement.data, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=irsb.tyenv, memory=mem_version)
            if isinstance(expr, LowerFailure):
                temp_failures[int(statement.tmp)] = expr
            else:
                temp_defs[int(statement.tmp)] = expr
            continue
        if tag == "Ist_Put":
            if _is_unobserved_flags_write(int(statement.offset), output_regs):
                continue
            expr = _lower_expr(statement.data, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=irsb.tyenv, memory=mem_version)
            if isinstance(expr, LowerFailure):
                access = _register_write_target(int(statement.offset), None)
                if access is None:
                    return LowerFailure("unsupported_ir", f"unsupported VEX register offset {statement.offset}")
                reg_versions[access[0]] = SsaExpr("unsupported", access[1], name=f"{expr.reason}|{expr.message}")
                continue
            failure = _write_register(reg_versions, int(statement.offset), expr)
            if failure is not None:
                return failure
            continue
        if tag == "Ist_Store":
            addr = _lower_expr(statement.addr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=irsb.tyenv, memory=mem_version)
            if isinstance(addr, LowerFailure):
                return addr
            data = _lower_expr(statement.data, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=irsb.tyenv, memory=mem_version)
            if isinstance(data, LowerFailure):
                return data
            endness = str(getattr(statement, "endness", "Iend_LE"))
            if endness not in {"Iend_LE", "Iend_BE"}:
                return LowerFailure("unsupported_ir", f"unsupported VEX store endness: {endness}")
            op = "storele" if endness == "Iend_LE" else "storebe"
            mem_version = SsaExpr(op, 0, (mem_version, _coerce_width(addr, 32), data))
            memory_touched = True
            continue
        if tag == "Ist_Exit":
            guard = _lower_expr(statement.guard, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=irsb.tyenv, memory=mem_version)
            if isinstance(guard, LowerFailure):
                return guard
            dst = _lower_expr(statement.dst, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=irsb.tyenv, memory=mem_version)
            if isinstance(dst, LowerFailure):
                return dst
            exits.append((_coerce_width(guard, 1), _coerce_width(dst, 16 if dst.width <= 16 else dst.width)))
            continue
        if tag in {"Ist_NoOp", "Ist_AbiHint", "Ist_MBE"}:
            continue
        return LowerFailure("unsupported_ir", f"unsupported VEX statement: {tag}")

    next_expr = _lower_expr(irsb.next, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=irsb.tyenv, memory=mem_version)
    if isinstance(next_expr, LowerFailure):
        return next_expr
    ip_expr = _coerce_width(next_expr, 16)
    for guard, dst in reversed(exits):
        ip_expr = SsaExpr("ite", 16, (_coerce_width(guard, 1), _coerce_width(dst, 16), ip_expr))
    reg_versions["ip"] = ip_expr

    requested: dict[str, SsaExpr] = {}
    for reg in output_regs:
        if reg not in reg_versions:
            return LowerFailure("unsupported_ir", f"unsupported output register: {reg}")
        expr = reg_versions[reg]
        failure = _expr_failure(expr)
        if failure is not None:
            return failure
        requested[reg] = expr

    assignments: list[dict[str, Any]] = []
    memo: dict[tuple[Any, ...], str] = {}
    key_cache: dict[int, tuple[Any, ...]] = {}
    outputs = {reg: _materialize(expr, assignments=assignments, memo=memo, key_cache=key_cache) for reg, expr in requested.items()}
    if memory_touched:
        outputs["memory"] = _materialize(mem_version, assignments=assignments, memo=memo, key_cache=key_cache)
    if max_assignments_per_function > 0 and len(assignments) > max_assignments_per_function:
        return LowerFailure("slice_too_large", f"SSA assignment limit reached: {len(assignments)} > {max_assignments_per_function}")
    inputs = _collect_inputs(requested.values())
    if memory_touched:
        inputs.update(_collect_inputs((mem_version,)))
    return {
        "inputs": _input_items(inputs),
        "outputs": outputs,
        "assignments": assignments,
    }


BYTE_REGISTER_ACCESS = {
    0: ("ax", False),
    1: ("ax", True),
    2: ("cx", False),
    3: ("cx", True),
    4: ("dx", False),
    5: ("dx", True),
    6: ("bx", False),
    7: ("bx", True),
}


def _vex_irsb_to_ail_block(*, project: Any, irsb: Any) -> Any:
    from angr.ailment.converter_vex import VEXIRSBConverter
    from angr.ailment.manager import Manager

    return VEXIRSBConverter.convert(irsb, Manager(arch=project.arch))


def _lower_ail_block(block: Any, *, output_regs: tuple[str, ...], max_assignments_per_function: int) -> dict[str, Any] | LowerFailure:
    temp_defs: dict[int, SsaExpr] = {}
    temp_failures: dict[int, LowerFailure] = {}
    reg_versions: dict[str, SsaExpr] = {name: SsaExpr("input", width, name=name) for _offset, (name, width) in REG_BY_OFFSET.items()}
    mem_version = SsaExpr("mem_input", 0, name="mem")
    memory_touched = False
    ip_expr: SsaExpr | None = None
    exits: list[tuple[SsaExpr, SsaExpr]] = []

    for statement in getattr(block, "statements", []) or []:
        kind = statement.__class__.__name__
        if kind in {"Assignment", "WeakAssignment"}:
            dst = statement.dst
            dst_kind = dst.__class__.__name__
            if dst_kind == "Register" and _is_unobserved_flags_write(int(dst.reg_offset), output_regs):
                continue
            src = _lower_ail_expr(statement.src, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=mem_version)
            if dst_kind == "Tmp":
                if isinstance(src, LowerFailure):
                    temp_failures[int(dst.tmp_idx)] = src
                else:
                    temp_defs[int(dst.tmp_idx)] = src
                continue
            if dst_kind == "Register":
                if isinstance(src, LowerFailure):
                    access = _register_write_target(int(dst.reg_offset), None)
                    if access is None:
                        return LowerFailure("unsupported_ir", f"unsupported AIL register offset {dst.reg_offset}")
                    reg_versions[access[0]] = SsaExpr("unsupported", access[1], name=f"{src.reason}|{src.message}")
                    continue
                failure = _write_register(reg_versions, int(dst.reg_offset), src)
                if failure is not None:
                    return failure
                continue
            return LowerFailure("unsupported_ir", f"unsupported AIL assignment destination: {dst_kind}")

        if kind == "Store":
            guard = getattr(statement, "guard", None)
            if guard is not None:
                lowered_guard = _lower_ail_expr(guard, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=mem_version)
                if isinstance(lowered_guard, LowerFailure):
                    return lowered_guard
                if _const_value(lowered_guard) != 1:
                    return LowerFailure("unsupported_ir", "guarded AIL store is not modeled")
            addr = _lower_ail_expr(statement.addr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=mem_version)
            if isinstance(addr, LowerFailure):
                return addr
            data = _lower_ail_expr(statement.data, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=mem_version)
            if isinstance(data, LowerFailure):
                return data
            endness = str(getattr(statement, "endness", "Iend_LE"))
            if endness not in {"Iend_LE", "Iend_BE"}:
                return LowerFailure("unsupported_ir", f"unsupported AIL store endness: {endness}")
            width = int(getattr(statement, "size", 0)) * 8
            if width <= 0:
                return LowerFailure("unsupported_ir", "AIL store has invalid width")
            op = "storele" if endness == "Iend_LE" else "storebe"
            mem_version = SsaExpr(op, 0, (mem_version, _coerce_width(addr, 32), _coerce_width(data, width)))
            memory_touched = True
            continue

        if kind == "ConditionalJump":
            guard = _lower_ail_expr(statement.condition, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=mem_version)
            if isinstance(guard, LowerFailure):
                return guard
            dst = _lower_ail_expr(statement.true_target, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=mem_version)
            if isinstance(dst, LowerFailure):
                return dst
            false_target = getattr(statement, "false_target", None)
            if false_target is not None:
                false_expr = _lower_ail_expr(false_target, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=mem_version)
                if isinstance(false_expr, LowerFailure):
                    return false_expr
                ip_expr = _coerce_width(false_expr, 16)
            exits.append((_coerce_width(guard, 1), _coerce_width(dst, 16 if dst.width <= 16 else dst.width)))
            continue

        if kind == "Jump":
            target = _lower_ail_expr(statement.target, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=mem_version)
            if isinstance(target, LowerFailure):
                return target
            ip_expr = _coerce_width(target, 16)
            continue

        if kind == "Return":
            continue

        if kind == "SideEffectStatement":
            expr = getattr(statement, "expr", None)
            if getattr(expr, "op", None) == "call":
                continue
            return LowerFailure("unsupported_ir", f"unsupported AIL side-effect statement: {expr}")

        if kind in {"Label"}:
            continue
        return LowerFailure("unsupported_ir", f"unsupported AIL statement: {kind}")

    if ip_expr is not None:
        for guard, dst in reversed(exits):
            ip_expr = SsaExpr("ite", 16, (_coerce_width(guard, 1), _coerce_width(dst, 16), ip_expr))
        reg_versions["ip"] = ip_expr
    elif "ip" in output_regs and exits:
        return LowerFailure("unsupported_ir", "AIL conditional jump has no false target")

    requested: dict[str, SsaExpr] = {}
    for reg in output_regs:
        if reg not in reg_versions:
            return LowerFailure("unsupported_ir", f"unsupported output register: {reg}")
        expr = reg_versions[reg]
        failure = _expr_failure(expr)
        if failure is not None:
            return failure
        requested[reg] = expr

    assignments: list[dict[str, Any]] = []
    memo: dict[tuple[Any, ...], str] = {}
    key_cache: dict[int, tuple[Any, ...]] = {}
    outputs = {reg: _materialize(expr, assignments=assignments, memo=memo, key_cache=key_cache) for reg, expr in requested.items()}
    if memory_touched:
        outputs["memory"] = _materialize(mem_version, assignments=assignments, memo=memo, key_cache=key_cache)
    if max_assignments_per_function > 0 and len(assignments) > max_assignments_per_function:
        return LowerFailure("slice_too_large", f"SSA assignment limit reached: {len(assignments)} > {max_assignments_per_function}")
    inputs = _collect_inputs(requested.values())
    if memory_touched:
        inputs.update(_collect_inputs((mem_version,)))
    return {
        "inputs": _input_items(inputs),
        "outputs": outputs,
        "assignments": assignments,
    }


def _lower_ail_expr(
    expr: Any,
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    if expr is None:
        return LowerFailure("unsupported_ir", "AIL expression is missing")
    kind = expr.__class__.__name__
    if kind == "Const":
        bits = int(getattr(expr, "bits", 0))
        value = getattr(expr, "value", None)
        if not isinstance(value, int) or bits <= 0:
            return LowerFailure("unsupported_ir", f"unsupported AIL constant: {expr}")
        return SsaExpr("const", bits, value=value & _mask(bits))
    if kind == "Tmp":
        tmp = int(expr.tmp_idx)
        if tmp in temp_failures:
            return temp_failures[tmp]
        if tmp not in temp_defs:
            return LowerFailure("unsupported_ir", f"read of undefined AIL tmp t{tmp}")
        return temp_defs[tmp]
    if kind == "Register":
        return _read_register(reg_versions, int(expr.reg_offset), int(expr.bits), source="AIL")
    if kind == "BinaryOp":
        return _lower_ail_binop(expr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if kind == "UnaryOp":
        return _lower_ail_unop(expr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if kind == "Convert":
        operand = _lower_ail_expr(expr.operand, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
        if isinstance(operand, LowerFailure):
            return operand
        width = int(expr.to_bits)
        if width == operand.width:
            return operand
        if width > operand.width:
            return SsaExpr("sext" if bool(expr.is_signed) else "zext", width, (operand,))
        return SsaExpr("trunc", width, (operand,))
    if kind == "Load":
        guard = getattr(expr, "guard", None)
        if guard is not None:
            lowered_guard = _lower_ail_expr(guard, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
            if isinstance(lowered_guard, LowerFailure):
                return lowered_guard
            if _const_value(lowered_guard) != 1:
                return LowerFailure("unsupported_ir", "guarded AIL load is not modeled")
        addr = _lower_ail_expr(expr.addr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
        if isinstance(addr, LowerFailure):
            return addr
        endness = str(getattr(expr, "endness", "Iend_LE"))
        if endness not in {"Iend_LE", "Iend_BE"}:
            return LowerFailure("unsupported_ir", f"unsupported AIL load endness: {endness}")
        op = "loadle" if endness == "Iend_LE" else "loadbe"
        return SsaExpr(op, int(expr.size) * 8, (memory, _coerce_width(addr, 32)))
    if kind == "ITE":
        cond = _lower_ail_expr(expr.cond, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
        if isinstance(cond, LowerFailure):
            return cond
        iftrue = _lower_ail_expr(expr.iftrue, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
        if isinstance(iftrue, LowerFailure):
            return iftrue
        iffalse = _lower_ail_expr(expr.iffalse, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
        if isinstance(iffalse, LowerFailure):
            return iffalse
        return SsaExpr("ite", int(expr.bits), (_coerce_width(cond, 1), _coerce_width(iftrue, int(expr.bits)), _coerce_width(iffalse, int(expr.bits))))
    if kind == "Extract":
        return _lower_ail_extract(expr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if kind == "Insert":
        return _lower_ail_insert(expr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if kind == "Call":
        return LowerFailure("unsupported_ir", "AIL call expression is not modeled inside value slice")
    if kind in {"DirtyExpression", "VEXCCallExpression"}:
        callee = str(getattr(expr, "callee", kind))
        return LowerFailure("unsupported_ir", f"unsupported AIL helper expression: {callee}")
    if kind == "MultiStatementExpression":
        return LowerFailure("unsupported_ir", "AIL multi-statement expression is not modeled")
    return LowerFailure("unsupported_ir", f"unsupported AIL expression: {kind}")


def _lower_ail_binop(
    expr: Any,
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    args: list[SsaExpr] = []
    for operand in expr.operands:
        lowered = _lower_ail_expr(operand, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
        if isinstance(lowered, LowerFailure):
            return lowered
        args.append(lowered)
    if len(args) != 2:
        return LowerFailure("unsupported_ir", f"unsupported AIL binop arity: {expr.op}")
    op = str(expr.op)
    width = int(expr.bits)
    signed = bool(getattr(expr, "signed", False))
    if op == "Concat":
        return SsaExpr("concat", width, tuple(args))
    op_map = {
        "Add": "add",
        "Sub": "sub",
        "Mul": "mul",
        "Mull": "smull" if signed else "umull",
        "Div": "sdiv" if signed else "udiv",
        "Mod": "srem" if signed else "urem",
        "And": "and",
        "LogicalAnd": "and",
        "Or": "or",
        "LogicalOr": "or",
        "Xor": "xor",
        "Shl": "shl",
        "Shr": "lshr",
        "Sar": "ashr",
        "CmpEQ": "eq",
        "CmpNE": "ne",
        "CmpLT": "slt" if signed else "ult",
        "CmpLE": "sle" if signed else "ule",
        "CmpGT": "sgt" if signed else "ugt",
        "CmpGE": "sge" if signed else "uge",
    }
    lowered_op = op_map.get(op)
    if lowered_op is None:
        return LowerFailure("unsupported_ir", f"unsupported AIL binop: {op}")
    if lowered_op in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
        return SsaExpr(lowered_op, 1, (_coerce_width(args[0], args[1].width), args[1]))
    if lowered_op in {"shl", "lshr", "ashr"}:
        return SsaExpr(lowered_op, width, (_coerce_width(args[0], width), args[1]))
    if lowered_op in {"umull", "smull"}:
        return SsaExpr(lowered_op, width, tuple(args))
    if lowered_op in {"udiv", "sdiv", "urem", "srem"}:
        return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))
    return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))


def _lower_ail_unop(
    expr: Any,
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    operand = _lower_ail_expr(expr.operand, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if isinstance(operand, LowerFailure):
        return operand
    op = str(expr.op)
    width = int(expr.bits)
    if op in {"BitwiseNeg", "Not"}:
        return SsaExpr("not", width, (_coerce_width(operand, width),))
    if op == "Neg":
        return SsaExpr("sub", width, (SsaExpr("const", width, value=0), _coerce_width(operand, width)))
    return LowerFailure("unsupported_ir", f"unsupported AIL unop: {op}")


def _lower_ail_extract(
    expr: Any,
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    base = _lower_ail_expr(expr.base, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if isinstance(base, LowerFailure):
        return base
    offset = _lower_ail_expr(expr.offset, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if isinstance(offset, LowerFailure):
        return offset
    offset_value = _const_value(offset)
    if offset_value is None:
        return LowerFailure("unsupported_ir", "AIL dynamic bit extract offset is not modeled")
    shifted = SsaExpr("lshr", base.width, (_coerce_width(base, base.width), SsaExpr("const", 8, value=offset_value & 0xFF)))
    return _coerce_width(shifted, int(expr.bits))


def _lower_ail_insert(
    expr: Any,
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    base = _lower_ail_expr(expr.base, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if isinstance(base, LowerFailure):
        return base
    value = _lower_ail_expr(expr.value, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if isinstance(value, LowerFailure):
        return value
    offset = _lower_ail_expr(expr.offset, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, memory=memory)
    if isinstance(offset, LowerFailure):
        return offset
    offset_value = _const_value(offset)
    if offset_value is None:
        return LowerFailure("unsupported_ir", "AIL dynamic bit insert offset is not modeled")
    width = int(expr.bits)
    value_width = int(value.width)
    mask = ((_mask(value_width) << offset_value) ^ _mask(width)) & _mask(width)
    cleared = SsaExpr("and", width, (_coerce_width(base, width), SsaExpr("const", width, value=mask)))
    shifted = SsaExpr("shl", width, (_coerce_width(value, width), SsaExpr("const", 8, value=offset_value & 0xFF)))
    return SsaExpr("or", width, (cleared, shifted))


def _read_register(reg_versions: dict[str, SsaExpr], offset: int, width: int, *, source: str) -> SsaExpr | LowerFailure:
    reg = REG_BY_OFFSET.get(offset)
    if reg is not None and width == reg[1]:
        if reg[0] == "flags":
            return SsaExpr("input", width, name="flags")
        return reg_versions.get(reg[0], SsaExpr("input", width, name=reg[0]))
    byte_access = BYTE_REGISTER_ACCESS.get(offset)
    if byte_access is not None and width == 8:
        base_name, high = byte_access
        full = reg_versions.get(base_name, SsaExpr("input", 16, name=base_name))
        if high:
            shifted = SsaExpr("lshr", 16, (_coerce_width(full, 16), SsaExpr("const", 8, value=8)))
            return _coerce_width(shifted, 8)
        return _coerce_width(full, 8)
    if reg is None:
        return LowerFailure("unsupported_ir", f"unsupported {source} register offset {offset}")
    return LowerFailure("unsupported_ir", f"unsupported {source} register access: offset {offset} width {width}")


def _register_write_target(offset: int, width: int | None) -> tuple[str, int] | None:
    reg = REG_BY_OFFSET.get(offset)
    if reg is not None and (width is None or width == reg[1]):
        return reg
    byte_access = BYTE_REGISTER_ACCESS.get(offset)
    if byte_access is not None and (width is None or width == 8):
        return byte_access[0], 16
    return None


def _write_register(reg_versions: dict[str, SsaExpr], offset: int, expr: SsaExpr) -> LowerFailure | None:
    reg = REG_BY_OFFSET.get(offset)
    if reg is not None and expr.width == reg[1]:
        reg_versions[reg[0]] = _coerce_width(expr, reg[1])
        return None
    byte_access = BYTE_REGISTER_ACCESS.get(offset)
    if byte_access is not None and expr.width == 8:
        base_name, high = byte_access
        full = reg_versions.get(base_name, SsaExpr("input", 16, name=base_name))
        data = _coerce_width(expr, 8)
        if high:
            cleared = SsaExpr("and", 16, (_coerce_width(full, 16), SsaExpr("const", 16, value=0x00FF)))
            shifted = SsaExpr("shl", 16, (_coerce_width(data, 16), SsaExpr("const", 8, value=8)))
            masked = SsaExpr("and", 16, (shifted, SsaExpr("const", 16, value=0xFF00)))
            reg_versions[base_name] = SsaExpr("or", 16, (cleared, masked))
            return None
        cleared = SsaExpr("and", 16, (_coerce_width(full, 16), SsaExpr("const", 16, value=0xFF00)))
        reg_versions[base_name] = SsaExpr("or", 16, (cleared, _coerce_width(data, 16)))
        return None
    if reg is None and byte_access is None:
        return LowerFailure("unsupported_ir", f"unsupported register offset {offset}")
    return LowerFailure("unsupported_ir", f"unsupported register write: offset {offset} width {expr.width}")


def _const_value(expr: SsaExpr) -> int | None:
    return expr.value if expr.op == "const" else None


def _is_unobserved_flags_write(offset: int, output_regs: tuple[str, ...]) -> bool:
    reg = REG_BY_OFFSET.get(offset)
    return reg is not None and reg[0] == "flags" and "flags" not in output_regs


def _lower_expr(
    expr: Any,
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    if not hasattr(expr, "tag") and hasattr(expr, "size") and hasattr(expr, "value"):
        return SsaExpr("const", int(expr.size), value=int(expr.value) & _mask(int(expr.size)))
    tag = expr.tag
    if str(tag).startswith("Ico_") and hasattr(expr, "size") and hasattr(expr, "value"):
        return SsaExpr("const", int(expr.size), value=int(expr.value) & _mask(int(expr.size)))
    if tag == "Iex_RdTmp":
        tmp = int(expr.tmp)
        if tmp in temp_failures:
            return temp_failures[tmp]
        if tmp not in temp_defs:
            return LowerFailure("unsupported_ir", f"read of undefined VEX tmp t{tmp}")
        return temp_defs[tmp]
    if tag == "Iex_Get":
        width = int(expr.result_size(tyenv))
        return _read_register(reg_versions, int(expr.offset), width, source="VEX")
    if tag == "Iex_Const":
        return SsaExpr("const", int(expr.con.size), value=int(expr.con.value) & _mask(int(expr.con.size)))
    if tag == "Iex_Binop":
        return _lower_binop(expr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory)
    if tag == "Iex_Unop":
        return _lower_unop(expr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory)
    if tag == "Iex_ITE":
        cond = _lower_expr(expr.cond, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory)
        if isinstance(cond, LowerFailure):
            return cond
        iftrue = _lower_expr(expr.iftrue, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory)
        if isinstance(iftrue, LowerFailure):
            return iftrue
        iffalse = _lower_expr(expr.iffalse, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory)
        if isinstance(iffalse, LowerFailure):
            return iffalse
        return SsaExpr("ite", int(expr.result_size(tyenv)), (_coerce_width(cond, 1), iftrue, iffalse))
    if tag == "Iex_Load":
        addr = _lower_expr(expr.addr, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory)
        if isinstance(addr, LowerFailure):
            return addr
        endness = str(getattr(expr, "endness", "Iend_LE"))
        if endness not in {"Iend_LE", "Iend_BE"}:
            return LowerFailure("unsupported_ir", f"unsupported VEX load endness: {endness}")
        op = "loadle" if endness == "Iend_LE" else "loadbe"
        return SsaExpr(op, int(expr.result_size(tyenv)), (memory, _coerce_width(addr, 32)))
    return LowerFailure("unsupported_ir", f"unsupported VEX expression: {tag}")


def _lower_binop(
    expr: Any,
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    op = _strip_iop(str(expr.op))
    base = _normalize_binop(op)
    lowered_op = SUPPORTED_BINOPS.get(base)
    if lowered_op is None:
        return LowerFailure("unsupported_ir", f"unsupported VEX binop: {op}")
    args: list[SsaExpr] = []
    for arg in expr.args:
        lowered = _lower_expr(arg, temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory)
        if isinstance(lowered, LowerFailure):
            return lowered
        args.append(lowered)
    width = int(expr.result_size(tyenv))
    if lowered_op in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
        return SsaExpr(lowered_op, 1, (_coerce_width(args[0], args[1].width), args[1]))
    if lowered_op in {"shl", "lshr", "ashr"}:
        return SsaExpr(lowered_op, width, (_coerce_width(args[0], width), args[1]))
    if lowered_op in {"umull", "smull"}:
        return SsaExpr(lowered_op, width, tuple(args))
    if lowered_op in {"udiv", "sdiv", "urem", "srem"}:
        return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))
    return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))


def _lower_unop(
    expr: Any,
    *,
    temp_defs: dict[int, SsaExpr],
    temp_failures: dict[int, LowerFailure],
    reg_versions: dict[str, SsaExpr],
    tyenv: Any,
    memory: SsaExpr,
) -> SsaExpr | LowerFailure:
    op = _strip_iop(str(expr.op))
    if len(expr.args) != 1:
        return LowerFailure("unsupported_ir", f"unsupported VEX unop arity: {op}")
    arg = _lower_expr(expr.args[0], temp_defs=temp_defs, temp_failures=temp_failures, reg_versions=reg_versions, tyenv=tyenv, memory=memory)
    if isinstance(arg, LowerFailure):
        return arg
    width = int(expr.result_size(tyenv))
    if op.startswith("Not"):
        return SsaExpr("not", width, (_coerce_width(arg, width),))
    if "Uto" in op:
        return SsaExpr("zext", width, (arg,))
    if "Sto" in op:
        return SsaExpr("sext", width, (arg,))
    if "to" in op:
        return SsaExpr("trunc", width, (arg,))
    return LowerFailure("unsupported_ir", f"unsupported VEX unop: {op}")


def _materialize(
    expr: SsaExpr,
    *,
    assignments: list[dict[str, Any]],
    memo: dict[tuple[Any, ...], str],
    key_cache: dict[int, tuple[Any, ...]],
) -> dict[str, Any]:
    if expr.op == "input":
        return {"op": "input", "name": expr.name, "width": expr.width}
    if expr.op == "mem_input":
        return {"op": "mem_input", "name": expr.name, "addr_width": 32, "value_width": 8}
    if expr.op == "const":
        return {"op": "const", "value": normalize_hex(expr.value or 0), "width": expr.width}
    key = _expr_key(expr, key_cache)
    if key in memo:
        return {"ref": memo[key]}
    args = [_materialize(arg, assignments=assignments, memo=memo, key_cache=key_cache) for arg in expr.args]
    ident = f"v{len(assignments)}"
    memo[key] = ident
    assignments.append({"id": ident, "op": expr.op, "width": expr.width, "args": args})
    return {"ref": ident}


def _expr_key(expr: SsaExpr, key_cache: dict[int, tuple[Any, ...]]) -> tuple[Any, ...]:
    ident = id(expr)
    cached = key_cache.get(ident)
    if cached is not None:
        return cached
    key = (expr.op, expr.width, expr.value, expr.name, tuple(_expr_key(arg, key_cache) for arg in expr.args))
    key_cache[ident] = key
    return key


def _ssa_solver_gate(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    max_solver_assignments: int,
    max_solver_inputs: int,
    max_solver_memory_stores: int,
) -> dict[str, Any] | None:
    sides = (("oracle", oracle), ("candidate", candidate))
    if max_solver_assignments > 0:
        for side, function in sides:
            count = len(function.get("assignments", []) or [])
            if count > max_solver_assignments:
                return {
                    "kind": "solver_gate",
                    "reason": "slice_too_large",
                    "detail": f"{side} SSA assignment count {count} exceeds solver gate {max_solver_assignments}",
                    "side": side,
                    "metric": "assignments",
                    "value": count,
                    "limit": max_solver_assignments,
                }
    if max_solver_inputs > 0:
        for side, function in sides:
            count = len(function.get("inputs", []) or [])
            if count > max_solver_inputs:
                return {
                    "kind": "solver_gate",
                    "reason": "slice_too_large",
                    "detail": f"{side} SSA input count {count} exceeds solver gate {max_solver_inputs}",
                    "side": side,
                    "metric": "inputs",
                    "value": count,
                    "limit": max_solver_inputs,
                }
    if max_solver_memory_stores > 0:
        for side, function in sides:
            outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
            if "memory" not in outputs:
                continue
            count = _ssa_store_count(function)
            if count > max_solver_memory_stores:
                return {
                    "kind": "solver_gate",
                    "reason": "slice_too_large",
                    "detail": f"{side} SSA memory store count {count} exceeds solver gate {max_solver_memory_stores}",
                    "side": side,
                    "metric": "memory_stores",
                    "value": count,
                    "limit": max_solver_memory_stores,
                }
    return None


def _ssa_store_count(function: dict[str, Any]) -> int:
    return sum(1 for item in function.get("assignments", []) or [] if isinstance(item, dict) and item.get("op") in {"storele", "storebe"})


def _compare_functions(oracle: dict[str, Any], candidate: dict[str, Any], *, timeout_ms: int) -> dict[str, Any]:
    try:
        import z3  # type: ignore
    except Exception:  # noqa: BLE001
        return {"status": "refused", "reason": "unsupported_ir", "mismatches": [{"kind": "z3_unavailable"}], "solver_time_ms": 0}

    import time

    started = time.monotonic()
    oracle_outputs = oracle.get("outputs", {}) if isinstance(oracle.get("outputs"), dict) else {}
    candidate_outputs = candidate.get("outputs", {}) if isinstance(candidate.get("outputs"), dict) else {}
    oracle_output_names = set(oracle_outputs)
    candidate_output_names = set(candidate_outputs)
    if oracle_output_names != candidate_output_names:
        return {
            "status": "failed",
            "reason": "observable_mismatch",
            "mismatches": [
                {
                    "kind": "output_set_changed",
                    "oracle_only": sorted(oracle_output_names - candidate_output_names),
                    "candidate_only": sorted(candidate_output_names - oracle_output_names),
                }
            ],
            "solver_time_ms": 0,
        }
    output_regs = sorted(oracle_output_names)
    if not output_regs:
        return {"status": "refused", "reason": "unsupported_ir", "mismatches": [{"kind": "no_common_outputs"}], "solver_time_ms": 0}

    inputs = _z3_inputs(oracle, candidate, z3)
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    differing: list[Any] = []
    pairs: list[tuple[str, Any, Any]] = []
    for reg in output_regs:
        oracle_expr = _z3_term(oracle_outputs[reg], document=oracle, inputs=inputs, z3=z3)
        candidate_expr = _z3_term(candidate_outputs[reg], document=candidate, inputs=inputs, z3=z3)
        if not (_is_z3_array(oracle_expr, z3) or _is_z3_array(candidate_expr, z3)):
            oracle_expr, candidate_expr = _align_z3_widths(oracle_expr, candidate_expr, z3)
        pairs.append((reg, oracle_expr, candidate_expr))
        differing.append(oracle_expr != candidate_expr)
    solver.add(z3.Or(*differing))
    status = solver.check()
    elapsed = int((time.monotonic() - started) * 1000)
    if status == z3.unknown:
        return {"status": "refused", "reason": "timeout", "mismatches": [{"kind": "z3_unknown", "detail": solver.reason_unknown()}], "solver_time_ms": elapsed}
    if status != z3.sat:
        return {"status": "passed", "reason": None, "mismatches": [], "solver_time_ms": elapsed}
    model = solver.model()
    counterexample = {name: normalize_hex(model.eval(value, model_completion=True).as_long(), width=width // 4) for name, (value, width) in inputs.items() if width > 0}
    mismatches: list[dict[str, Any]] = []
    for reg, oracle_expr, candidate_expr in pairs:
        if _is_z3_array(oracle_expr, z3) or _is_z3_array(candidate_expr, z3):
            if z3.is_true(model.eval(oracle_expr != candidate_expr, model_completion=True)):
                mismatches.append(
                    {
                        "kind": "memory_expr_changed",
                        "reg": reg,
                        "counterexample": counterexample,
                    }
                )
            continue
        oracle_value = model.eval(oracle_expr, model_completion=True).as_long()
        candidate_value = model.eval(candidate_expr, model_completion=True).as_long()
        if oracle_value != candidate_value:
            mismatches.append(
                {
                    "kind": "output_expr_changed",
                    "reg": reg,
                    "oracle_value": normalize_hex(oracle_value),
                    "candidate_value": normalize_hex(candidate_value),
                    "counterexample": counterexample,
                }
            )
    return {"status": "failed", "reason": "observable_mismatch", "mismatches": mismatches, "solver_time_ms": elapsed}


def _is_z3_array(expr: Any, z3: Any) -> bool:
    try:
        return expr.sort().kind() == z3.Z3_ARRAY_SORT
    except Exception:  # noqa: BLE001
        return False


def _mapped_candidate_detail(mapped: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(mapped, dict):
        return None
    return {
        "id": mapped.get("candidate_id"),
        "name": mapped.get("candidate_name"),
        "entry": mapped.get("candidate_entry"),
        "sources": list(mapped.get("sources", []) or []),
    }


def _ssa_function_report_detail(function: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(function, dict):
        return None
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
    inputs = function.get("inputs", []) if isinstance(function.get("inputs"), list) else []
    return {
        "part": function.get("part") if isinstance(function.get("part"), dict) else None,
        "entry": function.get("entry"),
        "jumpkind": source.get("jumpkind"),
        "transfer": source.get("transfer") if isinstance(source.get("transfer"), dict) else _transfer_info_from_instructions(source),
        "instruction_count": source.get("instruction_count", len(instructions)),
        "instructions": instructions,
        "instructions_truncated": 0,
        "function_machine_code_sha256": source.get("function_machine_code_sha256"),
        "function_machine_code_size": source.get("function_machine_code_size"),
        "machine_code_sha256": source.get("machine_code_sha256"),
        "machine_code_size": source.get("machine_code_size"),
        "outputs": sorted(str(name) for name in outputs),
        "input_count": len(inputs),
        "assignment_count": len(function.get("assignments", []) or []),
    }


def _summary_detail(summary: dict[str, Any]) -> dict[str, Any]:
    if summary.get("status") != "passed":
        return {key: summary.get(key) for key in ("status", "reason", "mismatches") if key in summary}
    function = summary.get("function", {}) if isinstance(summary.get("function"), dict) else {}
    return {
        "status": summary.get("status"),
        "part_count": summary.get("part_count"),
        "terminal_count": summary.get("terminal_count"),
        "outputs": sorted((function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}).keys()),
        "input_count": len(function.get("inputs", []) or []),
        "assignment_count": len(function.get("assignments", []) or []),
    }


def _abi_functions(abi_manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in abi_manifest.get("functions", []) or [] if isinstance(item, dict)]


def _abi_data_segment_para(abi_manifest: dict[str, Any]) -> int:
    contract = abi_manifest.get("data_segment_contract") if isinstance(abi_manifest.get("data_segment_contract"), dict) else {}
    for key in ("static_data_segment", "link_data_segment", "data_segment"):
        value = _optional_int(contract.get(key))
        if value is not None:
            return value & 0xFFFF
    return 0x0100


def _abi_observables(abi_function: dict[str, Any]) -> dict[str, Any]:
    return_regs: set[str] = set()
    preserved_regs: set[str] = set()
    for item in abi_function.get("returns", []) or []:
        if isinstance(item, dict) and item.get("location"):
            return_regs.add(str(item["location"]).lower())
        elif isinstance(item, str):
            return_regs.add(item.lower())
    for item in abi_function.get("preserved", []) or []:
        preserved_regs.add(str(item).lower())
    preserved_regs -= {str(item).lower() for item in abi_function.get("clobbers", []) or []}
    explicit_regs = abi_function.get("ssa_observe_regs")
    if explicit_regs is not None:
        regs = {str(item).lower() for item in explicit_regs or []}
    else:
        regs = {"sp"} | return_regs | preserved_regs
    memory = [item for item in abi_function.get("effects", []) or [] if isinstance(item, dict)]
    return {"regs": sorted(regs), "memory": memory}


def _ssa_function_groups(functions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        keys = {str(info.get("id") or ""), str(info.get("name") or "")}
        for key in keys:
            if key:
                groups.setdefault(key, []).append(function)
    return groups


def _ssa_group_for_abi_function(
    groups: dict[str, list[dict[str, Any]]],
    abi_function: dict[str, Any],
    *,
    side: str,
    mapped: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if side == "candidate" and isinstance(mapped, dict):
        for key in (str(mapped.get("candidate_id") or ""), str(mapped.get("candidate_name") or "")):
            if key and key in groups:
                return groups[key]
    prefixes = ("oracle_", "candidate_") if side == "oracle" else ("candidate_", "oracle_")
    for key_name in (f"{prefixes[0]}id", f"{prefixes[0]}name", "id", "name"):
        key = str(abi_function.get(key_name) or "")
        if key and key in groups:
            return groups[key]
    name = str(abi_function.get("name") or "")
    return groups.get(name, [])


def _summarize_abi_function(
    parts: list[dict[str, Any]],
    *,
    abi_function: dict[str, Any],
    observables: dict[str, Any],
    data_segment_para: int,
) -> dict[str, Any]:
    if not parts:
        return {"status": "refused", "reason": "function_missing", "mismatches": [{"kind": "function_missing"}]}
    block_by_key: dict[int, dict[str, Any]] = {}
    for part in parts:
        entry = part.get("entry", {}) if isinstance(part.get("entry"), dict) else {}
        for value in (_optional_int(entry.get("linear")), _optional_int(entry.get("ip"))):
            if value is not None:
                block_by_key[value & 0xFFFF] = part
    start = min(parts, key=lambda item: int((item.get("part", {}) if isinstance(item.get("part"), dict) else {}).get("index", 0)))
    state = _initial_abi_state(abi_function, observables=observables, data_segment_para=data_segment_para)
    try:
        final_state, terminal_count = _compose_abi_state(start, state, block_by_key=block_by_key, path=[])
        summary_function = _materialize_abi_summary(
            start,
            final_state,
            observables=observables,
            data_segment_para=data_segment_para,
        )
    except LowerFailure as ex:
        return {"status": "refused", "reason": ex.reason, "mismatches": [{"kind": ex.reason, "detail": ex.message}]}
    return {
        "status": "passed",
        "part_count": len(parts),
        "terminal_count": terminal_count,
        "function": summary_function,
    }


def _initial_abi_state(
    abi_function: dict[str, Any] | None = None,
    *,
    observables: dict[str, Any] | None = None,
    data_segment_para: int = 0x0100,
) -> dict[str, dict[str, Any]]:
    if abi_function is None:
        state = {name: {"op": "input", "name": name, "width": width} for _offset, (name, width) in REG_BY_OFFSET.items()}
        state["memory"] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
        return state

    reg_widths = {name: width for _offset, (name, width) in REG_BY_OFFSET.items()}
    preserved = {str(item).lower() for item in abi_function.get("preserved", []) or []}
    observed_regs = {str(item).lower() for item in (observables or {}).get("regs", []) or []}
    symbolic_regs = {"sp"} | (preserved & observed_regs)
    for item in abi_function.get("inputs", []) or []:
        if isinstance(item, dict) and item.get("location"):
            symbolic_regs.add(str(item["location"]).lower())
        elif isinstance(item, str):
            symbolic_regs.add(item.lower())

    defaults = {
        "flags": 0x0202,
        "sp": 0xFF00,
        "ds": data_segment_para,
        "es": data_segment_para,
        "ss": 0x3000,
    }
    state: dict[str, dict[str, Any]] = {}
    for name, width in reg_widths.items():
        if name in symbolic_regs:
            state[name] = {"op": "input", "name": name, "width": width}
        else:
            state[name] = {"op": "const", "value": normalize_hex(defaults.get(name, 0), width=max(1, width // 4)), "width": width}
    state["memory"] = _initial_abi_memory(abi_function, state)
    return state


def _initial_abi_memory(abi_function: dict[str, Any], state: dict[str, dict[str, Any]]) -> dict[str, Any]:
    memory: dict[str, Any] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    stack_args = [item for item in abi_function.get("stack_args", []) or [] if isinstance(item, dict)]
    if not stack_args:
        return memory
    return_bytes = 4 if str(abi_function.get("kind") or "").lower() == "far" else 2
    next_offset = return_bytes
    for index, item in enumerate(stack_args):
        width = int(_optional_int(item.get("width")) or 16)
        size = max(1, (width + 7) // 8)
        entry_offset = _optional_int(item.get("entry_sp_offset"))
        if entry_offset is None:
            entry_offset = next_offset
        next_offset = int(entry_offset) + size
        name = re.sub(r"[^A-Za-z0-9_]+", "_", str(item.get("name") or f"arg{index}")).strip("_") or f"arg{index}"
        memory = {
            "op": "storele",
            "width": 0,
            "args": [
                memory,
                _stack_address_term(state["ss"], state["sp"], int(entry_offset)),
                {"op": "input", "name": f"arg_{name}", "width": width},
            ],
        }
    return memory


def _stack_address_term(ss_term: dict[str, Any], sp_term: dict[str, Any], offset: int) -> dict[str, Any]:
    return {
        "op": "add",
        "width": 32,
        "args": [
            {
                "op": "shl",
                "width": 32,
                "args": [
                    {"op": "zext", "width": 32, "args": [copy.deepcopy(ss_term)]},
                    {"op": "const", "value": "0x04", "width": 8},
                ],
            },
            {
                "op": "zext",
                "width": 32,
                "args": [
                    {
                        "op": "add",
                        "width": 16,
                        "args": [
                            copy.deepcopy(sp_term),
                            {"op": "const", "value": normalize_hex(offset & 0xFFFF, width=4), "width": 16},
                        ],
                    }
                ],
            },
        ],
    }


def _compose_abi_state(
    block: dict[str, Any],
    incoming_state: dict[str, dict[str, Any]],
    *,
    block_by_key: dict[int, dict[str, Any]],
    path: list[int],
) -> tuple[dict[str, dict[str, Any]], int]:
    entry = block.get("entry", {}) if isinstance(block.get("entry"), dict) else {}
    key = (_optional_int(entry.get("linear")) or _optional_int(entry.get("ip")) or 0) & 0xFFFF
    if key in path:
        raise LowerFailure("unsupported_ir", f"loop or repeated block reached at {normalize_hex(key, width=4)}")
    source = block.get("source", {}) if isinstance(block.get("source"), dict) else {}
    if source.get("jumpkind") == "Ijk_Call":
        raise LowerFailure("call_boundary", "function summary stops at a call; callee summaries are required")
    assignments = {str(item["id"]): item for item in block.get("assignments", []) or [] if isinstance(item, dict) and "id" in item}
    state = dict(incoming_state)
    block_outputs = block.get("outputs", {}) if isinstance(block.get("outputs"), dict) else {}
    for name, term in block_outputs.items():
        if not isinstance(term, dict):
            continue
        inlined = _inline_ssa_json_term(term, assignments=assignments, cache={})
        state[str(name)] = _substitute_abi_inputs(inlined, incoming_state)
    ip_term = state.get("ip")
    if ip_term is None:
        raise LowerFailure("unsupported_ir", "function-level ABI summary requires `ip` in SSA outputs")
    branch = _direct_branch_targets(ip_term, block_by_key)
    next_path = [*path, key]
    if branch is not None:
        cond, true_target, false_target = branch
        true_state, true_terminals = _compose_or_terminal(true_target, state, block_by_key=block_by_key, path=next_path)
        false_state, false_terminals = _compose_or_terminal(false_target, state, block_by_key=block_by_key, path=next_path)
        return _merge_abi_states(cond, true_state, false_state), true_terminals + false_terminals
    direct = _direct_successor_target(ip_term, block_by_key)
    if direct is not None:
        return _compose_abi_state(direct, state, block_by_key=block_by_key, path=next_path)
    return state, 1


def _compose_or_terminal(
    target: dict[str, Any],
    state: dict[str, dict[str, Any]],
    *,
    block_by_key: dict[int, dict[str, Any]],
    path: list[int],
) -> tuple[dict[str, dict[str, Any]], int]:
    successor = _successor_for_target(target, block_by_key)
    if successor is None:
        return state, 1
    return _compose_abi_state(successor, state, block_by_key=block_by_key, path=path)


def _direct_branch_targets(term: dict[str, Any], block_by_key: dict[int, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    if term.get("op") != "ite":
        return None
    args = [arg for arg in term.get("args", []) or [] if isinstance(arg, dict)]
    if len(args) != 3:
        return None
    if _target_key(args[1]) is None and _target_key(args[2]) is None:
        return None
    if _target_key(args[1]) not in block_by_key and _target_key(args[2]) not in block_by_key:
        return None
    return args[0], args[1], args[2]


def _direct_successor_target(term: dict[str, Any], block_by_key: dict[int, dict[str, Any]]) -> dict[str, Any] | None:
    return _successor_for_target(term, block_by_key)


def _successor_for_target(term: dict[str, Any], block_by_key: dict[int, dict[str, Any]]) -> dict[str, Any] | None:
    key = _target_key(term)
    if key is None:
        return None
    return block_by_key.get(key)


def _target_key(term: dict[str, Any]) -> int | None:
    if not isinstance(term, dict) or term.get("op") != "const":
        return None
    value = _optional_int(term.get("value"))
    if value is None:
        return None
    return value & 0xFFFF


def _merge_abi_states(
    condition: dict[str, Any],
    true_state: dict[str, dict[str, Any]],
    false_state: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for key in sorted(set(true_state) | set(false_state)):
        left = true_state.get(key)
        right = false_state.get(key)
        if left is None:
            merged[key] = copy.deepcopy(right)
            continue
        if right is None:
            merged[key] = copy.deepcopy(left)
            continue
        if _term_identity(left) == _term_identity(right):
            merged[key] = copy.deepcopy(left)
            continue
        merged[key] = {"op": "ite", "width": _term_width(left), "args": [copy.deepcopy(condition), copy.deepcopy(left), copy.deepcopy(right)]}
    return merged


def _materialize_abi_summary(
    start: dict[str, Any],
    final_state: dict[str, dict[str, Any]],
    *,
    observables: dict[str, Any],
    data_segment_para: int,
) -> dict[str, Any]:
    outputs: dict[str, dict[str, Any]] = {}
    for reg in observables.get("regs", []) or []:
        if reg not in final_state:
            raise LowerFailure("unsupported_ir", f"observable register {reg} is not available in the SSA summary")
        outputs[reg] = final_state[reg]
    memory_term = final_state.get("memory", {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8})
    for effect in observables.get("memory", []) or []:
        offset = _optional_int(effect.get("offset"))
        size = _optional_int(effect.get("size"))
        if offset is None or size is None or size <= 0:
            raise LowerFailure("unsupported_ir", f"invalid memory effect descriptor: {effect}")
        name = str(effect.get("name") or f"mem_{offset:04x}_{size}")
        outputs[f"memory:{offset:04x}:{size}:{name}"] = {
            "op": "loadle",
            "width": size * 8,
            "args": [memory_term, _effect_address_term(effect, data_segment_para, offset)],
        }
    assignments: list[dict[str, Any]] = []
    memo: dict[str, str] = {}
    materialized_outputs = {
        name: _materialize_json_term(term, assignments=assignments, memo=memo)
        for name, term in outputs.items()
    }
    body_without_id = {
        "function": start.get("function", {}),
        "part": {"kind": "function_abi", "index": 0, "entry_delta": "0x0000"},
        "function_entry": start.get("function_entry"),
        "entry": start.get("function_entry") or start.get("entry"),
        "source": {
            "ir": (start.get("source", {}) if isinstance(start.get("source"), dict) else {}).get("ir"),
            "jumpkind": "Ijk_FunctionSummary",
            "instruction_count": sum(
                int((part.get("source", {}) if isinstance(part.get("source"), dict) else {}).get("instruction_count", 0))
                for part in [start]
            ),
            "instructions": [],
        },
        "inputs": _term_input_items(materialized_outputs.values(), assignments),
        "outputs": materialized_outputs,
        "assignments": assignments,
    }
    body = dict(body_without_id)
    body["id"] = stable_id("ssa-function-abi", body_without_id)
    return body


def _data_address_term(data_segment_para: int, offset: int) -> dict[str, Any]:
    return {
        "op": "add",
        "width": 32,
        "args": [
            {
                "op": "shl",
                "width": 32,
                "args": [
                    {"op": "const", "value": normalize_hex(data_segment_para, width=4), "width": 32},
                    {"op": "const", "value": "0x04", "width": 8},
                ],
            },
            {"op": "const", "value": normalize_hex(offset & 0xFFFF, width=4), "width": 32},
        ],
    }


def _effect_address_term(effect: dict[str, Any], data_segment_para: int, offset: int) -> dict[str, Any]:
    segment = str(effect.get("segment") or effect.get("segment_reg") or "").lower()
    if segment in {"ds", "input_ds"}:
        segment_term: dict[str, Any] = {"op": "zext", "width": 32, "args": [{"op": "input", "name": "ds", "width": 16}]}
    elif segment in {"ss", "input_ss"}:
        segment_term = {"op": "zext", "width": 32, "args": [{"op": "input", "name": "ss", "width": 16}]}
    else:
        segment_term = {"op": "const", "value": normalize_hex(data_segment_para, width=4), "width": 32}
    return {
        "op": "add",
        "width": 32,
        "args": [
            {
                "op": "shl",
                "width": 32,
                "args": [
                    segment_term,
                    {"op": "const", "value": "0x04", "width": 8},
                ],
            },
            {"op": "const", "value": normalize_hex(offset & 0xFFFF, width=4), "width": 32},
        ],
    }


def _inline_ssa_json_term(term: dict[str, Any], *, assignments: dict[str, dict[str, Any]], cache: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if "ref" in term:
        ident = str(term["ref"])
        if ident in cache:
            return copy.deepcopy(cache[ident])
        item = assignments.get(ident)
        if item is None:
            raise LowerFailure("unsupported_ir", f"SSA ref {ident} was not found")
        inlined = {
            "op": str(item.get("op")),
            "width": int(item.get("width", 16)),
            "args": [
                _inline_ssa_json_term(arg, assignments=assignments, cache=cache)
                for arg in item.get("args", []) or []
                if isinstance(arg, dict)
            ],
        }
        cache[ident] = inlined
        return copy.deepcopy(inlined)
    copied = copy.deepcopy(term)
    if isinstance(copied.get("args"), list):
        copied["args"] = [
            _inline_ssa_json_term(arg, assignments=assignments, cache=cache)
            for arg in copied.get("args", []) or []
            if isinstance(arg, dict)
        ]
    return copied


def _substitute_abi_inputs(term: dict[str, Any], state: dict[str, dict[str, Any]]) -> dict[str, Any]:
    op = term.get("op")
    if op == "input" and str(term.get("name")) in state:
        return copy.deepcopy(state[str(term["name"])])
    if op == "mem_input":
        return copy.deepcopy(state.get("memory", term))
    copied = copy.deepcopy(term)
    if isinstance(copied.get("args"), list):
        copied["args"] = [_substitute_abi_inputs(arg, state) for arg in copied["args"] if isinstance(arg, dict)]
    return copied


def _materialize_json_term(term: dict[str, Any], *, assignments: list[dict[str, Any]], memo: dict[str, str]) -> dict[str, Any]:
    op = term.get("op")
    if op in {"input", "mem_input", "const"}:
        return copy.deepcopy(term)
    key = _term_identity(term)
    if key in memo:
        return {"ref": memo[key]}
    args = [_materialize_json_term(arg, assignments=assignments, memo=memo) for arg in term.get("args", []) or [] if isinstance(arg, dict)]
    ident = f"v{len(assignments)}"
    memo[key] = ident
    assignments.append({"id": ident, "op": str(op), "width": _term_width(term), "args": args})
    return {"ref": ident}


def _term_input_items(terms: Any, assignments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    widths: dict[str, int] = {}
    memory_inputs: set[str] = set()

    def visit(term: dict[str, Any]) -> None:
        if "ref" in term:
            ref = str(term["ref"])
            for assignment in assignments:
                if assignment.get("id") == ref:
                    for arg in assignment.get("args", []) or []:
                        if isinstance(arg, dict):
                            visit(arg)
                    return
        op = term.get("op")
        if op == "input" and term.get("name"):
            name = str(term["name"])
            widths[name] = max(widths.get(name, 0), int(term.get("width", 16)))
            return
        if op == "mem_input" and term.get("name"):
            memory_inputs.add(str(term["name"]))
            return
        for arg in term.get("args", []) or []:
            if isinstance(arg, dict):
                visit(arg)

    for term in terms:
        if isinstance(term, dict):
            visit(term)
    items = [{"kind": "memory", "name": name, "addr_width": 32, "value_width": 8} for name in sorted(memory_inputs)]
    items.extend({"name": name, "width": width} for name, width in sorted(widths.items()))
    return items


def _term_width(term: dict[str, Any]) -> int:
    if term.get("op") == "mem_input":
        return 0
    return int(term.get("width", 16))


def _term_identity(term: dict[str, Any]) -> str:
    import json

    return json.dumps(term, sort_keys=True, separators=(",", ":"))


def _ssa_function_index(functions: list[dict[str, Any]]) -> dict[str, dict[Any, dict[str, Any]]]:
    indexed: dict[str, dict[Any, dict[str, Any]]] = {
        "by_id": {},
        "by_name": {},
        "by_linear": {},
        "by_linear_all": {},
        "by_linear_low16": {},
        "by_linear_low16_all": {},
        "by_ip": {},
        "by_ip_all": {},
    }
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        if function_id:
            indexed["by_id"].setdefault(function_id, function)
        if function_name:
            indexed["by_name"].setdefault(function_name, function)
        entry = function.get("entry", {}) if isinstance(function.get("entry"), dict) else {}
        linear = _optional_int(entry.get("linear"))
        ip = _optional_int(entry.get("ip"))
        if linear is not None:
            indexed["by_linear"].setdefault(linear, function)
            _append_index(indexed["by_linear_all"], linear, function)
            _set_unique_index(indexed["by_linear_low16"], linear & 0xFFFF, function)
            _append_index(indexed["by_linear_low16_all"], linear & 0xFFFF, function)
        if ip is not None:
            _set_unique_index(indexed["by_ip"], ip & 0xFFFF, function)
            _append_index(indexed["by_ip_all"], ip & 0xFFFF, function)
    return indexed


def _append_index(table: dict[Any, list[dict[str, Any]]], key: Any, function: dict[str, Any]) -> None:
    table.setdefault(key, []).append(function)


def _set_unique_index(table: dict[Any, dict[str, Any] | None], key: Any, function: dict[str, Any]) -> None:
    if key not in table:
        table[key] = function
        return
    if table[key] is not function:
        table[key] = None


def _compare_call_targets(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    mapping_document: dict[str, Any] | None,
    oracle_index: dict[str, dict[Any, dict[str, Any]]],
    candidate_index: dict[str, dict[Any, dict[str, Any]]],
    allow_aliased_call_targets: bool,
) -> dict[str, Any] | None:
    oracle_call = _resolve_call_target(oracle_function, oracle_index, allow_aliased_call_targets=allow_aliased_call_targets)
    candidate_call = _resolve_call_target(candidate_function, candidate_index, allow_aliased_call_targets=allow_aliased_call_targets)
    if oracle_call is None and candidate_call is None:
        return None
    equivalent, reason = _call_targets_equivalent(oracle_call, candidate_call, mapping_document=mapping_document)
    return {
        "kind": "direct_call",
        "oracle": oracle_call,
        "candidate": candidate_call,
        "equivalent": equivalent,
        "reason": reason,
        "allow_aliased_call_targets": allow_aliased_call_targets,
        "normalizations": [],
    }


def _resolve_call_target(
    function: dict[str, Any],
    index: dict[str, dict[Any, dict[str, Any]]],
    *,
    allow_aliased_call_targets: bool,
) -> dict[str, Any] | None:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    if source.get("jumpkind") != "Ijk_Call":
        return None
    raw = _direct_call_target(function)
    if raw is None:
        return {"kind": "unresolved", "reason": "call target is not a direct constant"}
    target, aliases, alias_reason = _function_for_call_target(raw, index, allow_aliased_call_targets=allow_aliased_call_targets)
    detail = {
        "kind": "direct",
        "raw": normalize_hex(raw),
        "low16": normalize_hex(raw & 0xFFFF, width=4),
        "resolved": _ssa_function_brief(target),
    }
    if aliases:
        detail["aliases"] = [_ssa_function_brief(function) for function in aliases]
    if target is None:
        detail["reason"] = alias_reason or "no SSA function starts at the direct call target"
    elif alias_reason:
        detail["resolution_note"] = alias_reason
    return detail


def _direct_call_target(function: dict[str, Any]) -> int | None:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else None
    if transfer:
        target = transfer.get("target") if isinstance(transfer.get("target"), dict) else None
        if target is not None:
            raw = _optional_int(target.get("raw"))
            if raw is not None:
                return raw
    return _direct_call_target_from_instructions(source)


def _direct_call_target_from_instructions(source: dict[str, Any]) -> int | None:
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    if not instructions:
        return None
    instruction = instructions[-1]
    mnemonic = str(instruction.get("mnemonic") or _mnemonic_from_disassembly(instruction)).lower()
    if mnemonic not in {"call", "lcall"}:
        return None
    operand = str(instruction.get("op_str") or _operand_from_disassembly(instruction)).strip().lower()
    if not operand or any(token in operand for token in ("[", "]", ",", ":")):
        return None
    if operand.startswith("far "):
        operand = operand[4:].strip()
    return _optional_int(operand)


def _function_for_call_target(
    raw: int,
    index: dict[str, dict[Any, dict[str, Any]]],
    *,
    allow_aliased_call_targets: bool,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str | None]:
    low16 = raw & 0xFFFF
    for unique_table, all_table, key in (
        ("by_linear", "by_linear_all", raw),
        ("by_linear_low16", "by_linear_low16_all", low16),
        ("by_linear", "by_linear_all", low16),
        ("by_ip", "by_ip_all", raw),
        ("by_ip", "by_ip_all", low16),
    ):
        if allow_aliased_call_targets:
            candidates = [item for item in index.get(all_table, {}).get(key, []) or [] if isinstance(item, dict)]
            if len(candidates) > 1:
                aliases = _same_entry_aliases(candidates)
                if aliases:
                    return aliases[0], aliases, f"resolved through same-entry aliases by {all_table}"
                return None, [], f"direct call target matched multiple non-equivalent SSA functions by {all_table}"
        table = index.get(unique_table, {})
        if key in table and table.get(key) is not None:
            return table[key], [], None
        if allow_aliased_call_targets:
            candidates = [item for item in index.get(all_table, {}).get(key, []) or [] if isinstance(item, dict)]
            if candidates:
                aliases = _same_entry_aliases(candidates)
                if aliases:
                    return aliases[0], aliases, f"resolved through same-entry aliases by {all_table}"
                return None, [], f"direct call target matched multiple non-equivalent SSA functions by {all_table}"
        if key in table:
            return None, [], f"direct call target matched multiple non-equivalent SSA functions by {unique_table}"
    return None, [], "no SSA function starts at the direct call target"


def _same_entry_aliases(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not functions:
        return []
    groups: dict[tuple[int | None, int | None], list[dict[str, Any]]] = {}
    for function in functions:
        entry = function.get("entry", {}) if isinstance(function.get("entry"), dict) else {}
        key = (_optional_int(entry.get("linear")), _optional_int(entry.get("ip")))
        groups.setdefault(key, []).append(function)
    if len(groups) != 1:
        return []
    return sorted(functions, key=lambda item: str((item.get("function", {}) if isinstance(item.get("function"), dict) else {}).get("name", "")))


def _ssa_function_brief(function: dict[str, Any] | None, *, instruction_limit: int = CALL_TARGET_PREVIEW_INSTRUCTION_LIMIT) -> dict[str, Any] | None:
    if not isinstance(function, dict):
        return None
    info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    return {
        "id": info.get("id"),
        "name": info.get("name"),
        "entry": function.get("entry"),
        "instruction_count": source.get("instruction_count", len(instructions)),
        "instructions": instructions[:instruction_limit],
        "machine_code_sha256": source.get("machine_code_sha256"),
        "machine_code_size": source.get("machine_code_size"),
        "semantic_ssa_id": _semantic_ssa_id(function),
    }


def _semantic_ssa_id(function: dict[str, Any]) -> str:
    return stable_id("ssa-semantic", _semantic_ssa_payload(function))


def _call_targets_equivalent(
    oracle_call: dict[str, Any] | None,
    candidate_call: dict[str, Any] | None,
    *,
    mapping_document: dict[str, Any] | None,
) -> tuple[bool, str]:
    if oracle_call is None and candidate_call is None:
        return True, "neither block ends in a direct call"
    if oracle_call is None or candidate_call is None:
        return False, "only one block ends in a direct call"
    oracle_target = oracle_call.get("resolved") if isinstance(oracle_call.get("resolved"), dict) else None
    candidate_target = candidate_call.get("resolved") if isinstance(candidate_call.get("resolved"), dict) else None
    if oracle_target is None or candidate_target is None:
        if (
            oracle_call.get("kind") == "unresolved"
            and candidate_call.get("kind") == "unresolved"
            and oracle_call.get("reason") == "call target is not a direct constant"
            and candidate_call.get("reason") == "call target is not a direct constant"
        ):
            return True, "both call targets are indirect expressions"
        return False, "one or both direct call targets did not resolve to SSA functions"

    oracle_targets = _call_target_briefs(oracle_call)
    candidate_targets = _call_target_briefs(candidate_call)
    for oracle_target in oracle_targets:
        oracle_id = str(oracle_target.get("id") or "")
        oracle_name = str(oracle_target.get("name") or "")
        mapped = _mapped_call_target(oracle_id, oracle_name, mapping_document)
        if mapped is not None:
            if any(
                str(mapped.get("candidate_id") or "") == str(candidate_target.get("id") or "")
                or str(mapped.get("candidate_name") or "") == str(candidate_target.get("name") or "")
                for candidate_target in candidate_targets
            ):
                return True, "direct call targets are equivalent through function mapping"
            return False, "direct call targets resolve to different mapped functions"
    for oracle_target in oracle_targets:
        oracle_id = str(oracle_target.get("id") or "")
        oracle_name = str(oracle_target.get("name") or "")
        if any(oracle_id and oracle_id == str(candidate_target.get("id") or "") for candidate_target in candidate_targets):
            return True, "direct call targets have the same function id"
        if any(oracle_name and oracle_name == str(candidate_target.get("name") or "") for candidate_target in candidate_targets):
            return True, "direct call targets have the same function name"
        oracle_normalized_name = _normalized_symbol_name(oracle_name)
        if oracle_normalized_name and any(
            oracle_normalized_name == _normalized_symbol_name(str(candidate_target.get("name") or ""))
            for candidate_target in candidate_targets
        ):
            return True, "direct call targets have equivalent normalized symbol names"
    semantic_reason = _call_target_semantic_equivalence_reason(oracle_targets, candidate_targets)
    if semantic_reason is not None:
        return True, semantic_reason
    return False, "no mapping proves direct call target equivalence"


def _call_target_briefs(call: dict[str, Any]) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    resolved = call.get("resolved") if isinstance(call.get("resolved"), dict) else None
    if resolved is not None:
        targets.append(resolved)
    for alias in call.get("aliases", []) or []:
        if isinstance(alias, dict) and alias not in targets:
            targets.append(alias)
    return targets


def _normalized_symbol_name(name: str) -> str:
    return name.lstrip("_").lower()


def _call_target_semantic_equivalence_reason(oracle_targets: list[dict[str, Any]], candidate_targets: list[dict[str, Any]]) -> str | None:
    for oracle_target in oracle_targets:
        for candidate_target in candidate_targets:
            oracle_block_hash = oracle_target.get("machine_code_sha256")
            candidate_block_hash = candidate_target.get("machine_code_sha256")
            oracle_block_size = oracle_target.get("machine_code_size")
            candidate_block_size = candidate_target.get("machine_code_size")
            if oracle_block_hash and oracle_block_hash == candidate_block_hash and oracle_block_size == candidate_block_size:
                return "direct call target entry blocks have identical machine code"
            oracle_semantic = oracle_target.get("semantic_ssa_id")
            candidate_semantic = candidate_target.get("semantic_ssa_id")
            if oracle_semantic and oracle_semantic == candidate_semantic:
                return "direct call target entry blocks have identical compact SSA"
    return None


def _mapped_call_target(oracle_id: str, oracle_name: str, mapping_document: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(mapping_document, dict) or mapping_document.get("schema") != "dosunit.mapping.v1":
        return None
    for item in mapping_document.get("functions", []) or []:
        if not isinstance(item, dict):
            continue
        if oracle_id and str(item.get("oracle_id") or "") == oracle_id:
            return item
        if oracle_name and str(item.get("oracle_name") or "") == oracle_name:
            return item
    return None


def _prepare_call_normalized_functions(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    call_compare: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    if not isinstance(call_compare, dict):
        return oracle_function, candidate_function, call_compare
    oracle_call = call_compare.get("oracle") if isinstance(call_compare.get("oracle"), dict) else None
    candidate_call = call_compare.get("candidate") if isinstance(call_compare.get("candidate"), dict) else None
    oracle_raw = _optional_int(oracle_call.get("raw")) if oracle_call is not None else None
    candidate_raw = _optional_int(candidate_call.get("raw")) if candidate_call is not None else None
    if oracle_raw is None or candidate_raw is None:
        return oracle_function, candidate_function, call_compare

    normalized = copy.deepcopy(call_compare)
    equivalent = bool(normalized.get("equivalent"))
    if equivalent:
        target_value = _canonical_call_target_value(normalized)
    else:
        target_value = None

    oracle_copy = _with_call_target_output(oracle_function, target_value if target_value is not None else oracle_raw)
    candidate_copy = _with_call_target_output(candidate_function, target_value if target_value is not None else candidate_raw)
    if equivalent:
        oracle_copy, oracle_return = _normalize_call_return_store(oracle_copy)
        candidate_copy, candidate_return = _normalize_call_return_store(candidate_copy)
        normalized["normalizations"] = [
            {"side": "oracle", **oracle_return},
            {"side": "candidate", **candidate_return},
        ]
    return oracle_copy, candidate_copy, normalized


def _prepare_layout_normalized_functions(
    oracle_function: dict[str, Any],
    candidate_function: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    pairs = _layout_constant_pairs(oracle_function, candidate_function)
    if not pairs:
        return oracle_function, candidate_function, None
    candidate_map: dict[int, int] = {}
    notes: list[dict[str, Any]] = []
    for pair in pairs:
        oracle_value = int(pair["oracle"])
        candidate_value = int(pair["candidate"])
        for candidate_key, oracle_replacement in _layout_constant_normalization_entries(pair):
            if candidate_key in candidate_map and candidate_map[candidate_key] != oracle_replacement:
                continue
            candidate_map[candidate_key] = oracle_replacement
        notes.append(
            {
                "oracle": normalize_hex(oracle_value, width=4),
                "candidate": normalize_hex(candidate_value, width=4),
                "reason": pair.get("reason"),
            }
        )
    if not candidate_map:
        return oracle_function, candidate_function, None
    candidate_copy = dict(candidate_function)
    candidate_copy["_constant_normalization"] = candidate_map
    return oracle_function, candidate_copy, {"kind": "layout_constants", "pairs": notes}


def _layout_constant_pairs(oracle_function: dict[str, Any], candidate_function: dict[str, Any]) -> list[dict[str, Any]]:
    oracle_instructions = _ssa_instructions(oracle_function)
    candidate_instructions = _ssa_instructions(candidate_function)
    if not oracle_instructions or len(oracle_instructions) != len(candidate_instructions):
        return []
    has_ivt_segment_store = any(
        _is_ivt_segment_store(oracle) and _is_ivt_segment_store(candidate)
        for oracle, candidate in zip(oracle_instructions, candidate_instructions)
    )
    data_segment_immediate_indexes = _data_segment_immediate_indexes(oracle_instructions, candidate_instructions)
    pairs: list[dict[str, Any]] = []
    memory_pairs: list[tuple[int, int]] = []
    deferred: list[dict[str, Any]] = []
    pointer_arithmetic_by_index = _pointer_arithmetic_evidence_by_index(oracle_instructions, candidate_instructions)
    for instruction_index, (oracle, candidate) in enumerate(zip(oracle_instructions, candidate_instructions)):
        instruction_pairs = _instruction_layout_constant_pairs(
            oracle,
            candidate,
            has_ivt_segment_store=has_ivt_segment_store,
            data_segment_immediate=instruction_index in data_segment_immediate_indexes,
            pointer_arithmetic_regs=pointer_arithmetic_by_index.get(instruction_index, set()),
        )
        for pair in instruction_pairs:
            if pair.get("reason") in {"memory_operand", "absolute_memory_operand"}:
                memory_pairs.append((int(pair["oracle"]), int(pair["candidate"])))
                pairs.append(pair)
            elif pair.get("reason") in {"pointer_immediate", "pointer_arithmetic", "ivt_segment", "data_segment_immediate"}:
                pairs.append(pair)
            else:
                deferred.append(pair)
    deltas = {((candidate - oracle) & 0xFFFF) for oracle, candidate in memory_pairs}
    for pair in deferred:
        oracle = int(pair["oracle"])
        candidate = int(pair["candidate"])
        if ((candidate - oracle) & 0xFFFF) in deltas:
            pair = dict(pair)
            pair["reason"] = "same_delta_address_base"
            pairs.append(pair)
    deferred_by_delta: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for pair in deferred:
        oracle = int(pair["oracle"])
        candidate = int(pair["candidate"])
        delta = (candidate - oracle) & 0xFFFF
        if delta in deltas:
            continue
        deferred_by_delta[delta].append(pair)
    for grouped in deferred_by_delta.values():
        if len(grouped) < 2:
            continue
        for pair in grouped:
            pair = dict(pair)
            pair["reason"] = "same_delta_constant_set"
            pairs.append(pair)
    return _unique_layout_pairs(pairs)


def _ssa_instructions(function: dict[str, Any]) -> list[dict[str, Any]]:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    return [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]


def _instruction_layout_constant_pairs(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    has_ivt_segment_store: bool,
    data_segment_immediate: bool,
    pointer_arithmetic_regs: set[str],
) -> list[dict[str, Any]]:
    if str(oracle.get("mnemonic", "")).lower() != str(candidate.get("mnemonic", "")).lower():
        return []
    oracle_op = str(oracle.get("op_str", "")).lower()
    candidate_op = str(candidate.get("op_str", "")).lower()
    if _number_template(oracle_op) != _number_template(candidate_op):
        return []
    oracle_numbers = _number_tokens(oracle_op)
    candidate_numbers = _number_tokens(candidate_op)
    if len(oracle_numbers) != len(candidate_numbers):
        return []
    pairs: list[dict[str, Any]] = []
    for index, (oracle_number, candidate_number) in enumerate(zip(oracle_numbers, candidate_numbers)):
        oracle_value = oracle_number & 0xFFFF
        candidate_value = candidate_number & 0xFFFF
        if oracle_value == candidate_value:
            continue
        reason = _layout_pair_reason(
            oracle_op,
            candidate_op,
            mnemonic=str(oracle.get("mnemonic", "")).lower(),
            index=index,
            has_ivt_segment_store=has_ivt_segment_store,
            data_segment_immediate=data_segment_immediate,
            pointer_arithmetic_regs=pointer_arithmetic_regs,
        )
        if reason not in {"absolute_memory_operand", "data_segment_immediate"} and not _looks_layout_constant(oracle_value, candidate_value):
            continue
        if reason is None:
            pairs.append(
                {
                    "oracle": oracle_value,
                    "candidate": candidate_value,
                    "oracle_raw": oracle_number,
                    "candidate_raw": candidate_number,
                    "reason": "deferred",
                }
            )
        else:
            pairs.append(
                {
                    "oracle": oracle_value,
                    "candidate": candidate_value,
                    "oracle_raw": oracle_number,
                    "candidate_raw": candidate_number,
                    "reason": reason,
                }
            )
    return pairs


NUMBER_RE = re.compile(r"(?P<sign>[+-])?\s*(?P<body>0x[0-9a-f]+|\d+)", re.IGNORECASE)


def _number_tokens(text: str) -> list[int]:
    values: list[int] = []
    for match in NUMBER_RE.finditer(text):
        body = match.group("body")
        value = int(body, 0)
        if match.group("sign") == "-":
            value = -value
        values.append(value)
    return values


def _number_template(text: str) -> str:
    template = NUMBER_RE.sub("#", text.lower())
    template = re.sub(r"([+-])\s*#", "#", template)
    template = re.sub(r"\s+", " ", template)
    return template.strip()


def _looks_layout_constant(oracle_value: int, candidate_value: int) -> bool:
    return oracle_value >= 0x1000 and candidate_value >= 0x1000


def _layout_pair_reason(
    oracle_op: str,
    candidate_op: str,
    *,
    mnemonic: str,
    index: int,
    has_ivt_segment_store: bool,
    data_segment_immediate: bool,
    pointer_arithmetic_regs: set[str],
) -> str | None:
    if _number_is_inside_memory_operand(oracle_op, index) and _number_is_inside_memory_operand(candidate_op, index):
        if _memory_operand_has_register(oracle_op) or _memory_operand_has_register(candidate_op):
            return "memory_operand"
        return "absolute_memory_operand"
    oracle_first = oracle_op.split(",", 1)[0].strip()
    candidate_first = candidate_op.split(",", 1)[0].strip()
    if mnemonic == "mov" and data_segment_immediate and oracle_first == candidate_first and oracle_first in {"ax", "bx", "cx", "dx"}:
        return "data_segment_immediate"
    if mnemonic in {"add", "sub"} and oracle_first == candidate_first and oracle_first in pointer_arithmetic_regs:
        return "pointer_arithmetic"
    if mnemonic in {"mov", "lea"} and oracle_first == candidate_first and oracle_first in {"si", "di", "bx", "bp"}:
        return "pointer_immediate"
    if mnemonic == "mov" and has_ivt_segment_store and oracle_first == candidate_first and oracle_first == "ax":
        return "ivt_segment"
    if _is_ivt_segment_store_operand(oracle_op) and _is_ivt_segment_store_operand(candidate_op):
        return "ivt_segment"
    return None


def _number_is_inside_memory_operand(text: str, index: int) -> bool:
    match = list(NUMBER_RE.finditer(text))[index]
    before = text[: match.start()]
    after = text[match.end() :]
    return before.rfind("[") > before.rfind("]") and after.find("]") != -1


def _is_ivt_segment_store(instruction: dict[str, Any]) -> bool:
    return _is_ivt_segment_store_operand(str(instruction.get("op_str", "")).lower())


def _is_ivt_segment_store_operand(op_str: str) -> bool:
    compact = op_str.replace(" ", "")
    return compact.startswith("wordptr") and "es:[2]" in compact


def _data_segment_immediate_indexes(
    oracle_instructions: list[dict[str, Any]],
    candidate_instructions: list[dict[str, Any]],
) -> set[int]:
    indexes: set[int] = set()
    for index in range(0, min(len(oracle_instructions), len(candidate_instructions)) - 1):
        oracle = oracle_instructions[index]
        candidate = candidate_instructions[index]
        if str(oracle.get("mnemonic", "")).lower() != "mov" or str(candidate.get("mnemonic", "")).lower() != "mov":
            continue
        oracle_operands = _split_operands(str(oracle.get("op_str", "")).lower())
        candidate_operands = _split_operands(str(candidate.get("op_str", "")).lower())
        if len(oracle_operands) != 2 or oracle_operands[0] != candidate_operands[0]:
            continue
        if oracle_operands[0] not in {"ax", "bx", "cx", "dx"}:
            continue
        if not _number_tokens(oracle_operands[1]) or not _number_tokens(candidate_operands[1]):
            continue
        if _is_mov_segment_from_register(oracle_instructions[index + 1], "ds", oracle_operands[0]) and _is_mov_segment_from_register(
            candidate_instructions[index + 1],
            "ds",
            candidate_operands[0],
        ):
            indexes.add(index)
    return indexes


def _is_mov_segment_from_register(instruction: dict[str, Any], segment: str, reg: str) -> bool:
    if str(instruction.get("mnemonic", "")).lower() != "mov":
        return False
    operands = _split_operands(str(instruction.get("op_str", "")).lower())
    return len(operands) == 2 and operands[0] == segment and operands[1] == reg


def _memory_operand_has_register(op_str: str) -> bool:
    for reg in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        if _register_used_inside_memory_operand(op_str, reg):
            return True
    return False


def _pointer_arithmetic_evidence_by_index(
    oracle_instructions: list[dict[str, Any]],
    candidate_instructions: list[dict[str, Any]],
) -> dict[int, set[str]]:
    evidence: dict[int, set[str]] = {}
    for index, (oracle, candidate) in enumerate(zip(oracle_instructions, candidate_instructions)):
        oracle_reg = _pointer_arithmetic_destination_register(oracle)
        candidate_reg = _pointer_arithmetic_destination_register(candidate)
        if oracle_reg is None or oracle_reg != candidate_reg:
            continue
        if _register_used_as_memory_base_later(oracle_instructions, index + 1, oracle_reg) and _register_used_as_memory_base_later(
            candidate_instructions,
            index + 1,
            candidate_reg,
        ):
            evidence.setdefault(index, set()).add(oracle_reg)
    return evidence


def _pointer_arithmetic_destination_register(instruction: dict[str, Any]) -> str | None:
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    if mnemonic not in {"add", "sub"}:
        return None
    operands = _split_operands(str(instruction.get("op_str", "")).lower())
    if len(operands) != 2:
        return None
    destination = operands[0].strip()
    source = operands[1].strip()
    if destination not in {"bx", "bp", "si", "di"}:
        return None
    if "[" in source or "]" in source or not _number_tokens(source):
        return None
    return destination


def _register_used_as_memory_base_later(instructions: list[dict[str, Any]], start_index: int, reg: str) -> bool:
    for instruction in instructions[start_index:]:
        op_str = str(instruction.get("op_str", "")).lower()
        if _register_used_inside_memory_operand(op_str, reg):
            return True
        if _instruction_overwrites_register(instruction, reg):
            return False
    return False


def _register_used_inside_memory_operand(op_str: str, reg: str) -> bool:
    pattern = re.compile(rf"\[[^\]]*\b{re.escape(reg)}\b[^\]]*\]")
    return pattern.search(op_str) is not None


def _instruction_overwrites_register(instruction: dict[str, Any], reg: str) -> bool:
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    operands = _split_operands(str(instruction.get("op_str", "")).lower())
    if not operands:
        return False
    destination = operands[0].strip()
    if destination != reg:
        return False
    return mnemonic not in {"cmp", "test", "push"}


def _split_operands(op_str: str) -> list[str]:
    operands: list[str] = []
    current: list[str] = []
    bracket_depth = 0
    for char in op_str:
        if char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth > 0:
            bracket_depth -= 1
        if char == "," and bracket_depth == 0:
            operands.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current or op_str:
        operands.append("".join(current).strip())
    return operands


def _unique_layout_pairs(pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[int, int]] = set()
    unique: list[dict[str, Any]] = []
    for pair in pairs:
        key = (int(pair["oracle"]), int(pair["candidate"]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(pair)
    return unique


def _layout_constant_normalization_entries(pair: dict[str, Any]) -> list[tuple[int, int]]:
    oracle_raw = int(pair.get("oracle_raw", pair["oracle"]))
    candidate_raw = int(pair.get("candidate_raw", pair["candidate"]))
    oracle_low = oracle_raw & 0xFFFF
    candidate_low = candidate_raw & 0xFFFF
    entries = [(candidate_low, oracle_low)]
    if candidate_raw < 0 or candidate_low >= 0x8000:
        signed_candidate = candidate_raw & 0xFFFFFFFF if candidate_raw < 0 else (candidate_low | 0xFFFF0000)
        signed_oracle = (oracle_raw & 0xFFFFFFFF) if oracle_raw < 0 else oracle_low
        entries.append((signed_candidate, signed_oracle))
    return _unique_int_pairs(entries)


def _unique_int_pairs(values: list[tuple[int, int]]) -> list[tuple[int, int]]:
    seen: set[tuple[int, int]] = set()
    unique: list[tuple[int, int]] = []
    for left, right in values:
        pair = (int(left), int(right))
        if pair in seen:
            continue
        seen.add(pair)
        unique.append(pair)
    return unique


def _with_call_target_output(function: dict[str, Any], target_value: int) -> dict[str, Any]:
    document = copy.deepcopy(function)
    outputs = dict(document.get("outputs", {}) if isinstance(document.get("outputs"), dict) else {})
    outputs["call_target"] = {"op": "const", "value": normalize_hex(target_value & 0xFFFFFFFF, width=8), "width": 32}
    document["outputs"] = outputs
    return document


def _canonical_call_target_value(call_compare: dict[str, Any]) -> int:
    oracle = call_compare.get("oracle") if isinstance(call_compare.get("oracle"), dict) else {}
    resolved = oracle.get("resolved") if isinstance(oracle.get("resolved"), dict) else {}
    key = str(resolved.get("id") or resolved.get("name") or oracle.get("raw") or "unknown-call-target")
    return int(hashlib.sha256(f"call-target:{key}".encode("utf-8")).hexdigest()[:8], 16)


def _normalize_call_return_store(function: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    outputs = function.get("outputs", {}) if isinstance(function.get("outputs"), dict) else {}
    memory = outputs.get("memory") if isinstance(outputs.get("memory"), dict) else None
    ref = memory.get("ref") if isinstance(memory, dict) else None
    if not isinstance(ref, str):
        return function, {"applied": False, "reason": "no memory output store to normalize"}
    assignments = list(function.get("assignments", []) or [])
    index = next((idx for idx, item in enumerate(assignments) if isinstance(item, dict) and item.get("id") == ref), None)
    if index is None:
        return function, {"applied": False, "reason": "memory output assignment was not found"}
    store = assignments[index]
    if store.get("op") not in {"storele", "storebe"}:
        return function, {"applied": False, "reason": "memory output is not a final store"}
    args = list(store.get("args", []) or [])
    if len(args) < 3:
        return function, {"applied": False, "reason": "final store has no stored value operand"}
    value = _term_const_int(args[2])
    fallthrough = _call_fallthrough_linear(function)
    if value is None or fallthrough is None:
        return function, {"applied": False, "reason": "final store value or call fall-through was not constant"}
    width = int(args[2].get("width", 16)) if isinstance(args[2], dict) else 16
    mask = _mask(width)
    if (value & mask) != (fallthrough & mask):
        return function, {
            "applied": False,
            "reason": "final store constant did not match the call fall-through address",
            "stored": normalize_hex(value),
            "fallthrough": normalize_hex(fallthrough),
        }
    normalized_store = dict(store)
    args[2] = {"op": "const", "value": normalize_hex(0, width=max(1, width // 4)), "width": width}
    normalized_store["args"] = args
    assignments[index] = normalized_store
    function = dict(function)
    function["assignments"] = assignments
    return function, {
        "applied": True,
        "reason": "normalized layout-dependent call return address store",
        "stored": normalize_hex(value),
        "fallthrough": normalize_hex(fallthrough),
    }


def _call_fallthrough_linear(function: dict[str, Any]) -> int | None:
    source = function.get("source", {}) if isinstance(function.get("source"), dict) else {}
    transfer = source.get("transfer") if isinstance(source.get("transfer"), dict) else None
    if transfer:
        fallthrough = transfer.get("fallthrough") if isinstance(transfer.get("fallthrough"), dict) else None
        value = _optional_int(fallthrough.get("linear")) if fallthrough is not None else None
        if value is not None:
            return value
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    if not instructions:
        return None
    instruction = instructions[-1]
    address = instruction.get("address", {}) if isinstance(instruction.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(instruction.get("size"))
    if linear is None or size is None:
        return None
    return linear + size


def _term_const_int(term: dict[str, Any] | None) -> int | None:
    if not isinstance(term, dict) or term.get("op") != "const":
        return None
    return _optional_int(term.get("value"))


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return parse_int(value, field="value")
    except DosUnitError:
        return None
    except (TypeError, ValueError):
        return None


def _z3_inputs(oracle: dict[str, Any], candidate: dict[str, Any], z3: Any) -> dict[str, tuple[Any, int]]:
    widths: dict[str, int] = {}
    memory_inputs: set[str] = set()
    for document in (oracle, candidate):
        for item in document.get("inputs", []) or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            if item.get("kind") == "memory":
                memory_inputs.add(str(item["name"]))
            else:
                widths[str(item["name"])] = max(int(item.get("width", 16)), widths.get(str(item["name"]), 0))
    inputs = {name: (z3.BitVec(name, width), width) for name, width in sorted(widths.items())}
    for name in sorted(memory_inputs):
        inputs[name] = (z3.Array(name, z3.BitVecSort(32), z3.BitVecSort(8)), 0)
    return inputs


def _z3_term(term: dict[str, Any], *, document: dict[str, Any], inputs: dict[str, tuple[Any, int]], z3: Any) -> Any:
    if "ref" in term:
        assignments = {item["id"]: item for item in document.get("assignments", []) or [] if isinstance(item, dict) and "id" in item}
        return _z3_assignment(str(term["ref"]), assignments=assignments, document=document, inputs=inputs, z3=z3, cache={})
    op = term.get("op")
    width = int(term.get("width", 16))
    if op == "input":
        return _resize_z3(inputs[str(term["name"])][0], inputs[str(term["name"])][1], width, signed=False, z3=z3)
    if op == "mem_input":
        return inputs[str(term["name"])][0]
    if op == "const":
        value = parse_int(term.get("value"), field="ssa.const")
        value = _normalized_constant_value(value, width=width, document=document)
        return z3.BitVecVal(value, width)
    raise DosUnitError(f"unsupported SSA term: {term}")


def _z3_assignment(
    ident: str,
    *,
    assignments: dict[str, dict[str, Any]],
    document: dict[str, Any],
    inputs: dict[str, tuple[Any, int]],
    z3: Any,
    cache: dict[str, Any],
) -> Any:
    if ident in cache:
        return cache[ident]
    item = assignments[ident]
    op = str(item.get("op"))
    width = int(item.get("width", 16))
    args = [_z3_term(arg, document={**document, "assignments": list(assignments.values())}, inputs=inputs, z3=z3) for arg in item.get("args", []) or []]
    result = _z3_apply(op, width, args, z3)
    cache[ident] = result
    return result


def _z3_apply(op: str, width: int, args: list[Any], z3: Any) -> Any:
    if op == "add":
        return _resize_z3(args[0] + args[1], args[0].size(), width, signed=False, z3=z3)
    if op == "sub":
        return _resize_z3(args[0] - args[1], args[0].size(), width, signed=False, z3=z3)
    if op == "mul":
        return _resize_z3(args[0] * args[1], args[0].size(), width, signed=False, z3=z3)
    if op == "umull":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3) * _resize_z3(args[1], args[1].size(), width, signed=False, z3=z3)
    if op == "smull":
        return _resize_z3(args[0], args[0].size(), width, signed=True, z3=z3) * _resize_z3(args[1], args[1].size(), width, signed=True, z3=z3)
    if op == "udiv":
        return z3.UDiv(args[0], args[1])
    if op == "sdiv":
        return args[0] / args[1]
    if op == "urem":
        return z3.URem(args[0], args[1])
    if op == "srem":
        return z3.SRem(args[0], args[1])
    if op == "and":
        return args[0] & args[1]
    if op == "or":
        return args[0] | args[1]
    if op == "xor":
        return args[0] ^ args[1]
    if op == "not":
        return ~args[0]
    if op == "concat":
        return z3.Concat(*args)
    if op == "shl":
        return _resize_z3(args[0] << _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3), args[0].size(), width, signed=False, z3=z3)
    if op == "lshr":
        return z3.LShR(args[0], _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3))
    if op == "ashr":
        return args[0] >> _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3)
    if op == "eq":
        return z3.If(args[0] == args[1], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "ne":
        return z3.If(args[0] != args[1], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "ult":
        return z3.If(z3.ULT(args[0], args[1]), z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "ule":
        return z3.If(z3.ULE(args[0], args[1]), z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "ugt":
        return z3.If(z3.UGT(args[0], args[1]), z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "uge":
        return z3.If(z3.UGE(args[0], args[1]), z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "slt":
        return z3.If(args[0] < args[1], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "sle":
        return z3.If(args[0] <= args[1], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "sgt":
        return z3.If(args[0] > args[1], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "sge":
        return z3.If(args[0] >= args[1], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "zext":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3)
    if op == "sext":
        return _resize_z3(args[0], args[0].size(), width, signed=True, z3=z3)
    if op == "trunc":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3)
    if op == "ite":
        return z3.If(args[0] != z3.BitVecVal(0, args[0].size()), args[1], args[2])
    if op == "loadle":
        return _z3_load(args[0], args[1], width=width, little_endian=True, z3=z3)
    if op == "loadbe":
        return _z3_load(args[0], args[1], width=width, little_endian=False, z3=z3)
    if op == "storele":
        return _z3_store(args[0], args[1], args[2], little_endian=True, z3=z3)
    if op == "storebe":
        return _z3_store(args[0], args[1], args[2], little_endian=False, z3=z3)
    raise DosUnitError(f"unsupported SSA op: {op}")


def _z3_load(memory: Any, address: Any, *, width: int, little_endian: bool, z3: Any) -> Any:
    if width % 8 != 0:
        raise DosUnitError(f"memory load width must be byte-addressable: {width}")
    address = _resize_z3(address, address.size(), 32, signed=False, z3=z3)
    bytes_ = [z3.Select(memory, address + z3.BitVecVal(index, 32)) for index in range(width // 8)]
    ordered = list(reversed(bytes_)) if little_endian else bytes_
    if len(ordered) == 1:
        return ordered[0]
    return z3.Concat(*ordered)


def _z3_store(memory: Any, address: Any, value: Any, *, little_endian: bool, z3: Any) -> Any:
    width = int(value.size())
    if width % 8 != 0:
        raise DosUnitError(f"memory store width must be byte-addressable: {width}")
    address = _resize_z3(address, address.size(), 32, signed=False, z3=z3)
    stored = memory
    byte_count = width // 8
    for index in range(byte_count):
        source_index = index if little_endian else byte_count - index - 1
        byte = z3.Extract(source_index * 8 + 7, source_index * 8, value)
        stored = z3.Store(stored, address + z3.BitVecVal(index, 32), byte)
    return stored


def _resize_z3(value: Any, from_width: int, to_width: int, *, signed: bool, z3: Any) -> Any:
    if from_width == to_width:
        return value
    if from_width > to_width:
        return z3.Extract(to_width - 1, 0, value)
    extend = z3.SignExt if signed else z3.ZeroExt
    return extend(to_width - from_width, value)


def _align_z3_widths(left: Any, right: Any, z3: Any) -> tuple[Any, Any]:
    left_width = int(left.size())
    right_width = int(right.size())
    width = max(left_width, right_width)
    return _resize_z3(left, left_width, width, signed=False, z3=z3), _resize_z3(right, right_width, width, signed=False, z3=z3)


def _normalized_constant_value(value: int, *, width: int, document: dict[str, Any]) -> int:
    normalization = document.get("_constant_normalization")
    if not isinstance(normalization, dict):
        return value
    mask = _mask(width)
    key = value & mask
    if key not in normalization:
        return value
    return int(normalization[key]) & mask


def _coerce_width(expr: SsaExpr, width: int) -> SsaExpr:
    if expr.width == width:
        return expr
    if expr.width < width:
        return SsaExpr("zext", width, (expr,))
    return SsaExpr("trunc", width, (expr,))


def _expr_failure(expr: SsaExpr) -> LowerFailure | None:
    if expr.op == "unsupported":
        if expr.name and "|" in expr.name:
            reason, message = expr.name.split("|", 1)
            return LowerFailure(reason, message)
        return LowerFailure("unsupported_ir", expr.name or "unsupported expression reached output slice")
    for arg in expr.args:
        failure = _expr_failure(arg)
        if failure is not None:
            return failure
    return None


def _collect_inputs(expressions: Any) -> set[str]:
    found: set[str] = set()
    for expr in expressions:
        if expr.op in {"input", "mem_input"} and expr.name:
            found.add(expr.name)
        found.update(_collect_inputs(expr.args))
    return found


def _input_items(inputs: set[str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    reg_widths = {name: width for _offset, (name, width) in REG_BY_OFFSET.items()}
    for name in sorted(inputs):
        if name == "mem":
            items.append({"kind": "memory", "name": "mem", "addr_width": 32, "value_width": 8})
            continue
        width = reg_widths.get(name)
        if width is not None:
            items.append({"name": name, "width": width})
    return items


def _strip_iop(op: str) -> str:
    return op[4:] if op.startswith("Iop_") else op


def _strip_width_suffix(op: str) -> str:
    while op and op[-1].isdigit():
        op = op[:-1]
    return op


def _normalize_binop(op: str) -> str:
    if op.startswith("CmpLT") and op.endswith("U"):
        return "CmpLTU"
    if op.startswith("CmpLE") and op.endswith("U"):
        return "CmpLEU"
    if op.startswith("CmpGT") and op.endswith("U"):
        return "CmpGTU"
    if op.startswith("CmpGE") and op.endswith("U"):
        return "CmpGEU"
    if op.startswith("CmpLT") and op.endswith("S"):
        return "CmpLTS"
    if op.startswith("CmpLE") and op.endswith("S"):
        return "CmpLES"
    if op.startswith("CmpGT") and op.endswith("S"):
        return "CmpGTS"
    if op.startswith("CmpGE") and op.endswith("S"):
        return "CmpGES"
    return _strip_width_suffix(op)


def _mask(width: int) -> int:
    return (1 << width) - 1


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _vex_cache_file(*, cache_dir: Path, exe_digest: str) -> Path:
    return cache_dir / "vex" / f"{exe_digest}.pickle"


def _new_vex_cache(exe_digest: str) -> dict[str, Any]:
    return {
        "schema": LIFTER_CACHE_SCHEMA,
        "flavor": "vex",
        "exe_sha256": exe_digest,
        "entries": {},
    }


def _load_vex_cache(*, cache_dir: Path, exe_digest: str) -> dict[str, Any]:
    path = _vex_cache_file(cache_dir=cache_dir, exe_digest=exe_digest)
    if not path.exists():
        return _new_vex_cache(exe_digest)
    try:
        with path.open("rb") as handle:
            document = pickle.load(handle)
    except Exception:  # noqa: BLE001
        return _new_vex_cache(exe_digest)
    if not isinstance(document, dict):
        return _new_vex_cache(exe_digest)
    if document.get("schema") != LIFTER_CACHE_SCHEMA or document.get("flavor") != "vex" or document.get("exe_sha256") != exe_digest:
        return _new_vex_cache(exe_digest)
    if not isinstance(document.get("entries"), dict):
        document["entries"] = {}
    return document


def _save_vex_cache(*, cache_dir: Path, exe_digest: str, cache_document: dict[str, Any]) -> None:
    path = _vex_cache_file(cache_dir=cache_dir, exe_digest=exe_digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(cache_document)
    payload.pop("_dirty", None)
    tmp = path.with_name(f"{path.name}.tmp")
    with tmp.open("wb") as handle:
        pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, path)


def _vex_cache_key(*, start: int, size: int, opt_level: int) -> str:
    return f"{start:08x}:{size:04x}:opt{opt_level}"


def _lift_vex_block_cached(
    *,
    project: Any,
    exe_path: Path,
    exe_digest: str,
    start: int,
    size: int,
    opt_level: int,
    cache_document: dict[str, Any] | None,
    cache_stats: dict[str, int],
) -> LiftedBlock:
    del exe_path
    key = _vex_cache_key(start=start, size=size, opt_level=opt_level)
    entries = cache_document.get("entries", {}) if isinstance(cache_document, dict) else {}
    if isinstance(entries, dict) and key in entries:
        entry = entries.get(key)
        if isinstance(entry, dict) and entry.get("exe_sha256") == exe_digest and "irsb" in entry and isinstance(entry.get("instructions"), list):
            cache_stats["hits"] += 1
            return LiftedBlock(irsb=entry["irsb"], instructions=list(entry["instructions"]), lifted=False)
        cache_stats["errors"] += 1

    if cache_document is not None:
        cache_stats["misses"] += 1
    block = project.factory.block(start, size=size, opt_level=opt_level)
    lifted = LiftedBlock(
        irsb=block.vex,
        instructions=[_instruction_record(item.insn) for item in block.capstone.insns],
        lifted=True,
    )
    if cache_document is not None:
        cache_document.setdefault("entries", {})[key] = {
            "exe_sha256": exe_digest,
            "start": start,
            "size": size,
            "opt_level": opt_level,
            "irsb": lifted.irsb,
            "instructions": lifted.instructions,
        }
        cache_document["_dirty"] = True
        cache_stats["writes"] += 1
    return lifted


def _functions_by_name_and_ordinal(functions: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    counts: dict[str, int] = defaultdict(int)
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for function in functions:
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = function_name or function_id
        ordinal = counts[key]
        counts[key] += 1
        indexed[(key, ordinal)] = function
    return indexed


def _ssa_part_index(function: dict[str, Any]) -> int:
    part = function.get("part") if isinstance(function.get("part"), dict) else {}
    value = part.get("index")
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _ssa_part_delta(function: dict[str, Any]) -> str:
    part = function.get("part") if isinstance(function.get("part"), dict) else {}
    value = part.get("entry_delta")
    if value is None:
        return ""
    try:
        return normalize_hex(parse_int(value, field="ssa.part.entry_delta") & 0xFFFF, width=4)
    except DosUnitError:
        return str(value)


def _functions_by_name_and_part(functions: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = function_name or function_id
        indexed.setdefault((key, _ssa_part_index(function)), function)
    return indexed


def _functions_by_name_and_delta(functions: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        delta = _ssa_part_delta(function)
        if not delta:
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = function_name or function_id
        indexed.setdefault((key, delta), function)
    return indexed


def _functions_by_id_and_part(functions: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if function_id:
            indexed.setdefault((function_id, _ssa_part_index(function)), function)
    return indexed


def _functions_by_id_and_delta(functions: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        delta = _ssa_part_delta(function)
        if not delta:
            continue
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if function_id:
            indexed.setdefault((function_id, delta), function)
    return indexed


def _functions_by_id(functions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for function in functions:
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if function_id:
            indexed[function_id] = function
    return indexed


def _ssa_candidate_mapping(mapping_document: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(mapping_document, dict) or mapping_document.get("schema") != "dosunit.mapping.v1":
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for item in mapping_document.get("functions", []) or []:
        if not isinstance(item, dict):
            continue
        oracle_id = item.get("oracle_id")
        oracle_name = item.get("oracle_name")
        if oracle_id is not None:
            indexed[str(oracle_id)] = item
        if oracle_name is not None:
            indexed[str(oracle_name)] = item
    return indexed


def _instruction_disassembly(insn: Any) -> str:
    mnemonic = str(insn.mnemonic).lower()
    op_str = str(insn.op_str).lower()
    return mnemonic if not op_str else f"{mnemonic} {op_str}"


def _instruction_record(insn: Any) -> dict[str, Any]:
    mnemonic = str(insn.mnemonic).lower()
    op_str = str(insn.op_str).lower()
    machine_code = bytes(getattr(insn, "bytes", b""))
    return {
        "linear": int(insn.address),
        "size": int(insn.size),
        "mnemonic": mnemonic,
        "op_str": op_str,
        "bytes": machine_code.hex(),
    }


def _instruction_text_from_record(record: dict[str, Any], *, function_base: int) -> dict[str, Any]:
    linear = parse_int(record.get("linear", 0), field="instruction.linear")
    mnemonic = str(record.get("mnemonic", "")).lower()
    op_str = str(record.get("op_str", "")).lower()
    return {
        "address": {
            "ip": normalize_hex((linear - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(linear),
        },
        "size": parse_int(record.get("size", 0), field="instruction.size"),
        "mnemonic": mnemonic,
        "op_str": op_str,
        "disassembly": mnemonic if not op_str else f"{mnemonic} {op_str}",
        "bytes": str(record.get("bytes", "")),
    }


def _instruction_text(insn: Any, *, function_base: int) -> dict[str, Any]:
    mnemonic = str(insn.mnemonic).lower()
    op_str = str(insn.op_str).lower()
    return {
        "address": {
            "ip": normalize_hex((int(insn.address) - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(int(insn.address)),
        },
        "size": int(insn.size),
        "mnemonic": mnemonic,
        "op_str": op_str,
        "disassembly": mnemonic if not op_str else f"{mnemonic} {op_str}",
    }


def _transfer_info(irsb: Any, instructions: list[dict[str, Any]]) -> dict[str, Any] | None:
    jumpkind = str(getattr(irsb, "jumpkind", ""))
    if jumpkind != "Ijk_Call":
        return None
    info: dict[str, Any] = {"kind": "direct_call", "jumpkind": jumpkind}
    target = _const_expr_value(getattr(irsb, "next", None))
    if target is None:
        target = _direct_call_target_from_instructions({"instructions": instructions})
    if target is not None:
        info["target"] = {
            "raw": normalize_hex(target),
            "low16": normalize_hex(target & 0xFFFF, width=4),
        }
    fallthrough = _call_fallthrough_linear_from_instructions(instructions)
    if fallthrough is not None:
        info["fallthrough"] = {
            "linear": normalize_hex(fallthrough),
            "low16": normalize_hex(fallthrough & 0xFFFF, width=4),
        }
    return info


def _transfer_info_from_instructions(source: dict[str, Any]) -> dict[str, Any] | None:
    if source.get("jumpkind") != "Ijk_Call":
        return None
    instructions = [item for item in source.get("instructions", []) or [] if isinstance(item, dict)]
    target = _direct_call_target_from_instructions(source)
    fallthrough = _call_fallthrough_linear_from_instructions(instructions)
    if target is None and fallthrough is None:
        return None
    info: dict[str, Any] = {"kind": "direct_call", "jumpkind": "Ijk_Call"}
    if target is not None:
        info["target"] = {
            "raw": normalize_hex(target),
            "low16": normalize_hex(target & 0xFFFF, width=4),
        }
    if fallthrough is not None:
        info["fallthrough"] = {
            "linear": normalize_hex(fallthrough),
            "low16": normalize_hex(fallthrough & 0xFFFF, width=4),
        }
    return info


def _call_fallthrough_linear_from_instructions(instructions: list[dict[str, Any]]) -> int | None:
    if not instructions:
        return None
    instruction = instructions[-1]
    address = instruction.get("address", {}) if isinstance(instruction.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(instruction.get("size"))
    if linear is None or size is None:
        return None
    return linear + size


def _ssa_block_successors(irsb: Any, instructions: list[dict[str, Any]]) -> list[int]:
    jumpkind = str(getattr(irsb, "jumpkind", ""))
    if jumpkind == "Ijk_Call" or jumpkind.startswith("Ijk_Ret") or jumpkind.startswith("Ijk_Sig"):
        return []
    if jumpkind != "Ijk_Boring":
        return []
    if not _last_instruction_is_control(instructions):
        return []
    successors: list[int] = []
    successors.extend(_direct_instruction_successors(instructions))
    for statement in getattr(irsb, "statements", []) or []:
        if getattr(statement, "tag", None) != "Ist_Exit":
            continue
        target = _const_expr_value(getattr(statement, "dst", None))
        if target is not None:
            successors.append(target)
    next_target = _const_expr_value(getattr(irsb, "next", None))
    if next_target is not None:
        successors.append(next_target)
    return _unique_ints(successors)


def _is_incomplete_noncontrol_block(irsb: Any, instructions: list[dict[str, Any]]) -> bool:
    if str(getattr(irsb, "jumpkind", "")) != "Ijk_Boring":
        return False
    return not _last_instruction_is_control(instructions)


def _last_instruction_is_control(instructions: list[dict[str, Any]]) -> bool:
    if not instructions:
        return False
    return str(instructions[-1].get("mnemonic", "")).lower() in CONTROL_MNEMONICS


def _direct_instruction_successors(instructions: list[dict[str, Any]]) -> list[int]:
    if not instructions:
        return []
    instruction = instructions[-1]
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    if mnemonic not in CONTROL_MNEMONICS:
        return []
    if mnemonic in {"call", "lcall", "int"}:
        return []
    address = instruction.get("address", {}) if isinstance(instruction.get("address"), dict) else {}
    linear = _optional_int(address.get("linear"))
    size = _optional_int(instruction.get("size"))
    target = _direct_control_target_from_instruction(instruction)
    if mnemonic in {"jmp", "ljmp"}:
        return [] if target is None else [target]
    if mnemonic in CONDITIONAL_JUMP_MNEMONICS:
        successors: list[int] = []
        if target is not None:
            successors.append(target)
        if linear is not None and size is not None:
            successors.append(linear + size)
        return successors
    return []


def _direct_control_target_from_instruction(instruction: dict[str, Any]) -> int | None:
    operand = str(instruction.get("op_str") or _operand_from_disassembly(instruction)).strip().lower()
    if not operand or any(token in operand for token in ("[", "]", ",", ":")):
        return None
    if operand.startswith("short "):
        operand = operand[6:].strip()
    if operand.startswith("near "):
        operand = operand[5:].strip()
    if operand.startswith("far "):
        operand = operand[4:].strip()
    return _optional_int(operand)


def _machine_code_bytes(instructions: list[dict[str, Any]]) -> bytes | None:
    chunks: list[bytes] = []
    for instruction in instructions:
        raw = instruction.get("bytes") if isinstance(instruction, dict) else None
        if not isinstance(raw, str) or not raw:
            return None
        try:
            chunks.append(bytes.fromhex(raw))
        except ValueError:
            return None
    return b"".join(chunks)


def _machine_code_sha256(instructions: list[dict[str, Any]]) -> str | None:
    return _bytes_sha256(_machine_code_bytes(instructions))


def _machine_code_size(instructions: list[dict[str, Any]]) -> int | None:
    data = _machine_code_bytes(instructions)
    return None if data is None else len(data)


def _loader_bytes(project: Any, start: int, size: int) -> bytes | None:
    try:
        return bytes(project.loader.memory.load(start, size))
    except Exception:  # noqa: BLE001
        return None


def _bytes_sha256(data: bytes | None) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def _unique_ints(values: list[int]) -> list[int]:
    seen: set[int] = set()
    unique: list[int] = []
    for value in values:
        value = int(value)
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _quick_compare_functions(
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    *,
    skip_binary_equal: bool,
) -> dict[str, Any] | None:
    oracle_source = oracle.get("source", {}) if isinstance(oracle.get("source"), dict) else {}
    candidate_source = candidate.get("source", {}) if isinstance(candidate.get("source"), dict) else {}
    if skip_binary_equal:
        for hash_key, size_key, reason in (
            ("function_machine_code_sha256", "function_machine_code_size", "binary_equal"),
            ("machine_code_sha256", "machine_code_size", "block_binary_equal"),
        ):
            oracle_hash = oracle_source.get(hash_key)
            candidate_hash = candidate_source.get(hash_key)
            oracle_size = oracle_source.get(size_key)
            candidate_size = candidate_source.get(size_key)
            if oracle_hash and candidate_hash and oracle_hash == candidate_hash and oracle_size == candidate_size:
                return {"status": "passed", "reason": reason, "mismatches": []}
    if _semantic_ssa_payload(oracle) == _semantic_ssa_payload(candidate):
        return {"status": "passed", "reason": "ssa_equal", "mismatches": []}
    return None


def _semantic_ssa_payload(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "inputs": function.get("inputs", []),
        "outputs": function.get("outputs", {}),
        "assignments": function.get("assignments", []),
    }


def _const_expr_value(expr: Any) -> int | None:
    if expr is None:
        return None
    if not hasattr(expr, "tag") and hasattr(expr, "size") and hasattr(expr, "value"):
        return int(expr.value)
    if getattr(expr, "tag", None) == "Iex_Const" and hasattr(expr, "con"):
        return int(expr.con.value)
    return None


def _mnemonic_from_disassembly(instruction: dict[str, Any]) -> str:
    disassembly = str(instruction.get("disassembly", "")).strip()
    return disassembly.split(None, 1)[0] if disassembly else ""


def _operand_from_disassembly(instruction: dict[str, Any]) -> str:
    disassembly = str(instruction.get("disassembly", "")).strip()
    parts = disassembly.split(None, 1)
    return parts[1] if len(parts) == 2 else ""


def _refusal(function: dict[str, Any], reason: str, message: str) -> dict[str, Any]:
    return {
        "status": "refused",
        "reason": reason,
        "detail": {
            "function_id": function.get("id"),
            "strategy": "straightline_ssa",
            "message": message,
        },
    }


def _refusal_counts(refusals: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in refusals:
        reason = str(item.get("reason", "unknown"))
        counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))
