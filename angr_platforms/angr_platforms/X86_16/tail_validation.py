from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import MutableMapping
from dataclasses import asdict, dataclass
from typing import Callable, Mapping, Sequence, TypeVar

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CDoWhileLoop,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfBreak,
    CIfElse,
    CReturn,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from .tail_validation_condition_context import build_x86_16_contextual_condition_fingerprints
from .tail_validation_fingerprint import (
    TAIL_VALIDATION_FINGERPRINT_VERSION,
    _bool_projection_fingerprint,
    _c_constant_int_value,
    _expr_fingerprint,
    _call_target_name,
    _extract_same_zero_compare_expr_8616,
    _extract_zero_flag_source_expr_8616,
    _location_fingerprint,
    _normalize_zero_flag_comparison_8616,
    _register_name,
    _wrap_not_fingerprint,
)
from .tail_validation_stack_policy import include_x86_16_tail_validation_stack_write
from .tail_validation_routing import build_tail_validation_family_routing

__all__ = [
    "X86_16TailValidationSummary",
    "X86_16ValidationCacheDescriptor",
    "annotate_x86_16_tail_validation_surface_with_baseline",
    "build_x86_16_tail_validation_aggregate",
    "build_x86_16_tail_validation_baseline",
    "build_x86_16_tail_validation_surface",
    "build_x86_16_tail_validation_cached_result",
    "build_x86_16_validation_cache_descriptor",
    "check_x86_16_tail_validation_surface_consistency",
    "compare_x86_16_tail_validation_baseline",
    "persist_x86_16_tail_validation_snapshot",
    "fingerprint_x86_16_tail_validation_boundary",
    "extract_x86_16_tail_validation_snapshot",
    "x86_16_tail_validation_snapshot_passed",
    "resolve_x86_16_validation_cached_artifact",
    "summarize_x86_16_tail_validation_records",
    "collect_x86_16_tail_validation_summary",
    "compare_x86_16_tail_validation_summaries",
    "build_x86_16_tail_validation_verdict",
    "format_x86_16_tail_validation_diff",
    "describe_x86_16_tail_validation_scope",
]

_TAIL_VALIDATION_MODES = {"coarse", "live_out"}
_TAIL_VALIDATION_AGGREGATE_CACHE: dict[str, dict[str, object]] = {}
_T = TypeVar("_T")
_TAIL_VALIDATION_OBSERVABLE_FIELDS = (
    "helper_calls",
    "register_writes",
    "stack_writes",
    "global_writes",
    "segmented_writes",
    "returns",
    "conditions",
    "control_flow_effects",
)


@dataclass(frozen=True, slots=True)
class X86_16TailValidationSummary:
    helper_calls: tuple[str, ...]
    register_writes: tuple[str, ...]
    stack_writes: tuple[str, ...]
    global_writes: tuple[str, ...]
    segmented_writes: tuple[str, ...]
    returns: tuple[str, ...]
    conditions: tuple[str, ...]
    control_flow_effects: tuple[str, ...]

    def as_dict(self) -> dict[str, tuple[str, ...]]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class X86_16ValidationCacheDescriptor:
    namespace: str
    fingerprint: str
    cache_key: str


def build_x86_16_validation_cache_descriptor(namespace: str, payload: object) -> X86_16ValidationCacheDescriptor:
    fingerprint = _json_fingerprint({"namespace": namespace, "payload": payload})
    return X86_16ValidationCacheDescriptor(
        namespace=namespace,
        fingerprint=fingerprint,
        cache_key=f"{namespace}:{fingerprint}",
    )


def resolve_x86_16_validation_cached_artifact(
    *,
    cache: MutableMapping[str, object] | None,
    descriptor: X86_16ValidationCacheDescriptor,
    build: Callable[[], _T],
    clone_on_hit: Callable[[_T], _T] | None = None,
    store_value: Callable[[_T], object] | None = None,
) -> dict[str, object]:
    if cache is not None:
        cached = cache.get(descriptor.cache_key)
        if cached is not None:
            value = clone_on_hit(cached) if clone_on_hit is not None else cached
            return {
                "cache_key": descriptor.cache_key,
                "cache_hit": True,
                "fingerprint": descriptor.fingerprint,
                "value": value,
            }

    value = build()
    if cache is not None:
        cache[descriptor.cache_key] = store_value(value) if store_value is not None else value
    return {
        "cache_key": descriptor.cache_key,
        "cache_hit": False,
        "fingerprint": descriptor.fingerprint,
        "value": value,
    }




def _codegen_root(codegen):
    cfunc = getattr(codegen, "cfunc", None)
    for attr in ("body", "statements", "stmt"):
        value = getattr(cfunc, attr, None)
        if value is not None:
            return value
    return cfunc


def _sorted_unique(values: set[str]) -> tuple[str, ...]:
    return tuple(sorted(values))


def _json_fingerprint(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


_INVERTED_COMPARISON_OPS_8616 = {
    "CmpEQ": "CmpNE",
    "CmpNE": "CmpEQ",
    "CmpLT": "CmpGE",
    "CmpLE": "CmpGT",
    "CmpGT": "CmpLE",
    "CmpGE": "CmpLT",
}


def _invert_condition_fingerprint_8616(node, project, contextual_condition_fingerprints: Mapping[int, str]) -> str | None:
    if isinstance(node, CBinaryOp):
        inverted_op = _INVERTED_COMPARISON_OPS_8616.get(node.op)
        if inverted_op is not None:
            lhs = _expr_fingerprint(node.lhs, project)
            rhs = _expr_fingerprint(node.rhs, project)
            return f"{inverted_op}({lhs},{rhs})"
    if isinstance(node, CUnaryOp) and node.op == "Not":
        return contextual_condition_fingerprints.get(id(node.operand), _expr_fingerprint(node.operand, project))
    fingerprint = contextual_condition_fingerprints.get(id(node), _expr_fingerprint(node, project))
    return _wrap_not_fingerprint(fingerprint)


def _extract_loop_break_guard_normalization_8616(
    loop, project, contextual_condition_fingerprints: Mapping[int, str]
) -> tuple[str, set[int]] | None:
    condition = getattr(loop, "condition", None)
    if _c_constant_int_value(condition) != 1:
        return None

    body = getattr(loop, "body", None)
    statements = tuple(getattr(body, "statements", ()) or ())
    if not statements:
        return None

    first_stmt = statements[0]
    break_cond = None
    suppressed_node_ids = {id(first_stmt)}

    if isinstance(first_stmt, CIfBreak):
        break_cond = getattr(first_stmt, "condition", None)
    elif isinstance(first_stmt, CIfElse):
        branches = tuple(getattr(first_stmt, "condition_and_nodes", ()) or ())
        if len(branches) != 1 or getattr(first_stmt, "else_node", None) is not None:
            return None
        break_cond, branch_node = branches[0]
        branch_statements = tuple(getattr(branch_node, "statements", ()) or ())
        if len(branch_statements) != 1 or not isinstance(branch_statements[0], CBreak):
            return None
        suppressed_node_ids.add(id(branch_statements[0]))
    else:
        return None

    if break_cond is None:
        return None
    normalized = _invert_condition_fingerprint_8616(break_cond, project, contextual_condition_fingerprints)
    if normalized is None:
        return None
    return normalized, suppressed_node_ids


def _node_boundary_fingerprint(node, project):
    if node is None:
        return None
    if isinstance(node, CConstant):
        return ("const", node.value)
    if isinstance(node, CVariable):
        return ("var", _location_fingerprint(node, project))
    if isinstance(node, CTypeCast):
        return ("cast", _node_boundary_fingerprint(node.expr, project))
    if isinstance(node, CUnaryOp):
        return ("unary", node.op, _node_boundary_fingerprint(node.operand, project))
    if isinstance(node, CBinaryOp):
        return ("binary", node.op, _node_boundary_fingerprint(node.lhs, project), _node_boundary_fingerprint(node.rhs, project))
    if isinstance(node, CFunctionCall):
        return (
            "call",
            _call_target_name(node),
            tuple(_node_boundary_fingerprint(arg, project) for arg in (getattr(node, "args", ()) or ())),
        )
    if isinstance(node, CAssignment):
        return ("assign", _node_boundary_fingerprint(node.lhs, project), _node_boundary_fingerprint(node.rhs, project))
    if isinstance(node, CReturn):
        return ("return", _node_boundary_fingerprint(getattr(node, "retval", None), project))
    if isinstance(node, CIfElse):
        return (
            "ifelse",
            tuple(
                (
                    _node_boundary_fingerprint(cond, project),
                    _node_boundary_fingerprint(body, project),
                )
                for cond, body in (getattr(node, "condition_and_nodes", ()) or ())
            ),
            _node_boundary_fingerprint(getattr(node, "else_node", None), project),
        )
    if isinstance(node, CIfBreak):
        return ("ifbreak", _node_boundary_fingerprint(getattr(node, "condition", None), project))
    if isinstance(node, CWhileLoop):
        return (
            "while",
            _node_boundary_fingerprint(getattr(node, "condition", None), project),
            _node_boundary_fingerprint(getattr(node, "body", None), project),
        )
    if isinstance(node, CDoWhileLoop):
        return (
            "dowhile",
            _node_boundary_fingerprint(getattr(node, "condition", None), project),
            _node_boundary_fingerprint(getattr(node, "body", None), project),
        )
    if isinstance(node, CForLoop):
        return (
            "for",
            _node_boundary_fingerprint(getattr(node, "initializer", None), project),
            _node_boundary_fingerprint(getattr(node, "condition", None), project),
            _node_boundary_fingerprint(getattr(node, "iterator", None), project),
            _node_boundary_fingerprint(getattr(node, "body", None), project),
        )
    if isinstance(node, CSwitchCase):
        cases = getattr(node, "cases", None)
        case_items = ()
        if isinstance(cases, dict):
            case_items = tuple(
                (
                    _switch_case_fingerprint(case_value, project),
                    _node_boundary_fingerprint(case_body, project),
                )
                for case_value, case_body in sorted(cases.items(), key=lambda item: _switch_case_fingerprint(item[0], project))
            )
        return (
            "switch",
            _node_boundary_fingerprint(getattr(node, "switch", None), project),
            case_items,
            _node_boundary_fingerprint(getattr(node, "default", None), project),
        )
    if isinstance(node, CGoto):
        return ("goto", getattr(node, "target", None), getattr(node, "target_idx", None))
    if isinstance(node, CBreak):
        return ("break",)
    if isinstance(node, CContinue):
        return ("continue",)
    if type(node).__name__ == "CStatements":
        return (
            "statements",
            tuple(_node_boundary_fingerprint(stmt, project) for stmt in (getattr(node, "statements", ()) or ())),
        )

    fields = []
    for attr in ("condition", "cond", "body", "else_node", "iftrue", "iffalse", "lhs", "rhs", "expr", "operand", "retval"):
        if hasattr(node, attr):
            fields.append((attr, _node_boundary_fingerprint(getattr(node, attr, None), project)))
    return (type(node).__name__, tuple(fields))


def _tail_validation_summary_cache_store(codegen) -> dict[str, object]:
    cache = getattr(codegen, "_inertia_tail_validation_summary_cache", None)
    if not isinstance(cache, dict):
        cache = {}
        codegen._inertia_tail_validation_summary_cache = cache
    stats = cache.setdefault("stats", {"hits": 0, "misses": 0})
    if not isinstance(stats, dict):
        cache["stats"] = {"hits": 0, "misses": 0}
    cache.setdefault("entries", {})
    return cache


def _clone_tail_validation_aggregate_payload(value: Mapping[str, object]) -> dict[str, object]:
    surface = value.get("surface")
    return {
        "summary": dict(value["summary"]),
        "surface": dict(surface) if isinstance(surface, Mapping) else None,
    }


def _records_with_uncollected_placeholders(
    records: Sequence[Mapping[str, object]],
    *,
    scanned: int,
) -> list[Mapping[str, object]]:
    normalized = [record for record in records if isinstance(record, Mapping)]
    missing_records = max(0, int(scanned or 0) - len(normalized))
    if missing_records <= 0:
        return normalized
    return normalized + [{} for _ in range(missing_records)]


def _tail_validation_validation_cache_store(owner) -> dict[str, object]:
    if owner is None:
        return {}
    if isinstance(owner, MutableMapping):
        cache = owner.setdefault("_x86_16_tail_validation_cache", {})
        if not isinstance(cache, MutableMapping):
            cache = {}
            owner["_x86_16_tail_validation_cache"] = cache
        cache.setdefault("comparisons", {})
        return cache
    return {}


def _tail_validation_records_fingerprint(records: Sequence[Mapping[str, object]], *, scanned: int) -> str:
    payload = {
        "scanned": int(scanned or 0),
        "records": [
            {
                "cod_file": record.get("cod_file"),
                "proc_name": record.get("proc_name"),
                "proc_kind": record.get("proc_kind"),
                "structuring": record.get("structuring"),
                "postprocess": record.get("postprocess"),
                "tail_validation_uncollected": record.get("tail_validation_uncollected"),
                "exit_kind": record.get("exit_kind"),
                "exit_detail": record.get("exit_detail"),
            }
            for record in records
        ],
    }
    return build_x86_16_validation_cache_descriptor("tail_validation.aggregate.records", payload).fingerprint


def _tail_validation_changed_observable_fields(entry: Mapping[str, object]) -> tuple[str, ...]:
    delta = entry.get("delta")
    changed_fields: list[str] = []
    if isinstance(delta, Mapping):
        for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
            field_delta = delta.get(field_name)
            if not isinstance(field_delta, Mapping):
                continue
            added = field_delta.get("added", ()) or ()
            removed = field_delta.get("removed", ()) or ()
            if added or removed:
                changed_fields.append(field_name)
        if changed_fields:
            return tuple(changed_fields)

    text_parts = []
    for key in ("summary_text", "verdict"):
        value = entry.get(key)
        if isinstance(value, str):
            text_parts.append(value)
    combined = " ".join(text_parts)
    return tuple(field_name for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS if f"{field_name}:" in combined)


def _tail_validation_changed_families(entry: Mapping[str, object]) -> tuple[str, ...]:
    fields = set(_tail_validation_changed_observable_fields(entry))
    families: list[str] = []
    if "helper_calls" in fields:
        families.append("helper call delta")
    if "register_writes" in fields:
        families.append("live-out register delta")
    if "stack_writes" in fields:
        families.append("stack write delta")
    if {"global_writes", "segmented_writes"} <= fields:
        families.append("segmented/global write delta")
    else:
        if "global_writes" in fields:
            families.append("global write delta")
        if "segmented_writes" in fields:
            families.append("segmented write delta")
    if "returns" in fields:
        families.append("return delta")
    if "conditions" in fields or "control_flow_effects" in fields:
        families.append("control-flow/guard delta")
    if not families:
        families.append("unclassified observable delta")
    return tuple(families)


def _tail_validation_changed_family_summary(changed_functions: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for item in changed_functions:
        if not isinstance(item, Mapping):
            continue
        stage = item.get("stage")
        function_key = (item.get("cod_file"), item.get("proc_name"), item.get("proc_kind"))
        function_label = {
            "cod_file": item.get("cod_file"),
            "proc_name": item.get("proc_name"),
            "proc_kind": item.get("proc_kind"),
        }
        families = item.get("families")
        if not isinstance(families, Sequence) or isinstance(families, (str, bytes)):
            families = ("unclassified observable delta",)
        for family in families:
            if not isinstance(family, str) or not family:
                continue
            row = rows.setdefault(
                family,
                {
                    "family": family,
                    "count": 0,
                    "stages": set(),
                    "functions": set(),
                    "examples": [],
                },
            )
            row["count"] += 1
            if isinstance(stage, str) and stage:
                row["stages"].add(stage)
            row["functions"].add(function_key)
            if len(row["examples"]) < 5 and function_label not in row["examples"]:
                row["examples"].append(function_label)

    summarized = []
    for row in rows.values():
        summarized.append(
            {
                "family": row["family"],
                "count": row["count"],
                "function_count": len(row["functions"]),
                "stages": tuple(sorted(row["stages"])),
                "examples": tuple(row["examples"]),
            }
        )
    return sorted(summarized, key=lambda item: (-int(item["count"]), item["family"]))


def _tail_validation_sort_value(value: object) -> str:
    return value if isinstance(value, str) else ""


def _tail_validation_function_sort_key(item: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        "" if isinstance(item.get("cod_file"), str) else "~",
        _tail_validation_sort_value(item.get("cod_file")),
        _tail_validation_sort_value(item.get("proc_name")),
        _tail_validation_sort_value(item.get("proc_kind")),
    )


def _tail_validation_stage_status(entry: object) -> str:
    if not isinstance(entry, Mapping):
        return "uncollected"
    if "changed" not in entry:
        return "unknown"
    return "changed" if bool(entry.get("changed", False)) else "passed"


def _tail_validation_record_proc_name(record: Mapping[str, object]) -> object:
    proc_name = record.get("proc_name")
    if proc_name:
        return proc_name
    return record.get("function_name")


def _tail_validation_function_accounting(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    status_counts: Counter[str] = Counter()
    for record in records:
        proc_name = _tail_validation_record_proc_name(record)
        stage_statuses = {
            stage: _tail_validation_stage_status(record.get(stage))
            for stage in ("structuring", "postprocess")
        }
        if "changed" in stage_statuses.values():
            status = "changed"
        elif "unknown" in stage_statuses.values():
            status = "unknown"
        elif "uncollected" in stage_statuses.values():
            status = "uncollected"
        else:
            status = "passed"
        status_counts[status] += 1
        rows.append(
            {
                "cod_file": record.get("cod_file"),
                "proc_name": proc_name,
                "proc_kind": record.get("proc_kind"),
                "status": status,
                "stage_statuses": dict(sorted(stage_statuses.items())),
                "exit_kind": record.get("exit_kind"),
                "exit_detail": record.get("exit_detail"),
                "tail_validation_uncollected": bool(record.get("tail_validation_uncollected", False)),
            }
        )
    rows.sort(key=_tail_validation_function_sort_key)
    return {
        "function_status_counts": dict(sorted(status_counts.items())),
        "function_statuses": rows,
        "passed_functions": [row for row in rows if row["status"] == "passed"],
        "changed_functions": [row for row in rows if row["status"] == "changed"],
        "unknown_functions": [row for row in rows if row["status"] == "unknown"],
        "uncollected_functions": [row for row in rows if row["status"] == "uncollected"],
    }


def _tail_validation_stage_summary(records: Sequence[Mapping[str, object]], stage: str) -> dict[str, object]:
    stable_count = 0
    changed_count = 0
    unknown_count = 0
    missing_count = 0
    mode_counter: Counter[str] = Counter()
    verdict_counter: Counter[str] = Counter()
    changed_functions: list[dict[str, object]] = []

    for record in records:
        entry = record.get(stage)
        if not isinstance(entry, Mapping):
            missing_count += 1
            continue
        if "changed" not in entry:
            unknown_count += 1
            continue
        changed = bool(entry.get("changed", False))
        mode = entry.get("mode")
        verdict = entry.get("verdict")
        if isinstance(mode, str) and mode:
            mode_counter[mode] += 1
        if changed:
            changed_count += 1
            if isinstance(verdict, str) and verdict:
                verdict_counter[verdict] += 1
            families = _tail_validation_changed_families(entry)
            changed_functions.append(
                {
                    "cod_file": record.get("cod_file"),
                    "proc_name": _tail_validation_record_proc_name(record),
                    "proc_kind": record.get("proc_kind"),
                    "stage": stage,
                    "verdict": verdict,
                    "families": families,
                }
            )
        else:
            stable_count += 1

    changed_functions.sort(
        key=lambda item: (
            "" if isinstance(item.get("cod_file"), str) else "~",
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
        )
    )
    top_verdicts = [
        {"verdict": verdict, "count": count}
        for verdict, count in sorted(verdict_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    return {
        "stable_count": stable_count,
        "changed_count": changed_count,
        "unknown_count": unknown_count,
        "missing_count": missing_count,
        "coverage_count": stable_count + changed_count + unknown_count,
        "mode_counts": dict(sorted(mode_counter.items())),
        "top_verdicts": top_verdicts,
        "changed_functions": changed_functions,
        "changed_families": _tail_validation_changed_family_summary(changed_functions),
    }


def _switch_case_fingerprint(case_value, project) -> str:
    if isinstance(case_value, (tuple, list)):
        return "[" + ",".join(_switch_case_fingerprint(item, project) for item in case_value) + "]"
    return _expr_fingerprint(case_value, project)


def fingerprint_x86_16_tail_validation_boundary(project, codegen, *, mode: str = "live_out") -> str:
    if mode not in _TAIL_VALIDATION_MODES:
        raise ValueError(f"Unsupported x86-16 tail validation mode: {mode}")
    root = _codegen_root(codegen)
    payload = {
        "arch": getattr(getattr(project, "arch", None), "name", None),
        "mode": mode,
        "fingerprint_version": TAIL_VALIDATION_FINGERPRINT_VERSION,
        "root": _node_boundary_fingerprint(root, project),
    }
    return build_x86_16_validation_cache_descriptor("tail_validation.boundary", payload).fingerprint


def extract_x86_16_tail_validation_snapshot(function_info: Mapping[str, object] | None) -> dict[str, object]:
    stages: dict[str, object] = {}
    if not isinstance(function_info, Mapping):
        return stages
    validation_info = function_info.get("x86_16_tail_validation")
    if not isinstance(validation_info, Mapping):
        return stages
    for stage in ("structuring", "postprocess"):
        entry = validation_info.get(stage)
        if not isinstance(entry, Mapping):
            continue
        stages[stage] = {
            "changed": bool(entry.get("changed", False)),
            "mode": entry.get("mode"),
            "verdict": entry.get("verdict"),
            "summary_text": entry.get("summary_text"),
        }
        delta = entry.get("delta")
        if isinstance(delta, Mapping):
            stages[stage]["delta"] = dict(delta)
    return stages


def x86_16_tail_validation_snapshot_passed(
    snapshot: Mapping[str, object] | None,
    *,
    expected_stages: Sequence[str] = ("structuring", "postprocess"),
) -> bool:
    if not isinstance(snapshot, Mapping):
        return False
    required_stages = tuple(stage for stage in expected_stages if isinstance(stage, str) and stage)
    if not required_stages:
        return False
    for stage in required_stages:
        entry = snapshot.get(stage)
        if not isinstance(entry, Mapping):
            return False
        if bool(entry.get("changed", False)):
            return False
    return True


def persist_x86_16_tail_validation_snapshot(
    *,
    function_info: MutableMapping[str, object] | None,
    codegen,
    stage: str,
    validation: Mapping[str, object],
) -> dict[str, object]:
    snapshot_entry = {
        "changed": bool(validation.get("changed", False)),
        "mode": validation.get("mode"),
        "verdict": validation.get("verdict"),
        "summary_text": validation.get("summary_text"),
    }
    delta = validation.get("delta")
    if isinstance(delta, Mapping):
        snapshot_entry["delta"] = dict(delta)
    if isinstance(function_info, MutableMapping):
        validation_info = function_info.setdefault("x86_16_tail_validation", {})
        if isinstance(validation_info, MutableMapping):
            validation_info[stage] = dict(validation)
    if codegen is not None:
        snapshot = getattr(codegen, "_inertia_tail_validation_snapshot", None)
        if not isinstance(snapshot, dict):
            snapshot = {}
            codegen._inertia_tail_validation_snapshot = snapshot
        snapshot[stage] = snapshot_entry
    return snapshot_entry


def check_x86_16_tail_validation_surface_consistency(
    summary: Mapping[str, object],
    surface: Mapping[str, object],
    *,
    scanned: int,
) -> tuple[str, ...]:
    issues: list[str] = []
    scanned_count = max(int(scanned or 0), 0)
    structuring = dict(summary.get("structuring", {}) or {})
    postprocess = dict(summary.get("postprocess", {}) or {})
    stage_summaries = {"structuring": structuring, "postprocess": postprocess}
    stage_rows = {
        row.get("stage"): row
        for row in surface.get("stage_rows", ()) or ()
        if isinstance(row, Mapping) and isinstance(row.get("stage"), str)
    }
    expected_changed_total = sum(int(stage.get("changed_count", 0) or 0) for stage in stage_summaries.values())
    expected_missing_total = sum(int(stage.get("missing_count", 0) or 0) for stage in stage_summaries.values())
    expected_unknown_total = sum(int(stage.get("unknown_count", 0) or 0) for stage in stage_summaries.values())
    expected_coverage_total = sum(int(stage.get("coverage_count", 0) or 0) for stage in stage_summaries.values())
    checks = (
        ("changed_stage_total", expected_changed_total),
        ("missing_stage_total", expected_missing_total),
        ("unknown_stage_total", expected_unknown_total),
        ("coverage_count", expected_coverage_total),
        ("changed_function_count", int(summary.get("changed_function_count", 0) or 0)),
        ("passed_function_count", int(summary.get("passed_function_count", 0) or 0)),
        ("unknown_function_count", int(summary.get("unknown_function_count", 0) or 0)),
        ("uncollected_function_count", int(summary.get("uncollected_function_count", 0) or 0)),
    )
    for key, expected in checks:
        actual = int(surface.get(key, 0) or 0)
        if actual != expected:
            issues.append(f"{key}: surface={actual} summary={expected}")
    if dict(surface.get("function_status_counts", {}) or {}) != dict(summary.get("function_status_counts", {}) or {}):
        issues.append("function_status_counts mismatch")
    if len(surface.get("function_statuses", ()) or ()) != scanned_count:
        issues.append(
            f"function_statuses: surface={len(surface.get('function_statuses', ()) or ())} scanned={scanned_count}"
        )
    for stage_name, stage_summary in stage_summaries.items():
        row = stage_rows.get(stage_name)
        if not isinstance(row, Mapping):
            issues.append(f"{stage_name}: missing stage row")
            continue
        for key in ("changed_count", "stable_count", "unknown_count", "missing_count", "coverage_count"):
            actual = int(row.get(key, 0) or 0)
            expected = int(stage_summary.get(key, 0) or 0)
            if actual != expected:
                issues.append(f"{stage_name}.{key}: surface={actual} summary={expected}")
    return tuple(issues)


def build_x86_16_tail_validation_surface(summary: Mapping[str, object], *, scanned: int) -> dict[str, object]:
    scanned_count = max(int(scanned or 0), 0)
    severity = str(summary.get("severity", "uncollected"))
    changed_function_count = int(summary.get("changed_function_count", 0) or 0)
    structuring = dict(summary.get("structuring", {}) or {})
    postprocess = dict(summary.get("postprocess", {}) or {})
    changed_functions = list(summary.get("changed_functions", []) or [])
    function_status_counts = dict(summary.get("function_status_counts", {}) or {})
    function_statuses = list(summary.get("function_statuses", []) or [])
    uncollected_functions = list(summary.get("uncollected_functions", []) or [])
    unknown_functions = list(summary.get("unknown_functions", []) or [])
    stage_rows = []
    total_changed = 0
    total_missing = 0
    total_unknown = 0
    total_coverage = 0

    for stage_name, stage_summary in (("structuring", structuring), ("postprocess", postprocess)):
        changed_count = int(stage_summary.get("changed_count", 0) or 0)
        stable_count = int(stage_summary.get("stable_count", 0) or 0)
        unknown_count = int(stage_summary.get("unknown_count", 0) or 0)
        missing_count = int(stage_summary.get("missing_count", 0) or 0)
        coverage_count = int(stage_summary.get("coverage_count", stable_count + changed_count + unknown_count) or 0)
        total_changed += changed_count
        total_missing += missing_count
        total_unknown += unknown_count
        total_coverage += coverage_count
        stage_rows.append(
            {
                "stage": stage_name,
                "changed_count": changed_count,
                "stable_count": stable_count,
                "unknown_count": unknown_count,
                "missing_count": missing_count,
                "coverage_count": coverage_count,
                "changed_rate": 0.0 if scanned_count == 0 else round(changed_count / scanned_count, 6),
                "coverage_rate": 0.0 if scanned_count == 0 else round(coverage_count / scanned_count, 6),
                "mode_counts": dict(stage_summary.get("mode_counts", {}) or {}),
                "top_verdicts": list(stage_summary.get("top_verdicts", []) or []),
            }
        )

    stage_hotspots = [
        {
            "stage": row["stage"],
            "changed_count": row["changed_count"],
            "changed_rate": row["changed_rate"],
            "top_verdicts": row["top_verdicts"],
        }
        for row in sorted(stage_rows, key=lambda item: (-item["changed_count"], item["stage"]))
        if row["changed_count"] > 0
    ]
    top_changed_verdicts = []
    verdict_counter: Counter[str] = Counter()
    for row in stage_rows:
        for item in row["top_verdicts"]:
            verdict = item.get("verdict")
            count = item.get("count")
            if isinstance(verdict, str) and verdict and isinstance(count, int):
                verdict_counter[verdict] += count
    top_changed_verdicts = [
        {"verdict": verdict, "count": count}
        for verdict, count in sorted(verdict_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    changed_function_rows: dict[tuple[object, object, object], dict[str, object]] = {}
    for item in changed_functions:
        if not isinstance(item, Mapping):
            continue
        key = (
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
        )
        row = changed_function_rows.setdefault(
            key,
            {
                "cod_file": item.get("cod_file"),
                "proc_name": item.get("proc_name"),
                "proc_kind": item.get("proc_kind"),
                "stages": [],
                "verdicts": [],
                "changed_stage_count": 0,
            },
        )
        stage = item.get("stage")
        verdict = item.get("verdict")
        if isinstance(stage, str) and stage and stage not in row["stages"]:
            row["stages"].append(stage)
        if isinstance(verdict, str) and verdict and verdict not in row["verdicts"]:
            row["verdicts"].append(verdict)
        row["changed_stage_count"] = len(row["stages"])
    top_changed_functions = sorted(
        (
            {
                **row,
                "stages": tuple(sorted(row["stages"])),
                "verdicts": tuple(row["verdicts"]),
            }
            for row in changed_function_rows.values()
        ),
        key=lambda item: (
            -int(item.get("changed_stage_count", 0) or 0),
            "" if isinstance(item.get("cod_file"), str) else "~",
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
        ),
    )
    changed_families = _tail_validation_changed_family_summary(changed_functions)
    top_uncollected_functions = sorted(
        (dict(item) for item in uncollected_functions if isinstance(item, Mapping)),
        key=_tail_validation_function_sort_key,
    )
    top_unknown_functions = sorted(
        (dict(item) for item in unknown_functions if isinstance(item, Mapping)),
        key=_tail_validation_function_sort_key,
    )

    merge_gate = severity == "clean"
    if scanned_count == 0:
        headline = "whole-tail validation: no functions scanned"
    elif severity == "clean":
        headline = f"whole-tail validation clean across {scanned_count} functions"
    elif severity == "uncollected":
        headline = f"whole-tail validation not collected across {scanned_count} functions"
    elif severity == "partial":
        headline = f"whole-tail validation partially collected across {scanned_count} functions"
    elif severity == "unknown":
        headline = f"whole-tail validation incomplete across {scanned_count} functions"
    else:
        headline = f"whole-tail validation changed in {changed_function_count} functions"

    surface = {
        "headline": headline,
        "severity": severity,
        "merge_gate": merge_gate,
        "changed_function_count": changed_function_count,
        "changed_stage_total": total_changed,
        "coverage_count": total_coverage,
        "missing_stage_total": total_missing,
        "unknown_stage_total": total_unknown,
        "function_status_counts": function_status_counts,
        "function_statuses": function_statuses,
        "passed_function_count": int(summary.get("passed_function_count", 0) or 0),
        "unknown_function_count": int(summary.get("unknown_function_count", 0) or 0),
        "uncollected_function_count": int(summary.get("uncollected_function_count", 0) or 0),
        "top_unknown_functions": top_unknown_functions,
        "top_uncollected_functions": top_uncollected_functions,
        "stage_rows": stage_rows,
        "stage_hotspots": stage_hotspots,
        "top_changed_verdicts": top_changed_verdicts,
        "top_changed_functions": top_changed_functions,
        "changed_families": changed_families,
        "changed_family_routing": build_tail_validation_family_routing(changed_families),
    }
    surface["consistency_issues"] = check_x86_16_tail_validation_surface_consistency(
        summary,
        surface,
        scanned=scanned_count,
    )
    return surface


def _normalized_tail_validation_baseline_entries(
    entries: Sequence[Mapping[str, object]] | None,
) -> list[dict[str, str]]:
    normalized: set[tuple[str, str, str, str, str]] = set()
    for item in entries or ():
        if not isinstance(item, Mapping):
            continue
        cod_file = item.get("cod_file")
        proc_name = item.get("proc_name")
        proc_kind = item.get("proc_kind")
        stage = item.get("stage")
        verdict = item.get("verdict")
        if not all(isinstance(value, str) and value for value in (cod_file, proc_name, proc_kind, stage, verdict)):
            continue
        normalized.add((cod_file, proc_name, proc_kind, stage, verdict))
    return [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(normalized)
    ]


def build_x86_16_tail_validation_baseline(summary: Mapping[str, object]) -> dict[str, object]:
    normalized_entries = _normalized_tail_validation_baseline_entries(summary.get("changed_functions"))
    return {
        "version": 1,
        "entries": normalized_entries,
        "entry_count": len(normalized_entries),
    }


def compare_x86_16_tail_validation_baseline(
    summary: Mapping[str, object],
    baseline: Mapping[str, object] | None,
) -> dict[str, object]:
    if not isinstance(baseline, Mapping):
        return {"status": "unavailable", "unexpected": [], "missing": [], "matches": []}

    current_entries = _normalized_tail_validation_baseline_entries(summary.get("changed_functions"))
    baseline_entries = _normalized_tail_validation_baseline_entries(baseline.get("entries"))
    current_set = {
        (
            item["cod_file"],
            item["proc_name"],
            item["proc_kind"],
            item["stage"],
            item["verdict"],
        )
        for item in current_entries
    }
    baseline_set = {
        (
            item["cod_file"],
            item["proc_name"],
            item["proc_kind"],
            item["stage"],
            item["verdict"],
        )
        for item in baseline_entries
    }
    unexpected = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(current_set - baseline_set)
    ]
    missing = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(baseline_set - current_set)
    ]
    matches = [
        {
            "cod_file": cod_file,
            "proc_name": proc_name,
            "proc_kind": proc_kind,
            "stage": stage,
            "verdict": verdict,
        }
        for cod_file, proc_name, proc_kind, stage, verdict in sorted(current_set & baseline_set)
    ]
    if unexpected:
        status = "regressed"
    elif missing:
        status = "improved"
    else:
        status = "matches_baseline"
    return {
        "status": status,
        "unexpected": unexpected,
        "missing": missing,
        "matches": matches,
    }


def annotate_x86_16_tail_validation_surface_with_baseline(
    surface: Mapping[str, object],
    comparison: Mapping[str, object] | None,
) -> dict[str, object]:
    annotated = dict(surface)
    if not isinstance(comparison, Mapping):
        return annotated
    status = comparison.get("status")
    if not isinstance(status, str) or not status:
        return annotated
    unexpected = list(comparison.get("unexpected", []) or [])
    missing = list(comparison.get("missing", []) or [])
    annotated["baseline_status"] = status
    annotated["baseline_unexpected_count"] = len(unexpected)
    annotated["baseline_missing_count"] = len(missing)
    annotated["baseline_unexpected"] = unexpected
    annotated["baseline_missing"] = missing
    return annotated


def build_x86_16_tail_validation_aggregate(
    records: Sequence[Mapping[str, object]],
    *,
    scanned: int,
) -> dict[str, object]:
    normalized_records = _records_with_uncollected_placeholders(records, scanned=scanned)
    descriptor = build_x86_16_validation_cache_descriptor(
        "tail_validation.aggregate",
        {
            "records_fingerprint": _tail_validation_records_fingerprint(records, scanned=scanned),
            "scanned": int(scanned or 0),
        },
    )
    cached = resolve_x86_16_validation_cached_artifact(
        cache=_TAIL_VALIDATION_AGGREGATE_CACHE,
        descriptor=descriptor,
        build=lambda: {
            "summary": summarize_x86_16_tail_validation_records(normalized_records),
            "surface": None,
        },
        clone_on_hit=_clone_tail_validation_aggregate_payload,
        store_value=_clone_tail_validation_aggregate_payload,
    )
    payload = dict(cached["value"])
    if payload.get("surface") is None:
        payload["surface"] = build_x86_16_tail_validation_surface(payload["summary"], scanned=scanned)
        _TAIL_VALIDATION_AGGREGATE_CACHE[descriptor.cache_key] = {
            "summary": dict(payload["summary"]),
            "surface": dict(payload["surface"]),
        }
    return {
        "cache_key": cached["cache_key"],
        "cache_hit": bool(cached["cache_hit"]),
        "summary": payload["summary"],
        "surface": payload["surface"],
    }


def summarize_x86_16_tail_validation_records(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    structuring = _tail_validation_stage_summary(records, "structuring")
    postprocess = _tail_validation_stage_summary(records, "postprocess")
    function_accounting = _tail_validation_function_accounting(records)
    changed_functions = sorted(
        structuring["changed_functions"] + postprocess["changed_functions"],
        key=lambda item: (
            "" if isinstance(item.get("cod_file"), str) else "~",
            item.get("cod_file"),
            item.get("proc_name"),
            item.get("proc_kind"),
            item.get("verdict"),
        ),
    )
    changed_function_count = len(changed_functions)
    changed_families = _tail_validation_changed_family_summary(changed_functions)
    coverage_count = int(structuring["coverage_count"]) + int(postprocess["coverage_count"])
    missing_count = int(structuring["missing_count"]) + int(postprocess["missing_count"])
    unknown_count = int(structuring["unknown_count"]) + int(postprocess["unknown_count"])
    severity = "clean"
    if changed_function_count > 0:
        severity = "changed"
    elif unknown_count > 0:
        severity = "unknown"
    elif coverage_count == 0 and missing_count > 0:
        severity = "uncollected"
    elif missing_count > 0:
        severity = "partial"
    return {
        "severity": severity,
        "changed_function_count": changed_function_count,
        "coverage_count": coverage_count,
        "missing_count": missing_count,
        "unknown_count": unknown_count,
        "structuring": structuring,
        "postprocess": postprocess,
        "changed_functions": changed_functions,
        "changed_families": changed_families,
        "function_status_counts": function_accounting["function_status_counts"],
        "function_statuses": function_accounting["function_statuses"],
        "passed_functions": function_accounting["passed_functions"],
        "unknown_functions": function_accounting["unknown_functions"],
        "uncollected_functions": function_accounting["uncollected_functions"],
        "passed_function_count": len(function_accounting["passed_functions"]),
        "unknown_function_count": len(function_accounting["unknown_functions"]),
        "uncollected_function_count": len(function_accounting["uncollected_functions"]),
    }


def _record_expr_locations(node, project, observed_locations: set[str]) -> None:
    if node is None:
        return
    if isinstance(node, CVariable):
        observed_locations.add(_location_fingerprint(node, project))
        return
    if isinstance(node, CTypeCast):
        _record_expr_locations(node.expr, project, observed_locations)
        return
    if isinstance(node, CUnaryOp):
        observed_locations.add(_location_fingerprint(node, project))
        _record_expr_locations(node.operand, project, observed_locations)
        return
    if isinstance(node, CBinaryOp):
        _record_expr_locations(node.lhs, project, observed_locations)
        _record_expr_locations(node.rhs, project, observed_locations)
        return
    if isinstance(node, CFunctionCall):
        for arg in getattr(node, "args", ()) or ():
            _record_expr_locations(arg, project, observed_locations)
        return


def _is_control_flow_node(node) -> bool:
    return isinstance(node, (CIfElse, CIfBreak, CWhileLoop, CDoWhileLoop, CForLoop, CSwitchCase, CGoto, CBreak, CContinue, CReturn))


def _collect_observed_locations(root, project, mode: str) -> set[str]:
    observed_locations: set[str] = set()
    if mode != "live_out":
        return observed_locations

    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CFunctionCall):
            for arg in getattr(node, "args", ()) or ():
                _record_expr_locations(arg, project, observed_locations)
        if isinstance(node, CReturn):
            _record_expr_locations(getattr(node, "retval", None), project, observed_locations)
    return observed_locations


def collect_x86_16_tail_validation_summary(project, codegen, *, mode: str = "live_out") -> X86_16TailValidationSummary:
    if mode not in _TAIL_VALIDATION_MODES:
        raise ValueError(f"Unsupported x86-16 tail validation mode: {mode}")
    cache = _tail_validation_summary_cache_store(codegen)
    descriptor = build_x86_16_validation_cache_descriptor(
        "tail_validation.summary",
        {
            "mode": mode,
            "boundary_fingerprint": fingerprint_x86_16_tail_validation_boundary(project, codegen, mode=mode),
        },
    )
    entries = cache.get("entries", {})

    root = _codegen_root(codegen)
    helper_calls: set[str] = set()
    register_writes: set[str] = set()
    stack_writes: set[str] = set()
    global_writes: set[str] = set()
    segmented_writes: set[str] = set()
    returns: set[str] = set()
    conditions: set[str] = set()
    control_flow_effects: set[str] = set()

    if root is None:
        return X86_16TailValidationSummary((), (), (), (), (), (), (), ())
    observed_locations = _collect_observed_locations(root, project, mode)
    contextual_condition_fingerprints = build_x86_16_contextual_condition_fingerprints(root, project)
    normalized_loop_conditions: dict[int, str] = {}
    suppressed_control_flow_nodes: set[int] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CWhileLoop):
            continue
        normalized = _extract_loop_break_guard_normalization_8616(node, project, contextual_condition_fingerprints)
        if normalized is None:
            continue
        normalized_loop_conditions[id(node)] = normalized[0]
        suppressed_control_flow_nodes.update(normalized[1])

    for node in _iter_c_nodes_deep_8616(root):
        if id(node) in suppressed_control_flow_nodes:
            continue
        if isinstance(node, CFunctionCall):
            helper_calls.add(_call_target_name(node))
        elif isinstance(node, CReturn):
            returns.add(_expr_fingerprint(getattr(node, "retval", None), project))
            control_flow_effects.add("return")
        elif isinstance(node, CAssignment):
            lhs = getattr(node, "lhs", None)
            location = _location_fingerprint(lhs, project)
            if location.startswith("reg:"):
                if mode == "coarse" or location in observed_locations:
                    register_writes.add(location)
            elif location.startswith("stack:"):
                if include_x86_16_tail_validation_stack_write(
                    location,
                    mode=mode,
                    observed_locations=observed_locations,
                ):
                    stack_writes.add(location)
            elif location.startswith("global:"):
                global_writes.add(location)
            elif location.startswith("deref:"):
                segmented_writes.add(location)
        elif isinstance(node, CIfElse):
            for cond, _child in getattr(node, "condition_and_nodes", ()) or ():
                cond_fingerprint = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
                control_flow_effects.add(f"if:{cond_fingerprint}")
                if mode == "live_out":
                    conditions.add(cond_fingerprint)
            if getattr(node, "else_node", None) is not None:
                control_flow_effects.add("if:else")
        elif isinstance(node, CIfBreak):
            cond = getattr(node, "condition", None)
            cond_fingerprint = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
            control_flow_effects.add(f"ifbreak:{cond_fingerprint}")
            if mode == "live_out":
                conditions.add(cond_fingerprint)
        elif isinstance(node, CWhileLoop):
            cond = getattr(node, "condition", None)
            cond_fingerprint = normalized_loop_conditions.get(
                id(node),
                contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project)),
            )
            control_flow_effects.add(f"while:{cond_fingerprint}")
            if mode == "live_out":
                conditions.add(cond_fingerprint)
        elif isinstance(node, CDoWhileLoop):
            cond = getattr(node, "condition", None)
            cond_fingerprint = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
            control_flow_effects.add(f"dowhile:{cond_fingerprint}")
            if mode == "live_out":
                conditions.add(cond_fingerprint)
        elif isinstance(node, CForLoop):
            cond = getattr(node, "condition", None)
            cond_fingerprint = contextual_condition_fingerprints.get(id(cond), _expr_fingerprint(cond, project))
            control_flow_effects.add(f"for:{cond_fingerprint}")
            if mode == "live_out":
                conditions.add(cond_fingerprint)
        elif isinstance(node, CSwitchCase):
            switch_fingerprint = _expr_fingerprint(getattr(node, "switch", None), project)
            control_flow_effects.add(f"switch:{switch_fingerprint}")
            if mode == "live_out":
                conditions.add(switch_fingerprint)
            cases = getattr(node, "cases", None)
            if isinstance(cases, dict):
                for case_value in cases:
                    control_flow_effects.add(f"case:{_switch_case_fingerprint(case_value, project)}")
            if getattr(node, "default", None) is not None:
                control_flow_effects.add("case:default")
        elif isinstance(node, CGoto):
            control_flow_effects.add(f"goto:{getattr(node, 'target', None)!r}")
        elif isinstance(node, CBreak):
            control_flow_effects.add("break")
        elif isinstance(node, CContinue):
            control_flow_effects.add("continue")

        if mode == "coarse" and not _is_control_flow_node(node):
            for attr in ("condition", "cond"):
                value = getattr(node, attr, None)
                if value is not None:
                    conditions.add(_expr_fingerprint(value, project))

    def _build_summary() -> X86_16TailValidationSummary:
        return X86_16TailValidationSummary(
            helper_calls=_sorted_unique(helper_calls),
            register_writes=_sorted_unique(register_writes),
            stack_writes=_sorted_unique(stack_writes),
            global_writes=_sorted_unique(global_writes),
            segmented_writes=_sorted_unique(segmented_writes),
            returns=_sorted_unique(returns),
            conditions=_sorted_unique(conditions),
            control_flow_effects=_sorted_unique(control_flow_effects),
        )

    cached = resolve_x86_16_validation_cached_artifact(
        cache=entries if isinstance(entries, dict) else None,
        descriptor=descriptor,
        build=_build_summary,
    )
    summary = cached["value"]
    if bool(cached["cache_hit"]):
        cache["stats"]["hits"] = int(cache["stats"].get("hits", 0) or 0) + 1
    else:
        cache["stats"]["misses"] = int(cache["stats"].get("misses", 0) or 0) + 1
    codegen._inertia_tail_validation_last_summary_cache_hit = bool(cached["cache_hit"])
    codegen._inertia_tail_validation_last_summary_cache_key = cached["cache_key"]
    return summary


def compare_x86_16_tail_validation_summaries(
    before: X86_16TailValidationSummary,
    after: X86_16TailValidationSummary,
) -> dict[str, object]:
    changed = False
    diff: dict[str, object] = {"changed": False, "before": before.as_dict(), "after": after.as_dict(), "delta": {}}
    for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
        before_values = set(getattr(before, field_name))
        after_values = set(getattr(after, field_name))
        added = tuple(sorted(after_values - before_values))
        removed = tuple(sorted(before_values - after_values))
        if added or removed:
            changed = True
        diff["delta"][field_name] = {"added": added, "removed": removed}
    diff["changed"] = changed
    return diff


def format_x86_16_tail_validation_diff(validation: dict[str, object]) -> str:
    if not validation.get("changed", False):
        return "no observable whole-tail changes"

    delta = validation.get("delta", {})
    parts: list[str] = []
    for field_name in _TAIL_VALIDATION_OBSERVABLE_FIELDS:
        field_delta = delta.get(field_name, {})
        added = field_delta.get("added", ()) or ()
        removed = field_delta.get("removed", ()) or ()
        if not added and not removed:
            continue
        field_parts = [f"+{value}" for value in added] + [f"-{value}" for value in removed]
        parts.append(f"{field_name}: " + ", ".join(field_parts))
    return "; ".join(parts) if parts else "observable whole-tail delta present"


def _format_x86_16_tail_validation_timing_suffix(validation: Mapping[str, object]) -> str:
    timings = validation.get("timings")
    if not isinstance(timings, Mapping):
        return ""

    parts: list[str] = []
    collect_before_ms = timings.get("collect_before_ms")
    collect_after_ms = timings.get("collect_after_ms")
    compare_ms = timings.get("compare_ms")
    total_ms = timings.get("total_ms")

    if isinstance(collect_before_ms, (int, float)) and isinstance(collect_after_ms, (int, float)):
        parts.append(f"collect={collect_before_ms:.1f}+{collect_after_ms:.1f}ms")
    elif isinstance(collect_before_ms, (int, float)):
        parts.append(f"collect={collect_before_ms:.1f}ms")
    elif isinstance(collect_after_ms, (int, float)):
        parts.append(f"collect={collect_after_ms:.1f}ms")

    if isinstance(compare_ms, (int, float)):
        parts.append(f"compare={compare_ms:.1f}ms")
    if isinstance(total_ms, (int, float)):
        parts.append(f"tail_validation={total_ms:.1f}ms")
    if not parts:
        return ""
    return " [" + " ".join(parts) + "]"


def build_x86_16_tail_validation_verdict(stage: str, validation: dict[str, object]) -> str:
    mode = validation.get("mode", "unknown")
    summary_text = validation.get("summary_text")
    if not isinstance(summary_text, str) or not summary_text:
        summary_text = format_x86_16_tail_validation_diff(validation)
    status = "changed" if validation.get("changed", False) else "stable"
    return f"{stage} whole-tail validation [{mode}] {status}: {summary_text}{_format_x86_16_tail_validation_timing_suffix(validation)}"


def describe_x86_16_tail_validation_scope() -> dict[str, object]:
    return {
        "boundary": "whole-tail validation compares observable structured-codegen effects before and after late x86-16 passes",
        "preferred_mode": "live_out",
        "modes": ("coarse", "live_out"),
        "cache_policy": "reuse summaries and stage comparisons only when structured-codegen boundary fingerprints match exactly",
        "coverage_semantics": {
            "missing": "validation metadata was not collected for that stage on that function",
            "unknown": "validation metadata existed but could not be classified into stable or changed",
        },
        "layers": ("structuring", "postprocess"),
        "observables": _TAIL_VALIDATION_OBSERVABLE_FIELDS,
        "ignored": (
            "temporary names",
            "dead internal rewrites",
            "non-live flag churn",
        ),
    }


def build_x86_16_tail_validation_cached_result(
    *,
    owner,
    stage: str,
    mode: str,
    before_fingerprint: str,
    after_fingerprint: str,
    before_summary: X86_16TailValidationSummary,
    after_summary: X86_16TailValidationSummary,
) -> dict[str, object]:
    cache = _tail_validation_validation_cache_store(owner)
    comparisons = cache.get("comparisons", {})
    descriptor = build_x86_16_validation_cache_descriptor(
        "tail_validation.comparison",
        {
            "stage": stage,
            "mode": mode,
            "before_fingerprint": before_fingerprint,
            "after_fingerprint": after_fingerprint,
        },
    )
    cached = resolve_x86_16_validation_cached_artifact(
        cache=comparisons if isinstance(comparisons, dict) else None,
        descriptor=descriptor,
        build=lambda: {
            **compare_x86_16_tail_validation_summaries(before_summary, after_summary),
            "mode": mode,
        },
        clone_on_hit=dict,
        store_value=dict,
    )
    result = dict(cached["value"])
    if "summary_text" not in result:
        result["summary_text"] = format_x86_16_tail_validation_diff(result)
    if "scope" not in result:
        result["scope"] = describe_x86_16_tail_validation_scope()
    if "verdict" not in result:
        result["verdict"] = build_x86_16_tail_validation_verdict(stage, result)
    result["cache_hit"] = bool(cached["cache_hit"])
    result["cache_key"] = cached["cache_key"]
    if isinstance(comparisons, dict) and not cached["cache_hit"]:
        comparisons[cached["cache_key"]] = dict(result)
    return result
