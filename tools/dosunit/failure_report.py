from __future__ import annotations

from collections import Counter
import json
from typing import Any


def render_failure_report(
    document: dict[str, Any],
    *,
    limit: int = 0,
    mismatch_limit: int = 8,
    show_unresolved_call_targets: bool = False,
) -> str:
    schema = str(document.get("schema", "unknown"))
    if schema == "dosunit.region_compare.v1":
        return _render_region_compare(document, limit=limit, mismatch_limit=mismatch_limit)
    if schema == "dosunit.results.v1":
        return _render_vector_results(document, limit=limit, mismatch_limit=mismatch_limit)
    if schema == "dosunit.data_compare.v1":
        return _render_data_compare(document, limit=limit, mismatch_limit=mismatch_limit)
    if schema == "dosunit.complexity.v1":
        return _render_complexity(document, limit=limit, mismatch_limit=mismatch_limit)
    if schema == "dosunit.ssa_compare.v1":
        return _render_ssa_compare(
            document,
            limit=limit,
            mismatch_limit=mismatch_limit,
            show_unresolved_call_targets=show_unresolved_call_targets,
        )
    if schema == "dosunit.ssa_abi_compare.v1":
        return _render_ssa_abi_compare(document, limit=limit, mismatch_limit=mismatch_limit)
    if "refusals" in document:
        return _render_refusals(document, limit=limit)
    return _render_unknown(document)


def _limited(items: list[Any], limit: int) -> list[Any]:
    if limit <= 0:
        return list(items)
    return list(items[:limit])


def _render_region_compare(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = document.get("summary", {})
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Oracle: `{document.get('oracle')}`",
        f"Candidate: `{document.get('candidate')}`",
        "",
        "## Summary",
        "",
        f"- Total: {summary.get('total', 0)}",
        f"- Passed: {summary.get('passed', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Refused: {summary.get('refused', 0)}",
        "",
        "## Failed Or Refused Regions",
        "",
    ]
    failing = [result for result in document.get("results", []) or [] if isinstance(result, dict) and result.get("status") != "passed"]
    if not failing:
        lines.append("No failed or refused regions.")
        return "\n".join(lines) + "\n"
    shown_failing = _limited(failing, limit)
    for index, result in enumerate(shown_failing, start=1):
        function = result.get("function", {})
        name = function.get("name") if isinstance(function, dict) else None
        ordinal = result.get("region_ordinal")
        lines.append(f"### {index}. `{name}` region {ordinal} `{result.get('status')}`")
        oracle_entry = _format_address(result.get("oracle_entry"))
        candidate_entry = _format_address(result.get("candidate_entry"))
        if oracle_entry:
            lines.append(f"- Oracle region entry: `{oracle_entry}`")
        if candidate_entry:
            lines.append(f"- Candidate region entry: `{candidate_entry}`")
        if result.get("reason"):
            lines.append(f"- Reason: `{result.get('reason')}`")
        mismatches = [item for item in result.get("mismatches", []) or [] if isinstance(item, dict)]
        if not mismatches:
            lines.append("- No mismatch detail recorded.")
            lines.append("")
            continue
        for mismatch in mismatches[:mismatch_limit]:
            lines.extend(_format_region_mismatch(mismatch))
        if len(mismatches) > mismatch_limit:
            lines.append(f"- ... {len(mismatches) - mismatch_limit} more mismatches")
        lines.append("")
    if len(failing) > len(shown_failing):
        lines.append(f"... {len(failing) - len(shown_failing)} more failed/refused regions not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_region_mismatch(mismatch: dict[str, Any]) -> list[str]:
    kind = mismatch.get("kind", "unknown")
    lines = [f"- Mismatch: `{kind}`"]
    if "instruction_index" in mismatch:
        lines.append(f"  - Instruction index: {mismatch.get('instruction_index')}")
    if mismatch.get("mnemonic"):
        lines.append(f"  - Mnemonic: `{mismatch.get('mnemonic')}`")
    oracle_instruction = mismatch.get("oracle_instruction")
    candidate_instruction = mismatch.get("candidate_instruction")
    if isinstance(oracle_instruction, dict):
        lines.append(f"  - Oracle instruction: `{_format_instruction(oracle_instruction)}`")
    if isinstance(candidate_instruction, dict):
        lines.append(f"  - Candidate instruction: `{_format_instruction(candidate_instruction)}`")
    if kind == "region_missing":
        lines.append(f"  - Detail: {mismatch.get('detail')}")
        return lines
    if kind == "instruction_count_changed":
        lines.append(f"  - Oracle count: {mismatch.get('oracle')}")
        lines.append(f"  - Candidate count: {mismatch.get('candidate')}")
        return lines
    if "oracle" in mismatch:
        lines.append(f"  - Oracle: `{_compact_json(mismatch.get('oracle'))}`")
    if "candidate" in mismatch:
        lines.append(f"  - Candidate: `{_compact_json(mismatch.get('candidate'))}`")
    return lines


def _render_vector_results(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = document.get("summary", {})
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Backend: `{document.get('backend')}`",
        "",
        "## Summary",
        "",
        f"- Total: {summary.get('total', 0)}",
        f"- Status counts: `{_compact_json(summary.get('status_counts', {}))}`",
        f"- Changed fields: `{_compact_json(summary.get('changed_fields', {}))}`",
        f"- Refusal reasons: `{_compact_json(summary.get('refusal_reasons', {}))}`",
        "",
        "## Failed Or Refused Vectors",
        "",
    ]
    failing = [result for result in document.get("results", []) or [] if isinstance(result, dict) and result.get("status") != "passed"]
    if not failing:
        lines.append("No failed or refused vectors.")
        return "\n".join(lines) + "\n"
    shown_failing = _limited(failing, limit)
    for index, result in enumerate(shown_failing, start=1):
        verdict = result.get("verdict", {}) if isinstance(result.get("verdict"), dict) else {}
        lines.append(f"### {index}. `{result.get('function')}` `{result.get('status')}`")
        lines.append(f"- Vector: `{result.get('vector_id')}`")
        lines.append(f"- Verdict: `{verdict.get('kind')}`")
        changed_fields = list(verdict.get("changed_fields", []) or [])
        if changed_fields:
            lines.append(f"- Changed fields: `{', '.join(str(field) for field in changed_fields)}`")
            oracle = result.get("oracle", {}) if isinstance(result.get("oracle"), dict) else {}
            candidate = result.get("candidate", {}) if isinstance(result.get("candidate"), dict) else {}
            for field in changed_fields[:mismatch_limit]:
                lines.append(f"  - `{field}` oracle: `{_compact_json(oracle.get(field))}`")
                lines.append(f"  - `{field}` candidate: `{_compact_json(candidate.get(field))}`")
        diagnostics = [item for item in result.get("diagnostics", []) or [] if isinstance(item, dict)]
        for diagnostic in diagnostics[:mismatch_limit]:
            lines.append(f"- Diagnostic `{diagnostic.get('reason')}`: {diagnostic.get('message')}")
        lines.append("")
    if len(failing) > len(shown_failing):
        lines.append(f"... {len(failing) - len(shown_failing)} more failed/refused vectors not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _render_data_compare(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = document.get("summary", {})
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Status: `{document.get('status')}`",
        f"Oracle EXE: `{document.get('oracle_exe')}`",
        f"Candidate EXE: `{document.get('candidate_exe')}`",
        "",
        "## Summary",
        "",
        f"- Ranges: {summary.get('ranges', 0)}",
        f"- Literal mismatches: {summary.get('literal_mismatches', 0)}",
        f"- Normalization failures: {summary.get('normalization_failures', 0)}",
        f"- Normalized fields: {summary.get('normalized_fields', 0)}",
        "",
        "## Failed Data Ranges",
        "",
    ]
    failed_ranges = [item for item in document.get("ranges", []) or [] if isinstance(item, dict) and item.get("status") != "passed"]
    if not failed_ranges:
        lines.append("No failed data ranges.")
    shown_failed_ranges = _limited(failed_ranges, limit)
    for index, item in enumerate(shown_failed_ranges, start=1):
        lines.append(f"### {index}. `{item.get('oracle_segment')}` -> `{item.get('candidate_segment')}`")
        lines.append(f"- Range: `{item.get('start')}..{item.get('end')}`")
        lines.append(f"- Mismatches: {item.get('mismatch_count')}")
        for mismatch in (item.get("mismatches", []) or [])[:mismatch_limit]:
            if isinstance(mismatch, dict):
                lines.append(f"  - Offset `{mismatch.get('offset')}` oracle `{mismatch.get('oracle')}` candidate `{mismatch.get('candidate')}`")
        lines.append("")
    failed_norms = [item for item in document.get("normalizations", []) or [] if isinstance(item, dict) and item.get("status") != "passed"]
    if failed_norms:
        lines.append("## Failed Normalizations")
        lines.append("")
        for item in _limited(failed_norms, limit):
            lines.append(f"- `{item.get('symbol')}` oracle `{item.get('oracle_value')}` expected `{item.get('oracle_expected')}`; candidate `{item.get('candidate_value')}` expected `{item.get('candidate_expected')}`")
    return "\n".join(lines) + "\n"


def _render_complexity(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    counters = document.get("counters", {}) if isinstance(document.get("counters"), dict) else {}
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"EXE: `{document.get('exe')}`",
        "",
        "## Summary",
        "",
        f"- Functions seen: {counters.get('functions_seen', 0)}",
        f"- Functions analyzed: {counters.get('functions_analyzed', 0)}",
        f"- Simple whole functions: {counters.get('simple_whole_functions', 0)}",
        f"- Complex functions: {counters.get('complex_functions', 0)}",
        f"- Refused functions: {counters.get('refused_functions', 0)}",
        f"- Comparison parts: {counters.get('comparison_parts_emitted', 0)}",
        f"- Refusal reasons: `{_compact_json(counters.get('refusals_by_reason', {}))}`",
        "",
        "## Complex Functions",
        "",
    ]
    complex_functions = [item for item in document.get("functions", []) or [] if isinstance(item, dict) and item.get("classification") != "simple_whole_function"]
    if not complex_functions:
        lines.append("No complex functions.")
    shown_complex_functions = _limited(complex_functions, limit)
    for index, item in enumerate(shown_complex_functions, start=1):
        function = item.get("function", {}) if isinstance(item.get("function"), dict) else {}
        entry = _format_address(item.get("entry"))
        risk = item.get("risk", {}) if isinstance(item.get("risk"), dict) else {}
        lines.append(f"### {index}. `{function.get('name', function.get('id', '<unknown>'))}`")
        if entry:
            lines.append(f"- Entry: `{entry}`")
        lines.append(f"- Classification: `{item.get('classification')}`")
        lines.append(f"- Risk score: {risk.get('score', 0)}")
        blockers = [blocker for blocker in item.get("blockers", []) or [] if isinstance(blocker, dict)]
        if blockers:
            lines.append(f"- Blockers: `{', '.join(str(blocker.get('kind')) for blocker in blockers[:mismatch_limit])}`")
        metrics = item.get("metrics", {}) if isinstance(item.get("metrics"), dict) else {}
        metric_summary = {
            "insns": metrics.get("instruction_count"),
            "conditions": metrics.get("condition_count"),
            "calls": metrics.get("call_count"),
            "indirect": metrics.get("indirect_control_count"),
            "symbolic_memory": metrics.get("explicit_symbolic_memory_count"),
            "backward": metrics.get("backward_branch_count"),
        }
        lines.append(f"- Metrics: `{_compact_json(metric_summary)}`")
        risk_points = [point for point in item.get("risk_points", []) or [] if isinstance(point, dict)]
        for point in risk_points[:mismatch_limit]:
            address = _format_address(point.get("address"))
            location = f"{address}: " if address else ""
            lines.append(f"  - `{', '.join(str(kind) for kind in point.get('kinds', []))}` {location}{point.get('disassembly')}")
        lines.append("")
    if len(complex_functions) > len(shown_complex_functions):
        lines.append(f"... {len(complex_functions) - len(shown_complex_functions)} more complex functions not shown.")
        lines.append("")

    refusals = [item for item in document.get("refusals", []) or [] if isinstance(item, dict)]
    if refusals:
        lines.append("## Refusals")
        lines.append("")
        shown_refusals = _limited(refusals, limit)
        for index, item in enumerate(shown_refusals, start=1):
            detail = item.get("detail", {}) if isinstance(item.get("detail"), dict) else {}
            lines.append(f"### {index}. `{item.get('reason')}`")
            if detail.get("function_id"):
                lines.append(f"- Function: `{detail.get('function_id')}`")
            if detail.get("message"):
                lines.append(f"- Message: {detail.get('message')}")
            lines.append("")
        if len(refusals) > len(shown_refusals):
            lines.append(f"... {len(refusals) - len(shown_refusals)} more refusals not shown.")
            lines.append("")
    return "\n".join(lines) + "\n"


def _render_ssa_compare(
    document: dict[str, Any],
    *,
    limit: int,
    mismatch_limit: int,
    show_unresolved_call_targets: bool,
) -> str:
    summary = document.get("summary", {}) if isinstance(document.get("summary"), dict) else {}
    results = [result for result in document.get("results", []) or [] if isinstance(result, dict)]
    failing = [result for result in results if result.get("status") != "passed"]
    skipped_function_missing = [result for result in failing if _has_mismatch_kind(result, "function_missing")]
    unresolved_call_target_failures = [
        result
        for result in failing
        if not _has_mismatch_kind(result, "function_missing") and _has_unresolved_call_target(result)
    ]
    displayed_failing = [
        result
        for result in failing
        if not _has_mismatch_kind(result, "function_missing")
        and (show_unresolved_call_targets or not _has_unresolved_call_target(result))
    ]
    semantic_failures = [result for result in displayed_failing if result.get("status") == "failed"]
    mapping_gaps = [result for result in displayed_failing if result.get("reason") in {"mapping_missing", "candidate_ssa_missing"}]
    other_refusals = [result for result in displayed_failing if result.get("status") == "refused" and result not in mapping_gaps]
    status_reasons = Counter(f"{result.get('status')}:{result.get('reason')}" for result in displayed_failing)
    mismatch_kinds = Counter(
        str(mismatch.get("kind", "unknown"))
        for result in displayed_failing
        for mismatch in (result.get("mismatches", []) or [])
        if isinstance(mismatch, dict)
    )
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Oracle: `{document.get('oracle')}`",
        f"Candidate: `{document.get('candidate')}`",
        f"Mapping: `{document.get('mapping')}`",
        "",
        "## Summary",
        "",
        f"- Total: {summary.get('total', 0)}",
        f"- Passed: {summary.get('passed', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Refused: {summary.get('refused', 0)}",
        f"- Unmapped oracle functions: {summary.get('skipped_unmapped', 0)}",
        f"- Missing-function rows skipped: {len(skipped_function_missing)}",
        f"- Unresolved-call-target rows skipped: {0 if show_unresolved_call_targets else len(unresolved_call_target_failures)}",
        f"- Solver time ms: {summary.get('solver_time_ms', 0)}",
        "",
        "## Cause Summary",
        "",
        f"- Failed/refused by reason: `{_compact_json(dict(sorted(status_reasons.items())))}`",
        f"- Mismatch kinds: `{_compact_json(dict(sorted(mismatch_kinds.items())))}`",
        "",
        "## Failed Or Refused SSA Functions",
        "",
    ]
    if not displayed_failing:
        lines.append("No failed or refused SSA functions.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "### Reading Notes",
            "",
            "- `observable_mismatch` means Z3 found a symbolic entry state where the bounded SSA outputs differ.",
            "- `memory_expr_changed` means modeled memory effects differ; inspect the shown stores/address expressions in the listed blocks.",
            "- `mapping_missing` means no rebuilt function was mapped for this oracle function; fix mapping/catalog before treating it as a decompiler bug.",
            "- `candidate_ssa_missing` means mapping exists, but the candidate function did not lower to SSA.",
            "- Missing-function mapping rows are omitted from detailed sections by default.",
            "- Unresolved direct-call-target rows are omitted by default; pass `--show-unresolved-call-targets` to include them.",
            "",
        ]
    )

    lines.append("## Semantic Mismatches")
    lines.append("")
    if not semantic_failures:
        lines.append("No semantic SSA mismatches.")
        lines.append("")
    shown_semantic_failures = _limited(semantic_failures, limit)
    for index, result in enumerate(shown_semantic_failures, start=1):
        lines.extend(_format_ssa_result(result, index=index, mismatch_limit=mismatch_limit, show_candidate=True))
    if len(semantic_failures) > len(shown_semantic_failures):
        lines.append(f"... {len(semantic_failures) - len(shown_semantic_failures)} more semantic mismatches not shown.")
        lines.append("")

    lines.append("## Mapping / Lowering Gaps")
    lines.append("")
    if not mapping_gaps:
        lines.append("No mapping or candidate-lowering gaps.")
        lines.append("")
    shown_mapping_gaps = _limited(mapping_gaps, limit)
    for index, result in enumerate(shown_mapping_gaps, start=1):
        lines.extend(_format_ssa_result(result, index=index, mismatch_limit=mismatch_limit, show_candidate=False))
    if len(mapping_gaps) > len(shown_mapping_gaps):
        lines.append(f"... {len(mapping_gaps) - len(shown_mapping_gaps)} more mapping/lowering gaps not shown.")
        lines.append("")

    if other_refusals:
        lines.append("## Other Refusals")
        lines.append("")
        shown_other_refusals = _limited(other_refusals, limit)
        for index, result in enumerate(shown_other_refusals, start=1):
            lines.extend(_format_ssa_result(result, index=index, mismatch_limit=mismatch_limit, show_candidate=True))
        if len(other_refusals) > len(shown_other_refusals):
            lines.append(f"... {len(other_refusals) - len(shown_other_refusals)} more other refusals not shown.")
            lines.append("")
    displayed_count = len(shown_semantic_failures) + len(shown_mapping_gaps) + len(_limited(other_refusals, limit))
    if len(displayed_failing) > displayed_count:
        lines.append(f"Total hidden by per-section limits: {len(displayed_failing) - displayed_count}.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _has_mismatch_kind(result: dict[str, Any], kind: str) -> bool:
    return any(isinstance(mismatch, dict) and mismatch.get("kind") == kind for mismatch in (result.get("mismatches", []) or []))


def _render_ssa_abi_compare(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = document.get("summary", {}) if isinstance(document.get("summary"), dict) else {}
    results = [result for result in document.get("results", []) or [] if isinstance(result, dict)]
    failing = [result for result in results if result.get("status") != "passed"]
    status_reasons = Counter(f"{result.get('status')}:{result.get('reason')}" for result in failing)
    mismatch_kinds = Counter(
        str(mismatch.get("kind", "unknown"))
        for result in failing
        for mismatch in (result.get("mismatches", []) or [])
        if isinstance(mismatch, dict)
    )
    lines = [
        "# DOS Unit ABI SSA Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Oracle: `{document.get('oracle')}`",
        f"Candidate: `{document.get('candidate')}`",
        f"Mapping: `{document.get('mapping')}`",
        f"Data segment: `{document.get('data_segment_para')}`",
        "",
        "## Summary",
        "",
        f"- Total: {summary.get('total', 0)}",
        f"- Passed: {summary.get('passed', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Refused: {summary.get('refused', 0)}",
        f"- Solver time ms: {summary.get('solver_time_ms', 0)}",
        "",
        "## Cause Summary",
        "",
        f"- Failed/refused by reason: `{_compact_json(dict(sorted(status_reasons.items())))}`",
        f"- Mismatch kinds: `{_compact_json(dict(sorted(mismatch_kinds.items())))}`",
        "",
        "## Failed Or Refused ABI Functions",
        "",
    ]
    if not failing:
        lines.append("No failed or refused ABI functions.")
        return "\n".join(lines) + "\n"
    lines.extend(
        [
            "### Reading Notes",
            "",
            "- `call_boundary` means the bounded function summary reached a call; static proof needs a callee summary/inlining policy.",
            "- Memory observables are declared ABI/data effects, not whole-memory equality, so temporary stack pushes are ignored.",
            "- `observable_mismatch` means Z3 found a symbolic entry state where a declared ABI register or memory effect differs.",
            "",
        ]
    )
    shown = _limited(failing, limit)
    for index, result in enumerate(shown, start=1):
        lines.extend(_format_ssa_abi_result(result, index=index, mismatch_limit=mismatch_limit))
    if len(failing) > len(shown):
        lines.append(f"... {len(failing) - len(shown)} more failed/refused ABI functions not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_ssa_abi_result(result: dict[str, Any], *, index: int, mismatch_limit: int) -> list[str]:
    function = result.get("function", {}) if isinstance(result.get("function"), dict) else {}
    name = function.get("name", "<unknown>")
    lines = [f"### {index}. `{name}` `{result.get('status')}`"]
    if function.get("kind"):
        lines.append(f"- Kind: `{function.get('kind')}`")
    if function.get("calling_convention"):
        lines.append(f"- Calling convention: `{function.get('calling_convention')}`")
    if result.get("reason"):
        lines.append(f"- Reason: `{result.get('reason')}`")
    if function.get("inputs"):
        lines.append("- Register inputs: " + ", ".join(f"`{item.get('location')}:{item.get('name')}`" for item in function.get("inputs", []) if isinstance(item, dict)))
    if function.get("stack_args"):
        lines.append("- Stack args: " + ", ".join(f"`[bp+{item.get('bp_offset')}]:{item.get('name')}`" for item in function.get("stack_args", []) if isinstance(item, dict)))
    if function.get("returns"):
        lines.append("- Returns: " + ", ".join(f"`{item.get('location')}`" for item in function.get("returns", []) if isinstance(item, dict)))
    if function.get("preserved"):
        lines.append("- Preserved: " + ", ".join(f"`{item}`" for item in function.get("preserved", []) or []))
    if function.get("clobbers"):
        lines.append("- Clobbers: " + ", ".join(f"`{item}`" for item in function.get("clobbers", []) or []))
    observables = result.get("observables") if isinstance(result.get("observables"), dict) else {}
    if observables:
        lines.append("- Compared regs: " + ", ".join(f"`{item}`" for item in observables.get("regs", []) or []))
        effects = [item for item in observables.get("memory", []) or [] if isinstance(item, dict)]
        if effects:
            lines.append("- Compared memory effects: " + ", ".join(f"`{item.get('space', 'SEG')}:{item.get('offset')} {item.get('name', '')}`".strip() for item in effects))
    for label, key in (("Oracle summary", "oracle_summary"), ("Candidate summary", "candidate_summary")):
        summary = result.get(key) if isinstance(result.get(key), dict) else None
        if not summary:
            continue
        lines.append(
            f"- {label}: status `{summary.get('status')}`, parts `{summary.get('part_count')}`, terminals `{summary.get('terminal_count')}`, inputs `{summary.get('input_count')}`, assignments `{summary.get('assignment_count')}`"
        )
        if summary.get("outputs"):
            lines.append(f"  - Outputs: `{', '.join(str(item) for item in summary.get('outputs', []) or [])}`")
    mismatches = [item for item in result.get("mismatches", []) or [] if isinstance(item, dict)]
    if mismatches:
        lines.append("- Mismatches:")
        for mismatch in mismatches[:mismatch_limit]:
            lines.extend(_format_ssa_mismatch(mismatch))
        if len(mismatches) > mismatch_limit:
            lines.append(f"  - ... {len(mismatches) - mismatch_limit} more mismatches")
    else:
        lines.append("- No mismatch detail recorded.")
    lines.append("")
    return lines


def _has_unresolved_call_target(result: dict[str, Any]) -> bool:
    call_compare = result.get("call_compare") if isinstance(result.get("call_compare"), dict) else None
    if not call_compare:
        return False
    for side in ("oracle", "candidate"):
        call = call_compare.get(side) if isinstance(call_compare.get(side), dict) else None
        if call and call.get("resolved") is None:
            return True
    return False


def _format_ssa_result(result: dict[str, Any], *, index: int, mismatch_limit: int, show_candidate: bool) -> list[str]:
    function = result.get("function", {}) if isinstance(result.get("function"), dict) else {}
    name = function.get("name", function.get("id", "<unknown>"))
    lines = [f"### {index}. `{name}` `{result.get('status')}`"]
    if function.get("id"):
        lines.append(f"- Function id: `{function.get('id')}`")
    if result.get("reason"):
        lines.append(f"- Reason: `{result.get('reason')}`")
    if result.get("oracle_function"):
        lines.append(f"- Oracle SSA id: `{result.get('oracle_function')}`")
    if result.get("candidate_function"):
        lines.append(f"- Candidate SSA id: `{result.get('candidate_function')}`")
    mapped_candidate = result.get("mapped_candidate") if isinstance(result.get("mapped_candidate"), dict) else None
    if mapped_candidate:
        lines.append(f"- Mapped candidate: `{mapped_candidate.get('name') or mapped_candidate.get('id')}` `{_format_ssa_entry(mapped_candidate.get('entry'))}`")

    oracle_detail = result.get("oracle_detail") if isinstance(result.get("oracle_detail"), dict) else None
    candidate_detail = result.get("candidate_detail") if isinstance(result.get("candidate_detail"), dict) else None
    lines.extend(_format_ssa_side("Oracle", oracle_detail))
    if show_candidate:
        lines.extend(_format_ssa_side("Candidate", candidate_detail))
    if _ssa_jumpkind(oracle_detail) == "Ijk_Call" or _ssa_jumpkind(candidate_detail) == "Ijk_Call":
        lines.append("- Call-boundary note: this bounded SSA block stops at a call; memory differences may reflect pushed arguments/return state or an unmapped call-target summary.")
    call_compare = result.get("call_compare") if isinstance(result.get("call_compare"), dict) else None
    if call_compare:
        lines.extend(_format_ssa_call_compare(call_compare))
    layout_normalization = result.get("layout_normalization") if isinstance(result.get("layout_normalization"), dict) else None
    if layout_normalization:
        lines.extend(_format_layout_normalization(layout_normalization))

    mismatches = [item for item in result.get("mismatches", []) or [] if isinstance(item, dict)]
    if mismatches:
        lines.append("- Mismatches:")
    for mismatch in mismatches[:mismatch_limit]:
        lines.extend(_format_ssa_mismatch(mismatch))
    if len(mismatches) > mismatch_limit:
        lines.append(f"  - ... {len(mismatches) - mismatch_limit} more mismatches")
    if not mismatches:
        lines.append("- No mismatch detail recorded.")
    lines.append("")
    return lines


def _format_layout_normalization(layout_normalization: dict[str, Any]) -> list[str]:
    pairs = [item for item in layout_normalization.get("pairs", []) or [] if isinstance(item, dict)]
    if not pairs:
        return []
    lines = ["- Layout constant normalization:"]
    for pair in pairs[:8]:
        lines.append(
            f"  - candidate `{pair.get('candidate')}` -> oracle `{pair.get('oracle')}` ({pair.get('reason', 'unknown')})"
        )
    if len(pairs) > 8:
        lines.append(f"  - ... {len(pairs) - 8} more layout constants")
    return lines


def _format_ssa_side(label: str, detail: dict[str, Any] | None) -> list[str]:
    if not isinstance(detail, dict):
        return [f"- {label}: no SSA detail recorded"]
    outputs = ", ".join(str(item) for item in detail.get("outputs", []) or [])
    lines = [
        f"- {label} entry: `{_format_ssa_entry(detail.get('entry'))}`",
        f"- {label} block: `{detail.get('instruction_count', 0)} insns`, jumpkind `{detail.get('jumpkind')}`, inputs `{detail.get('input_count', 0)}`, assignments `{detail.get('assignment_count', 0)}`, outputs `{outputs}`",
    ]
    part = detail.get("part") if isinstance(detail.get("part"), dict) else None
    if part:
        lines.append(f"- {label} SSA part: `{part.get('kind', 'block')}` #{part.get('index', 0)} delta `{part.get('entry_delta', '0x0000')}`")
    if detail.get("function_machine_code_sha256"):
        lines.append(
            f"- {label} function bytes: size `{detail.get('function_machine_code_size')}`, sha256 `{str(detail.get('function_machine_code_sha256'))[:16]}...`"
        )
    if detail.get("machine_code_sha256"):
        lines.append(f"- {label} block bytes: size `{detail.get('machine_code_size')}`, sha256 `{str(detail.get('machine_code_sha256'))[:16]}...`")
    instructions = [item for item in detail.get("instructions", []) or [] if isinstance(item, dict)]
    if instructions:
        lines.append(f"- {label} instructions:")
        for instruction in instructions:
            lines.append(f"  - `{_format_instruction(instruction)}`")
        truncated = int(detail.get("instructions_truncated", 0) or 0)
        if truncated:
            lines.append(f"  - WARNING: report input already truncated {truncated} lifted instructions before rendering")
    return lines


def _format_ssa_call_compare(call_compare: dict[str, Any]) -> list[str]:
    equivalent = "yes" if call_compare.get("equivalent") else "no"
    lines = [
        f"- Direct call target equivalent: `{equivalent}`",
        f"  - Reason: {call_compare.get('reason')}",
    ]
    oracle = call_compare.get("oracle") if isinstance(call_compare.get("oracle"), dict) else None
    candidate = call_compare.get("candidate") if isinstance(call_compare.get("candidate"), dict) else None
    lines.extend(_format_ssa_call_side("Oracle call", oracle))
    lines.extend(_format_ssa_call_side("Candidate call", candidate))
    normalizations = [item for item in call_compare.get("normalizations", []) or [] if isinstance(item, dict)]
    if normalizations:
        lines.append("  - Z3 call normalizations:")
        for item in normalizations:
            applied = "yes" if item.get("applied") else "no"
            detail = f"{item.get('side')}: applied={applied}; {item.get('reason')}"
            if item.get("stored") or item.get("fallthrough"):
                detail += f"; stored={item.get('stored')}; fallthrough={item.get('fallthrough')}"
            lines.append(f"    - {detail}")
    return lines


def _format_ssa_call_side(label: str, call: dict[str, Any] | None) -> list[str]:
    if not isinstance(call, dict):
        return [f"  - {label}: no direct call"]
    resolved = call.get("resolved") if isinstance(call.get("resolved"), dict) else None
    target = call.get("raw", "<unknown>")
    low16 = call.get("low16", "<unknown>")
    if resolved:
        entry = _format_ssa_entry(resolved.get("entry"))
        lines = [f"  - {label}: target `{target}` low16 `{low16}` -> `{resolved.get('name') or resolved.get('id')}` `{entry}`"]
        instructions = [item for item in resolved.get("instructions", []) or [] if isinstance(item, dict)]
        if instructions:
            lines.append("    - Target first instructions:")
            for instruction in instructions:
                lines.append(f"      - `{_format_instruction(instruction)}`")
        return lines
    reason = call.get("reason", "unresolved")
    return [f"  - {label}: target `{target}` low16 `{low16}` -> unresolved ({reason})"]


def _format_ssa_mismatch(mismatch: dict[str, Any]) -> list[str]:
    lines = [f"  - Kind: `{mismatch.get('kind')}`"]
    if mismatch.get("reg"):
        lines.append(f"    - Register: `{mismatch.get('reg')}`")
    if "oracle_value" in mismatch:
        lines.append(f"    - Oracle value: `{mismatch.get('oracle_value')}`")
    if "candidate_value" in mismatch:
        lines.append(f"    - Candidate value: `{mismatch.get('candidate_value')}`")
    if "counterexample" in mismatch:
        lines.append(f"    - Counterexample: `{_compact_json(mismatch.get('counterexample'))}`")
    if mismatch.get("kind") == "output_set_changed":
        lines.append(f"    - Oracle-only outputs: `{', '.join(str(item) for item in mismatch.get('oracle_only', []) or [])}`")
        lines.append(f"    - Candidate-only outputs: `{', '.join(str(item) for item in mismatch.get('candidate_only', []) or [])}`")
    if "detail" in mismatch:
        lines.append(f"    - Detail: {mismatch.get('detail')}")
    if mismatch.get("kind") == "memory_expr_changed":
        lines.append("    - Investigation: compare modeled stores/pushes and address expressions in the shown blocks; for call blocks, verify the callee mapping/summary.")
    if mismatch.get("kind") == "output_expr_changed":
        lines.append("    - Investigation: compare the producer of the listed register in the shown blocks; `ip` differences are often control-flow or layout mapping issues.")
    return lines


def _format_ssa_entry(entry: Any) -> str:
    if not isinstance(entry, dict):
        return "<unknown>"
    cs = entry.get("cs")
    ip = entry.get("ip")
    linear = entry.get("linear")
    parts = []
    if cs or ip:
        parts.append(f"{cs or '????'}:{ip or '????'}")
    if linear:
        parts.append(str(linear))
    return " / ".join(parts) if parts else "<unknown>"


def _ssa_jumpkind(detail: dict[str, Any] | None) -> str | None:
    if not isinstance(detail, dict):
        return None
    jumpkind = detail.get("jumpkind")
    return str(jumpkind) if jumpkind is not None else None


def _render_refusals(document: dict[str, Any], *, limit: int) -> str:
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema', 'unknown')}`",
        "",
        "## Refusals",
        "",
    ]
    refusals = [item for item in document.get("refusals", []) or [] if isinstance(item, dict)]
    if not refusals:
        lines.append("No refusals.")
        return "\n".join(lines) + "\n"
    shown_refusals = _limited(refusals, limit)
    for index, item in enumerate(shown_refusals, start=1):
        detail = item.get("detail", {}) if isinstance(item.get("detail"), dict) else {}
        lines.append(f"### {index}. `{item.get('reason')}`")
        if detail.get("function_id"):
            lines.append(f"- Function: `{detail.get('function_id')}`")
        if detail.get("message"):
            lines.append(f"- Message: {detail.get('message')}")
        lines.append("")
    if len(refusals) > len(shown_refusals):
        lines.append(f"... {len(refusals) - len(shown_refusals)} more refusals not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _render_unknown(document: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# DOS Unit Failure Report",
            "",
            f"Schema: `{document.get('schema', 'unknown')}`",
            "",
            "No specialized failure renderer is available for this document.",
            "",
        ]
    )


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _format_instruction(instruction: dict[str, Any]) -> str:
    address = _format_address(instruction.get("address"))
    disassembly = instruction.get("disassembly", "")
    if address:
        return f"{address}: {disassembly}"
    return str(disassembly)


def _format_address(address: Any) -> str | None:
    if not isinstance(address, dict):
        return None
    ip = address.get("ip")
    linear = address.get("linear")
    if ip and linear:
        return f"{ip} ({linear})"
    if ip:
        return str(ip)
    if linear:
        return str(linear)
    return None
