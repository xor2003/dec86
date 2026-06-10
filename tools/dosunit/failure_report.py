from __future__ import annotations

import json
from typing import Any


def render_failure_report(document: dict[str, Any], *, limit: int = 50, mismatch_limit: int = 8) -> str:
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
        return _render_ssa_compare(document, limit=limit, mismatch_limit=mismatch_limit)
    if "refusals" in document:
        return _render_refusals(document, limit=limit)
    return _render_unknown(document)


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
    for index, result in enumerate(failing[:limit], start=1):
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
    if len(failing) > limit:
        lines.append(f"... {len(failing) - limit} more failed/refused regions not shown.")
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
    for index, result in enumerate(failing[:limit], start=1):
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
    if len(failing) > limit:
        lines.append(f"... {len(failing) - limit} more failed/refused vectors not shown.")
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
    for index, item in enumerate(failed_ranges[:limit], start=1):
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
        for item in failed_norms[:limit]:
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
    for index, item in enumerate(complex_functions[:limit], start=1):
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
    if len(complex_functions) > limit:
        lines.append(f"... {len(complex_functions) - limit} more complex functions not shown.")
        lines.append("")

    refusals = [item for item in document.get("refusals", []) or [] if isinstance(item, dict)]
    if refusals:
        lines.append("## Refusals")
        lines.append("")
        for index, item in enumerate(refusals[:limit], start=1):
            detail = item.get("detail", {}) if isinstance(item.get("detail"), dict) else {}
            lines.append(f"### {index}. `{item.get('reason')}`")
            if detail.get("function_id"):
                lines.append(f"- Function: `{detail.get('function_id')}`")
            if detail.get("message"):
                lines.append(f"- Message: {detail.get('message')}")
            lines.append("")
        if len(refusals) > limit:
            lines.append(f"... {len(refusals) - limit} more refusals not shown.")
            lines.append("")
    return "\n".join(lines) + "\n"


def _render_ssa_compare(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = document.get("summary", {}) if isinstance(document.get("summary"), dict) else {}
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
        f"- Skipped unmapped: {summary.get('skipped_unmapped', 0)}",
        f"- Solver time ms: {summary.get('solver_time_ms', 0)}",
        "",
        "## Failed Or Refused SSA Functions",
        "",
    ]
    failing = [result for result in document.get("results", []) or [] if isinstance(result, dict) and result.get("status") != "passed"]
    if not failing:
        lines.append("No failed or refused SSA functions.")
        return "\n".join(lines) + "\n"
    for index, result in enumerate(failing[:limit], start=1):
        function = result.get("function", {}) if isinstance(result.get("function"), dict) else {}
        lines.append(f"### {index}. `{function.get('name', function.get('id', '<unknown>'))}` `{result.get('status')}`")
        if result.get("reason"):
            lines.append(f"- Reason: `{result.get('reason')}`")
        mismatches = [item for item in result.get("mismatches", []) or [] if isinstance(item, dict)]
        for mismatch in mismatches[:mismatch_limit]:
            lines.append(f"- Mismatch: `{mismatch.get('kind')}`")
            if mismatch.get("reg"):
                lines.append(f"  - Register: `{mismatch.get('reg')}`")
            if "oracle_value" in mismatch:
                lines.append(f"  - Oracle value: `{mismatch.get('oracle_value')}`")
            if "candidate_value" in mismatch:
                lines.append(f"  - Candidate value: `{mismatch.get('candidate_value')}`")
            if "counterexample" in mismatch:
                lines.append(f"  - Counterexample: `{_compact_json(mismatch.get('counterexample'))}`")
            if "detail" in mismatch:
                lines.append(f"  - Detail: {mismatch.get('detail')}")
        if len(mismatches) > mismatch_limit:
            lines.append(f"- ... {len(mismatches) - mismatch_limit} more mismatches")
        lines.append("")
    if len(failing) > limit:
        lines.append(f"... {len(failing) - limit} more failed/refused SSA functions not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


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
    for index, item in enumerate(refusals[:limit], start=1):
        detail = item.get("detail", {}) if isinstance(item.get("detail"), dict) else {}
        lines.append(f"### {index}. `{item.get('reason')}`")
        if detail.get("function_id"):
            lines.append(f"- Function: `{detail.get('function_id')}`")
        if detail.get("message"):
            lines.append(f"- Message: {detail.get('message')}")
        lines.append("")
    if len(refusals) > limit:
        lines.append(f"... {len(refusals) - limit} more refusals not shown.")
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
