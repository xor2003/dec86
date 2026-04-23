from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

CYCLE_STATE_SCHEMA_VERSION = "meta_harness.cycle_state.v1"
PREFLIGHT_STATE_SCHEMA_VERSION = "meta_harness.preflight.v1"
SESSION_LEDGER_SCHEMA_VERSION = "meta_harness.session.v1"
HISTORY_EVENT_SCHEMA_VERSION = "meta_harness.event.v1"
EVIDENCE_FACTS_SCHEMA_VERSION = "meta_harness.evidence_facts.v1"

EVENT_NAMES = {
    "cycle.started",
    "cycle.resumed",
    "cycle.outcome",
    "branch.stale_against_main",
    "role.started",
    "role.finished",
    "role.failed",
    "role.timed_out",
    "worker.stalled",
    "planner.rewrite_requested",
    "sweep.started",
    "sweep.finished",
    "sweep.failed",
    "operator.comments_consumed",
    "operator.action_requested",
    "maintenance.scheduled",
    "preflight.profilers_missing",
    "harness.restarting",
}

EVENT_STATUSES = {
    "running",
    "ready",
    "retrying",
    "blocked",
    "completed",
    "failed",
    "warning",
}

FAILURE_CLASSES = {
    "provider_failure",
    "worker_timeout",
    "worker_no_progress",
    "plan_item_too_broad",
    "reviewer_plan_mismatch",
    "sweep_failure",
    "resource_blocked",
    "restart_required",
    "ui_visibility_failure",
}


def iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def append_jsonl(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, sort_keys=True) + "\n")


def load_jsonl(path: Path, limit: int = 50) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            rows.append(entry)
    return rows


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def parse_usage_metrics(text: str) -> dict[str, object]:
    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0
    cost_usd = 0.0
    prompt_re = re.compile(r"\b(?:prompt_tokens|input_tokens)\b\s*[:=]\s*(\d+)")
    completion_re = re.compile(r"\b(?:completion_tokens|output_tokens)\b\s*[:=]\s*(\d+)")
    total_re = re.compile(r"\btotal_tokens\b\s*[:=]\s*(\d+)")
    cost_re = re.compile(r"\b(?:cost_usd|total_cost_usd|usd_cost)\b\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)")
    codex_tokens_re = re.compile(r"\btokens used\b\s*[:=]?\s*([0-9][0-9,]*)", re.IGNORECASE)

    for match in prompt_re.finditer(text):
        prompt_tokens += int(match.group(1))
    for match in completion_re.finditer(text):
        completion_tokens += int(match.group(1))
    for match in total_re.finditer(text):
        total_tokens += int(match.group(1))
    for match in cost_re.finditer(text):
        cost_usd += float(match.group(1))
    for match in codex_tokens_re.finditer(text):
        total_tokens += int(match.group(1).replace(",", ""))

    if total_tokens == 0:
        total_tokens = prompt_tokens + completion_tokens
    return {
        "prompt_tokens": prompt_tokens or None,
        "completion_tokens": completion_tokens or None,
        "total_tokens": total_tokens or None,
        "cost_usd": round(cost_usd, 6) if cost_usd else None,
    }


def build_history_event(
    *,
    event: str,
    status: str,
    message: str,
    at: str,
    cycle: int,
    current_plan_item: str,
    failure_class: str | None = None,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    if event not in EVENT_NAMES:
        raise ValueError(f"Unknown harness event: {event}")
    if status not in EVENT_STATUSES:
        raise ValueError(f"Unknown harness event status: {status}")
    if failure_class and failure_class not in FAILURE_CLASSES:
        raise ValueError(f"Unknown harness failure class: {failure_class}")
    return {
        "schema_version": HISTORY_EVENT_SCHEMA_VERSION,
        "at": at,
        "event": event,
        "status": status,
        "message": message,
        "cycle": cycle,
        "current_plan_item": current_plan_item,
        "failure_class": failure_class or "",
        "details": details or {},
    }


def summarize_session_rows(rows: list[dict[str, object]]) -> dict[str, object]:
    total_sessions = 0
    total_duration_secs = 0
    total_tokens = 0
    total_cost = 0.0
    roles: dict[str, int] = {}
    for row in rows:
        total_sessions += 1
        role = str(row.get("role", "unknown"))
        roles[role] = roles.get(role, 0) + 1
        duration = row.get("duration_secs")
        tokens = row.get("total_tokens")
        cost = row.get("cost_usd")
        if isinstance(duration, int):
            total_duration_secs += duration
        if isinstance(tokens, int):
            total_tokens += tokens
        if isinstance(cost, (float, int)):
            total_cost += float(cost)
    return {
        "total_sessions": total_sessions,
        "total_duration_secs": total_duration_secs,
        "total_tokens": total_tokens or None,
        "total_cost_usd": round(total_cost, 6) if total_cost else None,
        "by_role": roles,
    }


def compact_runtime_signals(
    history_rows: list[dict[str, object]],
    session_rows: list[dict[str, object]],
) -> dict[str, object]:
    event_counts: Counter[str] = Counter()
    failure_counts: Counter[str] = Counter()
    role_tokens: Counter[str] = Counter()
    plan_item_sessions: Counter[str] = Counter()
    for row in history_rows:
        event = str(row.get("event", "") or "")
        failure_class = str(row.get("failure_class", "") or "")
        if event:
            event_counts[event] += 1
        if failure_class:
            failure_counts[failure_class] += 1
    for row in session_rows:
        role = str(row.get("role", "unknown") or "unknown")
        current_plan_item = str(row.get("current_plan_item", "") or "")
        tokens = row.get("total_tokens")
        if isinstance(tokens, int):
            role_tokens[role] += tokens
        if current_plan_item:
            plan_item_sessions[current_plan_item] += 1
    return {
        "top_events": [{"name": name, "count": count} for name, count in event_counts.most_common(5)],
        "top_failure_classes": [{"name": name, "count": count} for name, count in failure_counts.most_common(5)],
        "top_roles_by_tokens": [{"name": name, "tokens": count} for name, count in role_tokens.most_common(5)],
        "top_plan_items_by_sessions": [
            {"item": name, "count": count} for name, count in plan_item_sessions.most_common(5)
        ],
    }


def build_evidence_facts(
    text: str,
    *,
    low_confidence_threshold: float = 0.6,
    generated_at: str | None = None,
) -> dict[str, object]:
    facts: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    key_value_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})=(-?\d+(?:\.\d+)?)\b")
    validation_re = re.compile(r"\bvalidation=([A-Za-z_][A-Za-z0-9_-]*)")
    done_re = re.compile(r"\bdone in ([0-9]+(?:\.[0-9]+)?)s")
    detail_re = re.compile(r"detail artifact (\S+)")
    retry_re = re.compile(r"retry reason=(.+)")
    failure_ratio_re = re.compile(r"failures=(\d+)/(\d+)")

    def _normalize_value(value: object) -> str:
        if isinstance(value, dict):
            return json.dumps(value, sort_keys=True)
        if isinstance(value, float):
            return f"{value:.6g}"
        return str(value)

    def _add_fact(
        *,
        kind: str,
        key: str,
        value: object,
        confidence: float,
        line_no: int,
        line: str,
        reason: str,
    ) -> None:
        dedupe_key = (kind, key, _normalize_value(value))
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        bounded = round(max(0.0, min(1.0, confidence)), 3)
        facts.append(
            {
                "kind": kind,
                "key": key,
                "value": value,
                "confidence": bounded,
                "confidence_pct": round(bounded * 100.0, 1),
                "line_no": line_no,
                "line": line,
                "reason": reason,
                "needs_more_evidence": bounded < low_confidence_threshold,
            }
        )

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()

        for match in failure_ratio_re.finditer(line):
            _add_fact(
                kind="structured",
                key="failures",
                value={"failed": int(match.group(1)), "total": int(match.group(2))},
                confidence=0.99,
                line_no=line_no,
                line=line,
                reason="explicit failures counter from sweep output",
            )

        for match in validation_re.finditer(line):
            _add_fact(
                kind="structured",
                key="validation",
                value=match.group(1),
                confidence=0.99,
                line_no=line_no,
                line=line,
                reason="explicit validation status from sweep output",
            )

        for match in done_re.finditer(line):
            _add_fact(
                kind="structured",
                key="elapsed_seconds",
                value=float(match.group(1)),
                confidence=0.97,
                line_no=line_no,
                line=line,
                reason="explicit completion timing from sweep output",
            )

        for match in detail_re.finditer(line):
            _add_fact(
                kind="artifact",
                key="detail_artifact",
                value=match.group(1),
                confidence=0.96,
                line_no=line_no,
                line=line,
                reason="explicit artifact path emitted by sweep",
            )

        for match in retry_re.finditer(line):
            _add_fact(
                kind="structured",
                key="retry_reason",
                value=match.group(1).strip(),
                confidence=0.93,
                line_no=line_no,
                line=line,
                reason="explicit retry note from sweep output",
            )

        for match in key_value_re.finditer(line):
            key = match.group(1)
            if key in {"validation", "failures"}:
                continue
            value_text = match.group(2)
            value = float(value_text) if "." in value_text else int(value_text)
            _add_fact(
                kind="counter",
                key=key,
                value=value,
                confidence=0.92,
                line_no=line_no,
                line=line,
                reason="explicit key=value counter from sweep output",
            )

        if "timeout" in lower:
            _add_fact(
                kind="heuristic",
                key="observed_timeout",
                value=True,
                confidence=0.45,
                line_no=line_no,
                line=line,
                reason="timeout wording seen in sweep log",
            )
        if "fallback" in lower:
            _add_fact(
                kind="heuristic",
                key="observed_fallback",
                value=True,
                confidence=0.42,
                line_no=line_no,
                line=line,
                reason="fallback wording seen in sweep log",
            )

    low_confidence_facts = [fact for fact in facts if bool(fact.get("needs_more_evidence"))]
    return {
        "schema_version": EVIDENCE_FACTS_SCHEMA_VERSION,
        "generated_at": generated_at or iso_now(),
        "summary": {
            "fact_count": len(facts),
            "low_confidence_threshold": low_confidence_threshold,
            "low_confidence_fact_count": len(low_confidence_facts),
            "needs_more_evidence": bool(low_confidence_facts),
        },
        "facts": facts,
        "needs_more_evidence": [
            {
                "key": str(fact.get("key", "")),
                "confidence_pct": fact.get("confidence_pct"),
                "reason": str(fact.get("reason", "")),
                "line_no": fact.get("line_no"),
            }
            for fact in sorted(low_confidence_facts, key=lambda fact: float(fact.get("confidence", 0.0)))[:5]
        ],
    }
