from __future__ import annotations

from pathlib import Path
from pathlib import PureWindowsPath
from typing import Iterable, Sequence


def emit_file_decompilation_summary(
    project,
    metadata,
    *,
    shown_total: int,
    decompiled: int,
    failed: int,
    skipped_signature_labels: int,
    same_family_retry_stops: int = 0,
    fallback_family_labels: Sequence[str] = (),
) -> None:
    compiler_versions = _compiler_versions(project)
    if compiler_versions:
        print(f"summary: probable compiler versions: {', '.join(compiler_versions[:4])}")
    signature_sources = _signature_sources(project)
    if signature_sources:
        print(f"summary: probable library/signature sources: {', '.join(signature_sources[:4])}")
    signature_code_addrs = len(getattr(metadata, "signature_code_addrs", ())) if metadata is not None else 0
    if signature_code_addrs:
        print(f"summary: signature-matched library functions: {signature_code_addrs}")
    if skipped_signature_labels:
        print(f"summary: hidden signature-matched labels: {skipped_signature_labels}")
    fallback_labels = ", ".join(fallback_family_labels) if fallback_family_labels else "none"
    print(
        "summary: "
        f"same_family_retry_stops={same_family_retry_stops} "
        f"fallback_family_labels={fallback_labels}"
    )
    print(f"summary: shown={shown_total} decompiled={decompiled} asm_or_detail_fallback={failed}")


def _compiler_versions(project) -> list[str]:
    raw = getattr(project, "_inertia_signature_compiler_names", ())
    filtered: list[str] = []
    for name in raw:
        normalized = str(name).strip()
        if not normalized or normalized.lower() in {"ida flair", "v"}:
            continue
        filtered.append(normalized)
    return _stable_unique_sorted(filtered)


def _signature_sources(project) -> list[str]:
    values: list[str] = []
    values.extend(_normalize_source_names(getattr(project, "_inertia_flair_sig_titles", ())))
    values.extend(_normalize_source_names(getattr(project, "_inertia_flair_local_pat_sources", ())))
    values.extend(_normalize_source_names(getattr(project, "_inertia_peer_exe_titles", ())))
    return _stable_unique_sorted(values)


def _normalize_source_names(values: Iterable[object]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        looks_like_path = _looks_like_filesystem_path(text)
        if looks_like_path:
            windows_path = PureWindowsPath(text)
            candidate = windows_path.stem if windows_path.suffix else text
        else:
            path = Path(text)
            candidate = path.stem if path.suffix else text
        normalized.append(candidate)
    return normalized


def _looks_like_filesystem_path(text: str) -> bool:
    if text.startswith(("/", "\\")):
        return True
    if len(text) >= 3 and text[1] == ":" and text[2] in {"\\", "/"}:
        return True
    return "\\" in text


def _stable_unique_sorted(values: Iterable[str]) -> list[str]:
    deduped: dict[str, str] = {}
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        key = text.casefold()
        if key not in deduped or text < deduped[key]:
            deduped[key] = text
    return sorted(deduped.values(), key=lambda item: (item.casefold(), item))
