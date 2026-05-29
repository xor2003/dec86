#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib
import json
import logging
import math
import os
import pickle
from pathlib import Path
import shutil
import sys
import threading
import tempfile
from typing import Iterable
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from omf_pat import _find_pat_matches, _hyperscan, load_cached_pat_regex_specs


def _load_image(binary_path: Path, *, use_angr: bool = False) -> tuple[int, bytes]:
    if not use_angr:
        return 0, binary_path.read_bytes()
    try:
        angr = importlib.import_module("angr")
    except Exception:
        return 0, binary_path.read_bytes()
    try:
        project = angr.Project(str(binary_path), auto_load_libs=False)
        main_object = project.loader.main_object
        memory = project.loader.memory
        min_addr = getattr(main_object, "min_addr", None)
        max_addr = getattr(main_object, "max_addr", None)
        if isinstance(min_addr, int) and isinstance(max_addr, int) and max_addr >= min_addr:
            image = bytes(memory.load(min_addr, max_addr - min_addr + 1))
            return min_addr, image
    except Exception:
        pass
    data = binary_path.read_bytes()
    return 0, data


def _split_compilers(raw: str) -> tuple[str, ...]:
    parts = [part.strip() for part in raw.split(" || ") if part.strip()]
    return tuple(parts)


_MS_RUNTIME_MARKERS: tuple[tuple[str, bytes], ...] = (
    ("Microsoft C 3", b"C Library - (C)Copyright Microsoft Corp 1985"),
    ("Microsoft Quick C 1.0", b"MS Run-Time Library - Copyright (c) 1987, Microsoft Corp\x1e"),
    ("Microsoft C 5.1", b"MS Run-Time Library - Copyright (c) 1988, Microsoft Corp\x11"),
    ("Microsoft Quick C 2.0", b"MS Run-Time Library - Copyright (c) 1989, Microsoft Corp\x10"),
    ("Microsoft Quick C 2.51", b"MS Run-Time Library - Copyright (c) 1990, Microsoft Corp\x18"),
)

_GENERIC_LIB_NAMES = {
    "memcpy", "memset", "memcmp", "strlen", "strcpy", "strncpy", "strcmp", "strncmp",
    "strcat", "strncat", "atoi", "atol", "abs", "labs", "malloc", "free", "realloc",
    "fopen", "fclose", "fread", "fwrite", "printf", "fprintf", "sprintf", "scanf",
}

_MSVC_HELPER_PREFIXES = (
    "__a", "__chkstk", "__cfltcvt", "__cftof", "__ftol", "__f", "__cxtoa", "__cltoasub",
)
_LIB_NAME_PREFIXES = (
    "__",
    "_ci",
    "_nci",
    "$",
)


def _detect_ms_runtime_libraries(image_bytes: bytes) -> list[str]:
    hits: list[str] = []
    for label, marker in _MS_RUNTIME_MARKERS:
        if marker in image_bytes:
            hits.append(label)
    return hits


def _normalize_symbol_name(name: str) -> str:
    return name.lstrip("_").lower()


def _load_aliases(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return {}
    aliases = payload.get("aliases", {})
    if not isinstance(aliases, dict):
        return {}
    return {str(k): str(v) for k, v in aliases.items()}


def _canonical_compiler_label(name: str, aliases: dict[str, str]) -> str:
    raw = name.strip()
    if raw in aliases:
        return aliases[raw]
    lower = raw.lower()
    if lower in {"unknown", ""}:
        return "unknown"
    if "microsoft c" in lower:
        if any(tok in lower for tok in ("5.10", "5.1", "v5.1")):
            return "Microsoft C 5.1 / CL 5.10"
        if "v4" in lower or " 4." in lower:
            return "Microsoft C 4.x"
        if "v3" in lower or " 3." in lower:
            return "Microsoft C 3.x"
        if "6.00" in lower or "v6" in lower:
            return "Microsoft C 6.x"
        if "2.01" in lower or "v2" in lower:
            return "Microsoft C 2.x"
        return "Microsoft C (unspecified)"
    if "quick c" in lower or "quickc" in lower:
        return "Microsoft QuickC family"
    if "borland" in lower:
        return "Borland C family"
    return raw


def _merge_counter_by_canonical(counter: Counter[str], aliases: dict[str, str]) -> Counter[str]:
    merged: Counter[str] = Counter()
    for name, value in counter.items():
        merged[_canonical_compiler_label(name, aliases)] += value
    return merged


def _spec_weight(public_names: tuple[str, ...]) -> float:
    if not public_names:
        return 1.0
    score = 1.0
    normalized = tuple(_normalize_symbol_name(name) for name in public_names)
    if all(name in _GENERIC_LIB_NAMES for name in normalized):
        score *= 0.25
    if any(
        any(_normalize_symbol_name(name).startswith(prefix) for prefix in _MSVC_HELPER_PREFIXES)
        for name in public_names
    ):
        score += 2.0
    if any(name.startswith(("$i8_", "__f", "_CI")) for name in public_names):
        score += 0.75
    return score


def _is_library_like_function_name(name: str) -> bool:
    n = _normalize_symbol_name(name)
    if not n:
        return True
    if n in _GENERIC_LIB_NAMES:
        return True
    if any(n.startswith(pfx) for pfx in _MSVC_HELPER_PREFIXES):
        return True
    lower_raw = name.lower().strip()
    if any(lower_raw.startswith(pfx) for pfx in _LIB_NAME_PREFIXES):
        return True
    if lower_raw.startswith("_") and len(lower_raw) > 1 and lower_raw[1].isalpha():
        return True
    if lower_raw.startswith("b$"):
        return True
    return False


def _is_non_library_function_entry(entry: dict[str, object]) -> bool:
    name = str(entry.get("function", ""))
    if _is_library_like_function_name(name):
        return False
    compilers = entry.get("compilers", [])
    if isinstance(compilers, list) and compilers:
        # For this matcher, "unknown" labels are the best proxy for non-library/user code.
        lowers = {str(c).lower() for c in compilers}
        if "unknown" not in lowers and "raw-candidate" not in lowers:
            return False
    return True


def _linker_family_from_raw(binary_bytes: bytes) -> str:
    # Simple raw-MZ heuristic: likely output from classic DOS linkers (incl. MS LINK family).
    if len(binary_bytes) < 0x40 or binary_bytes[:2] != b"MZ":
        return "unknown"
    rel_count = int.from_bytes(binary_bytes[0x06:0x08], "little")
    hdr_paras = int.from_bytes(binary_bytes[0x08:0x0A], "little")
    rel_off = int.from_bytes(binary_bytes[0x18:0x1A], "little")
    overlay = int.from_bytes(binary_bytes[0x1A:0x1C], "little")
    header_size = hdr_paras * 16
    plausible = (
        0x20 <= rel_off <= max(header_size, 0x20)
        and header_size >= 0x20
        and rel_off + rel_count * 4 <= len(binary_bytes)
    )
    if plausible and overlay == 0:
        return "DOS MZ linker-family (likely Microsoft LINK-era)"
    if plausible:
        return "DOS MZ linker-family"
    return "unknown"


def _runtime_bonus_map(ms_runtime_hits: list[str]) -> dict[str, float]:
    bonuses: dict[str, float] = {}
    for hit in ms_runtime_hits:
        bonuses[hit] = bonuses.get(hit, 0.0) + 25.0
        if hit.startswith("Microsoft Quick C"):
            bonuses["Microsoft QuickC"] = bonuses.get("Microsoft QuickC", 0.0) + 10.0
        if hit.startswith("Microsoft C"):
            bonuses["Microsoft C"] = bonuses.get("Microsoft C", 0.0) + 10.0
    return bonuses


def _load_flag_profiles(path: Path) -> dict[str, dict[str, float]]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return {}
    combos = payload.get("combos", {})
    out: dict[str, dict[str, float]] = {}
    if not isinstance(combos, dict):
        return {}
    for combo, entry in combos.items():
        tokens = entry.get("tokens", {}) if isinstance(entry, dict) else {}
        if isinstance(tokens, dict):
            out[str(combo)] = {str(k): float(v) for k, v in tokens.items()}
    return out


def _score_flag_combos(function_match_counts: Counter[str], profiles: dict[str, dict[str, float]]) -> list[tuple[str, float]]:
    if not profiles or not function_match_counts:
        return []
    obs = {name.lower(): float(cnt) for name, cnt in function_match_counts.items() if cnt > 0}
    # Discriminative weighting: tokens appearing in many combos are weak evidence.
    combo_count = max(1, len(profiles))
    token_df: Counter[str] = Counter()
    for prof in profiles.values():
        for token, w in prof.items():
            if w > 0:
                token_df[token] += 1
    token_idf: dict[str, float] = {}
    for token, df in token_df.items():
        token_idf[token] = math.log((combo_count + 1.0) / (df + 1.0)) + 1.0

    obs_w: dict[str, float] = {}
    for token, cnt in obs.items():
        if token in token_idf:
            obs_w[token] = math.log1p(cnt) * token_idf[token]
    obs_norm = math.sqrt(sum(v * v for v in obs_w.values()))
    if obs_norm <= 0:
        return []

    scored: list[tuple[str, float]] = []
    for combo, prof in profiles.items():
        if not prof:
            continue
        dot = 0.0
        prof_norm_sq = 0.0
        overlap = 0
        for token, weight in prof.items():
            w = max(0.0, float(weight))
            if w <= 0:
                continue
            idf = token_idf.get(token, 1.0)
            pw = math.log1p(w) * idf
            prof_norm_sq += pw * pw
            ow = obs_w.get(token, 0.0)
            if ow > 0.0:
                dot += pw * ow
                overlap += 1
        prof_norm = math.sqrt(prof_norm_sq)
        if prof_norm > 0 and overlap >= 8:
            scored.append((combo, dot / (prof_norm * obs_norm)))
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored


def _flag_combo_confidence(flag_scores: list[tuple[str, float]]) -> tuple[str, float]:
    if not flag_scores:
        return "none", 0.0
    top1 = flag_scores[0][1]
    top2 = flag_scores[1][1] if len(flag_scores) > 1 else 0.0
    gap = top1 - top2
    if top1 >= 0.55 and gap >= 0.08:
        return "high", gap
    if top1 >= 0.42 and gap >= 0.04:
        return "medium", gap
    return "low", gap


def _flag_marginals(flag_scores: list[tuple[str, float]], top_k: int = 32) -> list[tuple[str, float]]:
    if not flag_scores:
        return []
    pool = flag_scores[: max(1, top_k)]
    # Shift to non-negative weights.
    min_score = min(score for _, score in pool)
    shifted = [(combo, score - min_score + 1e-9) for combo, score in pool]
    total = sum(w for _, w in shifted)
    if total <= 0:
        return []
    marg: Counter[str] = Counter()
    for combo, w in shifted:
        p = w / total
        for tok in combo.split():
            if tok:
                marg[tok] += p
    return sorted(marg.items(), key=lambda kv: kv[1], reverse=True)


def _extract_capstone_features(image_bytes: bytes, code_offsets: list[int]) -> tuple[Counter[str], bool]:
    feats: Counter[str] = Counter()
    try:
        capstone = importlib.import_module("capstone")
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    except Exception:
        return feats, False
    seen = set()
    for off in code_offsets[:512]:
        if off in seen:
            continue
        seen.add(off)
        if off < 0 or off >= len(image_bytes):
            continue
        window = image_bytes[off : min(len(image_bytes), off + 96)]
        try:
            insns = list(md.disasm(bytes(window), off))
        except Exception:
            continue
        for ins in insns[:24]:
            mnem = str(getattr(ins, "mnemonic", "")).lower()
            opstr = str(getattr(ins, "op_str", "")).lower()
            if not mnem:
                continue
            feats[f"op:{mnem}"] += 1
            if " ptr " in opstr:
                feats["shape:ptr"] += 1
            if "[" in opstr and "]" in opstr:
                feats["shape:mem"] += 1
            if "bp" in opstr:
                feats["shape:bp"] += 1
            if "sp" in opstr:
                feats["shape:sp"] += 1
            if "si" in opstr or "di" in opstr:
                feats["shape:index"] += 1
            if "short" in opstr:
                feats["shape:short"] += 1
    return feats, True


def _extract_byte_ngram_features(blob: bytes, n: int = 4, step: int = 3, limit: int = 20000) -> Counter[str]:
    out: Counter[str] = Counter()
    if len(blob) < n:
        return out
    end = min(len(blob) - n + 1, limit)
    for i in range(0, end, step):
        gram = blob[i : i + n]
        out[f"b{n}:{gram.hex()}"] += 1
    return out


def _extract_byte_ngram_features_window(blob: bytes, start: int, size: int = 256) -> Counter[str]:
    if start < 0 or start >= len(blob):
        return Counter()
    end = min(len(blob), start + size)
    return _extract_byte_ngram_features(blob[start:end], n=4, step=2, limit=size)


def _format_top_combo_flags(flag_scores: list[tuple[str, float]], top_n: int = 3) -> str:
    if not flag_scores:
        return "n/a"
    return ", ".join(f"{combo} ({score:.3f})" for combo, score in flag_scores[:top_n])


def _normalize_combo_equivalences(combo: str) -> str:
    toks = {t for t in combo.split() if t}
    # Canonical equivalence for comparison: Ox == Oa+Oi+Ol+Ot+Gs
    if "Ox" in toks:
        toks.discard("Ox")
        toks.update({"Oa", "Oi", "Ol", "Ot", "Gs"})
    return " ".join(sorted(toks, key=lambda x: x.lower()))


def _pretty_combo_for_output(combo: str) -> str:
    toks = {t for t in combo.split() if t}
    if {"Oa", "Oi", "Ol", "Ot", "Gs"}.issubset(toks):
        toks.difference_update({"Oa", "Oi", "Ol", "Ot", "Gs"})
        toks.add("Ox")
    return " ".join(sorted(toks, key=lambda x: x.lower()))


def _row_vote_weight(row: dict[str, object]) -> float:
    top = row.get("top_combos", [])
    if not isinstance(top, list) or not top:
        return 0.0
    top1 = float(top[0][1]) if isinstance(top[0], (list, tuple)) and len(top[0]) > 1 else 0.0
    gap = float(row.get("gap", 0.0))
    if top1 < 0.72 or gap < 0.025:
        return 0.0
    return max(0.0, (top1 - 0.70)) * 2.0 + max(0.0, (gap - 0.02)) * 10.0


def _marginal_flag_set(row: dict[str, object], threshold: float = 0.55) -> str:
    flags = row.get("top_flags", [])
    if not isinstance(flags, list):
        return ""
    selected: set[str] = set()
    for item in flags:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        flag = str(item[0])
        prob = float(item[1])
        if prob >= threshold:
            selected.add(flag)
    return _normalize_combo_equivalences(" ".join(sorted(selected, key=str.lower)))


def _aggregate_flag_sets(function_flag_report: list[dict[str, object]]) -> list[tuple[str, float]]:
    counts: Counter[str] = Counter()
    for row in function_flag_report:
        if str(row.get("confidence", "low")) == "low":
            continue
        combo = _marginal_flag_set(row)
        if not combo:
            continue
        w = _row_vote_weight(row)
        if w > 0:
            counts[combo] += w
    return counts.most_common()


def _aggregate_flag_support(function_flag_report: list[dict[str, object]]) -> list[tuple[str, float]]:
    support: Counter[str] = Counter()
    total = 0.0
    for row in function_flag_report:
        if str(row.get("confidence", "low")) == "low":
            continue
        w = _row_vote_weight(row)
        if w <= 0:
            continue
        total += w
        flags = row.get("top_flags", [])
        if not isinstance(flags, list):
            continue
        for item in flags:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                support[str(item[0])] += w * float(item[1])
    if total <= 0:
        return []
    return sorted(((flag, value / total) for flag, value in support.items()), key=lambda kv: kv[1], reverse=True)


def _flag_presence_share(function_flag_report: list[dict[str, object]], flag: str, threshold: float = 0.55) -> float:
    total = 0.0
    present = 0.0
    for row in function_flag_report:
        if str(row.get("confidence", "low")) == "low":
            continue
        w = _row_vote_weight(row)
        if w <= 0:
            continue
        total += w
        prob = 0.0
        flags = row.get("top_flags", [])
        if isinstance(flags, list):
            for item in flags:
                if isinstance(item, (list, tuple)) and len(item) >= 2 and str(item[0]) == flag:
                    prob = float(item[1])
                    break
        if prob >= threshold:
            present += w
    if total <= 0:
        return 0.0
    return present / total


def _vote_confidence(flag_set_counts: list[tuple[str, float]]) -> tuple[str, float]:
    if not flag_set_counts:
        return "none", 0.0
    top1 = flag_set_counts[0][1]
    top2 = flag_set_counts[1][1] if len(flag_set_counts) > 1 else 0
    total = sum(c for _, c in flag_set_counts)
    if total <= 0:
        return "none", 0.0
    dominance = (top1 - top2) / float(total)
    if dominance >= 0.18 and top1 >= 1.8:
        return "high", dominance
    if dominance >= 0.10 and top1 >= 1.1:
        return "medium", dominance
    return "low", dominance


def _combine_confidence(global_conf: str, vote_conf: str) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    inv = {v: k for k, v in order.items()}
    return inv[min(order.get(global_conf, 0), order.get(vote_conf, 0))]


def _final_confidence(global_conf: str, vote_conf: str, vote_dom: float) -> str:
    base = _combine_confidence(global_conf, vote_conf)
    # Mixed binaries often have low global combo separation but strong per-function consensus.
    if base == "low" and vote_conf == "high" and vote_dom >= 0.60:
        return "medium"
    return base


def _build_per_function_flag_report(
    image_bytes: bytes,
    raw_bytes: bytes,
    function_entries: list[dict[str, object]],
    flag_profiles: dict[str, dict[str, float]],
    limit: int,
) -> list[dict[str, object]]:
    report: list[dict[str, object]] = []
    if not function_entries or not flag_profiles:
        return report
    sorted_entries = sorted(function_entries, key=lambda e: int(e.get("offset", 0)))
    for idx, entry in enumerate(sorted_entries[: max(1, limit * 6)]):
        fname = str(entry.get("function", ""))
        off = int(entry.get("offset", 0))
        module_len = int(entry.get("module_length", 0))
        if not _is_non_library_function_entry(entry):
            continue
        # Prefer real function boundaries: until next function entry, bounded.
        next_off = int(sorted_entries[idx + 1].get("offset", off + 256)) if idx + 1 < len(sorted_entries) else off + max(64, module_len, 256)
        region = max(64, min(1024, next_off - off, module_len if module_len > 0 else 1024))
        # Skip tiny regions that tend to be stubs/thunks and add noise.
        if region < 96:
            continue
        local = Counter()
        dis_local, _ok = _extract_capstone_features(image_bytes, [off])
        local.update(dis_local)
        local.update(_extract_byte_ngram_features_window(raw_bytes, off, size=region))
        if not local:
            continue
        # Require enough local evidence; otherwise prediction is unstable.
        if sum(local.values()) < 60:
            continue
        fs = _score_flag_combos(local, flag_profiles)
        if not fs:
            continue
        fconf, fgap = _flag_combo_confidence(fs)
        marg = _flag_marginals(fs, top_k=16)
        report.append(
            {
                "function": fname,
                "offset": int(off),
                "confidence": fconf,
                "gap": float(fgap),
                "top_combos": fs[:3],
                "top_flags": marg[:5],
            }
        )
    report.sort(
        key=lambda r: (
            0 if r.get("confidence") == "high" else 1 if r.get("confidence") == "medium" else 2,
            -float(r.get("gap", 0.0)),
        )
    )
    return report


def _find_candidate_function_offsets_raw(raw_bytes: bytes, limit: int = 256) -> list[dict[str, object]]:
    # Simple 16-bit DOS prologue/entry candidates, independent from PAT/library symbols.
    # Patterns: push bp; mov bp,sp (high precision, low noise).
    pats = (
        b"\x55\x8b\xec",  # push bp; mov bp,sp
        b"\x55\x89\xe5",  # push bp; mov bp,sp (alt encoding)
    )
    seen: set[int] = set()
    scored: list[tuple[int, int]] = []
    n = len(raw_bytes)
    for i in range(0, max(0, n - 3)):
        if raw_bytes[i : i + 3] in pats:
            if i not in seen:
                seen.add(i)
                scored.append((i, 3))
    # Greedy de-dup: avoid multiple candidates inside one function body.
    scored.sort(key=lambda x: (-x[1], x[0]))
    picked: list[int] = []
    min_gap = 48
    for off, _score in scored:
        if any(abs(off - p) < min_gap for p in picked):
            continue
        picked.append(off)
        if len(picked) >= max(1, limit):
            break
    picked.sort()
    out: list[dict[str, object]] = []
    for i in picked:
        out.append(
            {
                "function": f"SUB_{i:05X}",
                "offset": i,
                "module_length": 256,
                "compilers": ["raw-candidate"],
            }
        )
    return out


def _file_fingerprint(path: Path) -> str:
    st = path.stat()
    return f"{path.resolve()}|{st.st_size}|{st.st_mtime_ns}"


def _cache_key(
    binary_path: Path,
    catalog_path: Path,
    chunk_size: int,
    jobs: int,
    detect_flags_msc51: bool = False,
    msc51_profile_path: Path | None = None,
) -> str:
    profile_fp = ""
    if detect_flags_msc51 and msc51_profile_path is not None and msc51_profile_path.exists():
        profile_fp = _file_fingerprint(msc51_profile_path)
    payload = "|".join(
        (
            _file_fingerprint(binary_path),
            _file_fingerprint(catalog_path),
            str(chunk_size),
            str(jobs),
            str(int(bool(detect_flags_msc51))),
            profile_fp,
            "v14",
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _load_cached_result(cache_path: Path) -> dict | None:
    try:
        return json.loads(cache_path.read_text())
    except Exception:
        return None


def _store_cached_result(cache_path: Path, payload: dict) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass


def _resolve_catalog_input(catalog_input: Path) -> tuple[Path, Path, tuple]:
    """
    Resolve catalog input (PAT file or bundle zip) into:
      - effective catalog path
      - cache directory
      - optional preloaded specs tuple
    """
    if catalog_input.suffix.lower() != ".zip":
        effective_catalog = catalog_input.resolve()
        effective_cache_dir = effective_catalog.parent / ".signature_catalog_cache"
        return effective_catalog, effective_cache_dir, ()

    zip_stat = catalog_input.stat()
    zip_key = hashlib.sha256(
        f"{catalog_input.resolve()}|{zip_stat.st_size}|{zip_stat.st_mtime_ns}".encode("utf-8")
    ).hexdigest()[:24]
    extract_root = catalog_input.parent / ".zip_catalog_cache" / zip_key
    extract_root.mkdir(parents=True, exist_ok=True)
    stamp = extract_root / ".ready"
    if not stamp.exists():
        staging = Path(tempfile.mkdtemp(prefix="pat-catalog-bundle-"))
        with zipfile.ZipFile(catalog_input, "r") as zf:
            zf.extractall(staging)
        for child in staging.iterdir():
            target = extract_root / child.name
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
            shutil.move(str(child), str(target))
        stamp.write_text("ok")
    pat_candidates = sorted(extract_root.glob("*.pat"))
    if not pat_candidates:
        raise SystemExit(f"zip catalog has no .pat: {catalog_input}")
    effective_catalog = pat_candidates[0]
    effective_cache_dir = extract_root / ".signature_catalog_cache"
    preloaded_specs: tuple = ()
    snapshot_path = extract_root / "catalog_specs.pickle"
    if snapshot_path.exists():
        try:
            loaded = pickle.loads(snapshot_path.read_bytes())
            if isinstance(loaded, tuple):
                preloaded_specs = loaded
        except Exception:
            preloaded_specs = ()
    return effective_catalog, effective_cache_dir, preloaded_specs


def _iter_chunks(items: list, size: int) -> Iterable[list]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _scan_hyperscan_chunk(image_bytes: bytes, specs_chunk: list, chunk_offset: int) -> set[int]:
    unique_indexes: set[int] = set()
    if not specs_chunk:
        return unique_indexes
    image_size = len(image_bytes)
    db = _hyperscan.Database(mode=_hyperscan.HS_MODE_BLOCK)
    expressions = [spec.scan_source.decode("latin1") for spec in specs_chunk]
    ids = list(range(len(specs_chunk)))
    flags = [_hyperscan.HS_FLAG_DOTALL | _hyperscan.HS_FLAG_SINGLEMATCH] * len(specs_chunk)
    try:
        db.compile(expressions=expressions, ids=ids, elements=len(specs_chunk), flags=flags)
    except Exception:
        # Some patterns may be rejected by hyperscan (e.g., empty-buffer matches).
        # Fall back for this chunk only.
        return _scan_fallback_chunk(image_bytes, specs_chunk, chunk_offset)
    hit_counts = [0] * len(specs_chunk)

    def _on_match(expr_id, _from_offset, end_offset, _flags, _context):
        if expr_id < 0 or expr_id >= len(specs_chunk):
            return False
        spec = specs_chunk[expr_id]
        start = end_offset - spec.checked_match_length
        end_limit = image_size - spec.module_length + 1
        if 0 <= start < end_limit:
            hit_counts[expr_id] += 1
        return False

    db.scan(image_bytes, _on_match)
    for local_idx, count in enumerate(hit_counts):
        if count == 1:
            unique_indexes.add(chunk_offset + local_idx)
    return unique_indexes


def _emit_progress(done: int, total: int, state: dict[str, int], lock: threading.Lock) -> None:
    if total <= 0:
        return
    pct = (done * 100) // total
    with lock:
        while state["next"] <= 100 and pct >= state["next"]:
            print(f"[progress] {state['next']}%", file=sys.stderr)
            state["next"] += 5


def _find_unique_matches_batch_hyperscan(image_bytes: bytes, specs: list, chunk_size: int, jobs: int) -> set[int]:
    if _hyperscan is None:
        return set()
    chunks = [(chunk, chunk_idx * chunk_size) for chunk_idx, chunk in enumerate(_iter_chunks(specs, chunk_size))]
    if jobs <= 1:
        merged: set[int] = set()
        total = len(chunks)
        progress_state = {"next": 5}
        progress_lock = threading.Lock()
        for done, (chunk, offset) in enumerate(chunks, 1):
            merged.update(_scan_hyperscan_chunk(image_bytes, chunk, offset))
            _emit_progress(done, total, progress_state, progress_lock)
        return merged
    merged: set[int] = set()
    total = len(chunks)
    done = 0
    progress_state = {"next": 5}
    progress_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(_scan_hyperscan_chunk, image_bytes, chunk, offset) for chunk, offset in chunks]
        for fut in futures:
            merged.update(fut.result())
            done += 1
            _emit_progress(done, total, progress_state, progress_lock)
    return merged


def _scan_fallback_chunk(image_bytes: bytes, specs_chunk: list, chunk_offset: int) -> set[int]:
    unique_indexes: set[int] = set()
    for local_idx, spec in enumerate(specs_chunk):
        hits = _find_pat_matches(image_bytes, spec, backend="python_regex")
        if len(hits) == 1:
            unique_indexes.add(chunk_offset + local_idx)
    return unique_indexes


def _find_unique_matches_fallback_parallel(image_bytes: bytes, specs: list, chunk_size: int, jobs: int) -> set[int]:
    chunks = [(chunk, chunk_idx * chunk_size) for chunk_idx, chunk in enumerate(_iter_chunks(specs, chunk_size))]
    if jobs <= 1:
        merged: set[int] = set()
        total = len(chunks)
        progress_state = {"next": 5}
        progress_lock = threading.Lock()
        for done, (chunk, offset) in enumerate(chunks, 1):
            merged.update(_scan_fallback_chunk(image_bytes, chunk, offset))
            _emit_progress(done, total, progress_state, progress_lock)
        return merged
    merged: set[int] = set()
    total = len(chunks)
    done = 0
    progress_state = {"next": 5}
    progress_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(_scan_fallback_chunk, image_bytes, chunk, offset) for chunk, offset in chunks]
        for fut in futures:
            merged.update(fut.result())
            done += 1
            _emit_progress(done, total, progress_state, progress_lock)
    return merged


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report likely compiler versions from PAT function matches in an EXE/COM."
    )
    parser.add_argument("binary", type=Path, help="Input .exe/.com file")
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("signature_catalogs/all_compilers_catalog_bundle.zip"),
        help="PAT catalog path or zip bundle (default: signature_catalogs/all_compilers_catalog_bundle.zip)",
    )
    parser.add_argument("--top", type=int, default=20, help="Number of top functions to print")
    parser.add_argument(
        "--compilers-only",
        action="store_true",
        help="Print only ranked probable compilers (by matched functions).",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=2048,
        help="Hyperscan batch size (patterns per DB compile).",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, os.cpu_count() or 1),
        help="Number of worker threads for hyperscan chunk scanning (default: all CPUs).",
    )
    parser.add_argument(
        "--compiler-aliases-json",
        type=Path,
        default=Path("signature_catalogs/compiler_aliases.json"),
        help="Alias mapping JSON generated by probe_compiler_versions.py",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show raw/internal scoring tables in addition to simplified summary.",
    )
    parser.add_argument(
        "--detect-flags-msc51",
        action="store_true",
        help="Show top MS C 5.1 flag-combo candidates using dataset-derived profiles.",
    )
    parser.add_argument(
        "--msc51-flag-profiles",
        type=Path,
        default=Path("signature_catalogs/msc51_flag_profiles.json"),
        help="Profile JSON from build_msc51_flag_profiles.py",
    )
    parser.add_argument(
        "--per-function-flags-top",
        type=int,
        default=15,
        help="How many matched functions to show for per-function flag inference.",
    )
    args = parser.parse_args(argv)
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

    binary_path = args.binary.resolve()
    catalog_input = args.catalog.resolve()
    if not binary_path.exists():
        raise SystemExit(f"binary not found: {binary_path}")
    if not catalog_input.exists():
        raise SystemExit(f"catalog not found: {catalog_input}")

    catalog_path, cache_dir, preloaded_specs = _resolve_catalog_input(catalog_input)
    profile_path = args.msc51_flag_profiles if args.msc51_flag_profiles.is_absolute() else (REPO_ROOT / args.msc51_flag_profiles)
    flag_profiles = _load_flag_profiles(profile_path)

    specs = preloaded_specs or load_cached_pat_regex_specs(catalog_path, cache_dir)
    if not specs:
        raise SystemExit("no PAT specs loaded")

    key = _cache_key(
        binary_path,
        catalog_input,
        max(256, args.chunk_size),
        max(1, args.jobs),
        detect_flags_msc51=bool(args.detect_flags_msc51),
        msc51_profile_path=profile_path,
    )
    result_cache_path = cache_dir / f"report_compiler_matches-{key}.json"
    cached_payload = _load_cached_result(result_cache_path)
    if cached_payload is not None:
        compiler_items = cached_payload.get("compiler_match_counts", [])
        function_items = cached_payload.get("function_match_counts", [])
        function_compilers_items = cached_payload.get("function_compilers", {})
        matched_specs = int(cached_payload.get("matched_specs", 0))
        use_batch = bool(cached_payload.get("use_batch", False))
        compiler_match_counts = Counter({name: int(count) for name, count in compiler_items})
        weighted_compiler_scores = Counter({name: float(score) for name, score in cached_payload.get("weighted_compiler_scores", [])})
        linker_family = str(cached_payload.get("linker_family", "unknown"))
        function_match_counts = Counter({name: int(count) for name, count in function_items})
        function_compilers = defaultdict(set)
        for name, compilers in function_compilers_items.items():
            function_compilers[name].update(compilers)
        function_flag_report = cached_payload.get("function_flag_report", [])
    else:
        _, image_bytes = _load_image(binary_path)
        raw_bytes = binary_path.read_bytes()
        ms_runtime_hits = _detect_ms_runtime_libraries(raw_bytes)
        linker_family = _linker_family_from_raw(raw_bytes)

        compiler_match_counts: Counter[str] = Counter()
        weighted_compiler_scores: Counter[str] = Counter()
        function_match_counts: Counter[str] = Counter()
        function_compilers: dict[str, set[str]] = defaultdict(set)
        matched_specs = 0
        matched_code_offsets: list[int] = []
        function_offset_records: dict[int, dict[str, object]] = {}
        disasm_feature_count = 0
        disasm_backend_ok = False
        function_flag_report: list[dict[str, object]] = []

        if _hyperscan is not None:
            unique_indexes = _find_unique_matches_batch_hyperscan(
                image_bytes,
                list(specs),
                max(256, args.chunk_size),
                max(1, args.jobs),
            )
            use_batch = bool(unique_indexes)
        else:
            unique_indexes = _find_unique_matches_fallback_parallel(
                image_bytes,
                list(specs),
                max(256, args.chunk_size),
                max(1, args.jobs),
            )
            use_batch = True

        for spec_idx, spec in enumerate(specs):
            if use_batch:
                if spec_idx not in unique_indexes:
                    continue
            else:
                hits = _find_pat_matches(image_bytes, spec)
                if len(hits) != 1:
                    continue
            matched_specs += 1
            compiler_names = _split_compilers(getattr(spec, "compiler_name", ""))
            if not compiler_names:
                compiler_names = ("unknown",)
            public_names = tuple(pub.name for pub in spec.public_names) or (spec.module_name,)
            weight = _spec_weight(public_names)
            shared = max(1, len(compiler_names))
            for compiler_name in compiler_names:
                compiler_match_counts[compiler_name] += 1
                weighted_compiler_scores[compiler_name] += (weight / shared)
            if (not args.compilers_only) or args.detect_flags_msc51:
                for name in public_names:
                    function_match_counts[name] += 1
                    function_compilers[name].update(compiler_names)
            if args.detect_flags_msc51 and getattr(spec, "public_names", ()):
                # Recover one concrete code offset for instruction-level features.
                try:
                    hs = _find_pat_matches(image_bytes, spec, backend="python_regex")
                except Exception:
                    hs = []
                if len(hs) == 1:
                    try:
                        entry_off = int(hs[0]) + int(spec.public_names[0].offset)
                        matched_code_offsets.append(entry_off)
                        for pub in spec.public_names:
                            rec = function_offset_records.get(entry_off)
                            if rec is None:
                                rec = {
                                    "offset": entry_off,
                                    "function": str(pub.name),
                                    "module_length": int(getattr(spec, "module_length", 0)),
                                    "compilers": list(compiler_names),
                                }
                                function_offset_records[entry_off] = rec
                            else:
                                cur_name = str(rec.get("function", ""))
                                new_name = str(pub.name)
                                # Prefer non-library-like representative names for this offset.
                                if _is_library_like_function_name(cur_name) and not _is_library_like_function_name(new_name):
                                    rec["function"] = new_name
                                if int(getattr(spec, "module_length", 0)) > int(rec.get("module_length", 0)):
                                    rec["module_length"] = int(getattr(spec, "module_length", 0))
                                existing = set(str(x) for x in rec.get("compilers", []))
                                existing.update(str(x) for x in compiler_names)
                                rec["compilers"] = sorted(existing)
                    except Exception:
                        pass

        if args.detect_flags_msc51 and matched_code_offsets:
            dis_feats, disasm_backend_ok = _extract_capstone_features(image_bytes, matched_code_offsets)
            disasm_feature_count = sum(dis_feats.values())
            for k, v in dis_feats.items():
                function_match_counts[k] += v
        if args.detect_flags_msc51:
            byte_feats = _extract_byte_ngram_features(raw_bytes)
            for k, v in byte_feats.items():
                function_match_counts[k] += v
            raw_entries = _find_candidate_function_offsets_raw(
                raw_bytes,
                limit=max(64, args.per_function_flags_top * 12),
            )
            function_flag_report = _build_per_function_flag_report(
                image_bytes=image_bytes,
                raw_bytes=raw_bytes,
                function_entries=raw_entries,
                flag_profiles=flag_profiles,
                limit=max(1, args.per_function_flags_top),
            )

        runtime_bonuses = _runtime_bonus_map(ms_runtime_hits)
        for compiler_name in list(weighted_compiler_scores.keys()):
            lower = compiler_name.lower()
            for bonus_key, bonus_value in runtime_bonuses.items():
                key_lower = bonus_key.lower()
                if key_lower in lower or lower in key_lower:
                    weighted_compiler_scores[compiler_name] += bonus_value
        for bonus_key, bonus_value in runtime_bonuses.items():
            if bonus_key not in weighted_compiler_scores:
                weighted_compiler_scores[bonus_key] = bonus_value

        _store_cached_result(
            result_cache_path,
            {
                "matched_specs": matched_specs,
                "use_batch": use_batch,
                "ms_runtime_hits": ms_runtime_hits,
                "linker_family": linker_family,
                "compiler_match_counts": compiler_match_counts.most_common(),
                "weighted_compiler_scores": weighted_compiler_scores.most_common(),
                "function_match_counts": function_match_counts.most_common(),
                "function_compilers": {k: sorted(v) for k, v in function_compilers.items()},
                "disasm_feature_count": int(disasm_feature_count),
                "disasm_backend_ok": bool(disasm_backend_ok),
                "function_flag_report": function_flag_report,
            },
        )
    if cached_payload is not None:
        ms_runtime_hits = list(cached_payload.get("ms_runtime_hits", []))
        disasm_feature_count = int(cached_payload.get("disasm_feature_count", 0))
        disasm_backend_ok = bool(cached_payload.get("disasm_backend_ok", False))

    alias_path = args.compiler_aliases_json if args.compiler_aliases_json.is_absolute() else (REPO_ROOT / args.compiler_aliases_json)
    aliases = _load_aliases(alias_path)
    merged_weighted = _merge_counter_by_canonical(Counter(weighted_compiler_scores), aliases)
    merged_counts = _merge_counter_by_canonical(compiler_match_counts, aliases)
    flag_scores = _score_flag_combos(function_match_counts, flag_profiles) if args.detect_flags_msc51 else []

    if args.compilers_only:
        print("Summary:")
        if ms_runtime_hits:
            print(f"  Runtime string match: {', '.join(ms_runtime_hits)}")
        else:
            print("  Runtime string match: none")
        print(f"  Linker guess: {linker_family}")
        print("Method 1: Runtime string detector")
        print("  How: search raw binary bytes for known MS runtime banner strings.")
        if ms_runtime_hits:
            for hit in ms_runtime_hits:
                print(f"  Result: {hit}")
        else:
            print("  Result: no known runtime banner found")

        print("Method 2: Function signature matching (PAT)")
        print("  How: match code byte signatures from catalog; keep unique hits.")
        for compiler_name, count in merged_counts.most_common(10):
            print(f"  {count:6.0f}  {compiler_name}")

        print("Method 3: Linker family heuristic")
        print("  How: inspect raw MZ header/layout traits.")
        print(f"  Result: {linker_family}")
        if args.detect_flags_msc51:
            print("Method 4: MS C 5.1 flag combo detector")
            print("  How: compare PAT-matched helper/function tokens to deep dataset combo profiles.")
            if flag_scores:
                conf, gap = _flag_combo_confidence(flag_scores)
                set_votes = _aggregate_flag_sets(function_flag_report) if function_flag_report else []
                vconf, vdom = _vote_confidence(set_votes) if set_votes else ("none", 0.0)
                final_conf = _final_confidence(conf, vconf, vdom) if set_votes else conf
                if set_votes:
                    print(f"  Confidence: {final_conf} (vote={vconf}, global={conf})")
                    print(f"  Function-vote dominance: {vdom:.3f}; global top1-top2 gap={gap:.3f}")
                else:
                    print(f"  Confidence: {conf} (top1-top2 gap={gap:.3f})")
                print(
                    f"  Features: tokens={sum(function_match_counts.values())}, "
                    f"disasm_features={disasm_feature_count}, capstone={'ok' if disasm_backend_ok else 'missing'}"
                )
                if final_conf == "low":
                    print("  Result: not reliable for this binary (weak separation).")
                elif conf == "low" and vconf in {"medium", "high"}:
                    print("  Result: mixed-binary reliable by function votes; global combo remains ambiguous.")
                else:
                    for combo, score in flag_scores[:10]:
                        print(f"  {score:7.3f}  {combo}")
                vote_flag_support = _aggregate_flag_support(function_flag_report) if function_flag_report else []
                marg = vote_flag_support or _flag_marginals(flag_scores, top_k=32)
                if marg:
                    print("  Flag likelihoods (function-vote model):")
                    for tok, prob in marg[:10]:
                        print(f"    {prob:0.3f}  {tok}")
                    if vote_flag_support:
                        core = [flag for flag, prob in vote_flag_support if prob >= 0.75]
                        if core:
                            print(f"  Core flags: {_pretty_combo_for_output(_normalize_combo_equivalences(' '.join(core)))}")
                        zi_share = _flag_presence_share(function_flag_report, "Zi", threshold=0.55)
                        if zi_share > 0.0:
                            print(f"  /Zi evidence: present in about {zi_share*100.0:.1f}% of matched non-library functions")
                if function_flag_report:
                    print("  Top marginal flag sets by function count:")
                    for combo, cnt in set_votes[: max(1, args.per_function_flags_top)]:
                        print(f"    {cnt:6.2f}  {_pretty_combo_for_output(combo)}")
                    print(f"  Per-function flag hints (top {max(1, args.per_function_flags_top)}):")
                    shown = 0
                    for row in function_flag_report:
                        if shown >= max(1, args.per_function_flags_top):
                            break
                        flags_txt = ", ".join(f"{tok}:{prob:.2f}" for tok, prob in row.get("top_flags", []))
                        print(
                            f"    {row.get('function')} @0x{int(row.get('offset', 0)):x} "
                            f"[{row.get('confidence')}, gap={float(row.get('gap', 0.0)):.3f}] "
                            f"{_format_top_combo_flags([(_pretty_combo_for_output(str(c)), s) for c, s in list(row.get('top_combos', []))])} ; flags: {flags_txt}"
                        )
                        shown += 1
            else:
                print("  Result: no profile match (or no profiles loaded)")
        if args.verbose:
            print("Raw probable compilers weighted (debug):")
            for compiler_name, score in weighted_compiler_scores.most_common(10):
                print(f"  {score:7.2f}  {compiler_name}")
    if not args.compilers_only:
        print(f"binary: {binary_path}")
        print(f"catalog: {catalog_path}")
        print(f"matched_unique_specs: {matched_specs}")
        matcher_name = "batch_hyperscan" if _hyperscan is not None else "parallel_fallback"
        print(f"matcher: {matcher_name if use_batch else 'per_spec_fallback'}")
        if use_batch:
            print(f"jobs: {max(1, args.jobs)}")
        if ms_runtime_hits:
            print(f"ms_runtime_detector: {', '.join(ms_runtime_hits)}")
        else:
            print("ms_runtime_detector: none")
        print(f"linker_detector: {linker_family}")
        print()
        print("probable_compilers_weighted:")
        for compiler_name, score in weighted_compiler_scores.most_common(10):
            print(f"  {score:7.2f}  {compiler_name}")
        print()
        print("likely_compiler_versions:")
    if (not args.compilers_only) or args.verbose:
        for compiler_name, count in compiler_match_counts.most_common():
            print(f"  {count:6d}  {compiler_name}")
    if args.compilers_only and args.verbose:
        print("interpreted_match_counts:")
        for compiler_name, count in merged_counts.most_common(10):
            print(f"  {count:6.0f}  {compiler_name}")
    if not args.compilers_only:
        print()
        print(f"top_functions (top={args.top}):")
        for function_name, count in function_match_counts.most_common(args.top):
            compilers = ", ".join(sorted(function_compilers[function_name]))
            print(f"  {count:6d}  {function_name}  [{compilers}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
