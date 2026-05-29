#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib
import json
import logging
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


def _file_fingerprint(path: Path) -> str:
    st = path.stat()
    return f"{path.resolve()}|{st.st_size}|{st.st_mtime_ns}"


def _cache_key(binary_path: Path, catalog_path: Path, chunk_size: int, jobs: int) -> str:
    payload = "|".join(
        (
            _file_fingerprint(binary_path),
            _file_fingerprint(catalog_path),
            str(chunk_size),
            str(jobs),
            "v4",
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

    specs = preloaded_specs or load_cached_pat_regex_specs(catalog_path, cache_dir)
    if not specs:
        raise SystemExit("no PAT specs loaded")

    key = _cache_key(binary_path, catalog_input, max(256, args.chunk_size), max(1, args.jobs))
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
            if not args.compilers_only:
                for name in public_names:
                    function_match_counts[name] += 1
                    function_compilers[name].update(compiler_names)

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
            },
        )
    if cached_payload is not None:
        ms_runtime_hits = list(cached_payload.get("ms_runtime_hits", []))

    alias_path = args.compiler_aliases_json if args.compiler_aliases_json.is_absolute() else (REPO_ROOT / args.compiler_aliases_json)
    aliases = _load_aliases(alias_path)
    merged_weighted = _merge_counter_by_canonical(Counter(weighted_compiler_scores), aliases)
    merged_counts = _merge_counter_by_canonical(compiler_match_counts, aliases)

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
