#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

TOKEN_RE = re.compile(r"\b[_$A-Za-z][_$A-Za-z0-9]*\b")
ASM_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\b(.*)$")
SKIP = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "goto",
    "break",
    "continue",
    "mov",
    "push",
    "pop",
    "call",
    "cmp",
    "add",
    "sub",
    "mul",
    "div",
    "lea",
    "byte",
    "word",
    "ptr",
    "short",
    "near",
    "far",
}
ASM_PROMPT_RE = re.compile(r"Recover the function from this assembly:\s*(.*)", re.S | re.I)


def combo_from_name(path: Path) -> str:
    stem = path.stem
    if stem.startswith("output_"):
        stem = stem[len("output_") :]
    parts = [p for p in stem.split("_") if p]
    return " ".join(sorted(parts))


def extract_tokens(text: str) -> Counter[str]:
    c: Counter[str] = Counter()
    for m in TOKEN_RE.finditer(text):
        t = m.group(0)
        tl = t.lower()
        if tl in SKIP:
            continue
        if tl.startswith("__") or tl.startswith("$") or tl.startswith("_"):
            c[tl] += 1
    return c


def extract_instruction_tokens(text: str) -> Counter[str]:
    def _impl():
        out: Counter[str] = Counter()
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith(";"):
                continue
            m = ASM_LINE_RE.match(s)
            if not m:
                continue
            op = m.group(1).lower()
            rest = m.group(2).lower()
            out[f"op:{op}"] += 1
            # Cheap operand-shape markers that are often flag-sensitive.
            if " ptr " in rest:
                out["shape:ptr"] += 1
            if "[" in rest and "]" in rest:
                out["shape:mem"] += 1
            if "bp" in rest:
                out["shape:bp"] += 1
            if "sp" in rest:
                out["shape:sp"] += 1
            if "si" in rest or "di" in rest:
                out["shape:index"] += 1
            if "short" in rest:
                out["shape:short"] += 1
        return out

    return _impl()


def extract_byte_ngram_tokens(blob: bytes, n: int = 4, step: int = 3, limit: int = 20000) -> Counter[str]:
    out: Counter[str] = Counter()
    if len(blob) < n:
        return out
    end = min(len(blob) - n + 1, limit)
    for i in range(0, end, step):
        gram = blob[i : i + n]
        out[f"b{n}:{gram.hex()}"] += 1
    return out


def canonical_combo_from_flags(flags: str) -> str:
    parts: list[str] = []
    for tok in flags.split():
        t = tok.strip()
        if not t:
            continue
        if t.startswith("/"):
            t = t[1:]
        parts.append(t)
    norm = set(parts)
    if "Ox" in norm:
        norm.discard("Ox")
        norm.update({"Oa", "Oi", "Ol", "Ot", "Gs"})
    return " ".join(sorted(norm, key=lambda x: x.lower()))


def maybe_extract_asm_from_dataset_user_msg(text: str) -> str:
    m = ASM_PROMPT_RE.search(text)
    if not m:
        return ""
    return m.group(1).strip()


def main(argv: list[str] | None = None) -> int:
    def _impl():
        ap = argparse.ArgumentParser(description="Build MS C 5.1 flag-combo token profiles from deep/*.COD")
        ap.add_argument(
            "--cod-dir",
            dest="cod_dirs",
            action="append",
            type=Path,
            help="Directory containing output_*.COD (repeatable). Default: /home/xor/vextest/deep",
        )
        ap.add_argument(
            "--output",
            type=Path,
            default=Path("/home/xor/vextest/signature_catalogs/msc51_flag_profiles.json"),
        )
        ap.add_argument(
            "--dataset-jsonl",
            dest="dataset_jsonls",
            action="append",
            type=Path,
            help="Optional nndecomp dataset jsonl (repeatable), e.g. cod_combo_strict_10x.jsonl",
        )
        args = ap.parse_args(argv)

        profiles: dict[str, Counter[str]] = defaultdict(Counter)
        counts: Counter[str] = Counter()
        roots = args.cod_dirs or [Path("/home/xor/vextest/deep")]
        allowed_combos: set[str] = set()
        used_files = 0
        for root in roots:
            for cod in sorted(root.glob("output_*.COD")):
                combo = combo_from_name(cod)
                allowed_combos.add(combo)
                txt = cod.read_text(errors="ignore")
                profiles[combo].update(extract_tokens(txt))
                profiles[combo].update(extract_instruction_tokens(txt))
                base = cod.with_suffix("")
                for ext in (".EXE", ".OBJ"):
                    p = base.with_suffix(ext)
                    if p.exists():
                        try:
                            profiles[combo].update(extract_byte_ngram_tokens(p.read_bytes()))
                        except Exception:
                            pass
                counts[combo] += 1
                used_files += 1

        dataset_rows = 0
        dataset_sources = 0
        dataset_paths = args.dataset_jsonls or []
        if not dataset_paths:
            default_ds = Path("/home/xor/nndecomp/artifacts/dataset/cod_combo_strict_10x.jsonl")
            if default_ds.exists():
                dataset_paths = [default_ds]
        for ds in dataset_paths:
            if not ds.exists():
                continue
            dataset_sources += 1
            with ds.open("r", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    meta = obj.get("meta", {})
                    if not isinstance(meta, dict):
                        continue
                    flags = str(meta.get("flags", "")).strip()
                    if not flags:
                        continue
                    combo = canonical_combo_from_flags(flags)
                    if not combo:
                        continue
                    if allowed_combos and combo not in allowed_combos:
                        continue
                    msgs = obj.get("messages", [])
                    if not isinstance(msgs, list):
                        continue
                    user_text = ""
                    for msg in msgs:
                        if isinstance(msg, dict) and msg.get("role") == "user":
                            user_text = str(msg.get("content", ""))
                            break
                    if not user_text:
                        continue
                    asm_text = maybe_extract_asm_from_dataset_user_msg(user_text)
                    if not asm_text:
                        continue
                    profiles[combo].update(extract_instruction_tokens(asm_text))
                    profiles[combo].update(extract_tokens(asm_text))
                    counts[combo] += 1
                    dataset_rows += 1

        # Keep the most informative tokens per combo to improve separation.
        combo_count = max(1, len(profiles))
        token_df: Counter[str] = Counter()
        for prof in profiles.values():
            for token, value in prof.items():
                if value > 0:
                    token_df[token] += 1

        payload = {
            "schema": 2,
            "source_dirs": [str(r) for r in roots],
            "source_file_count": used_files,
            "dataset_sources": dataset_sources,
            "dataset_rows": dataset_rows,
            "combos": {
                combo: {
                    "samples": int(counts[combo]),
                    "tokens": dict(
                        sorted(
                            (
                                (
                                    tok,
                                    float(val) * (math.log((combo_count + 1.0) / (token_df.get(tok, 0) + 1.0)) + 1.0),
                                )
                                for tok, val in profiles[combo].items()
                                if val > 0
                            ),
                            key=lambda kv: kv[1],
                            reverse=True,
                        )[:800]
                    ),
                }
                for combo in sorted(profiles)
            },
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True))
        print(f"wrote {args.output} combos={len(payload['combos'])} files={used_files}")
        return 0

    if __name__ == "__main__":
        raise SystemExit(main())

    return _impl()
