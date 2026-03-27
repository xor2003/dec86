#!/usr/bin/env python3
"""
Probe decompilation on all files under angr_platforms/x16_samples and report files
that fall back to ASM or produce no decompiled code.

Writes results to `reports/x16_decompile_report.json` and `reports/x16_decompile_report.txt`.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "angr_platforms" / "x16_samples"
REPORT_DIR = ROOT / "reports"
REPORT_DIR.mkdir(exist_ok=True)
OUT_JSON = REPORT_DIR / "x16_decompile_report.json"
OUT_TXT = REPORT_DIR / "x16_decompile_report.txt"

TIMEOUT_PER = 30  # seconds per sample
PY = sys.executable
DECOMPILE_SCRIPT = ROOT / "decompile.py"

EXTS = {".COM", ".EXE", ".COD", ".BIN"}

results = []

for path in sorted(SAMPLES.rglob("*")):
    if path.is_dir():
        continue
    if path.suffix.upper() not in EXTS:
        # still try other files but prefer known sample types
        pass
    rel = path.relative_to(ROOT)
    cmd = [PY, str(DECOMPILE_SCRIPT), str(path), "--timeout", "10", "--max-functions", "6"]
    print(f"Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_PER)
        out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        print(f"Timeout on {rel}")
        results.append({"file": str(rel), "status": "timeout", "summary": "timeout"})
        continue

    fallback_reasons = []
    # heuristics for detecting fallback/no-decompilation
    if "Decompiler did not produce code" in out:
        fallback_reasons.append("no_decompiler_output")
    if "no bytes available" in out:
        fallback_reasons.append("no_bytes_available")
    if "ASM fallback" in out or "asm fallback" in out or "ASM:" in out:
        fallback_reasons.append("asm_fallback")
    # catch generic ellipsis fallback used previously
    if "..." in out and "Decompiler" in out:
        fallback_reasons.append("ellipsis_fallback")

    status = "ok" if not fallback_reasons else "fallback"
    summary = fallback_reasons[:3] if fallback_reasons else [l for l in out.splitlines()[:6]]
    snippet = "\n".join(out.splitlines()[:200])
    results.append({"file": str(rel), "status": status, "summary": summary, "snippet": snippet})

# write JSON and text reports
with OUT_JSON.open("w") as f:
    json.dump(results, f, indent=2)

with OUT_TXT.open("w") as f:
    for r in results:
        f.write(f"File: {r['file']}\n")
        f.write(f"Status: {r['status']}\n")
        f.write(f"Summary: {r['summary']}\n")
        f.write("--- snippet ---\n")
        f.write(r.get("snippet", "")[:800])
        f.write("\n\n")

print(f"Wrote: {OUT_JSON}\nWrote: {OUT_TXT}")
