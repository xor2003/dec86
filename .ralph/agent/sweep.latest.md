# Sweep Latest

- Refreshed: `2026-04-23T10:03:50Z`
- Command: `./.venv/bin/python -u decompile.py "${PWD}/SORTDEMO.EXE" --timeout 6 --max-functions 8`
- Lane: scan-safe bounded sweep (max 8 funcs, timeout 6s)
- Result: success
- Exit code: 0
- Timestamp: `2026-04-23 12:03:47-12:03:50 +0200`
- Functions queued: 20
- Functions shown: 8
- Decompiled: 8
- ASM/detail fallback: 0
- Validation status visibility: all 8 shown functions remain attributable as `validation=uncollected`; no `validation=disabled`
- Shown function verdicts: `0x10010=uncollected`, `0x10678=uncollected`, `0x10768=uncollected`, `0x107b8=uncollected`, `0x10970=uncollected`, `0x109e8=uncollected`, `0x10e70=uncollected`, `0x10f38=uncollected`
- Not shown in this bounded sweep: checker anchors `0x102e0`, `0x10ce0`
- Exact follow-up verdicts: `0x102e0=uncollected`, `0x10ce0=uncollected` in `.codex_automation/evidence.log`
- Signature context: sidecar-assisted; 67 signature-matched functions hidden/skipped by default
- Evidence log: `.codex_automation/evidence.log`
