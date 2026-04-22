# Sweep Latest

- Command: `./.venv/bin/python -u decompile.py "${PWD}/SORTDEMO.EXE" --timeout 6 --max-functions 8`
- Lane: scan-safe bounded sweep (max 8 funcs, timeout 6s)
- Result: success
- Exit code: 0
- Functions shown: 8
- Decompiled: 8
- ASM/detail fallback: 0
- Validation status visibility: `validation=disabled` in function logs (no changed/unknown/uncollected classification emitted in this sweep mode)
- Signature context: sidecar-assisted; 67 signature-matched functions hidden/skipped by default
- Evidence log: `.codex_automation/evidence.log`
