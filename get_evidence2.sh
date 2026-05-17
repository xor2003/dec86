#!/usr/bin/env bash
set -euo pipefail

OUT=result_important.txt
: > "$OUT"

collect() {
    for f in "$@"; do
        [ -f "$f" ] || continue
        printf '\n============================================================\n' >> "$OUT"
        printf 'FILE: %s\n' "$f" >> "$OUT"
        printf '============================================================\n\n' >> "$OUT"
        sed -n '1,4000p' "$f" >> "$OUT"
        printf '\n' >> "$OUT"
    done
}

collect \
AGENTS.md \
angr_platforms/angr_platforms/X86_16/access.py \
angr_platforms/angr_platforms/X86_16/address_ir.py \
angr_platforms/angr_platforms/X86_16/addressing_helpers.py \
angr_platforms/angr_platforms/X86_16/ir/*.py \
angr_platforms/angr_platforms/X86_16/alias/*.py \
angr_platforms/angr_platforms/X86_16/semantics/*.py \
angr_platforms/angr_platforms/X86_16/lowering/*.py \
angr_platforms/angr_platforms/X86_16/postprocess/*.py \
angr_platforms/angr_platforms/X86_16/decompiler_*_stage.py \
angr_platforms/angr_platforms/X86_16/tail_validation.py \
angr_platforms/angr_platforms/X86_16/validation_semantics.py \
angr_platforms/angr_platforms/X86_16/architecture_guard.py \
inertia_decompiler/decompile.py \
inertia_decompiler/cli.py \
SORTDEMO.dec \
/home/xor/vextest/angr_platforms/.cache/tail_validation_details/*

rm -f /home/xor/vextest/angr_platforms/.cache/tail_validation_details/*

echo "written to $OUT"