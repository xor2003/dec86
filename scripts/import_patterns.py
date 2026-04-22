#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from signature_catalog import build_signature_catalog


DEFAULT_MS_C_ROOTS = (
    Path("/home/xor/inertia_player/dos_compilers/Microsoft C v5"),
    Path("/home/xor/inertia_player/dos_compilers/Microsoft C v5.1"),
    Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax"),
)


def _default_input_roots() -> tuple[Path, ...]:
    return tuple(path for path in DEFAULT_MS_C_ROOTS if path.exists())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import PAT/OBJ/LIB patterns into the repo-global PAT file.")
    parser.add_argument("inputs", nargs="*", type=Path, help="PAT/OBJ/LIB files or directories to import.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("signature_catalogs/imported_patterns.pat"),
        help="Output PAT file. Defaults to signature_catalogs/imported_patterns.pat.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[1]
    output_path = args.output if args.output.is_absolute() else (repo_root / args.output)
    cache_dir = repo_root / "signature_catalogs" / ".signature_catalog_cache"
    input_roots = tuple(args.inputs) if args.inputs else _default_input_roots()
    if not input_roots:
        raise SystemExit("no input roots found")
    result = build_signature_catalog(input_roots, output_path, recursive=True, cache_dir=cache_dir)
    print(
        f"wrote {result.output_path} "
        f"inputs={result.input_count} unique_modules={result.unique_module_count} "
        f"duplicates={result.duplicate_module_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
