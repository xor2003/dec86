from __future__ import annotations

import argparse
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from angr_platforms.X86_16.corpus_recovery_artifact import write_x86_16_cod_corpus_recovery_artifact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a bounded corpus recovery artifact for one COD file.")
    parser.add_argument("cod_path", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--mode", default="scan-safe")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)

    result = write_x86_16_cod_corpus_recovery_artifact(
        args.cod_path,
        args.output,
        timeout_sec=args.timeout,
        mode=args.mode,
        limit=args.limit,
    )
    print(f"path: {result.write_result.path}")
    print(f"count: {result.proc_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
