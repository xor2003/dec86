from __future__ import annotations

import argparse
import sys

from .config import LlmConfig, RuntimeConfig
from .orchestrator import HarnessError, MetaHarness


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Python orchestration harness for iterative repository improvement.")
    parser.add_argument("--resume", action="store_true", help="Resume the latest incomplete cycle if one exists.")
    parser.add_argument("--fresh", action="store_true", help="Ignore any incomplete cycle and start a new one.")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    cfg = RuntimeConfig.from_env(argv)
    llm_cfg = LlmConfig.from_env()
    harness = MetaHarness(cfg, llm_cfg)
    peek_resume_step = getattr(harness, "peek_resume_step", lambda: None)
    resume = args.resume or (not args.fresh and peek_resume_step() is not None)
    try:
        return harness.run(resume=resume)
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 1
        if code not in (0, 10):
            harness.run_crash_review(code)
        raise
    except HarnessError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        harness.run_crash_review(1)
        return 1
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: {exc}", file=sys.stderr)
        harness.run_crash_review(1)
        return 1
