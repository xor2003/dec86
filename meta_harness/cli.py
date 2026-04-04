from __future__ import annotations

import argparse
import sys

from .config import LlmConfig, RuntimeConfig
from .orchestrator import HarnessError, MetaHarness, RoleRunError
from .webui import launch_web_ui


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
    web_ui = launch_web_ui(cfg)
    if web_ui is not None:
        print(f"Web UI: {web_ui.url}", file=sys.stderr)
    peek_resume_step = getattr(harness, "peek_resume_step", lambda: None)
    resume = args.resume or (not args.fresh and peek_resume_step() is not None)
    exit_code = 0
    try:
        exit_code = harness.run(resume=resume)
        return exit_code
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 1
        if code not in (0, 10, 124, 130, 143):
            harness.run_crash_review(code)
        exit_code = code
        raise
    except HarnessError as exc:
        graceful_codes = {124, 130, 143}
        if isinstance(exc, RoleRunError) and exc.exit_code in graceful_codes:
            exit_code = exc.exit_code
            return exit_code
        print(f"ERROR: {exc}", file=sys.stderr)
        harness.run_crash_review(1)
        exit_code = 1
        return 1
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        exit_code = 130
        return 130
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: {exc}", file=sys.stderr)
        harness.run_crash_review(1)
        exit_code = 1
        return 1
    finally:
        if web_ui is not None:
            web_ui.stop()
        if exit_code not in (0, 10):
            reason = "terminated" if exit_code in (124, 143) else "interrupted"
            harness.finalize_run(reason, exit_code)
