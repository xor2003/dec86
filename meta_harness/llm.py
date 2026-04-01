from __future__ import annotations

import re
import shlex
import subprocess
from datetime import datetime
from pathlib import Path

from .config import LlmConfig
from .procguard import register_child_process, unregister_child_process


SESSION_RE = re.compile(r"session id:\s*(\S+)", re.IGNORECASE)
LOCAL_BAD_PATTERNS = (
    "as an ai",
    "i can't access",
    "i cant access",
    "need more context",
    "cannot complete without",
)


def backend_supports_sessions(provider: str) -> bool:
    return provider == "codex"


def is_local_provider(provider: str) -> bool:
    return provider in {"ollama", "llamacpp"}


def extract_session_id(text: str) -> str:
    match = SESSION_RE.search(text)
    return match.group(1) if match else ""


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def build_effective_prompt(
    key: str,
    provider: str,
    base_prompt: str,
    config: LlmConfig,
    previous_log_path: str,
) -> str:
    if not is_local_provider(provider):
        return base_prompt
    extra = [
        "",
        "Local-model guardrails:",
        "- Follow the instructions literally.",
        "- Do not refuse, summarize vaguely, or switch to meta commentary.",
        "- Always include the exact required line markers, especially: Global Remaining steps: N",
        "- Be concrete and deterministic.",
        f"- If you reference project evidence, use {config.evidence_log_file}, {config.plan_path}, {config.status_file}, and the current repository state.",
    ]
    if previous_log_path:
        extra.append(f"- Previous {key} log for continuity: {previous_log_path}")
    return base_prompt + "\n" + "\n".join(extra) + "\n"


def validate_output(key: str, provider: str, log_path: Path, config: LlmConfig) -> bool:
    if not is_local_provider(provider):
        return True
    if not log_path.exists() or log_path.stat().st_size < config.local_model_min_output_bytes:
        return False
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if key in {"planner", "checker", "worker", "reviewer"} and not re.search(r"Global Remaining steps:\s*\d+", text):
        return False
    if key in {"planner", "checker", "reviewer"}:
        lowered = text.lower()
        if "correctness" not in lowered or "recompilation" not in lowered:
            return False
    lowered = text.lower()
    if any(pattern in lowered for pattern in LOCAL_BAD_PATTERNS):
        return False
    if key == "planner" and not config.plan_path.exists():
        return False
    return True


def run_provider_once(
    provider: str,
    mode: str,
    model: str,
    prompt: str,
    prompt_file: Path,
    log_file: Path,
    config: LlmConfig,
    session_id: str = "",
) -> int:
    timeout_cmd = ["timeout", "--foreground", f"{config.codex_timeout_secs}s"]
    header = (
        f"[{_timestamp()}] start provider={provider} mode={mode} model={model} "
        f"prompt={prompt_file.name} root={config.root_dir}\n"
    )
    if provider == "codex":
        if mode == "resume":
            cmd = [
                "codex",
                "exec",
                "resume",
                "--model",
                model,
                "--dangerously-bypass-approvals-and-sandbox",
                session_id,
                prompt,
            ]
        else:
            cmd = [
                "codex",
                "exec",
                "--model",
                model,
                "-C",
                str(config.root_dir),
                "--dangerously-bypass-approvals-and-sandbox",
                prompt,
            ]
        with log_file.open("w", encoding="utf-8") as out:
            out.write(header)
            out.flush()
            proc = subprocess.Popen(
                timeout_cmd + cmd,
                stdout=out,
                stderr=subprocess.STDOUT,
            )
            register_child_process(config.status_file.parent, proc.pid, "codex", str(config.root_dir), _timestamp())
            try:
                rc = proc.wait()
            finally:
                unregister_child_process(config.status_file.parent, proc.pid)
        with log_file.open("a", encoding="utf-8") as out:
            out.write(f"[{_timestamp()}] end rc={rc}\n")
        return rc
    if provider == "ollama":
        with prompt_file.open("rb") as inp, log_file.open("w", encoding="utf-8") as out:
            out.write(header)
            out.flush()
            proc = subprocess.Popen(
                timeout_cmd + [config.ollama_cmd, "run", model],
                stdin=inp,
                stdout=out,
                stderr=subprocess.STDOUT,
            )
            register_child_process(config.status_file.parent, proc.pid, "ollama", str(config.root_dir), _timestamp())
            try:
                rc = proc.wait()
            finally:
                unregister_child_process(config.status_file.parent, proc.pid)
        with log_file.open("a", encoding="utf-8") as out:
            out.write(f"[{_timestamp()}] end rc={rc}\n")
        return rc
    if provider == "llamacpp":
        cmd = timeout_cmd + [config.llamacpp_cmd, "-m", model]
        if config.llamacpp_extra_args:
            cmd.extend(shlex.split(config.llamacpp_extra_args))
        cmd.extend(["-f", str(prompt_file)])
        with log_file.open("w", encoding="utf-8") as out:
            out.write(header)
            out.flush()
            proc = subprocess.Popen(
                cmd,
                stdout=out,
                stderr=subprocess.STDOUT,
            )
            register_child_process(config.status_file.parent, proc.pid, "llamacpp", str(config.root_dir), _timestamp())
            try:
                rc = proc.wait()
            finally:
                unregister_child_process(config.status_file.parent, proc.pid)
        with log_file.open("a", encoding="utf-8") as out:
            out.write(f"[{_timestamp()}] end rc={rc}\n")
        return rc
    raise ValueError(f"Unsupported provider: {provider}")
