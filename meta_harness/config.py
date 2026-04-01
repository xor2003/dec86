from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_EVIDENCE_INPUT_FILES = [
    "cod/BIOSFUNC.COD",
    "cod/DOSFUNC.COD",
    "cod/OVERLAY.COD",
    "cod/default/BYTEOPS.COD",
    "cod/default/STRLEN.COD",
]


def _split_env_lines(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw:
        return list(default)
    return [line for line in raw.splitlines() if line.strip()]


@dataclass(frozen=True)
class LlmConfig:
    root_dir: Path
    plan_path: Path
    evidence_log_file: Path
    status_file: Path
    codex_timeout_secs: int
    planner_provider: str
    checker_provider: str
    worker_provider: str
    reviewer_provider: str
    crash_reviewer_provider: str
    default_provider: str
    ollama_cmd: str
    llamacpp_cmd: str
    llamacpp_extra_args: str
    local_model_max_retries: int
    local_model_min_output_bytes: int
    local_model_fallback_provider: str
    local_model_fallback_model: str
    local_model_fallback_context: str

    @classmethod
    def from_env(cls) -> "LlmConfig":
        root_dir = Path(os.environ.get("ROOT_DIR", os.getcwd())).resolve()
        return cls(
            root_dir=root_dir,
            plan_path=Path(os.environ.get("PLAN_PATH", root_dir / "PLAN.md")),
            evidence_log_file=Path(os.environ.get("EVIDENCE_LOG_FILE", root_dir / ".codex_automation" / "evidence.log")),
            status_file=Path(os.environ.get("STATUS_FILE", root_dir / ".codex_automation" / "status.txt")),
            codex_timeout_secs=int(os.environ.get("CODEX_TIMEOUT_SECS", "600")),
            planner_provider=os.environ.get("PLANNER_PROVIDER", os.environ.get("LLM_PROVIDER", "codex")),
            checker_provider=os.environ.get("CHECKER_PROVIDER", os.environ.get("LLM_PROVIDER", "codex")),
            worker_provider=os.environ.get("WORKER_PROVIDER", os.environ.get("LLM_PROVIDER", "codex")),
            reviewer_provider=os.environ.get("REVIEWER_PROVIDER", os.environ.get("LLM_PROVIDER", "codex")),
            crash_reviewer_provider=os.environ.get(
                "CRASH_REVIEWER_PROVIDER", os.environ.get("LLM_PROVIDER", "codex")
            ),
            default_provider=os.environ.get("LLM_PROVIDER", "codex"),
            ollama_cmd=os.environ.get("OLLAMA_CMD", "ollama"),
            llamacpp_cmd=os.environ.get("LLAMACPP_CMD", "llama-cli"),
            llamacpp_extra_args=os.environ.get("LLAMACPP_EXTRA_ARGS", ""),
            local_model_max_retries=int(os.environ.get("LOCAL_MODEL_MAX_RETRIES", "2")),
            local_model_min_output_bytes=int(os.environ.get("LOCAL_MODEL_MIN_OUTPUT_BYTES", "120")),
            local_model_fallback_provider=os.environ.get("LOCAL_MODEL_FALLBACK_PROVIDER", ""),
            local_model_fallback_model=os.environ.get("LOCAL_MODEL_FALLBACK_MODEL", ""),
            local_model_fallback_context=os.environ.get(
                "LOCAL_MODEL_FALLBACK_CONTEXT",
                "Use the same prompt but produce a stricter, more concrete answer that follows all required output markers exactly.",
            ),
        )

    def provider_for_key(self, key: str) -> str:
        return {
            "planner": self.planner_provider,
            "checker": self.checker_provider,
            "worker": self.worker_provider,
            "reviewer": self.reviewer_provider,
            "crash-reviewer": self.crash_reviewer_provider,
        }.get(key, self.default_provider)


@dataclass(frozen=True)
class RuntimeConfig:
    root_dir: Path
    harness_config: Path
    run_sh_path: Path
    python_bin: Path
    plan_path: Path
    state_dir: Path
    log_dir: Path
    runs_dir: Path
    stop_file: Path
    lock_file: Path
    status_file: Path
    last_log_file: Path
    prompt_dir: Path
    evidence_subset_dir: Path
    evidence_log_file: Path
    keep_log_count: int
    min_free_disk_mb: int
    min_free_ram_mb: int
    pause_when_ram_below_mb: int
    max_state_dir_mb: int
    max_single_artifact_mb: int
    max_worker_iters: int
    worker_sleep_secs: int
    planner_pause_secs: int
    codex_timeout_secs: int
    max_self_restarts: int
    self_restart_count: int
    worker_finish_token: str
    sweep_label: str
    sweep_cmd: str
    project_name: str
    project_description: str
    rules_file: Path
    primary_priority: str
    secondary_priority: str
    general_improvement_rule: str
    architecture_guidance: str
    evidence_kind: str
    compare_input_description: str
    planner_model: str
    checker_model: str
    worker_model: str
    reviewer_model: str
    crash_reviewer_model: str
    evidence_input_files: list[str]
    original_args: list[str]

    @classmethod
    def from_env(cls, argv: list[str]) -> "RuntimeConfig":
        root_dir = Path(os.environ.get("ROOT_DIR", os.getcwd())).resolve()
        state_dir = Path(os.environ.get("STATE_DIR", root_dir / ".codex_automation"))
        evidence_subset_dir = Path(os.environ.get("EVIDENCE_SUBSET_DIR", state_dir / "evidence_subset"))
        sweep_timeout = int(os.environ.get("SWEEP_TIMEOUT_SECS", "20"))
        sweep_subprocess_timeout = int(os.environ.get("SWEEP_SUBPROCESS_TIMEOUT_SECS", "600"))
        default_sweep_cmd = (
            f'./.venv/bin/python -u scripts/decompile_cod_dir.py "{evidence_subset_dir}" '
            f"--timeout {sweep_timeout} --subprocess-timeout {sweep_subprocess_timeout}"
        )
        return cls(
            root_dir=root_dir,
            harness_config=Path(os.environ.get("HARNESS_CONFIG", root_dir / ".codex_harness.conf")),
            run_sh_path=Path(os.environ.get("RUN_SH_PATH", root_dir / "run.sh")),
            python_bin=Path(os.environ.get("PYTHON_BIN", sys.executable if "sys" in globals() else "python3")),
            plan_path=Path(os.environ.get("PLAN_PATH", root_dir / "PLAN.md")),
            state_dir=state_dir,
            log_dir=Path(os.environ.get("LOG_DIR", state_dir / "logs")),
            runs_dir=Path(os.environ.get("RUNS_DIR", state_dir / "cycles")),
            stop_file=Path(os.environ.get("STOP_FILE", root_dir / "STOP")),
            lock_file=Path(os.environ.get("LOCK_FILE", state_dir / "run.lock")),
            status_file=Path(os.environ.get("STATUS_FILE", state_dir / "status.txt")),
            last_log_file=Path(os.environ.get("LAST_LOG_FILE", state_dir / "last.log")),
            prompt_dir=Path(os.environ.get("PROMPT_DIR", state_dir / "prompts")),
            evidence_subset_dir=evidence_subset_dir,
            evidence_log_file=Path(os.environ.get("EVIDENCE_LOG_FILE", state_dir / "evidence.log")),
            keep_log_count=int(os.environ.get("KEEP_LOG_COUNT", "40")),
            min_free_disk_mb=int(os.environ.get("MIN_FREE_DISK_MB", "8192")),
            min_free_ram_mb=int(os.environ.get("MIN_FREE_RAM_MB", "4096")),
            pause_when_ram_below_mb=int(os.environ.get("PAUSE_WHEN_RAM_BELOW_MB", "6144")),
            max_state_dir_mb=int(os.environ.get("MAX_STATE_DIR_MB", "12288")),
            max_single_artifact_mb=int(os.environ.get("MAX_SINGLE_ARTIFACT_MB", "1024")),
            max_worker_iters=int(os.environ.get("MAX_WORKER_ITERS", "40")),
            worker_sleep_secs=int(os.environ.get("WORKER_SLEEP_SECS", "4")),
            planner_pause_secs=int(os.environ.get("PLANNER_PAUSE_SECS", "60")),
            codex_timeout_secs=int(os.environ.get("CODEX_TIMEOUT_SECS", "600")),
            max_self_restarts=int(os.environ.get("MAX_SELF_RESTARTS", "5")),
            self_restart_count=int(os.environ.get("SELF_RESTART_COUNT", "0")),
            worker_finish_token=os.environ.get("WORKER_FINISH_TOKEN", "Global Remaining steps: 0"),
            sweep_label=os.environ.get("SWEEP_LABEL", "curated evidence sweep"),
            sweep_cmd=os.environ.get("SWEEP_CMD", default_sweep_cmd),
            project_name=os.environ.get("PROJECT_NAME", root_dir.name),
            project_description=os.environ.get("PROJECT_DESCRIPTION", "software repository"),
            rules_file=Path(os.environ.get("RULES_FILE", root_dir / "AGENTS.md")),
            primary_priority=os.environ.get("PRIMARY_PRIORITY", "improve correctness first"),
            secondary_priority=os.environ.get(
                "SECONDARY_PRIORITY", "improve recompilation, maintainability, and automation quality second"
            ),
            general_improvement_rule=os.environ.get(
                "GENERAL_IMPROVEMENT_RULE",
                "Never add hacks specific to one source file or one sample; fixes must be general-purpose improvements.",
            ),
            architecture_guidance=os.environ.get(
                "ARCHITECTURE_GUIDANCE",
                "Prefer the earliest correct layer in the pipeline and avoid pushing semantics into late rewrite.",
            ),
            evidence_kind=os.environ.get("EVIDENCE_KIND", "generated artifacts and repository analysis evidence"),
            compare_input_description=os.environ.get(
                "COMPARE_INPUT_DESCRIPTION", "the relevant source inputs, generated outputs, and the current code state"
            ),
            planner_model=os.environ.get("PLANNER_MODEL", "gpt-5.4"),
            checker_model=os.environ.get("CHECKER_MODEL", "gpt-5.4-mini"),
            worker_model=os.environ.get("WORKER_MODEL", "gpt-5.4-mini"),
            reviewer_model=os.environ.get("REVIEWER_MODEL", "gpt-5.4"),
            crash_reviewer_model=os.environ.get("CRASH_REVIEWER_MODEL", "gpt-5.4"),
            evidence_input_files=_split_env_lines("EVIDENCE_INPUT_FILES", DEFAULT_EVIDENCE_INPUT_FILES),
            original_args=argv,
        )

    def export_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "ROOT_DIR": str(self.root_dir),
                "PLAN_PATH": str(self.plan_path),
                "STATUS_FILE": str(self.status_file),
                "EVIDENCE_LOG_FILE": str(self.evidence_log_file),
                "CODEX_TIMEOUT_SECS": str(self.codex_timeout_secs),
                "HARNESS_CONFIG": str(self.harness_config),
                "RUN_SH_PATH": str(self.run_sh_path),
                "PYTHON_BIN": str(self.python_bin),
            }
        )
        return env
