from __future__ import annotations

import fcntl
import json
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from .config import LlmConfig, RuntimeConfig
from .llm import backend_supports_sessions, build_effective_prompt, extract_session_id, run_provider_once, validate_output
from .procguard import cleanup_stale_child_processes, install_child_cleanup_handler, register_child_process, unregister_child_process
from .prompts import (
    build_checker_prompt,
    build_crash_reviewer_prompt,
    build_planner_prompt,
    build_reviewer_prompt,
    build_worker_prompt,
)


class HarnessError(RuntimeError):
    pass


class RoleRunError(HarnessError):
    def __init__(self, role: str, log_file: Path, message: str):
        super().__init__(message)
        self.role = role
        self.log_file = log_file


class MetaHarness:
    step_order = ("full-sweep", "checker", "planner", "worker", "reviewer")

    def __init__(self, cfg: RuntimeConfig, llm_cfg: LlmConfig):
        self.cfg = cfg
        self.llm_cfg = llm_cfg
        self.current_cycle_dir: Path | None = None
        self.current_cycle_index = 0
        self.cycle_state: dict[str, object] | None = None
        self.crash_review_active = False
        self.lock_fp: object | None = None
        self.script_checksums = self._compute_script_checksums()
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        for path in (self.cfg.state_dir, self.cfg.log_dir, self.cfg.prompt_dir, self.cfg.runs_dir):
            path.mkdir(parents=True, exist_ok=True)
        install_child_cleanup_handler(self.cfg.state_dir, self.cfg.root_dir)

    def timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def iso_now(self) -> str:
        return datetime.now().astimezone().isoformat(timespec="seconds")

    def log(self, msg: str) -> None:
        print(f"[{self.iso_now()}] {msg}", file=sys.stderr)

    def die(self, msg: str) -> None:
        raise HarnessError(msg)

    def write_status(self, step: str, status: str, extra: str = "") -> None:
        lines = [f"step={step}", f"status={status}"]
        if extra:
            lines.append(f"extra={extra}")
        lines.append(f"updated_at={self.iso_now()}")
        self.cfg.status_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def check_stop_file(self) -> None:
        if self.cfg.stop_file.exists():
            self.write_status("stopped", "stop-file-detected", str(self.cfg.stop_file))
            raise SystemExit(10)

    def ensure_prereqs(self) -> None:
        for cmd in ("timeout", "df", "du"):
            if shutil.which(cmd) is None:
                self.die(f"{cmd} command not found in PATH")
        if not self.cfg.python_bin.exists():
            self.die(f"Missing {self.cfg.python_bin}")
        providers = {
            self.llm_cfg.planner_provider,
            self.llm_cfg.checker_provider,
            self.llm_cfg.worker_provider,
            self.llm_cfg.reviewer_provider,
            self.llm_cfg.crash_reviewer_provider,
        }
        for provider in providers:
            if provider == "codex" and shutil.which("codex") is None:
                self.die("codex CLI not found in PATH")
            if provider == "ollama" and shutil.which(self.llm_cfg.ollama_cmd) is None:
                self.die(f"ollama command not found: {self.llm_cfg.ollama_cmd}")
            if provider == "llamacpp" and shutil.which(self.llm_cfg.llamacpp_cmd) is None:
                self.die(f"llama.cpp command not found: {self.llm_cfg.llamacpp_cmd}")

    def acquire_lock(self) -> None:
        self.cfg.lock_file.parent.mkdir(parents=True, exist_ok=True)
        fp = self.cfg.lock_file.open("w")
        try:
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holders = ""
            if shutil.which("fuser"):
                result = subprocess.run(
                    ["fuser", "-v", str(self.cfg.lock_file)], capture_output=True, text=True, check=False
                )
                holders = result.stdout + result.stderr
            self.die(f"Another run instance is already active\n{holders}".rstrip())
        self.lock_fp = fp

    def trim_old_logs(self) -> None:
        logs = sorted(self.cfg.log_dir.glob("*.log"))
        for old in logs[: max(0, len(logs) - self.cfg.keep_log_count)]:
            old.unlink(missing_ok=True)

    def free_disk_mb(self) -> int:
        result = subprocess.run(["df", "-Pm", str(self.cfg.root_dir)], capture_output=True, text=True, check=True)
        return int(result.stdout.splitlines()[1].split()[3])

    def free_ram_mb(self) -> int | None:
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
        except OSError:
            return None
        return None

    def state_dir_mb(self) -> int:
        result = subprocess.run(["du", "-sm", str(self.cfg.state_dir)], capture_output=True, text=True, check=False)
        return int(result.stdout.split()[0]) if result.returncode == 0 and result.stdout.strip() else 0

    def cleanup_large_artifacts(self) -> None:
        threshold = self.cfg.max_single_artifact_mb * 1024 * 1024
        for path in sorted(self.cfg.state_dir.rglob("*")):
            if path.is_file() and path.stat().st_size > threshold:
                self.log(f"Removing oversized artifact {path}")
                path.unlink(missing_ok=True)

    def trim_old_cycles(self) -> None:
        cycles = sorted(p for p in self.cfg.runs_dir.iterdir() if p.is_dir()) if self.cfg.runs_dir.exists() else []
        total_mb = self.state_dir_mb()
        while total_mb > self.cfg.max_state_dir_mb and len(cycles) > 1:
            victim = cycles.pop(0)
            self.log(f"State dir is {total_mb}MB, pruning old cycle {victim.name}")
            shutil.rmtree(victim, ignore_errors=True)
            total_mb = self.state_dir_mb()

    def cleanup_state_dir(self) -> None:
        self.trim_old_logs()
        self.cleanup_large_artifacts()
        self.trim_old_cycles()

    def wait_for_memory_headroom(self, context: str) -> None:
        while True:
            self.check_stop_file()
            avail = self.free_ram_mb()
            if avail is None or avail >= self.cfg.pause_when_ram_below_mb:
                return
            self.write_status(context, "paused-low-ram", f"avail={avail}MB threshold={self.cfg.pause_when_ram_below_mb}MB")
            self.log(f"Low RAM before {context}: {avail}MB available; waiting {self.cfg.planner_pause_secs}s")
            time.sleep(self.cfg.planner_pause_secs)

    def preflight_resource_check(self, context: str) -> None:
        self.cleanup_state_dir()
        disk = self.free_disk_mb()
        if disk < self.cfg.min_free_disk_mb:
            self.cleanup_state_dir()
            disk = self.free_disk_mb()
            if disk < self.cfg.min_free_disk_mb:
                self.write_status(context, "blocked-low-disk", f"free={disk}MB required={self.cfg.min_free_disk_mb}MB")
                self.die(f"Not enough free disk space for {context}: {disk}MB available, need at least {self.cfg.min_free_disk_mb}MB")
        ram = self.free_ram_mb()
        if ram is not None and ram < self.cfg.min_free_ram_mb:
            self.wait_for_memory_headroom(context)
            ram = self.free_ram_mb()
            if ram is not None and ram < self.cfg.min_free_ram_mb:
                self.write_status(context, "blocked-low-ram", f"avail={ram}MB required={self.cfg.min_free_ram_mb}MB")
                self.die(f"Not enough free RAM for {context}: {ram}MB available, need at least {self.cfg.min_free_ram_mb}MB")
        self.write_status(context, "resources-ok", f"disk={disk}MB ram={ram if ram is not None else 'unknown'}MB state={self.state_dir_mb()}MB")

    def sha256_file(self, path: Path) -> str:
        if not path.exists():
            return ""
        h = hashlib.sha256()
        with path.open("rb") as fp:
            for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _compute_script_checksums(self) -> dict[str, str]:
        package_root = self.cfg.root_dir / "meta_harness"
        return {
            "run.sh": self.sha256_file(self.cfg.run_sh_path),
            "meta_harness": self.sha256_tree(package_root),
        }

    def sha256_tree(self, root: Path) -> str:
        if not root.exists():
            return ""
        h = hashlib.sha256()
        for path in sorted(root.rglob("*")):
            if path.is_file():
                h.update(path.relative_to(root).as_posix().encode("utf-8"))
                with path.open("rb") as fp:
                    for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                        h.update(chunk)
        return h.hexdigest()

    def latest_cycle_dir(self) -> Path | None:
        if not self.cfg.runs_dir.exists():
            return None
        cycles = sorted(p for p in self.cfg.runs_dir.iterdir() if p.is_dir())
        return cycles[-1] if cycles else None

    def cycle_state_file(self, cycle_dir: Path | None = None) -> Path | None:
        base = cycle_dir or self.current_cycle_dir
        return None if base is None else base / "cycle.state.json"

    def _empty_cycle_state(self, cycle_index: int) -> dict[str, object]:
        return {
            "cycle": cycle_index,
            "started_at": self.iso_now(),
            "updated_at": self.iso_now(),
            "completed": False,
            "steps": {step: {"status": "pending", "updated_at": "", "extra": ""} for step in self.step_order},
        }

    def _save_cycle_state(self) -> None:
        if self.current_cycle_dir is None or self.cycle_state is None:
            return
        self.cycle_state["updated_at"] = self.iso_now()
        state_file = self.cycle_state_file()
        if state_file is not None:
            state_file.write_text(json.dumps(self.cycle_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _load_cycle_state(self, cycle_dir: Path) -> dict[str, object] | None:
        state_file = cycle_dir / "cycle.state.json"
        if not state_file.exists():
            return None
        try:
            return json.loads(state_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def _resume_step_from_state(self, state: dict[str, object]) -> str | None:
        steps = state.get("steps")
        if not isinstance(steps, dict):
            return None
        for step in self.step_order:
            entry = steps.get(step)
            if not isinstance(entry, dict) or entry.get("status") != "done":
                return step
        return None

    def current_cycle_step(self) -> str | None:
        if self.cycle_state is None:
            return None
        steps = self.cycle_state.get("steps")
        if not isinstance(steps, dict):
            return None
        for step in self.step_order:
            entry = steps.get(step)
            if isinstance(entry, dict) and entry.get("status") in {"running", "paused-low-ram", "blocked-low-ram", "blocked-low-disk"}:
                return step
        return self._resume_step_from_state(self.cycle_state)

    def peek_resume_step(self) -> str | None:
        latest = self.latest_cycle_dir()
        if latest is None:
            return None
        state = self._load_cycle_state(latest)
        if state is None or state.get("completed") is True:
            return None
        return self._resume_step_from_state(state)

    def resume_latest_cycle(self) -> str | None:
        latest = self.latest_cycle_dir()
        if latest is None:
            return None
        state = self._load_cycle_state(latest)
        if state is None or state.get("completed") is True:
            return None
        resume_step = self._resume_step_from_state(state)
        if resume_step is None:
            return None
        self.current_cycle_dir = latest
        self.current_cycle_index = int(state.get("cycle", 0) or 0)
        self.cycle_state = state
        latest_link = self.cfg.state_dir / "latest_cycle"
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(self.current_cycle_dir)
        self.log(f"Resuming cycle {self.current_cycle_index:03d} from {resume_step}")
        return resume_step

    def prepare_cycle_workspace(self) -> None:
        self.cleanup_state_dir()
        self.current_cycle_index += 1
        self.current_cycle_dir = self.cfg.runs_dir / f"{self.timestamp()}_cycle{self.current_cycle_index:03d}"
        self.current_cycle_dir.mkdir(parents=True, exist_ok=True)
        self.cycle_state = self._empty_cycle_state(self.current_cycle_index)
        self._save_cycle_state()
        latest = self.cfg.state_dir / "latest_cycle"
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(self.current_cycle_dir)
        meta = (
            f"cycle={self.current_cycle_index}\n"
            f"started_at={self.iso_now()}\n"
            f"root={self.cfg.root_dir}\n"
            f"script={self.cfg.root_dir / 'meta_harness'}\n"
        )
        (self.current_cycle_dir / "cycle.meta").write_text(meta, encoding="utf-8")
        self.capture_git_state("start")
        if self.cfg.plan_path.exists():
            shutil.copy2(self.cfg.plan_path, self.current_cycle_dir / "PLAN.start.md")
        self._save_cycle_state()

    def capture_git_state(self, tag: str) -> None:
        if self.current_cycle_dir is None:
            return
        status = subprocess.run(["git", "-C", str(self.cfg.root_dir), "status", "--short"], capture_output=True, text=True, check=False).stdout
        diff_stat = subprocess.run(["git", "-C", str(self.cfg.root_dir), "diff", "--stat"], capture_output=True, text=True, check=False).stdout
        (self.current_cycle_dir / f"git-status.{tag}.txt").write_text(status, encoding="utf-8")
        (self.current_cycle_dir / f"git-diff-stat.{tag}.txt").write_text(diff_stat, encoding="utf-8")

    def capture_cycle_artifact(self, src: Path, dst_name: str | None = None) -> None:
        if self.current_cycle_dir is None or not src.exists():
            return
        shutil.copy2(src, self.current_cycle_dir / (dst_name or src.name))

    def capture_cycle_snapshot(self, tag: str) -> None:
        self.capture_cycle_artifact(self.cfg.status_file, f"status.{tag}.txt")
        self.capture_cycle_artifact(self.cfg.last_log_file, f"last.{tag}.log")
        self.capture_cycle_artifact(self.cfg.evidence_log_file, f"evidence_sweep.{tag}.log")
        state_file = self.cycle_state_file()
        if state_file is not None and state_file.exists():
            self.capture_cycle_artifact(state_file, f"cycle.{tag}.json")
        if self.current_cycle_dir is not None and self.cfg.plan_path.exists():
            shutil.copy2(self.cfg.plan_path, self.current_cycle_dir / f"PLAN.{tag}.md")
        self.capture_git_state(tag)

    def mark_cycle_step(self, step: str, status: str, extra: str = "") -> None:
        if self.cycle_state is None:
            return
        steps = self.cycle_state.setdefault("steps", {})
        if isinstance(steps, dict):
            steps[step] = {
                "status": status,
                "updated_at": self.iso_now(),
                "extra": extra,
            }
        if status == "done" and step == self.step_order[-1]:
            self.cycle_state["completed"] = True
        self._save_cycle_state()

    def maybe_self_restart(self, reason: str) -> bool:
        current = self._compute_script_checksums()
        if current == self.script_checksums:
            return False
        if self.cfg.self_restart_count >= self.cfg.max_self_restarts:
            self.die(f"Harness files changed during {reason}, but MAX_SELF_RESTARTS={self.cfg.max_self_restarts} was reached")
        self.capture_cycle_snapshot(f"restart-{reason}")
        self.log(f"Harness files changed during {reason}; restarting with updated code")
        env = self.cfg.export_env()
        env["SELF_RESTART_COUNT"] = str(self.cfg.self_restart_count + 1)
        env["EVIDENCE_INPUT_FILES"] = "\n".join(self.cfg.evidence_input_files)
        os.execvpe(self.cfg.python_bin.as_posix(), [self.cfg.python_bin.as_posix(), "-m", "meta_harness", *self.cfg.original_args], env)

    def finalize_run(self, reason: str, exit_code: int | None = None) -> None:
        if self.cycle_state is None:
            return
        status_text = self.cfg.status_file.read_text(encoding="utf-8", errors="replace") if self.cfg.status_file.exists() else ""
        if "status=done" in status_text or "status=stop-file-detected" in status_text or "status=restart-requested" in status_text:
            return
        current_step = self.current_cycle_step() or "cycle"
        step_state = self.cycle_state.get("steps", {})
        if isinstance(step_state, dict):
            for step, entry in step_state.items():
                if isinstance(entry, dict) and entry.get("status") == "running":
                    step_state[step] = {
                        "status": reason,
                        "updated_at": self.iso_now(),
                        "extra": f"exit_code={exit_code}" if exit_code is not None else "",
                    }
                    break
        self.cycle_state["completed"] = False
        self._save_cycle_state()
        self.write_status("harness", reason, f"cycle={self.current_cycle_index} step={current_step} exit_code={exit_code}")
        self.capture_cycle_snapshot(reason)

    def prepare_evidence_subset(self) -> None:
        if self.cfg.evidence_subset_dir.exists():
            shutil.rmtree(self.cfg.evidence_subset_dir, ignore_errors=True)
        self.cfg.evidence_subset_dir.mkdir(parents=True, exist_ok=True)
        for rel in self.cfg.evidence_input_files:
            src = self.cfg.root_dir / rel
            if not src.exists():
                self.die(f"Evidence input file missing: {src}")
            dst = self.cfg.evidence_subset_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            dst.symlink_to(src)

    def extract_remaining_steps(self, log_file: Path) -> str:
        text = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else ""
        for pat in (r"Global Remaining steps:\s*(\d+)", r"Remaining steps:\s*(\d+)"):
            match = re.search(pat, text)
            if match:
                return match.group(1)
        return ""

    def save_role_markers(self, role: str, log_file: Path, remaining: str | None = None) -> None:
        if remaining is not None:
            (self.cfg.state_dir / f"{role}.remaining").write_text(remaining + "\n", encoding="utf-8")
        (self.cfg.state_dir / f"{role}.lastlog").write_text(str(log_file) + "\n", encoding="utf-8")

    def last_role_log_file(self, role: str) -> str:
        path = self.cfg.state_dir / f"{role}.lastlog"
        return path.read_text(encoding="utf-8").strip() if path.exists() else ""

    def _run_llm_attempt(self, role: str, model: str, prompt: str, resume: bool = False) -> Path:
        provider = self.llm_cfg.provider_for_key(role)
        prompt_file = self.cfg.prompt_dir / f"{role}.prompt.txt"
        log_file = self.cfg.log_dir / f"{self.timestamp()}_{role}.log"
        session_file = self.cfg.state_dir / f"{role}.session"
        previous_log = self.last_role_log_file(role)

        def _raise_role_error(message: str) -> None:
            if log_file.exists():
                shutil.copy2(log_file, self.cfg.last_log_file)
                self.save_role_markers(role, log_file)
            raise RoleRunError(role, log_file, message)

        prompt_file.write_text(prompt, encoding="utf-8")
        effective = build_effective_prompt(role, provider, prompt, self.llm_cfg, previous_log)
        prompt_file.write_text(effective, encoding="utf-8")
        mode = "resume" if resume and backend_supports_sessions(provider) and session_file.exists() else "new"
        self.write_status(role, "running", f"provider={provider} model={model} log={log_file.name}")
        self.log(f"Starting {role} with {provider}/{model}{' via resume' if mode == 'resume' else ''}")

        if mode == "resume":
            session_id = session_file.read_text(encoding="utf-8").strip()
            if run_provider_once(provider, "resume", model, effective, prompt_file, log_file, self.llm_cfg, session_id) != 0:
                _raise_role_error(f"{role} resume failed")
        else:
            max_attempts = self.llm_cfg.local_model_max_retries + 1 if provider in {"ollama", "llamacpp"} else 1
            for attempt in range(1, max_attempts + 1):
                rc = run_provider_once(provider, "new", model, effective, prompt_file, log_file, self.llm_cfg)
                if rc == 0 and validate_output(role, provider, log_file, self.llm_cfg):
                    break
                if provider not in {"ollama", "llamacpp"}:
                    _raise_role_error(f"{role} failed")
                self.log(f"{role} produced invalid output via {provider}/{model}; retry {attempt}/{self.llm_cfg.local_model_max_retries}")
            else:
                fallback_provider = self.llm_cfg.local_model_fallback_provider
                fallback_model = self.llm_cfg.local_model_fallback_model
                if fallback_provider and fallback_model:
                    effective = build_effective_prompt(
                        role,
                        fallback_provider,
                        prompt + "\n\nFallback instruction:\n" + self.llm_cfg.local_model_fallback_context,
                        self.llm_cfg,
                        previous_log,
                    )
                    prompt_file.write_text(effective, encoding="utf-8")
                    rc = run_provider_once(fallback_provider, "new", fallback_model, effective, prompt_file, log_file, self.llm_cfg)
                    provider = fallback_provider
                    if rc != 0 or not validate_output(role, provider, log_file, self.llm_cfg):
                        _raise_role_error(f"{role} failed after retries")
                else:
                    _raise_role_error(f"{role} failed after retries")

        shutil.copy2(log_file, self.cfg.last_log_file)
        text = log_file.read_text(encoding="utf-8", errors="replace")
        session_id = extract_session_id(text)
        if session_id:
            session_file.write_text(session_id + "\n", encoding="utf-8")
        self.write_status(role, "done", f"provider={provider} log={log_file.name}")
        self.trim_old_logs()
        return log_file

    def run_role(self, role: str, model: str, prompt: str, resume: bool = False) -> Path:
        return self._run_llm_attempt(role, model, prompt, resume=resume)

    def sweep_step(self) -> None:
        self.check_stop_file()
        self.preflight_resource_check("full-sweep")
        self.mark_cycle_step("full-sweep", "running", f"log={self.cfg.evidence_log_file.name}")
        self.prepare_evidence_subset()
        self.write_status("full-sweep", "running", f"log={self.cfg.evidence_log_file.name}")
        self.log(f"Starting {self.cfg.sweep_label}")
        env = self.cfg.export_env()
        env["EVIDENCE_INPUT_FILES"] = "\n".join(self.cfg.evidence_input_files)
        env["EVIDENCE_SUBSET_DIR"] = str(self.cfg.evidence_subset_dir)
        header = f"[{self.iso_now()}] start sweep={self.cfg.sweep_label} root={self.cfg.root_dir}\n"
        cmd = [
            "timeout",
            "--foreground",
            f"{self.cfg.codex_timeout_secs}s",
            "bash",
            "-lc",
            self.cfg.sweep_cmd,
        ]
        with self.cfg.evidence_log_file.open("w", encoding="utf-8") as out:
            out.write(header)
            out.flush()
            proc = subprocess.Popen(cmd, cwd=self.cfg.root_dir, env=env, stdout=out, stderr=subprocess.STDOUT)
            register_child_process(self.cfg.state_dir, proc.pid, self.cfg.sweep_cmd, str(self.cfg.root_dir), self.iso_now())
            try:
                rc = proc.wait()
            finally:
                unregister_child_process(self.cfg.state_dir, proc.pid)
        with self.cfg.evidence_log_file.open("a", encoding="utf-8") as out:
            out.write(f"[{self.iso_now()}] end rc={rc}\n")
        log_text = self.cfg.evidence_log_file.read_text(encoding="utf-8", errors="replace") if self.cfg.evidence_log_file.exists() else ""
        completed_sweep = "done in" in log_text
        if rc != 0 and completed_sweep:
            self.log(f"{self.cfg.sweep_label} completed with non-zero rc={rc}; continuing because evidence was produced")
            if self.cfg.evidence_log_file.exists():
                shutil.copy2(self.cfg.evidence_log_file, self.cfg.last_log_file)
            self.write_status("full-sweep", "done-with-failures", f"log={self.cfg.evidence_log_file.name} rc={rc}")
            self.mark_cycle_step("full-sweep", "done-with-failures", f"rc={rc}")
            self.capture_cycle_artifact(self.cfg.evidence_log_file, "evidence_sweep.log")
            self.capture_cycle_snapshot("sweep")
            self.trim_old_logs()
            return
        if rc != 0:
            if self.cfg.evidence_log_file.exists():
                shutil.copy2(self.cfg.evidence_log_file, self.cfg.last_log_file)
            self.write_status("full-sweep", "failed", f"see {self.cfg.evidence_log_file.name}")
            self.mark_cycle_step("full-sweep", "failed", f"rc={rc}")
            self.die(f"{self.cfg.sweep_label} failed")
        shutil.copy2(self.cfg.evidence_log_file, self.cfg.last_log_file)
        self.write_status("full-sweep", "done", f"log={self.cfg.evidence_log_file.name}")
        self.mark_cycle_step("full-sweep", "done", f"log={self.cfg.evidence_log_file.name}")
        self.capture_cycle_artifact(self.cfg.evidence_log_file, "evidence_sweep.log")
        self.capture_cycle_snapshot("sweep")
        self.trim_old_logs()

    def checker_step(self) -> None:
        self.check_stop_file()
        self.preflight_resource_check("checker")
        self.mark_cycle_step("checker", "running")
        log_file = self.run_role("checker", self.cfg.checker_model, build_checker_prompt(self.cfg))
        remaining = self.extract_remaining_steps(log_file)
        if not remaining:
            self.die("Checker did not print remaining step count")
        self.save_role_markers("checker", log_file, remaining)
        self.capture_cycle_artifact(log_file, "checker.log")
        self.mark_cycle_step("checker", "done", f"remaining={remaining}")
        self.capture_cycle_snapshot("checker")

    def planner_step(self) -> None:
        self.check_stop_file()
        self.preflight_resource_check("planner")
        self.mark_cycle_step("planner", "running")
        log_file = self.run_role("planner", self.cfg.planner_model, build_planner_prompt(self.cfg))
        remaining = self.extract_remaining_steps(log_file)
        if not remaining:
            self.die("Planner did not print remaining step count")
        text = log_file.read_text(encoding="utf-8", errors="replace")
        if "Pause for minute" in text:
            self.log("Planner requested a pause")
            time.sleep(self.cfg.planner_pause_secs)
        if remaining == "0":
            print("Global Remaining steps: 0")
            raise SystemExit(0)
        if not self.cfg.plan_path.exists():
            self.die(f"Planner did not create or update {self.cfg.plan_path}")
        self.save_role_markers("planner", log_file, remaining)
        self.capture_cycle_artifact(log_file, "planner.log")
        self.mark_cycle_step("planner", "done", f"remaining={remaining}")
        self.capture_cycle_snapshot("planner")

    def worker_cycle(self) -> None:
        self.mark_cycle_step("worker", "running")
        for i in range(1, self.cfg.max_worker_iters + 1):
            self.check_stop_file()
            self.preflight_resource_check("worker")
            self.log(f"Worker iteration {i}/{self.cfg.max_worker_iters}")
            try:
                log_file = self.run_role("worker", self.cfg.worker_model, build_worker_prompt(self.cfg), resume=True)
            except HarnessError as exc:
                if isinstance(exc, RoleRunError):
                    self.capture_cycle_artifact(exc.log_file, f"worker.iter{i:02d}.resume-failed.log")
                (self.cfg.state_dir / "worker.session").unlink(missing_ok=True)
                try:
                    log_file = self.run_role("worker", self.cfg.worker_model, build_worker_prompt(self.cfg), resume=False)
                except HarnessError as final_exc:
                    failed_log = final_exc.log_file if isinstance(final_exc, RoleRunError) else None
                    if failed_log is not None:
                        self.capture_cycle_artifact(failed_log, f"worker.iter{i:02d}.failed.log")
                    self.log(f"Worker iteration {i} failed: {final_exc}")
                    self.write_status("worker", "retrying-after-error", f"iteration={i} error={final_exc}")
                    self.mark_cycle_step("worker", "running", f"iteration={i} error={final_exc}")
                    time.sleep(self.cfg.worker_sleep_secs)
                    continue
            remaining = self.extract_remaining_steps(log_file)
            if not remaining:
                self.die("Worker did not print remaining step count")
            self.save_role_markers("worker", log_file, remaining)
            self.capture_cycle_artifact(log_file, f"worker.iter{i:02d}.log")
            self.capture_cycle_snapshot(f"worker-iter{i:02d}")
            if self.cfg.worker_finish_token in log_file.read_text(encoding="utf-8", errors="replace"):
                self.mark_cycle_step("worker", "done", f"remaining={remaining}")
                return
            time.sleep(self.cfg.worker_sleep_secs)
        self.die(f"Reached MAX_WORKER_ITERS={self.cfg.max_worker_iters} without finishing worker cycle")

    def reviewer_step(self) -> str:
        self.check_stop_file()
        self.preflight_resource_check("reviewer")
        self.mark_cycle_step("reviewer", "running")
        log_file = self.run_role("reviewer", self.cfg.reviewer_model, build_reviewer_prompt(self.cfg))
        remaining = self.extract_remaining_steps(log_file)
        if not remaining:
            self.die("Reviewer did not print remaining step count")
        self.save_role_markers("reviewer", log_file, remaining)
        self.capture_cycle_artifact(log_file, "reviewer.log")
        self.mark_cycle_step("reviewer", "done", f"remaining={remaining}")
        self.capture_cycle_snapshot("reviewer")
        return remaining

    def run_crash_review(self, exit_code: int) -> None:
        if self.crash_review_active:
            return
        self.crash_review_active = True
        try:
            log_file = self.run_role(
                "crash-reviewer",
                self.cfg.crash_reviewer_model,
                build_crash_reviewer_prompt(self.cfg, str(self.current_cycle_dir), exit_code),
            )
        except Exception:
            return
        self.capture_cycle_artifact(log_file, "crash-reviewer.log")
        self.capture_cycle_snapshot("crash-reviewer")
        if "Harness restart required" in log_file.read_text(encoding="utf-8", errors="replace"):
            self.write_status("crash-reviewer", "restart-requested", f"log={log_file.name}")
            self.maybe_self_restart("crash-reviewer")

    def run(self, resume: bool = False) -> int:
        self.ensure_prereqs()
        self.acquire_lock()
        cleanup_stale_child_processes(self.cfg.state_dir, self.cfg.root_dir)
        self.write_status("startup", "ready", f"timeout={self.cfg.codex_timeout_secs}s")
        while True:
            start_step = self.resume_latest_cycle() if resume else None
            if start_step is None:
                self.prepare_cycle_workspace()
                start_step = self.step_order[0]
                self.write_status("cycle", "fresh", f"cycle={self.current_cycle_index} start={start_step}")
            else:
                self.write_status("cycle", "resumed", f"cycle={self.current_cycle_index} start={start_step}")
            self.capture_cycle_snapshot("cycle-start")
            self.check_stop_file()
            start_idx = self.step_order.index(start_step)
            if start_idx <= 0:
                self.sweep_step()
            if start_idx <= 1:
                self.checker_step()
            if start_idx <= 2:
                self.planner_step()
            if start_idx <= 3:
                self.worker_cycle()
            remaining = self.reviewer_step()
            self.log(f"Reviewer says {remaining} steps remain")
            self.maybe_self_restart("reviewer")
            if remaining == "0":
                self.capture_cycle_snapshot("complete")
                print("Global Remaining steps: 0")
                return 0
