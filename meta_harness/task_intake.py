from __future__ import annotations

from pathlib import Path

PENDING_TASK_FILE = Path(".codex_automation") / "requested_task.md"


def pending_task_path(root_dir: Path) -> Path:
    """Return the stable operator task handoff path."""
    return root_dir / PENDING_TASK_FILE


def write_pending_task(root_dir: Path, task: str) -> Path:
    """Persist an operator task for the planner to turn into PLAN.md steps."""
    text = task.strip()
    if not text:
        raise ValueError("task must not be empty")
    path = pending_task_path(root_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    return path


def read_pending_task(root_dir: Path) -> str:
    """Read the pending task without consuming it."""
    path = pending_task_path(root_dir)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace").strip()
