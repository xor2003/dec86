from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _run_python_snippet(args: list[str], snippet: str, memory_mb: int = 512) -> list[str]:
    env = os.environ.copy()
    env["INERTIA_ONELINER_MAX_MEMORY_MB"] = str(memory_mb)
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [sys.executable, *args],
        input=snippet,
        text=True,
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def test_sitecustomize_caps_python_stdin_one_liners():
    lines = _run_python_snippet(
        ["-"],
        "import resource\nimport sys\nprint(sys.argv[0])\nprint(resource.getrlimit(resource.RLIMIT_AS)[0])\n",
    )
    assert lines[0] == "-"
    assert int(lines[1]) == 512 * 1024 * 1024


def test_sitecustomize_caps_python_dash_c_one_liners():
    env = os.environ.copy()
    env["INERTIA_ONELINER_MAX_MEMORY_MB"] = "384"
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import resource, sys; print(sys.argv[0]); print(resource.getrlimit(resource.RLIMIT_AS)[0])",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines[0] == "-c"
    assert int(lines[1]) == 384 * 1024 * 1024
