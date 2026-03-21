from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SNAKE_EXE = REPO_ROOT / "snake.exe"


def test_decompile_cli_lists_and_decompiles_snake_functions():
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), str(SNAKE_EXE), "--timeout", "10", "--max-functions", "6"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "functions recovered:" in result.stdout
    assert "== function 0x1100 _start ==" in result.stdout
    assert "== function 0x1192 sub_1192 ==" in result.stdout
    assert "-- c --" in result.stdout
    assert "summary: decompiled" in result.stdout
