from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_makefile_quiets_inventory_expanded_tool_recipes() -> None:
    """Large file inventories stay hidden unless a developer requests them."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "Q ?= @" in makefile
    assert "MAKEFLAGS += --no-print-directory" in makefile
    assert "RUFF_OUTPUT_FLAGS ?= --quiet --output-format concise" in makefile
    assert "MYPY_OUTPUT_FLAGS ?= --no-pretty --no-color-output --no-error-summary" in makefile
    assert "PYRIGHT_OUTPUT_FLAGS ?= --level warning" in makefile
    assert "PYTEST_OUTPUT_FLAGS ?= --tb=short --no-header" in makefile
    assert "LIZARD_OUTPUT_FLAGS ?= --warnings_only" in makefile
    assert "\nruff:\n\t$(Q)$(PYTHON) -m ruff check --fix $(RUFF_OUTPUT_FLAGS)" in makefile
    assert "\nmypy:\n\t$(Q)$(PYTHON) -m mypy $(MYPY_OUTPUT_FLAGS)" in makefile
    assert "\nmypy-dev:\n\t$(Q)$(PYTHON) -m mypy $(MYPY_OUTPUT_FLAGS)" in makefile
    assert "PYRIGHT_CMD_BASE := $(PYTHON) -m pyright $(PYRIGHT_OUTPUT_FLAGS)" in makefile
    assert "\npyright:\n\t$(Q)$(PYRIGHT_CMD_BASE)" in makefile
    assert "\npyright-all:\n\t$(Q)$(PYRIGHT_CMD_BASE)" in makefile
    assert "\npytest:\n\t$(Q)INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=" in makefile
    assert "\nagent-context-check:\n\t$(Q)$(PYTHON) scripts/agent_context_check.py --compact" in makefile


def test_agents_document_bounded_gate_output() -> None:
    """Agents retain full diagnostics without loading successful broad logs."""
    instructions = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "### Token-efficient command output" in instructions
    assert "report only the exit status, pass/fail/skip counts" in instructions
    assert "Output reduction must never suppress diagnostics" in instructions
