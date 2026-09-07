"""Static QA inventories must agree with Make's literal assignment semantics."""

import subprocess
from pathlib import Path

import pytest

from scripts import check_decompiler_architecture as architecture


@pytest.mark.parametrize(
    "source,expected",
    [
        ("QA := a.py\nQA += b.py\n", ("a.py", "b.py")),
        ("QA += a.py\nQA += a.py\n", ("a.py", "a.py")),
        ("QA := old.py\nQA := new.py\nQA += tail.py\n", ("new.py", "tail.py")),
        ("QA ?= a.py\nQA ?= ignored.py\nQA += b.py\n", ("a.py", "b.py")),
        ("QA = a.py # comment\nQA += b.py\n", ("a.py", "b.py")),
        ("QA := a.py \\\n\tb.py\nQA += \\\n\tc.py\n", ("a.py", "b.py", "c.py")),
        ("QA_OTHER := ignored.py\nQA:=a.py\n", ("a.py",)),
        ("QA :=\nQA ?= ignored.py\n", ()),
    ],
)
def test_literal_inventory_matches_make(source: str, expected: tuple[str, ...]) -> None:
    oracle = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", "-", "inspect"],
        input=source + ".PHONY: inspect\ninspect:\n\t@printf '%s\\n' '$(QA)'\n",
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert oracle.returncode == 0, oracle.stderr
    assert tuple(oracle.stdout.split()) == expected
    assert architecture._makefile_variable_words(source, "QA") == expected


def test_appended_duplicate_and_missing_targets_are_checked(tmp_path: Path) -> None:
    (tmp_path / "Makefile").write_text(
        "QA_PYTEST_TARGETS := missing.py\nQA_PYTEST_TARGETS += missing.py\n",
        encoding="utf-8",
    )
    violations = architecture._check_makefile_gate_targets(tmp_path)
    assert any(item.rule == "makefile-duplicate-qa-target" for item in violations)
    assert any(item.rule == "makefile-missing-qa-target" for item in violations)
