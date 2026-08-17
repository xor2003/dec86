import json
from pathlib import Path

from scripts.pytest_source_state import (
    SourceTreeSnapshot,
    profile_artifact_has_stable_source,
    source_tree_snapshot,
)


def test_source_tree_snapshot_changes_with_source_content(tmp_path: Path) -> None:
    source_path = tmp_path / "module.py"
    source_path.write_text("VALUE = 1\n", encoding="utf-8")
    first = source_tree_snapshot(tmp_path)

    source_path.write_text("VALUE = 2\n", encoding="utf-8")
    second = source_tree_snapshot(tmp_path)

    assert not first.is_stable_with(second)
    assert first.sha256 != second.sha256


def test_source_tree_snapshot_ignores_generated_directories(tmp_path: Path) -> None:
    source_path = tmp_path / "module.py"
    source_path.write_text("VALUE = 1\n", encoding="utf-8")
    generated_path = tmp_path / "build" / "generated.py"
    generated_path.parent.mkdir()
    generated_path.write_text("VALUE = 2\n", encoding="utf-8")

    snapshot = source_tree_snapshot(tmp_path)

    assert snapshot.file_count == 1


def test_source_tree_snapshot_json_round_trip(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    snapshot = source_tree_snapshot(tmp_path)

    assert SourceTreeSnapshot.from_json(snapshot.to_json()) == snapshot


def test_profile_artifact_requires_explicit_stable_source(tmp_path: Path) -> None:
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps({"source_state": {"stable": False}}), encoding="utf-8")
    assert not profile_artifact_has_stable_source(profile_path)

    profile_path.write_text(json.dumps({"source_state": {"stable": True}}), encoding="utf-8")
    assert profile_artifact_has_stable_source(profile_path)
