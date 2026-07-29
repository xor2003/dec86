"""Layer: Recovery/reporting.

Responsibility: persist already-built recovery artifacts as JSON.
Forbidden: changing artifact semantics, rerunning recovery, or masking write failures as success.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .recovery_artifacts import (
    CorpusRecoveryArtifact,
    FunctionRecoveryArtifact,
    build_x86_16_corpus_recovery_artifact,
    build_x86_16_function_recovery_artifact,
)

__all__ = [
    "RecoveryArtifactWriteResult",
    "write_x86_16_corpus_recovery_artifact",
    "write_x86_16_function_recovery_artifact",
]


@dataclass(frozen=True, slots=True)
class RecoveryArtifactWriteResult:
    """Metadata for one persisted recovery artifact write."""

    path: Path
    artifact_kind: str
    row_count: int

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible write result."""
        return {
            "path": str(self.path),
            "artifact_kind": self.artifact_kind,
            "row_count": self.row_count,
        }


def _write_payload(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_x86_16_function_recovery_artifact(
    source: Mapping[str, object], path: str | Path
) -> RecoveryArtifactWriteResult:
    """Persist one already-produced function recovery artifact as JSON."""
    artifact: FunctionRecoveryArtifact = build_x86_16_function_recovery_artifact(source)
    output_path = Path(path)
    _write_payload(output_path, artifact.to_dict())
    return RecoveryArtifactWriteResult(
        path=output_path,
        artifact_kind="function_recovery",
        row_count=1,
    )


def write_x86_16_corpus_recovery_artifact(
    results: Sequence[Mapping[str, object]], path: str | Path
) -> RecoveryArtifactWriteResult:
    """Persist an already-produced corpus recovery artifact as JSON."""
    artifact: CorpusRecoveryArtifact = build_x86_16_corpus_recovery_artifact(list(results))
    output_path = Path(path)
    _write_payload(output_path, artifact.to_dict())
    return RecoveryArtifactWriteResult(
        path=output_path,
        artifact_kind="corpus_recovery",
        row_count=len(artifact.function_rows),
    )
