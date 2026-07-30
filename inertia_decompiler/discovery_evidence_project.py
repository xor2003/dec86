"""Create isolated projects for mutating discovery evidence scans.

Layer: CLI/fallback/reporting.
Responsibility: keep caller-evidence discovery mutations out of the target decompilation project.
"""

from __future__ import annotations

from pathlib import Path

import angr

from inertia_decompiler.project_loading import _build_project_cached


def isolated_discovery_evidence_project_8616(project: angr.Project) -> angr.Project:
    """Return a separate project for scans that mutate angr's knowledge base."""
    try:
        main_object = project.loader.main_object
        binary = main_object.binary
        linked_base = main_object.linked_base
        entry_point = project.entry
    except (AttributeError, TypeError):
        return project
    if not isinstance(binary, str | Path) or not isinstance(linked_base, int) or not isinstance(entry_point, int):
        return project
    try:
        return _build_project_cached(
            str(binary),
            force_blob=False,
            base_addr=linked_base,
            entry_point=entry_point,
        )
    except (OSError, ValueError):
        return project
