"""Layer: CLI/fallback/reporting.

Responsibility: enter one isolated serial function worker through the typed CLI core.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from inertia_decompiler.cli_core import main as _core_main


def main(argv: list[str] | None = None) -> int:
    """Run one clean worker without importing the legacy CLI compatibility surface."""
    return _core_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
