"""Layer: Compatibility shim.

Responsibility: preserve flat alias_state import surface during alias package migration.
Dynamic boundary: compatibility re-export only; canonical alias.state owns
the literal public API.
Forbidden: semantic ownership; import canonical alias.state only.
"""

from __future__ import annotations

from .alias.state import *  # noqa: F403
