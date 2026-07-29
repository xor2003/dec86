"""Layer: Compatibility shim.

Responsibility: preserve flat import surface during alias package migration.
Dynamic boundary: compatibility re-export only; canonical alias.alias_model owns
the literal public API.
Forbidden: semantic ownership; import canonical alias.alias_model only.
"""

from __future__ import annotations

from .alias.alias_model import *  # noqa: F403
