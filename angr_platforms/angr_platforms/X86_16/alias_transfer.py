"""Layer: Compatibility shim.

Responsibility: preserve flat alias_transfer import surface during alias package migration.
Dynamic boundary: compatibility re-export only; canonical alias.transfer owns
the literal public API.
Forbidden: semantic ownership; import canonical alias.transfer only.
"""

from __future__ import annotations

from .alias.transfer import *  # noqa: F403
