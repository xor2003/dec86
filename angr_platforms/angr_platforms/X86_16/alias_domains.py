"""Layer: Compatibility shim.

Responsibility: preserve flat alias_domains import surface during alias package migration.
Dynamic boundary: compatibility re-export only; canonical alias.domains owns
the literal public API.
Forbidden: semantic ownership; import canonical alias.domains only.
"""

from __future__ import annotations

from .alias.domains import *  # noqa: F403
