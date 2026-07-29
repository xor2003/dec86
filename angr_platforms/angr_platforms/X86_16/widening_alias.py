"""Layer: Compatibility shim.

Responsibility: preserve flat widening_alias import surface during widening package migration.
Dynamic boundary: compatibility re-export only; canonical widening.register_widening
owns the literal public API.
Forbidden: semantic ownership; import canonical widening.register_widening only.
"""

from __future__ import annotations

from .widening.register_widening import *  # noqa: F403
