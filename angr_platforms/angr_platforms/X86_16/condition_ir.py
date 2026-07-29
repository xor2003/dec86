"""Layer: Compatibility shim.

Responsibility: preserve flat condition_ir imports during IR package migration.
Dynamic boundary: compatibility re-export only; canonical ir.condition_ir owns
the literal public API.
Forbidden: semantic ownership; import canonical ir.condition_ir only.
"""

from __future__ import annotations

from .ir.condition_ir import *  # noqa: F403
