"""Compatibility shim for moved flag cleanup.

The implementation lives in ``X86_16.postprocess.flags_cleanup``. This root
module exists only for legacy imports while callers migrate.

Do not add behavior here. New flag cleanup belongs in the real postprocess
package module, and new flag semantics belong earlier in IR/semantics/condition
transfer rather than in any rewrite shim.
"""

from __future__ import annotations

from .postprocess import flags_cleanup as _flags_cleanup

globals().update({name: getattr(_flags_cleanup, name) for name in dir(_flags_cleanup) if not name.startswith("__")})

__all__ = getattr(_flags_cleanup, "__all__", tuple())
