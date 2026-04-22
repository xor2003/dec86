from __future__ import annotations

import os
import sys

try:
    import resource
except ImportError:  # pragma: no cover
    resource = None


def _is_one_liner_invocation() -> bool:
    if not sys.argv:
        return False
    return sys.argv[0] in {"-", "-c", ""}


def _apply_memory_cap() -> None:
    if resource is None or not _is_one_liner_invocation():
        return

    raw_limit = os.environ.get("INERTIA_ONELINER_MAX_MEMORY_MB", "6144")
    try:
        limit_mb = int(raw_limit)
    except ValueError:
        return
    if limit_mb <= 0:
        return

    limit_bytes = limit_mb * 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
    except (OSError, ValueError):
        return

    if hasattr(resource, "RLIMIT_DATA"):
        try:
            resource.setrlimit(resource.RLIMIT_DATA, (limit_bytes, limit_bytes))
        except (OSError, ValueError):
            pass


_apply_memory_cap()
