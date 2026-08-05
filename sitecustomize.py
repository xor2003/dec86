"""Repository-local Python startup compatibility hooks.

Layer: Tooling/gates.
"""

from __future__ import annotations

import json
import os
import sys
import types

resource: types.ModuleType | None = None
try:
    import resource as _resource
except ImportError:  # pragma: no cover
    pass
else:
    resource = _resource

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


def _install_msgspec_shim() -> None:
    try:
        import msgspec  # noqa: F401
    except ModuleNotFoundError:
        pass
    else:
        return

    class _MsgSpecJson:
        @staticmethod
        def encode(obj):
            return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        @staticmethod
        def decode(data):
            if isinstance(data, memoryview):
                data = bytes(data)
            if isinstance(data, (bytes, bytearray)):
                data = data.decode("utf-8")
            if not isinstance(data, str):
                raise TypeError(f"msgspec.json.decode expects bytes or str, got {type(data)!r}")
            return json.loads(data)

        @staticmethod
        def dumps(obj):
            return json.dumps(obj)

        @staticmethod
        def loads(data):
            if isinstance(data, memoryview):
                data = bytes(data)
            if isinstance(data, (bytes, bytearray)):
                data = data.decode("utf-8")
            if not isinstance(data, str):
                raise TypeError(f"msgspec.json.loads expects bytes or str, got {type(data)!r}")
            return json.loads(data)

    msgspec_module = types.ModuleType("msgspec")
    setattr(msgspec_module, "json", _MsgSpecJson)
    setattr(msgspec_module, "__all__", ["json"])
    sys.modules["msgspec"] = msgspec_module


_install_msgspec_shim()
