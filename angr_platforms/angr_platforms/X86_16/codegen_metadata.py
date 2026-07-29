"""Layer: Recovery metadata.

Responsibility: carry side metadata on codegen objects without changing semantics.
Forbidden: using metadata writes as proof, recovery, or validation acceptance.
Dynamic attribute boundary: getattr/setattr use here is limited to third-party
angr/codegen compatibility objects and optional diagnostic metadata.
"""

from __future__ import annotations

import typing

__all__ = [
    "append_codegen_sequence_attr",
    "get_codegen_sequence_attr",
    "get_codegen_side_metadata",
    "set_codegen_sequence_attr",
]


def get_codegen_side_metadata(codegen: object) -> dict[str, object]:
    """Return the mutable recovery metadata side map attached to a codegen object.

    Dynamic attribute boundary: codegen is a third-party angr/codegen
    compatibility object that intentionally carries optional diagnostic metadata.
    """
    metadata = getattr(codegen, "_inertia_recovery_metadata", None)
    if isinstance(metadata, dict):
        return metadata
    metadata = {}
    typing.cast(typing.Any, codegen)._inertia_recovery_metadata = metadata
    return metadata


def get_codegen_sequence_attr(codegen: object, cfunc: object, name: str) -> tuple[str, ...]:
    """Read a string sequence side attribute from codegen, falling back to cfunc.

    Dynamic attribute boundary: these are third-party angr/codegen
    compatibility objects that intentionally carry optional diagnostic metadata.
    """
    value = getattr(codegen, name, None)
    if isinstance(value, (tuple, list)):
        return tuple(str(item) for item in value)
    value = getattr(cfunc, name, None)
    if isinstance(value, (tuple, list)):
        return tuple(str(item) for item in value)
    return ()


def append_codegen_sequence_attr(codegen: object, cfunc: object, name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    """Append unique string values to a codegen/cfunc side metadata sequence.

    Dynamic attribute boundary: these are third-party angr/codegen
    compatibility objects that intentionally carry optional diagnostic metadata.
    """
    merged: list[str] = list(get_codegen_sequence_attr(codegen, cfunc, name))
    for value in values:
        if value not in merged:
            merged.append(value)
    return set_codegen_sequence_attr(codegen, cfunc, name, tuple(merged))


def set_codegen_sequence_attr(codegen: object, cfunc: object, name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    """Replace a string sequence on both transient codegen metadata owners.

    angr may replace the codegen wrapper while retaining the structured C
    function. Mirroring lowering artifacts onto both boundaries keeps them
    available without making CLI rendering rediscover semantics.
    """
    merged_tuple = tuple(dict.fromkeys(values))
    setattr(codegen, name, merged_tuple)
    try:
        setattr(cfunc, name, merged_tuple)
    except Exception:
        pass
    return merged_tuple
