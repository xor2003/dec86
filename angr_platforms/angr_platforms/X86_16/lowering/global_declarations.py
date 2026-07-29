"""Register proven C global declarations for 16-bit lowering.

Layer: Types/Lowering.
Responsibility: merge already-proven global storage declarations for emitted C.
Consumes alias, widening, and typed facts; it merges already-proven storage
identity into declarations without creating new storage evidence.
Do not recover semantics from COD, source, assembly, or rendered C text.
Postprocess and CLI may consume declarations, but proof belongs here.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast


class GlobalDeclarationCodegen8616(Protocol):
    """Dynamic codegen metadata slot used by proven global declaration lowering."""

    _inertia_global_declaration_specs_8616: tuple[tuple[str, str, int | None], ...]


class GlobalDeclarationCType8616(Enum):
    """Canonical C declaration type for one proven global storage width."""

    UNSIGNED_CHAR = "unsigned char"
    UNSIGNED_SHORT = "unsigned short"
    UNSIGNED_LONG = "unsigned long"

    @property
    def c_name(self) -> str:
        """Return the C spelling used in emitted declarations."""
        return self.value

    @property
    def width(self) -> int:
        """Return the byte width represented by this declaration type."""
        return _GLOBAL_CTYPE_WIDTHS_8616[self]


@dataclass(frozen=True, slots=True)
class NamedAggregateDeclarationCType8616:
    """Two lifecycle spellings of one proven named aggregate declaration.

    Before angr's function type store is available, a global may need an
    inline definition. Once the same type is registered, declarations must use
    its typedef name so codegen does not emit a duplicate struct definition.
    """

    type_name: str
    inline_definition: str
    registered: bool

    @property
    def c_name(self) -> str:
        """Return the currently valid C spelling for the aggregate."""
        if self.registered:
            return " ".join(self.type_name.split())
        return " ".join(self.inline_definition.split())

    def merge_with_serialized(self, old_ctype: str) -> str | None:
        """Merge an earlier serialized view of this exact aggregate.

        Return ``None`` when the earlier declaration is unrelated, leaving the
        generic declaration precedence rules responsible for that case.
        """
        old_name = " ".join(old_ctype.split())
        type_name = " ".join(self.type_name.split())
        inline_definition = " ".join(self.inline_definition.split())
        if old_name not in {type_name, inline_definition}:
            return None
        if self.registered or old_name == type_name:
            return type_name
        return inline_definition


_GLOBAL_CTYPE_WIDTHS_8616: dict[GlobalDeclarationCType8616, int] = {
    GlobalDeclarationCType8616.UNSIGNED_CHAR: 1,
    GlobalDeclarationCType8616.UNSIGNED_SHORT: 2,
    GlobalDeclarationCType8616.UNSIGNED_LONG: 4,
}


def ctype_for_global_width_8616(width: int) -> GlobalDeclarationCType8616:
    """Return the canonical declaration type for a proven global width."""
    if int(width) == 1:
        return GlobalDeclarationCType8616.UNSIGNED_CHAR
    if int(width) == 4:
        return GlobalDeclarationCType8616.UNSIGNED_LONG
    return GlobalDeclarationCType8616.UNSIGNED_SHORT


def record_global_declaration_spec_8616(
    codegen: object,
    *,
    ctype: GlobalDeclarationCType8616 | NamedAggregateDeclarationCType8616 | str,
    name: str,
    array_len: int | None,
) -> None:
    """Record one proven global declaration, merging duplicate storage identities.

    Multiple lowering paths may see the same global through different evidence
    views, e.g. direct `g_work+10` and indexed `g_work[si]`. The emitted C must
    contain one declaration for that semantic global, with the widest proven
    extent.
    """
    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_]\w*", name) is None:
        return
    typed_codegen = cast(GlobalDeclarationCodegen8616, codegen)
    if isinstance(ctype, (GlobalDeclarationCType8616, NamedAggregateDeclarationCType8616)):
        ctype_name = ctype.c_name
    else:
        ctype_name = " ".join(str(ctype).split())
    if not ctype_name:
        return
    normalized_len = int(array_len) if isinstance(array_len, int) and array_len > 0 else None
    try:
        raw_specs = typed_codegen._inertia_global_declaration_specs_8616
    except AttributeError:
        raw_specs = ()
    specs = tuple(cast(Iterable[object], raw_specs or ()))
    merged: list[tuple[str, str, int | None]] = []
    replaced = False
    for spec in specs:
        if not isinstance(spec, (list, tuple)) or len(spec) != 3:
            continue
        old_ctype, old_name, old_len = spec
        if not isinstance(old_ctype, str) or not isinstance(old_name, str):
            continue
        old_ctype_name = " ".join(old_ctype.split())
        old_array_len = int(old_len) if isinstance(old_len, int) and old_len > 0 else None
        if old_name != name:
            merged.append((old_ctype_name, old_name, old_array_len))
            continue
        replaced = True
        aggregate_merge = (
            ctype.merge_with_serialized(old_ctype_name)
            if isinstance(ctype, NamedAggregateDeclarationCType8616)
            else None
        )
        chosen_ctype = aggregate_merge or _choose_global_ctype_8616(old_ctype_name, ctype_name)
        if _scalar_global_covers_existing_array_8616(
            old_ctype_name,
            old_array_len,
            ctype_name,
            normalized_len,
        ):
            chosen_len = None
        else:
            chosen_len = _choose_global_array_len_8616(old_array_len, normalized_len)
        merged.append((chosen_ctype, name, chosen_len))
    if not replaced:
        merged.append((ctype_name, name, normalized_len))
    typed_codegen._inertia_global_declaration_specs_8616 = tuple(dict.fromkeys(merged))


def record_scalar_global_declaration_spec_8616(
    codegen: object,
    *,
    ctype: GlobalDeclarationCType8616 | str,
    name: str,
) -> None:
    """Record a proven scalar global and discard an equal-width one-element view.

    A direct scalar load used as a value is stronger shape evidence than an
    earlier compatibility declaration inferred from one addressed element.
    Wider arrays and differently sized declarations remain untouched because
    they may represent distinct aggregate evidence.
    """
    typed_codegen = cast(GlobalDeclarationCodegen8616, codegen)
    ctype_name = ctype.c_name if isinstance(ctype, GlobalDeclarationCType8616) else " ".join(str(ctype).split())
    try:
        specs = tuple(cast(Iterable[object], typed_codegen._inertia_global_declaration_specs_8616 or ()))
    except AttributeError:
        specs = ()
    filtered: list[tuple[str, str, int | None]] = []
    for spec in specs:
        if not isinstance(spec, (list, tuple)) or len(spec) != 3:
            continue
        old_ctype, old_name, old_len = spec
        if not isinstance(old_ctype, str) or not isinstance(old_name, str):
            continue
        old_ctype_name = " ".join(old_ctype.split())
        old_array_len = int(old_len) if isinstance(old_len, int) and old_len > 0 else None
        if (
            old_name == name
            and old_array_len == 1
            and _ctype_width_8616(old_ctype_name) == _ctype_width_8616(ctype_name)
        ):
            continue
        filtered.append((old_ctype_name, old_name, old_array_len))
    typed_codegen._inertia_global_declaration_specs_8616 = tuple(filtered)
    record_global_declaration_spec_8616(codegen, ctype=ctype, name=name, array_len=None)


def _choose_global_array_len_8616(left: int | None, right: int | None) -> int | None:
    """Choose the widest proven array extent for one merged global name."""
    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)


def _scalar_global_covers_existing_array_8616(
    left_ctype: str,
    left_len: int | None,
    right_ctype: str,
    right_len: int | None,
) -> bool:
    """Return whether a scalar declaration exactly covers an existing array."""
    left_width = _ctype_width_8616(left_ctype)
    right_width = _ctype_width_8616(right_ctype)
    if left_len is None and left_width >= 4:
        return _array_byte_extent_8616(right_ctype, right_len) == left_width
    if right_len is None and right_width >= 4:
        return _array_byte_extent_8616(left_ctype, left_len) == right_width
    return False


def _array_byte_extent_8616(ctype: str, array_len: int | None) -> int | None:
    """Return the byte extent for a declared array, when it is array-shaped."""
    if array_len is None:
        return None
    return _ctype_width_8616(ctype) * array_len


def _choose_global_ctype_8616(left: str, right: str) -> str:
    """Choose the declaration type preserving the most structured proven view."""
    if _ctype_is_pointer_8616(right) and not _ctype_is_pointer_8616(left):
        return right
    if _ctype_is_pointer_8616(left) and not _ctype_is_pointer_8616(right):
        return left
    if _ctype_is_struct_8616(right) and not _ctype_is_struct_8616(left):
        return right
    if _ctype_is_struct_8616(left) and not _ctype_is_struct_8616(right):
        return left
    left_width = _ctype_width_8616(left)
    right_width = _ctype_width_8616(right)
    if right_width > left_width:
        return right
    return left


def _ctype_is_struct_8616(ctype: str) -> bool:
    """Return whether a declaration type names a proven object/field aggregate."""
    return " ".join(ctype.split()).startswith("struct ")


def _ctype_is_pointer_8616(ctype: str) -> bool:
    """Return whether a declaration type is pointer-shaped C syntax."""
    return "*" in " ".join(ctype.split())


def _ctype_width_8616(ctype: str) -> int:
    """Return the storage width represented by a scalar or known aggregate type."""
    ctype = " ".join(ctype.split())
    if ctype in {"unsigned char", "signed char", "char", "uint8_t", "int8_t"}:
        return 1
    if ctype in {"unsigned long", "long", "uint32_t", "int32_t"}:
        return 4
    return 2
