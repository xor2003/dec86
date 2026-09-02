"""Project byte-safe C accesses from a wider indexed-global load site.

Layer: Types/Lowering.
Responsibility: preserve the exact byte lane of a structured C access when
binary load-site evidence proves that the originating machine load was wider.
Consumes typed load width, segmented-address decomposition, and the already
materialized indexed-global value. It does not infer objects from rendered C,
names, samples, or postprocess shape.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CExpression
from angr.sim_type import SimTypeLong, SimTypeShort

from .real_mode_linear import RealModeLinearGlobalAddress8616
from .runtime_memory_helpers import memory_pointer_helper_8616, segmented_memory_read_helper_8616

__all__ = ["IndexedLoadSubviewProjection8616", "project_indexed_load_subview_8616"]


@dataclass(frozen=True, slots=True)
class IndexedLoadSubviewProjection8616:
    """One exact access-width projection from a wider indexed-global value."""

    expression: CExpression
    byte_offset: int
    access_width: int


def _structured_access_width_8616(node: object) -> int | None:
    """Read the access width at the dynamic third-party structured-C boundary."""
    memory_helper = memory_pointer_helper_8616(node)
    if memory_helper is not None:
        return int(memory_helper.width)
    segmented_helper = segmented_memory_read_helper_8616(node)
    if segmented_helper is not None:
        return int(segmented_helper.width)
    if not isinstance(node, CExpression):
        return None
    try:
        bits = node.type.size
    except (AttributeError, ValueError):
        return None
    return bits // 8 if isinstance(bits, int) and bits > 0 and bits % 8 == 0 else None


def project_indexed_load_subview_8616(
    codegen: object,
    node: object,
    full_value: object,
    access: RealModeLinearGlobalAddress8616 | None,
    *,
    site_base_offset: int,
    site_width: int,
) -> IndexedLoadSubviewProjection8616 | None:
    """Project the exact C access lane from one binary-proven full value."""
    if not isinstance(full_value, CExpression) or site_width not in {1, 2, 4}:
        return None
    if site_width == 1:
        return IndexedLoadSubviewProjection8616(full_value, 0, site_width)
    access_width = _structured_access_width_8616(node)
    if access_width is None or access_width <= 0 or access_width > site_width:
        return None
    if access_width == site_width:
        return IndexedLoadSubviewProjection8616(full_value, 0, access_width)
    if access is None or access.segment_name != "ds" or access.width != access_width:
        return None
    byte_offset = (access.displacement - site_base_offset) & 0xFFFF
    if byte_offset + access_width > site_width:
        return None

    scalar_type = SimTypeLong(False) if site_width == 4 else SimTypeShort(False)
    projected: CExpression = full_value
    if byte_offset:
        projected = CBinaryOp(
            "Shr",
            projected,
            CConstant(byte_offset * 8, scalar_type, codegen=codegen),
            codegen=codegen,
        )
    mask = (1 << (access_width * 8)) - 1
    projected = CBinaryOp(
        "And",
        projected,
        CConstant(mask, scalar_type, codegen=codegen),
        codegen=codegen,
    )
    return IndexedLoadSubviewProjection8616(projected, byte_offset, access_width)
