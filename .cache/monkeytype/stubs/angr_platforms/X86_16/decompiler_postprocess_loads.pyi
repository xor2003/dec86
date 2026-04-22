from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CUnaryOp,
)
from types import SimpleNamespace


def _global_load_addr_8616(
    node: <class 'Union'>[angr.analyses.decompiler.structured_codegen.c.CVariable, angr.analyses.decompiler.structured_codegen.c.CUnaryOp]
) -> int | None: ...


def _match_global_scaled_high_byte_8616(node: CBinaryOp) -> int | None: ...


def _segmented_load_addr_8616(
    node: CUnaryOp,
    project: SimpleNamespace
) -> tuple[str | None, int | None]: ...
