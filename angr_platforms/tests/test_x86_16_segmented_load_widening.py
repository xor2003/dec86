from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import MemSpace
from angr_platforms.X86_16.widening.segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_identity_8616,
    segmented_load_tags_8616,
)
from angr_platforms.X86_16.widening.segmented_load_widening import (
    apply_segmented_load_widening_8616,
    join_adjacent_segmented_load_identities_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.cfunc = SimpleNamespace(addr=0x10560)

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _identity(space: MemSpace, offset: int, *, width: int = 1) -> SegmentedLoadIdentity8616:
    return SegmentedLoadIdentity8616(space=space, offset=offset, width=width, region=0x10560)


def test_join_adjacent_segmented_load_identities_proves_one_word() -> None:
    joined = join_adjacent_segmented_load_identities_8616(
        _identity(MemSpace.DS, 0x0BA2),
        _identity(MemSpace.DS, 0x0BA3),
    )

    assert joined == SegmentedLoadIdentity8616(
        space=MemSpace.DS,
        offset=0x0BA2,
        width=2,
        region=0x10560,
    )


def test_join_adjacent_segmented_load_identities_refuses_different_spaces() -> None:
    joined = join_adjacent_segmented_load_identities_8616(
        _identity(MemSpace.DS, 0x0BA2),
        _identity(MemSpace.ES, 0x0BA3),
    )

    assert joined is None


def test_join_adjacent_segmented_load_identities_refuses_gap_and_wrap() -> None:
    assert (
        join_adjacent_segmented_load_identities_8616(
            _identity(MemSpace.DS, 0x0BA2),
            _identity(MemSpace.DS, 0x0BA4),
        )
        is None
    )


def test_segmented_load_widening_materializes_and_retains_exact_identity() -> None:
    codegen = _Codegen()
    ds = CVariable(SimRegisterVariable(22, 2, name="ds"), codegen=codegen)
    low_offset = CConstant(0x0BA2, SimTypeShort(False), codegen=codegen)
    high_offset = CConstant(0x0BA3, SimTypeShort(False), codegen=codegen)
    low_identity = _identity(MemSpace.DS, 0x0BA2)
    high_identity = _identity(MemSpace.DS, 0x0BA3)
    low = CFunctionCall(
        "SEG_U8",
        None,
        [ds, low_offset],
        codegen=codegen,
        tags=segmented_load_tags_8616(
            low_identity,
            existing={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
        ),
    )
    high = CFunctionCall(
        "SEG_U8",
        None,
        [ds, high_offset],
        codegen=codegen,
        tags=segmented_load_tags_8616(
            high_identity,
            existing={"inertia_x86_16_runtime_segment_helper": "SEG_U8"},
        ),
    )
    expression = CBinaryOp(
        "Or",
        low,
        CBinaryOp(
            "Shl",
            high,
            CConstant(8, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([expression], codegen=codegen)
    codegen.cfunc.body = root
    codegen.cfunc.statements = root

    changed = apply_segmented_load_widening_8616(codegen)

    assert changed is True
    result = codegen.cfunc.statements.statements[0]
    assert isinstance(result, CFunctionCall)
    assert segmented_load_identity_8616(result) == SegmentedLoadIdentity8616(
        MemSpace.DS,
        0x0BA2,
        2,
        0x10560,
    )
    assert codegen._inertia_segmented_load_widening_report_8616.materialized_count == 1
    assert (
        join_adjacent_segmented_load_identities_8616(
            _identity(MemSpace.DS, 0xFFFF),
            _identity(MemSpace.DS, 0),
        )
        is None
    )
