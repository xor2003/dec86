"""Equivalent branch exits require empty SSA blocks and matching edges."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import IRInstr, IRRefusal
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.structuring.condition_exit_normalization import transparent_condition_exit_8616


def _artifact():
    return SSAFunctionArtifact(
        0x100,
        (
            SSABlock(0x110, (), ()),
            SSABlock(0x120, (), ()),
            SSABlock(0x130, (IRInstr(op="CALL", dst=None, args=(), size=0, addr=0x130),), ()),
        ),
        predecessor_map={0x120: (0x110,), 0x130: (0x120,)},
    )


def test_empty_exit_path_stops_before_continuation_effects():
    artifact = _artifact()
    assert transparent_condition_exit_8616(
        artifact, 0x110, {0x110: (0x120,), 0x120: (0x130,)}, stop_at=0x200,
    ) == 0x130
    assert artifact.blocks[-1].instrs[0].op == "CALL"


@pytest.mark.parametrize("refused_block", [None, 0x110, 0x120, 0x900])
def test_memory_refusals_are_scoped_but_unknown_locations_refuse(refused_block):
    artifact = replace(
        _artifact(), memory_refusals=(IRRefusal("unknown", "missing evidence", refused_block),),
    )
    result = transparent_condition_exit_8616(
        artifact, 0x110, {0x110: (0x120,), 0x120: (0x130,)}, stop_at=0x200,
    )
    assert result == (0x130 if refused_block == 0x900 else 0x110)


@pytest.mark.parametrize("case", ["missing", "refusal", "mismatch", "cycle", "opposite", "effect"])
def test_uncertain_or_effectful_exit_is_not_bypassed(case):
    artifact = _artifact()
    edges = {0x110: (0x120,), 0x120: (0x130,)}
    stop = 0x200
    if case == "missing":
        artifact = None
    elif case == "refusal":
        artifact = replace(artifact, blocks=(replace(artifact.blocks[0], refusals=("unknown",)), *artifact.blocks[1:]))
    elif case == "mismatch":
        edges[0x110] = (0x130,)
    elif case == "cycle":
        edges[0x120] = (0x110,)
        artifact = replace(artifact, predecessor_map={0x120: (0x110,), 0x110: (0x120,)})
    elif case == "opposite":
        stop = 0x130
    else:
        artifact = replace(artifact, blocks=(replace(artifact.blocks[0], instrs=artifact.blocks[-1].instrs), *artifact.blocks[1:]))
    assert transparent_condition_exit_8616(artifact, 0x110, edges, stop_at=stop) == 0x110
