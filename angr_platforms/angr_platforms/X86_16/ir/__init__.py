"""IR-layer package exports.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .core import (
    AddressStatus,
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCallOutputProvenance8616,
    IRCallOutputShape8616,
    IRCallStackEffect8616,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
    SegmentWriteFact,
    SegmentWriteKind,
    apply_x86_16_segment_function_contract,
    build_x86_16_segment_function_contract,
)
from .segment_state import (
    SegmentRegisterState,
    SegmentRestoreSource,
    SegmentStateArtifact,
    SegmentValueKind8616,
    apply_x86_16_segment_state_artifact,
    build_x86_16_segment_state_artifact,
)
from .ssa import SSABinding, SSABlock, build_x86_16_block_local_ssa
from .ssa_function import SSAFunctionArtifact, SSAIncomingValue, SSAPhiNode, build_x86_16_function_ssa
from .ssa_memory_contracts import (
    SSAFunctionMemoryResult8616,
    SSAMemoryBinding8616,
    SSAMemoryIncomingValue8616,
    SSAMemoryPhiNode8616,
    SSAMemoryStats8616,
)
from .string_effects import (
    IRStringEffectArtifact,
    IRStringEffectRecord,
    apply_x86_16_typed_string_effect_artifact,
    build_x86_16_typed_string_effect_artifact,
)
from .vex_import import (
    apply_x86_16_vex_ir_artifact,
    build_x86_16_ir_function_artifact,
    build_x86_16_ir_function_artifact_summary,
)

__all__ = [
    "IRBlock",
    "IRAddress",
    "IRBinaryValue",
    "IRCallOutputProvenance8616",
    "IRCallOutputShape8616",
    "IRCallStackEffect8616",
    "IRCondition",
    "IRFunctionArtifact",
    "IRInstr",
    "IRRefusal",
    "IRValue",
    "AddressStatus",
    "SegmentOrigin",
    "MemSpace",
    "SSABinding",
    "SSABlock",
    "SegmentRegisterState",
    "SegmentRestoreSource",
    "SegmentStateArtifact",
    "SegmentValueKind8616",
    "SegmentAccessFact",
    "SegmentAccessKind",
    "SegmentFactVerdict",
    "SegmentFunctionContract",
    "SegmentWriteFact",
    "SegmentWriteKind",
    "SSAFunctionArtifact",
    "SSAIncomingValue",
    "SSAPhiNode",
    "SSAFunctionMemoryResult8616",
    "SSAMemoryBinding8616",
    "SSAMemoryIncomingValue8616",
    "SSAMemoryPhiNode8616",
    "SSAMemoryStats8616",
    "IRStringEffectArtifact",
    "IRStringEffectRecord",
    "apply_x86_16_vex_ir_artifact",
    "apply_x86_16_segment_state_artifact",
    "apply_x86_16_segment_function_contract",
    "apply_x86_16_typed_string_effect_artifact",
    "build_x86_16_block_local_ssa",
    "build_x86_16_function_ssa",
    "build_x86_16_ir_function_artifact",
    "build_x86_16_ir_function_artifact_summary",
    "build_x86_16_segment_state_artifact",
    "build_x86_16_segment_function_contract",
    "build_x86_16_typed_string_effect_artifact",
]
