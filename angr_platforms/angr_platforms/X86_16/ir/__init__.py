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
from .indexed_address_contracts import (
    IndexedAddressAccessKind8616,
    IndexedAddressDefinitionSite8616,
    IndexedAddressEvidence8616,
    IndexedAddressFact8616,
    IndexedAddressFailureKind8616,
    IndexedAddressRefusal8616,
    IndexedAddressStats8616,
)
from .indexed_address_copy_contracts import (
    IndexedAddressCopyEvidence8616,
    IndexedAddressCopyFact8616,
    IndexedAddressCopyFailureKind8616,
    IndexedAddressCopyLane8616,
    IndexedAddressCopyRefusal8616,
    IndexedAddressCopyStats8616,
    IndexedAddressCopyStep8616,
    IndexedAddressCopyStepKind8616,
    IndexedAddressCopyValuePath8616,
)
from .indexed_address_copy_evidence import collect_indexed_address_copy_evidence_8616
from .indexed_address_evidence import collect_indexed_address_evidence_8616
from .logical_memory_capture import (
    IRLogicalMemoryCaptureCollection8616,
    IRLogicalMemoryCaptureRecord8616,
)
from .logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRLogicalMemoryArtifact8616,
    IRLogicalMemoryFailureKind8616,
    IRLogicalMemoryRefusal8616,
    IRLogicalMemoryStats8616,
    IRMemoryAccessKind8616,
    IRMemoryExecutionSlice8616,
)
from .logical_memory_resolution import resolve_logical_memory_accesses_8616
from .scalar_affine_contracts import (
    ScalarAffineExpression8616,
    ScalarAffineFailure8616,
    ScalarAffineTerm8616,
    ScalarAffineTrace8616,
    ScalarAffineTraceStats8616,
)
from .scalar_affine_trace import trace_scalar_affine_expression_8616
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
    SSAMemoryAccess8616,
    SSAMemoryAccessKind8616,
    SSAMemoryAccessSlice8616,
    SSAMemoryBinding8616,
    SSAMemoryIncomingValue8616,
    SSAMemoryOverlap8616,
    SSAMemoryOverlapRelation8616,
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
    "AddressStatus",
    "IRAddress",
    "IRBinaryValue",
    "IRBlock",
    "IRCallOutputProvenance8616",
    "IRCallOutputShape8616",
    "IRCallStackEffect8616",
    "IRCondition",
    "IRFunctionArtifact",
    "IRInstr",
    "IRLogicalMemoryAccess8616",
    "IRLogicalMemoryAccessKey8616",
    "IRLogicalMemoryArtifact8616",
    "IRLogicalMemoryCaptureCollection8616",
    "IRLogicalMemoryCaptureRecord8616",
    "IRLogicalMemoryFailureKind8616",
    "IRLogicalMemoryRefusal8616",
    "IRLogicalMemoryStats8616",
    "IRMemoryAccessKind8616",
    "IRMemoryExecutionSlice8616",
    "IRRefusal",
    "IRStringEffectArtifact",
    "IRStringEffectRecord",
    "IRValue",
    "IndexedAddressAccessKind8616",
    "IndexedAddressCopyEvidence8616",
    "IndexedAddressCopyFact8616",
    "IndexedAddressCopyFailureKind8616",
    "IndexedAddressCopyLane8616",
    "IndexedAddressCopyRefusal8616",
    "IndexedAddressCopyStats8616",
    "IndexedAddressCopyStep8616",
    "IndexedAddressCopyStepKind8616",
    "IndexedAddressCopyValuePath8616",
    "IndexedAddressDefinitionSite8616",
    "IndexedAddressEvidence8616",
    "IndexedAddressFact8616",
    "IndexedAddressFailureKind8616",
    "IndexedAddressRefusal8616",
    "IndexedAddressStats8616",
    "MemSpace",
    "SSABinding",
    "SSABlock",
    "SSAFunctionArtifact",
    "SSAFunctionMemoryResult8616",
    "SSAIncomingValue",
    "SSAMemoryAccess8616",
    "SSAMemoryAccessKind8616",
    "SSAMemoryAccessSlice8616",
    "SSAMemoryBinding8616",
    "SSAMemoryIncomingValue8616",
    "SSAMemoryOverlap8616",
    "SSAMemoryOverlapRelation8616",
    "SSAMemoryPhiNode8616",
    "SSAMemoryStats8616",
    "SSAPhiNode",
    "ScalarAffineExpression8616",
    "ScalarAffineFailure8616",
    "ScalarAffineTerm8616",
    "ScalarAffineTrace8616",
    "ScalarAffineTraceStats8616",
    "SegmentAccessFact",
    "SegmentAccessKind",
    "SegmentFactVerdict",
    "SegmentFunctionContract",
    "SegmentOrigin",
    "SegmentRegisterState",
    "SegmentRestoreSource",
    "SegmentStateArtifact",
    "SegmentValueKind8616",
    "SegmentWriteFact",
    "SegmentWriteKind",
    "apply_x86_16_segment_function_contract",
    "apply_x86_16_segment_state_artifact",
    "apply_x86_16_typed_string_effect_artifact",
    "apply_x86_16_vex_ir_artifact",
    "build_x86_16_block_local_ssa",
    "build_x86_16_function_ssa",
    "build_x86_16_ir_function_artifact",
    "build_x86_16_ir_function_artifact_summary",
    "build_x86_16_segment_function_contract",
    "build_x86_16_segment_state_artifact",
    "build_x86_16_typed_string_effect_artifact",
    "collect_indexed_address_copy_evidence_8616",
    "collect_indexed_address_evidence_8616",
    "resolve_logical_memory_accesses_8616",
    "trace_scalar_affine_expression_8616",
]
