from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.validation_condition_precision import (
    ConditionPrecisionEvidence8616,
    condition_precision_validation_delta_8616,
)

WIDE_LT = "CmpLT(stack_slot:SS:BP+0x4:size4,stack_slot:SS:BP+0x8:size4)"
WIDE_GT = "CmpGT(stack_slot:SS:BP+0x4:size4,stack_slot:SS:BP+0x8:size4)"
HIGH_LE = "CmpLE(stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP+0xa:size2)"
HIGH_GE = "CmpGE(stack_slot:SS:BP+0x6:size2,stack_slot:SS:BP+0xa:size2)"


def _validation(*, extra_return: bool = False) -> dict[str, object]:
    delta: dict[str, object] = {
        "conditions": {
            "added": (WIDE_GT, WIDE_LT),
            "removed": (HIGH_GE, HIGH_LE),
        },
        "control_flow_effects": {
            "added": (f"if:{WIDE_GT}", f"if:{WIDE_LT}"),
            "removed": (f"if:{HIGH_GE}", f"if:{HIGH_LE}"),
        },
    }
    if extra_return:
        delta["returns"] = {"added": ("const:1",), "removed": ()}
    return {"changed": True, "status": "changed", "delta": delta}


def _codegen() -> SimpleNamespace:
    return SimpleNamespace(
        _inertia_condition_precision_evidence_8616=(
            ConditionPrecisionEvidence8616(HIGH_LE, WIDE_LT),
            ConditionPrecisionEvidence8616(HIGH_GE, WIDE_GT),
        )
    )


def test_condition_precision_validation_accepts_exact_evidence_pairs() -> None:
    result = condition_precision_validation_delta_8616(_codegen(), _validation())

    assert result.accepted is True
    assert result.stats.classified_fact_count == 2
    assert result.stats.materialized_count == 2
    assert result.stats.failure_count == 0


def test_condition_precision_validation_refuses_unmatched_condition() -> None:
    validation = _validation()
    delta = validation["delta"]
    assert isinstance(delta, dict)
    conditions = delta["conditions"]
    assert isinstance(conditions, dict)
    conditions["added"] = (WIDE_GT, "CmpEQ(const:1,const:2)")

    result = condition_precision_validation_delta_8616(_codegen(), validation)

    assert result.accepted is False
    assert result.stats.failure_count == 1


def test_condition_precision_validation_refuses_extra_semantic_field() -> None:
    result = condition_precision_validation_delta_8616(
        _codegen(),
        _validation(extra_return=True),
    )

    assert result.accepted is False
    assert result.stats.failure_count == 1
