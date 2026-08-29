from __future__ import annotations

from angr_platforms.X86_16.structuring.identical_return_guards import (
    IdenticalReturnGuardCollapseResult8616,
    IdenticalReturnGuardCollapseStats8616,
    IdenticalReturnGuardMaterialization8616,
    IdenticalReturnGuardShape8616,
)
from angr_platforms.X86_16.validation_identical_return_guards import (
    IdenticalReturnGuardValidationStatus8616,
    consume_identical_return_guard_validation_delta_8616,
)


def _closed_result(
    shape: IdenticalReturnGuardShape8616 = IdenticalReturnGuardShape8616.ELSE_RETURN,
) -> IdenticalReturnGuardCollapseResult8616:
    return IdenticalReturnGuardCollapseResult8616(
        collapsed_guard_count=1,
        stats=IdenticalReturnGuardCollapseStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        ),
        materializations=(IdenticalReturnGuardMaterialization8616(0, shape),),
    )


def _validation_delta() -> dict[str, object]:
    fields = (
        "conditions",
        "control_flow_effects",
        "global_writes",
        "helper_calls",
        "register_writes",
        "returns",
        "segmented_writes",
        "stack_writes",
    )
    delta = {name: {"added": (), "removed": ()} for name in fields}
    delta["conditions"]["removed"] = ("condition-fingerprint",)
    delta["control_flow_effects"]["removed"] = (
        "first-control-fingerprint",
        "second-control-fingerprint",
        "if:else",
    )
    return {
        "changed": True,
        "status": "changed",
        "delta": delta,
        "semantic_failures": (),
    }


def test_identical_return_guard_validation_consumes_exact_delta() -> None:
    validation = _validation_delta()

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.accepted
    assert result.consumed_condition_count == 1
    assert result.consumed_control_effect_count == 3
    assert validation["changed"] is False
    assert validation["status"] == "stable"
    assert "delta" not in validation


def test_identical_return_guard_validation_refuses_write_delta() -> None:
    validation = _validation_delta()
    validation["delta"]["stack_writes"]["removed"] = ("stack-write",)

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(),
        validation,
    )

    assert result.status is (
        IdenticalReturnGuardValidationStatus8616.REFUSED_UNEXPECTED_EFFECT
    )
    assert validation["changed"] is True
    assert "delta" in validation


def test_identical_return_guard_validation_consumes_fallthrough_shape() -> None:
    validation = _validation_delta()
    validation["delta"]["control_flow_effects"]["removed"] = (
        "single-control-fingerprint",
    )

    result = consume_identical_return_guard_validation_delta_8616(
        _closed_result(IdenticalReturnGuardShape8616.FALLTHROUGH_RETURN),
        validation,
    )

    assert result.accepted
    assert result.consumed_condition_count == 1
    assert result.consumed_control_effect_count == 1
    assert validation["changed"] is False
