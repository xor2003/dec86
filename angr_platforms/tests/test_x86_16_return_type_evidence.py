from __future__ import annotations

from types import SimpleNamespace

from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort
from angr_platforms.X86_16.annotations import ANNOTATION_KEY
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.lowering.return_type_evidence import (
    FunctionReturnClass8616,
    caller_return_use_evidence_proves_used_8616,
    function_has_proven_void_return_type_8616,
    materialize_proven_void_return_type_8616,
    proven_function_return_class_8616,
)


def _evidence(
    verdict: CallerReturnUseVerdict8616,
    *,
    raw: int,
    classified: int,
    failures: int,
) -> CallerReturnUseEvidence8616:
    return CallerReturnUseEvidence8616(
        target_addr=0x1000,
        verdict=verdict,
        raw_fact_count=raw,
        normalized_fact_count=raw,
        classified_fact_count=classified,
        materialized_count=classified,
        failure_count=failures,
        used_callsite_count=classified if verdict is CallerReturnUseVerdict8616.USED else 0,
        unused_callsite_count=classified if verdict is CallerReturnUseVerdict8616.UNUSED else 0,
        callsite_addrs=tuple(range(raw)),
    )


def _function(arch: Arch86_16) -> SimpleNamespace:
    prototype = SimTypeFunction([SimTypeShort(False)], SimTypeShort(False)).with_arch(arch)
    return SimpleNamespace(
        addr=0x1000,
        prototype=prototype,
        is_prototype_guessed=True,
        info={},
    )


def test_proves_used_return_from_at_least_one_classified_caller() -> None:
    evidence = _evidence(CallerReturnUseVerdict8616.USED, raw=3, classified=2, failures=1)

    assert caller_return_use_evidence_proves_used_8616(evidence) is True


def test_classifies_used_and_closed_unused_return_evidence() -> None:
    project = SimpleNamespace()
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.USED, raw=3, classified=2, failures=1),
    )
    record_caller_return_use_evidence_8616(
        project,
        0x2000,
        CallerReturnUseEvidence8616(
            target_addr=0x2000,
            verdict=CallerReturnUseVerdict8616.UNUSED,
            raw_fact_count=2,
            normalized_fact_count=2,
            classified_fact_count=2,
            materialized_count=2,
            failure_count=0,
            used_callsite_count=0,
            unused_callsite_count=2,
            callsite_addrs=(0x1200, 0x1300),
        ),
    )

    assert proven_function_return_class_8616(project, 0x1000) is FunctionReturnClass8616.VALUE
    assert proven_function_return_class_8616(project, 0x2000) is FunctionReturnClass8616.VOID


def test_return_class_refuses_incomplete_or_absent_evidence() -> None:
    project = SimpleNamespace()
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNKNOWN, raw=3, classified=2, failures=1),
    )

    assert proven_function_return_class_8616(project, 0x1000) is None
    assert proven_function_return_class_8616(project, 0x2000) is None


def test_refuses_used_verdict_without_a_materialized_used_callsite() -> None:
    evidence = CallerReturnUseEvidence8616(
        target_addr=0x1000,
        verdict=CallerReturnUseVerdict8616.USED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=1,
        used_callsite_count=1,
        unused_callsite_count=0,
        callsite_addrs=(0x1200,),
    )

    assert caller_return_use_evidence_proves_used_8616(evidence) is False


def test_materializes_void_return_from_closed_unused_caller_evidence() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    function = _function(arch)
    evidence = _evidence(CallerReturnUseVerdict8616.UNUSED, raw=3, classified=3, failures=0)
    record_caller_return_use_evidence_8616(project, 0x1000, evidence)

    changed = materialize_proven_void_return_type_8616(project, function)

    assert changed is True
    assert isinstance(function.prototype.returnty, SimTypeBottom)
    assert function.prototype.returnty.label == "void"
    assert len(function.prototype.args) == 1
    assert function.is_prototype_guessed is False
    assert function_has_proven_void_return_type_8616(project, function) is True


def test_refuses_incomplete_unused_caller_evidence() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    function = _function(arch)
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNKNOWN, raw=3, classified=2, failures=1),
    )

    assert materialize_proven_void_return_type_8616(project, function) is False
    assert isinstance(function.prototype.returnty, SimTypeShort)
    assert function.is_prototype_guessed is True
    assert function_has_proven_void_return_type_8616(project, function) is False


def test_materializes_void_return_when_calling_convention_left_prototype_unset() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=None,
        is_prototype_guessed=True,
        info={},
    )
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=2, classified=2, failures=0),
    )

    assert materialize_proven_void_return_type_8616(project, function) is True
    assert isinstance(function.prototype, SimTypeFunction)
    assert isinstance(function.prototype.returnty, SimTypeBottom)
    assert function.prototype.args == ()


def test_refuses_overriding_explicit_prototype() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    function = _function(arch)
    function.is_prototype_guessed = False
    function.info = {ANNOTATION_KEY: {"prototype": function.prototype}}
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=3, classified=3, failures=0),
    )

    assert materialize_proven_void_return_type_8616(project, function) is False
    assert isinstance(function.prototype.returnty, SimTypeShort)


def test_materializes_void_over_binary_inferred_non_guessed_prototype() -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    function = _function(arch)
    function.is_prototype_guessed = False
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        _evidence(CallerReturnUseVerdict8616.UNUSED, raw=3, classified=3, failures=0),
    )

    assert materialize_proven_void_return_type_8616(project, function) is True
    assert isinstance(function.prototype.returnty, SimTypeBottom)
    assert function.prototype.returnty.label == "void"
    assert function.is_prototype_guessed is False
