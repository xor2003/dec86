from __future__ import annotations

from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _PostprocessValidationDeltaKind8616,
    _classify_postprocess_validation_delta_8616,
    _is_jcc_call_return_condition_rebinding_delta_8616,
    _restore_codegen_inertia_metadata_8616,
    _snapshot_codegen_inertia_metadata_8616,
    _snapshot_codegen_cfunc,
)


class _FakeCodegen:
    def __init__(self, cfunc):
        self.cfunc = cfunc


class _FakeCFunc:
    addr = 0x1000

    def __init__(self, statements):
        self.statements = statements


class _UncopyableStatements:
    def __deepcopy__(self, memo):
        raise TypeError("not independently copyable")


class _UncopyableCodegen:
    project = object()

    def __deepcopy__(self, memo):
        raise ValueError("ctypes objects containing pointers cannot be pickled")


class _StatementNodeWithCodegen:
    def __init__(self, codegen):
        self.codegen = codegen
        self.values = [1]


def test_postprocess_snapshot_requires_independent_statement_copy():
    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(_FakeCFunc(_UncopyableStatements())))

    assert snapshot is None


def test_postprocess_snapshot_does_not_share_statement_tree():
    cfunc = _FakeCFunc([{"value": [1]}])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.statements[0]["value"].append(2)

    assert snapshot is not None
    assert snapshot.statements == [{"value": [1]}]


def test_postprocess_snapshot_does_not_copy_live_codegen_backpointer():
    live_codegen = _UncopyableCodegen()
    cfunc = _FakeCFunc([_StatementNodeWithCodegen(live_codegen)])
    cfunc.codegen = live_codegen

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.statements[0].values.append(2)

    assert snapshot is not None
    assert snapshot.statements[0].codegen is None
    assert snapshot.statements[0].values == [1]


def test_postprocess_validation_delta_classifies_name_only_helper_annotations():
    validation = {
        "delta": {
            "helper_calls": {
                "added": (),
                "removed": ("name:addr:0x1d1c", "name:addr:0x1d91"),
            },
            "returns": {"added": (), "removed": ()},
        }
    }

    assert (
        _classify_postprocess_validation_delta_8616(validation)
        is _PostprocessValidationDeltaKind8616.NAME_ONLY_HELPER_ANNOTATION
    )


def test_postprocess_validation_delta_rejects_raw_helper_and_mixed_semantic_delta():
    assert (
        _classify_postprocess_validation_delta_8616(
            {
                "delta": {
                    "helper_calls": {
                        "added": (),
                        "removed": ("addr:0x1d1c",),
                    }
                }
            }
        )
        is _PostprocessValidationDeltaKind8616.BLOCKING
    )


def test_jcc_call_return_condition_delta_accepts_virtual_carrier_fingerprint_churn():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_jcc_call_return_register_rebindings = 3
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpNE(virtual:vvar_42,const:35)",),
                "removed": ("CmpNE(reg:ax,const:35)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpNE(virtual:vvar_42,const:35)",),
                "removed": ("if:CmpNE(reg:ax,const:35)",),
            },
            "segmented_writes": {
                "added": ("deref:Add(Mul(virtual:vvar_1146,const:16),virtual:vvar_1142,const:-2)",),
                "removed": ("deref:Add(Mul(virtual:vvar_11,const:16),virtual:vvar_6,const:-2)",),
            },
        }
    }

    assert _is_jcc_call_return_condition_rebinding_delta_8616(codegen, validation) is True


def test_jcc_call_return_condition_delta_refuses_without_consumed_rebinding_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpNE(virtual:vvar_42,const:35)",),
                "removed": ("CmpNE(reg:ax,const:35)",),
            }
        }
    }

    assert _is_jcc_call_return_condition_rebinding_delta_8616(codegen, validation) is False


def test_postprocess_metadata_restore_removes_rejected_return_chain_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_return_chain_flattened_8616 = False
    codegen._inertia_postprocess_rejected_passes = ("earlier",)

    snapshot = _snapshot_codegen_inertia_metadata_8616(codegen)
    codegen._inertia_return_chain_flattened_8616 = True
    codegen._inertia_return_chain_materialized_values_8616 = (1, 2, 3)
    codegen._inertia_postprocess_rejected_passes = ("earlier", "current")

    _restore_codegen_inertia_metadata_8616(codegen, snapshot)

    assert codegen._inertia_return_chain_flattened_8616 is False
    assert not hasattr(codegen, "_inertia_return_chain_materialized_values_8616")
    assert codegen._inertia_postprocess_rejected_passes == ("earlier", "current")

    assert (
        _classify_postprocess_validation_delta_8616(
            {
                "delta": {
                    "helper_calls": {
                        "added": (),
                        "removed": ("name:addr:0x1d1c",),
                    },
                    "returns": {
                        "added": ("const:255",),
                        "removed": (),
                    },
                }
            }
        )
        is _PostprocessValidationDeltaKind8616.BLOCKING
    )
