from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _PostprocessValidationDeltaKind8616,
    _classify_postprocess_validation_delta_8616,
    _is_callsite_stack_argument_materialization_delta_8616,
    _is_direct_global_update_materialization_delta_8616,
    _is_direct_stack_move_idiv_remainder_materialization_delta_8616,
    _is_direct_stack_update_materialization_delta_8616,
    _is_jcc_call_return_condition_rebinding_delta_8616,
    _is_jcc_condition_materialization_validation_delta_8616,
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
        self.body = statements


class _SlotCFunc:
    __slots__ = ("addr", "arg_list", "body", "codegen", "statements")

    def __init__(self, statements, arg_list):
        self.addr = 0x1000
        self.statements = statements
        self.body = statements
        self.arg_list = arg_list
        self.codegen = None


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


class _CtypesLikeMetadata:
    def __reduce_ex__(self, protocol):
        raise ValueError("ctypes objects containing pointers cannot be pickled")


class _DeepcopyPoisonMetadata:
    def __deepcopy__(self, memo):
        raise AssertionError("metadata snapshot should not deep-copy arbitrary objects")


class _StatementNodeWithCtypesMetadata:
    def __init__(self, metadata):
        self.metadata = metadata
        self.values = [1]


class _FakeFunctions:
    def __init__(self, names_by_addr):
        self._names_by_addr = dict(names_by_addr)

    def function(self, addr, create=False):
        del create
        name = self._names_by_addr.get(addr)
        return SimpleNamespace(name=name) if name is not None else None


def _fake_project_with_functions(names_by_addr):
    return SimpleNamespace(kb=SimpleNamespace(functions=_FakeFunctions(names_by_addr)))


def _jcc_condition_materialization_validation(*, helper="addr:0x11222", global_token="global:0xbab"):
    return {
        "before": {
            "helper_calls": (),
            "global_writes": ("global:0xbaa",),
        },
        "after": {
            "helper_calls": (helper,),
            "global_writes": ("global:0xbaa", global_token),
        },
        "delta": {
            "helper_calls": {
                "added": (helper,),
                "removed": (),
            },
            "global_writes": {
                "added": (global_token,),
                "removed": (),
            },
        },
    }


def _callsite_materialization_codegen():
    return SimpleNamespace(_inertia_callsite_materialization_stats=SimpleNamespace(call_arg_materialized_count=2))


def _callsite_global_precision_validation(*, global_token="global:0xbab"):
    return {
        "before": {
            "global_writes": ("global:0xbaa",),
        },
        "after": {
            "global_writes": ("global:0xbaa", global_token),
        },
        "delta": {
            "global_writes": {
                "added": (global_token,),
                "removed": (),
            },
        },
    }


def _direct_global_update_codegen():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_global_update_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    codegen._inertia_direct_global_update_evidence_8616 = (
        (
            ("displacement", 0x135),
            ("width", 1),
            ("delta", 1),
            ("ins_addr", 0x10420),
            ("name", "c"),
        ),
    )
    return codegen


def test_direct_global_update_materialization_delta_accepts_evidenced_ds_write_precision():
    validation = {
        "delta": {
            "segmented_writes": {
                "added": ("deref:Add(Mul(reg:ds,const:16),const:309)",),
                "removed": ("deref:Add(Add(Mul(reg:ds,const:16),const:308),const:1)",),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is True


def test_direct_global_update_materialization_delta_refuses_condition_change():
    validation = {
        "delta": {
            "segmented_writes": {
                "added": ("deref:Add(Mul(reg:ds,const:16),const:309)",),
                "removed": ("deref:Add(Add(Mul(reg:ds,const:16),const:308),const:1)",),
            },
            "conditions": {
                "added": ("CmpEQ(global:0x135,const:0)",),
                "removed": (),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is False


def test_direct_global_update_materialization_delta_refuses_unrelated_address():
    validation = {
        "delta": {
            "global_writes": {
                "added": ("global:0x222",),
                "removed": (),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is False


def test_postprocess_snapshot_uses_manual_fallback_for_uncopyable_statement_container():
    cfunc = _FakeCFunc(_UncopyableStatements())

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))

    assert snapshot is not None
    assert snapshot.statements is not cfunc.statements
    assert snapshot._inertia_validation_snapshot_fallback == "manual"


def test_postprocess_snapshot_does_not_share_statement_tree():
    cfunc = _FakeCFunc([{"value": [1]}])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.statements[0]["value"].append(2)

    assert snapshot is not None
    assert snapshot.statements == [{"value": [1]}]


def test_postprocess_snapshot_body_uses_cloned_statement_root():
    cfunc = _FakeCFunc([{"value": [1]}])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.body[0]["value"].append(2)

    assert snapshot is not None
    assert snapshot.body is snapshot.statements
    assert snapshot.body == [{"value": [1]}]


def test_postprocess_snapshot_clones_slot_backed_arg_list():
    cfunc = _SlotCFunc([{"stmt": [1]}], [{"arg": [10]}])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.arg_list[0]["arg"].append(11)
    cfunc.statements[0]["stmt"].append(2)

    assert snapshot is not None
    assert snapshot.arg_list == [{"arg": [10]}]
    assert snapshot.statements == [{"stmt": [1]}]
    assert snapshot.body is snapshot.statements


def test_postprocess_snapshot_preserves_live_codegen_backpointer_identity():
    live_codegen = _UncopyableCodegen()
    cfunc = _FakeCFunc([_StatementNodeWithCodegen(live_codegen)])
    cfunc.codegen = live_codegen

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.statements[0].values.append(2)

    assert snapshot is not None
    assert snapshot.statements[0].codegen is live_codegen
    assert snapshot.statements[0].values == [1]


def test_postprocess_snapshot_preserves_ctypes_metadata_identity_but_clones_tree():
    metadata = _CtypesLikeMetadata()
    cfunc = _FakeCFunc([_StatementNodeWithCtypesMetadata(metadata)])

    snapshot = _snapshot_codegen_cfunc(_FakeCodegen(cfunc))
    cfunc.statements[0].values.append(2)

    assert snapshot is not None
    assert snapshot.statements[0] is not cfunc.statements[0]
    assert snapshot.statements[0].metadata is metadata
    assert snapshot.statements[0].values == [1]
    assert snapshot._inertia_validation_snapshot_fallback == "ctypes_metadata_identity"


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


def test_jcc_condition_materialization_delta_accepts_stack_probe_and_high_byte_precision_churn():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_semantic_condition_materialized_count = 2
    project = _fake_project_with_functions({0x11222: "aNchkstk"})

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            _jcc_condition_materialization_validation(),
        )
        is True
    )


def test_jcc_condition_materialization_delta_refuses_without_consumed_condition_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    project = _fake_project_with_functions({0x11222: "aNchkstk"})

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            _jcc_condition_materialization_validation(),
        )
        is False
    )


def test_jcc_condition_materialization_delta_refuses_non_stack_probe_helper():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_semantic_condition_materialized_count = 1
    project = _fake_project_with_functions({0x11222: "printf"})

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            _jcc_condition_materialization_validation(),
        )
        is False
    )


def test_jcc_condition_materialization_delta_refuses_unrelated_global_write():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_semantic_condition_materialized_count = 1
    project = _fake_project_with_functions({0x11222: "aNchkstk"})

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            _jcc_condition_materialization_validation(global_token="global:0xbc0"),
        )
        is False
    )


def test_callsite_materialization_delta_accepts_adjacent_global_precision_churn():
    validation = _callsite_global_precision_validation(global_token="global:0xbab")

    assert _is_callsite_stack_argument_materialization_delta_8616(_callsite_materialization_codegen(), validation) is True


def test_callsite_materialization_delta_refuses_unrelated_global_write():
    validation = _callsite_global_precision_validation(global_token="global:0xbc0")

    assert _is_callsite_stack_argument_materialization_delta_8616(_callsite_materialization_codegen(), validation) is False


def _direct_stack_update_codegen():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_update_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    codegen._inertia_direct_stack_update_evidence_8616 = (
        (
            ("offset", -2),
            ("width", 2),
            ("delta", 1),
            ("ins_addr", 0x105CB),
            ("name", "iRow"),
        ),
    )
    return codegen


def _direct_stack_move_idiv_codegen():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_move_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (
            ("dst_offset", -118),
            ("width", 2),
            ("source_kind", "SIGNED_IDIV_REMAINDER"),
            ("source_offset", -4),
            ("source_op", "MOD"),
            ("source_immediate", 1),
            ("ins_addr", 0x10611),
        ),
    )
    return codegen


def test_direct_stack_update_materialization_delta_accepts_evidenced_stack_slot_rebind():
    validation = {
        "delta": {
            "segmented_writes": {
                "added": ("deref:Add(Reference(global:0x8f0),Shl(stack_slot:SS:BP-0x2:size4,const:1))",),
                "removed": ("deref:Add(Reference(global:0x8f0),Shl(stack_slot:SS:BP+0x0:size2,const:1))",),
            },
            "conditions": {
                "added": ("CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
            "control_flow_effects": {
                "added": ("for:CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("for:CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(_direct_stack_update_codegen(), validation) is True


def test_direct_stack_move_idiv_remainder_delta_accepts_insert_helper_and_ax_churn():
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:_INSERT",),
                "removed": (),
            },
            "register_writes": {
                "added": ("reg:ax",),
                "removed": (),
            },
        }
    }

    assert _is_direct_stack_move_idiv_remainder_materialization_delta_8616(
        _direct_stack_move_idiv_codegen(),
        validation,
    ) is True


def test_direct_stack_move_idiv_remainder_delta_accepts_combined_stack_update_delta():
    codegen = _direct_stack_update_codegen()
    move_codegen = _direct_stack_move_idiv_codegen()
    codegen._inertia_direct_stack_move_lowering_8616 = move_codegen._inertia_direct_stack_move_lowering_8616
    codegen._inertia_direct_stack_move_evidence_8616 = move_codegen._inertia_direct_stack_move_evidence_8616
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:_INSERT",),
                "removed": (),
            },
            "register_writes": {
                "added": ("reg:ax",),
                "removed": (),
            },
            "conditions": {
                "added": ("CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
            "control_flow_effects": {
                "added": ("for:CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("for:CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
        }
    }

    assert _is_direct_stack_move_idiv_remainder_materialization_delta_8616(codegen, validation) is True


def test_direct_stack_move_idiv_remainder_delta_refuses_without_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    validation = {
        "delta": {
            "helper_calls": {
                "added": ("name:_INSERT",),
                "removed": (),
            }
        }
    }

    assert _is_direct_stack_move_idiv_remainder_materialization_delta_8616(codegen, validation) is False


def test_direct_stack_update_materialization_delta_refuses_without_consumed_evidence():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_update_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpGT(global:0xba2,stack_slot:SS:BP-0x2:size4)",),
                "removed": ("CmpGT(global:0xba2,stack_slot:SS:BP+0x0:size2)",),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(codegen, validation) is False


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


def test_postprocess_metadata_snapshot_rolls_back_top_level_containers_without_deepcopying_objects():
    codegen = _FakeCodegen(_FakeCFunc([]))
    marker = _DeepcopyPoisonMetadata()
    codegen._inertia_example_metadata = {"items": [marker], "count": 1}

    snapshot = _snapshot_codegen_inertia_metadata_8616(codegen)
    codegen._inertia_example_metadata["items"].append("mutated")
    codegen._inertia_example_metadata["count"] = 2

    _restore_codegen_inertia_metadata_8616(codegen, snapshot)

    assert codegen._inertia_example_metadata["items"] == [marker]
    assert codegen._inertia_example_metadata["count"] == 1
