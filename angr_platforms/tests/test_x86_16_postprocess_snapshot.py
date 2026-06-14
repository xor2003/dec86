from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CIfElse,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
import angr_platforms.X86_16.decompiler_postprocess_stage as post_stage
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _classify_postprocess_validation_delta_8616,
    _direct_stack_move_validation_delta_kind_8616,
    _is_callsite_stack_argument_materialization_delta_8616,
    _is_direct_global_update_materialization_delta_8616,
    _is_direct_stack_move_materialization_delta_8616,
    _is_direct_stack_move_idiv_remainder_materialization_delta_8616,
    _is_direct_stack_update_materialization_delta_8616,
    _is_jcc_call_return_condition_rebinding_delta_8616,
    _is_jcc_condition_materialization_validation_delta_8616,
    _postprocess_run_bootstrap_steps_8616,
    _try_accept_failed_postprocess_validation_8616,
    _PostprocessValidationDeltaKind8616,
    _repair_missing_cnode_codegen_metadata_8616,
    _restore_codegen_inertia_metadata_8616,
    _snapshot_codegen_cfunc,
    _snapshot_codegen_inertia_metadata_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import DirectStackMoveSourceKind8616


class _FakeCodegen:
    def __init__(self, cfunc):
        self.cfunc = cfunc


class _FakeCFunc:
    addr = 0x1000

    def __init__(self, statements):
        self.statements = statements
        self.body = statements


def test_bootstrap_omits_stack_materialization_passes():
    seen: list[str] = []
    codegen = SimpleNamespace(_inertia_postprocess_validation_failed=False)

    def apply_step(name, _step):
        seen.append(name)
        return True

    assert _postprocess_run_bootstrap_steps_8616(SimpleNamespace(), codegen, set(), apply_step) is True
    assert seen[0] == "_normalize_fact_backed_stack_accesses_8616"
    assert "_materialize_direct_stack_incdec_instructions_8616" not in seen
    assert "_materialize_stable_stack_semantics_bootstrap_8616" not in seen


def test_generic_return_artifact_detects_unified_vvar_dereference():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    vvar_base = SimRegisterVariable(0, 2, name=None)
    vvar_base_unified = SimRegisterVariable(0, 2, name="vvar_59")
    vvar_base_expr = CVariable(vvar_base, unified_variable=vvar_base_unified, variable_type=word_type, codegen=codegen)
    deref = CUnaryOp("Dereference", vvar_base_expr, codegen=codegen)
    expr = CBinaryOp("Sub", CConstant(1, word_type, codegen=codegen), deref, codegen=codegen)

    assert post_stage._return_expr_has_generic_register_artifact_8616(expr) is True


def test_untyped_dereference_return_artifact_refuses_pointer_typed_operand():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    temp = CVariable(SimRegisterVariable(1, 2, name="tmp_1"), variable_type=word_type, codegen=codegen)
    pointer_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="p"),
        variable_type=SimTypePointer(word_type),
        codegen=codegen,
    )

    assert post_stage._return_expr_has_untyped_dereference_artifact_8616(
        CUnaryOp("Dereference", temp, codegen=codegen)
    ) is True
    assert post_stage._return_expr_has_untyped_dereference_artifact_8616(
        CUnaryOp("Dereference", pointer_arg, codegen=codegen)
    ) is False


def test_pointer_cast_dirty_dereference_return_artifact_is_not_pointer_proof():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    dirty_pointer_carrier = CTypeCast(
        None,
        SimTypePointer(word_type),
        CDirtyExpression("vvar_59 + vvar_60", codegen=codegen),
        codegen=codegen,
    )

    assert post_stage._return_expr_has_untyped_dereference_artifact_8616(
        CUnaryOp("Dereference", dirty_pointer_carrier, codegen=codegen)
    ) is True


def test_dirty_carrier_return_artifact_detects_unlowered_expression():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    expr = CBinaryOp(
        "Mul",
        CVariable(SimStackVariable(4, 2, base="bp", name="a"), variable_type=word_type, codegen=codegen),
        CDirtyExpression("vvar_60 | vvar_61 * 0x100", codegen=codegen),
        codegen=codegen,
    )

    assert post_stage._return_expr_has_dirty_carrier_artifact_8616(expr) is True


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


class _CodegenWithIndexes:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name):
        self._idx += 1
        return self._idx


class _VariableManagerWithUnified:
    def __init__(self, unified_by_variable):
        self._unified_by_variable = dict(unified_by_variable)

    def unified_variable(self, variable):
        return self._unified_by_variable.get(variable)


def test_repair_metadata_registers_live_register_variables_for_declarations():
    codegen = _CodegenWithIndexes()
    cfunc = SimpleNamespace(addr=0x1000, variables_in_use={}, unified_local_vars={})
    codegen.cfunc = cfunc

    word_type = SimTypeShort(False)
    ax_var = SimRegisterVariable(0, 2, name="ax")
    ax = CVariable(ax_var, variable_type=word_type, codegen=codegen)
    cond = CBinaryOp("CmpLT", ax, CConstant(3, word_type, codegen=codegen), codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    cfunc.statements = CStatements([if_stmt], codegen=codegen)
    cfunc.body = cfunc.statements
    ax.codegen = None

    repaired = _repair_missing_cnode_codegen_metadata_8616(cfunc, codegen)

    assert repaired > 0
    assert cfunc.variables_in_use[ax_var] is ax
    assert cfunc.unified_local_vars[ax_var] == {(ax, word_type)}
    assert ax.codegen is codegen
    stats = codegen._inertia_live_register_declaration_repair_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_repair_metadata_binds_live_register_to_unified_declaration_identity():
    codegen = _CodegenWithIndexes()
    word_type = SimTypeShort(False)
    ax_var = SimRegisterVariable(0, 2, name="ax")
    unified_ax = SimRegisterVariable(0, 2, name="v19")
    cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={},
        unified_local_vars={},
        variable_manager=_VariableManagerWithUnified({ax_var: unified_ax}),
    )
    codegen.cfunc = cfunc

    ax = CVariable(ax_var, variable_type=word_type, codegen=codegen)
    cond = CBinaryOp("CmpLT", ax, CConstant(3, word_type, codegen=codegen), codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    cfunc.statements = CStatements([if_stmt], codegen=codegen)
    cfunc.body = cfunc.statements

    _repair_missing_cnode_codegen_metadata_8616(cfunc, codegen)

    assert ax.unified_variable is unified_ax
    assert cfunc.unified_local_vars[unified_ax] == {(ax, word_type)}


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


def test_direct_global_update_materialization_delta_accepts_evidenced_return_precision():
    validation = {
        "delta": {
            "returns": {
                "added": ("Or(Dereference(Add(Mul(Reference(CIndexedVariable),const:16),const:309)),const:0)",),
                "removed": ("Or(Dereference(Add(Mul(reg:ds,const:16),const:309)),const:0)",),
            },
        }
    }

    assert _is_direct_global_update_materialization_delta_8616(_direct_global_update_codegen(), validation) is True


def test_direct_global_update_materialization_delta_refuses_unrelated_return_constant():
    validation = {
        "delta": {
            "returns": {
                "added": ("Or(Dereference(Add(Mul(reg:ds,const:16),const:57005)),const:0)",),
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


def test_jcc_condition_materialization_delta_accepts_exact_inverted_guard_pair():
    codegen = _FakeCodegen(_FakeCFunc([]))
    project = _fake_project_with_functions({})
    validation = {
        "delta": {
            "conditions": {
                "added": (
                    "CmpEQ(stack_slot:SS:BP-0x2:size2,const:0)",
                    "CmpGT(stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2)",
                ),
                "removed": (),
            },
            "control_flow_effects": {
                "added": (
                    "ifbreak:CmpEQ(stack_slot:SS:BP-0x2:size2,const:0)",
                    "ifbreak:CmpGT(stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2)",
                ),
                "removed": (
                    "ifbreak:CmpLE(stack_slot:SS:BP-0x4:size2,stack_slot:SS:BP-0x6:size2)",
                    "ifbreak:CmpNE(stack_slot:SS:BP-0x2:size2,const:0)",
                ),
            },
        },
    }

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            validation,
        )
        is True
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


def test_callsite_materialization_delta_accepts_stack_arg_slot_alias_conditions():
    codegen = _callsite_materialization_codegen()
    arg_codegen = _CodegenWithIndexes()
    arg_i_low = CVariable(SimStackVariable(4, 2, base="bp", name="iLow"), codegen=arg_codegen)
    arg_i_high = CVariable(SimStackVariable(6, 2, base="bp", name="iHigh"), codegen=arg_codegen)
    codegen.cfunc = _SlotCFunc(CStatements([], codegen=arg_codegen), [arg_i_low, arg_i_high])
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpLT(stack_arg:iLow:size2,stack_arg:iHigh:size2)",),
                "removed": ("CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpLT(stack_arg:iLow:size2,stack_arg:iHigh:size2)",),
                "removed": ("if:CmpLT(stack_slot:SS:BP+0x4:size2,stack_slot:SS:BP+0x6:size2)",),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_stack_arg_alias_delta_accepts_8616 == 1


def test_callsite_materialization_delta_accepts_stack_arg_size_precision_with_push_evidence():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x1027: SimpleNamespace(push_arg_sources=(("bp", 6), ("bp", -2))),
    }
    validation = {
        "delta": {
            "returns": {
                "added": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size2)",),
                "removed": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size4)",),
            },
        },
    }

    assert _is_callsite_stack_argument_materialization_delta_8616(codegen, validation) is True
    assert codegen._inertia_callsite_stack_arg_size_precision_delta_accepts_8616 == 1


def test_direct_stack_move_validation_accepts_proven_callsite_arg_size_precision_delta():
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x1027: SimpleNamespace(push_arg_sources=(("bp", 6), ("bp", -2))),
    }
    validation = {
        "delta": {
            "returns": {
                "added": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size2)",),
                "removed": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size4)",),
            },
        },
    }

    assert (
        _direct_stack_move_validation_delta_kind_8616(codegen, validation)
        is _PostprocessValidationDeltaKind8616.CALLSITE_STACK_ARGUMENT_MATERIALIZATION
    )


def test_final_validation_accepts_proven_callsite_arg_size_precision_delta(monkeypatch):
    codegen = _callsite_materialization_codegen()
    codegen._inertia_callsite_summaries = {
        0x1027: SimpleNamespace(push_arg_sources=(("bp", 6), ("bp", -2))),
    }
    accepted = []
    monkeypatch.setattr(
        post_stage,
        "_postprocess_stable_accept_8616",
        lambda _self, _validation, _snapshot_function_info: accepted.append(True),
    )
    validation = {
        "delta": {
            "returns": {
                "added": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size2)",),
                "removed": ("call:addr:0xfd1(stack_slot:SS:BP-0x2:size2,stack_arg:value:size4)",),
            },
        },
    }
    owner = SimpleNamespace(codegen=codegen, project=SimpleNamespace())

    assert (
        _try_accept_failed_postprocess_validation_8616(
            owner,
            validation=validation,
            validation_verdict_text="changed",
            function=None,
            snapshot_function_info=SimpleNamespace(),
            pre_postprocess_cfunc_snapshot=None,
            func_addr=0x1000,
            log=SimpleNamespace(warning=lambda *args, **kwargs: None),
        )
        is True
    )
    assert accepted == [True]


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


def _direct_stack_move_stack_slot_codegen():
    codegen = _FakeCodegen(_FakeCFunc([]))
    codegen._inertia_direct_stack_move_lowering_8616 = {
        "raw_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (
            ("dst_offset", -6),
            ("width", 2),
            ("source_kind", DirectStackMoveSourceKind8616.STACK_SLOT),
            ("source_offset", -2),
            ("ins_addr", 0x1070),
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


def test_direct_stack_update_materialization_delta_refuses_added_raw_flags_condition():
    validation = {
        "delta": {
            "conditions": {
                "added": (
                    "CmpEQ(CmpNE(And(reg:flags,const:128),const:0),CmpNE(And(reg:flags,const:2048),const:0))",
                ),
                "removed": (
                    "CmpLT(Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),"
                    "Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x4:size2,const:1),const:2892)))",
                ),
            },
            "control_flow_effects": {
                "added": (
                    "if:CmpEQ(CmpNE(And(reg:flags,const:128),const:0),CmpNE(And(reg:flags,const:2048),const:0))",
                ),
                "removed": (
                    "if:CmpLT(Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),"
                    "Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x4:size2,const:1),const:2892)))",
                ),
            },
        }
    }

    assert _is_direct_stack_update_materialization_delta_8616(_direct_stack_update_codegen(), validation) is False


def test_direct_stack_move_materialization_delta_accepts_evidenced_stack_slot_copy():
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x6:size2=stack_slot:SS:BP-0x2:size2",),
                "removed": (),
            },
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(_direct_stack_move_stack_slot_codegen(), validation) is True


def test_direct_stack_move_materialization_delta_refuses_unrelated_stack_slot_copy():
    validation = {
        "delta": {
            "stack_writes": {
                "added": ("stack_slot:SS:BP-0x8:size2=stack_slot:SS:BP-0xa:size2",),
                "removed": (),
            },
        }
    }

    assert _is_direct_stack_move_materialization_delta_8616(_direct_stack_move_stack_slot_codegen(), validation) is False


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
