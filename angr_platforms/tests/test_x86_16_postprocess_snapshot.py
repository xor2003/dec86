from __future__ import annotations

from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _PostprocessValidationDeltaKind8616,
    _classify_postprocess_validation_delta_8616,
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
