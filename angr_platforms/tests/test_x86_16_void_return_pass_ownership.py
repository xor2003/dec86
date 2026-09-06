"""Regress ownership of void-return normalization.

Layer: postprocess orchestration
Responsibility: keep return-shape normalization before validation baseline capture.
"""

from types import SimpleNamespace

from angr_platforms.X86_16 import decompiler_postprocess_stage as post_stage


def test_void_return_pruning_runs_only_during_prevalidation_priming(monkeypatch) -> None:
    """Do not repeat a baseline-defining mutation inside validated cleanup passes."""
    calls: list[str] = []
    monkeypatch.setattr(
        post_stage._post,
        "_classify_return_shape_8616",
        lambda _project, _codegen: calls.append("classify") or False,
    )
    monkeypatch.setattr(
        post_stage._post,
        "_prune_void_function_return_values_8616",
        lambda _project, _codegen: calls.append("prune") or True,
    )
    monkeypatch.setattr(post_stage, "_invalidate_tail_validation_derived_caches_8616", lambda _codegen: None)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = post_stage._prime_return_shape_before_validation_baseline_8616(SimpleNamespace(), codegen)

    assert changed is True
    assert calls == ["classify", "prune"]
    assert "_prune_void_function_return_values_8616" not in {
        spec.name for spec in post_stage.DECOMPILER_POSTPROCESS_PASSES
    }
