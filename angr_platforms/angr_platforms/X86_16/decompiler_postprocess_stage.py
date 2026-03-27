from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from angr.analyses.decompiler.decompiler import Decompiler

from . import decompiler_postprocess as _post
from . import decompiler_postprocess_flags as _flags
from . import decompiler_postprocess_globals as _globals
from . import decompiler_postprocess_simplify as _simplify

__all__ = [
    "DecompilerPostprocessPassSpec",
    "DECOMPILER_POSTPROCESS_PASSES",
    "_build_decompiler_postprocess_passes",
    "describe_x86_16_decompiler_postprocess_stage",
    "apply_x86_16_decompiler_postprocess",
]


@dataclass(frozen=True, slots=True)
class DecompilerPostprocessPassSpec:
    name: str
    func: Callable[..., bool]
    needs_project: bool


def _build_decompiler_postprocess_passes():
    return (
        DecompilerPostprocessPassSpec("_apply_word_global_types_8616", _globals._apply_word_global_types_8616, True),
        DecompilerPostprocessPassSpec(
            "_promote_stack_prototype_from_bp_loads_8616",
            _post._promote_stack_prototype_from_bp_loads_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unused_unnamed_memory_declarations_8616",
            _globals._prune_unused_unnamed_memory_declarations_8616,
            False,
        ),
        DecompilerPostprocessPassSpec("_apply_annotations_8616", _post._apply_annotations_8616, True),
        DecompilerPostprocessPassSpec(
            "_simplify_boolean_cites_8616",
            _simplify._simplify_boolean_cites_8616,
            False,
        ),
        DecompilerPostprocessPassSpec("_simplify_structured_expressions_8616", _simplify._simplify_structured_expressions_8616, False),
        DecompilerPostprocessPassSpec("_rewrite_flag_condition_pairs_8616", _flags._rewrite_flag_condition_pairs_8616, False),
        DecompilerPostprocessPassSpec("_prune_unused_flag_assignments_8616", _flags._prune_unused_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_prune_overwritten_flag_assignments_8616", _flags._prune_overwritten_flag_assignments_8616, True),
        DecompilerPostprocessPassSpec("_fix_interval_guard_conditions_8616", _flags._fix_interval_guard_conditions_8616, False),
    )


DECOMPILER_POSTPROCESS_PASSES = _build_decompiler_postprocess_passes()


def describe_x86_16_decompiler_postprocess_stage():
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_POSTPROCESS_PASSES)


def _postprocess_codegen_8616(project, codegen) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False

    addrs = set()
    addrs |= _globals._coalesce_word_global_loads_8616(project, codegen)
    addrs |= _globals._coalesce_word_global_constant_stores_8616(project, codegen)

    changed = bool(addrs)
    for spec in DECOMPILER_POSTPROCESS_PASSES:
        if spec.needs_project:
            if spec.func(project, codegen):
                changed = True
        elif spec.func(codegen):
            changed = True
    return changed


def _decompile_8616(self):
    _orig_decompiler_decompile = getattr(_decompile_8616, "_orig_decompiler_decompile", None)
    if _orig_decompiler_decompile is None:
        _orig_decompiler_decompile = Decompiler._decompile
        _decompile_8616._orig_decompiler_decompile = _orig_decompiler_decompile
    _orig_decompiler_decompile(self)
    if (
        self.project.arch.name == "86_16"
        and self.codegen is not None
        and _postprocess_codegen_8616(self.project, self.codegen)
    ):
        self.codegen.regenerate_text()


def apply_x86_16_decompiler_postprocess() -> None:
    if getattr(Decompiler._decompile, "__name__", "") != "_decompile_8616":
        _decompile_8616._orig_decompiler_decompile = Decompiler._decompile
        Decompiler._decompile = _decompile_8616
