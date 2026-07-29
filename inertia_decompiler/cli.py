"""Layer: CLI/fallback/reporting.

Responsibility: expose the command entrypoint and compatibility imports.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import sys
from types import ModuleType

from .architecture_runtime_guard import (
    DecompilerArchitectureGuardError,
    assert_decompiler_architecture_clean,
)

try:
    assert_decompiler_architecture_clean()
except DecompilerArchitectureGuardError as ex:
    print(str(ex), file=sys.stderr)
    raise SystemExit(3) from ex

import angr
from angr.analyses.decompiler import structured_codegen
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CVariable
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.semantics.alias_query import describe_alias_storage
from angr_platforms.X86_16.widening.register_widening import (
    can_join_adjacent_register_slices,
    join_adjacent_register_slices,
)
from angr_platforms.X86_16.widening_model import analyze_adjacent_storage_slices

from . import cache as _cache
from . import cli_access_profiles as _cli_access_profiles
from . import cli_c_ast_rewrites as _cli_c_ast_rewrites
from . import cli_c_text_postprocess as _cli_c_text_postprocess
from . import cli_core as _cli_core
from . import cli_decompilation as _cli_decompilation
from . import cli_fallback_decompilation as _cli_fallback_decompilation
from . import cli_function_discovery as _cli_function_discovery
from . import cli_interrupt_modeling as _cli_interrupt_modeling
from . import non_optimized_fallback as _non_optimized_fallback
from . import project_loading as _project_loading
from . import runtime_support as _runtime_support
from . import sidecar_metadata as _sidecar_metadata
from . import sidecar_parsers as _sidecar_parsers
from . import tail_validation as _tail_validation
from . import work_items as _work_items
from .cli_c_ast_rewrites import (
    _addr_exprs_are_byte_pair,
    _c_constant_value,
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _classify_segmented_addr_expr,
    _coalesce_cod_word_global_loads,
    _coalesce_direct_ss_local_word_statements,
    _coalesce_far_pointer_stack_expressions,
    _coalesce_linear_recurrence_statements,
    _coalesce_segmented_word_load_expressions,
    _coalesce_segmented_word_store_statements,
    _get_or_seed_inertia_alias_state,
    _make_word_dereference_from_addr_expr,
    _match_byte_load_addr_expr,
    _match_byte_store_addr_expr,
    _match_duplicate_word_increment_shift_expr,
    _match_shift_right_8_expr,
    _match_shifted_high_byte_addr_expr,
    _match_ss_local_plus_const,
    _match_word_rhs_from_byte_pair,
    _materialize_missing_stack_local_declarations,
    _resolve_stack_cvar_from_addr_expr,
    _rewrite_ss_stack_byte_offsets,
    _same_c_expression,
    _seed_adjacent_byte_pair_aliases,
    _stack_slot_identity_can_join,
    _unwrap_c_casts,
)
from .cli_c_text_postprocess import _simplify_x86_16_conditions, _simplify_x86_16_stack_byte_pointers
from .cli_core import main
from .disassembly_helpers import _infer_linear_disassembly_window, _linear_disassembly

_PROXY_MODULES = (
    _cli_core,
    _cli_access_profiles,
    _cli_c_ast_rewrites,
    _cli_decompilation,
    _cli_fallback_decompilation,
    _cli_function_discovery,
    _cli_interrupt_modeling,
    _non_optimized_fallback,
    _project_loading,
    _runtime_support,
    _sidecar_parsers,
    _sidecar_metadata,
    _tail_validation,
    _work_items,
    _cache,
)

structured_c: object = structured_codegen.c
_AccessTraitEvidenceProfile = _cli_access_profiles.AccessTraitEvidenceProfile
_AccessTraitStrideEvidence = _cli_access_profiles.AccessTraitStrideEvidence


def _probe_lift_break(project: angr.Project, addr: int, *, max_window: int = 0x80) -> str:
    start, end = _infer_linear_disassembly_window(project, addr, max_window=max_window)
    try:
        insns = _linear_disassembly(project, start, end)
    except Exception as ex:
        return f"<lift probe unavailable: {ex}>"
    if not insns:
        return "<lift probe unavailable: no instructions>"
    for index, insn in enumerate(insns):
        try:
            project.factory.block(insn.address, size=max(1, insn.size), opt_level=0)
        except Exception as ex:
            window = insns[max(0, index - 3) : min(len(insns), index + 5)]
            lines = [f"{cur.address:#06x}: {cur.mnemonic} {cur.op_str}".rstrip() for cur in window]
            return f"first lift failure at {insn.address:#x}: {_project_loading._describe_exception(ex)}\n" + "\n".join(
                lines
            )
    return "no per-instruction lift failure detected in linear probe window"


def _match_adjacent_register_pair_var_expr(low_expr: object, high_expr: object, codegen: object) -> object | None:
    # Compatibility surface for legacy tests and callers importing from decompile/cli.
    def _impl() -> object | None:
        current_low_expr = low_expr
        current_high_expr = high_expr
        if isinstance(current_high_expr, CBinaryOp) and current_high_expr.op in {"Mul", "Shl"}:
            for maybe_inner, maybe_scale in (
                (current_high_expr.lhs, current_high_expr.rhs),
                (current_high_expr.rhs, current_high_expr.lhs),
            ):
                scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
                if scale not in {8, 0x100}:
                    continue
                current_high_expr = _unwrap_c_casts(maybe_inner)
                break
        if not isinstance(current_low_expr, CVariable) or not isinstance(current_high_expr, CVariable):
            return None
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        low_var = getattr(current_low_expr, "variable", None)
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        high_var = getattr(current_high_expr, "variable", None)
        if not isinstance(low_var, SimRegisterVariable) or not isinstance(high_var, SimRegisterVariable):
            return None
        # Dynamic codegen boundary: SimRegisterVariable slice size comes from angr variable metadata.
        if getattr(low_var, "size", None) != 1 or getattr(high_var, "size", None) != 1:
            return None
        alias_state = _get_or_seed_inertia_alias_state(codegen)
        if alias_state is None:
            return None
        analysis = analyze_adjacent_storage_slices(current_low_expr, current_high_expr, alias_state=alias_state)
        if not analysis.ok:
            return None
        # Dynamic codegen boundary: widening proof shape comes from X86_16 analysis helpers.
        proof = getattr(analysis, "proof", None)
        if proof is None:
            return None
        # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
        if getattr(proof, "register_pair", None) is None:
            return None
        # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
        if getattr(proof, "left_version", None) is None or getattr(proof, "right_version", None) is None:
            return None
        # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
        if getattr(proof, "left_version", None) != getattr(proof, "right_version", None):
            return None
        if not can_join_adjacent_register_slices(
            current_low_expr, current_high_expr, alias_state=alias_state, proof=proof
        ):
            return None
        return join_adjacent_register_slices(
            current_low_expr, current_high_expr, codegen, alias_state=alias_state, proof=proof
        )

    return _impl()


class _CompatModule(ModuleType):
    def __getattr__(self, name: str) -> object:
        for module in _PROXY_MODULES:
            if hasattr(module, name):
                # Dynamic compatibility boundary: cli.py proxies legacy imports across split CLI modules.
                return getattr(module, name)
        raise AttributeError(name)

    def __setattr__(self, name: str, value: object) -> None:
        ModuleType.__setattr__(self, name, value)
        for module in _PROXY_MODULES:
            if module is _sidecar_metadata and name == "_recovery_code_labels":
                continue
            if hasattr(module, name):
                # Dynamic compatibility boundary: cli.py mirrors monkeypatched legacy attributes.
                setattr(module, name, value)
        if hasattr(_cli_c_ast_rewrites, name):
            # Dynamic compatibility boundary: cli.py mirrors monkeypatched legacy attributes.
            setattr(_cli_c_ast_rewrites, name, value)
        if hasattr(_cli_c_text_postprocess, name):
            # Dynamic compatibility boundary: cli.py mirrors monkeypatched legacy attributes.
            setattr(_cli_c_text_postprocess, name, value)

    def __dir__(self) -> list[str]:
        names = set(ModuleType.__dir__(self))
        for module in _PROXY_MODULES:
            names.update(dir(module))
        return sorted(names)


_THIS_MODULE = sys.modules[__name__]
_THIS_MODULE.__class__ = _CompatModule


__all__ = [
    "main",
    "_rewrite_ss_stack_byte_offsets",
    "_canonicalize_stack_cvars",
    "_match_adjacent_register_pair_var_expr",
    "_classify_segmented_addr_expr",
    "_addr_exprs_are_byte_pair",
    "_match_ss_local_plus_const",
    "_stack_slot_identity_can_join",
    "_match_byte_store_addr_expr",
    "_match_word_rhs_from_byte_pair",
    "_make_word_dereference_from_addr_expr",
    "_match_byte_load_addr_expr",
    "_match_shifted_high_byte_addr_expr",
    "_match_shift_right_8_expr",
    "_match_duplicate_word_increment_shift_expr",
    "_resolve_stack_cvar_from_addr_expr",
    "_coalesce_segmented_word_store_statements",
    "_coalesce_segmented_word_load_expressions",
    "_coalesce_direct_ss_local_word_statements",
    "_coalesce_far_pointer_stack_expressions",
    "_canonicalize_stack_cvar_expr",
    "_coalesce_cod_word_global_loads",
    "_seed_adjacent_byte_pair_aliases",
    "_coalesce_linear_recurrence_statements",
    "_same_c_expression",
    "_simplify_x86_16_stack_byte_pointers",
    "_simplify_x86_16_conditions",
    "_linear_disassembly",
    "_probe_lift_break",
    "_materialize_missing_stack_local_declarations",
    "describe_alias_storage",
    "analyze_adjacent_storage_slices",
    "join_adjacent_register_slices",
    "can_join_adjacent_register_slices",
    "structured_c",
    "SimTypePointer",
    "SimTypeShort",
    "SimMemoryVariable",
    "SimRegisterVariable",
    "SimStackVariable",
    "_AccessTraitEvidenceProfile",
    "_AccessTraitStrideEvidence",
]

if __name__ == "__main__":
    raise SystemExit(main())
