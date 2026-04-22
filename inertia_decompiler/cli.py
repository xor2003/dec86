from __future__ import annotations

import sys
from types import ModuleType

from angr.analyses.decompiler import structured_codegen
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.semantics.alias_query import describe_alias_storage
from angr_platforms.X86_16.widening_alias import (
    can_join_adjacent_register_slices,
    join_adjacent_register_slices,
)
from angr_platforms.X86_16.widening_model import analyze_adjacent_storage_slices

from .cli_core import main
from .cli_c_ast_rewrites import (
    _addr_exprs_are_byte_pair,
    _c_constant_value,
    _classify_segmented_addr_expr,
    _coalesce_cod_word_global_loads,
    _coalesce_direct_ss_local_word_statements,
    _coalesce_far_pointer_stack_expressions,
    _coalesce_linear_recurrence_statements,
    _coalesce_segmented_word_load_expressions,
    _coalesce_segmented_word_store_statements,
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _get_or_seed_inertia_alias_state,
    _make_word_dereference_from_addr_expr,
    _materialize_missing_stack_local_declarations,
    _match_byte_load_addr_expr,
    _match_byte_store_addr_expr,
    _match_shift_right_8_expr,
    _match_shifted_high_byte_addr_expr,
    _match_ss_local_plus_const,
    _match_duplicate_word_increment_shift_expr,
    _match_word_rhs_from_byte_pair,
    _rewrite_ss_stack_byte_offsets,
    _same_c_expression,
    _resolve_stack_cvar_from_addr_expr,
    _seed_adjacent_byte_pair_aliases,
    _stack_slot_identity_can_join,
    _unwrap_c_casts,
)
from .cli_c_text_postprocess import _simplify_x86_16_stack_byte_pointers
from . import cli_c_ast_rewrites as _cli_c_ast_rewrites
from . import cli_c_text_postprocess as _cli_c_text_postprocess

structured_c = structured_codegen.c


def _match_adjacent_register_pair_var_expr(low_expr, high_expr, codegen):
    # Compatibility surface for legacy tests and callers importing from decompile/cli.
    if isinstance(high_expr, structured_c.CBinaryOp) and high_expr.op in {"Mul", "Shl"}:
        for maybe_inner, maybe_scale in ((high_expr.lhs, high_expr.rhs), (high_expr.rhs, high_expr.lhs)):
            scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
            if scale not in {8, 0x100}:
                continue
            high_expr = _unwrap_c_casts(maybe_inner)
            break
    if not isinstance(low_expr, structured_c.CVariable) or not isinstance(high_expr, structured_c.CVariable):
        return None
    low_var = getattr(low_expr, "variable", None)
    high_var = getattr(high_expr, "variable", None)
    if not isinstance(low_var, SimRegisterVariable) or not isinstance(high_var, SimRegisterVariable):
        return None
    if getattr(low_var, "size", None) != 1 or getattr(high_var, "size", None) != 1:
        return None
    alias_state = _get_or_seed_inertia_alias_state(codegen)
    if alias_state is None:
        return None
    analysis = analyze_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not analysis.ok:
        return None
    proof = getattr(analysis, "proof", None)
    if proof is None:
        return None
    if getattr(proof, "register_pair", None) is None:
        return None
    if getattr(proof, "left_version", None) is None or getattr(proof, "right_version", None) is None:
        return None
    if getattr(proof, "left_version", None) != getattr(proof, "right_version", None):
        return None
    if not can_join_adjacent_register_slices(low_expr, high_expr, alias_state=alias_state, proof=proof):
        return None
    return join_adjacent_register_slices(low_expr, high_expr, codegen, alias_state=alias_state, proof=proof)


class _CompatModule(ModuleType):
    def __setattr__(self, name: str, value):
        ModuleType.__setattr__(self, name, value)
        if hasattr(_cli_c_ast_rewrites, name):
            setattr(_cli_c_ast_rewrites, name, value)
        if hasattr(_cli_c_text_postprocess, name):
            setattr(_cli_c_text_postprocess, name, value)


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
    "_materialize_missing_stack_local_declarations",
    "describe_alias_storage",
    "analyze_adjacent_storage_slices",
    "join_adjacent_register_slices",
    "can_join_adjacent_register_slices",
    "structured_c",
    "SimTypeShort",
    "SimMemoryVariable",
    "SimRegisterVariable",
    "SimStackVariable",
]

if __name__ == "__main__":
    raise SystemExit(main())
