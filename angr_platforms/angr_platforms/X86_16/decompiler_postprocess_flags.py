"""Compatibility shim for moved flag cleanup.

Layer: Compatibility shim.
Responsibility: preserve legacy flag-cleanup imports while the canonical
postprocess implementation owns behavior and exports.

The implementation lives in ``X86_16.postprocess.flags_cleanup``. This root
module exists only for legacy imports while callers migrate.

Ownership rule:
- Do not add behavior here. New flag cleanup belongs in
  ``postprocess/flags_cleanup`` or earlier pipeline layers.
- This shim should only forward the canonical implementation for compatibility.
- Once all direct imports are migrated off this shim, remove it and update import
  shims accordingly.

Do not add behavior here. New flag cleanup belongs in the real postprocess
package module, and new flag semantics belong earlier in IR/semantics/condition
transfer rather than in any rewrite shim.
"""

from __future__ import annotations

from .postprocess.flags_cleanup import (
    _bool_cite_values_8616,
    _c_expr_uses_register_8616,
    _c_expr_uses_var_8616,
    _extract_bool_compare_term_8616,
    _extract_flag_predicate_from_expr_8616,
    _extract_flag_test_info_8616,
    _fix_impossible_interval_guard_expr_8616,
    _fix_interval_guard_conditions_8616,
    _invert_cmp_op_8616,
    _make_bool_cite_8616,
    _make_bool_expr_from_compare_8616,
    _prune_overwritten_flag_assignments_8616,
    _prune_unused_flag_assignments_8616,
    _recover_ordering_condition_from_flag_mask_8616,
    _recover_signed_condition_8616,
    _recover_unsigned_condition_8616,
    _rewrite_flag_bit_value_uses_8616,
    _rewrite_flag_condition_expr_8616,
    _rewrite_flag_condition_pairs_8616,
    _split_ordering_if_chain_replacement_condition_8616,
    _stmt_reads_reg_before_write_8616,
)

__all__ = (
    "_bool_cite_values_8616",
    "_c_expr_uses_register_8616",
    "_c_expr_uses_var_8616",
    "_extract_bool_compare_term_8616",
    "_extract_flag_predicate_from_expr_8616",
    "_extract_flag_test_info_8616",
    "_fix_impossible_interval_guard_expr_8616",
    "_fix_interval_guard_conditions_8616",
    "_invert_cmp_op_8616",
    "_make_bool_cite_8616",
    "_make_bool_expr_from_compare_8616",
    "_prune_overwritten_flag_assignments_8616",
    "_prune_unused_flag_assignments_8616",
    "_recover_ordering_condition_from_flag_mask_8616",
    "_recover_signed_condition_8616",
    "_recover_unsigned_condition_8616",
    "_rewrite_flag_bit_value_uses_8616",
    "_rewrite_flag_condition_expr_8616",
    "_rewrite_flag_condition_pairs_8616",
    "_split_ordering_if_chain_replacement_condition_8616",
    "_stmt_reads_reg_before_write_8616",
)
