"""Record reviewed owner layers for tests that hide imports dynamically.

Layer: Tooling/gates.
Responsibility: preserve explicit test-module ownership decisions that cannot
be derived from normal Python imports or the changed-file ownership manifest.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final


@dataclass(frozen=True, slots=True)
class RetiredTestContract:
    """Document one removed redundant test and the contracts that supersede it."""

    reason: str
    replacements: tuple[str, ...]


REVIEWED_TEST_MODULE_LAYERS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "angr_platforms/tests/test_agent_test_focus.py": ("tooling/gates",),
        "angr_platforms/tests/test_omf_pat_far_transfer_variants.py": ("compiler-flags",),
        "angr_platforms/tests/test_omf_pat_fixup_widths.py": ("compiler-flags",),
        "angr_platforms/tests/test_omf_pat_lidata.py": ("compiler-flags",),
        "angr_platforms/tests/test_omf_pat_x87_emulator_variants.py": ("compiler-flags",),
        "angr_platforms/tests/test_omf_pat_zero_displacement.py": ("compiler-flags",),
        "angr_platforms/tests/test_parallel_job_defaults.py": ("tooling/gates",),
        "angr_platforms/tests/test_report_compiler_matches_flags.py": ("compiler-flags",),
        "angr_platforms/tests/test_x86_16_access_trait_arrays.py": ("X86_16/lowering", "inertia_decompiler/cli"),
        "angr_platforms/tests/test_x86_16_access_trait_policy.py": ("X86_16/lowering", "inertia_decompiler/cli"),
        "angr_platforms/tests/test_x86_16_access_trait_strides.py": ("X86_16/lowering", "inertia_decompiler/cli"),
        "angr_platforms/tests/test_x86_16_boolean_simplify.py": ("X86_16/postprocess", "inertia_decompiler/cli"),
        "angr_platforms/tests/test_x86_16_helper_replacements.py": ("X86_16/postprocess", "inertia_decompiler/cli"),
        "angr_platforms/tests/test_x86_16_mypy_monkeytype_targets.py": ("tooling/gates",),
        "angr_platforms/tests/test_x86_16_msc6_regressions.py": ("inertia_decompiler/cli",),
        "angr_platforms/tests/test_x86_16_msc6_sort_patterns_regression.py": ("inertia_decompiler/cli",),
        "angr_platforms/tests/test_x86_16_segment_association.py": ("X86_16/lowering", "inertia_decompiler/cli"),
        "angr_platforms/tests/test_x86_16_string_corpus_anchors.py": ("inertia_decompiler/cli",),
        "angr_platforms/tests/test_x86_16_structuring_cyclic.py": ("X86_16/structuring",),
        "angr_platforms/tests/test_x86_16_structuring_stage_environment.py": ("X86_16/structuring",),
    }
)

RETIRED_TEST_CONTRACTS: Final[Mapping[str, RetiredTestContract]] = MappingProxyType(
    {
        "angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_small_cod_logic_batch"
        "[path12-_TIDShowRange-NEAR-10-30-expected_tokens12-forbidden_tokens12]": RetiredTestContract(
            reason="duplicate command whose timeout branch bypassed all nominal output assertions",
            replacements=(
                "angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_tidshowrange_layout_logic",
            ),
        ),
        "angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_small_cod_logic_batch"
        "[path13-_DrawRadarAlt-NEAR-10-30-expected_tokens13-forbidden_tokens13]": RetiredTestContract(
            reason="duplicate command with output assertions strictly weaker than its dedicated regression",
            replacements=(
                "angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_drawradaralt_branch_logic",
            ),
        ),
        "angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_regression_targets_are_recoverable"
        "[OVERLAY.COD-_overlay_load-20]": RetiredTestContract(
            reason="duplicate command with status and output assertions covered by the overlay sample regression",
            replacements=(
                "angr_platforms/tests/test_x86_16_cod_samples.py::"
                "test_overlay_cod_sample_wrapper_returns_overlay_segment",
            ),
        ),
        "angr_platforms/tests/test_x86_16_cod_regressions.py::"
        "test_cod_overlay_load_preserves_guarded_free_memory_probe_before_final_return": RetiredTestContract(
            reason="duplicate command whose successful-path assertions are a strict subset of the overlay sample regression",
            replacements=(
                "angr_platforms/tests/test_x86_16_cod_samples.py::"
                "test_overlay_cod_sample_wrapper_returns_overlay_segment",
            ),
        ),
        "angr_platforms/tests/test_x86_16_structuring_cyclic.py::"
        "TestLoopExitClassification::test_simple_while_loop_classification": RetiredTestContract(
            reason="pass-only placeholder superseded by executable natural-loop classification",
            replacements=(
                "angr_platforms/tests/test_x86_16_structuring_cyclic.py::"
                "TestNaturalLoopDetection::test_simple_single_back_edge_loop",
            ),
        ),
        "angr_platforms/tests/test_x86_16_structuring_cyclic.py::"
        "TestLoopExitClassification::test_loop_with_break_classification": RetiredTestContract(
            reason="pass-only placeholder superseded by typed loop-break materialization",
            replacements=(
                "angr_platforms/tests/test_x86_16_structuring_loop_break_jcc.py::"
                "test_structuring_unconsumed_loop_break_jcc_inserts_guard_before_taken_body",
            ),
        ),
    }
)
