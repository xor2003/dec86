from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationLayerSpec:
    name: str
    purpose: str
    default_checks: tuple[str, ...]


VALIDATION_LAYERS = (
    ValidationLayerSpec(
        name="unit",
        purpose="Keep alias, widening, and low-level recovery helpers individually safe.",
        default_checks=(
            "tests/test_x86_16_alias_register_mvp.py",
            "tests/test_x86_16_storage_domain_alias.py",
            "tests/test_x86_16_widening_model.py",
            "tests/test_x86_16_word_global_helpers.py",
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_readability_set.py",
            "tests/test_x86_16_validation_manifest.py",
        ),
    ),
    ValidationLayerSpec(
        name="focused_corpus",
        purpose="Keep sample-backed and semantic regressions green on real bounded inputs.",
        default_checks=(
            "tests/test_x86_16_smoketest.py",
            "tests/test_x86_16_compare_semantics.py",
            "tests/test_x86_16_corpus_scan.py",
            "tests/test_x86_16_sample_matrix.py",
        ),
    ),
    ValidationLayerSpec(
        name="whole_program",
        purpose="Keep the bounded scan-safe lane and sample-matrix whole-program probes stable.",
        default_checks=(
            "scripts/scan_cod_dir.py --mode scan-safe",
            "tests/test_x86_16_runtime_samples.py",
            "tests/test_x86_16_sample_matrix.py",
        ),
    ),
)


def describe_x86_16_validation_layers() -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((layer.name, layer.default_checks) for layer in VALIDATION_LAYERS)


__all__ = ["VALIDATION_LAYERS", "ValidationLayerSpec", "describe_x86_16_validation_layers"]
