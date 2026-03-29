from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationLayerSpec:
    name: str
    purpose: str
    default_checks: tuple[str, ...]


@dataclass(frozen=True)
class ValidationFamilySpec:
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


VALIDATION_FAMILIES = (
    ValidationFamilySpec(
        name="addressing",
        purpose="Keep effective-address, far-pointer, and width-matrix behavior explicit.",
        default_checks=(
            "tests/test_x86_16_addressing_helpers.py",
            "tests/test_x86_16_decode_metadata.py",
            "tests/test_x86_16_instruction_core_factoring.py",
        ),
    ),
    ValidationFamilySpec(
        name="stack_control",
        purpose="Keep call/ret/enter/leave, privilege stack, and branch helpers stable.",
        default_checks=(
            "tests/test_x86_16_stack_helpers.py",
            "tests/test_x86_16_instruction_core_factoring.py",
        ),
    ),
    ValidationFamilySpec(
        name="string",
        purpose="Keep REP, direction-flag, and compare/store string behavior stable.",
        default_checks=(
            "tests/test_x86_16_string_helpers.py",
            "tests/test_x86_16_compare_semantics.py",
        ),
    ),
    ValidationFamilySpec(
        name="alu",
        purpose="Keep flag-update and arithmetic/shift/rotate behavior stable.",
        default_checks=(
            "tests/test_x86_16_alu_helpers.py",
            "tests/test_x86_16_compare_semantics.py",
        ),
    ),
    ValidationFamilySpec(
        name="interrupt_api",
        purpose="Keep interrupt-core semantics and DOS/BIOS/API lowering separable.",
        default_checks=(
            "tests/test_x86_16_milestone_report.py",
            "tests/test_x86_16_corpus_scan.py",
        ),
    ),
)


def describe_x86_16_validation_layers() -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((layer.name, layer.default_checks) for layer in VALIDATION_LAYERS)


def describe_x86_16_validation_families() -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((family.name, family.default_checks) for family in VALIDATION_FAMILIES)


__all__ = [
    "VALIDATION_FAMILIES",
    "VALIDATION_LAYERS",
    "ValidationFamilySpec",
    "ValidationLayerSpec",
    "describe_x86_16_validation_families",
    "describe_x86_16_validation_layers",
]
