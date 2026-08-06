"""Compatibility exports for the CLI-owned generated-C unit assembler.

Layer: Tooling/gates.
Responsibility: keep existing gate imports stable while the implementation and
declaration policy remain owned by ``inertia_decompiler`` CLI/export assembly.
"""

from __future__ import annotations

from inertia_decompiler.generated_translation_unit_assembly import (
    DeclarationContractConflict,
    DeclarationContractKind,
    GeneratedTranslationUnit,
    assemble_generated_translation_unit,
)

__all__ = [
    "DeclarationContractConflict",
    "DeclarationContractKind",
    "GeneratedTranslationUnit",
    "assemble_generated_translation_unit",
]
