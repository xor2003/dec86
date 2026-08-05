from __future__ import annotations

from scripts.generated_translation_unit_assembly import (
    DeclarationContractKind,
    assemble_generated_translation_unit,
)


def test_assembler_deduplicates_types_and_uses_internal_definition_contract() -> None:
    first = """
typedef struct Row { unsigned short value; } Row;
int second(unsigned short value);
void first(void) { second(1); }
"""
    second = """
typedef struct Row { unsigned short value; } Row;
void second(unsigned short value) { (void)value; }
"""

    result = assemble_generated_translation_unit((first, second))

    assert result.source.count("typedef struct Row") == 1
    assert result.source.count("void second(unsigned short value)") == 2
    assert "int second(" not in result.source
    assert result.conflicts == ()


def test_assembler_retains_and_reports_conflicting_global_contracts() -> None:
    first = "extern unsigned short shared[1];\nvoid first(void) {}\n"
    second = "extern unsigned char shared[1];\nvoid second(void) {}\n"

    result = assemble_generated_translation_unit((first, second))

    assert len(result.conflicts) == 1
    assert result.conflicts[0].kind is DeclarationContractKind.GLOBAL
    assert result.conflicts[0].name == "shared"
    assert "extern unsigned short shared[1];" in result.source
    assert "extern unsigned char shared[1];" in result.source


def test_assembler_joins_wide_external_return_and_discards_weaker_declaration() -> None:
    first = "int helper();\nvoid first(void) { helper(1, 2); }\n"
    second = "unsigned short helper(unsigned short a, unsigned short b);\nvoid second(void) {}\n"
    third = "unsigned long helper(unsigned short a, unsigned short b);\nvoid third(void) {}\n"

    result = assemble_generated_translation_unit((first, second, third))

    assert result.source.count("unsigned long helper(unsigned short a, unsigned short b)") == 1
    assert "int helper()" not in result.source
    assert "unsigned short helper(" not in result.source
    assert result.conflicts == ()


def test_assembler_joins_compatible_external_parameter_array_bounds() -> None:
    first = "int output();\nvoid first(void) {}\n"
    second = "int output(char text[80], unsigned short segment);\nvoid second(void) {}\n"
    third = "int output(char text[44], unsigned short segment);\nvoid third(void) {}\n"

    result = assemble_generated_translation_unit((first, second, third))

    assert result.source.count("int output(char text[80], unsigned short segment)") == 1
    assert "text[44]" not in result.source
    assert "int output()" not in result.source
    assert result.conflicts == ()


def test_assembler_refuses_incompatible_external_parameter_contracts() -> None:
    first = "int helper(unsigned short value);\nvoid first(void) {}\n"
    second = "int helper(char *value);\nvoid second(void) {}\n"

    result = assemble_generated_translation_unit((first, second))

    assert len(result.conflicts) == 1
    assert result.conflicts[0].kind is DeclarationContractKind.EXTERNAL_FUNCTION
    assert result.conflicts[0].name == "helper"
    assert result.source.count("helper(") == 2
