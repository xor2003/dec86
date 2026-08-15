"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.

Export subresponsibility: canonicalize top-level declarations, join
ABI-compatible external prototypes, and use generated definitions as internal
contracts without changing any function-body AST.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from enum import StrEnum
from typing import Sequence

from pycparser import c_ast, c_generator, c_parser

_PARSE_PREFIX = (
    "typedef _Bool bool;\n"
    "typedef signed char int8_t;\n"
    "typedef unsigned char uint8_t;\n"
    "typedef signed short int16_t;\n"
    "typedef unsigned short uint16_t;\n"
    "typedef signed long int32_t;\n"
    "typedef unsigned long uint32_t;\n"
    "typedef long clock_t;\n"
    "typedef long time_t;\n"
)
_PARSE_PREFIX_NODE_COUNT = 9


class DeclarationContractKind(StrEnum):
    """Typed top-level declaration families used by export assembly."""

    TYPE = "type"
    GLOBAL = "global"
    EXTERNAL_FUNCTION = "external-function"


@dataclass(frozen=True, slots=True)
class DeclarationContractConflict:
    """One named declaration for which generated payloads disagree."""

    kind: DeclarationContractKind
    name: str
    variants: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GeneratedTranslationUnit:
    """Canonical syntax plus declarations that require an owning-layer fix."""

    source: str
    function_count: int
    conflicts: tuple[DeclarationContractConflict, ...]


@dataclass(slots=True)
class _NamedDeclarationSet:
    """Mutable first-seen declaration state used only during assembly."""

    kind: DeclarationContractKind
    name: str
    nodes: list[c_ast.Node]
    variants: list[str]


_TypeContract = tuple[object, ...]


def _identifier_tokens(node: c_ast.Node) -> tuple[str, ...] | None:
    """Return identifier-type tokens beneath one declarator node."""
    current = node
    while isinstance(current, (c_ast.Decl, c_ast.Typename, c_ast.TypeDecl)):
        current = current.type
    if not isinstance(current, c_ast.IdentifierType):
        return None
    return tuple(current.names)


def _type_contract(node: c_ast.Node, *, parameter: bool = False) -> _TypeContract | None:
    """Return a structural type contract with parameter arrays decayed to pointers."""
    if isinstance(node, (c_ast.Decl, c_ast.Typename)):
        return _type_contract(node.type, parameter=parameter)
    if isinstance(node, c_ast.TypeDecl):
        nested = _type_contract(node.type, parameter=parameter)
        return None if nested is None else ("type", tuple(node.quals or ()), nested)
    if isinstance(node, c_ast.IdentifierType):
        return "identifier", tuple(node.names)
    if isinstance(node, c_ast.PtrDecl):
        nested = _type_contract(node.type)
        return None if nested is None else ("pointer", tuple(node.quals or ()), nested)
    if isinstance(node, c_ast.ArrayDecl):
        nested = _type_contract(node.type)
        if nested is None:
            return None
        if parameter:
            return "pointer", (), nested
        return "array", nested
    if isinstance(node, c_ast.Struct):
        return "struct", node.name
    if isinstance(node, c_ast.Union):
        return "union", node.name
    if isinstance(node, c_ast.Enum):
        return "enum", node.name
    return None


def _parameter_contracts(function_type: c_ast.FuncDecl) -> tuple[_TypeContract, ...] | None:
    """Return normalized prototype parameters, or None for K&R declarations."""
    if function_type.args is None:
        return None
    parameters = tuple(function_type.args.params or ())
    if len(parameters) == 1 and _identifier_tokens(parameters[0]) == ("void",):
        return ()
    contracts: list[_TypeContract] = []
    for parameter in parameters:
        if isinstance(parameter, c_ast.EllipsisParam):
            contracts.append(("ellipsis",))
            continue
        contract = _type_contract(parameter, parameter=True)
        if contract is None:
            return None
        contracts.append(contract)
    return tuple(contracts)


def _integer_return_contract(node: c_ast.Node) -> tuple[int, bool] | None:
    """Return target x86-16 integer width and unsignedness for one return type."""
    tokens = _identifier_tokens(node)
    if tokens is None:
        return None
    token_set = frozenset(tokens)
    if token_set in {
        frozenset({"int8_t"}),
        frozenset({"char"}),
        frozenset({"signed", "char"}),
    }:
        return 8, False
    if token_set in {frozenset({"uint8_t"}), frozenset({"unsigned", "char"})}:
        return 8, True
    if token_set in {
        frozenset({"int16_t"}),
        frozenset({"short"}),
        frozenset({"signed", "short"}),
        frozenset({"int"}),
        frozenset({"signed", "int"}),
    }:
        return 16, False
    if token_set in {
        frozenset({"uint16_t"}),
        frozenset({"unsigned", "short"}),
        frozenset({"unsigned", "int"}),
    }:
        return 16, True
    if token_set in {
        frozenset({"int32_t"}),
        frozenset({"long"}),
        frozenset({"signed", "long"}),
    }:
        return 32, False
    if token_set in {frozenset({"uint32_t"}), frozenset({"unsigned", "long"})}:
        return 32, True
    return None


def _canonical_external_function_decl(nodes: Sequence[c_ast.Node]) -> c_ast.Decl | None:
    """Join compatible typed external declarations without consulting C bodies."""
    declarations = tuple(
        node
        for node in nodes
        if isinstance(node, c_ast.Decl) and isinstance(node.type, c_ast.FuncDecl)
    )
    if len(declarations) != len(nodes):
        return None
    typed = tuple(
        (declaration, _parameter_contracts(declaration.type))
        for declaration in declarations
        if declaration.type.args is not None
    )
    if not typed:
        return None
    parameter_contracts = {contracts for _declaration, contracts in typed}
    if None in parameter_contracts or len(parameter_contracts) != 1:
        return None

    exact_returns = tuple(_type_contract(declaration.type.type) for declaration, _contracts in typed)
    if len(set(exact_returns)) == 1:
        return typed[0][0]
    integer_returns = tuple(
        (declaration, _integer_return_contract(declaration.type.type))
        for declaration, _contracts in typed
    )
    if any(contract is None for _declaration, contract in integer_returns):
        return None
    widest_bits = max(contract[0] for _declaration, contract in integer_returns if contract is not None)
    widest = tuple(
        (declaration, contract)
        for declaration, contract in integer_returns
        if contract is not None and contract[0] == widest_bits
    )
    if len({contract[1] for _declaration, contract in widest}) != 1:
        return None
    return widest[0][0]


def _preprocess_payload(payload: str, *, compiler: str) -> str:
    """Use the C preprocessor to remove comments before structured parsing."""
    completed = subprocess.run(
        [compiler, "-E", "-P", "-x", "c", "-"],
        input=f"{_PARSE_PREFIX}{payload}",
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"generated C preprocessing failed: {completed.stderr.strip()}")
    return completed.stdout


def _parse_payload(payload: str, *, compiler: str) -> tuple[c_ast.Node, ...]:
    """Parse one independently validated C payload into top-level syntax nodes."""
    preprocessed = _preprocess_payload(payload, compiler=compiler)
    try:
        parsed = c_parser.CParser().parse(preprocessed)
    except c_parser.ParseError as ex:
        raise ValueError(f"generated C parser rejected validated payload: {ex}") from ex
    return tuple(parsed.ext[_PARSE_PREFIX_NODE_COUNT:])


def _declaration_identity(
    node: c_ast.Node,
    generator: c_generator.CGenerator,
) -> tuple[str, str] | None:
    """Return a stable syntax identity for one non-definition declaration."""
    rendered = generator.visit(node)
    if isinstance(node, c_ast.Typedef):
        return node.name, rendered
    if isinstance(node, c_ast.Decl):
        if node.name is not None:
            return node.name, rendered
        if isinstance(node.type, (c_ast.Struct, c_ast.Union, c_ast.Enum)) and node.type.name is not None:
            return node.type.name, rendered
        return rendered, rendered
    return None


def _declaration_kind(node: c_ast.Node) -> DeclarationContractKind:
    """Classify a parsed top-level declaration without semantic inference."""
    if isinstance(node, c_ast.Typedef) or (
        isinstance(node, c_ast.Decl)
        and isinstance(node.type, (c_ast.Struct, c_ast.Union, c_ast.Enum))
    ):
        return DeclarationContractKind.TYPE
    if isinstance(node, c_ast.Decl) and isinstance(node.type, c_ast.FuncDecl):
        return DeclarationContractKind.EXTERNAL_FUNCTION
    return DeclarationContractKind.GLOBAL


def _is_redundant_aggregate_forward_decl(node: c_ast.Node) -> bool:
    """Return whether a node is only ``struct/union/enum Name;``."""
    return (
        isinstance(node, c_ast.Decl)
        and node.name is None
        and isinstance(node.type, (c_ast.Struct, c_ast.Union, c_ast.Enum))
        and (
            node.type.values is None
            if isinstance(node.type, c_ast.Enum)
            else node.type.decls is None
        )
    )


def assemble_generated_translation_unit(
    payloads: Sequence[str],
    *,
    compiler: str = "gcc",
) -> GeneratedTranslationUnit:
    """Build one declaration table and preserve every parsed function-body AST."""
    parsed_payloads = tuple(_parse_payload(payload, compiler=compiler) for payload in payloads)
    definitions = tuple(
        node
        for payload_nodes in parsed_payloads
        for node in payload_nodes
        if isinstance(node, c_ast.FuncDef)
    )
    definition_names = {definition.decl.name for definition in definitions}
    if len(definition_names) != len(definitions):
        raise ValueError("generated C contains duplicate function definitions")

    generator = c_generator.CGenerator()
    declaration_order: list[_NamedDeclarationSet] = []
    declarations_by_key: dict[tuple[DeclarationContractKind, str], _NamedDeclarationSet] = {}
    for payload_nodes in parsed_payloads:
        for node in payload_nodes:
            if isinstance(node, c_ast.FuncDef):
                continue
            if isinstance(node, c_ast.Decl) and isinstance(node.type, c_ast.FuncDecl):
                if node.name in definition_names:
                    continue
            identity = _declaration_identity(node, generator)
            if identity is None:
                raise ValueError(f"unsupported generated top-level node: {type(node).__name__}")
            name, rendered = identity
            kind = _declaration_kind(node)
            key = kind, name
            declaration_set = declarations_by_key.get(key)
            if declaration_set is None:
                declaration_set = _NamedDeclarationSet(kind=kind, name=name, nodes=[], variants=[])
                declarations_by_key[key] = declaration_set
                declaration_order.append(declaration_set)
            if rendered not in declaration_set.variants:
                declaration_set.nodes.append(node)
                declaration_set.variants.append(rendered)

    for declaration_set in declaration_order:
        if declaration_set.kind is DeclarationContractKind.TYPE:
            type_definitions = tuple(
                node
                for node in declaration_set.nodes
                if not _is_redundant_aggregate_forward_decl(node)
            )
            if len(type_definitions) == 1 and all(
                node is type_definitions[0] or _is_redundant_aggregate_forward_decl(node)
                for node in declaration_set.nodes
            ):
                declaration_set.nodes = [type_definitions[0]]
                declaration_set.variants = [generator.visit(type_definitions[0])]
            continue
        if declaration_set.kind is not DeclarationContractKind.EXTERNAL_FUNCTION:
            continue
        canonical = _canonical_external_function_decl(declaration_set.nodes)
        if canonical is None:
            continue
        declaration_set.nodes = [canonical]
        declaration_set.variants = [generator.visit(canonical)]

    conflicts = tuple(
        DeclarationContractConflict(item.kind, item.name, tuple(item.variants))
        for item in declaration_order
        if len(item.variants) > 1
    )
    declaration_nodes = [
        node
        for kind in (
            DeclarationContractKind.TYPE,
            DeclarationContractKind.GLOBAL,
            DeclarationContractKind.EXTERNAL_FUNCTION,
        )
        for item in declaration_order
        if item.kind is kind
        for node in item.nodes
    ]
    internal_prototypes = [definition.decl for definition in definitions]
    merged = c_ast.FileAST([*declaration_nodes, *internal_prototypes, *definitions])
    return GeneratedTranslationUnit(
        source=generator.visit(merged).rstrip() + "\n",
        function_count=len(definitions),
        conflicts=conflicts,
    )


__all__ = [
    "DeclarationContractConflict",
    "DeclarationContractKind",
    "GeneratedTranslationUnit",
    "assemble_generated_translation_unit",
]
