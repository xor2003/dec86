#!/usr/bin/env python3
"""Dump optional CodeView/Turbo Debug metadata for diagnostics.

Layer: Tooling/gates.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "angr_platforms"))
logging.getLogger("angr.state_plugins.unicorn_engine").disabled = True

from angr_platforms.X86_16.codeview_nb00 import CodeViewNB00Info, parse_codeview_nb00  # noqa: E402
from angr_platforms.X86_16.codeview_nb02_nb04 import (  # noqa: E402
    CodeViewNB0204Info,
    CodeViewSymbol,
    parse_codeview_nb0204,
)
from angr_platforms.X86_16.turbo_debug_tdinfo import TDInfoEXEInfo, TDInfoSymbolClass, parse_tdinfo_exe  # noqa: E402


def _parse_int(value: str) -> int:
    return int(value, 0)


def _hex_keyed(mapping: dict[int, Any]) -> dict[str, Any]:
    return {f"0x{addr:x}": value for addr, value in sorted(mapping.items())}


def _symbol(symbol: CodeViewSymbol) -> dict[str, Any]:
    return {
        "type_code": f"0x{int(symbol.type_code):04x}",
        "name": symbol.name,
        "offset": symbol.offset,
        "segment": symbol.segment,
        "length": symbol.length,
        "data_type": symbol.data_type,
        "extra": symbol.extra,
    }


def _type_member(member: Any) -> dict[str, Any]:  # noqa: ANN401
    return {
        "name": member.name,
        "offset": member.offset,
        "owner_type_index": getattr(member, "owner_type_index", None),
        "leaf_index": getattr(member, "leaf_index", None),
        "type_index": getattr(member, "type_index", None),
        "source": getattr(member, "source", None),
    }


def _nb00(info: CodeViewNB00Info | None) -> dict[str, Any] | None:
    if info is None:
        return None
    return {
        "version": info.version,
        "debug_base": f"0x{info.debug_base:x}",
        "subsection_directory_offset": f"0x{info.subsection_directory_offset:x}",
        "modules": [
            {
                "module_index": module.module_index,
                "cs_base": module.cs_base,
                "cs_offset": module.cs_offset,
                "cs_length": module.cs_length,
                "overlay_number": module.overlay_number,
                "library_index": module.library_index,
                "segment_count": module.segment_count,
                "name": module.name,
            }
            for module in info.modules
        ],
        "publics": [
            {
                "module_index": public.module_index,
                "offset": public.offset,
                "segment": public.segment,
                "type_index": public.type_index,
                "name": public.name,
            }
            for public in info.publics
        ],
        "type_definitions": [
            {
                "index": definition.index,
                "linkage": definition.linkage,
                "leaves": [{"kind": leaf.kind, "value": leaf.value} for leaf in definition.leaves],
            }
            for definition in info.type_definitions
        ],
        "type_record_names": list(info.type_record_names),
        "type_members": [_type_member(member) for member in info.type_members],
        "source_files": list(info.source_files),
        "debug_identifiers": list(info.debug_identifiers),
        "line_map": _hex_keyed({addr: [line, col] for addr, (line, col) in info.line_map.items()}),
        "code_labels": _hex_keyed(info.code_labels),
        "data_labels": _hex_keyed(info.data_labels),
        "code_ranges": _hex_keyed({start: [span[0], span[1]] for start, span in info.code_ranges.items()}),
    }


def _nb0204(info: CodeViewNB0204Info | None) -> dict[str, Any] | None:
    if info is None:
        return None
    return {
        "version": info.version,
        "debug_base": f"0x{info.debug_base:x}",
        "modules": list(info.modules),
        "source_files": list(info.source_files),
        "type_record_names": list(info.type_record_names),
        "type_members": [_type_member(member) for member in info.type_members],
        "debug_identifiers": list(info.debug_identifiers),
        "code_labels": _hex_keyed(info.code_labels),
        "data_labels": _hex_keyed(info.data_labels),
        "procedures": [_symbol(symbol) for symbol in info.procedures],
        "stack_variables": {
            name: [_symbol(symbol) for symbol in symbols] for name, symbols in sorted(info.stack_variables.items())
        },
        "line_map": _hex_keyed({addr: [line, col] for addr, (line, col) in info.line_map.items()}),
    }


def _td_symbol_class(symbol_class: TDInfoSymbolClass) -> str:
    return f"{symbol_class.name}({int(symbol_class)})"


def _tdinfo(info: TDInfoEXEInfo | None) -> dict[str, Any] | None:
    if info is None:
        return None

    def record(record_obj) -> dict[str, Any]:  # noqa: ANN001
        return {
            "index": record_obj.index,
            "type_index": record_obj.type_index,
            "offset": record_obj.offset,
            "signed_offset": record_obj.signed_offset,
            "segment": record_obj.segment,
            "symbol_class": _td_symbol_class(record_obj.symbol_class),
        }

    def named(named_obj) -> dict[str, Any]:  # noqa: ANN001
        return {"name": named_obj.name, "record": record(named_obj.record)}

    return {
        "debug_info_offset": f"0x{info.debug_info_offset:x}",
        "header": {
            "major_version": info.header.major_version,
            "minor_version": info.header.minor_version,
            "names_pool_size_in_bytes": info.header.names_pool_size_in_bytes,
            "names_count": info.header.names_count,
            "types_count": info.header.types_count,
            "members_count": info.header.members_count,
            "symbols_count": info.header.symbols_count,
            "globals_count": info.header.globals_count,
            "extension_size": info.header.extension_size,
        },
        "tds_version": info.tds_version_str,
        "tlink_version": info.tlink_version_str,
        "products": info.products,
        "commandline_hint": info.commandline_hint,
        "names": list(info.names),
        "name_pool_entries": [
            {"index": entry.index, "name": entry.name, "kind": entry.kind.name} for entry in info.name_pool_entries
        ],
        "source_files": list(info.source_files),
        "candidate_identifiers": list(info.candidate_identifiers),
        "public_symbols": list(info.public_symbols),
        "local_identifiers": list(info.local_identifiers),
        "type_names": list(info.type_names),
        "type_descriptors": [
            {
                "type_index": descriptor.type_index,
                "kind": descriptor.kind.name,
                "name": descriptor.name,
                "size": descriptor.size,
                "payload_offset": f"0x{descriptor.payload_offset:x}",
                "base_type_index": descriptor.base_type_index,
                "target_type_index": descriptor.target_type_index,
                "return_type_index": descriptor.return_type_index,
                "call_kind": descriptor.call_kind,
                "attributes": descriptor.attributes,
                "lower_bound": descriptor.lower_bound,
                "upper_bound": descriptor.upper_bound,
                "raw_bytes": descriptor.raw_bytes.hex(),
            }
            for descriptor in info.type_descriptors
        ],
        "type_references": [
            {
                "name": ref.name,
                "type_index": ref.type_index,
                "symbol_class": _td_symbol_class(ref.symbol_class),
            }
            for ref in info.type_references
        ],
        "type_members": [
            {
                "name": member.name,
                "offset": member.offset,
                "owner_type_index": member.owner_type_index,
                "type_index": member.type_index,
                "attributes": member.attributes,
                "payload_offset": f"0x{member.payload_offset:x}",
            }
            for member in info.type_members
        ],
        "enum_members": [
            {
                "name": member.name,
                "value": member.value,
                "owner_type_index": member.owner_type_index,
                "attributes": member.attributes,
                "payload_offset": f"0x{member.payload_offset:x}",
            }
            for member in info.enum_members
        ],
        "raw_table_spans": [
            {
                "name": span.name,
                "offset": f"0x{span.offset:x}",
                "size": span.size,
                "count": span.count,
                "record_size": span.record_size,
            }
            for span in info.raw_table_spans
        ],
        "symbols": [record(symbol) for symbol in info.symbols],
        "named_symbols": [named(symbol) for symbol in info.named_symbols],
        "names_by_class": {_td_symbol_class(klass): list(names) for klass, names in info.names_by_class.items()},
        "symbols_by_class": {
            _td_symbol_class(klass): [record(symbol) for symbol in symbols]
            for klass, symbols in info.symbols_by_class.items()
        },
        "stack_variables": [named(symbol) for symbol in info.stack_variables],
        "register_symbols": [named(symbol) for symbol in info.register_symbols],
        "constant_symbols": [named(symbol) for symbol in info.constant_symbols],
        "code_labels": _hex_keyed(info.code_labels),
        "data_labels": _hex_keyed(info.data_labels),
    }


def dump_debug_info(path: Path, *, load_base_linear: int) -> dict[str, Any]:  # noqa: D103
    return {
        "binary": str(path),
        "load_base_linear": f"0x{load_base_linear:x}",
        "codeview_nb00": _nb00(parse_codeview_nb00(path, load_base_linear=load_base_linear)),
        "codeview_nb0204": _nb0204(parse_codeview_nb0204(path, load_base_linear=load_base_linear)),
        "tdinfo": _tdinfo(parse_tdinfo_exe(path, load_base_linear=load_base_linear)),
    }


def main(argv: list[str] | None = None) -> int:  # noqa: D103
    parser = argparse.ArgumentParser(description="Dump all supported DOS debug information from an executable.")
    parser.add_argument("binary", type=Path)
    parser.add_argument("--load-base-linear", type=_parse_int, default=0, help="linear load base, e.g. 0x10000")
    parser.add_argument("--compact", action="store_true", help="emit single-line JSON")
    args = parser.parse_args(argv)

    payload = dump_debug_info(args.binary, load_base_linear=args.load_base_linear)
    indent = None if args.compact else 2
    print(json.dumps(payload, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
