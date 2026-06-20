from __future__ import annotations

from pathlib import Path

import angr
from angr_platforms.X86_16.codeview_nb00 import parse_codeview_nb00
from angr_platforms.X86_16.codeview_nb02_nb04 import parse_codeview_nb0204
from angr_platforms.X86_16.lst_extract import (
    DebugEnumMemberEvidence,
    DebugSymbolEvidence,
    DebugTypeDescriptorEvidence,
    DebugTypeMemberEvidence,
    DebugTypeReferenceEvidence,
    LSTMetadata,
    extract_lst_metadata,
)
from angr_platforms.X86_16.turbo_debug_tdinfo import parse_tdinfo_exe

from inertia_decompiler.project_loading import _probe_ida_base_linear
from inertia_decompiler.sidecar_cache import (
    _attach_debug_evidence_attrs,
    apply_cached_sidecar_metadata,
    emit_sidecar_metadata_debug,
    load_cached_sidecar_metadata,
    store_cached_sidecar_metadata,
)
from inertia_decompiler.sidecar_parsers import (
    _detect_flair_metadata,
    _parse_cod_sidecar_metadata,
    _parse_ida_lst_proc_metadata,
    _parse_ida_map_metadata,
    _parse_idc_metadata,
    _parse_inc_struct_names,
    _parse_mzre_map_metadata,
    _parse_ne_exe_metadata,
    _reconcile_cod_listing_with_codeview,
    _synthesize_code_ranges,
)
from inertia_decompiler.telemetry import trace_function


def _find_sibling_sidecar(binary: Path, suffix: str) -> Path | None:
    direct = binary.with_suffix(suffix)
    if direct.exists():
        return direct
    try:
        siblings = sorted(binary.parent.iterdir(), key=lambda path: path.name.lower())
    except OSError:
        return None
    wanted_stem = binary.stem.lower()
    wanted_suffix = suffix.lower()
    for sibling in siblings:
        if sibling.stem.lower() == wanted_stem and sibling.suffix.lower() == wanted_suffix:
            return sibling
    return None


def _signature_matched_code_addrs(metadata: LSTMetadata | None) -> frozenset[int]:
    if metadata is None:
        return frozenset()
    addrs = getattr(metadata, "signature_code_addrs", frozenset())
    return addrs if isinstance(addrs, frozenset) else frozenset(addrs)


def _visible_code_labels(metadata: LSTMetadata | None) -> dict[int, str]:
    if metadata is None:
        return {}
    code_labels = getattr(metadata, "code_labels", None)
    if not isinstance(code_labels, dict):
        return {}
    skipped = _signature_matched_code_addrs(metadata)
    if not skipped:
        return dict(code_labels)
    cod_proc_addrs = set((getattr(metadata, "cod_proc_kinds", None) or {}).keys())
    return {addr: name for addr, name in code_labels.items() if addr not in skipped or addr in cod_proc_addrs}


def _recovery_code_labels(metadata: LSTMetadata | None) -> dict[int, str]:
    if metadata is None:
        return {}
    labels = _visible_code_labels(metadata)
    signature_addrs = _signature_matched_code_addrs(metadata)
    if not signature_addrs:
        return labels
    code_labels = getattr(metadata, "code_labels", None)
    if not isinstance(code_labels, dict):
        return labels
    for addr in sorted(signature_addrs):
        if addr in labels:
            continue
        if _lst_code_region(metadata, addr) is None:
            continue
        name = code_labels.get(addr)
        if name is not None:
            labels[addr] = name
    return labels


def _load_ida_map_sidecar(
    binary: Path,
    *,
    load_base_linear: int,
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    source_formats: list[str],
) -> dict[str, int]:
    map_path = _find_sibling_sidecar(binary, ".map")
    segment_offsets: dict[str, int] = {}
    if map_path is None:
        return segment_offsets
    try:
        ida_code, ida_data, segment_offsets = _parse_ida_map_metadata(map_path, load_base_linear=load_base_linear)
        if ida_code or ida_data or segment_offsets:
            code_labels.update(ida_code)
            data_labels.update(ida_data)
            source_formats.append("ida_map")
    except Exception as exc:
        print(f"[dbg] failed to parse IDA map {map_path}: {exc}")
    return segment_offsets


def _load_lst_sidecar(
    binary: Path,
    *,
    load_base_linear: int,
    segment_offsets: dict[str, int],
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    code_ranges: dict[int, tuple[int, int]],
    source_formats: list[str],
) -> None:
    def _impl():
        lst_path = _find_sibling_sidecar(binary, ".lst")
        if lst_path is None:
            return
        try:
            metadata = extract_lst_metadata(lst_path)
            if metadata.code_labels or metadata.data_labels:
                if metadata.absolute_addrs:
                    code_labels.update(metadata.code_labels)
                    data_labels.update(metadata.data_labels)
                    code_ranges.update(metadata.code_ranges)
                else:
                    for offset, name in metadata.data_labels.items():
                        data_labels.setdefault(load_base_linear + offset, name)
                    for offset, name in metadata.code_labels.items():
                        code_labels.setdefault(load_base_linear + offset, name)
                    for offset, span in metadata.code_ranges.items():
                        code_ranges.setdefault(
                            load_base_linear + offset, (load_base_linear + span[0], load_base_linear + span[1])
                        )
                source_formats.append(metadata.source_format)
        except Exception as exc:
            print(f"[dbg] failed to parse source listing {lst_path}: {exc}")
        try:
            ida_proc_labels = _parse_ida_lst_proc_metadata(
                lst_path,
                load_base_linear=load_base_linear,
                segment_offsets=segment_offsets,
            )
            if ida_proc_labels:
                code_labels.update(ida_proc_labels)
                source_formats.append("ida_lst")
        except Exception as exc:
            print(f"[dbg] failed to parse IDA proc listing {lst_path}: {exc}")

    return _impl()


def _load_idc_inc_sidecars(
    binary: Path,
    *,
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    struct_names: list[str],
    source_formats: list[str],
) -> None:
    idc_path = _find_sibling_sidecar(binary, ".idc")
    if idc_path is not None:
        try:
            idc_code, idc_data = _parse_idc_metadata(idc_path)
            if idc_code or idc_data:
                code_labels.update(idc_code)
                data_labels.update(idc_data)
                source_formats.append("ida_idc")
        except Exception as exc:
            print(f"[dbg] failed to parse IDC file {idc_path}: {exc}")
    inc_path = _find_sibling_sidecar(binary, ".inc")
    if inc_path is not None:
        try:
            struct_names.extend(_parse_inc_struct_names(inc_path))
            source_formats.append("ida_inc")
        except Exception as exc:
            print(f"[dbg] failed to parse INC file {inc_path}: {exc}")


def _load_codeview_or_ne_metadata(
    binary: Path,
    project: angr.Project,
    *,
    load_base_linear: int,
) -> tuple[
    dict[int, str],
    dict[int, str],
    dict[int, tuple[int, int]],
    str | None,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[DebugSymbolEvidence, ...],
    tuple[DebugTypeMemberEvidence, ...],
    dict[int, tuple[int, int]],
]:
    def _impl():
        codeview_code: dict[int, str] = {}
        codeview_data: dict[int, str] = {}
        codeview_ranges: dict[int, tuple[int, int]] = {}
        codeview_format: str | None = None
        debug_source_files: tuple[str, ...] = ()
        debug_type_names: tuple[str, ...] = ()
        debug_symbols: tuple[DebugSymbolEvidence, ...] = ()
        debug_type_members: tuple[DebugTypeMemberEvidence, ...] = ()
        debug_identifiers: tuple[str, ...] = ()
        debug_line_map: dict[int, tuple[int, int]] = {}
        try:
            parsed_nb00 = parse_codeview_nb00(binary, load_base_linear=load_base_linear)
            if parsed_nb00 is not None:
                codeview_format = "codeview_nb00"
                codeview_code = dict(parsed_nb00.code_labels)
                codeview_data = dict(parsed_nb00.data_labels)
                codeview_ranges = dict(parsed_nb00.code_ranges)
                debug_source_files = parsed_nb00.source_files
                debug_type_names = parsed_nb00.type_record_names
                debug_symbols = _nb00_publics_to_symbol_evidence(
                    parsed_nb00.publics,
                    load_base_linear=load_base_linear,
                    source="codeview_nb00",
                )
                debug_type_members = _codeview_type_members_to_evidence(
                    parsed_nb00.type_members,
                    source="codeview_nb00",
                )
                debug_identifiers = parsed_nb00.debug_identifiers
                debug_line_map = dict(parsed_nb00.line_map)
        except Exception as exc:
            print(f"[dbg] failed to parse CodeView NB00 metadata from {binary}: {exc}")
        if codeview_format is None:
            try:
                parsed_nb0204 = parse_codeview_nb0204(binary, load_base_linear=load_base_linear)
                if parsed_nb0204 is not None:
                    codeview_format = "codeview_nb0204"
                    codeview_code = dict(parsed_nb0204.code_labels)
                    codeview_data = dict(parsed_nb0204.data_labels)
                    codeview_ranges = _nb0204_procedure_ranges(
                        parsed_nb0204.procedures,
                        load_base_linear=load_base_linear,
                    )
                    debug_source_files = parsed_nb0204.source_files
                    debug_type_names = parsed_nb0204.type_record_names
                    debug_symbols = _nb0204_symbols_to_evidence(
                        parsed_nb0204.procedures,
                        parsed_nb0204.stack_variables,
                        load_base_linear=load_base_linear,
                        source="codeview_nb0204",
                    )
                    debug_type_members = _codeview_type_members_to_evidence(
                        parsed_nb0204.type_members,
                        source="codeview_nb0204",
                    )
                    debug_identifiers = parsed_nb0204.debug_identifiers
                    debug_line_map = dict(parsed_nb0204.line_map)
            except Exception as exc:
                print(f"[dbg] failed to parse CodeView NB02/NB04 metadata from {binary}: {exc}")
        if codeview_format is None:
            try:
                ne_code, ne_data, ne_ranges = _parse_ne_exe_metadata(
                    binary, load_base_linear=load_base_linear, project=project
                )
                if ne_code or ne_data or ne_ranges:
                    codeview_code, codeview_data, codeview_ranges = ne_code, ne_data, ne_ranges
                    codeview_format = "ne_exe"
            except Exception as exc:
                print(f"[dbg] failed to parse NE format metadata from {binary}: {exc}")
        return (
            codeview_code,
            codeview_data,
            codeview_ranges,
            codeview_format,
            debug_source_files,
            debug_type_names,
            debug_symbols,
            debug_type_members,
            debug_identifiers,
            debug_line_map,
        )

    return _impl()


def _load_tdinfo_sidecar(
    binary: Path,
    *,
    load_base_linear: int,
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    debug_source_files: list[str],
    debug_type_names: list[str],
    debug_type_descriptors: list[DebugTypeDescriptorEvidence],
    debug_type_references: list[DebugTypeReferenceEvidence],
    debug_symbols: list[DebugSymbolEvidence],
    debug_type_members: list[DebugTypeMemberEvidence],
    debug_enum_members: list[DebugEnumMemberEvidence],
    debug_identifiers: list[str],
    source_formats: list[str],
) -> None:
    try:
        tdinfo = parse_tdinfo_exe(binary, load_base_linear=load_base_linear)
    except Exception as exc:
        print(f"[dbg] failed to parse Turbo Debug TDInfo metadata from {binary}: {exc}")
        return
    if tdinfo is None:
        return
    if not (
        tdinfo.code_labels
        or tdinfo.data_labels
        or tdinfo.source_files
        or tdinfo.type_names
        or tdinfo.type_descriptors
        or tdinfo.type_references
        or tdinfo.type_members
        or tdinfo.enum_members
        or tdinfo.named_symbols
        or tdinfo.names_by_class
        or tdinfo.symbols_by_class
        or tdinfo.stack_variables
        or tdinfo.register_symbols
        or tdinfo.constant_symbols
        or tdinfo.candidate_identifiers
    ):
        return
    for addr, name in tdinfo.code_labels.items():
        code_labels.setdefault(addr, name)
    for addr, name in tdinfo.data_labels.items():
        data_labels.setdefault(addr, name)
    debug_source_files.extend(tdinfo.source_files)
    debug_type_names.extend(tdinfo.type_names)
    for descriptor in tdinfo.type_descriptors:
        debug_type_descriptors.append(
            DebugTypeDescriptorEvidence(
                type_index=descriptor.type_index,
                kind=descriptor.kind.name,
                name=descriptor.name,
                size=descriptor.size,
                base_type_index=descriptor.base_type_index,
                target_type_index=descriptor.target_type_index,
                return_type_index=descriptor.return_type_index,
                call_kind=descriptor.call_kind,
                attributes=descriptor.attributes,
                lower_bound=descriptor.lower_bound,
                upper_bound=descriptor.upper_bound,
                source="turbo_debug_tdinfo",
            )
        )
    for ref in tdinfo.type_references:
        debug_type_references.append(
            DebugTypeReferenceEvidence(
                name=ref.name,
                type_index=ref.type_index,
                symbol_class=ref.symbol_class.name,
                source="turbo_debug_tdinfo",
            )
        )
    debug_symbols.extend(
        _tdinfo_symbols_to_evidence(
            tdinfo.named_symbols,
            load_base_linear=load_base_linear,
            source="turbo_debug_tdinfo",
        )
    )
    for member in tdinfo.type_members:
        debug_type_members.append(
            DebugTypeMemberEvidence(
                name=member.name,
                offset=member.offset,
                owner_type_index=member.owner_type_index,
                type_index=member.type_index,
                attributes=member.attributes,
                source="turbo_debug_tdinfo",
            )
        )
    for member in tdinfo.enum_members:
        debug_enum_members.append(
            DebugEnumMemberEvidence(
                name=member.name,
                value=member.value,
                owner_type_index=member.owner_type_index,
                attributes=member.attributes,
                source="turbo_debug_tdinfo",
            )
        )
    debug_identifiers.extend(tdinfo.candidate_identifiers)
    source_formats.append("turbo_debug_tdinfo")


def _codeview_type_members_to_evidence(
    members: tuple[object, ...],
    *,
    source: str,
) -> tuple[DebugTypeMemberEvidence, ...]:
    evidence: list[DebugTypeMemberEvidence] = []
    for member in members:
        name = str(getattr(member, "name", "")).strip()
        if not name:
            continue
        offset = getattr(member, "offset", None)
        owner_type_index = getattr(member, "owner_type_index", None)
        type_index = getattr(member, "type_index", None)
        leaf_index = getattr(member, "leaf_index", None)
        evidence.append(
            DebugTypeMemberEvidence(
                name=name,
                offset=int(offset) if offset is not None else None,
                owner_type_index=int(owner_type_index) if owner_type_index is not None else None,
                type_index=int(type_index) if type_index is not None else None,
                leaf_index=int(leaf_index) if leaf_index is not None else None,
                source=source,
            )
        )
    return tuple(evidence)


def _attrs_from_mapping(mapping: dict[object, object]) -> tuple[tuple[str, str], ...]:
    return tuple((str(key), str(value)) for key, value in sorted(mapping.items(), key=lambda item: str(item[0])))


def _nb00_publics_to_symbol_evidence(
    publics: tuple[object, ...],
    *,
    load_base_linear: int,
    source: str,
) -> tuple[DebugSymbolEvidence, ...]:
    evidence: list[DebugSymbolEvidence] = []
    for public in publics:
        name = str(getattr(public, "name", "")).strip()
        if not name:
            continue
        offset = getattr(public, "offset", None)
        segment = getattr(public, "segment", None)
        type_index = getattr(public, "type_index", None)
        evidence.append(
            DebugSymbolEvidence(
                name=name,
                symbol_class="PUBLIC",
                storage="public",
                offset=int(offset) if offset is not None else None,
                segment=int(segment) if segment is not None else None,
                linear_addr=public.linear_addr(load_base_linear=load_base_linear),
                type_index=int(type_index) if type_index is not None else None,
                source=source,
            )
        )
    return tuple(evidence)


def _nb0204_symbols_to_evidence(
    procedures: tuple[object, ...],
    stack_variables: dict[str, list[object]],
    *,
    load_base_linear: int,
    source: str,
) -> tuple[DebugSymbolEvidence, ...]:
    evidence: list[DebugSymbolEvidence] = []
    for symbol in procedures:
        name = str(getattr(symbol, "name", "")).strip()
        if not name:
            continue
        segment = getattr(symbol, "segment", None)
        offset = getattr(symbol, "offset", None)
        type_index = getattr(symbol, "data_type", None)
        evidence.append(
            DebugSymbolEvidence(
                name=name,
                symbol_class=f"0x{int(getattr(symbol, 'type_code', 0)):04x}",
                storage="procedure",
                offset=int(offset) if offset is not None else None,
                segment=int(segment) if segment is not None else None,
                linear_addr=load_base_linear + (int(segment) << 4) + int(offset)
                if segment is not None and offset is not None
                else None,
                length=int(symbol.length) if getattr(symbol, "length", None) is not None else None,
                type_index=int(type_index) if type_index is not None else None,
                attributes=_attrs_from_mapping(getattr(symbol, "extra", {}) or {}),
                source=source,
            )
        )
    for owner_name, symbols in stack_variables.items():
        for symbol in symbols:
            name = str(getattr(symbol, "name", "")).strip()
            if not name:
                continue
            offset = getattr(symbol, "offset", None)
            type_index = getattr(symbol, "data_type", None)
            evidence.append(
                DebugSymbolEvidence(
                    name=name,
                    symbol_class=f"0x{int(getattr(symbol, 'type_code', 0)):04x}",
                    storage="stack",
                    offset=int(offset) if offset is not None else None,
                    signed_offset=int(offset) if offset is not None else None,
                    type_index=int(type_index) if type_index is not None else None,
                    owner_name=str(owner_name),
                    attributes=_attrs_from_mapping(getattr(symbol, "extra", {}) or {}),
                    source=source,
                )
            )
    return tuple(evidence)


def _nb0204_procedure_ranges(
    procedures: tuple[object, ...],
    *,
    load_base_linear: int,
) -> dict[int, tuple[int, int]]:
    ranges: dict[int, tuple[int, int]] = {}
    for symbol in procedures:
        segment = getattr(symbol, "segment", None)
        offset = getattr(symbol, "offset", None)
        length = getattr(symbol, "length", None)
        if segment is None or offset is None or length is None:
            continue
        start = load_base_linear + (int(segment) << 4) + int(offset)
        end = start + int(length)
        if end > start:
            ranges.setdefault(start, (start, end))
    return ranges


def _tdinfo_symbols_to_evidence(
    named_symbols: tuple[object, ...],
    *,
    load_base_linear: int,
    source: str,
) -> tuple[DebugSymbolEvidence, ...]:
    evidence: list[DebugSymbolEvidence] = []
    for named in named_symbols:
        name = str(getattr(named, "name", "")).strip()
        record = getattr(named, "record", None)
        if not name or record is None:
            continue
        symbol_class = getattr(record, "symbol_class", None)
        symbol_class_name = getattr(symbol_class, "name", str(symbol_class))
        evidence.append(
            DebugSymbolEvidence(
                name=name,
                symbol_class=symbol_class_name,
                storage=str(symbol_class_name).lower(),
                offset=int(record.offset),
                signed_offset=int(record.signed_offset),
                segment=int(record.segment),
                linear_addr=record.linear_addr(load_base_linear=load_base_linear),
                type_index=int(record.type_index),
                attributes=(("record_index", str(record.index)),),
                source=source,
            )
        )
    return tuple(evidence)


def _load_cod_mzre_flair_sidecars(
    binary: Path,
    project: angr.Project,
    *,
    load_base_linear: int,
    code_labels: dict[int, str],
    data_labels: dict[int, str],
    code_ranges: dict[int, tuple[int, int]],
    source_formats: list[str],
    codeview_code: dict[int, str],
    codeview_ranges: dict[int, tuple[int, int]],
    pat_backend: str | None,
    signature_catalog: Path | None,
    cod_proc_kinds: dict[int, str],
) -> tuple[Path | None, set[int]]:
    def _impl():
        cod_path: Path | None = None
        signature_code_addrs: set[int] = set()
        sibling_cod_path = _find_sibling_sidecar(binary, ".cod")
        if sibling_cod_path is not None:
            try:
                cod_anchor_labels = dict(code_labels)
                cod_anchor_labels.update(codeview_code)
                cod_listing = _parse_cod_sidecar_metadata(
                    sibling_cod_path,
                    load_base_linear=load_base_linear,
                    existing_code_labels=cod_anchor_labels,
                    project=project,
                )
                cod_listing = _reconcile_cod_listing_with_codeview(cod_listing, codeview_code, codeview_ranges)
                if cod_listing.code_labels or cod_listing.code_ranges or cod_listing.proc_kinds:
                    existing_by_name: dict[str, list[int]] = {}
                    for existing_addr, existing_name in code_labels.items():
                        existing_by_name.setdefault(existing_name.lstrip("_"), []).append(existing_addr)
                    for addr, name in cod_listing.code_labels.items():
                        normalized = name.lstrip("_")
                        span = cod_listing.code_ranges.get(addr)
                        matching_entries = [
                            existing_addr
                            for existing_addr in existing_by_name.get(normalized, ())
                            if existing_addr <= addr
                        ]
                        precise_entries = [
                            existing_addr
                            for existing_addr in matching_entries
                            if existing_addr in code_ranges or existing_addr in codeview_code
                        ]
                        if precise_entries and span is not None:
                            public_start = max(precise_entries)
                            existing_span = code_ranges.get(public_start)
                            public_span = (public_start, span[1])
                            if existing_span is None or existing_span[1] < public_span[1]:
                                code_ranges[public_start] = public_span
                            proc_kind = cod_listing.proc_kinds.get(addr)
                            if proc_kind is not None:
                                cod_proc_kinds.setdefault(public_start, proc_kind)
                            continue
                        if matching_entries:
                            public_start = max(matching_entries)
                            if span is not None and public_start not in code_ranges:
                                public_span = (public_start, int(span[1]))
                                if public_span[1] > public_span[0]:
                                    code_ranges.setdefault(public_start, public_span)
                            proc_kind = cod_listing.proc_kinds.get(addr)
                            if proc_kind is not None:
                                cod_proc_kinds.setdefault(public_start, proc_kind)
                            continue
                        code_labels.setdefault(addr, name)
                        if span is not None:
                            code_ranges.setdefault(addr, span)
                        proc_kind = cod_listing.proc_kinds.get(addr)
                        if proc_kind is not None:
                            cod_proc_kinds.setdefault(addr, proc_kind)
                    cod_path = sibling_cod_path
                    source_formats.append("cod_listing")
            except Exception as exc:
                print(f"[dbg] failed to parse COD listing {sibling_cod_path}: {exc}")
        external_mzre_map = Path("/home/xor/games/f15se2-re/map") / f"{binary.stem}.map"
        if external_mzre_map.exists():
            try:
                mzre_code, mzre_data, mzre_ranges = _parse_mzre_map_metadata(
                    external_mzre_map, load_base_linear=load_base_linear
                )
                if mzre_code or mzre_data or mzre_ranges:
                    for addr, name in mzre_code.items():
                        code_labels.setdefault(addr, name)
                    for addr, name in mzre_data.items():
                        data_labels.setdefault(addr, name)
                    for addr, span in mzre_ranges.items():
                        code_ranges.setdefault(addr, span)
                    source_formats.append("mzre_map")
            except Exception as exc:
                print(f"[dbg] failed to parse mzretools map {external_mzre_map}: {exc}")
        try:
            flair_code, flair_ranges, flair_formats = _detect_flair_metadata(
                binary,
                project,
                pat_backend=pat_backend,
                signature_catalog=signature_catalog,
            )
            if flair_code or flair_ranges:
                for addr, name in flair_code.items():
                    code_labels.setdefault(addr, name)
                    signature_code_addrs.add(addr)
                for addr, span in flair_ranges.items():
                    code_ranges.setdefault(addr, span)
            source_formats.extend(flair_formats)
        except Exception as exc:
            print(f"[dbg] failed to inspect FLAIR metadata for {binary}: {exc}")
        return cod_path, signature_code_addrs

    return _impl()


@trace_function(name="sidecar.load_metadata")
def _load_lst_metadata(
    binary: Path,
    project: angr.Project,
    *,
    pat_backend: str | None = None,
    signature_catalog: Path | None = None,
) -> LSTMetadata | None:
    def _impl():
        cached_sidecar, sidecar_cache_key = load_cached_sidecar_metadata(
            binary_path=binary,
            pat_backend=pat_backend,
            signature_catalog=signature_catalog,
        )
        if cached_sidecar is not None:
            metadata = apply_cached_sidecar_metadata(project, cached_sidecar)
            emit_sidecar_metadata_debug(project, metadata)
            return metadata
        load_base_linear = _probe_ida_base_linear(binary, getattr(project.loader.main_object, "linked_base", 0))
        code_labels: dict[int, str] = {}
        data_labels: dict[int, str] = {}
        code_ranges: dict[int, tuple[int, int]] = {}
        signature_code_addrs: set[int] = set()
        cod_proc_kinds: dict[int, str] = {}
        struct_names: list[str] = []
        debug_source_files: list[str] = []
        debug_type_names: list[str] = []
        debug_type_descriptors: list[DebugTypeDescriptorEvidence] = []
        debug_type_references: list[DebugTypeReferenceEvidence] = []
        debug_symbols: list[DebugSymbolEvidence] = []
        debug_type_members: list[DebugTypeMemberEvidence] = []
        debug_enum_members: list[DebugEnumMemberEvidence] = []
        debug_identifiers: list[str] = []
        debug_line_map: dict[int, tuple[int, int]] = {}
        source_formats: list[str] = []
        cod_path: Path | None = None
        segment_offsets = _load_ida_map_sidecar(
            binary,
            load_base_linear=load_base_linear,
            code_labels=code_labels,
            data_labels=data_labels,
            source_formats=source_formats,
        )
        _load_lst_sidecar(
            binary,
            load_base_linear=load_base_linear,
            segment_offsets=segment_offsets,
            code_labels=code_labels,
            data_labels=data_labels,
            code_ranges=code_ranges,
            source_formats=source_formats,
        )
        _load_idc_inc_sidecars(
            binary,
            code_labels=code_labels,
            data_labels=data_labels,
            struct_names=struct_names,
            source_formats=source_formats,
        )
        (
            codeview_code,
            codeview_data,
            codeview_ranges,
            codeview_format,
            codeview_source_files,
            codeview_type_names,
            codeview_symbols,
            codeview_type_members,
            codeview_identifiers,
            codeview_line_map,
        ) = _load_codeview_or_ne_metadata(
            binary,
            project,
            load_base_linear=load_base_linear,
        )
        debug_source_files.extend(codeview_source_files)
        debug_type_names.extend(codeview_type_names)
        debug_symbols.extend(codeview_symbols)
        debug_type_members.extend(codeview_type_members)
        debug_identifiers.extend(codeview_identifiers)
        debug_line_map.update(codeview_line_map)

        if codeview_code or codeview_data or codeview_ranges:
            code_labels.update(codeview_code)
            data_labels.update(codeview_data)
            code_ranges.update(codeview_ranges)
            source_formats.append(codeview_format or "codeview_unknown")
        _load_tdinfo_sidecar(
            binary,
            load_base_linear=load_base_linear,
            code_labels=code_labels,
            data_labels=data_labels,
            debug_source_files=debug_source_files,
            debug_type_names=debug_type_names,
            debug_type_descriptors=debug_type_descriptors,
            debug_type_references=debug_type_references,
            debug_symbols=debug_symbols,
            debug_type_members=debug_type_members,
            debug_enum_members=debug_enum_members,
            debug_identifiers=debug_identifiers,
            source_formats=source_formats,
        )
        cod_path, signature_code_addrs = _load_cod_mzre_flair_sidecars(
            binary,
            project,
            load_base_linear=load_base_linear,
            code_labels=code_labels,
            data_labels=data_labels,
            code_ranges=code_ranges,
            source_formats=source_formats,
            codeview_code=codeview_code,
            codeview_ranges=codeview_ranges,
            pat_backend=pat_backend,
            signature_catalog=signature_catalog,
            cod_proc_kinds=cod_proc_kinds,
        )

        if (
            not code_labels
            and not data_labels
            and not struct_names
            and not debug_source_files
            and not debug_type_names
            and not debug_type_descriptors
            and not debug_type_references
            and not debug_symbols
            and not debug_type_members
            and not debug_enum_members
            and not debug_identifiers
            and not debug_line_map
        ):
            return None

        for addr, name in data_labels.items():
            project.kb.labels[addr] = name
        for addr, name in code_labels.items():
            project.kb.labels[addr] = name

        image_end = getattr(getattr(project.loader, "main_object", None), "max_addr", None)
        if isinstance(image_end, int):
            image_end += 1
        code_ranges = _synthesize_code_ranges(code_labels, code_ranges, image_end=image_end)

        metadata = LSTMetadata(
            data_labels=data_labels,
            code_labels=code_labels,
            code_ranges=code_ranges,
            signature_code_addrs=frozenset(signature_code_addrs),
            absolute_addrs=True,
            source_format="+".join(dict.fromkeys(source_formats)) or "sidecars",
            struct_names=tuple(dict.fromkeys(struct_names)),
            debug_source_files=tuple(dict.fromkeys(debug_source_files)),
            debug_type_names=tuple(dict.fromkeys(debug_type_names)),
            debug_type_descriptors=tuple(dict.fromkeys(debug_type_descriptors)),
            debug_type_references=tuple(dict.fromkeys(debug_type_references)),
            debug_symbols=tuple(dict.fromkeys(debug_symbols)),
            debug_type_members=tuple(dict.fromkeys(debug_type_members)),
            debug_enum_members=tuple(dict.fromkeys(debug_enum_members)),
            debug_identifiers=tuple(dict.fromkeys(debug_identifiers)),
            debug_line_map=debug_line_map,
            cod_path=str(cod_path) if cod_path is not None else None,
            cod_proc_kinds=cod_proc_kinds,
        )
        project._inertia_lst_metadata = metadata
        _attach_debug_evidence_attrs(project, metadata)
        store_cached_sidecar_metadata(cache_key=sidecar_cache_key, metadata=metadata, project=project)
        emit_sidecar_metadata_debug(project, metadata)
        return metadata

    return _impl()


def attach_lst_metadata_to_project(project: angr.Project | None, metadata: LSTMetadata | None) -> bool:
    """Attach already-loaded sidecar metadata to a fresh project instance.

    Fresh retry/isolation projects are intentionally rebuilt without re-parsing
    sidecars. Semantic consumers still need the same metadata on the project
    object, and labels must be present in the KB label map.
    """
    if project is None or metadata is None:
        return False
    changed = False
    _attach_debug_evidence_attrs(project, metadata)
    if getattr(project, "_inertia_lst_metadata", None) is not metadata:
        project._inertia_lst_metadata = metadata
        changed = True
    labels = getattr(getattr(project, "kb", None), "labels", None)
    if labels is None:
        return changed
    for addr, name in getattr(metadata, "data_labels", {}).items():
        if labels.get(addr) != name:
            labels[addr] = name
            changed = True
    for addr, name in getattr(metadata, "code_labels", {}).items():
        if labels.get(addr) != name:
            labels[addr] = name
            changed = True
    return changed


def _lst_data_label(metadata: LSTMetadata | None, offset: int | None) -> str | None:
    if metadata is None or offset is None:
        return None
    return metadata.data_labels.get(offset)


def _lst_code_label(metadata: LSTMetadata | None, addr: int | None, code_base: int | None) -> str | None:
    if metadata is None or addr is None:
        return None
    absolute_addrs = getattr(metadata, "absolute_addrs", True)
    lookup_addr = addr if absolute_addrs else addr - code_base if code_base is not None else None
    if lookup_addr is None:
        return None
    code_labels = getattr(metadata, "code_labels", None)
    if not isinstance(code_labels, dict):
        return None
    label = code_labels.get(lookup_addr)
    if label is not None:
        return label
    region = _lst_code_region(metadata, lookup_addr)
    if region is None:
        return None
    return code_labels.get(region[0])


def _lst_code_region(metadata: LSTMetadata | None, addr: int | None) -> tuple[int, int] | None:
    def _impl():
        if metadata is None or addr is None:
            return None
        code_ranges = getattr(metadata, "code_ranges", None) or {}
        span = code_ranges.get(addr)
        if span is not None:
            return span
        containing_spans = [(start, span) for start, span in code_ranges.items() if start <= addr < span[1]]
        if containing_spans:
            return max(containing_spans, key=lambda item: item[0])[1]
        # Fallback: derive a bounded span from ordered code labels when explicit
        # code_ranges are unavailable/incomplete for this address.
        code_labels = getattr(metadata, "code_labels", None) or {}
        if not isinstance(code_labels, dict) or not code_labels:
            return None
        ordered = sorted(int(k) for k in code_labels.keys() if isinstance(k, int))
        if not ordered:
            return None
        if not (ordered[0] <= addr <= ordered[-1]):
            return None
        start = None
        end = None
        for i, label_addr in enumerate(ordered):
            next_addr = ordered[i + 1] if i + 1 < len(ordered) else None
            if label_addr <= addr and (next_addr is None or addr < next_addr):
                start = label_addr
                end = next_addr
                break
        if start is None:
            return None
        # Keep fallback spans bounded to avoid swallowing unrelated neighbors.
        if end is None or end <= start:
            end = start + 0x200
        return (start, end)

    return _impl()
