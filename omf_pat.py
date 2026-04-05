from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import re
import subprocess
import tempfile


@dataclass(frozen=True)
class PatPublicName:
    offset: int
    name: str


@dataclass(frozen=True)
class PatModule:
    source_path: str
    module_name: str
    pattern_bytes: tuple[int | None, ...]
    module_length: int
    public_names: tuple[PatPublicName, ...]
    referenced_names: tuple[PatPublicName, ...]
    tail_bytes: tuple[int | None, ...]


@dataclass(frozen=True)
class LocalPatMatchResult:
    code_labels: dict[int, str]
    code_ranges: dict[int, tuple[int, int]]
    source_formats: tuple[str, ...]


@dataclass
class _OMFSegment:
    name: str
    class_name: str
    declared_length: int
    data: bytearray
    max_written_end: int = 0


@dataclass(frozen=True)
class _OMFPublic:
    seg_index: int
    offset: int
    name: str


@dataclass(frozen=True)
class OMFModuleBlob:
    module_name: str
    data: bytes
    page_offset: int
    page_number: int
    dependency_indexes: tuple[int, ...] = ()


@dataclass(frozen=True)
class MicrosoftLibHeader:
    page_size: int
    dictionary_offset: int
    dictionary_blocks: int
    case_sensitive: bool


@dataclass(frozen=True)
class MicrosoftLibExtendedRecord:
    page_number: int
    dependency_offset: int
    dependency_indexes: tuple[int, ...]


@dataclass(frozen=True)
class MicrosoftLibMetadata:
    header: MicrosoftLibHeader
    modules: tuple[OMFModuleBlob, ...]
    extended_records: tuple[MicrosoftLibExtendedRecord, ...]


_PAT_HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}|\.\.)+$")
_PAT_PUBLIC_RE = re.compile(r"^:(?P<offset>-?[0-9A-Fa-f]{4,8})(?:@)?$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def parse_pat_file(pat_path: Path) -> tuple[PatModule, ...]:
    modules: list[PatModule] = []
    try:
        lines = pat_path.read_text(errors="ignore").splitlines()
    except OSError:
        return ()
    for line in lines:
        parsed = parse_pat_line(line, source_path=str(pat_path))
        if parsed is not None:
            modules.append(parsed)
    return tuple(modules)


def parse_pat_line(line: str, *, source_path: str = "<memory>") -> PatModule | None:
    stripped = line.strip()
    if not stripped or stripped == "---":
        return None
    parts = stripped.split()
    if len(parts) < 5:
        return None
    pattern_text = parts[0]
    if len(pattern_text) < 64 or not _PAT_HEX_RE.fullmatch(pattern_text):
        return None
    try:
        module_length = int(parts[3], 16)
    except ValueError:
        return None
    pattern_bytes = tuple(_decode_pat_bytes(pattern_text[:64]))
    public_names: list[PatPublicName] = []
    referenced_names: list[PatPublicName] = []
    tail_bytes: tuple[int | None, ...] = ()
    idx = 4
    while idx < len(parts):
        token = parts[idx]
        public_match = _PAT_PUBLIC_RE.match(token)
        if public_match is not None and idx + 1 < len(parts):
            try:
                offset = int(public_match.group("offset"), 16)
            except ValueError:
                offset = 0
            public_names.append(PatPublicName(offset=offset, name=parts[idx + 1]))
            idx += 2
            continue
        if token.startswith("^") and idx + 1 < len(parts):
            try:
                ref_offset = int(token[1:], 16)
            except ValueError:
                ref_offset = 0
            referenced_names.append(PatPublicName(offset=ref_offset, name=parts[idx + 1]))
            idx += 2
            continue
        if _PAT_HEX_RE.fullmatch(token):
            tail_bytes = tuple(_decode_pat_bytes(token))
            idx += 1
            continue
        idx += 1
    if not public_names or module_length <= 0:
        return None
    return PatModule(
        source_path=source_path,
        module_name=public_names[0].name,
        pattern_bytes=pattern_bytes,
        module_length=module_length,
        public_names=tuple(public_names),
        referenced_names=tuple(referenced_names),
        tail_bytes=tail_bytes,
    )


def ensure_pat_from_omf_input(
    input_path: Path,
    cache_dir: Path,
    *,
    flair_root: Path | None = None,
) -> Path | None:
    suffix = input_path.suffix.lower()
    if suffix == ".pat" and input_path.exists():
        return input_path
    if suffix not in {".obj", ".lib"} or not input_path.exists():
        return None
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_key = _cache_key_for_file(input_path)
    out_path = cache_dir / f"{_sanitize_component(input_path.stem)}-{cache_key}.pat"
    lines: list[str] = []
    if _run_local_plb(input_path, out_path, flair_root=flair_root):
        try:
            lines.extend(
                line for line in out_path.read_text(errors="ignore").splitlines() if line.strip() and line.strip() != "---"
            )
        except OSError:
            pass
    if suffix == ".obj":
        fallback_path = cache_dir / f"{_sanitize_component(input_path.stem)}-{cache_key}.fallback.pat"
        if generate_pat_from_omf_obj(input_path, fallback_path) > 0:
            try:
                lines.extend(
                    line
                    for line in fallback_path.read_text(errors="ignore").splitlines()
                    if line.strip() and line.strip() != "---"
                )
            except OSError:
                pass
            finally:
                try:
                    fallback_path.unlink(missing_ok=True)
                except Exception:
                    pass
    elif suffix == ".lib":
        fallback_path = cache_dir / f"{_sanitize_component(input_path.stem)}-{cache_key}.fallback.pat"
        if generate_pat_from_omf_lib(input_path, fallback_path) > 0:
            try:
                lines.extend(
                    line
                    for line in fallback_path.read_text(errors="ignore").splitlines()
                    if line.strip() and line.strip() != "---"
                )
            except OSError:
                pass
            finally:
                try:
                    fallback_path.unlink(missing_ok=True)
                except Exception:
                    pass
    if not lines:
        return None
    deduped_lines = list(dict.fromkeys(lines))
    out_path.write_text("".join(f"{line}\n" for line in deduped_lines) + "---\n")
    return out_path


def discover_local_pat_matches(
    binary_path: Path,
    project,
    *,
    flair_root: Path | None = None,
    max_candidate_inputs: int = 32,
    max_pat_modules: int = 512,
) -> LocalPatMatchResult:
    candidate_inputs = _discover_candidate_pat_inputs(binary_path)[:max_candidate_inputs]
    if not candidate_inputs:
        return LocalPatMatchResult({}, {}, ())

    cache_dir = _pick_pat_cache_dir(binary_path)
    modules: list[PatModule] = []
    used_generated = False
    used_plain_pat = False
    for candidate in candidate_inputs:
        pat_path = ensure_pat_from_omf_input(candidate, cache_dir, flair_root=flair_root)
        if pat_path is None:
            continue
        used_generated |= pat_path != candidate
        used_plain_pat |= pat_path == candidate
        modules.extend(parse_pat_file(pat_path))
        if len(modules) >= max_pat_modules:
            modules = modules[:max_pat_modules]
            break
    if not modules:
        return LocalPatMatchResult({}, {}, ())

    image = _load_project_image(project)
    if image is None:
        return LocalPatMatchResult({}, {}, ())
    base_addr, image_bytes = image
    code_labels, code_ranges = match_pat_modules(image_bytes, base_addr, modules)
    source_formats: list[str] = []
    if code_labels:
        if used_plain_pat:
            source_formats.append("local_pat")
        if used_generated:
            source_formats.append("local_omf_pat")
    return LocalPatMatchResult(code_labels, code_ranges, tuple(source_formats))


def match_pat_modules(
    image_bytes: bytes,
    base_addr: int,
    modules: tuple[PatModule, ...] | list[PatModule],
) -> tuple[dict[int, str], dict[int, tuple[int, int]]]:
    code_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    for module in modules:
        hits = _find_pat_matches(image_bytes, module)
        if len(hits) != 1:
            continue
        start_off = hits[0]
        match_addr = base_addr + start_off
        if module.public_names:
            first_public = min(module.public_names, key=lambda pub: pub.offset)
            code_start = match_addr + first_public.offset
            code_end = match_addr + module.module_length
            if code_end > code_start:
                code_ranges.setdefault(code_start, (code_start, code_end))
        for public_name in module.public_names:
            linear = match_addr + public_name.offset
            code_labels.setdefault(linear, public_name.name.lstrip("_"))
    return code_labels, code_ranges


def generate_pat_from_omf_obj(obj_path: Path, out_path: Path) -> int:
    lines = _generate_pat_lines_from_omf_blob(obj_path.read_bytes(), source_name=obj_path.name)
    out_path.write_text("".join(f"{line}\n" for line in lines) + "---\n")
    return len(lines)


def generate_pat_from_omf_lib(lib_path: Path, out_path: Path) -> int:
    lines: list[str] = []
    for module in extract_omf_modules_from_lib(lib_path):
        lines.extend(_generate_pat_lines_from_omf_blob(module.data, source_name=module.module_name))
    out_path.write_text("".join(f"{line}\n" for line in lines) + "---\n")
    return len(lines)


def extract_omf_modules_from_lib(lib_path: Path) -> tuple[OMFModuleBlob, ...]:
    return parse_microsoft_lib(lib_path).modules


def parse_microsoft_lib(lib_path: Path) -> MicrosoftLibMetadata:
    blob = lib_path.read_bytes()
    if len(blob) < 16 or blob[0] != 0xF0:
        empty_header = MicrosoftLibHeader(page_size=0, dictionary_offset=0, dictionary_blocks=0, case_sensitive=False)
        return MicrosoftLibMetadata(header=empty_header, modules=(), extended_records=())
    header = _parse_microsoft_lib_header(blob)
    page_size = header.page_size
    if page_size <= 0 or len(blob) < page_size:
        return MicrosoftLibMetadata(header=header, modules=(), extended_records=())
    dict_offset = header.dictionary_offset
    if dict_offset <= 0 or dict_offset > len(blob):
        dict_offset = len(blob)
    extended_records = _parse_microsoft_lib_extended_dict(blob, header)
    deps_by_page = {record.page_number: record.dependency_indexes for record in extended_records}
    modules: list[OMFModuleBlob] = []
    offset = page_size
    while offset < dict_offset:
        if offset + 3 > len(blob):
            break
        record_type = blob[offset]
        if record_type in {0x00, 0xF1}:
            offset = _align_up(offset + 1, page_size)
            continue
        module_end = _find_omf_module_end(blob, offset, dict_offset)
        if module_end is None:
            break
        module_blob = blob[offset:module_end]
        module_name = _peek_omf_module_name(module_blob) or f"{lib_path.stem}@0x{offset:x}"
        page_number = offset // page_size
        modules.append(
            OMFModuleBlob(
                module_name=module_name,
                data=module_blob,
                page_offset=offset,
                page_number=page_number,
                dependency_indexes=deps_by_page.get(page_number, ()),
            )
        )
        offset = _align_up(module_end, page_size)
    return MicrosoftLibMetadata(header=header, modules=tuple(modules), extended_records=extended_records)


def _build_pat_line(function_bytes: bytes, *, public_name: str, module_name: str) -> str | None:
    if len(function_bytes) < 4:
        return None
    head = list(function_bytes[:32])
    while len(head) < 32:
        head.append(None)
    tail = function_bytes[32:]
    return (
        f"{_encode_pat_bytes(head)} 00 0000 {len(function_bytes):04X} "
        f":0000 {public_name} {_encode_pat_bytes(tail)} ; {module_name}"
    ).rstrip()


def _parse_omf_obj(obj_path: Path) -> tuple[str, list[_OMFSegment], list[_OMFPublic]]:
    return _parse_omf_blob(obj_path.read_bytes(), module_name_hint=obj_path.stem)


def _parse_omf_blob(blob: bytes, *, module_name_hint: str) -> tuple[str, list[_OMFSegment], list[_OMFPublic]]:
    lnames: list[str] = [""]
    segments: list[_OMFSegment] = []
    publics: list[_OMFPublic] = []
    module_name = module_name_hint
    for record_type, payload in _iter_omf_records(blob):
        if record_type == 0x80 and payload:
            name_len = payload[0]
            module_name = payload[1 : 1 + name_len].decode("latin1", errors="ignore") or module_name
        elif record_type in {0x96, 0xCA}:
            lnames.extend(_parse_lnames(payload))
        elif record_type == 0x98:
            segments.append(_parse_segdef(payload, lnames))
        elif record_type in {0x90, 0xB6}:
            publics.extend(_parse_pubdef(payload))
        elif record_type == 0xA0:
            _apply_ledata(payload, segments)
    return module_name, segments, publics


def _generate_pat_lines_from_omf_blob(blob: bytes, *, source_name: str) -> list[str]:
    module_name, segments, publics = _parse_omf_blob(blob, module_name_hint=Path(source_name).stem)
    lines: list[str] = []
    publics_by_segment: dict[int, list[_OMFPublic]] = {}
    for public in publics:
        publics_by_segment.setdefault(public.seg_index, []).append(public)
    for seg_index, seg_publics in sorted(publics_by_segment.items()):
        if seg_index <= 0 or seg_index > len(segments):
            continue
        segment = segments[seg_index - 1]
        if not _segment_looks_like_code(segment):
            continue
        seg_publics.sort(key=lambda item: item.offset)
        seg_limit = segment.max_written_end or len(segment.data)
        for index, public in enumerate(seg_publics):
            start = public.offset
            next_public = seg_publics[index + 1].offset if index + 1 < len(seg_publics) else seg_limit
            end = max(start, min(next_public, seg_limit))
            if end <= start:
                continue
            func_bytes = bytes(segment.data[start:end])
            if sum(1 for _ in func_bytes[:32]) < 4:
                continue
            line = _build_pat_line(
                func_bytes,
                public_name=public.name,
                module_name=f"{module_name}:{public.name}",
            )
            if line is not None:
                lines.append(line)
    return lines


def _iter_omf_records(blob: bytes):
    offset = 0
    while offset + 3 <= len(blob):
        record_type = blob[offset]
        record_length = blob[offset + 1] | (blob[offset + 2] << 8)
        if record_length <= 0 or offset + 3 + record_length > len(blob):
            break
        payload = blob[offset + 3 : offset + 3 + record_length - 1]
        yield record_type, payload
        offset += 3 + record_length


def _find_omf_module_end(blob: bytes, start: int, limit: int) -> int | None:
    offset = start
    while offset + 3 <= limit:
        record_length = blob[offset + 1] | (blob[offset + 2] << 8)
        record_end = offset + 3 + record_length
        if record_length <= 0 or record_end > limit:
            return None
        if blob[offset] == 0x8A:
            return record_end
        offset = record_end
    return None


def _peek_omf_module_name(blob: bytes) -> str | None:
    if len(blob) < 5 or blob[0] != 0x80:
        return None
    name_len = blob[3]
    if 4 + name_len > len(blob):
        return None
    return blob[4 : 4 + name_len].decode("latin1", errors="ignore") or None


def _parse_microsoft_lib_header(blob: bytes) -> MicrosoftLibHeader:
    record_length = int.from_bytes(blob[1:3], "little")
    page_size = record_length + 3
    dictionary_offset = int.from_bytes(blob[3:7], "little")
    dictionary_blocks = int.from_bytes(blob[7:9], "little")
    flags = blob[9] if len(blob) > 9 else 0
    return MicrosoftLibHeader(
        page_size=page_size,
        dictionary_offset=dictionary_offset,
        dictionary_blocks=dictionary_blocks,
        case_sensitive=bool(flags & 0x01),
    )


def _parse_microsoft_lib_extended_dict(
    blob: bytes,
    header: MicrosoftLibHeader,
) -> tuple[MicrosoftLibExtendedRecord, ...]:
    if header.dictionary_blocks <= 0 or header.dictionary_offset <= 0:
        return ()
    dict_end = header.dictionary_offset + header.dictionary_blocks * 512
    if dict_end + 5 > len(blob):
        return ()
    if blob[dict_end] != 0xF2:
        return ()
    record_length = int.from_bytes(blob[dict_end + 1 : dict_end + 3], "little")
    record_end = dict_end + 3 + record_length
    if record_end > len(blob):
        return ()
    payload = blob[dict_end + 3 : record_end - 1]
    if len(payload) < 2:
        return ()
    module_count = int.from_bytes(payload[:2], "little")
    table_off = 2
    table_size = module_count * 4
    if len(payload) < table_off + table_size:
        return ()
    records: list[MicrosoftLibExtendedRecord] = []
    for index in range(module_count):
        entry_off = table_off + index * 4
        page_number = int.from_bytes(payload[entry_off : entry_off + 2], "little")
        dependency_offset = int.from_bytes(payload[entry_off + 2 : entry_off + 4], "little")
        dependency_indexes = _parse_extended_dependency_list(payload, dependency_offset)
        records.append(
            MicrosoftLibExtendedRecord(
                page_number=page_number,
                dependency_offset=dependency_offset,
                dependency_indexes=dependency_indexes,
            )
        )
    return tuple(records)


def _parse_extended_dependency_list(payload: bytes, dependency_offset: int) -> tuple[int, ...]:
    if dependency_offset <= 0 or dependency_offset >= len(payload):
        return ()
    values: list[int] = []
    off = dependency_offset
    while off + 2 <= len(payload):
        value = int.from_bytes(payload[off : off + 2], "little")
        off += 2
        if value == 0:
            break
        values.append(value)
    return tuple(values)


def _parse_lnames(payload: bytes) -> list[str]:
    names: list[str] = []
    offset = 0
    while offset < len(payload):
        name_len = payload[offset]
        offset += 1
        names.append(payload[offset : offset + name_len].decode("latin1", errors="ignore"))
        offset += name_len
    return names


def _parse_segdef(payload: bytes, lnames: list[str]) -> _OMFSegment:
    offset = 0
    acbp = payload[offset]
    offset += 1
    use32 = bool(acbp & 0x01)
    seg_length_size = 4 if use32 else 2
    declared_length = int.from_bytes(payload[offset : offset + seg_length_size], "little")
    offset += seg_length_size
    seg_name_index, offset = _read_omf_index(payload, offset)
    class_name_index, offset = _read_omf_index(payload, offset)
    _, offset = _read_omf_index(payload, offset)
    seg_name = lnames[seg_name_index] if seg_name_index < len(lnames) else ""
    class_name = lnames[class_name_index] if class_name_index < len(lnames) else ""
    return _OMFSegment(
        name=seg_name,
        class_name=class_name,
        declared_length=declared_length,
        data=bytearray(declared_length),
        max_written_end=0,
    )


def _parse_pubdef(payload: bytes) -> list[_OMFPublic]:
    offset = 0
    group_index, offset = _read_omf_index(payload, offset)
    seg_index, offset = _read_omf_index(payload, offset)
    if group_index == 0 and seg_index == 0:
        offset += 2
    publics: list[_OMFPublic] = []
    while offset < len(payload):
        name_len = payload[offset]
        offset += 1
        name = payload[offset : offset + name_len].decode("latin1", errors="ignore")
        offset += name_len
        if offset + 2 > len(payload):
            break
        public_offset = int.from_bytes(payload[offset : offset + 2], "little")
        offset += 2
        _, offset = _read_omf_index(payload, offset)
        if seg_index:
            publics.append(_OMFPublic(seg_index=seg_index, offset=public_offset, name=name))
    return publics


def _apply_ledata(payload: bytes, segments: list[_OMFSegment]) -> None:
    seg_index, offset = _read_omf_index(payload, 0)
    if seg_index <= 0 or seg_index > len(segments) or offset + 2 > len(payload):
        return
    data_offset = int.from_bytes(payload[offset : offset + 2], "little")
    offset += 2
    data = payload[offset:]
    segment = segments[seg_index - 1]
    end = data_offset + len(data)
    if end > len(segment.data):
        segment.data.extend(b"\x00" * (end - len(segment.data)))
    segment.data[data_offset:end] = data
    segment.max_written_end = max(segment.max_written_end, end)


def _read_omf_index(payload: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(payload):
        return 0, offset
    first = payload[offset]
    if first & 0x80:
        if offset + 1 >= len(payload):
            return first & 0x7F, len(payload)
        return ((first & 0x7F) << 8) | payload[offset + 1], offset + 2
    return first, offset + 1


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def _segment_looks_like_code(segment: _OMFSegment) -> bool:
    text = f"{segment.name} {segment.class_name}".upper()
    if any(token in text for token in ("CODE", "TEXT")):
        return True
    if any(token in text for token in ("DATA", "BSS", "STACK")):
        return False
    return bool(segment.max_written_end)


def _run_local_plb(input_path: Path, out_path: Path, *, flair_root: Path | None = None) -> bool:
    root = flair_root or Path("/home/xor/ida77/flair77")
    plb_path = root / "bin" / "linux" / "plb"
    if not plb_path.exists():
        return False
    with tempfile.NamedTemporaryFile(prefix="inertia-plb-", suffix=".pat", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        proc = subprocess.run(
            [str(plb_path), str(input_path), str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return False
        modules = parse_pat_file(tmp_path)
        if not modules:
            return False
        out_path.write_text(tmp_path.read_text(errors="ignore"))
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def _discover_candidate_pat_inputs(binary_path: Path) -> list[Path]:
    parent = binary_path.parent
    candidates: list[Path] = []
    for child in sorted(parent.iterdir()):
        if not child.is_file():
            continue
        if child == binary_path:
            continue
        if child.suffix.lower() in {".pat", ".obj", ".lib"}:
            candidates.append(child)
    return candidates


def _pick_pat_cache_dir(binary_path: Path) -> Path:
    preferred = binary_path.parent / ".inertia_pat_cache"
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        probe = preferred / ".write_test"
        probe.write_text("ok")
        probe.unlink(missing_ok=True)
        return preferred
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "inertia_pat_cache"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def _load_project_image(project) -> tuple[int, bytes] | None:
    main_object = getattr(getattr(project, "loader", None), "main_object", None)
    memory = getattr(getattr(project, "loader", None), "memory", None)
    if main_object is None or memory is None:
        return None
    min_addr = getattr(main_object, "min_addr", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not isinstance(min_addr, int) or not isinstance(max_addr, int) or max_addr < min_addr:
        return None
    size = max_addr - min_addr + 1
    try:
        return min_addr, bytes(memory.load(min_addr, size))
    except Exception:
        return None


def _find_pat_matches(image_bytes: bytes, module: PatModule) -> list[int]:
    if module.module_length <= 0 or module.module_length > len(image_bytes):
        return []
    constant_positions = [idx for idx, byte in enumerate(module.pattern_bytes) if byte is not None]
    if not constant_positions:
        return []
    anchor_index = constant_positions[0]
    anchor_value = module.pattern_bytes[anchor_index]
    assert anchor_value is not None
    hits: list[int] = []
    end_limit = len(image_bytes) - module.module_length + 1
    for start in range(0, end_limit):
        if image_bytes[start + anchor_index] != anchor_value:
            continue
        if not _bytes_match_pattern(image_bytes, start, module.pattern_bytes, min(module.module_length, 32)):
            continue
        tail_start = start + 32
        if module.tail_bytes and not _bytes_match_pattern(image_bytes, tail_start, module.tail_bytes, len(module.tail_bytes)):
            continue
        hits.append(start)
        if len(hits) > 4:
            break
    return hits


def _bytes_match_pattern(image_bytes: bytes, start: int, pattern: tuple[int | None, ...], limit: int) -> bool:
    if start < 0 or start + limit > len(image_bytes):
        return False
    for index in range(limit):
        expected = pattern[index]
        if expected is None:
            continue
        if image_bytes[start + index] != expected:
            return False
    return True


def _decode_pat_bytes(text: str) -> list[int | None]:
    decoded: list[int | None] = []
    for idx in range(0, len(text), 2):
        token = text[idx : idx + 2]
        decoded.append(None if token == ".." else int(token, 16))
    return decoded


def _encode_pat_bytes(data: bytes | bytearray | list[int | None]) -> str:
    parts: list[str] = []
    for byte in data:
        parts.append(".." if byte is None else f"{byte:02X}")
    return "".join(parts)


def _sanitize_component(text: str) -> str:
    return _SAFE_NAME_RE.sub("-", text).strip("-") or "pat"


def _cache_key_for_file(path: Path) -> str:
    stat = path.stat()
    raw = f"{path}:{stat.st_mtime_ns}:{stat.st_size}".encode()
    return hashlib.sha1(raw).hexdigest()[:12]
