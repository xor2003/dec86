from __future__ import annotations

import contextlib
import functools
import re

from collections.abc import MutableMapping

from angr.sim_type import SimTypeFunction, SimTypePointer
from angr.utils.library import convert_cproto_to_py

from .analysis_helpers import preferred_known_helper_signature_decl, seed_calling_conventions
from .cod_known_objects import known_cod_object_spec
from .simos_86_16 import SimCC8616MSCsmall
from typing import Tuple

ANNOTATION_KEY = "x86_16_annotations"

_PROTO_EMIT_TYPEDEFS_8616 = (
    "typedef unsigned long clock_t;",
    "typedef unsigned short clock_t;",
    "typedef long time_t;",
    "typedef unsigned long time_t;",
)


def _source_prototype_calling_convention_8616(project):
    arch = getattr(project, "arch", None)
    if getattr(arch, "name", None) != "86_16":
        return None
    return SimCC8616MSCsmall(arch)

_C_TYPE_KEYWORDS_8616 = {
    "char",
    "const",
    "double",
    "enum",
    "extern",
    "float",
    "int",
    "long",
    "register",
    "short",
    "signed",
    "static",
    "struct",
    "union",
    "unsigned",
    "void",
    "volatile",
}

_SOURCE_DECL_RE_8616 = re.compile(
    r"^(?P<prefix>(?:(?:extern|static|inline|const|volatile|unsigned|signed|struct|union|enum|long|short|int|char|_Bool|[A-Za-z_]\w*)|\s|\*)+?)"
    r"\s*(?P<name>[A-Za-z_][\w$?@]*)\s*\([^()]*\)\s*(?:\{|;)?\s*$"
)


def _opaque_typedef_headers_for_c_decl_8616(c_decl: str) -> tuple[str, ...]:
    match = re.match(
        r"^\s*(?P<ret>.*?)\b(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*;?\s*$",
        c_decl,
    )
    if match is None:
        return ()
    function_name = match.group("name")
    candidate_type_names: set[str] = set()
    chunks = [match.group("ret")]
    chunks.extend(part.strip() for part in match.group("args").split(",") if part.strip() and part.strip() != "void")
    for chunk_index, chunk in enumerate(chunks):
        cleaned = re.sub(r"\[[^\]]*\]", " ", chunk.replace("*", " "))
        tokens = re.findall(r"[A-Za-z_]\w*", cleaned)
        if not tokens:
            continue
        if chunk_index > 0 and len(tokens) > 1:
            tokens = tokens[:-1]
        for index, token in enumerate(tokens):
            if token == function_name or token in _C_TYPE_KEYWORDS_8616:
                continue
            if index > 0 and tokens[index - 1] in {"struct", "union", "enum"}:
                continue
            candidate_type_names.add(token)
    return tuple(f"typedef unsigned short {name};" for name in sorted(candidate_type_names))


def _converted_c_prototype_or_none_8616(source: str):
    converted = convert_cproto_to_py(source)
    if len(converted) >= 2 and converted[1] is not None:
        return converted
    return None


def _c_decl_requires_opaque_typedefs_8616(c_decl: str) -> bool:
    normalized_decl = _normalize_c_decl_text(c_decl)
    try:
        if _converted_c_prototype_or_none_8616(normalized_decl) is not None:
            return False
    except Exception:
        pass
    for typedef_header in _PROTO_EMIT_TYPEDEFS_8616:
        try:
            if _converted_c_prototype_or_none_8616(f"{typedef_header}\n{normalized_decl}") is not None:
                return False
        except Exception:
            pass
    return bool(_opaque_typedef_headers_for_c_decl_8616(normalized_decl))


def _parse_c_prototype_8616(c_decl: str) -> Tuple[str, SimTypeFunction, str]:
    normalized_decl = _normalize_c_decl_text(c_decl)
    try:
        converted = _converted_c_prototype_or_none_8616(normalized_decl)
        if converted is not None:
            return converted
    except Exception:
        pass

    for typedef_header in _PROTO_EMIT_TYPEDEFS_8616:
        try:
            converted = _converted_c_prototype_or_none_8616(f"{typedef_header}\n{normalized_decl}")
            if converted is not None:
                return converted
        except Exception:
            pass

    opaque_headers = _opaque_typedef_headers_for_c_decl_8616(normalized_decl)
    if opaque_headers:
        try:
            converted = _converted_c_prototype_or_none_8616("\n".join((*opaque_headers, normalized_decl)))
            if converted is not None:
                return converted
        except Exception:
            pass

    raise


def _annotation_dict(function):
    info = getattr(function, "info", None)
    if not isinstance(info, MutableMapping):
        function.info = {}
        info = function.info
    return info.setdefault(
        ANNOTATION_KEY,
        {
            "stack_vars": {},
            "global_vars": {},
            "source_lines": (),
            "source_return_lines": (),
        },
    )


def _normalize_bp_disp(offset: int) -> int:
    return offset - 2


def _normalize_arg_names(arg_names: list[str] | tuple[str, ...], count: int) -> list[str]:
    normalized: list[str] = []
    used: set[str] = set()
    source = list(arg_names)
    for index in range(count):
        base_name = source[index] if index < len(source) else None
        if not isinstance(base_name, str) or not base_name:
            base_name = f"a{index}"
        candidate = base_name
        suffix = 2
        while candidate in used:
            candidate = f"{base_name}_{suffix}"
            suffix += 1
        normalized.append(candidate)
        used.add(candidate)
    return normalized


def _normalize_c_decl_text(c_decl: str) -> str:
    normalized = c_decl
    replacements = (
        (r"\buint8\b", "unsigned char"),
        (r"\buint16\b", "unsigned short"),
        (r"\buint32\b", "unsigned long"),
        (r"\bint8\b", "signed char"),
        (r"\bint16\b", "short"),
        (r"\bint32\b", "long"),
        (r"\bFAR\b", ""),
        (r"\bfar\b", ""),
    )
    for pattern, replacement in replacements:
        normalized = re.sub(pattern, replacement, normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    normalized = re.sub(r"\s+\)", ")", normalized)
    normalized = re.sub(r"\(\s+", "(", normalized)
    normalized = re.sub(r"\s+;", ";", normalized)
    return normalized


def _source_decl_from_cod_source_lines(source_lines: tuple[str, ...], function_name: str | None = None) -> str | None:
    normalized_lines = tuple(str(line) for line in (source_lines or ()))
    normalized_name = function_name if isinstance(function_name, str) and function_name else None
    return _source_decl_from_cod_source_lines_cached_8616(normalized_lines, normalized_name)


@functools.lru_cache(maxsize=4096)
def _source_decl_from_cod_source_lines_cached_8616(
    source_lines: tuple[str, ...],
    function_name: str | None = None,
) -> str | None:
    target_name = function_name.lstrip("_") if isinstance(function_name, str) and function_name else None
    first_decl: str | None = None
    for line in source_lines:
        stripped = line.strip()
        if not stripped or stripped == "}":
            continue
        if stripped.startswith(("if ", "while ", "for ", "switch ", "return ", "case ", "default ")):
            continue
        if "(" not in stripped or ")" not in stripped:
            continue
        header = stripped[:-1].rstrip() if stripped.endswith("{") else stripped
        match = _SOURCE_DECL_RE_8616.match(header)
        if match is None:
            continue
        if not header.endswith(";"):
            header = f"{header};"
        if first_decl is None:
            first_decl = header
        if target_name is not None and match.group("name").lstrip("_") == target_name:
            return header
        if target_name is None:
            return header
    return first_decl if target_name is None else None


def _source_args_from_cod_source_lines(source_lines: tuple[str, ...], func_name: str | None) -> str | None:
    def _impl():
        if not isinstance(func_name, str) or not func_name:
            return None

        candidate_names = {func_name}
        stripped_name = func_name.lstrip("_")
        if stripped_name and stripped_name != func_name:
            candidate_names.add(stripped_name)

        decl_re = re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?:\{|;)?\s*$")
        for line in source_lines:
            stripped = line.strip()
            if not stripped or stripped in {"{", "}"}:
                continue
            if stripped.startswith(("if ", "while ", "for ", "switch ", "return ", "case ", "default ")):
                continue
            decl_match = decl_re.match(stripped)
            if decl_match is None or decl_match.group("name") not in candidate_names:
                continue
            return decl_match.group("args")
        return None

    return _impl()


def _source_function_pointer_local_types_8616(project, source_lines: tuple[str, ...]) -> dict[str, SimTypePointer]:
    def _impl():
        local_types: dict[str, SimTypePointer] = {}
        fp_decl_re = re.compile(
            r"^\s*(?P<ret>.+?)\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*\((?P<args>[^;]*)\)\s*;\s*$"
        )
        for raw_line in tuple(source_lines or ()):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith((";", "//")):
                continue
            match = fp_decl_re.match(stripped)
            if match is None:
                continue
            name = match.group("name")
            fake_decl = f"{match.group('ret').strip()} __inertia_fp({match.group('args').strip()});"
            try:
                _parsed_name, function_type, _ = _parse_c_prototype_8616(fake_decl)
            except Exception:
                continue
            if function_type is None:
                continue
            function_type = function_type.with_arch(project.arch)
            pointer_type = SimTypePointer(function_type).with_arch(project.arch)
            local_types[name] = pointer_type
        return local_types

    return _impl()


def annotate_function(
    project,
    func_addr: int,
    *,
    name: str | None = None,
    c_decl: str | None = None,
    prototype: SimTypeFunction | None = None,
    calling_convention=None,
    arg_names: list[str] | tuple[str, ...] | None = None,
    stack_vars: dict[int, str | dict] | None = None,
    bp_stack_vars: dict[int, str | dict] | None = None,
    global_vars: dict[int, str | dict] | None = None,
):
    def _impl():
        func = project.kb.functions.function(addr=func_addr, create=True)
        if func is None:
            raise KeyError(func_addr)
        annotations = _annotation_dict(func)

        parsed_name = None
        parsed_proto = None
        if c_decl is not None:
            parsed_name, parsed_proto, _ = _parse_c_prototype_8616(c_decl)
            if parsed_proto is None:
                raise ValueError(f"Failed to parse C declaration: {c_decl}")
            parsed_proto = parsed_proto.with_arch(project.arch)

        final_name = name if name is not None else parsed_name
        if final_name is not None:
            func.name = final_name

        final_proto = prototype.with_arch(project.arch) if prototype is not None else parsed_proto
        if final_proto is not None:
            func.prototype = final_proto
            func.is_prototype_guessed = False

        if calling_convention is not None:
            func.calling_convention = calling_convention

        if arg_names is not None:
            if func.prototype is None:
                raise ValueError("Cannot assign argument names without a prototype.")
            normalized_names = _normalize_arg_names(arg_names, len(func.prototype.args))
            func.prototype = SimTypeFunction(
                func.prototype.args,
                func.prototype.returnty,
                arg_names=tuple(normalized_names),
                variadic=func.prototype.variadic,
            ).with_arch(project.arch)
            func.is_prototype_guessed = False

        if stack_vars:
            for offset, spec in stack_vars.items():
                entry = annotations["stack_vars"].setdefault(offset, {})
                if isinstance(spec, str):
                    entry["name"] = spec
                else:
                    entry.update(spec)

        if bp_stack_vars:
            translated = {}
            for bp_disp, spec in bp_stack_vars.items():
                translated[_normalize_bp_disp(bp_disp)] = spec
            annotate_function(project, func_addr, stack_vars=translated)

        if global_vars:
            for addr, spec in global_vars.items():
                if isinstance(spec, str):
                    entry = {"name": spec}
                    label = spec
                elif isinstance(spec, dict):
                    entry = dict(spec)
                    label = entry.get("name")
                    if not isinstance(label, str):
                        raise ValueError(f"Global annotation for {addr:#x} must include a string name.")
                else:
                    raise TypeError(f"Unsupported global annotation spec for {addr:#x}: {type(spec).__name__}")
                annotations["global_vars"][addr] = entry
                project.kb.labels[addr] = label

        return func

    return _impl()


def annotate_stack_variable(project, func_addr: int, offset: int, name: str, type_=None):
    spec = {"name": name}
    if type_ is not None:
        spec["type"] = type_
    return annotate_function(project, func_addr, stack_vars={offset: spec})


def annotate_bp_stack_variable(project, func_addr: int, bp_disp: int, name: str, type_=None):
    spec = {"name": name}
    if type_ is not None:
        spec["type"] = type_
    return annotate_function(project, func_addr, bp_stack_vars={bp_disp: spec})


def annotate_global_variable(project, addr: int, name: str):
    project.kb.labels[addr] = name
    return name


def _apply_known_helper_signatures(project, cod_metadata=None) -> bool:
    if cod_metadata is None:
        return False

    changed = False
    seen_decls: set[str] = set()
    for call_name in getattr(cod_metadata, "call_names", ()) or ():
        decl = preferred_known_helper_signature_decl(call_name)
        if decl is None or decl in seen_decls:
            continue
        seen_decls.add(decl)

        helper_func = project.kb.functions.function(name=call_name, create=False)
        if helper_func is None and call_name.startswith("_"):
            helper_func = project.kb.functions.function(name=call_name.lstrip("_"), create=False)
        if helper_func is None:
            continue

        annotate_function(
            project,
            helper_func.addr,
            name=getattr(helper_func, "name", call_name),
            c_decl=decl,
        )
        changed = True

    return changed


def _typed_cod_spec_dict_8616(spec) -> dict[str, object]:
    return {
        "name": spec.name,
        "type": spec.type,
        "type_name": spec.type_name,
        "field_names": spec.field_names,
        "field_offsets": spec.field_offsets,
        "field_widths": spec.field_widths,
        "packed": spec.packed,
        "allowed_views": spec.allowed_views,
        "segment_domain": spec.segment_domain,
    }


def _split_source_arg_names_8616(source_arg_text: str | None) -> list[str]:
    def _impl():
        if not source_arg_text:
            return []
        source_arg_names: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in source_arg_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                part = "".join(current).strip()
                if part:
                    match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part)
                    if match is not None:
                        source_arg_names.append(match.group(1))
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            part = "".join(current).strip()
            if part:
                match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part)
                if match is not None:
                    source_arg_names.append(match.group(1))
        return source_arg_names

    return _impl()


def _apply_source_prototype_annotations_8616(project, func_addr: int, func, source_lines: tuple[str, ...]) -> bool:
    def _impl():
        changed = False
        annotations = _annotation_dict(func)
        annotations["source_lines"] = source_lines
        annotations["source_return_lines"] = tuple(line.strip() for line in source_lines if re.match(r"^return\s+[^;]+;\s*$", line.strip()))
        source_decl = _source_decl_from_cod_source_lines(source_lines, getattr(func, "name", None))
        if source_decl is None:
            return changed
        current_proto = getattr(func, "prototype", None)
        opaque_source_types = _c_decl_requires_opaque_typedefs_8616(source_decl)
        try:
            parsed_name, parsed_proto, _ = _parse_c_prototype_8616(source_decl)
        except Exception:
            parsed_name = None
            parsed_proto = None
        else:
            if parsed_proto is not None:
                parsed_proto = parsed_proto.with_arch(project.arch)
        active_proto = current_proto
        source_cc = _source_prototype_calling_convention_8616(project)
        if current_proto is not None and parsed_proto is not None:
            current_args = list(getattr(current_proto, "args", ()) or ())
            parsed_args = list(getattr(parsed_proto, "args", ()) or ())
            if len(current_args) == len(parsed_args):
                merged_args = current_args if opaque_source_types else parsed_args
                with contextlib.suppress(ValueError):
                    active_proto = current_proto.__class__(
                        merged_args,
                        parsed_proto.returnty,
                        arg_names=getattr(current_proto, "arg_names", None),
                        variadic=getattr(current_proto, "variadic", False),
                    ).with_arch(project.arch)
                    annotate_function(
                        project,
                        func_addr,
                        name=getattr(func, "name", None) or parsed_name,
                        prototype=active_proto,
                        calling_convention=source_cc,
                    )
                    changed = True
        elif parsed_proto is not None and not opaque_source_types:
            with contextlib.suppress(ValueError):
                annotate_function(
                    project,
                    func_addr,
                    name=getattr(func, "name", None) or parsed_name,
                    c_decl=source_decl,
                    calling_convention=source_cc,
                )
                changed = True
                active_proto = getattr(func, "prototype", parsed_proto)
        if active_proto is not None:
            source_arg_names = _split_source_arg_names_8616(_source_args_from_cod_source_lines(source_lines, getattr(func, "name", None)))
            if source_arg_names and len(source_arg_names) == len(getattr(active_proto, "args", ()) or ()):
                with contextlib.suppress(ValueError):
                    annotate_function(
                        project,
                        func_addr,
                        name=getattr(func, "name", None),
                        prototype=active_proto,
                        calling_convention=source_cc,
                        arg_names=source_arg_names,
                    )
                    changed = True
        return changed

    return _impl()


def apply_x86_16_metadata_annotations(
    project,
    *,
    func_addr: int | None = None,
    cod_metadata=None,
    lst_metadata=None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> bool:
    def _impl():
        changed = False

        if lst_metadata is not None:
            for offset, name in getattr(lst_metadata, "data_labels", {}).items():
                if project.kb.labels.get(offset) != name:
                    project.kb.labels[offset] = name
                    changed = True

            if func_addr is not None:
                code_name = getattr(lst_metadata, "code_labels", {}).get(func_addr)
                if isinstance(code_name, str) and code_name:
                    func = project.kb.functions.function(addr=func_addr, create=True)
                    if func is not None and getattr(func, "name", None) != code_name:
                        func.name = code_name
                        changed = True

        if func_addr is not None and cod_metadata is not None:
            stack_aliases = getattr(cod_metadata, "stack_aliases", None) or {}
            source_lines = tuple(getattr(cod_metadata, "source_lines", ()) or ())
            source_local_types = _source_function_pointer_local_types_8616(project, source_lines) if source_lines else {}
            if stack_aliases:
                typed_stack_aliases = {}
                for bp_disp, alias in stack_aliases.items():
                    spec = known_cod_object_spec(alias)
                    source_type = source_local_types.get(alias) if isinstance(alias, str) else None
                    if source_type is not None:
                        typed_stack_aliases[bp_disp] = {"name": alias, "type": source_type}
                    elif spec is None:
                        typed_stack_aliases[bp_disp] = alias
                        continue
                    else:
                        typed_stack_aliases[bp_disp] = _typed_cod_spec_dict_8616(spec)
                annotate_function(project, func_addr, bp_stack_vars=typed_stack_aliases)
                changed = True

        if cod_metadata is not None:
            changed |= _apply_known_helper_signatures(project, cod_metadata)
            source_lines = tuple(getattr(cod_metadata, "source_lines", ()) or ())
            if source_lines:
                func = project.kb.functions.function(addr=func_addr, create=True)
                if func is None:
                    raise KeyError(func_addr)
                changed |= _apply_source_prototype_annotations_8616(project, func_addr, func, source_lines)

        if func_addr is not None and synthetic_globals:
            seen_addrs: set[int] = set()
            for addr, (raw_name, _width) in synthetic_globals.items():
                if addr in seen_addrs:
                    continue
                seen_addrs.add(addr)
                spec = known_cod_object_spec(raw_name)
                if spec is None:
                    continue
                annotate_function(
                    project,
                    func_addr,
                    global_vars={
                        addr: _typed_cod_spec_dict_8616(spec)
                    },
                )
                changed = True

        return changed

    return _impl()


def decompile_function(project, func_addr: int, **annotations):
    cfg = project.analyses.CFGFast(normalize=True)
    cod_metadata = annotations.get("cod_metadata")
    lst_metadata = annotations.get("lst_metadata")
    synthetic_globals = annotations.get("synthetic_globals")
    if cod_metadata is not None or lst_metadata is not None or synthetic_globals is not None:
        apply_x86_16_metadata_annotations(
            project,
            func_addr=func_addr,
            cod_metadata=cod_metadata,
            lst_metadata=lst_metadata,
            synthetic_globals=synthetic_globals,
        )
    seed_calling_conventions(cfg)
    func = cfg.functions[func_addr]
    direct_annotations = {
        key: annotations[key]
        for key in (
            "name",
            "c_decl",
            "prototype",
            "calling_convention",
            "arg_names",
            "stack_vars",
            "bp_stack_vars",
            "global_vars",
        )
        if key in annotations
    }
    if direct_annotations:
        annotate_function(project, func_addr, **direct_annotations)
        func = project.kb.functions[func_addr]
    apply_x86_16_metadata_annotations(
        project,
        func_addr=func_addr,
        cod_metadata=cod_metadata,
        lst_metadata=lst_metadata,
        synthetic_globals=synthetic_globals,
    )
    return project.analyses.Decompiler(func, cfg=cfg)
