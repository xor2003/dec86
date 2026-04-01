from __future__ import annotations

import re

from angr.analyses import CFGFast, Decompiler
from angr.sim_type import SimTypeFunction
from angr.utils.library import convert_cproto_to_py

from .analysis_helpers import seed_calling_conventions
from .analysis_helpers import known_helper_signature_decl
from .cod_known_objects import known_cod_object_spec


ANNOTATION_KEY = "x86_16_annotations"


def _annotation_dict(function):
    return function.info.setdefault(
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
    func = project.kb.functions.function(addr=func_addr, create=True)
    if func is None:
        raise KeyError(func_addr)
    annotations = _annotation_dict(func)

    parsed_name = None
    parsed_proto = None
    if c_decl is not None:
        parsed_name, parsed_proto, _ = convert_cproto_to_py(c_decl)
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
        decl = known_helper_signature_decl(call_name) or known_helper_signature_decl(call_name.lstrip("_"))
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


def apply_x86_16_metadata_annotations(
    project,
    *,
    func_addr: int | None = None,
    cod_metadata=None,
    lst_metadata=None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> bool:
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
        if stack_aliases:
            annotate_function(project, func_addr, bp_stack_vars=stack_aliases)
            changed = True

    if cod_metadata is not None:
        changed |= _apply_known_helper_signatures(project, cod_metadata)
        source_lines = tuple(getattr(cod_metadata, "source_lines", ()) or ())
        if source_lines:
            func = project.kb.functions.function(addr=func_addr, create=True)
            if func is None:
                raise KeyError(func_addr)
            annotations = _annotation_dict(func)
            annotations["source_lines"] = source_lines
            annotations["source_return_lines"] = tuple(
                line.strip()
                for line in source_lines
                if re.match(r"^return\s+[^;]+;\s*$", line.strip())
            )

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
                    addr: {
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
                },
            )
            changed = True

    return changed


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
