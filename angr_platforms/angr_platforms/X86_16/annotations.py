from __future__ import annotations

from angr.analyses import CFGFast, Decompiler
from angr.sim_type import SimTypeFunction
from angr.utils.library import convert_cproto_to_py


ANNOTATION_KEY = "x86_16_annotations"


def _annotation_dict(function):
    return function.info.setdefault(
        ANNOTATION_KEY,
        {
            "stack_vars": {},
            "global_vars": {},
        },
    )


def _normalize_bp_disp(offset: int) -> int:
    return offset - 2


def annotate_function(
    project,
    func_addr: int,
    *,
    name: str | None = None,
    c_decl: str | None = None,
    prototype: SimTypeFunction | None = None,
    arg_names: list[str] | tuple[str, ...] | None = None,
    stack_vars: dict[int, str | dict] | None = None,
    bp_stack_vars: dict[int, str | dict] | None = None,
    global_vars: dict[int, str] | None = None,
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

    if arg_names is not None:
        if func.prototype is None:
            raise ValueError("Cannot assign argument names without a prototype.")
        func.prototype = SimTypeFunction(
            func.prototype.args,
            func.prototype.returnty,
            arg_names=tuple(arg_names),
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
        for addr, var_name in global_vars.items():
            annotations["global_vars"][addr] = var_name
            project.kb.labels[addr] = var_name

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


def decompile_function(project, func_addr: int, **annotations):
    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.functions[func_addr]
    if annotations:
        annotate_function(project, func_addr, **annotations)
        func = project.kb.functions[func_addr]
    return project.analyses.Decompiler(func, cfg=cfg)
