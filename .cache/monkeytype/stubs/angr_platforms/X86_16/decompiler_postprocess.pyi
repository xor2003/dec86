from types import SimpleNamespace


def _classify_return_shape_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool: ...


def _function_complexity_8616(project: SimpleNamespace, function: SimpleNamespace) -> tuple[int, int]: ...


def _is_tiny_function_8616(project: SimpleNamespace, function: SimpleNamespace) -> bool: ...


def _normalize_arg_names_8616(
    arg_names: tuple[str | None, ...] | list[str | None] | None,
    count: int
) -> list[str | None]: ...


def _promote_stack_prototype_from_bp_loads_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool: ...


def _prune_return_address_stack_arguments_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool: ...


def _return_value_shape_8616(
    retval: <class 'Union'>[angr.analyses.decompiler.structured_codegen.c.CConstant, angr.analyses.decompiler.structured_codegen.c.CFunctionCall]
) -> str | None: ...


def _source_return_shape_8616(source_return_lines: <class 'Union'>[Tuple[str], Tuple[()]]) -> str | None: ...


def _stack_arg_has_pointer_evidence_8616(
    codegen: SimpleNamespace,
    variable: <class 'Union'>[None, angr.sim_variable.SimStackVariable]
) -> bool: ...


def _unwrap_synthetic_wide_return_8616(
    retval: <class 'Union'>[angr.analyses.decompiler.structured_codegen.c.CConstant, angr.analyses.decompiler.structured_codegen.c.CFunctionCall]
) -> None: ...
