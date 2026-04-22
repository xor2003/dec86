def _attach_access_trait_field_names(
    project: Any,
    codegen: Any,
    *,
    should_attach_access_trait_names: Callable[[Any], bool],
    load_access_rewrite_artifact: Callable[[Any, Any], AccessRewriteArtifact | None],
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None],
    access_trait_variable_key: Callable[[Any], BaseKey | None],
    stack_object_name: Callable[[int], str],
    access_trait_field_name: Callable[[int, int], str],
    replace_c_children: ReplaceCChildren
) -> bool: ...


def _should_attach_access_trait_names(codegen: Any, *, has_access_rewrite_artifact: Callable[[Any], bool]) -> bool: ...
