from __future__ import annotations

from angr_platforms.X86_16.cod_source_rewrites import (
    COD_SOURCE_REWRITE_SPECS,
    COD_SOURCE_REWRITE_SPECS_BY_NAME,
    COD_SOURCE_REWRITE_REGISTRY,
    cod_source_rewrite_description,
    cod_source_rewrite_names,
    cod_source_rewrite_summary,
    describe_x86_16_source_backed_rewrite_status,
    get_cod_source_rewrite_spec,
)


def test_cod_source_rewrite_registry_is_keyed_and_unique():
    names = [spec.name for spec in COD_SOURCE_REWRITE_SPECS]
    assert names == list(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert len(names) == len(set(names))
    assert set(names) == {
        "configcrts",
        "setgear",
        "sethook",
        "rotate_pt",
        "mousepos",
        "tidshowrange",
    }


def test_cod_source_rewrite_registry_lookup_matches_spec_objects():
    for spec in COD_SOURCE_REWRITE_SPECS:
        assert get_cod_source_rewrite_spec(spec.name) is spec


def test_cod_source_rewrite_registry_exposes_name_order():
    assert COD_SOURCE_REWRITE_REGISTRY.names() == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_summary_matches_registry_contents():
    summary = cod_source_rewrite_summary()
    assert summary["count"] == len(COD_SOURCE_REWRITE_SPECS)
    assert summary["names"] == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_description_matches_registry_contents():
    description = cod_source_rewrite_description()
    assert description["count"] == len(COD_SOURCE_REWRITE_SPECS)
    assert description["names"] == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert [item["name"] for item in description["specs"]] == list(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_status_matches_registry_contents():
    status = describe_x86_16_source_backed_rewrite_status()

    assert status["count"] == len(COD_SOURCE_REWRITE_SPECS)
    assert status["names"] == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert [item["name"] for item in status["specs"]] == list(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_names_matches_registry_contents():
    assert cod_source_rewrite_names() == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_registry_behaves_like_a_container():
    assert len(COD_SOURCE_REWRITE_REGISTRY) == len(COD_SOURCE_REWRITE_SPECS)
    assert [spec.name for spec in COD_SOURCE_REWRITE_REGISTRY] == [spec.name for spec in COD_SOURCE_REWRITE_SPECS]
    assert "rotate_pt" in COD_SOURCE_REWRITE_REGISTRY
    assert "missing" not in COD_SOURCE_REWRITE_REGISTRY


def test_cod_source_rewrite_registry_supports_mapping_access():
    assert list(COD_SOURCE_REWRITE_REGISTRY.keys()) == list(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert list(COD_SOURCE_REWRITE_REGISTRY.values()) == list(COD_SOURCE_REWRITE_SPECS)
    assert list(COD_SOURCE_REWRITE_REGISTRY.items()) == list(COD_SOURCE_REWRITE_SPECS_BY_NAME.items())
    assert COD_SOURCE_REWRITE_REGISTRY["rotate_pt"] is COD_SOURCE_REWRITE_SPECS_BY_NAME["rotate_pt"]


def test_cod_source_rewrite_registry_lookup_is_read_only():
    try:
        COD_SOURCE_REWRITE_REGISTRY.by_name["missing"] = COD_SOURCE_REWRITE_SPECS[0]  # type: ignore[index]
    except TypeError:
        return
    raise AssertionError("registry lookup map should be read-only")


def test_cod_source_rewrite_spec_lookup_map_is_read_only():
    try:
        COD_SOURCE_REWRITE_SPECS_BY_NAME["missing"] = COD_SOURCE_REWRITE_SPECS[0]  # type: ignore[index]
    except TypeError:
        return
    raise AssertionError("spec lookup map should be read-only")
