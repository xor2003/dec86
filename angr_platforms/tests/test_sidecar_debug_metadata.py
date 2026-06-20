from __future__ import annotations

from angr_platforms.X86_16.lst_extract import (
    DebugEnumMemberEvidence,
    DebugSymbolEvidence,
    DebugTypeDescriptorEvidence,
    DebugTypeMemberEvidence,
    DebugTypeReferenceEvidence,
    LSTMetadata,
)
from inertia_decompiler.sidecar_cache import _deserialize_lst_metadata, _serialize_lst_metadata


def test_sidecar_metadata_cache_preserves_debug_information_fields():
    metadata = LSTMetadata(
        data_labels={0x2000: "global_counter"},
        code_labels={0x1000: "main"},
        debug_source_files=("DBGPROBE.C",),
        debug_type_names=("Pair", "left", "right"),
        debug_type_descriptors=(
            DebugTypeDescriptorEvidence(
                type_index=0x201,
                kind="STRUCT",
                name="Pair",
                size=4,
                attributes=0x10,
                source="turbo_debug_tdinfo",
            ),
            DebugTypeDescriptorEvidence(
                type_index=0x220,
                kind="FUNCTION",
                name="callback",
                size=0,
                return_type_index=0x201,
                call_kind=2,
                attributes=0x20,
                source="turbo_debug_tdinfo",
            ),
            DebugTypeDescriptorEvidence(
                type_index=0x230,
                kind="ENUM",
                name="Color",
                size=2,
                base_type_index=0x10,
                attributes=0x30,
                lower_bound=0,
                upper_bound=3,
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_type_references=(
            DebugTypeReferenceEvidence(
                name="Pair",
                type_index=0x201,
                symbol_class="TYPEDEF",
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_symbols=(
            DebugSymbolEvidence(
                name="_main",
                symbol_class="0x0105",
                storage="procedure",
                offset=0x20,
                segment=0,
                linear_addr=0x1020,
                length=0x24,
                type_index=0x220,
                attributes=(("debug_start", "1"), ("flags", "0")),
                source="codeview_nb0204",
            ),
            DebugSymbolEvidence(
                name="local_i",
                symbol_class="AUTO",
                storage="auto",
                offset=0xFFFE,
                signed_offset=-2,
                segment=0,
                linear_addr=0xFFFE,
                type_index=0x74,
                attributes=(("record_index", "2"),),
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_type_members=(
            DebugTypeMemberEvidence(
                name="left",
                offset=0,
                owner_type_index=0x201,
                type_index=0x74,
                leaf_index=1,
                source="codeview_nb00",
            ),
            DebugTypeMemberEvidence(
                name="right",
                offset=2,
                owner_type_index=0x201,
                type_index=0x74,
                attributes=0x40,
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_enum_members=(
            DebugEnumMemberEvidence(
                name="RED",
                value=1,
                owner_type_index=0x230,
                attributes=0x80,
                source="turbo_debug_tdinfo",
            ),
        ),
        debug_identifiers=("LOCAL_SUM", "RESULT"),
        debug_line_map={0x1000: (12, 0)},
        absolute_addrs=True,
        source_format="codeview_nb00+turbo_debug_tdinfo",
    )

    restored = _deserialize_lst_metadata(_serialize_lst_metadata(metadata))

    assert restored is not None
    assert restored.debug_source_files == ("DBGPROBE.C",)
    assert restored.debug_type_names == ("Pair", "left", "right")
    assert restored.debug_type_descriptors == (
        DebugTypeDescriptorEvidence(
            type_index=0x201,
            kind="STRUCT",
            name="Pair",
            size=4,
            attributes=0x10,
            source="turbo_debug_tdinfo",
        ),
        DebugTypeDescriptorEvidence(
            type_index=0x220,
            kind="FUNCTION",
            name="callback",
            size=0,
            return_type_index=0x201,
            call_kind=2,
            attributes=0x20,
            source="turbo_debug_tdinfo",
        ),
        DebugTypeDescriptorEvidence(
            type_index=0x230,
            kind="ENUM",
            name="Color",
            size=2,
            base_type_index=0x10,
            attributes=0x30,
            lower_bound=0,
            upper_bound=3,
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_type_references == (
        DebugTypeReferenceEvidence(
            name="Pair",
            type_index=0x201,
            symbol_class="TYPEDEF",
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_symbols == (
        DebugSymbolEvidence(
            name="_main",
            symbol_class="0x0105",
            storage="procedure",
            offset=0x20,
            segment=0,
            linear_addr=0x1020,
            length=0x24,
            type_index=0x220,
            attributes=(("debug_start", "1"), ("flags", "0")),
            source="codeview_nb0204",
        ),
        DebugSymbolEvidence(
            name="local_i",
            symbol_class="AUTO",
            storage="auto",
            offset=0xFFFE,
            signed_offset=-2,
            segment=0,
            linear_addr=0xFFFE,
            type_index=0x74,
            attributes=(("record_index", "2"),),
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_type_members == (
        DebugTypeMemberEvidence(
            name="left",
            offset=0,
            owner_type_index=0x201,
            type_index=0x74,
            leaf_index=1,
            source="codeview_nb00",
        ),
        DebugTypeMemberEvidence(
            name="right",
            offset=2,
            owner_type_index=0x201,
            type_index=0x74,
            attributes=0x40,
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_enum_members == (
        DebugEnumMemberEvidence(
            name="RED",
            value=1,
            owner_type_index=0x230,
            attributes=0x80,
            source="turbo_debug_tdinfo",
        ),
    )
    assert restored.debug_identifiers == ("LOCAL_SUM", "RESULT")
    assert restored.debug_line_map == {0x1000: (12, 0)}
