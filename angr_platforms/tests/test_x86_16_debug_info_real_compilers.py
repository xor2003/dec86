from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts.build_debug_info_corpus import build_one, selected_specs

KVIKDOS = Path("/home/xor/kvikdos/kvikdos")
DOSBOX = Path("/opt/dosbox-staging/dosbox") if Path("/opt/dosbox-staging/dosbox").exists() else Path("/usr/bin/dosbox")
COMPILERS = Path("/home/xor/inertia_player/dos_compilers")


def _real_compiler_matrix_available() -> bool:
    required = [
        KVIKDOS,
        COMPILERS / "Microsoft C v5" / "CL.EXE",
        COMPILERS / "Microsoft C v6ax" / "BIN" / "CL.EXE",
        COMPILERS / "Microsoft C v8" / "BIN" / "CL.EXE",
        COMPILERS / "Borland Turbo C v2" / "TCC.EXE",
    ]
    return all(path.exists() for path in required) and shutil.which("wine") is not None


@pytest.mark.skipif(not _real_compiler_matrix_available(), reason="DOS compiler matrix is not available")
def test_real_compiler_debug_info_corpus_representative_formats(tmp_path):
    results = {
        spec.name: build_one(spec, tmp_path, kvikdos=KVIKDOS, dosbox=DOSBOX, compilers_root=COMPILERS)
        for spec in selected_specs("msc5,msc6,msc8,tc2")
    }

    assert results["msc5"]["built"]
    nb00 = results["msc5"]["debug"]["nb00"]
    assert nb00["source_files"] == ["c:\\DBG.C"]
    assert nb00["line_count"] == 13
    assert nb00["type_record_names"][:3] == ["pair_s", "left", "right"]
    assert {"name": "left", "offset": 0, "owner_type_index": 0x205} in nb00["type_members"]
    assert {"name": "right", "offset": 2, "owner_type_index": 0x205} in nb00["type_members"]
    assert "helper" in nb00["debug_identifiers"]
    assert "local_pair" in nb00["debug_identifiers"]

    assert results["msc6"]["built"]
    nb0204 = results["msc6"]["debug"]["nb0204"]
    assert nb0204["version"] == "NB02"
    assert nb0204["source_files"] == ["c:\\DBG.C"]
    assert nb0204["line_count"] == 13
    assert nb0204["type_record_names"][:3] == ["pair_s", "left", "right"]
    assert "global_counter" in nb0204["debug_identifiers"]

    if not results["msc8"]["built"]:
        pytest.skip("Microsoft C v8 debug-info sample did not build in this local compiler matrix")
    nb09 = results["msc8"]["debug"]["nb0204"]
    assert nb09["version"] == "NB09"
    assert nb09["line_count"] == 13
    assert nb09["type_record_names"][:3] == ["left", "right", "pair_s"]
    assert {"name": "left", "offset": 0, "owner_type_index": 0x1000} in nb09["type_members"]
    assert {"name": "right", "offset": 2, "owner_type_index": 0x1000} in nb09["type_members"]

    assert results["tc2"]["built"]
    tdinfo = results["tc2"]["debug"]["tdinfo"]
    assert tdinfo["source_files"] == ["DBG.C", "C:\\DBG.C"]
    assert "_HELPER" in tdinfo["candidate_identifiers"]
    assert {"name": "LEFT", "offset": 0, "owner_type_index": 25, "type_index": 4} in tdinfo["type_members"]
    assert {"name": "RIGHT", "offset": 2, "owner_type_index": 25, "type_index": 4} in tdinfo["type_members"]
    assert any(span["name"] == "symbol_records" for span in tdinfo["raw_table_spans"])
