from __future__ import annotations

from pathlib import Path

import inertia_decompiler.cli as decompile
import inertia_decompiler.sidecar_metadata as sidecar_metadata


REPO_ROOT = Path(__file__).resolve().parents[2]
LIFE_EXE = REPO_ROOT / "LIFE.EXE"


def test_life_rand_decompiles_to_c_without_asm_fallback() -> None:
    project = decompile._build_project(LIFE_EXE, force_blob=False, base_addr=0x1000, entry_point=0)
    metadata = sidecar_metadata._load_lst_metadata(LIFE_EXE, project, allow_peer_exe=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        data_references=True,
        force_segment=True,
        resolve_indirect_jumps=False,
        show_progressbar=False,
        regions=[(0x11732, 0x1175E)],
    )
    function = cfg.kb.functions.floor_func(0x11732)

    status, payload = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=8,
        api_style="c",
        binary_path=LIFE_EXE,
        lst_metadata=metadata,
    )

    assert status == "ok"
    assert "short rand(void)" in payload
    assert "sub_2cc0();" in payload
    assert "/* == asm ==" not in payload
