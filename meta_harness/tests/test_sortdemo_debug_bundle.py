from __future__ import annotations  # noqa: D100

import importlib.util
from pathlib import Path


def _load_module():  # noqa: ANN202
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "capture_sortdemo_debug_bundle.py"
    spec = importlib.util.spec_from_file_location("capture_sortdemo_debug_bundle", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_collect_cod_window_lines_keeps_nearby_source_comments() -> None:  # noqa: D103
    module = _load_module()
    cod_text = "\n".join(
        [
            "demo\tPROC NEAR",
            ";|*** int demo(void)",
            "    *** 1000 55             push bp",
            "    *** 1001 8B EC          mov bp, sp",
            ";|*** if (x) {",
            "    *** 1003 74 02          je 1007",
            "    *** 1005 90             nop",
            "    *** 1006 C3             ret",
            "demo\tENDP",
        ]
    )

    window = module._collect_cod_window_lines(cod_text, 0x1003, radius=1)

    assert ";|*** if (x) {" in window
    assert "    *** 1001 8B EC          mov bp, sp" in window
    assert "    *** 1003 74 02          je 1007" in window
    assert "    *** 1005 90             nop" in window
