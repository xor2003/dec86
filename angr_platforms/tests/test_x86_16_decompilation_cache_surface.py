from pathlib import Path

from inertia_decompiler.cache import DECOMPILATION_CACHE_SOURCE_FILES


def test_decompilation_cache_surface_includes_tail_validation_layers():
    names = {Path(path).name for path in DECOMPILATION_CACHE_SOURCE_FILES}

    assert "tail_validation.py" in names
    assert "tail_validation_fingerprint.py" in names
    assert "tail_validation_routing.py" in names
