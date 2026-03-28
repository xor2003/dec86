from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

_ACCESS_TRAIT_REWRITE_TARGETS = _decompile._ACCESS_TRAIT_REWRITE_TARGETS
_should_attach_access_trait_names = _decompile._should_attach_access_trait_names


def test_access_trait_rewrite_targets_are_explicit_stable_examples():
    assert _ACCESS_TRAIT_REWRITE_TARGETS == {"sub_1287", "_rotate_pt", "_ConfigCrts", "_TIDShowRange", "_SetGear", "_DrawRadarAlt", "_SetHook", "_ChangeWeather", "_LookDown", "_LookUp", "_MousePOS"}


def test_access_trait_rewrite_policy_only_enables_stable_examples():
    def make_codegen(name: str, addr: int):
        return SimpleNamespace(cfunc=SimpleNamespace(name=name, addr=addr))

    assert _should_attach_access_trait_names(make_codegen("sub_1287", 0x1287))
    assert _should_attach_access_trait_names(make_codegen("_rotate_pt", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_ConfigCrts", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_TIDShowRange", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_SetGear", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_DrawRadarAlt", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_SetHook", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_ChangeWeather", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_LookDown", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_LookUp", 0x1000))
    assert _should_attach_access_trait_names(make_codegen("_MousePOS", 0x1000))
