from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.compiler_helpers import (
    CompilerHelperEvidenceKind8616,
    identify_x86_16_compiler_helper_at_8616,
    is_x86_16_stack_probe_name_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_stage import _target_is_stack_probe_helper_8616


MSC_ANCHKSTK_BYTES = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")


def _project_with_memory(code: bytes, *, base: int = 0x1000):
    def _load(addr: int, size: int):
        offset = addr - base
        if offset < 0:
            raise KeyError(addr)
        return code[offset : offset + size]

    return SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=_load)),
    )


def test_identify_msc_anchkstk_from_binary_bytes_without_sidecars():
    project = _project_with_memory(MSC_ANCHKSTK_BYTES)

    evidence = identify_x86_16_compiler_helper_at_8616(project, 0x1000)

    assert evidence is not None
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE
    assert evidence.name == "aNchkstk"
    assert evidence.pattern_name == "msc_aNchkstk_popcx_sp_ax"
    assert evidence.matched_bytes == len(MSC_ANCHKSTK_BYTES)


def test_stack_probe_name_normalization_covers_msc_and_chkstk_spellings():
    assert is_x86_16_stack_probe_name_8616("__aNchkstk") is True
    assert is_x86_16_stack_probe_name_8616("_chkstk") is True
    assert is_x86_16_stack_probe_name_8616("__analloca_probe") is True
    assert is_x86_16_stack_probe_name_8616("clock") is False


def test_selector_effect_gate_uses_binary_stack_probe_evidence_without_sidecar_name():
    project = _project_with_memory(MSC_ANCHKSTK_BYTES)

    assert _target_is_stack_probe_helper_8616(project, 0x1000, "sub_1000") is True
