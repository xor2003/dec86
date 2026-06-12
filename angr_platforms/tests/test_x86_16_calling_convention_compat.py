from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong
from angr_platforms.X86_16.calling_convention_compat import (
    _set_function_prototype_8616,
    apply_x86_16_wide_stack_prototype_evidence,
)


def test_wide_stack_prototype_evidence_preserves_non_guessed_source_prototype():
    arch = archinfo.ArchX86()
    source_proto = SimTypeFunction([SimTypeLong(False)], SimTypeBottom(label="void")).with_arch(arch)
    wide_proto = SimTypeFunction([SimTypeLong(False)], SimTypeLong(False)).with_arch(arch)
    function = SimpleNamespace(
        prototype=source_proto,
        is_prototype_guessed=False,
        project=SimpleNamespace(arch=arch),
    )

    _cc, selected = _set_function_prototype_8616(function, "wide-cc", wide_proto)

    assert selected is source_proto
    assert function.prototype is source_proto
    assert not hasattr(function, "calling_convention")


def test_apply_wide_stack_prototype_evidence_refuses_non_guessed_existing_prototype():
    arch = SimpleNamespace(name="86_16")
    source_proto = SimTypeFunction([SimTypeLong(False)], SimTypeBottom(label="void"))
    function = SimpleNamespace(prototype=source_proto, is_prototype_guessed=False)
    project = SimpleNamespace(arch=arch)

    changed = apply_x86_16_wide_stack_prototype_evidence(project, function)

    assert changed is False
    assert function.prototype is source_proto
