from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _normalize_stack_variable_identifiers_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_display_names import (
    reapply_stack_variable_projection_names_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def test_normalizer_uses_machine_bp_coordinate_for_projected_argument() -> None:
    codegen = _Codegen()
    variable = SimStackVariable(2, 2, base="bp", name="stack_sp_p2")
    cvar = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    prototype = SimTypeFunction(
        [SimTypeShort(False)],
        SimTypeShort(False),
        arg_names=["arg_4"],
    ).with_arch(codegen.project.arch)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[cvar],
        functy=prototype,
        statements=cvar,
        unified_local_vars={variable: {(cvar, cvar.variable_type)}},
        variables_in_use={variable: cvar},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
        display_name="arg_4",
    )

    _normalize_stack_variable_identifiers_8616(codegen)
    reapply_stack_variable_projection_names_8616(codegen)

    assert variable.name == "arg_4"
