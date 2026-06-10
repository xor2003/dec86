from types import SimpleNamespace

from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler import cli_core
from inertia_decompiler.sidecar_metadata import attach_lst_metadata_to_project
from inertia_decompiler.x86_16_exact_slice import mark_function_original_addr


def test_isolated_project_recovery_target_uses_original_addr_for_rebased_slice():
    function = SimpleNamespace(addr=0x1000, info={})
    mark_function_original_addr(function, 0x10010)
    isolated_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x13FFF))
    )

    candidate_addr, image_end = cli_core._isolated_project_recovery_target_8616(
        function,
        isolated_project,
        fallback_linked_base=0x1000,
        fallback_max_addr=0x104D,
    )

    assert candidate_addr == 0x10010
    assert image_end == 0x14000


def test_isolated_project_recovery_target_handles_relative_image_size():
    function = SimpleNamespace(addr=0x1000, info={"inertia_original_addr": 0x10010})
    isolated_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x4000))
    )

    candidate_addr, image_end = cli_core._isolated_project_recovery_target_8616(
        function,
        isolated_project,
        fallback_linked_base=0x1000,
        fallback_max_addr=0x104D,
    )

    assert candidate_addr == 0x10010
    assert image_end == 0x14001


def test_call_order_gate_ignores_inactive_selftest_source_branch():
    emitted = """
/// int main(void)
/// {
/// #if defined(SORTDEMO_FUNCTION_SELFTEST)
///     return sortdemo_function_selftest();
/// #else
///     InitBars();
///     InitMenu();
///     RunMenu();
/// #endif
/// }
int main(void)
{
    InitBars();
    InitMenu();
    RunMenu();
    return 0;
}
"""

    assert cli_core._expected_call_order_from_original_8616(emitted) == ["InitBars", "InitMenu", "RunMenu"]
    assert cli_core._call_order_gate_violations_8616(emitted) == []


def test_call_order_gate_ignores_inactive_os2_source_branch_for_dos_target():
    emitted = """
/// void Beep(int frequency, int duration)
/// {
/// #if defined( OS2 )
///     DosBeep( frequency, duration );
/// #else
///     outp( 0x43, 0xb6 );
///     Sleep( (clock_t)duration );
/// #endif
/// }
void Beep(int frequency, int duration)
{
    outp(0x43, 0xb6);
    Sleep(duration);
}
"""

    assert cli_core._expected_call_order_from_original_8616(emitted) == ["outp", "Sleep"]
    assert cli_core._call_order_gate_violations_8616(emitted) == []


def test_preserve_source_label_uses_original_addr_for_rebased_slice():
    source = SimpleNamespace(addr=0x1000, name="main", info={})
    recovered = SimpleNamespace(addr=0x10010, name="sub_10010", info={})
    mark_function_original_addr(source, 0x10010)

    assert cli_core._preserve_source_label_for_recovered_function_8616(source, recovered) is True
    assert recovered.name == "main"
    assert recovered.info["inertia_original_addr"] == 0x10010


def test_attach_lst_metadata_to_project_populates_fresh_project_labels():
    metadata = LSTMetadata(
        code_labels={0x10010: "main", 0x12A29: "settextrows"},
        data_labels={0x1BA2: "cRow"},
        absolute_addrs=True,
        source_format="cod_listing",
        cod_path="SORTDEMO.COD",
    )
    project = SimpleNamespace(kb=SimpleNamespace(labels={}))

    assert attach_lst_metadata_to_project(project, metadata) is True
    assert project._inertia_lst_metadata is metadata
    assert project.kb.labels[0x10010] == "main"
    assert project.kb.labels[0x12A29] == "settextrows"
    assert project.kb.labels[0x1BA2] == "cRow"
