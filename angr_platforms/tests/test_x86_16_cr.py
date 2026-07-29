from __future__ import annotations

import pytest
from angr_platforms.X86_16.cr import CR


def test_control_registers_start_as_real_mode_zero_state() -> None:
    registers = CR()

    assert registers.get_crn(0) == 0
    assert registers.get_crn(1) == 0
    assert registers.get_crn(2) == 0
    assert registers.get_crn(3) == 0
    assert registers.get_crn(4) == 0
    assert registers.is_protected() is False
    assert registers.is_ena_paging() is False


def test_control_register_helpers_report_owned_register_fields() -> None:
    registers = CR()
    registers.cr0 = 1 << 31
    registers.cr3 = 0x12345000

    assert registers.is_ena_paging() is True
    assert registers.get_pdir_base() == 0x12000


def test_control_register_lookup_rejects_unknown_register_index() -> None:
    with pytest.raises(ValueError, match="Invalid CR index: 5"):
        CR().get_crn(5)
