from __future__ import annotations

import angr_platforms.X86_16  # noqa: F401
import pyvex.const as pyvex_const
from pyvex.lifting.util import vex_helper


def test_pyvex_runtime_compatibility_is_applied() -> None:
    assert hasattr(pyvex_const.get_type_size, "cache_info")
    assert hasattr(pyvex_const.get_type_spec_size, "cache_info")
    assert vex_helper.Type.int_16 == vex_helper.Type.int_16
