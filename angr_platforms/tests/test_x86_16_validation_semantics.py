import pytest

from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.validation_semantics import assert_known_call_semantics_8616


def test_final_semantics_gate_allows_generic_vvar_temporaries():
    c_text = """
    void f(void)
    {
        unsigned short vvar_1;
        vvar_1 = 3;
        return;
    }
    """

    assert_known_call_semantics_8616(c_text, function_addr=0x1000)


def test_final_semantics_gate_rejects_raw_stack_placeholders():
    c_text = """
    void f(void)
    {
        unsigned short s_0;
        s_0 = 3;
        return;
    }
    """

    with pytest.raises(PipelineHardError, match="unresolved stack locals"):
        assert_known_call_semantics_8616(c_text, function_addr=0x1000)
