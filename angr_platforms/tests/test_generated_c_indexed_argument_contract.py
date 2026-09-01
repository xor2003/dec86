from scripts.generated_c_contracts import (
    GeneratedCContract,
    GeneratedCContractStatus,
)
from scripts.generated_c_indexed_argument_contract import IndexedArgumentUseRequirement

_REQUIREMENT = IndexedArgumentUseRequirement(
    base_name="arg_6",
    index_name="local_2",
    minimum_count=3,
    guard_call="sub_10010",
    required_guard_arguments=(104, 118),
)


def test_segmented_near_pointer_index_uses_satisfy_structural_contract() -> None:
    source = """
    unsigned short SEG_U16(unsigned short segment, unsigned short offset);
    unsigned short PTR_U16(unsigned short *pointer);
    void *SEG_PTR(unsigned short segment, unsigned short offset);
    unsigned short sub_10010(void *value, unsigned short letter);
    void sub_106d6(unsigned short, unsigned short);
    unsigned short f(unsigned short inertia_ds, unsigned short *arg_6, unsigned short local_2) {
        if (sub_10010(SEG_PTR(inertia_ds, SEG_U16(inertia_ds, PTR_U16(arg_6) + (local_2 << 1))), 104)) { }
        if (sub_10010(SEG_PTR(inertia_ds, SEG_U16(inertia_ds, PTR_U16(arg_6) + (local_2 << 1))), 118)) { }
        sub_106d6(676, SEG_U16(inertia_ds, PTR_U16(arg_6) + (local_2 << 1)));
        return 0;
    }
    """

    result = GeneratedCContract(indexed_argument_uses=(_REQUIREMENT,)).assess(source)

    assert result.status is GeneratedCContractStatus.PASSED
    assert result.missing_indexed_argument_uses == ()


def test_unscaled_pointer_arithmetic_fails_structural_contract() -> None:
    source = """
    unsigned short SEG_U16(unsigned short segment, unsigned short offset);
    unsigned short PTR_U16(unsigned short *pointer);
    unsigned short f(unsigned short inertia_ds, unsigned short *arg_6, unsigned short local_2) {
        return SEG_U16(inertia_ds, PTR_U16(arg_6) + local_2);
    }
    """

    result = GeneratedCContract(indexed_argument_uses=(_REQUIREMENT,)).assess(source)

    assert result.status is GeneratedCContractStatus.FAILED
    assert result.missing_indexed_argument_uses == (_REQUIREMENT.label(),)
