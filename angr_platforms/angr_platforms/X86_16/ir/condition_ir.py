from __future__ import annotations

# Layer: IR
# Responsibility: typed condition domain representation.
# Forbidden: late rewrite ownership and text-pattern semantics.
from dataclasses import dataclass, replace
from typing import Any, Literal

from .core import IRCondition, IRValue

ConditionOp = Literal[
    "and",
    "compare",
    "eq",
    "ne",
    "not",
    "or",
    "slt",
    "sle",
    "sgt",
    "sge",
    "ult",
    "ule",
    "ugt",
    "uge",
    "zero",
    "nonzero",
]

_COMPARE_SYMBOLS_8616: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "slt": "<",
    "sle": "<=",
    "sgt": ">",
    "sge": ">=",
    "ult": "<",
    "ule": "<=",
    "ugt": ">",
    "uge": ">=",
}

# ── JCC mnemonic families (flag aliases normalized) ──

JCC_EQ_MNEMONICS_8616: frozenset[str] = frozenset({"je", "jz"})
JCC_NE_MNEMONICS_8616: frozenset[str] = frozenset({"jne", "jnz"})
JCC_ULT_MNEMONICS_8616: frozenset[str] = frozenset({"jb", "jnae", "jc"})
JCC_UGE_MNEMONICS_8616: frozenset[str] = frozenset({"jae", "jnb", "jnc"})
JCC_ULE_MNEMONICS_8616: frozenset[str] = frozenset({"jbe", "jna"})
JCC_UGT_MNEMONICS_8616: frozenset[str] = frozenset({"ja", "jnbe"})
JCC_SLT_MNEMONICS_8616: frozenset[str] = frozenset({"jl", "jnge"})
JCC_SGE_MNEMONICS_8616: frozenset[str] = frozenset({"jge", "jnl"})
JCC_SLE_MNEMONICS_8616: frozenset[str] = frozenset({"jle", "jng"})
JCC_SGT_MNEMONICS_8616: frozenset[str] = frozenset({"jg", "jnle"})

_JCC_COMPARISON_MNEMONICS_8616: frozenset[str] = frozenset({"jo", "jno", "js", "jns", "jp", "jpe", "jpo", "jnp"})

JCC_TO_COND_8616: dict[str, ConditionOp] = {mnemonic: "eq" for mnemonic in JCC_EQ_MNEMONICS_8616}
JCC_TO_COND_8616.update({mnemonic: "ne" for mnemonic in JCC_NE_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "ult" for mnemonic in JCC_ULT_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "uge" for mnemonic in JCC_UGE_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "ule" for mnemonic in JCC_ULE_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "ugt" for mnemonic in JCC_UGT_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "slt" for mnemonic in JCC_SLT_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "sge" for mnemonic in JCC_SGE_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "sle" for mnemonic in JCC_SLE_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "sgt" for mnemonic in JCC_SGT_MNEMONICS_8616})
JCC_TO_COND_8616.update({mnemonic: "compare" for mnemonic in _JCC_COMPARISON_MNEMONICS_8616})

# Canonical list of all supported jcc synonyms, used for coverage checks.
_SUPPORTED_JCC_MNEMONICS_8616: frozenset[str] = frozenset(JCC_TO_COND_8616.keys())


# ── Condition builders from CMP/TEST sources ──


@dataclass(frozen=True, slots=True)
class ConditionIR:
    """Typed condition IR object — the canonical form for branches.

    Forbidden: flags-based conditions, tmp-based conditions.
    AGENTS rule: Conditions must be explicit (``x < y``, not ``flags & ZF``).
    """

    op: ConditionOp
    lhs: Any
    rhs: Any | None = None
    width_bits: int = 16
    source: tuple[str, ...] = ()
    src_insn: int | None = None
    block_addr: int | None = None
    producer_insn: int | None = None

    @property
    def is_comparison(self) -> bool:
        return self.op in {
            "eq",
            "ne",
            "slt",
            "sle",
            "sgt",
            "sge",
            "ult",
            "ule",
            "ugt",
            "uge",
        }

    @property
    def is_zero_test(self) -> bool:
        return self.op in {"zero", "nonzero"}

    @property
    def is_signed(self) -> bool:
        return self.op in {"slt", "sle", "sgt", "sge"}

    @property
    def is_unsigned(self) -> bool:
        return self.op in {"ult", "ule", "ugt", "uge"}


@dataclass(frozen=True, slots=True)
class ConditionFailure:
    reason: str
    source: tuple[str, ...] = ()
    detail: str = ""

    @property
    def is_failure(self) -> bool:
        return True


# Type alias for condition-or-failure returns
ConditionResult = ConditionIR | ConditionFailure


def build_condition_from_cmp_8616(
    lhs: Any,
    rhs: Any,
    jcc: str,
    *,
    width_bits: int = 16,
    src_insn: int | None = None,
    block_addr: int | None = None,
    producer_insn: int | None = None,
) -> ConditionResult:
    """Build a ConditionIR from CMP operands + JCC mnemonic.

    CMP lhs, rhs
    JCC label  →  ConditionIR(op, lhs, rhs)
    """
    op = JCC_TO_COND_8616.get(jcc.lower())
    if op is None:
        return ConditionFailure(
            "unsupported_jcc",
            source=("cmp", jcc),
            detail=f"JCC mnemonic '{jcc}' not in JCC_TO_COND_8616",
        )
    return ConditionIR(
        op=op,
        lhs=lhs,
        rhs=rhs,
        width_bits=width_bits,
        source=("cmp", jcc),
        src_insn=src_insn,
        block_addr=block_addr,
        producer_insn=producer_insn,
    )


def build_condition_from_test_8616(
    value: Any,
    jcc: str,
    *,
    width_bits: int = 16,
    src_insn: int | None = None,
    block_addr: int | None = None,
    producer_insn: int | None = None,
) -> ConditionResult:
    """Build a ConditionIR from TEST/OR/AND self-test + JCC mnemonic.

    test ax, ax  (or: or ax, ax / and ax, ax where both operands same)
    jz label  →  ConditionIR(ZERO, ax)
    """
    jcc = jcc.lower()
    if jcc in {"je", "jz"}:
        return ConditionIR(
            op="zero",
            lhs=value,
            width_bits=width_bits,
            source=("test", jcc),
            src_insn=src_insn,
            block_addr=block_addr,
            producer_insn=producer_insn,
        )
    if jcc in {"jne", "jnz"}:
        return ConditionIR(
            op="nonzero",
            lhs=value,
            width_bits=width_bits,
            source=("test", jcc),
            src_insn=src_insn,
            block_addr=block_addr,
            producer_insn=producer_insn,
        )
    return ConditionFailure(
        "unsupported_test_jcc",
        source=("test", jcc),
        detail=f"TEST JCC '{jcc}' not supported (only je/jz/jne/jnz)",
    )


def build_condition_from_compare_8616(
    op: ConditionOp,
    lhs: Any,
    rhs: Any,
    *,
    width_bits: int = 16,
    source: tuple[str, ...] = (),
    src_insn: int | None = None,
    block_addr: int | None = None,
    producer_insn: int | None = None,
) -> ConditionIR:
    """Direct ConditionIR constructor from known op and operands."""
    return ConditionIR(
        op=op,
        lhs=lhs,
        rhs=rhs,
        width_bits=width_bits,
        source=source,
        src_insn=src_insn,
        block_addr=block_addr,
        producer_insn=producer_insn,
    )


# ── Condition source tracking (on emulator) ──


@dataclass(slots=True)
class ConditionSource:
    """Lightweight record of last CMP/TEST for JCC consumption."""

    kind: str  # "cmp" or "test"
    lhs: Any | None = None
    rhs: Any | None = None
    semantics: tuple[Any, ...] | None = None
    fallthrough_from_jcc: str | None = None
    width_bits: int = 16
    addr: int | None = None
    block_addr: int | None = None


@dataclass(frozen=True, slots=True)
class ConditionEdgeEvidence:
    """Typed condition evidence for a control-flow edge, not an AST guard yet."""

    edge_block_addr: int
    condition: ConditionIR
    edge_kind: str
    source_jcc: str
    producer_insn: int | None = None


# ── Condition sorting/deduplication ──


def condition_sort_key_8616(cond: ConditionIR) -> tuple:
    """Deterministic sort key for ConditionIR."""
    return (
        cond.block_addr if isinstance(cond.block_addr, int) else -1,
        cond.src_insn if isinstance(cond.src_insn, int) else -1,
        cond.producer_insn if isinstance(cond.producer_insn, int) else -1,
        "".join(cond.source),
        cond.op,
        str(cond.lhs) if cond.lhs is not None else "",
        str(cond.rhs) if cond.rhs is not None else "",
        cond.width_bits,
    )


def deduplicate_conditions_8616(conditions: list[ConditionIR]) -> list[ConditionIR]:
    """Return deduplicated, deterministically sorted conditions."""
    seen: set[tuple] = set()
    unique: list[ConditionIR] = []
    for cond in sorted(conditions, key=condition_sort_key_8616):
        key = condition_sort_key_8616(cond)
        if key not in seen:
            seen.add(key)
            unique.append(cond)
    return unique


# ── IRValue-based builders (for use with the core IR types) ──


def build_condition_ir_8616(
    op: ConditionOp,
    *args: IRValue,
    expr: tuple[str, ...] | None = None,
) -> IRCondition:
    """Build an IRCondition from typed op and value args.

    This is the existing IR-layer builder — kept for compatibility.
    Preference: use ConditionIR and its builders above for semantic recovery.
    """
    return IRCondition(op=op, args=tuple(args), expr=expr)


def coerce_condition_value_size_8616(value: IRValue, size: int) -> IRValue:
    if size <= 0 or value.size == size:
        return value
    return replace(value, size=size)


def harmonize_condition_args_8616(*args: IRValue, size: int = 0) -> tuple[IRValue, ...]:
    target_size = int(size or 0)
    if target_size <= 0:
        target_size = max((int(arg.size or 0) for arg in args), default=0)
    if target_size <= 0:
        return tuple(args)
    return tuple(coerce_condition_value_size_8616(arg, target_size) for arg in args)


def normalize_condition_op_8616(op: str) -> ConditionOp:
    if op in {"and", "or", "not"}:
        return op  # type: ignore[return-value]
    if op in {"masked_nonzero", "nonzero"}:
        return "nonzero"
    if op in {"masked_zero", "zero"}:
        return "zero"
    if op in {
        "eq",
        "ne",
        "slt",
        "sle",
        "sgt",
        "sge",
        "ult",
        "ule",
        "ugt",
        "uge",
        "compare",
    }:
        return op  # type: ignore[return-value]
    if op in {"lt", "le", "gt", "ge"}:
        return f"s{op}"  # type: ignore[return-value]
    if op in {"lt_u", "le_u", "gt_u", "ge_u"}:
        return f"u{op[:-2]}"  # type: ignore[return-value]
    return "compare"


def is_condition_truth_test_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"zero", "nonzero", "and", "or", "not"}


def is_condition_compare_family_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {
        "compare",
        "eq",
        "ne",
        "slt",
        "sle",
        "sgt",
        "sge",
        "ult",
        "ule",
        "ugt",
        "uge",
    }


def condition_compare_symbol_8616(op: str) -> str | None:
    return _COMPARE_SYMBOLS_8616.get(normalize_condition_op_8616(op))


def is_signed_condition_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"slt", "sle", "sgt", "sge"}


def is_unsigned_condition_8616(op: str) -> bool:
    return normalize_condition_op_8616(op) in {"ult", "ule", "ugt", "uge"}


_INVERTED_COMPARISON_OPS_8616: dict[str, str] = {
    "CmpEQ": "CmpNE",
    "CmpNE": "CmpEQ",
    "CmpLT": "CmpGE",
    "CmpLE": "CmpGT",
    "CmpGT": "CmpLE",
    "CmpGE": "CmpLT",
}


def inverted_comparison_op_8616(op: str) -> str | None:
    """Return the inverted comparison op name, e.g. ``CmpEQ`` → ``CmpNE``.

    This lives in the IR layer because condition-op inversion is a semantic
    identity that belongs to typed condition representation, not to
    late-rewrite or validation-string normalization.
    """
    return _INVERTED_COMPARISON_OPS_8616.get(op)


def normalize_condition_fingerprint_string_8616(
    value: str,
    *,
    control_flow_prefixes: tuple[str, ...] | None = None,
) -> str:
    """Canonicalize a condition fingerprint string by inverting ``Not(CmpEQ(...))`` → ``CmpNE(...)``.

    This operates on fingerprint-string representations of conditions.
    The normalization is driven by the IR-layer ``inverted_comparison_op_8616``
    mapping, but the string parsing is fingerprint-format specific.
    """
    if not isinstance(value, str) or not value:
        return value

    if control_flow_prefixes is None:
        control_flow_prefixes = (
            "if:",
            "ifbreak:",
            "while:",
            "dowhile:",
            "for:",
            "switch:",
        )

    for prefix in control_flow_prefixes:
        if value.startswith(prefix):
            return prefix + normalize_condition_fingerprint_string_8616(
                value[len(prefix) :],
                control_flow_prefixes=control_flow_prefixes,
            )

    call = _split_fingerprint_call_8616(value)
    if call is None:
        return value
    op, inner = call
    if op == "Not":
        inner_call = _split_fingerprint_call_8616(inner)
        if inner_call is None:
            return value
        inner_op, inner_args = inner_call
        inverted = inverted_comparison_op_8616(inner_op)
        if inverted is not None:
            return f"{inverted}({inner_args})"
    return value


def invert_condition_fingerprint_string_8616(value: str) -> str | None:
    """Invert a comparison fingerprint while preserving its arguments."""
    call = _split_fingerprint_call_8616(value)
    if call is None:
        return None
    op, inner = call
    if op == "Not":
        return inner
    inverted = inverted_comparison_op_8616(op)
    if inverted is None:
        return None
    return f"{inverted}({inner})"


def _split_fingerprint_call_8616(value: str) -> tuple[str, str] | None:
    """Split ``CmpEQ(reg:ax,#0x0)`` into (``CmpEQ``, ``reg:ax,#0x0``)."""
    if not isinstance(value, str) or not value.endswith(")"):
        return None
    open_idx = value.find("(")
    if open_idx <= 0:
        return None
    return value[:open_idx], value[open_idx + 1 : -1]


def _split_fingerprint_args_8616(args_str: str) -> list[str]:
    """Split fingerprint arguments by top-level commas, respecting nested parens."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in args_str:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return parts


def _normalize_segmented_index_duplicate_displacement_8616(value: str) -> str:
    call = _split_fingerprint_call_8616(value)
    if call is None:
        return value
    op, args_str = call
    args = [
        _normalize_segmented_index_duplicate_displacement_8616(arg) for arg in _split_fingerprint_args_8616(args_str)
    ]
    if op != "Add" or len(args) < 3 or args[0] not in {"Mul(reg:ds,const:16)", "Mul(reg:es,const:16)"}:
        return f"{op}({','.join(args)})"

    const_positions = {
        arg: idx for idx, arg in enumerate(args[1:], start=1) if isinstance(arg, str) and arg.startswith("const:")
    }
    for idx, arg in enumerate(args[1:], start=1):
        inner = _split_fingerprint_call_8616(arg)
        if inner is None:
            continue
        inner_op, inner_args_str = inner
        if inner_op != "Add":
            continue
        inner_args = _split_fingerprint_args_8616(inner_args_str)
        inner_consts = [part for part in inner_args if part.startswith("const:")]
        if len(inner_consts) != 1:
            continue
        duplicate_const = inner_consts[0]
        duplicate_idx = const_positions.get(duplicate_const)
        if duplicate_idx is None or duplicate_idx == idx:
            continue
        merged_args = [args[0]]
        for pos, part in enumerate(args[1:], start=1):
            if pos == duplicate_idx:
                continue
            if pos == idx:
                merged_args.extend(inner_args)
            else:
                merged_args.append(part)
        return f"Add({','.join(merged_args)})"
    return f"{op}({','.join(args)})"


def normalize_condition_fingerprint_algebraic_8616(value: str) -> str:
    def _impl():
        """Apply algebraic normalization to a condition fingerprint string.

        Rules (validation-only, deterministic, side-effect-free):

            CmpEQ(Sub(x,const:c),const:0) → CmpEQ(x,const:c)
            CmpNE(Sub(x,const:c),const:0) → CmpNE(x,const:c)
            CmpEQ(Sub(x,y),const:0) → CmpEQ(x,y)
            CmpNE(Sub(x,y),const:0) → CmpNE(x,y)

        Also handles doubled Sub nesting:

            CmpEQ(Sub(Sub(x,const:a),const:b),const:0) → CmpEQ(x,const:a+b)

        This is a pure string-level normalization that preserves the fingerprint
        format.  It does not mutate IR or feed results back into recovery.
        """
        if not isinstance(value, str) or not value:
            return value

        # Handle control-flow prefixes
        for prefix in ("if:", "ifbreak:", "while:", "dowhile:", "for:", "switch:"):
            if value.startswith(prefix):
                return prefix + normalize_condition_fingerprint_algebraic_8616(value[len(prefix) :])

        normalized_value = _normalize_segmented_index_duplicate_displacement_8616(value)

        call = _split_fingerprint_call_8616(normalized_value)
        if call is None:
            return normalized_value

        op, args_str = call

        # Rule: CmpEQ(Sub(x,const:c),const:0) → CmpEQ(x,const:c)
        # Rule: CmpNE(Sub(x,const:c),const:0) → CmpNE(x,const:c)
        if op in ("CmpEQ", "CmpNE"):
            args = _split_fingerprint_args_8616(args_str)
            if len(args) == 2 and args[1] == "const:0":
                lhs_call = _split_fingerprint_call_8616(args[0])
                if lhs_call is not None:
                    lhs_op, lhs_args = lhs_call
                    if lhs_op == "Sub":
                        sub_args = _split_fingerprint_args_8616(lhs_args)
                        if len(sub_args) == 2:
                            # Sub(x, const:c) == 0  →  x == const:c
                            if sub_args[1].startswith("const:"):
                                return f"{op}({sub_args[0]},{sub_args[1]})"
                            # Sub(x, y) == 0  →  x == y
                            return f"{op}({sub_args[0]},{sub_args[1]})"
                        # Handle nested Sub: Sub(Sub(x, a), b) == 0  →  x == a+b
                        if len(sub_args) == 2:
                            inner_call = _split_fingerprint_call_8616(sub_args[0])
                            if inner_call is not None and inner_call[0] == "Sub":
                                inner_args = _split_fingerprint_args_8616(inner_call[1])
                                if (
                                    len(inner_args) == 2
                                    and inner_args[1].startswith("const:")
                                    and sub_args[1].startswith("const:")
                                ):
                                    try:
                                        a = (
                                            int(inner_args[1].split(":")[-1], 0)
                                            if inner_args[1].startswith("const:")
                                            else 0
                                        )
                                        b = (
                                            int(sub_args[1].split(":")[-1], 0)
                                            if sub_args[1].startswith("const:")
                                            else 0
                                        )
                                    except (ValueError, IndexError):
                                        return normalized_value
                                    c_sum = a + b
                                    if c_sum >= 0:
                                        c_str = f"const:{c_sum:#x}"
                                    else:
                                        c_str = f"const:{c_sum}"
                                    return f"{op}({inner_args[0]},{c_str})"

        # Recurse into args for nested normalization
        args = _split_fingerprint_args_8616(args_str)
        normalized_args = [_normalize_arg_fingerprint_8616(a) for a in args]
        if normalized_args != args:
            return f"{op}({','.join(normalized_args)})"

        return normalized_value

    return _impl()


def _normalize_arg_fingerprint_8616(arg: str) -> str:
    """Recursively normalize a fingerprint arg, handling nested calls."""
    word_pair = _normalize_global_word_pair_arg_fingerprint_8616(arg)
    if word_pair is not None:
        return word_pair
    call = _split_fingerprint_call_8616(arg)
    if call is None:
        return arg
    op, args_str = call
    args = _split_fingerprint_args_8616(args_str)
    normalized_args = [_normalize_arg_fingerprint_8616(a) for a in args]
    return f"{op}({','.join(normalized_args)})"


def _normalize_global_word_pair_arg_fingerprint_8616(arg: str) -> str | None:
    call = _split_fingerprint_call_8616(arg)
    if call is None or call[0] != "Or":
        return None
    args = _split_fingerprint_args_8616(call[1])
    if len(args) != 2:
        return None
    low = _global_offset_fingerprint_8616(args[0])
    high = _shifted_ds_byte_offset_fingerprint_8616(args[1])
    if not isinstance(low, int) or not isinstance(high, int):
        low = _global_offset_fingerprint_8616(args[1])
        high = _shifted_ds_byte_offset_fingerprint_8616(args[0])
    if not isinstance(low, int) or not isinstance(high, int):
        return None
    if high != low + 1:
        return None
    return f"global:{low:#x}"


def _global_offset_fingerprint_8616(value: str) -> int | None:
    if not isinstance(value, str) or not value.startswith("global:"):
        return None
    try:
        return int(value[len("global:") :], 0)
    except ValueError:
        return None


def _shifted_ds_byte_offset_fingerprint_8616(value: str) -> int | None:
    call = _split_fingerprint_call_8616(value)
    if call is None:
        return None
    op, args_str = call
    args = _split_fingerprint_args_8616(args_str)
    if op == "Shl" and len(args) == 2 and args[1] == "const:8":
        return _ds_byte_deref_offset_fingerprint_8616(args[0])
    if op == "Mul" and len(args) == 2:
        if args[0] == "const:256":
            return _ds_byte_deref_offset_fingerprint_8616(args[1])
        if args[1] == "const:256":
            return _ds_byte_deref_offset_fingerprint_8616(args[0])
    return None


def _ds_byte_deref_offset_fingerprint_8616(value: str) -> int | None:
    call = _split_fingerprint_call_8616(value)
    if call is None or call[0] != "Dereference":
        return None
    parsed = _linear_ds_offset_fingerprint_8616(call[1])
    if parsed is None:
        return None
    has_ds, offset = parsed
    return offset if has_ds else None


def _linear_ds_offset_fingerprint_8616(value: str) -> tuple[bool, int] | None:
    if value.startswith("const:"):
        try:
            return False, int(value[len("const:") :], 0)
        except ValueError:
            return None
    if value == "reg:ds":
        return True, 0
    call = _split_fingerprint_call_8616(value)
    if call is None:
        return None
    op, args_str = call
    args = _split_fingerprint_args_8616(args_str)
    if op == "Mul" and len(args) == 2:
        if (args[0], args[1]) in {("reg:ds", "const:16"), ("const:16", "reg:ds")}:
            return True, 0
    if op == "Shl" and len(args) == 2 and args[0] == "reg:ds" and args[1] == "const:4":
        return True, 0
    if op != "Add" or len(args) != 2:
        return None
    left = _linear_ds_offset_fingerprint_8616(args[0])
    right = _linear_ds_offset_fingerprint_8616(args[1])
    if left is None or right is None:
        return None
    left_has_ds, left_offset = left
    right_has_ds, right_offset = right
    if left_has_ds and right_has_ds:
        return None
    return left_has_ds or right_has_ds, left_offset + right_offset
