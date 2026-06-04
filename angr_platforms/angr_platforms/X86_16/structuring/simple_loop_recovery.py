from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InsnSummary8616:
    mnemonic: str
    op0_kind: str | None = None
    op0_value: int | str | None = None
    op1_kind: str | None = None
    op1_value: int | str | None = None
    op0_size: int | None = None
    op1_size: int | None = None


@dataclass(frozen=True, slots=True)
class CountedStackLoop8616:
    induction_disp: int
    accumulator_disp: int
    limit_disp: int
    parity_mask: int


def _sanitize_c_identifier_8616(name: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in str(name or ""))
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"sub_{cleaned}" if cleaned else "sub_func"
    return cleaned


def _local_name_8616(disp: int) -> str:
    if disp < 0:
        return f"local_{abs(disp):x}"
    return f"arg_{disp:x}"


def recover_counted_stack_loop_from_summaries_8616(
    summaries: list[InsnSummary8616],
) -> CountedStackLoop8616 | None:
    """Recover a simple MS C counted stack-local loop from binary operands.

    This is intentionally conservative: every emitted variable must be tied to
    repeated BP-relative instruction evidence. Unknown or partial patterns are
    refused rather than guessed.
    """
    zero_inits: set[int] = set()
    inc_slots: set[int] = set()
    cmp_pairs: list[tuple[int, int]] = []
    test_pairs: list[tuple[int, int]] = []
    add_pairs: list[tuple[int, int]] = []
    dec_slots: set[int] = set()
    ax_loads: list[int] = []

    previous_ax_load: int | None = None
    for insn in summaries:
        mnemonic = insn.mnemonic.lower()
        if (
            mnemonic == "mov"
            and insn.op0_kind == "bp_mem"
            and insn.op1_kind == "imm"
            and int(insn.op1_value or 0) == 0
            and (insn.op0_size in {None, 2})
        ):
            zero_inits.add(int(insn.op0_value))
        elif mnemonic == "inc" and insn.op0_kind == "bp_mem" and (insn.op0_size in {None, 2}):
            inc_slots.add(int(insn.op0_value))
        elif mnemonic == "mov" and insn.op0_kind == "reg" and insn.op0_value == "ax" and insn.op1_kind == "bp_mem":
            previous_ax_load = int(insn.op1_value)
            ax_loads.append(previous_ax_load)
        elif (
            mnemonic == "cmp"
            and insn.op0_kind == "bp_mem"
            and insn.op1_kind == "reg"
            and insn.op1_value == "ax"
            and previous_ax_load is not None
        ):
            cmp_pairs.append((int(insn.op0_value), previous_ax_load))
        elif mnemonic == "test" and insn.op0_kind == "bp_mem" and insn.op1_kind == "imm":
            test_pairs.append((int(insn.op0_value), int(insn.op1_value or 0)))
        elif (
            mnemonic == "add"
            and insn.op0_kind == "bp_mem"
            and insn.op1_kind == "reg"
            and insn.op1_value == "ax"
            and previous_ax_load is not None
        ):
            add_pairs.append((int(insn.op0_value), previous_ax_load))
        elif mnemonic == "dec" and insn.op0_kind == "bp_mem" and (insn.op0_size in {None, 2}):
            dec_slots.add(int(insn.op0_value))
        elif mnemonic not in {"mov", "cmp", "test", "add"}:
            previous_ax_load = None

    for induction_disp, limit_disp in cmp_pairs:
        if induction_disp >= 0 or limit_disp <= 0:
            continue
        if induction_disp not in zero_inits or induction_disp not in inc_slots:
            continue
        parity_masks = [mask for disp, mask in test_pairs if disp == induction_disp and mask > 0]
        if not parity_masks:
            continue
        for accumulator_disp, add_source_disp in add_pairs:
            if accumulator_disp >= 0 or add_source_disp != induction_disp:
                continue
            if accumulator_disp not in zero_inits or accumulator_disp not in dec_slots:
                continue
            if accumulator_disp not in ax_loads:
                continue
            return CountedStackLoop8616(
                induction_disp=induction_disp,
                accumulator_disp=accumulator_disp,
                limit_disp=limit_disp,
                parity_mask=int(parity_masks[0]),
            )
    return None


def _summarize_capstone_insn_8616(insn) -> InsnSummary8616:
    operands = tuple(getattr(insn, "operands", ()) or ())

    def _operand(index: int) -> tuple[str | None, int | str | None, int | None]:
        if index >= len(operands):
            return None, None, None
        operand = operands[index]
        op_type = int(getattr(operand, "type", -1))
        size = getattr(operand, "size", None)
        if op_type == 1:
            return "reg", str(insn.reg_name(operand.reg)).lower(), size
        if op_type == 2:
            return "imm", int(getattr(operand, "imm", 0) or 0), size
        if op_type == 3:
            mem = getattr(operand, "mem", None)
            if mem is not None and str(insn.reg_name(mem.base)).lower() == "bp":
                return "bp_mem", int(getattr(mem, "disp", 0) or 0), size
            return "mem", None, size
        return None, None, size

    op0_kind, op0_value, op0_size = _operand(0)
    op1_kind, op1_value, op1_size = _operand(1)
    return InsnSummary8616(
        mnemonic=str(getattr(insn, "mnemonic", "")).lower(),
        op0_kind=op0_kind,
        op0_value=op0_value,
        op1_kind=op1_kind,
        op1_value=op1_value,
        op0_size=op0_size,
        op1_size=op1_size,
    )


def _function_instruction_summaries_8616(project, function) -> list[InsnSummary8616]:
    summaries: list[InsnSummary8616] = []
    for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        try:
            block = project.factory.block(block_addr)
        except Exception:
            continue
        for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
            summaries.append(_summarize_capstone_insn_8616(insn.insn))
    return summaries


def _linear_instruction_summaries_8616(project, function, *, max_size: int = 0x180) -> list[InsnSummary8616]:
    addr = getattr(function, "addr", None)
    if not isinstance(addr, int):
        return []
    size = getattr(function, "size", None)
    if not isinstance(size, int) or size <= 0:
        size = max_size
    size = max(1, min(int(size), max_size))
    try:
        block = project.factory.block(addr, size=size)
    except Exception:
        return []
    return [_summarize_capstone_insn_8616(insn.insn) for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ()]


def recover_counted_stack_loop_c_8616(project, function) -> str | None:
    summaries = _function_instruction_summaries_8616(project, function)
    evidence = recover_counted_stack_loop_from_summaries_8616(summaries)
    if evidence is None:
        summaries = _linear_instruction_summaries_8616(project, function)
        evidence = recover_counted_stack_loop_from_summaries_8616(summaries)
    if evidence is None:
        return None
    func_name = _sanitize_c_identifier_8616(getattr(function, "name", None) or f"sub_{getattr(function, 'addr', 0):x}")
    induction = _local_name_8616(evidence.induction_disp)
    accumulator = _local_name_8616(evidence.accumulator_disp)
    limit = "arg"
    mask = evidence.parity_mask
    return (
        f"int {func_name}(int {limit})\n"
        "{\n"
        f"    int {induction};\n"
        f"    int {accumulator};\n"
        f"    {accumulator} = 0;\n"
        f"    for ({induction} = 0; {induction} < {limit}; ++{induction}) {{\n"
        f"        if (({induction} & {mask}) == 0) {{\n"
        f"            {accumulator} += {induction};\n"
        "        } else {\n"
        f"            {accumulator} -= 1;\n"
        "        }\n"
        "    }\n"
        f"    return {accumulator};\n"
        "}\n"
    )


__all__ = [
    "CountedStackLoop8616",
    "InsnSummary8616",
    "recover_counted_stack_loop_c_8616",
    "recover_counted_stack_loop_from_summaries_8616",
]
