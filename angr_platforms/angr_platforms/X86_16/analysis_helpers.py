from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FarCallTarget:
    callsite_addr: int
    target_addr: int
    return_addr: int | None


def infer_com_region(path: Path, *, base_addr: int, window: int, arch) -> tuple[int, int]:
    """
    Infer a bounded `.COM` code region by scanning until a likely terminator.

    This keeps tiny DOS stubs from decompiling their trailing strings as code.
    """

    data = path.read_bytes()
    end_limit = min(len(data), window)
    current = 0
    ah = None

    while current < end_limit:
        chunk = data[current : current + 16]
        insn = next(arch.capstone.disasm(chunk, base_addr + current, 1), None)
        if insn is None:
            break

        text = f"{insn.mnemonic} {insn.op_str}".strip().lower()
        if text.startswith("mov ah, "):
            ah = int(text.split(", ", 1)[1], 0)
        elif text.startswith("mov ax, "):
            ax = int(text.split(", ", 1)[1], 0)
            ah = (ax >> 8) & 0xFF

        current += insn.size

        if insn.mnemonic == "int":
            if insn.op_str.lower() == "0x20":
                break
            if insn.op_str.lower() == "0x21" and ah == 0x4C:
                break
            if insn.op_str.lower() == "0x27":
                break
        if insn.mnemonic in {"ret", "retf", "iret", "jmp"}:
            break

    return base_addr, base_addr + max(current, 1)


def _absolute_mem_disp(operand) -> int | None:
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    if getattr(mem, "base", 0) != 0 or getattr(mem, "index", 0) != 0:
        return None
    return getattr(mem, "disp", 0) & 0xFFFF


def _initial_cs_linear_base(project) -> int | None:
    initial_regs = getattr(project.loader.main_object, "initial_register_values", None)
    if not initial_regs:
        return None
    cs = initial_regs.get("cs")
    if cs is None:
        return None
    return (cs & 0xFFFF) << 4


def resolve_direct_call_target_from_block(project, block_addr: int) -> int | None:
    """
    Recover a direct call target from the last instruction in a block.

    This is intentionally narrow and only handles the direct near/far forms
    that show up in our DOS samples. Indirect calls still return ``None``.
    """

    block = project.factory.block(block_addr, opt_level=0)
    insns = getattr(block.capstone, "insns", ())
    if not insns:
        return None

    last = insns[-1]
    operands = getattr(last.insn, "operands", ())

    if last.mnemonic == "lcall" and len(operands) == 2 and all(op.type == 2 for op in operands):
        seg = operands[0].imm & 0xFFFF
        off = operands[1].imm & 0xFFFF
        return (seg << 4) + off

    if last.mnemonic == "call" and len(operands) == 1 and operands[0].type == 2:
        return operands[0].imm & 0xFFFF

    return None


def resolve_stored_near_call_target_from_function(function, callsite_addr: int) -> int | None:
    """
    Recover a near call target from a startup-built absolute pointer slot.

    This is intentionally narrow. It only handles patterns like:

        mov word ptr ss:[0x60], 0x01a2
        ...
        call word ptr [0x60]

    which appear in MSC startup code for real-mode DOS.
    """

    project = function.project
    if project is None:
        return None

    block = project.factory.block(callsite_addr, opt_level=0)
    insns = getattr(block.capstone, "insns", ())
    if not insns:
        return None
    last = insns[-1]
    operands = getattr(last.insn, "operands", ())
    if last.mnemonic != "call" or len(operands) != 1 or operands[0].type != 3:
        return None

    slot_disp = _absolute_mem_disp(operands[0])
    if slot_disp is None:
        return None

    cs_base = _initial_cs_linear_base(project)
    if cs_base is None:
        return None

    prior_insns = []
    for addr in sorted(function.block_addrs_set):
        if addr >= callsite_addr:
            continue
        prior_block = project.factory.block(addr, opt_level=0)
        prior_insns.extend(getattr(prior_block.capstone, "insns", ()))

    for ins in reversed(prior_insns):
        if ins.address >= callsite_addr:
            continue
        opers = getattr(ins.insn, "operands", ())
        if ins.mnemonic != "mov" or len(opers) != 2:
            continue
        dst, src = opers
        if dst.type != 3 or src.type != 2:
            continue
        dst_disp = _absolute_mem_disp(dst)
        if dst_disp != slot_disp:
            continue
        return cs_base + (src.imm & 0xFFFF)

    return None


def collect_direct_far_call_targets(function) -> list[FarCallTarget]:
    """
    Recover direct or startup-recoverable call targets directly from lifted blocks.

    angr's stock call-target recovery does not currently understand the x86-16
    `CS:IP` far-call pattern very well, so medium-model DOS startup code often
    ends up with `UnresolvableCallTarget` call edges even when the block itself
    is fully understood. This helper keeps the workaround small, explicit, and
    reusable for CLI tooling and tests.
    """

    if function.project is None or function.project.arch.name != "86_16":
        return []

    project = function.project
    recovered: list[FarCallTarget] = []

    for callsite_addr in sorted(function.get_call_sites()):
        target_addr = resolve_direct_call_target_from_block(project, callsite_addr)
        if target_addr is None:
            target_addr = resolve_stored_near_call_target_from_function(function, callsite_addr)
        # Real-mode far calls commonly land below 64 KiB once segment:offset is
        # linearized (for example 0x0114:0x0240 -> 0x1380). Only discard calls
        # we still failed to resolve, not low linear addresses.
        if target_addr is None:
            continue

        recovered.append(
            FarCallTarget(
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                return_addr=function.get_call_return(callsite_addr),
            )
        )

    return recovered


def patch_far_call_sites(function, far_targets: list[FarCallTarget]) -> bool:
    """
    Rewrite Function._call_sites for immediate far calls recovered from blocks.

    CFGFast currently leaves some x86-16 far callsites pointing at a bogus short
    target (for example `0x14`) even when the block disassembly clearly shows an
    immediate `seg:off` far call. The decompiler reads `Function.get_call_target()`
    from `_call_sites`, so patching those entries gives downstream analyses a
    much better callee address without needing to modify site-packages angr.
    """

    changed = False

    for target in far_targets:
        old = function._call_sites.get(target.callsite_addr)
        new = (target.target_addr, target.return_addr)
        if old != new:
            function._call_sites[target.callsite_addr] = new
            changed = True

    return changed


def extend_cfg_for_far_calls(project, function, *, entry_window: int, callee_window: int = 0x80):
    """
    Re-run CFG with direct far callees seeded as extra function starts.

    This keeps bounded DOS startup recovery focused on the functions actually
    reached by immediate far calls, instead of forcing a broad CFG window that
    quickly runs into unrelated unsupported instructions.
    """

    far_targets = collect_direct_far_call_targets(function)
    if not far_targets:
        return None

    patch_far_call_sites(function, far_targets)

    function_starts = [function.addr, *(target.target_addr for target in far_targets)]
    regions = [(function.addr, function.addr + entry_window)]
    regions.extend((target.target_addr, target.target_addr + callee_window) for target in far_targets)

    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=sorted(set(function_starts)),
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    if function.addr in cfg.functions:
        patch_far_call_sites(cfg.functions[function.addr], far_targets)
    for target in far_targets:
        callee = cfg.kb.functions.function(addr=target.target_addr, create=True)
        if callee is not None:
            callee._init_prototype_and_calling_convention()
    return cfg
