from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FarCallTarget:
    callsite_addr: int
    target_addr: int
    return_addr: int | None


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


def collect_direct_far_call_targets(function) -> list[FarCallTarget]:
    """
    Recover immediate far-call targets directly from lifted blocks.

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
