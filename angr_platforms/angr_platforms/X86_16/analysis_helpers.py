from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FarCallTarget:
    callsite_addr: int
    target_addr: int
    return_addr: int | None


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
        block = project.factory.block(callsite_addr, opt_level=0)
        insns = getattr(block.capstone, "insns", ())
        if not insns:
            continue

        last = insns[-1]
        if last.mnemonic not in {"lcall", "call"}:
            continue

        operands = getattr(last.insn, "operands", ())
        if len(operands) != 2 or not all(op.type == 2 for op in operands):
            continue

        seg = operands[0].imm & 0xFFFF
        off = operands[1].imm & 0xFFFF
        recovered.append(
            FarCallTarget(
                callsite_addr=callsite_addr,
                target_addr=(seg << 4) + off,
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
    return cfg
