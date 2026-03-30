from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MartypcPrioritySpec:
    code: str
    title: str
    priority: str
    status: str
    deterministic_goal: str
    code_surfaces: tuple[str, ...]
    completion_signal: str


MARTYPC_PRIORITY_SPECS: tuple[MartypcPrioritySpec, ...] = (
    MartypcPrioritySpec(
        code="P0.1",
        title="Split address-width and operand-width explicitly",
        priority="P0",
        status="landed",
        deterministic_goal="Keep address formation and operand arithmetic on separate width paths.",
        code_surfaces=("addressing_helpers.py", "exec.py", "parse.py", "instr16.py", "instr32.py"),
        completion_signal="No instruction handler should guess whether an add is address math or operand math.",
    ),
    MartypcPrioritySpec(
        code="P0.2",
        title="Move effective-address and default-segment logic behind one boundary",
        priority="P0",
        status="landed",
        deterministic_goal="Route ModRM effective addresses and default segments through one shared boundary.",
        code_surfaces=("addressing_helpers.py", "access.py", "exec.py", "instr16.py", "instr32.py"),
        completion_signal="Any memory operand can be traced through one addressing boundary.",
    ),
    MartypcPrioritySpec(
        code="P0.3",
        title="Extract stack semantics into a focused helper layer",
        priority="P0",
        status="landed",
        deterministic_goal="Centralize call/ret/iret/enter/leave and stack frame choreography into shared helpers.",
        code_surfaces=("stack_helpers.py", "instr_base.py", "instr16.py", "instr32.py", "emu.py"),
        completion_signal="Stack pointer order and far-frame formation no longer live inside every opcode handler.",
    ),
    MartypcPrioritySpec(
        code="P0.4",
        title="Extract string semantics into one family module",
        priority="P0",
        status="landed",
        deterministic_goal="Keep source/destination selection, repeat gating, and direction-flag stepping in one family layer.",
        code_surfaces=("string_helpers.py", "instr16.py", "instr_base.py", "instr32.py"),
        completion_signal="String instructions are wrappers around shared helper behavior.",
    ),
    MartypcPrioritySpec(
        code="P0.5",
        title="Centralize ALU flag/update families",
        priority="P0",
        status="landed",
        deterministic_goal="Drive binary, unary, compare, shift, and rotate flag behavior through one family helper layer.",
        code_surfaces=("alu_helpers.py", "instr_base.py", "instr16.py", "eflags.py", "processor.py"),
        completion_signal="New ALU-like support is added by plugging accessors into shared helpers.",
    ),
    MartypcPrioritySpec(
        code="P1.1",
        title="Make decode metadata richer and execution dumber",
        priority="P1",
        status="landed",
        deterministic_goal="Make decode facts carry width and control-flow metadata so execution can stop re-deriving them.",
        code_surfaces=("instruction.py", "parse.py", "exec.py"),
        completion_signal="Execution mostly consumes decode results and semantic helpers.",
    ),
    MartypcPrioritySpec(
        code="P1.2",
        title="Make 386 real-mode with 16-bit addressing an explicit extension path",
        priority="P1",
        status="landed",
        deterministic_goal="Keep mixed-width matrix support explicit so 386 real-mode extension reuses existing helpers.",
        code_surfaces=("addressing_helpers.py", "instruction.py", "parse.py", "exec.py", "instr16.py", "instr32.py"),
        completion_signal="The mixed-width matrix is explicit and the decode metadata now carries the named case.",
    ),
    MartypcPrioritySpec(
        code="P1.3",
        title="Separate interrupt-core semantics from DOS/BIOS API lowering",
        priority="P1",
        status="landed",
        deterministic_goal="Keep interrupt entry/stack semantics separate from DOS/BIOS/MS-C lowering policy.",
        code_surfaces=("instr_base.py", "interrupt.py", "simos_86_16.py", "analysis_helpers.py", "decompile.py"),
        completion_signal="BIOS/DOS helper rendering can evolve without touching interrupt stack logic.",
    ),
    MartypcPrioritySpec(
        code="P2.1",
        title="Add instruction-family validation slices",
        priority="P2",
        status="landed",
        deterministic_goal="Keep focused unit and corpus tests grouped by family so regressions isolate quickly.",
        code_surfaces=("validation_manifest.py", "tests/test_x86_16*.py"),
        completion_signal="A regression in one family can be isolated without broad sample sweeps.",
    ),
    MartypcPrioritySpec(
        code="P2.2",
        title="Add targeted MartyPC-assisted differential triage",
        priority="P2",
        status="landed",
        deterministic_goal="Use MartyPC as a bounded secondary reference for tricky instruction families.",
        code_surfaces=("validation_manifest.py", "docs/x86_16_martypc_improvement_plan.md"),
        completion_signal="The triage workflow is now structured with bounded opcode sets and explicit evidence sources.",
    ),
    MartypcPrioritySpec(
        code="P2.3",
        title="Make scan-safe failure clustering point back to semantic families",
        priority="P2",
        status="landed",
        deterministic_goal="Tag failures and ugly clusters with family ownership so corpus pain points map back to the core layer.",
        code_surfaces=("corpus_scan.py", "milestone_report.py", "validation_manifest.py"),
        completion_signal="Low-level cleanup priorities come from corpus evidence, not intuition alone.",
    ),
    MartypcPrioritySpec(
        code="P3.1",
        title="Push more projection cleanup onto explicit low-level facts",
        priority="P3",
        status="landed",
        deterministic_goal="Move late rewrite cleanup onto alias and widening facts instead of re-solving storage identity.",
        code_surfaces=("decompiler_postprocess_simplify.py", "alias_model.py", "widening_model.py", "milestone_report.py"),
        completion_signal="Decompiler cleanup becomes thinner because the lift is cleaner.",
    ),
    MartypcPrioritySpec(
        code="P3.2",
        title="Use interrupt/API lowering only after the instruction-core path is clean",
        priority="P3",
        status="landed",
        deterministic_goal="Keep DOS/BIOS/MS-C helper lowering downstream of stable stack/register/interrupt facts.",
        code_surfaces=("analysis_helpers.py", "decompile.py", "cod_source_rewrites.py"),
        completion_signal="Helper-call lowering looks more natural because the low-level evidence is better.",
    ),
)


def describe_x86_16_martypc_improvement_progress() -> tuple[tuple[str, str, str, str, tuple[str, ...], str], ...]:
    return tuple(
        (
            spec.code,
            spec.title,
            spec.priority,
            spec.status,
            spec.code_surfaces,
            spec.completion_signal,
        )
        for spec in MARTYPC_PRIORITY_SPECS
    )


def summarize_x86_16_martypc_improvement_progress() -> dict[str, object]:
    landed = sum(1 for spec in MARTYPC_PRIORITY_SPECS if spec.status == "landed")
    partial = sum(1 for spec in MARTYPC_PRIORITY_SPECS if spec.status == "partial")
    open_ = sum(1 for spec in MARTYPC_PRIORITY_SPECS if spec.status == "open")
    strict_percent = round(landed / len(MARTYPC_PRIORITY_SPECS) * 100, 2) if MARTYPC_PRIORITY_SPECS else 0.0
    weighted_percent = round((landed + 0.5 * partial) / len(MARTYPC_PRIORITY_SPECS) * 100, 2) if MARTYPC_PRIORITY_SPECS else 0.0
    return {
        "total": len(MARTYPC_PRIORITY_SPECS),
        "landed": landed,
        "partial": partial,
        "open": open_,
        "strict_percent": strict_percent,
        "weighted_percent": weighted_percent,
        "landed_codes": tuple(spec.code for spec in MARTYPC_PRIORITY_SPECS if spec.status == "landed"),
        "partial_codes": tuple(spec.code for spec in MARTYPC_PRIORITY_SPECS if spec.status == "partial"),
        "open_codes": tuple(spec.code for spec in MARTYPC_PRIORITY_SPECS if spec.status == "open"),
    }


__all__ = [
    "MARTYPC_PRIORITY_SPECS",
    "MartypcPrioritySpec",
    "describe_x86_16_martypc_improvement_progress",
    "summarize_x86_16_martypc_improvement_progress",
]
