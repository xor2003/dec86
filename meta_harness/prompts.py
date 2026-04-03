from __future__ import annotations

from .config import RuntimeConfig


def _style_contract() -> str:
    return (
        "Response style:\n"
        "- Minimal and actionable.\n"
        "- No repetition.\n"
        "- No explanations unless needed for the role.\n"
        "- Prefer concrete results over narration.\n\n"
    )


def build_master_prompt(cfg: RuntimeConfig) -> str:
    if cfg.compact_prompts:
        return (
            f"Work in {cfg.root_dir}. Repo rules: {cfg.rules_file}.\n"
            f"Maintain {cfg.plan_path}. Use {cfg.evidence_log_file} as current evidence.\n\n"
            f"Priorities: 1) {cfg.primary_priority}; 2) {cfg.secondary_priority}; "
            f"3) {cfg.general_improvement_rule}; 4) {cfg.architecture_guidance}.\n"
            f"Compare against: {cfg.compare_input_description}.\n"
            "Always state current quality for correctness and recompilation.\n"
            "Use concrete repository evidence, not vague claims.\n\n"
            + _style_contract()
        )
    return (
        f"You are working on {cfg.root_dir}, a {cfg.project_description}.\n\n"
        f"Always use the repository rules from {cfg.rules_file}.\n\n"
        "Role model:\n"
        "- Checker validates current evidence only.\n"
        "- Planner updates the plan only.\n"
        "- Worker implements one or more unfinished plan steps.\n"
        "- Reviewer audits completion and may improve the harness itself.\n"
        "- Crash-reviewer diagnoses harness failures and may request a restart.\n\n"
        "Main operating goals:\n"
        f"1. Run and use {cfg.evidence_kind} as evidence.\n"
        f"2. Generate and maintain {cfg.plan_path}.\n"
        f"3. {cfg.primary_priority}\n"
        f"4. {cfg.secondary_priority}\n"
        f"5. {cfg.general_improvement_rule}\n"
        f"6. {cfg.architecture_guidance}\n\n"
        "When evaluating progress, compare:\n"
        f"- {cfg.compare_input_description}\n\n"
        "Always report current quality for:\n"
        "- correctness\n"
        "- recompilation\n\n"
        "Use concrete evidence from the project, not vague claims.\n\n"
        + _style_contract()
    )


def build_checker_prompt(cfg: RuntimeConfig) -> str:
    return build_master_prompt(cfg) + (
        "\nChecker step:\n"
        f"- Inspect {cfg.evidence_log_file} for crashes, timeouts, or obvious regressions.\n"
        "- Print current quality for correctness and recompilation.\n"
        "- Do not update the plan or implement code changes in this step.\n"
        "- At the end, print exactly: Global Remaining steps: N\n"
    )


def build_planner_prompt(cfg: RuntimeConfig) -> str:
    return build_master_prompt(cfg) + (
        "\nPlanner step:\n"
        "- Analyze the current difference between relevant inputs and generated outputs.\n"
        "- Inspect the current code state.\n"
        f"- Do not rerun the evidence sweep; the sweep step already produced {cfg.evidence_log_file} and the checker step reviewed it for this cycle.\n"
        f"- Create or update {cfg.plan_path} as a flat numbered checklist.\n"
        "- Each item must name the target file(s) and exact source line numbers when available.\n"
        "- Each item must specify the concrete functions, tests, or scripts to change.\n"
        "- Each item must include a deterministic definition of done.\n"
        "- Keep items deterministic, short, and directly actionable.\n"
        "- The plan must prioritize correctness first and recompilation second.\n"
        "- Preserve unfinished strategic items already present in the plan unless they are now done or clearly superseded by a more precise item.\n"
        "- Do not drop user-added unfinished goals just because the current cycle focuses on a different bug.\n"
        "- Remove any done items from the plan and leave only unfinished work.\n"
        "- Print current quality of correctness and recompilation.\n"
        "- If there is nothing meaningful left to do, say that clearly.\n"
        "- At the end, print exactly: Global Remaining steps: N\n"
    )


def build_worker_prompt(cfg: RuntimeConfig) -> str:
    return build_master_prompt(cfg) + (
        "\nWorker step:\n"
        f"- Use the most recent {cfg.evidence_log_file} and the checker review as current evidence for correctness, recompilation quality, crashes, and smoothness.\n"
        f"- Continue implementing the unfinished steps from {cfg.plan_path}.\n"
        "- Work like an ongoing continuation: make real code changes, update tests, verify results, and commit often.\n"
        "- Never use source-specific hacks.\n"
        "- If the harness itself can be improved safely while you work, you may improve it too.\n"
        "- At the end of each step, print exactly: Global Remaining steps: N\n"
    )


def build_reviewer_prompt(cfg: RuntimeConfig) -> str:
    return build_master_prompt(cfg) + (
        "\nReviewer step:\n"
        "- In a fresh session, review the current code state and current plan.\n"
        "- Check what is genuinely finished and what is not.\n"
        f"- Remove completed steps from {cfg.plan_path}.\n"
        "- You may also improve the harness itself if that reduces future failures or manual babysitting.\n"
        "- Do not run worker cycles in this step.\n"
        "- Print achieved results.\n"
        "- Print the true remaining step count at the end as: Global Remaining steps: N\n"
    )


def build_crash_reviewer_prompt(cfg: RuntimeConfig, current_cycle_dir: str, exit_code: int) -> str:
    return build_master_prompt(cfg) + (
        "\nCrash-review step:\n"
        f"- The harness itself exited with status {exit_code}.\n"
        "- Inspect these artifacts first:\n"
        f"  - {cfg.status_file}\n"
        f"  - {cfg.last_log_file}\n"
        f"  - {cfg.evidence_log_file}\n"
        f"  - {current_cycle_dir}\n"
        f"- You may update {cfg.run_sh_path}, {cfg.plan_path}, or other harness files if that improves stability or self-maintenance.\n"
        "- Prefer improving the harness itself over changing reviewer/worker goals.\n"
        "- Print a short crash diagnosis and concrete harness fix summary.\n"
        "- If the harness was changed and should restart with the new code, print exactly: Harness restart required\n"
    )


def build_resume_prompt(role: str, cfg: RuntimeConfig, *, comments: str = "") -> str:
    role_instructions = {
        "worker": (
            f"Continue the existing {role} session.\n"
            f"Implement the next unfinished item(s) from {cfg.plan_path}.\n"
            "Use the existing session context instead of re-deriving the whole plan.\n"
            "Keep output minimal and actionable.\n"
            "At the end, print exactly: Global Remaining steps: N\n"
        ),
        "planner": (
            f"Continue the existing {role} session.\n"
            f"Update only {cfg.plan_path}.\n"
            "Keep unfinished strategic items unless done or superseded.\n"
            "At the end, print exactly: Global Remaining steps: N\n"
        ),
        "reviewer": (
            f"Continue the existing {role} session.\n"
            "Re-check the current code state and remaining plan items.\n"
            "At the end, print exactly: Global Remaining steps: N\n"
        ),
        "checker": (
            f"Continue the existing {role} session.\n"
            f"Validate {cfg.evidence_log_file} only.\n"
            "At the end, print exactly: Global Remaining steps: N\n"
        ),
    }
    prompt = role_instructions.get(
        role,
        f"Continue the existing {role} session.\nKeep output minimal and actionable.\n",
    )
    if comments.strip():
        prompt += "\nOperator comments to apply now:\n" + comments.strip() + "\n"
    return prompt
