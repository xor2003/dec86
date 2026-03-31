#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${ROOT_DIR}/.codex_automation"
LOG_DIR="${STATE_DIR}/logs"
PLAN_PATH="${ROOT_DIR}/PLAN.md"
STOP_FILE="${ROOT_DIR}/STOP"
LOCK_FILE="${STATE_DIR}/run.lock"
STATUS_FILE="${STATE_DIR}/status.txt"
LAST_LOG_FILE="${STATE_DIR}/last.log"
PROMPT_DIR="${STATE_DIR}/prompts"
VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"
KEEP_LOG_COUNT="${KEEP_LOG_COUNT:-40}"

PLANNER_MODEL="gpt-5.4"
WORKER_MODEL="gpt-5.4-mini"
REVIEWER_MODEL="gpt-5.4"

MAX_WORKER_ITERS="${MAX_WORKER_ITERS:-40}"
WORKER_SLEEP_SECS="${WORKER_SLEEP_SECS:-4}"
PLANNER_PAUSE_SECS="${PLANNER_PAUSE_SECS:-60}"
CODEX_TIMEOUT_SECS="${CODEX_TIMEOUT_SECS:-600}"
WORKER_FINISH_TOKEN="Global Remaining steps: 0"

mkdir -p "${LOG_DIR}" "${PROMPT_DIR}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

timestamp() {
  date +"%Y%m%d_%H%M%S"
}

log() {
  printf '[%s] %s\n' "$(date +"%H:%M:%S")" "$*"
}

write_status() {
  local step="$1"
  local status="$2"
  local extra="${3:-}"
  {
    printf 'step=%s\n' "${step}"
    printf 'status=%s\n' "${status}"
    if [[ -n "${extra}" ]]; then
      printf 'extra=%s\n' "${extra}"
    fi
    printf 'updated_at=%s\n' "$(date --iso-8601=seconds)"
  } > "${STATUS_FILE}"
}

check_stop_file() {
  if [[ -f "${STOP_FILE}" ]]; then
    write_status "stopped" "stop-file-detected" "${STOP_FILE}"
    log "Stop file detected at ${STOP_FILE}, stopping"
    exit 10
  fi
}

ensure_prereqs() {
  command -v codex >/dev/null 2>&1 || die "codex CLI not found in PATH"
  command -v timeout >/dev/null 2>&1 || die "timeout command not found in PATH"
  [[ -x "${VENV_PYTHON}" ]] || die "Missing ${VENV_PYTHON}"
}

acquire_lock() {
  exec 9>"${LOCK_FILE}"
  if ! flock -n 9; then
    die "Another run.sh instance is already active"
  fi
}

trim_old_logs() {
  local logs
  mapfile -t logs < <(find "${LOG_DIR}" -maxdepth 1 -type f -name '*.log' | sort)
  local count="${#logs[@]}"
  if (( count <= KEEP_LOG_COUNT )); then
    return
  fi
  local remove_count=$((count - KEEP_LOG_COUNT))
  local i
  for ((i=0; i<remove_count; i++)); do
    rm -f "${logs[i]}"
  done
}

quota_or_rate_limited() {
  local file="$1"
  grep -Eqi 'credit|quota|rate limit|billing|insufficient|exhaust|too many requests' "$file"
}

extract_session_id() {
  local file="$1"
  awk -F': ' '/session id:/ {print $2}' "$file" | tail -n1
}

extract_remaining_steps() {
  local file="$1"
  local steps
  steps="$(grep -Eo 'Global Remaining steps: [0-9]+' "$file" | tail -n1 | awk '{print $4}' || true)"
  if [[ -z "${steps}" ]]; then
    steps="$(grep -Eo 'Remaining steps: [0-9]+' "$file" | tail -n1 | awk '{print $3}' || true)"
  fi
  if [[ -z "${steps}" ]]; then
    echo ""
  else
    echo "${steps}"
  fi
}

save_session_id() {
  local key="$1"
  local value="$2"
  printf '%s\n' "${value}" > "${STATE_DIR}/${key}.session"
}

load_session_id() {
  local key="$1"
  local path="${STATE_DIR}/${key}.session"
  if [[ -f "${path}" ]]; then
    cat "${path}"
  fi
}

run_codex_new() {
  local key="$1"
  local model="$2"
  local prompt="$3"
  local log_file="${LOG_DIR}/$(timestamp)_${key}.log"
  local prompt_file="${PROMPT_DIR}/${key}.prompt.txt"

  check_stop_file
  printf '%s\n' "${prompt}" > "${prompt_file}"
  write_status "${key}" "running" "model=${model} log=$(basename "${log_file}")"
  log "Starting ${key} with ${model}"
  if ! timeout --foreground "${CODEX_TIMEOUT_SECS}s" \
    codex exec \
      --model "${model}" \
      -C "${ROOT_DIR}" \
      --dangerously-bypass-approvals-and-sandbox \
      "${prompt}" > "${log_file}" 2>&1; then
    cp -f "${log_file}" "${LAST_LOG_FILE}" 2>/dev/null || true
    write_status "${key}" "failed" "see $(basename "${log_file}")"
    die "${key} failed"
  fi
  cp -f "${log_file}" "${LAST_LOG_FILE}" 2>/dev/null || true

  local session_id
  session_id="$(extract_session_id "${log_file}")"
  if [[ -n "${session_id}" ]]; then
    save_session_id "${key}" "${session_id}"
  fi

  quota_or_rate_limited "${log_file}" && die "quota, billing, or rate limit issue detected during ${key}"
  write_status "${key}" "done" "log=$(basename "${log_file}")"
  trim_old_logs
  printf '%s\n' "${log_file}"
}

run_codex_resume() {
  local key="$1"
  local model="$2"
  local prompt="$3"
  local session_id
  session_id="$(load_session_id "${key}")"
  [[ -n "${session_id}" ]] || die "No saved session for ${key}"

  local log_file="${LOG_DIR}/$(timestamp)_${key}.log"
  local prompt_file="${PROMPT_DIR}/${key}.prompt.txt"
  check_stop_file
  printf '%s\n' "${prompt}" > "${prompt_file}"
  write_status "${key}" "running" "resume session=${session_id} model=${model} log=$(basename "${log_file}")"
  log "Resuming ${key} with ${model} using session ${session_id}"
  if ! timeout --foreground "${CODEX_TIMEOUT_SECS}s" \
    codex exec resume \
      --model "${model}" \
      --dangerously-bypass-approvals-and-sandbox \
      "${session_id}" \
      "${prompt}" > "${log_file}" 2>&1; then
    cp -f "${log_file}" "${LAST_LOG_FILE}" 2>/dev/null || true
    write_status "${key}" "resume-failed" "session=${session_id} log=$(basename "${log_file}")"
    return 1
  fi
  cp -f "${log_file}" "${LAST_LOG_FILE}" 2>/dev/null || true

  quota_or_rate_limited "${log_file}" && die "quota, billing, or rate limit issue detected during ${key}"
  write_status "${key}" "done" "log=$(basename "${log_file}")"
  trim_old_logs
  printf '%s\n' "${log_file}"
}

read -r -d '' MASTER_PROMPT <<'EOF' || true
You are working on /home/xor/vextest, an angr-based x86-16 DOS decompiler.

Always use the repository rules from AGENTS.md.

Main operating goals:
1. Run and use cod/ decompilation results as evidence.
2. Generate and maintain /home/xor/vextest/PLAN.md.
3. Improve correctness first.
4. Improve recompilation second.
5. Never add hacks specific to one source file or one sample; fixes must be general-purpose decompiler improvements.
6. Prefer earliest correct layer in the pipeline: IR -> Alias model -> Widening -> Traits -> Types -> Rewrite.

When evaluating progress, compare:
- the original .COD files in cod/
- the generated .dec files in cod/
- the current code state in decompile.py and angr_platforms/X86_16

Always report current quality for:
- correctness
- recompilation

Use concrete evidence from the corpus, not vague claims.
EOF

read -r -d '' PLANNER_PROMPT <<EOF || true
${MASTER_PROMPT}

Planner step:
- Analyze the current difference between .COD files and generated .dec files.
- Inspect the current code state.
- Create or update /home/xor/vextest/PLAN.md with a deterministic step list.
- The plan must prioritize correctness first and recompilation second.
- Remove any done items from PLAN.md and leave only unfinished work.
- Print current quality of correctness and recompilation.
- If there is nothing meaningful left to do, say that clearly.
- If work should pause before the next cycle, print exactly: Pause for minute
- At the end, print exactly: Global Remaining steps: N
EOF

read -r -d '' WORKER_PROMPT <<EOF || true
${MASTER_PROMPT}

Worker step:
- Step 0 on a fresh worker session: before implementing plan items, run the full COD decompilation sweep so you can verify it runs smoothly on the current codebase:
  `./.venv/bin/python -u scripts/decompile_cod_dir.py cod --timeout 20 --subprocess-timeout 600 | tee ${STATE_DIR}/decompile_sweep.log`
- Step 0 on resumed worker iterations: if the full sweep already ran in this worker session, do a lighter verification pass instead of repeating the whole corpus unless the code changed in a way that requires a full rerun.
- Use the result of that sweep as current evidence for correctness, recompilation quality, crashes, and smoothness.
- Continue implementing the unfinished steps from PLAN.md.
- Work like an ongoing resume session: make real code changes, update tests, verify results, and commit often.
- Never use source-specific hacks.
- Keep fixes general-purpose and aligned with the decompiler architecture.
- At the end of each step, print exactly: Global Remaining steps: N
EOF

read -r -d '' REVIEWER_PROMPT <<EOF || true
${MASTER_PROMPT}

Reviewer step:
- In a fresh session, review the current code state and current PLAN.md.
- Check what is genuinely finished and what is not.
- Remove completed steps from /home/xor/vextest/PLAN.md.
- Do not run worker cycles in this step.
- Print achieved results.
- Print the true remaining step count at the end as: Global Remaining steps: N
EOF

planner_step() {
  local log_file
  check_stop_file
  log_file="$(run_codex_new planner "${PLANNER_MODEL}" "${PLANNER_PROMPT}")"

  local remaining
  remaining="$(extract_remaining_steps "${log_file}")"
  [[ -n "${remaining}" ]] || die "Planner did not print remaining step count"

  if grep -Fq "Pause for minute" "${log_file}"; then
    log "Planner requested a pause"
    check_stop_file
    sleep "${PLANNER_PAUSE_SECS}"
  fi

  if [[ "${remaining}" == "0" ]]; then
    log "Planner reported zero remaining steps"
    echo "Global Remaining steps: 0"
    exit 0
  fi

  [[ -f "${PLAN_PATH}" ]] || die "Planner did not create or update ${PLAN_PATH}"
  printf '%s\n' "${remaining}" > "${STATE_DIR}/planner.remaining"
  printf '%s\n' "${log_file}" > "${STATE_DIR}/planner.lastlog"
}

worker_cycle() {
  local worker_session
  worker_session="$(load_session_id worker || true)"
  local i log_file remaining

  for ((i=1; i<=MAX_WORKER_ITERS; i++)); do
    check_stop_file
    log "Worker iteration ${i}/${MAX_WORKER_ITERS}"
    if [[ -n "${worker_session}" ]]; then
      if ! log_file="$(run_codex_resume worker "${WORKER_MODEL}" "${WORKER_PROMPT}")"; then
        log "Worker resume failed, starting a fresh worker session"
        rm -f "${STATE_DIR}/worker.session"
        worker_session=""
        log_file="$(run_codex_new worker "${WORKER_MODEL}" "${WORKER_PROMPT}")"
        worker_session="$(load_session_id worker || true)"
      fi
    else
      log_file="$(run_codex_new worker "${WORKER_MODEL}" "${WORKER_PROMPT}")"
      worker_session="$(load_session_id worker || true)"
    fi

    remaining="$(extract_remaining_steps "${log_file}")"
    [[ -n "${remaining}" ]] || die "Worker did not print remaining step count"

    if grep -Fq "${WORKER_FINISH_TOKEN}" "${log_file}"; then
      log "Worker reported completion"
      return 0
    fi

    log "Worker still has ${remaining} steps left"
    check_stop_file
    sleep "${WORKER_SLEEP_SECS}"
  done

  die "Reached MAX_WORKER_ITERS=${MAX_WORKER_ITERS} without finishing worker cycle"
}

reviewer_step() {
  local log_file
  check_stop_file
  log_file="$(run_codex_new reviewer "${REVIEWER_MODEL}" "${REVIEWER_PROMPT}")"

  local remaining
  remaining="$(extract_remaining_steps "${log_file}")"
  [[ -n "${remaining}" ]] || die "Reviewer did not print remaining step count"

  printf '%s\n' "${remaining}" > "${STATE_DIR}/reviewer.remaining"
  printf '%s\n' "${log_file}" > "${STATE_DIR}/reviewer.lastlog"
  printf '%s\n' "${remaining}"
}

main() {
  ensure_prereqs
  acquire_lock
  write_status "startup" "ready" "timeout=${CODEX_TIMEOUT_SECS}s"
  while true; do
    check_stop_file
    planner_step
    worker_cycle

    local remaining
    remaining="$(reviewer_step)"
    log "Reviewer says ${remaining} steps remain"

    if [[ "${remaining}" == "0" ]]; then
      log "All plan steps completed"
      echo "Global Remaining steps: 0"
      exit 0
    fi
  done
}

main "$@"
