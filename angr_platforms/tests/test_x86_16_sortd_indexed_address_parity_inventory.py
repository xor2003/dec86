from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.check_sortd_sidecar_free import EXPECTED_SORTD_FUNCTION_ADDRS

REPO_ROOT = Path(__file__).resolve().parents[2]
SORTD_EXE = REPO_ROOT / "SORTD.EXE"
INVENTORY_SCRIPT = REPO_ROOT / "scripts" / "indexed_address_parity_inventory.py"


def test_sortd_sidecar_free_inventory_matches_reviewed_migration_baseline() -> None:
    result = subprocess.run(
        [sys.executable, str(INVENTORY_SCRIPT), str(SORTD_EXE)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["closed"] is True
    assert payload["exact"] is False
    assert tuple(report["function_addr"] for report in payload["functions"]) == EXPECTED_SORTD_FUNCTION_ADDRS
    stats = payload["stats"]
    assert stats == {
        "alias_failure_count": 2,
        "alias_materialized_count": 47,
        "alias_only_count": 18,
        "alias_only_no_legacy_count": 12,
        "classified_fact_count": 49,
        "divergent_function_count": 11,
        "duplicate_key_count": 0,
        "exact_function_count": 9,
        "failure_count": 2,
        "function_count": 20,
        "identity_conflict_count": 8,
        "legacy_only_alias_refusal_count": 0,
        "legacy_only_count": 10,
        "legacy_only_ir_refusal_count": 0,
        "legacy_only_no_ir_count": 8,
        "matched_key_count": 29,
        "materialized_count": 47,
        "normalized_fact_count": 49,
        "normalized_key_count": 86,
        "raw_fact_count": 49,
        "raw_key_count": 86,
    }
