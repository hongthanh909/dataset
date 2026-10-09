#!/usr/bin/env python3
"""Normalize freshly collected hardcoded-credential advisories for evidence review.

No rows are added to the accepted dataset. Keep direct advisory mappings separate
from semantic verification of each selected source-code unit.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from merge_python_advisory_candidates import normalize_direct, read_csv, write_csv
from workspace_paths import legacy_data


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    active = root / "active/six-groups-v2"
    live = normalize_direct(read_csv(active / "discovery/github/cve_ghsa_by_cwe.csv"))
    old = read_csv(legacy_data(root) / "python-advisories/all_python_advisory.csv")
    old_ids = {row.get("ghsa_id") or row.get("cve_id") for row in old
               if row.get("model_label") == "HARDCODED_CREDENTIALS"}
    rows = [row for row in live if row["model_label"] == "HARDCODED_CREDENTIALS"]
    rows.sort(key=lambda row: (row["target_cwe_id"], row["ghsa_id"]))
    destination = active / "evidence/all_python_advisory.csv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_csv(destination, rows)
    ids = {row["ghsa_id"] or row["cve_id"] for row in rows}
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "candidate_rows": len(rows),
        "unique_advisories": len(ids),
        "new_advisories_vs_old_hardcoded_queue": sorted(ids - old_ids),
        "candidate_cwe_counts": dict(sorted(Counter(row["target_cwe_id"] for row in rows).items())),
        "candidate_rows_with_commit_reference": sum(bool(row["commit_reference_count"]) for row in rows),
        "training_samples_added": 0,
        "status": "CANDIDATES_ONLY_REQUIRES_SOURCE_FIX_AND_LABEL_REVIEW",
    }
    (active / "reports/hardcoded_discovery_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
