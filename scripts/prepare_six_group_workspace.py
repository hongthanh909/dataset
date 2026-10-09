#!/usr/bin/env python3
"""Create a non-destructive working area for expanding the existing dataset.

Historical inputs may live in archive/legacy-data. Snapshot copies are hash-verified.
This script does not declare automatically screened samples to be ground truth.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from workspace_paths import legacy_data, legacy_readme


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def copy_verified(source: Path, target: Path) -> dict[str, str]:
    source_hash = digest(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if digest(target) != source_hash:
            raise RuntimeError(f"Refusing to overwrite a different snapshot: {target}")
    else:
        shutil.copy2(source, target)
    if digest(target) != source_hash:
        raise RuntimeError(f"Snapshot verification failed: {target}")
    return {"source": str(source), "snapshot": str(target), "sha256": source_hash}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    historical_data = legacy_data(root)
    baseline = historical_data / "python-advisories/phase-5c"
    active = root / "active/six-groups-v2"
    snapshot = root / "archive/phase5c-v1"
    entries = []
    for source in sorted(baseline.iterdir()):
        if source.is_file():
            entries.append(copy_verified(source, snapshot / "dataset" / source.name))
    for source in sorted((root / "config").glob("*.json")):
        entries.append(copy_verified(source, snapshot / "config" / source.name))
    for source in sorted((root / "scripts").glob("*.py")):
        # Preserve original pipeline scripts, not this new workspace helper.
        if source.name in {"collect_python_advisories.py", "collect_missing_cwe_advisories.py",
                           "crawl_filter_mitre_cwe.py", "resolve_review_cwes.py",
                           "merge_python_advisory_candidates.py", "verify_fix_commits.py",
                           "resolve_fix_commits.py", "extract_python_before_after.py",
                           "review_full_function_context.py", "finalize_codebert_dataset.py"}:
            entries.append(copy_verified(source, snapshot / "scripts" / source.name))
    entries.append(copy_verified(legacy_readme(root), snapshot / "README.md"))
    manifest = snapshot / "snapshot_manifest.json"
    if not manifest.exists():
        save_json(manifest, {"created_at_utc": datetime.now(timezone.utc).isoformat(), "files": entries})
    for name in ("discovery", "evidence", "review", "dataset", "training", "reports"):
        (active / name).mkdir(parents=True, exist_ok=True)

    allowlist = read_rows(historical_data / "mitre-cwe/review-resolution/final_selected_cwe_to_model_label.csv")
    selected = [row for row in allowlist if row["model_label"] == "HARDCODED_CREDENTIALS"]
    if not selected:
        raise RuntimeError("No hardcoded-credentials CWEs in the existing approved allowlist")
    subset = active / "discovery/hardcoded_cwe_allowlist.csv"
    with subset.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(selected[0]))
        writer.writeheader()
        writer.writerows(selected)

    rows = read_rows(baseline / "accepted_final_samples.csv")
    hardcoded = [row for row in rows if row["label"] == "HARDCODED_CREDENTIALS"]
    status = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_dataset": str(baseline),
        "baseline_sha256": digest(baseline / "accepted_final_samples.csv"),
        "snapshot": str(snapshot),
        "active_workspace": str(active),
        "baseline_label_counts": dict(sorted(Counter(row["label"] for row in rows).items())),
        "hardcoded_split_counts": {split: sum(row["split"] == split for row in hardcoded)
                                   for split in ("train", "validation", "test")},
        "hardcoded_independent_repositories": sorted({row["repository"] for row in hardcoded}),
        "approved_discovery_cwes": [row["cwe_id"] for row in selected],
        "training_status": "HOLD",
        "training_hold_reasons": [
            "No hardcoded-credentials validation sample in the current grouped split",
            "Only two independent repositories for the existing hardcoded-credentials samples",
            "Candidate snippets and mechanism labels need semantic review before promotion",
            "Existing dataset has vulnerability-class samples only; no verified all-zero controls",
            "Five-group checkpoint path and label mapping have not been supplied",
        ],
        "cleanup": {"permanent_deletions": False,
                    "legacy_data_location": str(historical_data),
                    "legacy_runners_location": str(root / "archive/legacy-runners"),
                    "comparison_files_found_in_this_folder": [],
                    "policy": "Active workspace kept separate; historical evidence retained in archive"},
    }
    save_json(active / "reports/workspace_status.json", status)
    print(json.dumps({"snapshot_files_verified": len(entries),
                      "active_workspace": str(active),
                      "hardcoded_counts": status["hardcoded_split_counts"],
                      "training_status": status["training_status"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
