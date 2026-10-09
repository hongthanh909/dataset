from __future__ import annotations

import argparse
import csv
import io
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


RESOLUTIONS = {
    "PROMOTE_TO_SELECT",
    "REVIEW_PER_SAMPLE",
    "DISCOVERY_ONLY",
    "EXCLUDE",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def pending_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}.pending{path.suffix}")


def write_bytes_if_changed(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.exists() and path.read_bytes() == payload:
            return
        path.write_bytes(payload)
    except PermissionError as error:
        fallback = pending_path(path)
        fallback.write_bytes(payload)
        raise PermissionError(
            f"Cannot update '{path}' because it is open in Excel/WPS or another "
            f"application. Close that file and run the command again. The new "
            f"content was saved to '{fallback}'."
        ) from error


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    write_bytes_if_changed(path, buffer.getvalue().encode("utf-8-sig"))


def cwe_number(cwe_id: str) -> int:
    return int(cwe_id.upper().replace("CWE-", ""))


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Resolve the 10 CWE taxonomy review items into final project decisions."
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=project_root / "config" / "review_resolution.json",
    )
    parser.add_argument(
        "--taxonomy-dir",
        type=Path,
        default=project_root / "data" / "mitre-cwe" / "combined",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_root / "data" / "mitre-cwe" / "review-resolution",
    )
    args = parser.parse_args()

    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    decisions: dict[str, dict[str, Any]] = policy["decisions"]
    review_rows = read_csv(args.taxonomy_dir / "review_queue.csv")
    selected_rows = read_csv(args.taxonomy_dir / "selected_cwe_to_model_label.csv")

    review_by_id = {row["cwe_id"]: row for row in review_rows}
    policy_ids = set(decisions)
    review_ids = set(review_by_id)
    if policy_ids != review_ids:
        missing = sorted(review_ids - policy_ids, key=cwe_number)
        stale = sorted(policy_ids - review_ids, key=cwe_number)
        raise ValueError(
            "Review policy and review queue differ. "
            f"Missing policy decisions={missing}; stale policy decisions={stale}"
        )

    resolved: list[dict[str, Any]] = []
    for cwe_id in sorted(policy_ids, key=cwe_number):
        source = review_by_id[cwe_id]
        decision = decisions[cwe_id]
        resolution = str(decision["resolution"])
        if resolution not in RESOLUTIONS:
            raise ValueError(f"Invalid resolution {resolution!r} for {cwe_id}")
        if decision["model_label"] != source["model_label"]:
            raise ValueError(
                f"Model-label mismatch for {cwe_id}: "
                f"queue={source['model_label']} policy={decision['model_label']}"
            )
        resolved.append(
            {
                **source,
                "initial_decision": source["decision"],
                "final_resolution": resolution,
                "review_criteria": ";".join(decision.get("criteria", [])),
                "resolution_reason": decision["reason"],
                "sample_acceptance_condition": decision["sample_acceptance_condition"],
                "mitre_review_url": decision["mitre_url"],
                "review_policy_version": policy["policy_version"],
                "reviewed_catalog_version": policy["catalog_version_reviewed"],
                "reviewed_catalog_date": policy["catalog_date_reviewed"],
            }
        )

    resolution_fields = list(resolved[0].keys())
    write_csv(args.output_dir / "review_resolution.csv", resolved, resolution_fields)
    for resolution, filename in (
        ("PROMOTE_TO_SELECT", "promoted_to_select.csv"),
        ("REVIEW_PER_SAMPLE", "review_per_sample.csv"),
        ("DISCOVERY_ONLY", "discovery_only.csv"),
        ("EXCLUDE", "excluded_after_review.csv"),
    ):
        write_csv(
            args.output_dir / filename,
            [row for row in resolved if row["final_resolution"] == resolution],
            resolution_fields,
        )

    promoted = [row for row in resolved if row["final_resolution"] == "PROMOTE_TO_SELECT"]
    final_selected = [dict(row) for row in selected_rows]
    selected_fields = list(selected_rows[0].keys())
    for row in promoted:
        promoted_row = {field: row.get(field, "") for field in selected_fields}
        promoted_row["decision"] = "SELECT"
        promoted_row["decision_reason"] = (
            "Promoted after consistency review: " + row["resolution_reason"]
        )
        final_selected.append(promoted_row)
    final_selected.sort(key=lambda row: (row["model_label"], cwe_number(row["cwe_id"])))

    duplicates: dict[str, set[str]] = defaultdict(set)
    for row in final_selected:
        duplicates[row["cwe_id"]].add(row["model_label"])
    overlap = {
        cwe_id: sorted(labels)
        for cwe_id, labels in duplicates.items()
        if len(labels) > 1
    }
    if overlap:
        raise ValueError(f"Final selected mapping contains label overlap: {overlap}")

    write_csv(
        args.output_dir / "final_selected_cwe_to_model_label.csv",
        final_selected,
        selected_fields,
    )

    counts = Counter(row["final_resolution"] for row in resolved)
    summary = {
        "review_policy_version": policy["policy_version"],
        "catalog_version": policy["catalog_version_reviewed"],
        "catalog_date": policy["catalog_date_reviewed"],
        "reviewed_cwes": len(resolved),
        "resolution_counts": dict(sorted(counts.items())),
        "initial_selected_cwes": len(selected_rows),
        "promoted_cwes": len(promoted),
        "final_selected_cwes": len(final_selected),
        "final_selected_overlap_conflicts": 0,
        "criteria": policy["criteria"],
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_bytes_if_changed(
        args.output_dir / "resolution_summary.json",
        (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )

    print(f"Reviewed CWE items: {len(resolved)}")
    for resolution in (
        "PROMOTE_TO_SELECT",
        "REVIEW_PER_SAMPLE",
        "DISCOVERY_ONLY",
        "EXCLUDE",
    ):
        ids = [row["cwe_id"] for row in resolved if row["final_resolution"] == resolution]
        print(f"{resolution}: {len(ids)} ({', '.join(ids) if ids else '-'})")
    print(f"Final selected CWE mappings: {len(final_selected)}")
    print(f"Output: {args.output_dir}")


if __name__ == "__main__":
    main()
