#!/usr/bin/env python3
"""Phase 3C: merge direct and parent/root Python advisory candidates.

The merged file is a work queue, not an accepted dataset.  It preserves the
difference between direct advisory-CWE mappings and child-CWE hypotheses found
through a parent/root CWE.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FIELDS = [
    "record_id",
    "cohort",
    "model_label",
    "target_cwe_id",
    "target_cwe_name",
    "discovery_cwe_id",
    "advisory_cwe_ids",
    "resolved_cwe_id",
    "ghsa_id",
    "cve_id",
    "osv_id",
    "summary",
    "severity",
    "package_names",
    "affected_package_ranges",
    "repository_url",
    "advisory_url",
    "commit_urls",
    "commit_reference_count",
    "discovery_source",
    "python_evidence_status",
    "mapping_status",
    "review_status",
    "next_gate",
]


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--direct",
        type=Path,
        default=project_root
        / "data"
        / "python-advisories"
        / "cve_ghsa_by_cwe.csv",
    )
    parser.add_argument(
        "--phase3b",
        type=Path,
        default=project_root
        / "data"
        / "python-advisories"
        / "phase-3b"
        / "phase3b_candidates.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root
        / "data"
        / "python-advisories"
        / "all_python_advisory.csv",
    )
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"Input CSV is empty: {path}")
    return rows


def parse_json_list(value: str) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return [part for part in value.split(";") if part]
    return parsed if isinstance(parsed, list) else [parsed]


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def record_id(target_cwe: str, advisory_id: str, cohort: str) -> str:
    value = "|".join([target_cwe, advisory_id, cohort])
    return "ALLADV-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def normalize_direct(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        advisory_id = row.get("ghsa_id") or row.get("cve_id") or ""
        target = row["cwe_id"]
        commits = parse_json_list(row.get("commit_urls", ""))
        output.append(
            {
                "record_id": record_id(target, advisory_id, "DIRECT_38_CWE"),
                "cohort": "DIRECT_38_CWE",
                "model_label": row["model_label"],
                "target_cwe_id": target,
                "target_cwe_name": row.get("cwe_name", ""),
                "discovery_cwe_id": target,
                "advisory_cwe_ids": target,
                "resolved_cwe_id": "",
                "ghsa_id": row.get("ghsa_id", ""),
                "cve_id": row.get("cve_id", ""),
                "osv_id": "",
                "summary": row.get("summary", ""),
                "severity": row.get("severity", ""),
                "package_names": row.get("package_names", ""),
                "affected_package_ranges": row.get("affected_package_ranges", "[]"),
                "repository_url": row.get("repository_url", ""),
                "advisory_url": row.get("advisory_url", ""),
                "commit_urls": json_text(sorted({str(value) for value in commits})),
                "commit_reference_count": len(commits),
                "discovery_source": "GITHUB_REVIEWED_DIRECT_CWE",
                "python_evidence_status": "CONFIRMED_GITHUB_PIP_FILTER",
                "mapping_status": "DIRECT_ADVISORY_CWE_NEEDS_FIX_VALIDATION",
                "review_status": "PENDING_FIX_COMMIT_REVIEW",
                "next_gate": "RESOLVE_FIX_COMMIT_THEN_APPLY_TC01_TC08",
            }
        )
    return output


def normalize_phase3b(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        advisory_id = row.get("ghsa_id") or row.get("cve_id") or row.get("osv_id") or ""
        grouped[(row["target_cwe_id"], advisory_id)].append(row)

    output: list[dict[str, Any]] = []
    for (target, advisory_id), items in grouped.items():
        first = items[0]
        packages: set[str] = set()
        commits: set[str] = set()
        sources: set[str] = set()
        advisory_cwes: set[str] = set()
        repositories: list[str] = []
        for item in items:
            packages.update(part for part in item.get("package_names", "").split(";") if part)
            commits.update(str(value) for value in parse_json_list(item.get("commit_urls", "")))
            sources.add(item.get("discovery_source", ""))
            advisory_cwes.update(
                part for part in item.get("advisory_cwe_ids", "").split(";") if part
            )
            if item.get("repository_url"):
                repositories.append(item["repository_url"])

        exact = any(
            item.get("mapping_status") == "DIRECT_EXACT_NEEDS_FIX_VALIDATION"
            for item in items
        )
        if exact:
            cohort = "SUPPLEMENTAL_EXACT_25_CWE"
            mapping_status = "DIRECT_EXACT_NEEDS_FIX_VALIDATION"
        else:
            cohort = "PARENT_ROOT_CANDIDATE_25_CWE"
            mapping_status = "PARENT_CANDIDATE_NEEDS_CODE_REVIEW"
        output.append(
            {
                "record_id": record_id(target, advisory_id, cohort),
                "cohort": cohort,
                "model_label": first["model_label"],
                "target_cwe_id": target,
                "target_cwe_name": first.get("target_cwe_name", ""),
                "discovery_cwe_id": first.get("discovery_cwe_id", ""),
                "advisory_cwe_ids": ";".join(sorted(advisory_cwes)),
                "resolved_cwe_id": "",
                "ghsa_id": first.get("ghsa_id", ""),
                "cve_id": first.get("cve_id", ""),
                "osv_id": first.get("osv_id", ""),
                "summary": first.get("summary", ""),
                "severity": "",
                "package_names": ";".join(sorted(packages)),
                "affected_package_ranges": "[]",
                "repository_url": repositories[0] if repositories else "",
                "advisory_url": first.get("advisory_url", ""),
                "commit_urls": json_text(sorted(commits)),
                "commit_reference_count": len(commits),
                "discovery_source": ";".join(sorted(value for value in sources if value)),
                "python_evidence_status": first.get("python_evidence_status", ""),
                "mapping_status": mapping_status,
                "review_status": "PENDING_FIX_COMMIT_AND_CWE_REVIEW",
                "next_gate": "VERIFY_FIX_COMMIT_AND_DECIDE_CHILD_OR_PARENT",
            }
        )
    return output


def pending_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}.pending{path.suffix}")


def write_bytes_if_changed(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == content:
        return
    try:
        path.write_bytes(content)
    except PermissionError as exc:
        fallback = pending_path(path)
        fallback.write_bytes(content)
        raise PermissionError(
            f"Cannot update {path}; it is probably open in Excel/WPS. "
            f"New content was saved to {fallback}. Close it and rerun."
        ) from exc


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    write_bytes_if_changed(path, buffer.getvalue().encode("utf-8-sig"))


def main() -> int:
    args = parse_args()
    direct = normalize_direct(read_csv(args.direct))
    phase3b = normalize_phase3b(read_csv(args.phase3b))
    rows = [*direct, *phase3b]
    rows.sort(
        key=lambda row: (
            row["model_label"],
            int(str(row["target_cwe_id"]).split("-", 1)[1]),
            row["cohort"],
            row["ghsa_id"] or row["cve_id"] or row["osv_id"],
        )
    )

    record_ids = [str(row["record_id"]) for row in rows]
    if len(record_ids) != len(set(record_ids)):
        duplicates = [key for key, count in Counter(record_ids).items() if count > 1]
        raise ValueError(f"Duplicate merged record IDs: {duplicates[:10]}")
    target_cwes = {str(row["target_cwe_id"]) for row in rows}
    if len(target_cwes) != 63:
        raise ValueError(f"Expected coverage for 63 target CWE, found {len(target_cwes)}")

    write_csv(args.output, rows)
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "output": str(args.output.resolve()),
        "rows": len(rows),
        "unique_record_ids": len(set(record_ids)),
        "unique_advisories": len(
            {
                row["ghsa_id"] or row["cve_id"] or row["osv_id"]
                for row in rows
            }
        ),
        "target_cwes": len(target_cwes),
        "model_labels": len({str(row["model_label"]) for row in rows}),
        "cohort_counts": dict(sorted(Counter(row["cohort"] for row in rows).items())),
        "mapping_status_counts": dict(
            sorted(Counter(row["mapping_status"] for row in rows).items())
        ),
        "warning": (
            "This is an advisory candidate work queue. Rows from the 25-CWE "
            "parent/root cohort are not child-CWE confirmations."
        ),
    }
    summary_path = args.output.with_name("all_python_advisory_summary.json")
    write_bytes_if_changed(
        summary_path,
        (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )

    print(f"Direct-CWE advisory rows: {len(direct)}")
    print(f"Phase 3B advisory rows after target/advisory grouping: {len(phase3b)}")
    print(f"Merged advisory work-queue rows: {len(rows)}")
    print(f"Unique advisories: {summary['unique_advisories']}")
    print(f"Target CWE coverage: {summary['target_cwes']}")
    for cohort, count in summary["cohort_counts"].items():
        print(f"{cohort}: {count}")
    print(f"Output: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, PermissionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
