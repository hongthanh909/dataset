#!/usr/bin/env python3
"""Phase 4B: resolve parent commits and correlate commit/advisory evidence."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import html
import io
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


USER_AGENT = "PyVul-Fix-Commit-Resolver/1.0 (+research dataset builder)"
EMBEDDED_RE = re.compile(
    r'<script[^>]+data-target="react-app\.embeddedData"[^>]*>(.*?)</script>',
    re.DOTALL,
)

COMMIT_FIELDS = [
    "commit_key",
    "commit_url",
    "github_repository",
    "requested_sha",
    "actual_commit_sha",
    "parent_commits",
    "parent_count",
    "commit_subject",
    "commit_body",
    "authored_at",
    "committed_at",
    "python_files",
    "python_file_count",
    "repository_match",
    "related_record_count",
    "record_ids",
    "advisory_ids",
    "cohorts",
    "model_labels",
    "target_cwe_ids",
    "identifier_matches",
    "semantic_signal_hits",
    "phase4a_status",
    "phase4b_status",
    "phase4b_reason",
    "metadata_fetch_status",
    "metadata_cache_path",
    "error",
]

RECORD_FIELDS = [
    "record_id",
    "commit_key",
    "cohort",
    "model_label",
    "target_cwe_id",
    "discovery_cwe_id",
    "advisory_cwe_ids",
    "resolved_cwe_id",
    "cwe_resolution_status",
    "ghsa_id",
    "cve_id",
    "osv_id",
    "repository_url",
    "fix_commit",
    "parent_commit",
    "python_files",
    "fix_commit_status",
    "fix_evidence",
    "next_gate",
]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    base = root / "data" / "python-advisories"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisories", type=Path, default=base / "all_python_advisory.csv")
    parser.add_argument(
        "--phase4a",
        type=Path,
        default=base / "fix-commits" / "commit_patch_verification.csv",
    )
    parser.add_argument(
        "--record-map",
        type=Path,
        default=base / "fix-commits" / "record_commit_map.csv",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=base / "fix-commits" / "phase-4b"
    )
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--timeout", type=int, default=45)
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"Input CSV is empty: {path}")
    return rows


def parse_json_list(value: str) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return [item for item in value.split(";") if item]
    if not isinstance(parsed, list):
        parsed = [parsed]
    return [str(item) for item in parsed if item]


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


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


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    write_bytes_if_changed(path, buffer.getvalue().encode("utf-8-sig"))


def metadata_cache_path(cache_dir: Path, commit_url: str) -> Path:
    digest = hashlib.sha256(commit_url.encode("utf-8")).hexdigest()
    return cache_dir / digest[:2] / f"{digest}.json"


def find_commit_payload(page: str) -> dict[str, Any]:
    for match in EMBEDDED_RE.finditer(page):
        raw = html.unescape(match.group(1))
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        payload = value.get("payload") or {}
        commit = ((payload.get("commitRoute") or {}).get("commit") or {})
        if commit.get("oid"):
            return commit
    raise ValueError("GitHub embedded commit metadata was not found")


def fetch_commit_metadata(url: str, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
    )
    last_error = ""
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                page = response.read().decode("utf-8", errors="replace")
            commit = find_commit_payload(page)
            return {
                "fetch_status": "FETCHED",
                "oid": commit.get("oid") or "",
                "parents": commit.get("parents") or [],
                "subject": commit.get("shortMessage")
                or re.sub(r"<[^>]+>", "", commit.get("shortMessageMarkdown") or ""),
                "body": commit.get("bodyMessageHtml") or "",
                "authored_at": commit.get("authoredDate") or "",
                "committed_at": commit.get("committedDate") or "",
                "error": "",
            }
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_error = str(exc)
            if attempt < 3:
                time.sleep(2**attempt)
                continue
            return {"fetch_status": "FETCH_FAILED", "error": last_error}
    return {"fetch_status": "FETCH_FAILED", "error": last_error}


def load_or_fetch(
    row: dict[str, str], cache_dir: Path, refresh: bool, timeout: int
) -> tuple[dict[str, Any], Path]:
    path = metadata_cache_path(cache_dir, row["commit_url"])
    if path.exists() and not refresh:
        return json.loads(path.read_text(encoding="utf-8")), path
    value = fetch_commit_metadata(row["commit_url"], timeout)
    if value["fetch_status"] == "FETCHED":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return value, path


def strip_html(value: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", value or ""))


def resolve_one(
    row: dict[str, str],
    related_rows: list[dict[str, str]],
    cache_dir: Path,
    refresh: bool,
    timeout: int,
) -> dict[str, Any]:
    meta, path = load_or_fetch(row, cache_dir, refresh, timeout)
    result: dict[str, Any] = {
        "commit_key": row["commit_key"],
        "commit_url": row["commit_url"],
        "github_repository": row["github_repository"],
        "requested_sha": row["requested_sha"],
        "actual_commit_sha": row.get("actual_commit_sha", ""),
        "parent_commits": "[]",
        "parent_count": 0,
        "commit_subject": row.get("commit_subject", ""),
        "commit_body": "",
        "authored_at": "",
        "committed_at": "",
        "python_files": row.get("python_files", "[]"),
        "python_file_count": row.get("python_file_count", "0"),
        "repository_match": row.get("repository_match", ""),
        "related_record_count": len(related_rows),
        "record_ids": json_text(sorted({item["record_id"] for item in related_rows})),
        "advisory_ids": ";".join(
            sorted(
                {
                    item.get("ghsa_id") or item.get("cve_id") or item.get("osv_id") or ""
                    for item in related_rows
                }
                - {""}
            )
        ),
        "cohorts": ";".join(sorted({item["cohort"] for item in related_rows})),
        "model_labels": ";".join(sorted({item["model_label"] for item in related_rows})),
        "target_cwe_ids": ";".join(
            sorted(
                {item["target_cwe_id"] for item in related_rows},
                key=lambda value: int(value.split("-")[1]),
            )
        ),
        "identifier_matches": "[]",
        "semantic_signal_hits": row.get("semantic_signal_hits", "[]"),
        "phase4a_status": row.get("fix_validation_status", ""),
        "phase4b_status": "METADATA_FETCH_FAILED",
        "phase4b_reason": "",
        "metadata_fetch_status": meta.get("fetch_status", "FETCH_FAILED"),
        "metadata_cache_path": str(path.resolve()) if path.exists() else "",
        "error": meta.get("error", ""),
    }
    if meta.get("fetch_status") != "FETCHED":
        result["phase4b_reason"] = "Could not retrieve GitHub commit metadata"
        return result

    parents = [str(value) for value in meta.get("parents") or []]
    subject = strip_html(str(meta.get("subject") or row.get("commit_subject") or "")).strip()
    body = strip_html(str(meta.get("body") or "")).strip()
    identifiers = {
        item.get("ghsa_id") or item.get("cve_id") or item.get("osv_id") or ""
        for item in related_rows
    } - {""}
    combined_text = (subject + "\n" + body).lower()
    identifier_matches = sorted(
        identifier for identifier in identifiers if identifier.lower() in combined_text
    )

    result.update(
        {
            "actual_commit_sha": meta.get("oid") or row.get("actual_commit_sha", ""),
            "parent_commits": json_text(parents),
            "parent_count": len(parents),
            "commit_subject": subject,
            "commit_body": body,
            "authored_at": meta.get("authored_at") or "",
            "committed_at": meta.get("committed_at") or "",
            "identifier_matches": json_text(identifier_matches),
        }
    )

    if len(parents) == 0:
        status = "NO_PARENT_COMMIT"
        reason = "Commit metadata has no parent"
    elif len(parents) > 1:
        status = "MERGE_COMMIT_REVIEW"
        reason = "Merge commit has multiple parents; vulnerable baseline is ambiguous"
    elif row.get("repository_match") == "MISMATCH_REVIEW":
        status = "REPOSITORY_MISMATCH_REVIEW"
        reason = "Commit repository differs from the advisory source repository"
    elif identifier_matches:
        status = "CONFIRMED_FIX_EVIDENCE_AUTO"
        reason = "Commit text names a related GHSA/CVE/OSV identifier and changes Python"
    elif row.get("fix_validation_status") == "HIGH_PRIORITY_PYTHON_FIX_CANDIDATE":
        status = "PROVISIONAL_FIX_EVIDENCE_AUTO"
        reason = "Python patch, repository match, fix signal, and security-family signal agree"
    else:
        status = "SEMANTIC_REVIEW_REQUIRED"
        reason = "Python changed but advisory-to-patch semantics are not strong enough for auto confirmation"
    result["phase4b_status"] = status
    result["phase4b_reason"] = reason
    return result


def main() -> int:
    args = parse_args()
    if args.workers < 1 or args.workers > 16:
        raise ValueError("--workers must be between 1 and 16")
    advisories = read_csv(args.advisories)
    phase4a = read_csv(args.phase4a)
    record_map = read_csv(args.record_map)

    advisory_by_record = {row["record_id"]: row for row in advisories}
    records_by_commit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for mapping in record_map:
        source = advisory_by_record.get(mapping["record_id"])
        if source:
            records_by_commit[mapping["commit_key"]].append(source)

    python_rows = [row for row in phase4a if int(row.get("python_file_count") or 0) > 0]
    selected = python_rows[: args.limit] if args.limit else python_rows
    cache_dir = args.output_dir / "cache" / "commit-metadata"
    results: list[dict[str, Any]] = []
    lock = threading.Lock()
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                resolve_one,
                row,
                records_by_commit.get(row["commit_key"], []),
                cache_dir,
                args.refresh,
                args.timeout,
            ): row
            for row in selected
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            with lock:
                completed += 1
                if completed % 25 == 0 or completed == len(selected):
                    print(f"Resolved parent/semantic metadata: {completed}/{len(selected)}", flush=True)

    results.sort(key=lambda row: (row["github_repository"].lower(), row["requested_sha"]))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "commit_parent_semantic_verification.csv", results, COMMIT_FIELDS)

    accepted_statuses = {"CONFIRMED_FIX_EVIDENCE_AUTO", "PROVISIONAL_FIX_EVIDENCE_AUTO"}
    verified = [row for row in results if row["phase4b_status"] in accepted_statuses]
    review = [row for row in results if row["phase4b_status"] not in accepted_statuses]
    write_csv(args.output_dir / "verified_python_fix_commits.csv", verified, COMMIT_FIELDS)
    write_csv(args.output_dir / "fix_commit_semantic_review_queue.csv", review, COMMIT_FIELDS)

    commit_result = {row["commit_key"]: row for row in results}
    record_rows: list[dict[str, Any]] = []
    for mapping in record_map:
        commit = commit_result.get(mapping["commit_key"])
        source = advisory_by_record.get(mapping["record_id"])
        if not commit or not source:
            continue
        parents = parse_json_list(commit["parent_commits"])
        fix_status = commit["phase4b_status"]
        if fix_status in accepted_statuses and source["cohort"] == "DIRECT_38_CWE":
            resolved_cwe = source["target_cwe_id"]
            cwe_status = "DIRECT_CWE_CONFIRMED_WITH_FIX_EVIDENCE"
            next_gate = "EXTRACT_CODE_BEFORE_AFTER_THEN_APPLY_TC01_TC08"
        elif fix_status in accepted_statuses:
            resolved_cwe = ""
            cwe_status = "CHILD_CWE_REQUIRES_CODE_REVIEW"
            next_gate = "EXTRACT_CODE_FOR_PARENT_CHILD_RESOLUTION"
        else:
            resolved_cwe = ""
            cwe_status = "FIX_COMMIT_REVIEW_REQUIRED"
            next_gate = "MANUAL_FIX_COMMIT_REVIEW"
        record_rows.append(
            {
                "record_id": source["record_id"],
                "commit_key": mapping["commit_key"],
                "cohort": source["cohort"],
                "model_label": source["model_label"],
                "target_cwe_id": source["target_cwe_id"],
                "discovery_cwe_id": source["discovery_cwe_id"],
                "advisory_cwe_ids": source["advisory_cwe_ids"],
                "resolved_cwe_id": resolved_cwe,
                "cwe_resolution_status": cwe_status,
                "ghsa_id": source["ghsa_id"],
                "cve_id": source["cve_id"],
                "osv_id": source["osv_id"],
                "repository_url": source["repository_url"],
                "fix_commit": commit["actual_commit_sha"],
                "parent_commit": parents[0] if len(parents) == 1 else "",
                "python_files": commit["python_files"],
                "fix_commit_status": fix_status,
                "fix_evidence": commit["phase4b_reason"],
                "next_gate": next_gate,
            }
        )
    record_rows.sort(key=lambda row: (row["record_id"], row["commit_key"]))
    write_csv(args.output_dir / "record_fix_resolution.csv", record_rows, RECORD_FIELDS)
    resolved_direct = [
        row for row in record_rows if row["cwe_resolution_status"] == "DIRECT_CWE_CONFIRMED_WITH_FIX_EVIDENCE"
    ]
    write_csv(args.output_dir / "resolved_cve_ghsa_by_cwe.csv", resolved_direct, RECORD_FIELDS)

    status_counts = Counter(row["phase4b_status"] for row in results)
    cwe_counts = Counter(row["cwe_resolution_status"] for row in record_rows)
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "python_commits_from_phase4a": len(python_rows),
        "processed_in_this_run": len(results),
        "verified_or_provisional_fix_commits": len(verified),
        "semantic_review_commits": len(review),
        "parent_sha_resolved": sum(int(row["parent_count"] or 0) == 1 for row in results),
        "phase4b_status_counts": dict(sorted(status_counts.items())),
        "record_fix_resolution_rows": len(record_rows),
        "cwe_resolution_status_counts": dict(sorted(cwe_counts.items())),
        "resolved_direct_rows": len(resolved_direct),
        "warning": (
            "PROVISIONAL_FIX_EVIDENCE_AUTO is suitable for extraction/review, not final TC01-TC08 acceptance. "
            "Parent/root cohort rows never receive a child resolved_cwe_id automatically."
        ),
    }
    write_bytes_if_changed(
        args.output_dir / "phase4b_summary.json",
        (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )

    print(f"Python commits processed: {len(results)}")
    print(f"Verified/provisional fix commits: {len(verified)}")
    print(f"Commits needing semantic review: {len(review)}")
    print(f"Single parent SHA resolved: {summary['parent_sha_resolved']}")
    print(f"Resolved direct-CWE record rows: {len(resolved_direct)}")
    for status, count in sorted(status_counts.items()):
        print(f"{status}: {count}")
    print(f"Output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, PermissionError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
