#!/usr/bin/env python3
"""Collect PyPI advisory candidates for the project's selected CWE allowlist.

This is the first stage of sample discovery.  It does not claim that an
advisory, reference, or commit passes TC01-TC08.  The output is a reviewable
candidate inventory that preserves the source CWE -> model-label mapping.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


API_URL = "https://api.github.com/advisories"
API_VERSION = "2022-11-28"
USER_AGENT = "PyVul-Python-Advisory-Collector/1.0 (+research dataset builder)"
COMMIT_URL_RE = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})(?:[/?#].*)?$"
)
REPOSITORY_URL_RE = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+)")


FIELDS = [
    "candidate_id",
    "model_label",
    "source_cwe_id",
    "source_cwe_name",
    "all_advisory_cwes",
    "label_resolution",
    "ghsa_id",
    "cve_id",
    "advisory_type",
    "severity",
    "summary",
    "description",
    "package_name",
    "ecosystem",
    "vulnerable_version_range",
    "first_patched_version",
    "vulnerable_functions",
    "repository_url",
    "repository_advisory_url",
    "advisory_url",
    "references",
    "commit_urls",
    "commit_reference_count",
    "published_at",
    "updated_at",
    "withdrawn_at",
    "cvss_v3_score",
    "cvss_v3_vector",
    "cvss_v4_score",
    "cvss_v4_vector",
    "discovery_source",
    "candidate_status",
    "next_gate",
]

CVE_GHSA_BY_CWE_FIELDS = [
    "model_label",
    "cwe_id",
    "cwe_name",
    "ghsa_id",
    "cve_id",
    "summary",
    "severity",
    "package_names",
    "affected_package_ranges",
    "repository_url",
    "advisory_url",
    "commit_urls",
    "commit_reference_count",
    "label_resolution",
    "candidate_status",
    "published_at",
    "updated_at",
]

MISSING_CWE_PLAN_FIELDS = [
    "model_label",
    "missing_cwe_id",
    "missing_cwe_name",
    "path_from_root",
    "fallback_discovery_cwe",
    "fallback_type",
    "fallback_github_pip_advisories",
    "resolution_status",
    "resolution_rule",
]


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Query GitHub Global Security Advisories for the final CWE allowlist "
            "and retain only PyPI/Python advisory candidates."
        )
    )
    parser.add_argument(
        "--cwe-file",
        type=Path,
        default=(
            project_root
            / "data"
            / "mitre-cwe"
            / "review-resolution"
            / "final_selected_cwe_to_model_label.csv"
        ),
        help="CSV containing cwe_id and model_label.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_root / "data" / "python-advisories",
        help="Directory for raw and normalized advisory outputs.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Call GitHub again instead of reusing the cached raw response.",
    )
    parser.add_argument(
        "--include-unreviewed",
        action="store_true",
        help="Also collect GitHub unreviewed advisories (kept visibly marked).",
    )
    parser.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable containing an optional GitHub token.",
    )
    return parser.parse_args()


def read_cwe_allowlist(path: Path) -> tuple[list[dict[str, str]], dict[str, dict[str, str]]]:
    if not path.exists():
        raise FileNotFoundError(f"CWE allowlist not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"CWE allowlist is empty: {path}")
    required = {"cwe_id", "model_label"}
    missing = required - set(rows[0])
    if missing:
        raise ValueError(f"CWE allowlist is missing columns: {sorted(missing)}")

    mapping: dict[str, dict[str, str]] = {}
    for row in rows:
        cwe_id = str(row["cwe_id"]).strip().upper()
        if not re.fullmatch(r"CWE-\d+", cwe_id):
            raise ValueError(f"Invalid CWE ID in allowlist: {cwe_id!r}")
        if cwe_id in mapping and mapping[cwe_id]["model_label"] != row["model_label"]:
            raise ValueError(
                f"CWE label conflict for {cwe_id}: "
                f"{mapping[cwe_id]['model_label']} vs {row['model_label']}"
            )
        row = dict(row)
        row["cwe_id"] = cwe_id
        mapping[cwe_id] = row
    return rows, mapping


def parse_next_link(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        match = re.match(r"<([^>]+)>", section)
        if match:
            return match.group(1)
    return None


def fetch_json(url: str, token: str, attempts: int = 4) -> tuple[Any, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(attempts):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read().decode("utf-8"))
                return payload, response.headers
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            retryable = exc.code in {429, 500, 502, 503, 504}
            remaining = exc.headers.get("X-RateLimit-Remaining", "")
            reset = exc.headers.get("X-RateLimit-Reset", "")
            if exc.code == 403 and remaining == "0":
                reset_text = "unknown"
                if reset.isdigit():
                    reset_text = datetime.fromtimestamp(
                        int(reset), tz=timezone.utc
                    ).isoformat()
                raise RuntimeError(
                    "GitHub API rate limit exhausted. Set GITHUB_TOKEN and rerun; "
                    f"reset time: {reset_text}. Response: {body[:500]}"
                ) from exc
            if retryable and attempt + 1 < attempts:
                time.sleep(2**attempt)
                continue
            raise RuntimeError(
                f"GitHub API request failed with HTTP {exc.code}: {body[:1000]}"
            ) from exc
        except urllib.error.URLError as exc:
            if attempt + 1 < attempts:
                time.sleep(2**attempt)
                continue
            raise RuntimeError(f"GitHub API request failed: {exc}") from exc
    raise AssertionError("unreachable")


def collect_github_advisories(
    cwe_ids: Iterable[str], token: str, include_unreviewed: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    numeric_cwes = ",".join(cwe_id.split("-", 1)[1] for cwe_id in cwe_ids)
    advisory_types = ["reviewed"]
    if include_unreviewed:
        advisory_types.append("unreviewed")

    advisories_by_id: dict[str, dict[str, Any]] = {}
    requests: list[dict[str, Any]] = []
    for advisory_type in advisory_types:
        params = urllib.parse.urlencode(
            {
                "ecosystem": "pip",
                "cwes": numeric_cwes,
                "type": advisory_type,
                "is_withdrawn": "false",
                "per_page": "100",
            }
        )
        url: str | None = f"{API_URL}?{params}"
        page = 0
        while url:
            page += 1
            payload, headers = fetch_json(url, token)
            if not isinstance(payload, list):
                raise RuntimeError("Unexpected GitHub API response: expected a JSON array")
            for advisory in payload:
                advisory_id = str(advisory.get("ghsa_id") or advisory.get("cve_id") or "")
                if advisory_id:
                    advisories_by_id[advisory_id] = advisory
            requests.append(
                {
                    "type": advisory_type,
                    "page": page,
                    "records": len(payload),
                    "rate_limit_remaining": headers.get("X-RateLimit-Remaining", ""),
                    "request_url": url,
                }
            )
            url = parse_next_link(headers.get("Link"))
    advisories = sorted(
        advisories_by_id.values(),
        key=lambda item: str(item.get("ghsa_id") or item.get("cve_id") or ""),
    )
    return advisories, requests


def json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def commit_urls(references: list[str]) -> list[str]:
    return sorted({url for url in references if COMMIT_URL_RE.match(url)})


def repository_from_advisory(advisory: dict[str, Any], references: list[str]) -> str:
    source = str(advisory.get("source_code_location") or "").rstrip("/")
    if source:
        return source
    for url in references:
        match = REPOSITORY_URL_RE.match(url)
        if not match:
            continue
        repo = match.group(2)
        if repo in {"advisories", "security"}:
            continue
        return f"https://github.com/{match.group(1)}/{repo}"
    return ""


def normalize_advisories(
    advisories: list[dict[str, Any]], cwe_map: dict[str, dict[str, str]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for advisory in advisories:
        advisory_cwes = sorted(
            {
                str(item.get("cwe_id") or "").upper()
                for item in advisory.get("cwes") or []
                if item.get("cwe_id")
            }
        )
        selected_cwes = [cwe_id for cwe_id in advisory_cwes if cwe_id in cwe_map]
        if not selected_cwes:
            continue
        selected_labels = sorted({cwe_map[cwe_id]["model_label"] for cwe_id in selected_cwes})
        resolution = "UNIQUE_MODEL_LABEL" if len(selected_labels) == 1 else "MULTI_LABEL_REVIEW"
        references = sorted({str(url) for url in advisory.get("references") or [] if url})
        commits = commit_urls(references)
        repository_url = repository_from_advisory(advisory, references)
        cvss_severities = advisory.get("cvss_severities") or {}
        cvss_v3 = cvss_severities.get("cvss_v3") or {}
        cvss_v4 = cvss_severities.get("cvss_v4") or {}

        pip_vulnerabilities = [
            item
            for item in advisory.get("vulnerabilities") or []
            if str((item.get("package") or {}).get("ecosystem") or "").lower() == "pip"
        ]
        for cwe_id in selected_cwes:
            source = cwe_map[cwe_id]
            for vulnerability in pip_vulnerabilities:
                package = vulnerability.get("package") or {}
                package_name = str(package.get("name") or "").strip()
                ghsa_id = str(advisory.get("ghsa_id") or "")
                cve_id = str(advisory.get("cve_id") or "")
                vulnerable_range = str(
                    vulnerability.get("vulnerable_version_range") or ""
                )
                first_patched = str(vulnerability.get("first_patched_version") or "")
                identity = "|".join(
                    [
                        ghsa_id or cve_id,
                        cwe_id,
                        package_name,
                        vulnerable_range,
                        first_patched,
                    ]
                )
                candidate_id = "ADV-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
                status = (
                    "COMMIT_REFERENCE_FOUND_NEEDS_VALIDATION"
                    if commits
                    else "NEEDS_FIX_COMMIT_RESOLUTION"
                )
                if resolution == "MULTI_LABEL_REVIEW":
                    status = "MULTI_LABEL_REVIEW"
                rows.append(
                    {
                        "candidate_id": candidate_id,
                        "model_label": source["model_label"],
                        "source_cwe_id": cwe_id,
                        "source_cwe_name": source.get("name", ""),
                        "all_advisory_cwes": ";".join(advisory_cwes),
                        "label_resolution": resolution,
                        "ghsa_id": ghsa_id,
                        "cve_id": cve_id,
                        "advisory_type": advisory.get("type") or "",
                        "severity": advisory.get("severity") or "",
                        "summary": advisory.get("summary") or "",
                        "description": advisory.get("description") or "",
                        "package_name": package_name,
                        "ecosystem": package.get("ecosystem") or "",
                        "vulnerable_version_range": vulnerable_range,
                        "first_patched_version": first_patched,
                        "vulnerable_functions": json_value(
                            vulnerability.get("vulnerable_functions") or []
                        ),
                        "repository_url": repository_url,
                        "repository_advisory_url": advisory.get(
                            "repository_advisory_url"
                        )
                        or "",
                        "advisory_url": advisory.get("html_url") or "",
                        "references": json_value(references),
                        "commit_urls": json_value(commits),
                        "commit_reference_count": len(commits),
                        "published_at": advisory.get("published_at") or "",
                        "updated_at": advisory.get("updated_at") or "",
                        "withdrawn_at": advisory.get("withdrawn_at") or "",
                        "cvss_v3_score": cvss_v3.get("score") or "",
                        "cvss_v3_vector": cvss_v3.get("vector_string") or "",
                        "cvss_v4_score": cvss_v4.get("score") or "",
                        "cvss_v4_vector": cvss_v4.get("vector_string") or "",
                        "discovery_source": "GITHUB_GLOBAL_SECURITY_ADVISORY",
                        "candidate_status": status,
                        "next_gate": "RESOLVE_FIX_COMMIT_THEN_APPLY_TC01_TC08",
                    }
                )
    rows.sort(
        key=lambda row: (
            row["model_label"],
            int(row["source_cwe_id"].split("-", 1)[1]),
            row["ghsa_id"],
            row["package_name"],
        )
    )
    return rows


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
            f"New content was saved to {fallback}. Close the CSV and rerun."
        ) from exc


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    write_bytes_if_changed(path, buffer.getvalue().encode("utf-8-sig"))


def write_json(path: Path, value: Any) -> None:
    content = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    write_bytes_if_changed(path, content)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    content = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    write_bytes_if_changed(path, content.encode("utf-8"))


def make_coverage(
    allowlist_rows: list[dict[str, str]], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in candidates:
        by_cwe[row["source_cwe_id"]].append(row)
    coverage: list[dict[str, Any]] = []
    for item in allowlist_rows:
        cwe_id = item["cwe_id"].strip().upper()
        rows = by_cwe.get(cwe_id, [])
        advisories = {row["ghsa_id"] or row["cve_id"] for row in rows}
        packages = {row["package_name"] for row in rows if row["package_name"]}
        commit_advisories = {
            row["ghsa_id"] or row["cve_id"]
            for row in rows
            if int(row["commit_reference_count"] or 0) > 0
        }
        coverage.append(
            {
                "model_label": item["model_label"],
                "cwe_id": cwe_id,
                "cwe_name": item.get("name", ""),
                "github_pip_advisories": len(advisories),
                "pypi_packages": len(packages),
                "advisories_with_commit_reference": len(commit_advisories),
                "coverage_status": (
                    "PYTHON_ADVISORY_CANDIDATES_FOUND"
                    if advisories
                    else "NO_GITHUB_PIP_ADVISORY_FOUND"
                ),
                "next_action": (
                    "RESOLVE_FIX_COMMITS_AND_APPLY_TC01_TC08"
                    if advisories
                    else "SEARCH_NVD_OSV_AND_PROJECT_ADVISORIES"
                ),
            }
        )
    coverage.sort(
        key=lambda row: (row["model_label"], int(row["cwe_id"].split("-", 1)[1]))
    )
    return coverage


def make_cve_ghsa_by_cwe(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse version-range rows into one review row per CWE and advisory."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in candidates:
        advisory_id = str(row["ghsa_id"] or row["cve_id"])
        grouped[(str(row["source_cwe_id"]), advisory_id)].append(row)

    output: list[dict[str, Any]] = []
    for (cwe_id, _advisory_id), rows in grouped.items():
        first = rows[0]
        package_names = sorted({str(row["package_name"]) for row in rows if row["package_name"]})
        affected = sorted(
            {
                (
                    str(row["package_name"]),
                    str(row["vulnerable_version_range"]),
                    str(row["first_patched_version"]),
                )
                for row in rows
            }
        )
        affected_payload = [
            {
                "package": package,
                "vulnerable_range": vulnerable_range,
                "first_patched_version": first_patched,
            }
            for package, vulnerable_range, first_patched in affected
        ]
        statuses = {str(row["candidate_status"]) for row in rows}
        if "MULTI_LABEL_REVIEW" in statuses:
            status = "MULTI_LABEL_REVIEW"
        elif "COMMIT_REFERENCE_FOUND_NEEDS_VALIDATION" in statuses:
            status = "COMMIT_REFERENCE_FOUND_NEEDS_VALIDATION"
        else:
            status = "NEEDS_FIX_COMMIT_RESOLUTION"
        output.append(
            {
                "model_label": first["model_label"],
                "cwe_id": cwe_id,
                "cwe_name": first["source_cwe_name"],
                "ghsa_id": first["ghsa_id"],
                "cve_id": first["cve_id"],
                "summary": first["summary"],
                "severity": first["severity"],
                "package_names": ";".join(package_names),
                "affected_package_ranges": json_value(affected_payload),
                "repository_url": first["repository_url"],
                "advisory_url": first["advisory_url"],
                "commit_urls": first["commit_urls"],
                "commit_reference_count": first["commit_reference_count"],
                "label_resolution": first["label_resolution"],
                "candidate_status": status,
                "published_at": first["published_at"],
                "updated_at": first["updated_at"],
            }
        )
    output.sort(
        key=lambda row: (
            row["model_label"],
            int(row["cwe_id"].split("-", 1)[1]),
            row["ghsa_id"] or row["cve_id"],
        )
    )
    return output


def make_missing_cwe_plan(
    allowlist_rows: list[dict[str, str]], coverage: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Plan parent/root discovery without falsely assigning a child CWE."""
    advisory_counts = {
        str(row["cwe_id"]): int(row["github_pip_advisories"] or 0)
        for row in coverage
    }
    output: list[dict[str, Any]] = []
    for item in allowlist_rows:
        cwe_id = str(item["cwe_id"]).strip().upper()
        if advisory_counts.get(cwe_id, 0) > 0:
            continue
        path = str(item.get("path_from_root") or cwe_id)
        path_ids = [part.strip() for part in path.split(">") if part.strip()]
        selected_parent = ""
        for ancestor in reversed(path_ids[:-1]):
            if advisory_counts.get(ancestor, 0) > 0:
                selected_parent = ancestor
                break
        if selected_parent:
            fallback = selected_parent
            fallback_type = "NEAREST_SELECTED_ANCESTOR"
            resolution_status = "PARENT_CANDIDATES_AVAILABLE"
        else:
            fallback = str(item.get("root_cwe") or (path_ids[0] if path_ids else ""))
            fallback_type = "FAMILY_ROOT_DISCOVERY"
            resolution_status = "SEARCH_ROOT_IN_ADDITIONAL_SOURCES"
        output.append(
            {
                "model_label": item["model_label"],
                "missing_cwe_id": cwe_id,
                "missing_cwe_name": item.get("name", ""),
                "path_from_root": path,
                "fallback_discovery_cwe": fallback,
                "fallback_type": fallback_type,
                "fallback_github_pip_advisories": advisory_counts.get(fallback, 0),
                "resolution_status": resolution_status,
                "resolution_rule": (
                    "Search the fallback CWE, inspect Python code and the fix, and remap to "
                    f"{cwe_id} only when the exact child mechanism is evidenced. Otherwise "
                    "retain the advisory's supported CWE and the six-class model label."
                ),
            }
        )
    output.sort(
        key=lambda row: (
            row["model_label"],
            int(row["missing_cwe_id"].split("-", 1)[1]),
        )
    )
    return output


def main() -> int:
    args = parse_args()
    allowlist_rows, cwe_map = read_cwe_allowlist(args.cwe_file)
    raw_path = args.output_dir / "raw" / "github_pip_advisories.json"
    request_log: list[dict[str, Any]] = []
    token = os.environ.get(args.token_env, "").strip()

    if raw_path.exists() and not args.refresh:
        advisories = json.loads(raw_path.read_text(encoding="utf-8"))
        source_mode = "CACHE"
    else:
        advisories, request_log = collect_github_advisories(
            sorted(cwe_map, key=lambda value: int(value.split("-", 1)[1])),
            token,
            args.include_unreviewed,
        )
        write_json(raw_path, advisories)
        source_mode = "LIVE_API"

    candidates = normalize_advisories(advisories, cwe_map)
    coverage = make_coverage(allowlist_rows, candidates)
    cve_ghsa_by_cwe = make_cve_ghsa_by_cwe(candidates)
    missing_cwe_plan = make_missing_cwe_plan(allowlist_rows, coverage)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "advisory_candidates.csv", candidates, FIELDS)
    write_jsonl(args.output_dir / "advisory_candidates.jsonl", candidates)
    write_csv(
        args.output_dir / "cve_ghsa_by_cwe.csv",
        cve_ghsa_by_cwe,
        CVE_GHSA_BY_CWE_FIELDS,
    )
    write_csv(
        args.output_dir / "missing_cwe_discovery_plan.csv",
        missing_cwe_plan,
        MISSING_CWE_PLAN_FIELDS,
    )
    coverage_fields = list(coverage[0].keys())
    write_csv(args.output_dir / "cwe_python_coverage.csv", coverage, coverage_fields)
    write_csv(
        args.output_dir / "needs_fix_commit_resolution.csv",
        [
            row
            for row in candidates
            if row["candidate_status"] != "COMMIT_REFERENCE_FOUND_NEEDS_VALIDATION"
        ],
        FIELDS,
    )

    candidate_statuses = Counter(row["candidate_status"] for row in candidates)
    coverage_statuses = Counter(row["coverage_status"] for row in coverage)
    unique_advisories = {
        row["ghsa_id"] or row["cve_id"] for row in candidates if row["ghsa_id"] or row["cve_id"]
    }
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_mode": source_mode,
        "source_api": API_URL,
        "github_api_version": API_VERSION,
        "github_authenticated": bool(token),
        "include_unreviewed": args.include_unreviewed,
        "cwe_allowlist_path": str(args.cwe_file.resolve()),
        "selected_cwes": len(cwe_map),
        "raw_advisories": len(advisories),
        "matched_unique_advisories": len(unique_advisories),
        "cwe_advisory_pairs": len(cve_ghsa_by_cwe),
        "normalized_candidate_rows": len(candidates),
        "candidate_statuses": dict(sorted(candidate_statuses.items())),
        "coverage_statuses": dict(sorted(coverage_statuses.items())),
        "missing_cwe_discovery_plan_rows": len(missing_cwe_plan),
        "requests": request_log,
        "warning": (
            "These are discovery candidates, not accepted training samples. "
            "Commit references can include non-fix commits and must be validated before TC01-TC08."
        ),
    }
    write_json(args.output_dir / "collection_summary.json", summary)

    print(f"Selected CWE allowlist: {len(cwe_map)}")
    print(f"GitHub PyPI advisories: {len(unique_advisories)}")
    print(f"CWE-advisory pairs: {len(cve_ghsa_by_cwe)}")
    print(f"Normalized advisory-CWE-package rows: {len(candidates)}")
    print(
        "CWEs with Python advisory candidates: "
        f"{coverage_statuses.get('PYTHON_ADVISORY_CANDIDATES_FOUND', 0)}"
    )
    print(
        "CWEs without GitHub PyPI advisory candidates: "
        f"{coverage_statuses.get('NO_GITHUB_PIP_ADVISORY_FOUND', 0)}"
    )
    for status, count in sorted(candidate_statuses.items()):
        print(f"{status}: {count}")
    print(f"Output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, RuntimeError, PermissionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
