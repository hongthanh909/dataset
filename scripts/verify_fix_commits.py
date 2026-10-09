#!/usr/bin/env python3
"""Phase 4A: verify commit references from all_python_advisory.csv.

Public GitHub ``.patch`` representations are cached and inspected to establish
that a commit exists and changes Python code.  This is technical verification,
not a claim that every Python-changing commit is the vulnerability fix.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
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


USER_AGENT = "PyVul-Fix-Commit-Verifier/1.0 (+research dataset builder)"
COMMIT_RE = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})(?:[/?#].*)?$"
)
DIFF_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$", re.MULTILINE)
FROM_RE = re.compile(r"^From ([0-9a-fA-F]{40}) ", re.MULTILINE)
SUBJECT_RE = re.compile(r"^Subject:\s*(.+)$", re.MULTILINE)

SECURITY_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "PATH_TRAVERSAL": [
        ("path_traversal", r"path[ -]?traversal|directory[ -]?traversal"),
        ("path_resolution", r"realpath|commonpath|is_relative_to|\.resolve\("),
        ("unsafe_path", r"\.\./|\.\.\\\\"),
    ],
    "XSS": [
        ("xss", r"cross[ -]?site scripting|\bxss\b"),
        ("html_escape", r"escape|sanitize|markupsafe|htmlsafe|html encoding"),
    ],
    "OS_COMMAND_INJECTION": [
        ("command_injection", r"command[ -]?injection|shell[ -]?injection"),
        ("process_sink", r"subprocess|os\.system|shell\s*=\s*true|shlex"),
    ],
    "SQL_INJECTION": [
        ("sql_injection", r"sql[ -]?injection"),
        ("sql_parameterization", r"parameteri[sz]ed|execute\(|executemany\(|raw sql"),
    ],
    "INSECURE_AUTHENTICATION": [
        ("authentication", r"authenticat|login|credential|session|jwt|token"),
        ("certificate", r"certificate|openssl|tls|ssl|hostname verif"),
    ],
    "HARDCODED_CREDENTIALS": [
        ("hardcoded", r"hard[ -]?coded|default password|fixed key"),
        ("secret", r"password|credential|secret|api[_ -]?key|private[_ -]?key"),
    ],
}
GENERIC_FIX_RE = re.compile(
    r"\b(?:fix|fixed|security|vulnerab|cve-\d|ghsa-|sanitize|validate|prevent|harden)\b",
    re.IGNORECASE,
)


QUEUE_FIELDS = [
    "commit_key",
    "commit_url",
    "github_repository",
    "requested_sha",
    "related_record_count",
    "record_ids",
    "advisory_ids",
    "cohorts",
    "model_labels",
    "target_cwe_ids",
    "expected_repositories",
    "repository_match",
]

MAP_FIELDS = [
    "record_id",
    "commit_key",
    "commit_url",
    "cohort",
    "model_label",
    "target_cwe_id",
    "ghsa_id",
    "cve_id",
    "osv_id",
]

VERIFY_FIELDS = QUEUE_FIELDS + [
    "fetch_status",
    "http_status",
    "actual_commit_sha",
    "commit_subject",
    "changed_file_count",
    "changed_files",
    "python_file_count",
    "python_files",
    "non_python_files",
    "semantic_signal_hits",
    "generic_fix_signal",
    "evidence_score",
    "technical_status",
    "fix_validation_status",
    "parent_commit",
    "parent_resolution_status",
    "patch_cache_path",
    "error",
]

NO_COMMIT_FIELDS = [
    "advisory_id",
    "ghsa_id",
    "cve_id",
    "osv_id",
    "related_record_count",
    "record_ids",
    "cohorts",
    "model_labels",
    "target_cwe_ids",
    "repository_urls",
    "advisory_urls",
    "resolution_status",
    "next_action",
]


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=project_root
        / "data"
        / "python-advisories"
        / "all_python_advisory.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_root / "data" / "python-advisories" / "fix-commits",
    )
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--limit", type=int, default=0, help="Verify only the first N commits.")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--max-patch-mb", type=int, default=12)
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"Input is empty: {path}")
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


def normalized_repo(url: str) -> str:
    match = re.match(r"^https://github\.com/([^/]+)/([^/#?]+)", url or "")
    if not match:
        return ""
    repo = match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"{match.group(1)}/{repo}".lower()


def commit_key(repository: str, sha: str) -> str:
    return f"{repository.lower()}@{sha.lower()}"


def build_queues(
    rows: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    commits: dict[str, dict[str, Any]] = {}
    record_map: list[dict[str, Any]] = []
    no_commit_groups: dict[str, list[dict[str, str]]] = defaultdict(list)

    for row in rows:
        urls = parse_json_list(row.get("commit_urls", ""))
        advisory_id = row.get("ghsa_id") or row.get("cve_id") or row.get("osv_id") or ""
        valid_urls: list[tuple[str, re.Match[str]]] = []
        for url in urls:
            match = COMMIT_RE.match(url)
            if match:
                valid_urls.append((url.split("?", 1)[0].split("#", 1)[0], match))
        if not valid_urls:
            no_commit_groups[advisory_id].append(row)
            continue

        for url, match in valid_urls:
            repository = f"{match.group(1)}/{match.group(2)}"
            sha = match.group(3)
            key = commit_key(repository, sha)
            item = commits.setdefault(
                key,
                {
                    "commit_key": key,
                    "commit_url": url,
                    "github_repository": repository,
                    "requested_sha": sha,
                    "record_ids": set(),
                    "advisory_ids": set(),
                    "cohorts": set(),
                    "model_labels": set(),
                    "target_cwe_ids": set(),
                    "expected_repositories": set(),
                },
            )
            item["record_ids"].add(row["record_id"])
            item["advisory_ids"].add(advisory_id)
            item["cohorts"].add(row["cohort"])
            item["model_labels"].add(row["model_label"])
            item["target_cwe_ids"].add(row["target_cwe_id"])
            expected = normalized_repo(row.get("repository_url", ""))
            if expected:
                item["expected_repositories"].add(expected)
            record_map.append(
                {
                    "record_id": row["record_id"],
                    "commit_key": key,
                    "commit_url": url,
                    "cohort": row["cohort"],
                    "model_label": row["model_label"],
                    "target_cwe_id": row["target_cwe_id"],
                    "ghsa_id": row.get("ghsa_id", ""),
                    "cve_id": row.get("cve_id", ""),
                    "osv_id": row.get("osv_id", ""),
                }
            )

    queue: list[dict[str, Any]] = []
    for item in commits.values():
        repo_lower = str(item["github_repository"]).lower()
        expected = set(item["expected_repositories"])
        if not expected:
            repository_match = "NO_EXPECTED_REPOSITORY"
        elif repo_lower in expected:
            repository_match = "MATCH"
        else:
            repository_match = "MISMATCH_REVIEW"
        queue.append(
            {
                "commit_key": item["commit_key"],
                "commit_url": item["commit_url"],
                "github_repository": item["github_repository"],
                "requested_sha": item["requested_sha"],
                "related_record_count": len(item["record_ids"]),
                "record_ids": json_text(sorted(item["record_ids"])),
                "advisory_ids": ";".join(sorted(item["advisory_ids"])),
                "cohorts": ";".join(sorted(item["cohorts"])),
                "model_labels": ";".join(sorted(item["model_labels"])),
                "target_cwe_ids": ";".join(
                    sorted(item["target_cwe_ids"], key=lambda value: int(value.split("-")[1]))
                ),
                "expected_repositories": ";".join(sorted(expected)),
                "repository_match": repository_match,
            }
        )
    queue.sort(key=lambda row: (row["github_repository"].lower(), row["requested_sha"]))

    no_commit: list[dict[str, Any]] = []
    for advisory_id, items in no_commit_groups.items():
        no_commit.append(
            {
                "advisory_id": advisory_id,
                "ghsa_id": next((item["ghsa_id"] for item in items if item.get("ghsa_id")), ""),
                "cve_id": next((item["cve_id"] for item in items if item.get("cve_id")), ""),
                "osv_id": next((item["osv_id"] for item in items if item.get("osv_id")), ""),
                "related_record_count": len(items),
                "record_ids": json_text(sorted({item["record_id"] for item in items})),
                "cohorts": ";".join(sorted({item["cohort"] for item in items})),
                "model_labels": ";".join(sorted({item["model_label"] for item in items})),
                "target_cwe_ids": ";".join(
                    sorted(
                        {item["target_cwe_id"] for item in items},
                        key=lambda value: int(value.split("-")[1]),
                    )
                ),
                "repository_urls": ";".join(
                    sorted({item["repository_url"] for item in items if item.get("repository_url")})
                ),
                "advisory_urls": ";".join(
                    sorted({item["advisory_url"] for item in items if item.get("advisory_url")})
                ),
                "resolution_status": "MISSING_COMMIT_REFERENCE",
                "next_action": "SEARCH_ADVISORY_PR_RELEASE_OSV_GIT_RANGE",
            }
        )
    no_commit.sort(key=lambda row: row["advisory_id"])
    return queue, record_map, no_commit


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


def cache_path(cache_dir: Path, commit_url: str) -> Path:
    digest = hashlib.sha256(commit_url.encode("utf-8")).hexdigest()
    return cache_dir / digest[:2] / f"{digest}.patch"


def fetch_patch(url: str, timeout: int, max_bytes: int) -> tuple[str, str, str]:
    patch_url = url.rstrip("/") + ".patch"
    request = urllib.request.Request(
        patch_url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain"},
    )
    last_error = ""
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content = response.read(max_bytes + 1)
                if len(content) > max_bytes:
                    return "PATCH_TOO_LARGE", "", f"Patch exceeds {max_bytes} bytes"
                return "FETCHED", content.decode("utf-8", errors="replace"), str(response.status)
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.code in {403, 429, 500, 502, 503, 504} and attempt < 3:
                time.sleep(2**attempt)
                continue
            return "FETCH_FAILED", "", last_error
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
            if attempt < 3:
                time.sleep(2**attempt)
                continue
            return "FETCH_FAILED", "", last_error
    return "FETCH_FAILED", "", last_error


def parse_changed_files(patch: str) -> list[str]:
    files: set[str] = set()
    for _old, new in DIFF_RE.findall(patch):
        value = new.strip().strip('"')
        if value != "/dev/null":
            files.add(value)
    if not files:
        for line in patch.splitlines():
            if line.startswith("+++ b/"):
                files.add(line[6:].strip().strip('"'))
    return sorted(files)


def semantic_hits(labels: list[str], text: str) -> list[str]:
    hits: set[str] = set()
    for label in labels:
        for name, pattern in SECURITY_PATTERNS.get(label, []):
            if re.search(pattern, text, re.IGNORECASE):
                hits.add(f"{label}:{name}")
    return sorted(hits)


def inspect_one(
    row: dict[str, Any],
    cache_dir: Path,
    refresh: bool,
    timeout: int,
    max_bytes: int,
) -> dict[str, Any]:
    path = cache_path(cache_dir, row["commit_url"])
    if path.exists() and not refresh:
        patch = path.read_text(encoding="utf-8", errors="replace")
        fetch_status, http_status, error = "CACHED", "200", ""
    else:
        fetch_status, patch, info = fetch_patch(row["commit_url"], timeout, max_bytes)
        if fetch_status == "FETCHED":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(patch, encoding="utf-8")
            http_status, error = info, ""
        else:
            http_status, error = "", info

    result = dict(row)
    result.update(
        {
            "fetch_status": fetch_status,
            "http_status": http_status,
            "actual_commit_sha": "",
            "commit_subject": "",
            "changed_file_count": 0,
            "changed_files": "[]",
            "python_file_count": 0,
            "python_files": "[]",
            "non_python_files": "[]",
            "semantic_signal_hits": "[]",
            "generic_fix_signal": "NO",
            "evidence_score": 0,
            "technical_status": "PATCH_FETCH_FAILED",
            "fix_validation_status": "UNVERIFIED",
            "parent_commit": "",
            "parent_resolution_status": "NOT_ATTEMPTED",
            "patch_cache_path": str(path.resolve()) if path.exists() else "",
            "error": error,
        }
    )
    if fetch_status not in {"FETCHED", "CACHED"}:
        result["technical_status"] = fetch_status
        result["fix_validation_status"] = "COMMIT_UNAVAILABLE_OR_TOO_LARGE"
        return result

    actual = FROM_RE.search(patch)
    subject = SUBJECT_RE.search(patch)
    files = parse_changed_files(patch)
    python_files = [name for name in files if name.lower().endswith((".py", ".pyi"))]
    non_python = [name for name in files if name not in python_files]
    labels = [value for value in str(row["model_labels"]).split(";") if value]
    text_for_signals = ((subject.group(1) if subject else "") + "\n" + patch).lower()
    hits = semantic_hits(labels, text_for_signals)
    generic = bool(GENERIC_FIX_RE.search(text_for_signals))

    score = 0
    if python_files:
        score += 2
    if row["repository_match"] == "MATCH":
        score += 1
    if hits:
        score += 1
    if generic:
        score += 1

    if not files:
        technical = "PATCH_UNPARSEABLE_OR_NO_FILES"
        validation = "MANUAL_REVIEW_PATCH_FORMAT"
    elif not python_files:
        technical = "PATCH_FETCHED_NO_PYTHON_CHANGE"
        validation = "NON_PYTHON_COMMIT"
    elif score >= 4:
        technical = "PATCH_FETCHED_PYTHON_CHANGED"
        validation = "HIGH_PRIORITY_PYTHON_FIX_CANDIDATE"
    else:
        technical = "PATCH_FETCHED_PYTHON_CHANGED"
        validation = "PYTHON_COMMIT_NEEDS_SEMANTIC_REVIEW"

    result.update(
        {
            "actual_commit_sha": actual.group(1) if actual else "",
            "commit_subject": subject.group(1).strip() if subject else "",
            "changed_file_count": len(files),
            "changed_files": json_text(files),
            "python_file_count": len(python_files),
            "python_files": json_text(python_files),
            "non_python_files": json_text(non_python),
            "semantic_signal_hits": json_text(hits),
            "generic_fix_signal": "YES" if generic else "NO",
            "evidence_score": score,
            "technical_status": technical,
            "fix_validation_status": validation,
            "parent_resolution_status": "NEEDS_GITHUB_API_OR_GIT_FETCH",
        }
    )
    return result


def main() -> int:
    args = parse_args()
    if args.workers < 1 or args.workers > 16:
        raise ValueError("--workers must be between 1 and 16")
    rows = read_csv(args.input)
    queue, record_map, no_commit = build_queues(rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "commit_reference_queue.csv", queue, QUEUE_FIELDS)
    write_csv(args.output_dir / "record_commit_map.csv", record_map, MAP_FIELDS)
    write_csv(args.output_dir / "no_commit_reference_queue.csv", no_commit, NO_COMMIT_FIELDS)

    selected = queue[: args.limit] if args.limit else queue
    cache_dir = args.output_dir / "cache" / "patches"
    max_bytes = args.max_patch_mb * 1024 * 1024
    verified: list[dict[str, Any]] = []
    lock = threading.Lock()
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                inspect_one,
                row,
                cache_dir,
                args.refresh,
                args.timeout,
                max_bytes,
            ): row
            for row in selected
        }
        for future in concurrent.futures.as_completed(futures):
            verified.append(future.result())
            with lock:
                completed += 1
                if completed % 25 == 0 or completed == len(selected):
                    print(f"Verified commit patches: {completed}/{len(selected)}", flush=True)

    verified.sort(key=lambda row: (row["github_repository"].lower(), row["requested_sha"]))
    write_csv(args.output_dir / "commit_patch_verification.csv", verified, VERIFY_FIELDS)
    write_csv(
        args.output_dir / "python_commit_candidates.csv",
        [row for row in verified if int(row["python_file_count"] or 0) > 0],
        VERIFY_FIELDS,
    )
    write_csv(
        args.output_dir / "high_priority_python_fix_candidates.csv",
        [
            row
            for row in verified
            if row["fix_validation_status"] == "HIGH_PRIORITY_PYTHON_FIX_CANDIDATE"
        ],
        VERIFY_FIELDS,
    )
    write_csv(
        args.output_dir / "non_python_or_unavailable_commits.csv",
        [row for row in verified if int(row["python_file_count"] or 0) == 0],
        VERIFY_FIELDS,
    )

    technical_counts = Counter(row["technical_status"] for row in verified)
    validation_counts = Counter(row["fix_validation_status"] for row in verified)
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_rows": len(rows),
        "unique_commit_references": len(queue),
        "verified_in_this_run": len(verified),
        "unique_advisories_without_commit_reference": len(no_commit),
        "record_commit_map_rows": len(record_map),
        "technical_status_counts": dict(sorted(technical_counts.items())),
        "fix_validation_status_counts": dict(sorted(validation_counts.items())),
        "python_changing_commits": sum(int(row["python_file_count"] or 0) > 0 for row in verified),
        "high_priority_python_fix_candidates": sum(
            row["fix_validation_status"] == "HIGH_PRIORITY_PYTHON_FIX_CANDIDATE"
            for row in verified
        ),
        "parent_commits_resolved": 0,
        "warning": (
            "A fetched patch that changes Python is a technical fix candidate, not yet a "
            "confirmed vulnerability fix. Semantic advisory/patch review and parent commit "
            "resolution are still required before TC01-TC08."
        ),
    }
    write_bytes_if_changed(
        args.output_dir / "fix_commit_verification_summary.json",
        (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )

    print(f"Unique commit references: {len(queue)}")
    print(f"Verified this run: {len(verified)}")
    print(f"Python-changing commits: {summary['python_changing_commits']}")
    print(
        "High-priority Python fix candidates: "
        f"{summary['high_priority_python_fix_candidates']}"
    )
    print(f"Advisories without commit reference: {len(no_commit)}")
    for status, count in sorted(validation_counts.items()):
        print(f"{status}: {count}")
    print(f"Output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, PermissionError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
