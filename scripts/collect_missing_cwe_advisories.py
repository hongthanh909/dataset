#!/usr/bin/env python3
"""Phase 3B: find Python advisory evidence for the 25 missing CWE variants.

The script keeps exact-CWE evidence separate from parent/root discovery.  A
parent/root advisory is never silently relabelled as its child CWE.
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
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


OSV_PYPI_DUMP = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "PyVul-Missing-CWE-Advisory-Collector/1.0 (+research dataset builder)"
COMMIT_URL_RE = re.compile(
    r"^https://github\.com/[^/]+/[^/]+/commit/[0-9a-fA-F]{7,40}(?:[/?#].*)?$"
)
GITHUB_REPO_RE = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+)")
PYTHON_SIGNAL_RE = re.compile(
    r"\b(?:python|pypi|pip package|django|flask|fastapi|jupyter|ansible)\b|\.py\b",
    re.IGNORECASE,
)


CANDIDATE_FIELDS = [
    "candidate_id",
    "model_label",
    "target_cwe_id",
    "target_cwe_name",
    "discovery_cwe_id",
    "advisory_cwe_ids",
    "path_from_root",
    "ghsa_id",
    "cve_id",
    "osv_id",
    "package_names",
    "ecosystem",
    "summary",
    "details",
    "repository_url",
    "advisory_url",
    "references",
    "commit_urls",
    "published_at",
    "updated_at",
    "discovery_source",
    "discovery_method",
    "python_evidence_status",
    "mapping_status",
    "next_gate",
]

NVD_FIELDS = [
    "target_cwe_id",
    "model_label",
    "cve_id",
    "nvd_cwe_ids",
    "description",
    "published_at",
    "updated_at",
    "vuln_status",
    "references",
    "matched_osv_ids",
    "matched_pypi_packages",
    "python_evidence_status",
    "next_action",
]

STATUS_FIELDS = [
    "model_label",
    "target_cwe_id",
    "target_cwe_name",
    "fallback_discovery_cwe",
    "osv_exact_candidates",
    "nvd_exact_results",
    "nvd_exact_pypi_confirmed",
    "parent_root_candidates",
    "phase3b_status",
    "next_action",
]


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan",
        type=Path,
        default=project_root
        / "data"
        / "python-advisories"
        / "missing_cwe_discovery_plan.csv",
    )
    parser.add_argument(
        "--direct-candidates",
        type=Path,
        default=project_root
        / "data"
        / "python-advisories"
        / "advisory_candidates.csv",
    )
    parser.add_argument(
        "--osv-zip",
        type=Path,
        default=project_root / "data" / "osv-pypi" / "cache" / "all.zip",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_root / "data" / "python-advisories" / "phase-3b",
    )
    parser.add_argument("--refresh-osv", action="store_true")
    parser.add_argument(
        "--skip-nvd",
        action="store_true",
        help="Use existing NVD cache only; do not make missing NVD requests.",
    )
    parser.add_argument("--nvd-key-env", default="NVD_API_KEY")
    parser.add_argument(
        "--nvd-delay",
        type=float,
        default=None,
        help="Seconds between uncached NVD requests (default 6.2 without key, 0.7 with key).",
    )
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


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


def write_json(path: Path, value: Any) -> None:
    write_bytes_if_changed(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )


def download(url: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        content = response.read()
    if not zipfile.is_zipfile(io.BytesIO(content)):
        raise RuntimeError(f"Downloaded OSV payload is not a ZIP file: {url}")
    write_bytes_if_changed(path, content)


def load_osv(
    path: Path,
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, list[dict[str, Any]]],
]:
    records: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    by_alias: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            record = json.loads(archive.read(name))
            records.append(record)
            record_id = str(record.get("id") or "")
            if record_id:
                by_id[record_id] = record
            for identifier in [record_id, *(record.get("aliases") or [])]:
                if identifier:
                    by_alias[str(identifier)].append(record)
    return records, by_id, by_alias


def osv_cwes(record: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(value).upper()
            for value in ((record.get("database_specific") or {}).get("cwe_ids") or [])
            if re.fullmatch(r"CWE-\d+", str(value).upper())
        }
    )


def osv_packages(record: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str((affected.get("package") or {}).get("name") or "")
            for affected in record.get("affected") or []
            if str((affected.get("package") or {}).get("ecosystem") or "").lower()
            == "pypi"
            and (affected.get("package") or {}).get("name")
        }
    )


def osv_references(record: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(item.get("url") or "")
            for item in record.get("references") or []
            if item.get("url")
        }
    )


def commit_urls(references: list[str]) -> list[str]:
    return sorted({url for url in references if COMMIT_URL_RE.match(url)})


def repository_url(references: list[str]) -> str:
    for url in references:
        match = GITHUB_REPO_RE.match(url)
        if not match:
            continue
        repo = match.group(2)
        if repo in {"advisories", "security"}:
            continue
        return f"https://github.com/{match.group(1)}/{repo}"
    return ""


def aliases(record: dict[str, Any], prefix: str) -> list[str]:
    values = [str(record.get("id") or ""), *(record.get("aliases") or [])]
    return sorted({value for value in values if value.startswith(prefix)})


def candidate_id(*parts: str) -> str:
    return "P3B-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def candidate_from_osv(
    plan: dict[str, str],
    record: dict[str, Any],
    discovery_cwe: str,
    method: str,
    mapping_status: str,
) -> dict[str, Any]:
    refs = osv_references(record)
    commits = commit_urls(refs)
    ghsa_ids = aliases(record, "GHSA-")
    cve_ids = aliases(record, "CVE-")
    packages = osv_packages(record)
    advisory_id = ghsa_ids[0] if ghsa_ids else (cve_ids[0] if cve_ids else str(record.get("id") or ""))
    return {
        "candidate_id": candidate_id(plan["missing_cwe_id"], advisory_id, method),
        "model_label": plan["model_label"],
        "target_cwe_id": plan["missing_cwe_id"],
        "target_cwe_name": plan["missing_cwe_name"],
        "discovery_cwe_id": discovery_cwe,
        "advisory_cwe_ids": ";".join(osv_cwes(record)),
        "path_from_root": plan["path_from_root"],
        "ghsa_id": ghsa_ids[0] if ghsa_ids else "",
        "cve_id": cve_ids[0] if cve_ids else "",
        "osv_id": record.get("id") or "",
        "package_names": ";".join(packages),
        "ecosystem": "PyPI",
        "summary": record.get("summary") or "",
        "details": record.get("details") or "",
        "repository_url": repository_url(refs),
        "advisory_url": (
            f"https://osv.dev/vulnerability/{record.get('id')}" if record.get("id") else ""
        ),
        "references": json_text(refs),
        "commit_urls": json_text(commits),
        "published_at": record.get("published") or "",
        "updated_at": record.get("modified") or "",
        "discovery_source": "OSV_PYPI_DUMP",
        "discovery_method": method,
        "python_evidence_status": "CONFIRMED_PYPI_RECORD",
        "mapping_status": mapping_status,
        "next_gate": "VERIFY_FIX_COMMIT_AND_CHILD_MECHANISM",
    }


def candidate_from_github(
    plan: dict[str, str],
    row: dict[str, str],
    discovery_method: str,
    mapping_status: str,
) -> dict[str, Any]:
    advisory_id = row.get("ghsa_id") or row.get("cve_id") or row.get("candidate_id") or ""
    advisory_type = str(row.get("advisory_type") or "reviewed").upper()
    source_cwe = str(row.get("source_cwe_id") or plan["fallback_discovery_cwe"])
    return {
        "candidate_id": candidate_id(
            plan["missing_cwe_id"],
            advisory_id,
            row.get("package_name", ""),
            discovery_method,
        ),
        "model_label": plan["model_label"],
        "target_cwe_id": plan["missing_cwe_id"],
        "target_cwe_name": plan["missing_cwe_name"],
        "discovery_cwe_id": source_cwe,
        "advisory_cwe_ids": row.get("all_advisory_cwes", ""),
        "path_from_root": plan["path_from_root"],
        "ghsa_id": row.get("ghsa_id", ""),
        "cve_id": row.get("cve_id", ""),
        "osv_id": "",
        "package_names": row.get("package_name", ""),
        "ecosystem": row.get("ecosystem", "pip"),
        "summary": row.get("summary", ""),
        "details": row.get("description", ""),
        "repository_url": row.get("repository_url", ""),
        "advisory_url": row.get("advisory_url", ""),
        "references": row.get("references", "[]"),
        "commit_urls": row.get("commit_urls", "[]"),
        "published_at": row.get("published_at", ""),
        "updated_at": row.get("updated_at", ""),
        "discovery_source": f"GITHUB_{advisory_type}_ADVISORY",
        "discovery_method": discovery_method,
        "python_evidence_status": "CONFIRMED_GITHUB_PIP_FILTER",
        "mapping_status": mapping_status,
        "next_gate": "VERIFY_FIX_COMMIT_AND_CHILD_MECHANISM",
    }


def fetch_nvd(cwe_id: str, api_key: str) -> dict[str, Any]:
    params = urllib.parse.urlencode({"cweId": cwe_id, "resultsPerPage": 2000})
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(f"{NVD_API}?{params}", headers=headers)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code in {403, 429, 500, 502, 503, 504} and attempt < 3:
                time.sleep(3 * (attempt + 1))
                continue
            raise RuntimeError(f"NVD {cwe_id} HTTP {exc.code}: {body[:500]}") from exc
        except urllib.error.URLError as exc:
            if attempt < 3:
                time.sleep(3 * (attempt + 1))
                continue
            raise RuntimeError(f"NVD {cwe_id} request failed: {exc}") from exc
    raise AssertionError("unreachable")


def nvd_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return str(item.get("value") or "")
    return str(descriptions[0].get("value") or "") if descriptions else ""


def nvd_cwes(cve: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for weakness in cve.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            value = str(item.get("value") or "").upper()
            if re.fullmatch(r"CWE-\d+", value):
                values.add(value)
    return sorted(values)


def nvd_references(cve: dict[str, Any]) -> list[str]:
    return sorted(
        {str(item.get("url") or "") for item in cve.get("references") or [] if item.get("url")}
    )


def make_nvd_rows(
    plan: dict[str, str], payload: dict[str, Any], osv_by_alias: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for wrapper in payload.get("vulnerabilities") or []:
        cve = wrapper.get("cve") or {}
        cve_id = str(cve.get("id") or "")
        refs = nvd_references(cve)
        description = nvd_description(cve)
        matched_osv = osv_by_alias.get(cve_id, [])
        matched_packages = sorted({package for record in matched_osv for package in osv_packages(record)})
        if matched_packages:
            evidence = "CONFIRMED_PYPI_VIA_OSV_ALIAS"
            next_action = "ADD_EXACT_CANDIDATE_AND_VERIFY_FIX"
        elif PYTHON_SIGNAL_RE.search(description + " " + " ".join(refs)):
            evidence = "POSSIBLE_PYTHON_TEXT_SIGNAL"
            next_action = "MANUAL_VERIFY_PYTHON_ECOSYSTEM"
        else:
            evidence = "NOT_CONFIRMED_PYTHON"
            next_action = "DO_NOT_MERGE_WITH_PYTHON_CANDIDATES"
        rows.append(
            {
                "target_cwe_id": plan["missing_cwe_id"],
                "model_label": plan["model_label"],
                "cve_id": cve_id,
                "nvd_cwe_ids": ";".join(nvd_cwes(cve)),
                "description": description,
                "published_at": cve.get("published") or "",
                "updated_at": cve.get("lastModified") or "",
                "vuln_status": cve.get("vulnStatus") or "",
                "references": json_text(refs),
                "matched_osv_ids": ";".join(
                    sorted({str(record.get("id") or "") for record in matched_osv})
                ),
                "matched_pypi_packages": ";".join(matched_packages),
                "python_evidence_status": evidence,
                "next_action": next_action,
            }
        )
    return rows


def exact_candidate_from_nvd_osv(
    plan: dict[str, str], nvd_row: dict[str, Any], osv_record: dict[str, Any]
) -> dict[str, Any]:
    row = candidate_from_osv(
        plan,
        osv_record,
        plan["missing_cwe_id"],
        "NVD_EXACT_CWE_CROSSLINK_OSV_PYPI",
        "DIRECT_EXACT_NEEDS_FIX_VALIDATION",
    )
    row["cve_id"] = nvd_row["cve_id"]
    row["advisory_cwe_ids"] = nvd_row["nvd_cwe_ids"]
    row["discovery_source"] = "NVD_EXACT_PLUS_OSV_PYPI"
    row["python_evidence_status"] = "CONFIRMED_PYPI_VIA_OSV_ALIAS"
    return row


def deduplicate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        result[str(row["candidate_id"])] = row
    return sorted(
        result.values(),
        key=lambda row: (
            row["model_label"],
            int(str(row["target_cwe_id"]).split("-", 1)[1]),
            row["ghsa_id"] or row["cve_id"] or row["osv_id"],
            row["package_names"],
        ),
    )


def main() -> int:
    args = parse_args()
    plans = read_csv(args.plan)
    direct = read_csv(args.direct_candidates)
    if len(plans) != 25:
        raise ValueError(f"Expected 25 missing-CWE plan rows, found {len(plans)}")

    if args.refresh_osv or not args.osv_zip.exists():
        print(f"Downloading OSV PyPI dump: {OSV_PYPI_DUMP}", flush=True)
        download(OSV_PYPI_DUMP, args.osv_zip)
    records, _osv_by_id, osv_by_alias = load_osv(args.osv_zip)
    osv_by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        for cwe_id in osv_cwes(record):
            osv_by_cwe[cwe_id].append(record)

    direct_by_cwe: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in direct:
        direct_by_cwe[row["source_cwe_id"]].append(row)

    exact_candidates: list[dict[str, Any]] = []
    parent_candidates: list[dict[str, Any]] = []
    for plan in plans:
        target = plan["missing_cwe_id"]
        fallback = plan["fallback_discovery_cwe"]
        for row in direct_by_cwe.get(target, []):
            exact_candidates.append(
                candidate_from_github(
                    plan,
                    row,
                    "GITHUB_EXACT_CWE",
                    "DIRECT_EXACT_NEEDS_FIX_VALIDATION",
                )
            )
        for record in osv_by_cwe.get(target, []):
            exact_candidates.append(
                candidate_from_osv(
                    plan,
                    record,
                    target,
                    "OSV_EXACT_CWE",
                    "DIRECT_EXACT_NEEDS_FIX_VALIDATION",
                )
            )
        if direct_by_cwe.get(fallback):
            for row in direct_by_cwe[fallback]:
                parent_candidates.append(
                    candidate_from_github(
                        plan,
                        row,
                        "PARENT_CWE_FALLBACK",
                        "PARENT_CANDIDATE_NEEDS_CODE_REVIEW",
                    )
                )
        else:
            for record in osv_by_cwe.get(fallback, []):
                parent_candidates.append(
                    candidate_from_osv(
                        plan,
                        record,
                        fallback,
                        "ROOT_CWE_FALLBACK",
                        "PARENT_CANDIDATE_NEEDS_CODE_REVIEW",
                    )
                )

    api_key = os.environ.get(args.nvd_key_env, "").strip()
    delay = args.nvd_delay if args.nvd_delay is not None else (0.7 if api_key else 6.2)
    nvd_cache = args.output_dir / "cache" / "nvd"
    nvd_rows: list[dict[str, Any]] = []
    fetched = 0
    for index, plan in enumerate(plans, start=1):
        cwe_id = plan["missing_cwe_id"]
        cache_path = nvd_cache / f"{cwe_id}.json"
        if cache_path.exists():
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
            mode = "cache"
        elif args.skip_nvd:
            print(f"NVD {index}/{len(plans)} {cwe_id}: skipped (no cache)", flush=True)
            continue
        else:
            if fetched:
                time.sleep(delay)
            payload = fetch_nvd(cwe_id, api_key)
            write_json(cache_path, payload)
            fetched += 1
            mode = "live"
        rows = make_nvd_rows(plan, payload, osv_by_alias)
        nvd_rows.extend(rows)
        print(
            f"NVD {index}/{len(plans)} {cwe_id}: {len(rows)} exact CVE ({mode})",
            flush=True,
        )
        for nvd_row in rows:
            if nvd_row["python_evidence_status"] != "CONFIRMED_PYPI_VIA_OSV_ALIAS":
                continue
            for osv_record in osv_by_alias.get(str(nvd_row["cve_id"]), []):
                exact_candidates.append(
                    exact_candidate_from_nvd_osv(plan, nvd_row, osv_record)
                )

    exact_candidates = deduplicate(exact_candidates)
    parent_candidates = deduplicate(parent_candidates)
    all_candidates = deduplicate([*exact_candidates, *parent_candidates])
    nvd_rows.sort(
        key=lambda row: (
            row["model_label"],
            int(str(row["target_cwe_id"]).split("-", 1)[1]),
            row["cve_id"],
        )
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "additional_exact_candidates.csv", exact_candidates, CANDIDATE_FIELDS)
    write_csv(args.output_dir / "parent_root_candidates.csv", parent_candidates, CANDIDATE_FIELDS)
    write_csv(args.output_dir / "phase3b_candidates.csv", all_candidates, CANDIDATE_FIELDS)
    write_csv(args.output_dir / "nvd_exact_results_all.csv", nvd_rows, NVD_FIELDS)

    exact_by_target = Counter(row["target_cwe_id"] for row in exact_candidates)
    parent_by_target = Counter(row["target_cwe_id"] for row in parent_candidates)
    nvd_by_target = Counter(row["target_cwe_id"] for row in nvd_rows)
    nvd_confirmed_by_target = Counter(
        row["target_cwe_id"]
        for row in nvd_rows
        if row["python_evidence_status"] == "CONFIRMED_PYPI_VIA_OSV_ALIAS"
    )
    status_rows: list[dict[str, Any]] = []
    for plan in plans:
        target = plan["missing_cwe_id"]
        if exact_by_target[target]:
            status = "EXACT_PYTHON_CANDIDATE_FOUND"
            next_action = "VERIFY_FIX_COMMIT_THEN_APPLY_TC01_TC08"
        elif parent_by_target[target]:
            status = "PARENT_ROOT_CANDIDATES_FOUND"
            next_action = "VERIFY_FIX_AND_DECIDE_CHILD_OR_PARENT"
        else:
            status = "NO_PYTHON_CANDIDATE_FOUND"
            next_action = "KEEP_NO_EXACT_PYTHON_EVIDENCE"
        status_rows.append(
            {
                "model_label": plan["model_label"],
                "target_cwe_id": target,
                "target_cwe_name": plan["missing_cwe_name"],
                "fallback_discovery_cwe": plan["fallback_discovery_cwe"],
                "osv_exact_candidates": sum(
                    1
                    for row in exact_candidates
                    if row["target_cwe_id"] == target
                    and row["discovery_method"] == "OSV_EXACT_CWE"
                ),
                "nvd_exact_results": nvd_by_target[target],
                "nvd_exact_pypi_confirmed": nvd_confirmed_by_target[target],
                "parent_root_candidates": parent_by_target[target],
                "phase3b_status": status,
                "next_action": next_action,
            }
        )
    write_csv(args.output_dir / "phase3b_cwe_status.csv", status_rows, STATUS_FIELDS)

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "missing_cwes": len(plans),
        "osv_pypi_records_scanned": len(records),
        "nvd_exact_results": len(nvd_rows),
        "nvd_python_confirmed_results": sum(
            row["python_evidence_status"] == "CONFIRMED_PYPI_VIA_OSV_ALIAS"
            for row in nvd_rows
        ),
        "additional_exact_candidates": len(exact_candidates),
        "parent_root_candidates": len(parent_candidates),
        "phase3b_candidate_rows": len(all_candidates),
        "phase3b_status_counts": dict(
            sorted(Counter(row["phase3b_status"] for row in status_rows).items())
        ),
        "nvd_requests_fetched_live": fetched,
        "nvd_authenticated": bool(api_key),
        "warning": (
            "Parent/root candidates are discovery evidence only. Never assign the target "
            "child CWE until Python code and the real fix commit prove the child mechanism."
        ),
    }
    write_json(args.output_dir / "phase3b_summary.json", summary)

    print(f"OSV PyPI records scanned: {len(records)}")
    print(f"NVD exact-CWE results: {len(nvd_rows)}")
    print(f"Additional exact Python candidates: {len(exact_candidates)}")
    print(f"Parent/root discovery candidates: {len(parent_candidates)}")
    print(f"Phase 3B candidate rows: {len(all_candidates)}")
    for status, count in summary["phase3b_status_counts"].items():
        print(f"{status}: {count}")
    print(f"Output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, RuntimeError, PermissionError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
