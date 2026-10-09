#!/usr/bin/env python3
"""Phase 5A: extract Python before/after hunks and pre-screen TC01-TC08.

The vulnerable-side hunk is the training candidate.  The fixed-side hunk is
retained only as evidence; this script never creates a SAFE class.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:\s?(.*))?$"
)
DIFF_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
TOKEN_RE = re.compile(r"[A-Za-z_]\w*|\d+(?:\.\d+)?|[^\s\w]", re.UNICODE)
CODE_LINE_RE = re.compile(r"\S")
DEF_CONTEXT_RE = re.compile(r"\b(?:async\s+def|def|class)\s+[A-Za-z_]\w*")

LABEL_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "PATH_TRAVERSAL": [
        ("path_join", re.compile(r"os\.path|pathlib|Path\s*\(|join\s*\(", re.I)),
        ("path_guard", re.compile(r"resolve\s*\(|realpath|commonpath|is_relative_to", re.I)),
        ("file_sink", re.compile(r"\bopen\s*\(|send_file|FileResponse|read_text|write_text", re.I)),
    ],
    "XSS": [
        ("html_output", re.compile(r"render|response|html|template|markup|set-cookie", re.I)),
        ("xss_guard", re.compile(r"escape|sanitize|markupsafe|bleach|htmlsafe", re.I)),
        ("request_input", re.compile(r"request|query|param|form|cookie|header", re.I)),
    ],
    "OS_COMMAND_INJECTION": [
        ("process_sink", re.compile(r"subprocess|os\.system|os\.popen|shell\s*=\s*True", re.I)),
        ("command_guard", re.compile(r"shlex|shell\s*=\s*False|quote|allowlist", re.I)),
    ],
    "SQL_INJECTION": [
        ("sql_sink", re.compile(r"execute\s*\(|executemany\s*\(|raw\s*\(|cursor", re.I)),
        ("sql_text", re.compile(r"\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b", re.I)),
        ("sql_guard", re.compile(r"parameter|placeholder|bindparam|params", re.I)),
    ],
    "INSECURE_AUTHENTICATION": [
        ("auth_flow", re.compile(r"auth|login|session|jwt|token|password|certificate", re.I)),
        ("auth_guard", re.compile(r"verify|constant_time|compare_digest|check_password|permission", re.I)),
    ],
    "HARDCODED_CREDENTIALS": [
        ("credential", re.compile(r"password|passwd|secret|api[_-]?key|token|private[_-]?key", re.I)),
        ("literal_assignment", re.compile(r"(?:password|secret|key|token)\w*\s*=\s*['\"]", re.I)),
        ("external_secret", re.compile(r"environ|getenv|config|keyring|vault", re.I)),
    ],
}

OUTPUT_FIELDS = [
    "sample_id",
    "model_label",
    "resolved_cwe_ids",
    "candidate_cwe_ids",
    "cwe_resolution_statuses",
    "advisory_ids",
    "record_ids",
    "repository",
    "fix_commit",
    "parent_commit",
    "commit_url",
    "phase4b_status",
    "file_path_before",
    "file_path_after",
    "change_type",
    "hunk_index",
    "old_start",
    "old_count",
    "new_start",
    "new_count",
    "hunk_context",
    "code_before",
    "code_after",
    "changed_lines_before",
    "changed_lines_after",
    "model_code_before",
    "estimated_model_tokens",
    "token_estimation_method",
    "truncated_for_model",
    "semantic_signal_hits",
    "code_before_sha256",
    "code_after_sha256",
    "patch_sha256",
    "duplicate_group_size",
    "tc01_python_vulnerable_code",
    "tc02_cwe_label_consistency",
    "tc03_before_after_evidence",
    "tc04_context_sufficient",
    "tc05_codebert_compatibility",
    "tc06_traceability",
    "tc07_separation_dedup",
    "tc08_access_integrity",
    "license_review_status",
    "failed_criteria",
    "review_reasons",
    "final_decision",
    "decision_reason",
]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    base = root / "data" / "python-advisories" / "fix-commits"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verified-commits",
        type=Path,
        default=base / "phase-4b" / "verified_python_fix_commits.csv",
    )
    parser.add_argument(
        "--phase4a",
        type=Path,
        default=base / "commit_patch_verification.csv",
    )
    parser.add_argument(
        "--record-resolution",
        type=Path,
        default=base / "phase-4b" / "record_fix_resolution.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=root / "data" / "python-advisories" / "before-after",
    )
    parser.add_argument("--max-model-tokens", type=int, default=512)
    parser.add_argument("--context-lines", type=int, default=18)
    parser.add_argument("--limit", type=int, default=0)
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
        return [item.strip() for item in value.split(";") if item.strip()]
    if not isinstance(parsed, list):
        parsed = [parsed]
    return [str(item) for item in parsed if item not in (None, "")]


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def estimate_tokens(code: str) -> int:
    return len(TOKEN_RE.findall(code))


def crop_for_model(lines: list[str], changed_positions: list[int], max_tokens: int, radius: int) -> tuple[str, bool]:
    full = "\n".join(lines).rstrip()
    if estimate_tokens(full) <= max_tokens:
        return full, False
    if not lines:
        return "", False
    anchors = changed_positions or [len(lines) // 2]
    keep: set[int] = set()
    local_radius = max(2, radius)
    while local_radius >= 2:
        keep.clear()
        for anchor in anchors:
            lo = max(0, anchor - local_radius)
            hi = min(len(lines), anchor + local_radius + 1)
            keep.update(range(lo, hi))
        cropped = "\n".join(lines[i] for i in sorted(keep)).rstrip()
        if estimate_tokens(cropped) <= max_tokens:
            return cropped, True
        local_radius //= 2
    anchor = max(0, min(anchors[0], len(lines) - 1))
    selected: list[str] = []
    for i in range(anchor, len(lines)):
        candidate = "\n".join(selected + [lines[i]])
        if estimate_tokens(candidate) > max_tokens:
            break
        selected.append(lines[i])
    return "\n".join(selected).rstrip(), True


def clean_path(value: str) -> str:
    value = value.strip()
    if value == "/dev/null":
        return ""
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    return value.strip('"')


def parse_patch(patch: str) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    old_path = ""
    new_path = ""
    hunk: dict[str, Any] | None = None
    hunk_index = 0

    def finish_hunk() -> None:
        nonlocal hunk
        if hunk is not None:
            hunk["code_before"] = "\n".join(hunk.pop("before_lines")).rstrip()
            hunk["code_after"] = "\n".join(hunk.pop("after_lines")).rstrip()
            hunk["changed_lines_before"] = "\n".join(hunk.pop("removed_lines")).rstrip()
            hunk["changed_lines_after"] = "\n".join(hunk.pop("added_lines")).rstrip()
            hunk["changed_positions_before"] = hunk.pop("removed_positions")
            samples.append(hunk)
        hunk = None

    for raw_line in patch.splitlines():
        diff_match = DIFF_RE.match(raw_line)
        if diff_match:
            finish_hunk()
            old_path, new_path = diff_match.group(1), diff_match.group(2)
            hunk_index = 0
            continue
        if raw_line.startswith("--- "):
            old_path = clean_path(raw_line[4:].split("\t", 1)[0])
            continue
        if raw_line.startswith("+++ "):
            new_path = clean_path(raw_line[4:].split("\t", 1)[0])
            continue
        hunk_match = HUNK_RE.match(raw_line)
        if hunk_match:
            finish_hunk()
            hunk_index += 1
            hunk = {
                "file_path_before": clean_path(old_path),
                "file_path_after": clean_path(new_path),
                "hunk_index": hunk_index,
                "old_start": int(hunk_match.group(1)),
                "old_count": int(hunk_match.group(2) or "1"),
                "new_start": int(hunk_match.group(3)),
                "new_count": int(hunk_match.group(4) or "1"),
                "hunk_context": (hunk_match.group(5) or "").strip(),
                "before_lines": [],
                "after_lines": [],
                "removed_lines": [],
                "added_lines": [],
                "removed_positions": [],
            }
            continue
        if hunk is None or raw_line == r"\ No newline at end of file":
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            hunk["after_lines"].append(raw_line[1:])
            hunk["added_lines"].append(raw_line[1:])
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            hunk["removed_positions"].append(len(hunk["before_lines"]))
            hunk["before_lines"].append(raw_line[1:])
            hunk["removed_lines"].append(raw_line[1:])
        elif raw_line.startswith(" "):
            text = raw_line[1:]
            hunk["before_lines"].append(text)
            hunk["after_lines"].append(text)
    finish_hunk()
    return samples


def is_python_hunk(item: dict[str, Any]) -> bool:
    return item["file_path_before"].lower().endswith(".py") or item[
        "file_path_after"
    ].lower().endswith(".py")


def code_has_content(code: str) -> bool:
    for line in code.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return True
    return False


def is_training_source_path(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").strip("/").lower()
    if not normalized.endswith(".py"):
        return False
    parts = normalized.split("/")
    excluded_parts = {
        "test",
        "tests",
        "testing",
        "doc",
        "docs",
        "example",
        "examples",
        "benchmark",
        "benchmarks",
        "fixture",
        "fixtures",
    }
    name = parts[-1]
    return not (
        any(part in excluded_parts for part in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def semantic_hits(labels: list[str], text: str) -> list[str]:
    hits: list[str] = []
    for label in labels:
        for name, pattern in LABEL_PATTERNS.get(label, []):
            if pattern.search(text):
                hits.append(f"{label}:{name}")
    return sorted(set(hits))


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in OUTPUT_FIELDS})


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def unique_join(values: Iterable[str]) -> str:
    return ";".join(sorted({value for value in values if value}))


def main() -> int:
    args = parse_args()
    verified = read_csv(args.verified_commits)
    if args.limit:
        verified = verified[: args.limit]
    phase4a = {row["commit_key"]: row for row in read_csv(args.phase4a)}
    record_rows = read_csv(args.record_resolution)
    records_by_commit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in record_rows:
        records_by_commit[row["commit_key"]].append(row)

    output_rows: list[dict[str, Any]] = []
    skipped_commits: list[dict[str, str]] = []
    patch_count = 0

    for index, commit in enumerate(verified, start=1):
        key = commit["commit_key"]
        technical = phase4a.get(key)
        if not technical:
            skipped_commits.append({"commit_key": key, "reason": "PHASE4A_ROW_NOT_FOUND"})
            continue
        patch_path = Path(technical.get("patch_cache_path", ""))
        if not patch_path.exists():
            skipped_commits.append({"commit_key": key, "reason": "PATCH_CACHE_NOT_FOUND"})
            continue
        patch_bytes = patch_path.read_bytes()
        patch = patch_bytes.decode("utf-8", errors="replace")
        patch_sha = hashlib.sha256(patch_bytes).hexdigest()
        patch_count += 1
        related = records_by_commit.get(key, [])
        direct = [
            row
            for row in related
            if row.get("cwe_resolution_status")
            == "DIRECT_CWE_CONFIRMED_WITH_FIX_EVIDENCE"
        ]
        labels = sorted({row.get("model_label", "") for row in related if row.get("model_label")})
        if not labels:
            labels = [item for item in commit.get("model_labels", "").split(";") if item]
        resolved_cwes = sorted({row.get("resolved_cwe_id", "") for row in direct if row.get("resolved_cwe_id")})
        candidate_cwes = sorted({row.get("target_cwe_id", "") for row in related if row.get("target_cwe_id")})
        resolution_statuses = sorted({row.get("cwe_resolution_status", "") for row in related if row.get("cwe_resolution_status")})
        advisory_ids = sorted(
            {
                row.get("ghsa_id") or row.get("cve_id") or row.get("osv_id") or ""
                for row in related
            }
            - {""}
        )
        record_ids = sorted({row.get("record_id", "") for row in related} - {""})
        parent_values = parse_json_list(commit.get("parent_commits", ""))
        parent = parent_values[0] if len(parent_values) == 1 else ""

        for item in parse_patch(patch):
            if not is_python_hunk(item):
                continue
            before = item["code_before"]
            after = item["code_after"]
            changed_before = item["changed_lines_before"]
            changed_after = item["changed_lines_after"]
            before_lines = before.splitlines()
            model_code, truncated = crop_for_model(
                before_lines,
                item["changed_positions_before"],
                args.max_model_tokens,
                args.context_lines,
            )
            token_count = estimate_tokens(model_code)
            combined = "\n".join(
                [item["hunk_context"], before, after, changed_before, changed_after]
            )
            hits = semantic_hits(labels, combined)
            change_type = (
                "ADD_FILE"
                if not item["file_path_before"]
                else "DELETE_FILE"
                if not item["file_path_after"]
                else "MODIFY"
            )
            identity = "|".join(
                [
                    key,
                    item["file_path_before"],
                    item["file_path_after"],
                    str(item["hunk_index"]),
                    str(item["old_start"]),
                    str(item["new_start"]),
                ]
            )
            row: dict[str, Any] = {
                "sample_id": "P5-" + hashlib.sha256(identity.encode()).hexdigest()[:16],
                "model_label": unique_join(labels),
                "resolved_cwe_ids": unique_join(resolved_cwes),
                "candidate_cwe_ids": unique_join(candidate_cwes),
                "cwe_resolution_statuses": unique_join(resolution_statuses),
                "advisory_ids": unique_join(advisory_ids),
                "record_ids": json_text(record_ids),
                "repository": commit["github_repository"],
                "fix_commit": commit["actual_commit_sha"],
                "parent_commit": parent,
                "commit_url": commit["commit_url"],
                "phase4b_status": commit["phase4b_status"],
                "file_path_before": item["file_path_before"],
                "file_path_after": item["file_path_after"],
                "change_type": change_type,
                "hunk_index": item["hunk_index"],
                "old_start": item["old_start"],
                "old_count": item["old_count"],
                "new_start": item["new_start"],
                "new_count": item["new_count"],
                "hunk_context": item["hunk_context"],
                "code_before": before,
                "code_after": after,
                "changed_lines_before": changed_before,
                "changed_lines_after": changed_after,
                "model_code_before": model_code,
                "estimated_model_tokens": token_count,
                "token_estimation_method": "regex_proxy_not_codebert_tokenizer",
                "truncated_for_model": str(truncated).lower(),
                "semantic_signal_hits": json_text(hits),
                "code_before_sha256": sha256_text(before),
                "code_after_sha256": sha256_text(after),
                "patch_sha256": patch_sha,
                "duplicate_group_size": 1,
                "license_review_status": "PENDING_REPOSITORY_LICENSE_AUDIT",
            }

            failed: list[str] = []
            review: list[str] = []
            row["tc01_python_vulnerable_code"] = (
                "PASS"
                if is_training_source_path(item["file_path_before"])
                and code_has_content(before)
                else "FAIL"
            )
            if row["tc01_python_vulnerable_code"] == "FAIL":
                failed.append("TC01")

            if len(labels) != 1:
                row["tc02_cwe_label_consistency"] = "FAIL_AMBIGUOUS_MODEL_LABEL"
                failed.append("TC02")
            elif resolved_cwes:
                row["tc02_cwe_label_consistency"] = "PASS_DIRECT_CWE"
            else:
                row["tc02_cwe_label_consistency"] = "REVIEW_CHILD_CWE_FROM_CODE"
                review.append("TC02_CHILD_CWE")

            if before and after and before != after and change_type == "MODIFY":
                row["tc03_before_after_evidence"] = "PASS"
            else:
                row["tc03_before_after_evidence"] = "FAIL"
                failed.append("TC03")

            has_structural_context = bool(DEF_CONTEXT_RE.search(item["hunk_context"]))
            if has_structural_context and hits:
                row["tc04_context_sufficient"] = "PASS_HUNK_FUNCTION_AND_SECURITY_SIGNAL"
            elif hits:
                row["tc04_context_sufficient"] = "REVIEW_SECURITY_SIGNAL_WITHOUT_FULL_FUNCTION"
                review.append("TC04_FULL_CONTEXT")
            else:
                row["tc04_context_sufficient"] = "REVIEW_NO_LOCAL_SECURITY_SIGNAL"
                review.append("TC04_SEMANTIC")

            if model_code and token_count <= args.max_model_tokens:
                row["tc05_codebert_compatibility"] = "PRECHECK_PASS"
            else:
                row["tc05_codebert_compatibility"] = "FAIL"
                failed.append("TC05")

            trace_values = [
                row["repository"],
                row["fix_commit"],
                row["parent_commit"],
                row["commit_url"],
                row["file_path_before"] or row["file_path_after"],
                row["advisory_ids"],
            ]
            row["tc06_traceability"] = "PASS" if all(trace_values) else "FAIL"
            if row["tc06_traceability"] == "FAIL":
                failed.append("TC06")

            row["tc07_separation_dedup"] = "PENDING_GLOBAL_DEDUP_AND_REPOSITORY_SPLIT"
            row["tc08_access_integrity"] = "PASS_PATCH_ACCESS_AND_SHA256;LICENSE_PENDING"
            review.append("TC08_LICENSE")
            row["failed_criteria"] = unique_join(failed)
            row["review_reasons"] = unique_join(review)
            output_rows.append(row)

        if index % 100 == 0 or index == len(verified):
            print(f"Parsed verified commits: {index}/{len(verified)}", flush=True)

    duplicate_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in output_rows:
        duplicate_groups[row["code_before_sha256"]].append(row)
    for group in duplicate_groups.values():
        size = len(group)
        for row in group:
            row["duplicate_group_size"] = size
            if size > 1:
                row["tc07_separation_dedup"] = "REVIEW_EXACT_DUPLICATE"
                reasons = set(filter(None, row["review_reasons"].split(";")))
                reasons.add("TC07_DUPLICATE")
                row["review_reasons"] = unique_join(reasons)
            else:
                row["tc07_separation_dedup"] = "PASS_EXACT_UNIQUE;SPLIT_PENDING"

    for row in output_rows:
        failed = list(filter(None, row["failed_criteria"].split(";")))
        reviews = list(filter(None, row["review_reasons"].split(";")))
        semantic_reviews = [reason for reason in reviews if reason != "TC08_LICENSE"]
        if failed:
            row["final_decision"] = "REJECT"
            row["decision_reason"] = "Failed required automated gates: " + ", ".join(failed)
        elif semantic_reviews:
            row["final_decision"] = "REVIEW"
            row["decision_reason"] = "Manual/full-context checks required: " + ", ".join(semantic_reviews)
        else:
            row["final_decision"] = "ACCEPT_CANDIDATE"
            row["decision_reason"] = (
                "Passed automated extraction gates; repository license audit and leakage-safe split remain"
            )

    output_rows.sort(key=lambda row: (row["repository"].lower(), row["fix_commit"], row["file_path_before"], int(row["hunk_index"])))
    accepted = [row for row in output_rows if row["final_decision"] == "ACCEPT_CANDIDATE"]
    review_rows = [row for row in output_rows if row["final_decision"] == "REVIEW"]
    rejected = [row for row in output_rows if row["final_decision"] == "REJECT"]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "python_before_after_samples.csv", output_rows)
    write_jsonl(args.output_dir / "python_before_after_samples.jsonl", output_rows)
    write_csv(args.output_dir / "accepted_candidates.csv", accepted)
    write_csv(args.output_dir / "review_samples.csv", review_rows)
    write_csv(args.output_dir / "rejected_samples.csv", rejected)
    skip_fields = ["commit_key", "reason"]
    with (args.output_dir / "skipped_commits.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=skip_fields)
        writer.writeheader()
        writer.writerows(skipped_commits)

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "safe_class_created": False,
        "input_verified_commits": len(verified),
        "patches_read": patch_count,
        "skipped_commits": len(skipped_commits),
        "python_before_after_hunks": len(output_rows),
        "accept_candidates": len(accepted),
        "review_samples": len(review_rows),
        "rejected_samples": len(rejected),
        "decision_counts": dict(sorted(Counter(row["final_decision"] for row in output_rows).items())),
        "label_counts": dict(sorted(Counter(row["model_label"] for row in output_rows).items())),
        "failed_criteria_counts": dict(
            sorted(Counter(value for row in output_rows for value in row["failed_criteria"].split(";") if value).items())
        ),
        "review_reason_counts": dict(
            sorted(Counter(value for row in output_rows for value in row["review_reasons"].split(";") if value).items())
        ),
        "exact_duplicate_samples": sum(int(row["duplicate_group_size"]) > 1 for row in output_rows),
        "warnings": [
            "ACCEPT_CANDIDATE is not final TC01-TC08 acceptance.",
            "code_after is evidence only and is never assigned a SAFE label.",
            "TC05 uses a regex token-count proxy; the real CodeBERT tokenizer must be applied before training.",
            "TC07 repository-grouped split and TC08 repository license audit remain mandatory.",
        ],
    }
    (args.output_dir / "phase5_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print(f"Python before/after hunks: {len(output_rows)}")
    print(f"ACCEPT_CANDIDATE: {len(accepted)}")
    print(f"REVIEW: {len(review_rows)}")
    print(f"REJECT: {len(rejected)}")
    print("SAFE class created: no")
    print(f"Output: {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
