#!/usr/bin/env python3
"""Phase 5B: fetch full Python scopes and re-evaluate Phase 5A review rows.

Only strong, local, label-consistent evidence is promoted.  The fixed version
remains audit evidence and is never converted into a SAFE training class.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import csv
import functools
import gzip
import hashlib
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


USER_AGENT = "PyVul-Full-Context-Reviewer/1.0 (+research dataset builder)"

MECHANISMS: dict[str, dict[str, list[tuple[str, re.Pattern[str]]]]] = {
    "PATH_TRAVERSAL": {
        "source": [("external_path", re.compile(r"request|query|param|argv|input\s*\(|url|filename", re.I))],
        "sink": [("filesystem_sink", re.compile(r"\bopen\s*\(|os\.path|pathlib|Path\s*\(|send_file|FileResponse|extract", re.I))],
        "guard": [("path_guard", re.compile(r"resolve\s*\(|realpath|commonpath|is_relative_to|normpath|startswith", re.I))],
    },
    "XSS": {
        "source": [("web_input", re.compile(r"request|query|param|form|cookie|header|user[_-]?input", re.I))],
        "sink": [("html_sink", re.compile(r"render|response|html|template|markup|set-cookie|innerHTML", re.I))],
        "guard": [("output_encoding", re.compile(r"escape|sanitize|markupsafe|bleach|htmlsafe|quote", re.I))],
    },
    "OS_COMMAND_INJECTION": {
        "source": [("command_input", re.compile(r"request|query|param|argv|input\s*\(|command|cmd", re.I))],
        "sink": [("process_sink", re.compile(r"subprocess|os\.system|os\.popen|Popen\s*\(|shell\s*=\s*True", re.I))],
        "guard": [("command_guard", re.compile(r"shlex|shell\s*=\s*False|quote|allowlist|validate", re.I))],
    },
    "SQL_INJECTION": {
        "source": [("query_input", re.compile(r"request|query|param|form|input\s*\(|filter", re.I))],
        "sink": [("sql_sink", re.compile(r"execute\s*\(|executemany\s*\(|raw\s*\(|cursor|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b", re.I))],
        "guard": [("parameterization", re.compile(r"parameter|placeholder|bindparam|params|\?\s*[,)]|%s", re.I))],
    },
    "INSECURE_AUTHENTICATION": {
        "source": [("credential_input", re.compile(r"request|header|cookie|password|credential|jwt|token|certificate", re.I))],
        "sink": [("auth_decision", re.compile(r"auth|login|session|permission|is_authenticated|verify", re.I))],
        "guard": [("auth_guard", re.compile(r"compare_digest|check_password|verify|constant_time|permission|deny|reject|expiry|audience|issuer", re.I))],
    },
    "HARDCODED_CREDENTIALS": {
        "source": [("literal_secret", re.compile(r"(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\w*\s*[:=]\s*['\"][^'\"]+['\"]", re.I))],
        "sink": [("credential_use", re.compile(r"password|passwd|secret|api[_-]?key|token|credential|private[_-]?key", re.I))],
        "guard": [("external_secret", re.compile(r"environ|getenv|config|keyring|vault|secret[_-]?manager", re.I))],
    },
}

BASE_FIELDS: list[str] = []
EXTRA_FIELDS = [
    "before_blob_url",
    "after_blob_url",
    "before_fetch_status",
    "after_fetch_status",
    "before_blob_sha256",
    "after_blob_sha256",
    "before_scope_kind",
    "before_scope_name",
    "before_scope_start",
    "before_scope_end",
    "after_scope_kind",
    "after_scope_name",
    "after_scope_start",
    "after_scope_end",
    "full_code_before",
    "full_code_after",
    "before_mechanism_hits",
    "after_mechanism_hits",
    "changed_mechanism_hits",
    "new_guard_hits",
    "removed_risk_hits",
    "semantic_score",
    "phase5b_status",
    "phase5b_reason",
    "phase5b_tc02",
    "phase5b_tc03",
    "phase5b_tc04",
]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    base = root / "data" / "python-advisories" / "before-after"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", type=Path, default=base / "review_samples.csv")
    parser.add_argument("--accepted", type=Path, default=base / "accepted_candidates.csv")
    parser.add_argument("--output-dir", type=Path, default=base / "phase-5b")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--max-source-mb", type=int, default=4)
    parser.add_argument("--max-scope-lines", type=int, default=260)
    parser.add_argument("--fallback-radius", type=int, default=45)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fields = list(reader.fieldnames or [])
    if not rows:
        raise ValueError(f"Input CSV is empty: {path}")
    return fields, rows


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def cache_path(cache_dir: Path, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_dir / digest[:2] / f"{digest}.json.gz"


def raw_url(repository: str, commit: str, file_path: str) -> str:
    encoded = urllib.parse.quote(file_path, safe="/")
    return f"https://raw.githubusercontent.com/{repository}/{commit}/{encoded}"


def fetch_blob(
    url: str,
    cache_dir: Path,
    refresh: bool,
    timeout: int,
    max_bytes: int,
) -> dict[str, Any]:
    target = cache_path(cache_dir, url)
    if target.exists() and not refresh:
        try:
            with gzip.open(target, "rt", encoding="utf-8") as handle:
                cached = json.load(handle)
            if cached.get("status") in {"FETCHED", "NOT_FOUND", "SOURCE_TOO_LARGE"}:
                return cached
        except (OSError, json.JSONDecodeError):
            pass
    result: dict[str, Any] = {
        "url": url,
        "status": "FETCH_FAILED",
        "http_status": "",
        "content": "",
        "sha256": "",
        "error": "",
    }
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > max_bytes:
                result["status"] = "SOURCE_TOO_LARGE"
                result["http_status"] = str(response.status)
            else:
                payload = response.read(max_bytes + 1)
                result["http_status"] = str(response.status)
                if len(payload) > max_bytes:
                    result["status"] = "SOURCE_TOO_LARGE"
                else:
                    result["status"] = "FETCHED"
                    result["content"] = payload.decode("utf-8", errors="replace")
                    result["sha256"] = sha256_bytes(payload)
    except urllib.error.HTTPError as exc:
        result["http_status"] = str(exc.code)
        result["status"] = "NOT_FOUND" if exc.code == 404 else "HTTP_ERROR"
        result["error"] = str(exc)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + f".{threading.get_ident()}.tmp")
    with gzip.open(temporary, "wt", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False)
    temporary.replace(target)
    return result


def node_span(node: ast.AST) -> tuple[int, int] | None:
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if isinstance(start, int) and isinstance(end, int):
        return start, end
    return None


def crop_scope(lines: list[str], start: int, end: int, anchor: int, max_lines: int) -> tuple[int, int, str]:
    if end - start + 1 > max_lines:
        half = max_lines // 2
        start = max(start, anchor - half)
        end = min(end, start + max_lines - 1)
        start = max(1, end - max_lines + 1)
    return start, end, "\n".join(lines[start - 1 : end]).rstrip()


def fallback_scope(source: str, anchor: int, radius: int, max_lines: int) -> dict[str, Any]:
    lines = source.splitlines()
    if not lines:
        return {"kind": "EMPTY", "name": "", "start": 0, "end": 0, "code": ""}
    anchor = max(1, min(anchor, len(lines)))
    definition = re.compile(r"^(\s*)(?:async\s+def|def|class)\s+([A-Za-z_]\w*)")
    for index in range(anchor - 1, -1, -1):
        match = definition.match(lines[index])
        if not match:
            continue
        indent = len(match.group(1).expandtabs(8))
        end = len(lines)
        for cursor in range(index + 1, len(lines)):
            stripped = lines[cursor].strip()
            current_indent = len(lines[cursor]) - len(lines[cursor].lstrip(" \t"))
            if stripped and not stripped.startswith("#") and current_indent <= indent:
                end = cursor
                break
        start, end, code = crop_scope(lines, index + 1, end, anchor, max_lines)
        return {"kind": "INDENT_SCOPE", "name": match.group(2), "start": start, "end": end, "code": code}
    start = max(1, anchor - radius)
    end = min(len(lines), anchor + radius)
    start, end, code = crop_scope(lines, start, end, anchor, max_lines)
    return {"kind": "LINE_WINDOW", "name": "", "start": start, "end": end, "code": code}


@functools.lru_cache(maxsize=16)
def parse_ast_cached(source: str) -> ast.AST | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            return ast.parse(source)
    except (SyntaxError, ValueError, MemoryError):
        return None


def extract_scope(source: str, anchor: int, radius: int, max_lines: int) -> dict[str, Any]:
    lines = source.splitlines()
    if not lines:
        return {"kind": "EMPTY", "name": "", "start": 0, "end": 0, "code": ""}
    anchor = max(1, min(anchor, len(lines)))
    tree = parse_ast_cached(source)
    if tree is None:
        return fallback_scope(source, anchor, radius, max_lines)
    candidates: list[tuple[int, int, int, ast.AST]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        span = node_span(node)
        if span and span[0] <= anchor <= span[1]:
            priority = 0 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else 1
            candidates.append((span[1] - span[0], priority, span[0], node))
    if not candidates:
        return fallback_scope(source, anchor, radius, max_lines)
    _, _, _, chosen = min(candidates, key=lambda item: (item[0], item[1], -item[2]))
    start, end = node_span(chosen) or (anchor, anchor)
    start, end, code = crop_scope(lines, start, end, anchor, max_lines)
    return {
        "kind": type(chosen).__name__.upper(),
        "name": getattr(chosen, "name", ""),
        "start": start,
        "end": end,
        "code": code,
    }


def mechanism_hits(label: str, text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {"source": [], "sink": [], "guard": []}
    for category, patterns in MECHANISMS.get(label, {}).items():
        for name, pattern in patterns:
            if pattern.search(text):
                result[category].append(name)
    return result


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


def flatten_hits(hits: dict[str, list[str]]) -> list[str]:
    return sorted(f"{category}:{name}" for category, names in hits.items() for name in names)


def assess_semantics(row: dict[str, str], before: str, after: str) -> dict[str, Any]:
    labels = [label for label in row["model_label"].split(";") if label]
    if len(labels) != 1:
        return {
            "score": 0,
            "strong": False,
            "partial": False,
            "before": [],
            "after": [],
            "changed": [],
            "new_guards": [],
            "removed_risks": [],
            "reason": "Ambiguous model label",
        }
    label = labels[0]
    before_hits = mechanism_hits(label, before)
    after_hits = mechanism_hits(label, after)
    changed_before = row.get("changed_lines_before", "")
    changed_after = row.get("changed_lines_after", "")
    changed_hits_before = mechanism_hits(label, changed_before)
    changed_hits_after = mechanism_hits(label, changed_after)
    before_flat = set(flatten_hits(before_hits))
    after_flat = set(flatten_hits(after_hits))
    changed_flat = set(flatten_hits(changed_hits_before) + flatten_hits(changed_hits_after))
    new_guards = set(f"guard:{name}" for name in after_hits["guard"]) - set(
        f"guard:{name}" for name in before_hits["guard"]
    )
    removed_risks = set(
        [f"source:{name}" for name in before_hits["source"]]
        + [f"sink:{name}" for name in before_hits["sink"]]
    ) - after_flat
    sink_before = bool(before_hits["sink"])
    source_before = bool(before_hits["source"])
    changed_relevant = bool(changed_flat)
    fix_delta = bool(new_guards or removed_risks)
    score = (
        3 * int(sink_before)
        + 2 * int(source_before)
        + 3 * int(changed_relevant)
        + 3 * int(fix_delta)
    )
    if label == "HARDCODED_CREDENTIALS":
        strong = bool(before_hits["source"] and changed_relevant and (new_guards or not after_hits["source"]))
    else:
        strong = sink_before and changed_relevant and (source_before or fix_delta)
    partial = (sink_before and changed_relevant) or (changed_relevant and fix_delta)
    reason = (
        "Strong source/sink/guard evidence in the changed full scope"
        if strong
        else "Partial mechanism evidence; manual confirmation required"
        if partial
        else "No label-specific mechanism tied to the changed full scope"
    )
    return {
        "score": score,
        "strong": strong,
        "partial": partial,
        "before": sorted(before_flat),
        "after": sorted(after_flat),
        "changed": sorted(changed_flat),
        "new_guards": sorted(new_guards),
        "removed_risks": sorted(removed_risks),
        "reason": reason,
    }


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    args = parse_args()
    global BASE_FIELDS
    BASE_FIELDS, review_rows = read_csv(args.review)
    _, accepted_rows = read_csv(args.accepted)
    if args.limit:
        review_rows = review_rows[: args.limit]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = args.output_dir / "cache" / "source-blobs"

    requests: dict[str, tuple[str, str, str]] = {}
    for row in review_rows:
        before_url = raw_url(row["repository"], row["parent_commit"], row["file_path_before"])
        after_url = raw_url(row["repository"], row["fix_commit"], row["file_path_after"])
        requests[before_url] = (row["repository"], row["parent_commit"], row["file_path_before"])
        requests[after_url] = (row["repository"], row["fix_commit"], row["file_path_after"])
    urls = sorted(requests)
    fetched: dict[str, dict[str, Any]] = {}
    max_bytes = args.max_source_mb * 1024 * 1024
    print(f"Unique source blobs to resolve: {len(urls)}", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_map = {
            executor.submit(
                fetch_blob,
                url,
                cache_dir,
                args.refresh,
                args.timeout,
                max_bytes,
            ): url
            for url in urls
        }
        for index, future in enumerate(concurrent.futures.as_completed(future_map), start=1):
            url = future_map[future]
            try:
                fetched[url] = future.result()
            except Exception as exc:  # defensive boundary around worker failures
                fetched[url] = {
                    "url": url,
                    "status": "WORKER_FAILED",
                    "http_status": "",
                    "content": "",
                    "sha256": "",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            if index % 100 == 0 or index == len(urls):
                print(f"Resolved source blobs: {index}/{len(urls)}", flush=True)

    evaluated: list[dict[str, Any]] = []
    for row in review_rows:
        item: dict[str, Any] = dict(row)
        before_url = raw_url(row["repository"], row["parent_commit"], row["file_path_before"])
        after_url = raw_url(row["repository"], row["fix_commit"], row["file_path_after"])
        before_blob = fetched[before_url]
        after_blob = fetched[after_url]
        item["before_blob_url"] = before_url
        item["after_blob_url"] = after_url
        item["before_fetch_status"] = before_blob["status"]
        item["after_fetch_status"] = after_blob["status"]
        item["before_blob_sha256"] = before_blob.get("sha256", "")
        item["after_blob_sha256"] = after_blob.get("sha256", "")
        if before_blob["status"] == "FETCHED":
            before_anchor = int(row["old_start"]) + min(
                3, max(0, int(row.get("old_count", "1") or "1") - 1)
            )
            before_scope = extract_scope(
                before_blob["content"],
                before_anchor,
                args.fallback_radius,
                args.max_scope_lines,
            )
        else:
            before_scope = {"kind": "UNAVAILABLE", "name": "", "start": 0, "end": 0, "code": ""}
        if after_blob["status"] == "FETCHED":
            after_anchor = int(row["new_start"]) + min(
                3, max(0, int(row.get("new_count", "1") or "1") - 1)
            )
            after_scope = extract_scope(
                after_blob["content"],
                after_anchor,
                args.fallback_radius,
                args.max_scope_lines,
            )
        else:
            after_scope = {"kind": "UNAVAILABLE", "name": "", "start": 0, "end": 0, "code": ""}
        for prefix, scope in (("before", before_scope), ("after", after_scope)):
            item[f"{prefix}_scope_kind"] = scope["kind"]
            item[f"{prefix}_scope_name"] = scope["name"]
            item[f"{prefix}_scope_start"] = scope["start"]
            item[f"{prefix}_scope_end"] = scope["end"]
            item[f"full_code_{prefix}"] = scope["code"]

        both_fetched = before_blob["status"] == after_blob["status"] == "FETCHED"
        meaningful_pair = bool(before_scope["code"] and after_scope["code"] and before_scope["code"] != after_scope["code"])
        semantics = assess_semantics(row, before_scope["code"], after_scope["code"])
        item["before_mechanism_hits"] = json_text(semantics["before"])
        item["after_mechanism_hits"] = json_text(semantics["after"])
        item["changed_mechanism_hits"] = json_text(semantics["changed"])
        item["new_guard_hits"] = json_text(semantics["new_guards"])
        item["removed_risk_hits"] = json_text(semantics["removed_risks"])
        item["semantic_score"] = semantics["score"]
        item["phase5b_tc03"] = "PASS_FULL_CONTEXT_PAIR" if meaningful_pair else "REVIEW_OR_FAIL"
        structural_scope = before_scope["kind"] not in {
            "LINE_WINDOW",
            "EMPTY",
            "UNAVAILABLE",
        } and after_scope["kind"] not in {"LINE_WINDOW", "EMPTY", "UNAVAILABLE"}
        item["phase5b_tc04"] = (
            "PASS_STRONG_MECHANISM_IN_STRUCTURAL_SCOPE"
            if semantics["strong"] and structural_scope
            else "REVIEW_STRONG_SIGNAL_WITHOUT_STRUCTURAL_SCOPE"
            if semantics["strong"]
            else "REVIEW_PARTIAL_MECHANISM"
            if semantics["partial"]
            else "FAIL_NO_MECHANISM"
        )
        child_pending = "TC02_CHILD_CWE" in row["review_reasons"].split(";")
        ambiguous = ";" in row["model_label"]
        if ambiguous:
            item["phase5b_tc02"] = "FAIL_AMBIGUOUS_MODEL_LABEL"
        elif child_pending:
            item["phase5b_tc02"] = "REVIEW_EXACT_CHILD_CWE_UNRESOLVED"
        elif semantics["strong"]:
            item["phase5b_tc02"] = "PASS_LABEL_MECHANISM_CONSISTENT"
        else:
            item["phase5b_tc02"] = "REVIEW_LABEL_MECHANISM"

        duplicate_pending = int(row.get("duplicate_group_size", "1") or "1") > 1
        if not is_training_source_path(row["file_path_before"]):
            item["phase5b_status"] = "FULL_CONTEXT_REJECT"
            item["phase5b_reason"] = "TC01 excludes test, documentation, example, benchmark, or fixture code"
        elif not both_fetched:
            item["phase5b_status"] = "FULL_CONTEXT_REVIEW"
            item["phase5b_reason"] = "Source retrieval incomplete; retry or inspect repository manually"
        elif not meaningful_pair:
            item["phase5b_status"] = "FULL_CONTEXT_REJECT"
            item["phase5b_reason"] = "Full before/after scopes are empty or unchanged"
        elif ambiguous:
            item["phase5b_status"] = "FULL_CONTEXT_REJECT"
            item["phase5b_reason"] = "The same sample maps to multiple model labels"
        elif child_pending:
            item["phase5b_status"] = "FULL_CONTEXT_REVIEW"
            item["phase5b_reason"] = "Label mechanism may match, but the exact child CWE is unresolved"
        elif duplicate_pending:
            item["phase5b_status"] = "FULL_CONTEXT_REVIEW"
            item["phase5b_reason"] = "Exact duplicate group must be collapsed before promotion"
        elif semantics["strong"] and structural_scope:
            item["phase5b_status"] = "FULL_CONTEXT_PASS"
            item["phase5b_reason"] = semantics["reason"]
            item["tc02_cwe_label_consistency"] = "PASS_FULL_CONTEXT_LABEL_MECHANISM"
            item["tc03_before_after_evidence"] = "PASS_FULL_CONTEXT"
            item["tc04_context_sufficient"] = "PASS_FULL_FUNCTION_SECURITY_MECHANISM"
            item["final_decision"] = "ACCEPT_CANDIDATE"
            item["decision_reason"] = "Promoted by Phase 5B full-context semantic evidence"
            remaining = [
                reason
                for reason in row["review_reasons"].split(";")
                if reason and reason not in {"TC04_FULL_CONTEXT", "TC04_SEMANTIC"}
            ]
            item["review_reasons"] = ";".join(sorted(set(remaining)))
        elif semantics["strong"]:
            item["phase5b_status"] = "FULL_CONTEXT_REVIEW"
            item["phase5b_reason"] = (
                "Strong keyword/mechanism signal, but no enclosing function/class scope was resolved"
            )
        elif semantics["partial"]:
            item["phase5b_status"] = "FULL_CONTEXT_REVIEW"
            item["phase5b_reason"] = semantics["reason"]
        else:
            item["phase5b_status"] = "FULL_CONTEXT_REJECT"
            item["phase5b_reason"] = semantics["reason"]
        evaluated.append(item)

    fields = BASE_FIELDS + EXTRA_FIELDS
    passed = [row for row in evaluated if row["phase5b_status"] == "FULL_CONTEXT_PASS"]
    still_review = [row for row in evaluated if row["phase5b_status"] == "FULL_CONTEXT_REVIEW"]
    rejected = [row for row in evaluated if row["phase5b_status"] == "FULL_CONTEXT_REJECT"]
    write_csv(args.output_dir / "full_context_evaluation.csv", fields, evaluated)
    write_jsonl(args.output_dir / "full_context_evaluation.jsonl", evaluated)
    write_csv(args.output_dir / "full_context_pass.csv", fields, passed)
    write_csv(args.output_dir / "full_context_review.csv", fields, still_review)
    write_csv(args.output_dir / "full_context_reject.csv", fields, rejected)

    pool_fields = fields
    pool: list[dict[str, Any]] = []
    for row in accepted_rows:
        item = dict(row)
        item.update(
            {
                "phase5b_status": "NOT_REQUIRED_PHASE5A_ACCEPT",
                "phase5b_reason": "Passed Phase 5A automated hunk gates",
            }
        )
        pool.append(item)
    pool.extend(passed)
    pool.sort(key=lambda row: row["sample_id"])
    write_csv(args.output_dir / "final_candidate_pool.csv", pool_fields, pool)
    write_jsonl(args.output_dir / "final_candidate_pool.jsonl", pool)

    fetch_counts = Counter(result["status"] for result in fetched.values())
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "safe_class_created": False,
        "input_review_samples": len(review_rows),
        "unique_source_blobs": len(urls),
        "source_fetch_status_counts": dict(sorted(fetch_counts.items())),
        "full_context_pass": len(passed),
        "full_context_review": len(still_review),
        "full_context_reject": len(rejected),
        "phase5b_status_counts": dict(sorted(Counter(row["phase5b_status"] for row in evaluated).items())),
        "phase5a_accept_candidates": len(accepted_rows),
        "final_candidate_pool": len(pool),
        "candidate_pool_label_counts": dict(sorted(Counter(row["model_label"] for row in pool).items())),
        "warnings": [
            "final_candidate_pool is not ACCEPT_FINAL.",
            "TC05 must use the real CodeBERT tokenizer.",
            "TC07 exact/near deduplication and repository-grouped splitting remain required.",
            "TC08 repository license audit remains required.",
            "code_after/full_code_after are evidence only; no SAFE class is created.",
        ],
    }
    (args.output_dir / "phase5b_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"FULL_CONTEXT_PASS: {len(passed)}")
    print(f"FULL_CONTEXT_REVIEW: {len(still_review)}")
    print(f"FULL_CONTEXT_REJECT: {len(rejected)}")
    print(f"Final candidate pool (not ACCEPT_FINAL): {len(pool)}")
    print("SAFE class created: no")
    print(f"Output: {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
