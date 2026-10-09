#!/usr/bin/env python3
"""Bounded source retrieval followed by the original context-review pipeline.

curl has a total request timeout; subprocess has a separate hard timeout. This
avoids unbounded platform DNS/TLS waits. No vulnerable third-party code is run.
All outputs remain candidate evidence, not approved ground truth.
"""
from __future__ import annotations
import concurrent.futures
import csv
import gzip
import hashlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
import review_full_function_context as pipeline


ROOT = Path(__file__).resolve().parents[1]
ACTIVE = ROOT / "active/six-groups-v2/evidence"
CACHE = ACTIVE / "full-context/cache/source-blobs"


def retrieve(url: str) -> dict:
    target = pipeline.cache_path(CACHE, url)
    if target.exists():
        with gzip.open(target, "rt", encoding="utf-8") as f:
            prior = json.load(f)
        if prior.get("status") == "FETCHED" and prior.get("url") == url:
            return prior
    result = {"url": url, "status": "FETCH_FAILED", "http_status": "",
              "content": "", "sha256": "", "error": "", "retrieval": "curl_bounded_15s"}
    try:
        response = subprocess.run(
            ["curl.exe", "--fail", "--location", "--silent", "--show-error",
             "--proto", "=https", "--proto-redir", "=https", "--max-time", "15",
             "--connect-timeout", "5", "--max-filesize", "4194304", url],
            capture_output=True, timeout=18, check=False)
        if response.returncode:
            result["error"] = response.stderr.decode("utf-8", errors="replace")[:500]
        elif len(response.stdout) > 4 * 1024 * 1024:
            result["status"] = "SOURCE_TOO_LARGE"
        else:
            content = response.stdout.decode("utf-8")
            result.update(status="FETCHED", http_status="200", content=content,
                          sha256=hashlib.sha256(response.stdout).hexdigest())
    except (subprocess.TimeoutExpired, OSError, UnicodeDecodeError) as exc:
        result["error"] = str(exc)[:500]
    target.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(target, "wt", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)
    return result


def cache_only(url: str, cache_dir: Path, refresh: bool, timeout: int, max_bytes: int) -> dict:
    target = pipeline.cache_path(CACHE, url)
    if target.exists():
        with gzip.open(target, "rt", encoding="utf-8") as f:
            return json.load(f)
    return {"url": url, "status": "FETCH_FAILED", "content": "", "sha256": "",
            "http_status": "", "error": "No bounded retrieval result"}


def main() -> int:
    with (ACTIVE / "before-after/python_before_after_samples.csv").open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    urls = set()
    for row in rows:
        urls.add(pipeline.raw_url(row["repository"], row["parent_commit"], row["file_path_before"]))
        urls.add(pipeline.raw_url(row["repository"], row["fix_commit"], row["file_path_after"]))
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(retrieve, url) for url in sorted(urls)]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            results.append(future.result())
            if index % 20 == 0 or index == len(futures):
                print(f"Bounded source retrieval: {index}/{len(futures)}", flush=True)
    summary = dict(Counter(result["status"] for result in results))
    (ROOT / "active/six-groups-v2/reports/source_retrieval_summary.json").write_text(
        json.dumps({"urls": len(urls), "statuses": summary}, indent=2) + "\n", encoding="utf-8")
    pipeline.fetch_blob = cache_only
    sys.argv = [sys.argv[0], "--review", str(ACTIVE / "before-after/python_before_after_samples.csv"),
                "--accepted", str(ACTIVE / "before-after/accepted_candidates.csv"),
                "--output-dir", str(ACTIVE / "full-context"), "--workers", "1"]
    return pipeline.main()


if __name__ == "__main__":
    raise SystemExit(main())
