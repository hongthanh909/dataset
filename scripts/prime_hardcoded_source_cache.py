#!/usr/bin/env python3
"""Reuse original verified source cache without touching it."""
from __future__ import annotations
import csv
import gzip
import hashlib
import json
import shutil
from pathlib import Path
from review_full_function_context import cache_path, raw_url
from workspace_paths import legacy_data


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    active = root / "active/six-groups-v2/evidence"
    original = legacy_data(root) / "python-advisories/before-after/phase-5b/cache/source-blobs"
    destination = active / "full-context/cache/source-blobs"
    with (active / "before-after/python_before_after_samples.csv").open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    urls = set()
    for row in rows:
        urls.add(raw_url(row["repository"], row["parent_commit"], row["file_path_before"]))
        urls.add(raw_url(row["repository"], row["fix_commit"], row["file_path_after"]))
    copied = 0
    for url in sorted(urls):
        source = cache_path(original, url)
        target = cache_path(destination, url)
        if target.exists() or not source.exists():
            continue
        with gzip.open(source, "rt", encoding="utf-8") as f:
            blob = json.load(f)
        if blob.get("url") != url or blob.get("status") != "FETCHED":
            continue
        if hashlib.sha256(blob["content"].encode("utf-8")).hexdigest() != blob.get("sha256"):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if source.read_bytes() != target.read_bytes():
            raise RuntimeError(f"Cache copy mismatch: {target}")
        copied += 1
    print(f"Original source cache reused: {copied}/{len(urls)} URLs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
