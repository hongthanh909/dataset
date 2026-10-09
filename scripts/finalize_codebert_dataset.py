#!/usr/bin/env python3
"""Phase 5C: CodeBERT tokenization, deduplication, license audit, and safe split."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import gzip
import hashlib
import io
import json
import keyword
import math
import random
import re
import token as token_module
import tokenize
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from transformers import AutoTokenizer


USER_AGENT = "PyVul-Phase5C/1.0 (+research dataset builder)"
LABEL_MAPPING = {
    "PATH_TRAVERSAL": 0,
    "XSS": 1,
    "OS_COMMAND_INJECTION": 2,
    "SQL_INJECTION": 3,
    "INSECURE_AUTHENTICATION": 4,
    "HARDCODED_CREDENTIALS": 5,
}
LICENSE_FILENAMES = [
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "LICENSE.rst",
    "COPYING",
    "COPYING.txt",
    "COPYING.md",
    "LICENCE",
    "LICENCE.txt",
    "LICENSE-MIT",
    "LICENSE-APACHE",
]
PERMISSIVE_LICENSES = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Python-2.0",
    "Unlicense",
    "CC0-1.0",
    "Zlib",
}

REPORT_FIELDS = [
    "sample_id",
    "origin",
    "repository",
    "fix_commit",
    "model_label",
    "resolved_cwe_ids",
    "file_path_before",
    "original_token_count",
    "final_token_count",
    "was_truncated",
    "changed_region_retained",
    "tokenizer_name",
    "tc05_status",
    "tc05_reason",
    "exact_hash",
    "normalized_hash",
    "structural_hash",
    "simhash64",
    "duplicate_group_id",
    "duplicate_group_size",
    "representative_sample_id",
    "dedup_decision",
    "license_name",
    "license_file",
    "license_url",
    "license_status",
    "tc08_status",
    "split",
    "tc07_status",
    "phase5c_decision",
    "phase5c_reason",
]

FINAL_FIELDS = [
    "sample_id",
    "code",
    "label",
    "label_id",
    "cwe_ids",
    "advisory_ids",
    "repository",
    "file_path",
    "fix_commit",
    "parent_commit",
    "commit_url",
    "tokenizer_name",
    "token_count",
    "was_truncated",
    "changed_region_retained",
    "code_hash",
    "normalized_hash",
    "structural_hash",
    "license_name",
    "license_file",
    "license_url",
    "split",
    "tc01_status",
    "tc02_status",
    "tc03_status",
    "tc04_status",
    "tc05_status",
    "tc06_status",
    "tc07_status",
    "tc08_status",
    "final_decision",
]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    base = root / "data" / "python-advisories" / "before-after" / "phase-5b"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, default=base / "final_candidate_pool.csv")
    parser.add_argument("--review", type=Path, default=base / "full_context_review.csv")
    parser.add_argument("--output-dir", type=Path, default=root / "data" / "python-advisories" / "phase-5c")
    parser.add_argument("--tokenizer", default="microsoft/codebert-base")
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--refresh-license", action="store_true")
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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def training_code(row: dict[str, str]) -> str:
    return (
        row.get("full_code_before", "").strip()
        or row.get("model_code_before", "").strip()
        or row.get("code_before", "").strip()
    )


def choose_duplicate_representatives(review: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    eligible: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in review:
        if int(row.get("duplicate_group_size", "1") or "1") <= 1:
            continue
        if row.get("phase5b_tc04") != "PASS_STRONG_MECHANISM_IN_STRUCTURAL_SCOPE":
            continue
        if not row.get("phase5b_tc02", "").startswith("PASS"):
            continue
        if row.get("phase5b_tc03") != "PASS_FULL_CONTEXT_PAIR":
            continue
        if ";" in row.get("model_label", ""):
            continue
        eligible[row["code_before_sha256"]].append(row)
    selected: list[dict[str, str]] = []
    decisions: list[dict[str, Any]] = []
    for code_hash, group in sorted(eligible.items()):
        ranked = sorted(
            group,
            key=lambda row: (
                row.get("phase4b_status") != "CONFIRMED_FIX_EVIDENCE_AUTO",
                -int(row.get("semantic_score", "0") or "0"),
                row["sample_id"],
            ),
        )
        representative = dict(ranked[0])
        representative["origin"] = "PHASE5B_DUPLICATE_REPRESENTATIVE"
        representative["final_decision"] = "ACCEPT_CANDIDATE"
        selected.append(representative)
        for row in ranked:
            decisions.append(
                {
                    "sample_id": row["sample_id"],
                    "code_before_sha256": code_hash,
                    "duplicate_group_size": len(group),
                    "representative_sample_id": representative["sample_id"],
                    "decision": "REPRESENTATIVE_SELECTED" if row is ranked[0] else "DUPLICATE_REMOVED",
                    "reason": "Best provenance and semantic score in Phase 5B exact-duplicate group",
                }
            )
    return selected, decisions


def locate_anchor(code: str, row: dict[str, str]) -> tuple[int, int] | None:
    changed = [line.strip() for line in row.get("changed_lines_before", "").splitlines() if line.strip()]
    for line in changed:
        start = code.find(line)
        if start >= 0:
            return start, start + len(line)
    hunk = row.get("code_before", "").strip()
    if hunk:
        start = code.find(hunk)
        if start >= 0:
            return start, start + len(hunk)
    return None


def tokenize_sample(tokenizer: Any, code: str, row: dict[str, str], max_length: int) -> dict[str, Any]:
    encoded = tokenizer(code, add_special_tokens=False, return_offsets_mapping=True, truncation=False)
    ids = list(encoded["input_ids"])
    offsets = list(encoded["offset_mapping"])
    original_count = len(ids) + 2
    result = {
        "code": code,
        "original_token_count": original_count,
        "final_token_count": original_count,
        "was_truncated": False,
        "changed_region_retained": True,
        "tc05_status": "PASS",
        "tc05_reason": "Code fits CodeBERT maximum length",
    }
    content_limit = max_length - 2
    if original_count <= max_length:
        return result
    anchor = locate_anchor(code, row)
    if not anchor or not offsets:
        result.update(
            {
                "changed_region_retained": False,
                "tc05_status": "REVIEW",
                "tc05_reason": "Over length and changed region could not be located",
            }
        )
        return result
    anchor_start, anchor_end = anchor
    anchor_tokens = [i for i, (start, end) in enumerate(offsets) if end > anchor_start and start < anchor_end]
    if not anchor_tokens:
        result.update(
            {
                "changed_region_retained": False,
                "tc05_status": "REVIEW",
                "tc05_reason": "Changed region has no tokenizer offset mapping",
            }
        )
        return result
    center = (anchor_tokens[0] + anchor_tokens[-1]) // 2
    left = max(0, center - content_limit // 2)
    right = min(len(ids), left + content_limit)
    left = max(0, right - content_limit)
    if anchor_tokens[0] < left or anchor_tokens[-1] >= right:
        result.update(
            {
                "changed_region_retained": False,
                "tc05_status": "REJECT",
                "tc05_reason": "Changed region itself exceeds the model window",
            }
        )
        return result
    char_start = offsets[left][0]
    char_end = offsets[right - 1][1]
    cropped = code[char_start:char_end].strip()
    final_count = len(tokenizer.encode(cropped, add_special_tokens=True, truncation=False))
    result.update(
        {
            "code": cropped,
            "final_token_count": final_count,
            "was_truncated": True,
            "changed_region_retained": True,
            "tc05_status": "PASS_TRUNCATED" if final_count <= max_length else "REVIEW",
            "tc05_reason": (
                "Centered token window retains the changed vulnerable region"
                if final_count <= max_length
                else "Cropped window still exceeds the model maximum"
            ),
        }
    )
    return result


def normalized_tokens(code: str, structural: bool = False) -> list[str]:
    output: list[str] = []
    try:
        stream = tokenize.generate_tokens(io.StringIO(code).readline)
        for item in stream:
            if item.type in {
                token_module.ENCODING,
                token_module.ENDMARKER,
                token_module.INDENT,
                token_module.DEDENT,
                token_module.NEWLINE,
                tokenize.NL,
                tokenize.COMMENT,
            }:
                continue
            value = item.string
            if structural:
                if item.type == token_module.NAME and not keyword.iskeyword(value):
                    value = "ID"
                elif item.type == token_module.STRING:
                    value = "STR"
                elif item.type == token_module.NUMBER:
                    value = "NUM"
            output.append(value)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        output = re.findall(r"[A-Za-z_]\w*|\d+|[^\s\w]", code)
        if structural:
            output = ["ID" if re.fullmatch(r"[A-Za-z_]\w*", value) and not keyword.iskeyword(value) else "NUM" if value.isdigit() else value for value in output]
    return output


def simhash64(tokens: list[str]) -> int:
    grams = ["\x1f".join(tokens[i : i + 4]) for i in range(max(1, len(tokens) - 3))]
    if not grams:
        grams = [""]
    vector = [0] * 64
    for gram in grams:
        value = int.from_bytes(hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest(), "big")
        for bit in range(64):
            vector[bit] += 1 if value & (1 << bit) else -1
    result = 0
    for bit, score in enumerate(vector):
        if score >= 0:
            result |= 1 << bit
    return result


class UnionFind:
    def __init__(self, values: Iterable[str]):
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def deduplicate(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    for row in rows:
        code = row["training_code"]
        normal = normalized_tokens(code)
        structural = normalized_tokens(code, structural=True)
        row["exact_hash"] = sha256_text(code)
        row["normalized_hash"] = sha256_text("\x1f".join(normal))
        row["structural_hash"] = sha256_text("\x1f".join(structural))
        row["simhash64"] = f"{simhash64(structural):016x}"
        row["structural_token_count"] = len(structural)
    uf = UnionFind(row["sample_id"] for row in rows)
    by_normal: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_normal[(row["model_label"], row["normalized_hash"])].append(row)
    for group in by_normal.values():
        for other in group[1:]:
            uf.union(group[0]["sample_id"], other["sample_id"])
    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_label[row["model_label"]].append(row)
    for group in by_label.values():
        ordered = sorted(group, key=lambda row: (row["structural_token_count"], row["simhash64"]))
        for i, left in enumerate(ordered):
            left_count = max(1, left["structural_token_count"])
            for right in ordered[i + 1 :]:
                ratio = right["structural_token_count"] / left_count
                if ratio > 1.08:
                    break
                distance = (int(left["simhash64"], 16) ^ int(right["simhash64"], 16)).bit_count()
                if distance <= 2:
                    uf.union(left["sample_id"], right["sample_id"])
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[uf.find(row["sample_id"])].append(row)
    kept: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for index, group in enumerate(sorted(grouped.values(), key=lambda g: min(r["sample_id"] for r in g)), start=1):
        group_id = f"DUP-{index:06d}"
        ranked = sorted(
            group,
            key=lambda row: (
                row.get("phase4b_status") != "CONFIRMED_FIX_EVIDENCE_AUTO",
                row["was_truncated"],
                row["final_token_count"],
                row["sample_id"],
            ),
        )
        representative = ranked[0]
        for row in ranked:
            row["duplicate_group_id"] = group_id
            row["duplicate_group_size_phase5c"] = len(group)
            row["representative_sample_id"] = representative["sample_id"]
            if row is representative:
                row["dedup_decision"] = "KEEP_REPRESENTATIVE"
                kept.append(row)
            else:
                row["dedup_decision"] = "DUPLICATE_REMOVED"
                removed.append(row)
    return kept, removed


def detect_license(text: str) -> str:
    low = text.lower()
    if "permission is hereby granted, free of charge" in low:
        return "MIT"
    if "apache license" in low and "version 2.0" in low:
        return "Apache-2.0"
    if "redistribution and use in source and binary forms" in low:
        return "BSD-3-Clause" if "neither the name" in low else "BSD-2-Clause"
    if "permission to use, copy, modify, and/or distribute this software" in low:
        return "ISC"
    if "python software foundation license" in low:
        return "Python-2.0"
    if "mozilla public license" in low and "2.0" in low:
        return "MPL-2.0"
    if "gnu affero general public license" in low:
        return "AGPL"
    if "gnu lesser general public license" in low:
        return "LGPL"
    if "gnu general public license" in low:
        return "GPL"
    if "eclipse public license" in low:
        return "EPL"
    if "this is free and unencumbered software released into the public domain" in low:
        return "Unlicense"
    if "creative commons zero" in low or "cc0 1.0 universal" in low:
        return "CC0-1.0"
    if "zlib license" in low or "this software is provided 'as-is', without any express or implied warranty" in low:
        return "Zlib"
    return "UNKNOWN"


def license_cache_path(cache_dir: Path, repository: str, commit: str) -> Path:
    digest = hashlib.sha256(f"{repository.lower()}@{commit}".encode()).hexdigest()
    return cache_dir / digest[:2] / f"{digest}.json.gz"


def audit_license(repository: str, commit: str, cache_dir: Path, timeout: int, refresh: bool) -> dict[str, Any]:
    target = license_cache_path(cache_dir, repository, commit)
    if target.exists() and not refresh:
        try:
            with gzip.open(target, "rt", encoding="utf-8") as handle:
                cached = json.load(handle)
            if cached.get("fetch_status") in {"FOUND", "NOT_FOUND"}:
                return cached
        except (OSError, json.JSONDecodeError):
            pass
    result: dict[str, Any] = {
        "repository": repository,
        "audit_commit": commit,
        "license_name": "",
        "license_file": "",
        "license_url": "",
        "fetch_status": "NOT_FOUND",
        "license_status": "REVIEW_NO_LICENSE",
        "tc08_status": "REVIEW",
        "content_sha256": "",
        "error": "",
    }
    transient_errors: list[str] = []
    for filename in LICENSE_FILENAMES:
        url = f"https://raw.githubusercontent.com/{repository}/{commit}/{urllib.parse.quote(filename)}"
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024:
                continue
            text = payload.decode("utf-8", errors="replace")
            name = detect_license(text)
            result.update(
                {
                    "license_name": name,
                    "license_file": filename,
                    "license_url": url,
                    "fetch_status": "FOUND",
                    "content_sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
            if name in PERMISSIVE_LICENSES:
                result["license_status"] = "PASS_WITH_ATTRIBUTION"
                result["tc08_status"] = "PASS"
            elif name == "UNKNOWN":
                result["license_status"] = "REVIEW_CUSTOM_OR_UNKNOWN"
            else:
                result["license_status"] = "REVIEW_COPYLEFT_OR_RESTRICTIVE"
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                transient_errors.append(f"{filename}: HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            transient_errors.append(f"{filename}: {type(exc).__name__}: {exc}")
    if result["fetch_status"] == "NOT_FOUND" and transient_errors:
        result["fetch_status"] = "FETCH_INCOMPLETE"
        result["license_status"] = "REVIEW_FETCH_ERROR"
        result["error"] = "; ".join(transient_errors)
    target.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(target, "wt", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False)
    return result


def assign_splits(rows: list[dict[str, Any]], seed: int) -> dict[str, str]:
    ids = [row["sample_id"] for row in rows]
    uf = UnionFind(ids)
    indexes: dict[tuple[str, str], str] = {}
    for row in rows:
        values = [
            ("repo", row["repository"].lower()),
            ("commit", f"{row['repository'].lower()}@{row['fix_commit']}"),
        ]
        for advisory in filter(None, row.get("advisory_ids", "").split(";")):
            values.append(("advisory", advisory))
        for key in values:
            if key in indexes:
                uf.union(row["sample_id"], indexes[key])
            else:
                indexes[key] = row["sample_id"]
    components: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        components[uf.find(row["sample_id"])].append(row)
    splits = ["train", "validation", "test"]
    ratios = {"train": 0.8, "validation": 0.1, "test": 0.1}
    total_by_label = Counter(row["model_label"] for row in rows)
    targets = {split: {label: count * ratios[split] for label, count in total_by_label.items()} for split in splits}
    target_total = {split: len(rows) * ratios[split] for split in splits}
    current = {split: Counter() for split in splits}
    current_total = Counter()
    rng = random.Random(seed)
    ordered = list(components.values())
    rng.shuffle(ordered)
    ordered.sort(key=lambda group: (-len(group), min(total_by_label[r["model_label"]] for r in group)))
    assignment: dict[str, str] = {}

    # Seed rare labels across as many independent grouped components as are
    # actually available. With two components, prefer train+test; with three
    # or more, cover train+validation+test without breaking leakage rules.
    component_key = {id(group): min(row["sample_id"] for row in group) for group in ordered}
    assigned_components: dict[str, str] = {}
    labels_by_rarity = sorted(total_by_label, key=lambda label: total_by_label[label])
    for label in labels_by_rarity:
        eligible = [group for group in ordered if any(row["model_label"] == label for row in group)]
        desired = ["train"] if len(eligible) == 1 else ["train", "test"] if len(eligible) == 2 else ["train", "validation", "test"]
        eligible.sort(
            key=lambda group: (
                -sum(row["model_label"] == label for row in group),
                -len(group),
                component_key[id(group)],
            )
        )
        for split in desired:
            if any(
                assigned_components.get(component_key[id(group)]) == split
                and any(row["model_label"] == label for row in group)
                for group in eligible
            ):
                continue
            candidate = next(
                (group for group in eligible if component_key[id(group)] not in assigned_components),
                None,
            )
            if candidate is None:
                continue
            key = component_key[id(candidate)]
            assigned_components[key] = split
            for row in candidate:
                assignment[row["sample_id"]] = split
                current[split][row["model_label"]] += 1
                current_total[split] += 1

    for group in ordered:
        key = component_key[id(group)]
        if key in assigned_components:
            continue
        counts = Counter(row["model_label"] for row in group)
        best_split = "train"
        best_score = -float("inf")
        for split in splits:
            label_need = sum(
                count * (targets[split][label] - current[split][label]) / max(1.0, targets[split][label])
                for label, count in counts.items()
            )
            total_need = (target_total[split] - current_total[split]) / max(1.0, target_total[split])
            overfill = max(0.0, current_total[split] + len(group) - target_total[split]) / max(1.0, target_total[split])
            score = label_need + total_need - 4.0 * overfill
            if score > best_score:
                best_score, best_split = score, split
        for row in group:
            assignment[row["sample_id"]] = best_split
            current[best_split][row["model_label"]] += 1
            current_total[best_split] += 1
    return assignment


def overlap_count(rows: list[dict[str, Any]], field_fn: Any) -> int:
    seen: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        for value in field_fn(row):
            if value:
                seen[value].add(row["split"])
    return sum(len(splits) > 1 for splits in seen.values())


def main() -> int:
    args = parse_args()
    candidates = read_csv(args.candidates)
    review = read_csv(args.review)
    duplicate_reps, initial_duplicate_decisions = choose_duplicate_representatives(review)
    for row in candidates:
        row["origin"] = row.get("origin") or "PHASE5_FINAL_CANDIDATE_POOL"
    combined = candidates + duplicate_reps
    unique: dict[str, dict[str, str]] = {row["sample_id"]: row for row in combined}
    combined = list(unique.values())
    if args.limit:
        combined = combined[: args.limit]

    print(f"Phase 5B candidates: {len(candidates)}")
    print(f"Eligible duplicate representatives added: {len(duplicate_reps)}")
    print(f"Phase 5C input samples: {len(combined)}", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer, use_fast=True)
    # We intentionally inspect full sequences before applying our own auditable
    # changed-region window, so suppress the library's premature length warning.
    tokenizer.model_max_length = 1_000_000_000

    reports: list[dict[str, Any]] = []
    token_pass: list[dict[str, Any]] = []
    for index, row in enumerate(combined, start=1):
        code = training_code(row)
        token_result = tokenize_sample(tokenizer, code, row, args.max_length)
        item: dict[str, Any] = dict(row)
        item.update(token_result)
        item["training_code"] = token_result["code"]
        item["tokenizer_name"] = args.tokenizer
        item["origin"] = row.get("origin", "")
        item["phase5c_decision"] = "TOKEN_PASS" if token_result["tc05_status"].startswith("PASS") else "REVIEW" if token_result["tc05_status"] == "REVIEW" else "REJECT"
        item["phase5c_reason"] = token_result["tc05_reason"]
        reports.append(item)
        if token_result["tc05_status"].startswith("PASS"):
            token_pass.append(item)
        if index % 250 == 0 or index == len(combined):
            print(f"Tokenized samples: {index}/{len(combined)}", flush=True)

    dedup_kept, duplicate_removed = deduplicate(token_pass)
    kept_ids = {row["sample_id"] for row in dedup_kept}
    removed_ids = {row["sample_id"] for row in duplicate_removed}
    for row in reports:
        if row["sample_id"] in removed_ids:
            row["phase5c_decision"] = "REJECT"
            row["phase5c_reason"] = "Removed as exact, normalized, or conservative near duplicate"
        elif row["sample_id"] in kept_ids:
            row["phase5c_decision"] = "DEDUP_PASS"

    repo_commits: dict[str, str] = {}
    for row in dedup_kept:
        repo_commits.setdefault(row["repository"].lower(), row["fix_commit"])
    cache_dir = args.output_dir / "cache" / "licenses"
    audits: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_map = {
            executor.submit(audit_license, repo, commit, cache_dir, args.timeout, args.refresh_license): repo
            for repo, commit in repo_commits.items()
        }
        for index, future in enumerate(concurrent.futures.as_completed(future_map), start=1):
            repo = future_map[future]
            try:
                audits[repo] = future.result()
            except Exception as exc:
                audits[repo] = {
                    "repository": repo,
                    "audit_commit": repo_commits[repo],
                    "license_name": "",
                    "license_file": "",
                    "license_url": "",
                    "fetch_status": "WORKER_FAILED",
                    "license_status": "REVIEW_FETCH_ERROR",
                    "tc08_status": "REVIEW",
                    "content_sha256": "",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            if index % 50 == 0 or index == len(future_map):
                print(f"Audited repository licenses: {index}/{len(future_map)}", flush=True)

    audit_counts = Counter(row["repository"].lower() for row in dedup_kept)
    audit_rows: list[dict[str, Any]] = []
    for repo in sorted(audits):
        audit = dict(audits[repo])
        audit["affected_sample_count"] = audit_counts[repo]
        audit_rows.append(audit)

    license_pass: list[dict[str, Any]] = []
    for row in dedup_kept:
        audit = audits[row["repository"].lower()]
        row["license_name"] = audit["license_name"]
        row["license_file"] = audit["license_file"]
        row["license_url"] = audit["license_url"]
        row["license_status"] = audit["license_status"]
        row["tc08_status"] = audit["tc08_status"]
        if audit["tc08_status"] == "PASS":
            license_pass.append(row)
            row["phase5c_decision"] = "LICENSE_PASS"
        else:
            row["phase5c_decision"] = "REVIEW"
            row["phase5c_reason"] = f"TC08: {audit['license_status']}"

    assignment = assign_splits(license_pass, args.seed)
    for row in license_pass:
        row["split"] = assignment[row["sample_id"]]
        row["tc07_status"] = "PASS_GROUPED_SPLIT_NO_KNOWN_OVERLAP"
        row["phase5c_decision"] = "ACCEPT_FINAL"
        row["phase5c_reason"] = "Passed TC01-TC08 automated and provenance gates"

    for row in reports:
        source = next((candidate for candidate in dedup_kept if candidate["sample_id"] == row["sample_id"]), None)
        if source:
            for field in [
                "exact_hash", "normalized_hash", "structural_hash", "simhash64",
                "duplicate_group_id", "duplicate_group_size_phase5c", "representative_sample_id",
                "dedup_decision", "license_name", "license_file", "license_url", "license_status",
                "tc08_status", "split", "tc07_status", "phase5c_decision", "phase5c_reason",
            ]:
                row[field] = source.get(field, row.get(field, ""))

    final_rows: list[dict[str, Any]] = []
    for row in license_pass:
        final_rows.append(
            {
                "sample_id": row["sample_id"],
                "code": row["training_code"],
                "label": row["model_label"],
                "label_id": LABEL_MAPPING[row["model_label"]],
                "cwe_ids": row.get("resolved_cwe_ids", ""),
                "advisory_ids": row.get("advisory_ids", ""),
                "repository": row["repository"],
                "file_path": row["file_path_before"],
                "fix_commit": row["fix_commit"],
                "parent_commit": row["parent_commit"],
                "commit_url": row["commit_url"],
                "tokenizer_name": args.tokenizer,
                "token_count": row["final_token_count"],
                "was_truncated": str(row["was_truncated"]).lower(),
                "changed_region_retained": str(row["changed_region_retained"]).lower(),
                "code_hash": row["exact_hash"],
                "normalized_hash": row["normalized_hash"],
                "structural_hash": row["structural_hash"],
                "license_name": row["license_name"],
                "license_file": row["license_file"],
                "license_url": row["license_url"],
                "split": row["split"],
                "tc01_status": row.get("tc01_python_vulnerable_code", "PASS"),
                "tc02_status": row.get("tc02_cwe_label_consistency", row.get("phase5b_tc02", "PASS")),
                "tc03_status": row.get("tc03_before_after_evidence", row.get("phase5b_tc03", "PASS")),
                "tc04_status": row.get("tc04_context_sufficient", row.get("phase5b_tc04", "PASS")),
                "tc05_status": row["tc05_status"],
                "tc06_status": row.get("tc06_traceability", "PASS"),
                "tc07_status": row["tc07_status"],
                "tc08_status": row["tc08_status"],
                "final_decision": "ACCEPT_FINAL",
            }
        )
    final_rows.sort(key=lambda row: (row["split"], row["label_id"], row["sample_id"]))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "phase5c_evaluation.csv", REPORT_FIELDS, reports)
    write_csv(args.output_dir / "codebert_tokenization_report.csv", REPORT_FIELDS, reports)
    write_csv(args.output_dir / "duplicate_removed_samples.csv", REPORT_FIELDS, duplicate_removed)
    initial_dup_fields = ["sample_id", "code_before_sha256", "duplicate_group_size", "representative_sample_id", "decision", "reason"]
    write_csv(args.output_dir / "phase5b_duplicate_resolution.csv", initial_dup_fields, initial_duplicate_decisions)
    license_fields = [
        "repository", "audit_commit", "license_name", "license_file", "license_url",
        "fetch_status", "license_status", "tc08_status", "content_sha256", "affected_sample_count", "error",
    ]
    write_csv(args.output_dir / "repository_license_audit.csv", license_fields, audit_rows)
    license_review_ids = {row["sample_id"] for row in dedup_kept if row.get("tc08_status") != "PASS"}
    write_csv(args.output_dir / "license_review_samples.csv", REPORT_FIELDS, [row for row in reports if row["sample_id"] in license_review_ids])
    write_csv(args.output_dir / "phase5c_review_samples.csv", REPORT_FIELDS, [row for row in reports if row.get("phase5c_decision") == "REVIEW"])
    write_csv(args.output_dir / "phase5c_rejected_samples.csv", REPORT_FIELDS, [row for row in reports if row.get("phase5c_decision") == "REJECT"])
    write_csv(args.output_dir / "accepted_final_samples.csv", FINAL_FIELDS, final_rows)
    write_jsonl(args.output_dir / "accepted_final_samples.jsonl", final_rows)
    for split in ["train", "validation", "test"]:
        subset = [row for row in final_rows if row["split"] == split]
        write_csv(args.output_dir / f"{split}.csv", FINAL_FIELDS, subset)
        write_jsonl(args.output_dir / f"{split}.jsonl", subset)
    (args.output_dir / "label_mapping.json").write_text(
        json.dumps(LABEL_MAPPING, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    leakage = {
        "repository_overlap": overlap_count(license_pass, lambda row: [row["repository"].lower()]),
        "fix_commit_overlap": overlap_count(license_pass, lambda row: [f"{row['repository'].lower()}@{row['fix_commit']}"]),
        "advisory_overlap": overlap_count(license_pass, lambda row: row.get("advisory_ids", "").split(";")),
        "normalized_duplicate_overlap": overlap_count(license_pass, lambda row: [row["normalized_hash"]]),
        "structural_duplicate_overlap": overlap_count(license_pass, lambda row: [row["structural_hash"]]),
    }
    leakage_rows = [{"check": key, "overlap_count": value, "status": "PASS" if value == 0 else "FAIL"} for key, value in leakage.items()]
    write_csv(args.output_dir / "split_leakage_report.csv", ["check", "overlap_count", "status"], leakage_rows)

    file_hashes: dict[str, str] = {}
    for path in sorted(args.output_dir.glob("*")):
        if path.is_file() and path.name not in {"dataset_manifest.json", "phase5c_summary.json"}:
            file_hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    split_counts = Counter(row["split"] for row in final_rows)
    label_counts = Counter(row["label"] for row in final_rows)
    label_split_counts: dict[str, dict[str, int]] = defaultdict(dict)
    for label in LABEL_MAPPING:
        for split in ["train", "validation", "test"]:
            label_split_counts[label][split] = sum(
                row["label"] == label and row["split"] == split for row in final_rows
            )
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "safe_class_created": False,
        "phase5b_candidates": len(candidates),
        "duplicate_representatives_added": len(duplicate_reps),
        "phase5c_input": len(combined),
        "tokenizer": args.tokenizer,
        "max_length": args.max_length,
        "tc05_pass": len(token_pass),
        "phase5c_duplicates_removed": len(duplicate_removed),
        "dedup_representatives": len(dedup_kept),
        "repositories_audited": len(audits),
        "license_pass_samples": len(license_pass),
        "accept_final": len(final_rows),
        "split_counts": dict(sorted(split_counts.items())),
        "label_counts": dict(sorted(label_counts.items())),
        "label_split_counts": dict(sorted(label_split_counts.items())),
        "leakage": leakage,
        "warnings": [
            "License classification is an automated research-data screening, not legal advice.",
            "Copyleft, custom, missing, or unknown licenses remain in review and are excluded from ACCEPT_FINAL.",
            "code_after is evidence only; no SAFE class is created.",
        ],
    }
    (args.output_dir / "phase5c_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    manifest = {
        "dataset_version": "1.0.0-phase5c",
        "generated_at_utc": summary["generated_at_utc"],
        "random_seed": args.seed,
        "tokenizer": args.tokenizer,
        "max_length": args.max_length,
        "labels": LABEL_MAPPING,
        "split_policy": "repository+advisory+fix-commit connected groups; target 80/10/10",
        "source_candidates": str(args.candidates.resolve()),
        "source_review": str(args.review.resolve()),
        "file_sha256": file_hashes,
    }
    (args.output_dir / "dataset_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print(f"TC05 pass: {len(token_pass)}")
    print(f"Phase 5C duplicates removed: {len(duplicate_removed)}")
    print(f"Repositories audited: {len(audits)}")
    print(f"ACCEPT_FINAL: {len(final_rows)}")
    print(f"Split counts: {dict(sorted(split_counts.items()))}")
    print(f"Leakage checks: {leakage}")
    print("SAFE class created: no")
    print(f"Output: {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
