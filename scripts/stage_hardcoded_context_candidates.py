#!/usr/bin/env python3
"""Verify source spans of previously curated supplementary pairs in a staging area.

Prior approval in another project is not approval for this six-group dataset.
After-code is kept as evidence; it is not automatically an all-zero target.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
from review_full_function_context import raw_url
from review_hardcoded_context import retrieve


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-project", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    active = root / "active/six-groups-v2"
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base", local_files_only=True)
    records = []
    seen = set()
    for path in sorted((args.source_project / "data/supplement/cwe-798/batches").glob("*/normalized_pairs.jsonl")):
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            pair = json.loads(line)
            if not str(pair.get("curation_status", "")).startswith("APPROVED"):
                continue
            if pair.get("labels") != ["HARDCODED_CREDENTIALS"]:
                continue
            key = (pair["repository"].lower(), pair["commit_id"], pair["file_path"])
            if key in seen:
                continue
            seen.add(key)
            checks = {}
            blobs = {}
            source_pair = dict(pair)
            for side, commit_key in (("before", "parent_commit_id"), ("after", "commit_id")):
                url = raw_url(pair["repository"], pair[commit_key], pair["file_path"])
                blob = retrieve(url)
                blobs[side] = {"url": url, "status": blob["status"], "sha256": blob.get("sha256", "")}
                expected = pair[f"code_{side}"]
                spans = pair.get(f"source_spans_{side}", [])
                if blob["status"] == "FETCHED" and spans:
                    lines = blob["content"].splitlines()
                    extracted = "\n".join(line for span in spans
                                          for line in lines[int(span["start_line"]) - 1:int(span["end_line"])])
                    checks[f"{side}_exact_source_spans"] = extracted.strip() == expected.strip()
                    try:
                        checks[f"{side}_source_ast_equivalent"] = (
                            ast.dump(ast.parse(extracted), include_attributes=False) ==
                            ast.dump(ast.parse(expected), include_attributes=False))
                    except (SyntaxError, ValueError):
                        checks[f"{side}_source_ast_equivalent"] = False
                    # Stage verbatim span concatenation, not the prior formatted text.
                    source_pair[f"code_{side}"] = extracted + "\n"
                    source_pair[f"source_file_sha256_{side}"] = blob["sha256"]
                else:
                    checks[f"{side}_exact_source_spans"] = False
                    checks[f"{side}_source_ast_equivalent"] = False
                try:
                    ast.parse(expected)
                    checks[f"{side}_ast_parse"] = True
                except (SyntaxError, ValueError):
                    checks[f"{side}_ast_parse"] = False
                count = len(tokenizer.encode(expected, add_special_tokens=True, truncation=False))
                checks[f"{side}_token_count"] = count
                checks[f"{side}_within_512_tokens"] = count <= 512
                checks[f"{side}_source_hash_matches_prior"] = (
                    pair.get(f"source_file_sha256_{side}") in (None, "", blob.get("sha256")))
            status = "SOURCE_VERIFIED_REQUIRES_SIX_GROUP_SEMANTIC_REVIEW" if all(
                value for name, value in checks.items()
                if not name.endswith(("token_count", "exact_source_spans"))) else "HOLD_SOURCE_OR_TOKEN_CHECK"
            records.append({"source_pair_file": str(path.resolve()),
                            "source_pair_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "source_pair": pair, "proposed_verbatim_source_pair": source_pair,
                            "source_blobs": blobs, "checks": checks,
                            "staging_status": status, "training_approved": False,
                            "after_is_all_zero_target": False})
    output = active / "review/supplementary_context_pairs.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in records), encoding="utf-8")
    summary = {"staged_pairs": len(records),
               "source_verified_pairs": sum(row["staging_status"].startswith("SOURCE_VERIFIED") for row in records),
               "repositories": sorted({row["source_pair"]["repository"] for row in records}),
               "training_samples_added": 0, "all_zero_controls_added": 0,
               "warning": "Prior source-project approval does not establish six-group labels or clean controls"}
    (active / "reports/supplementary_context_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
