#!/usr/bin/env python3
"""Report basic prerequisites, without treating passing counts as model quality."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from workspace_paths import legacy_data, snapshot_paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path)
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    active = root / "active/six-groups-v2"
    baseline = legacy_data(root) / "python-advisories/phase-5c"
    snapshot = root / "archive/phase5c-v1/snapshot_manifest.json"
    if not snapshot.is_file() or not (baseline / "accepted_final_samples.csv").is_file():
        report = {
            "status": "HOLD_LOCAL_BASELINE_NOT_AVAILABLE",
            "reasons": ["Historical baseline/snapshot is local-only and not included in the public repository",
                        "Restore reviewed baseline and evidence before using this baseline-dependent audit"],
            "baseline_files_unchanged": None,
            "snapshot_integrity_verified": None,
            "training_started": False,
        }
        output = active / "reports/training_readiness.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 2
    saved = json.loads(snapshot.read_text(encoding="utf-8"))
    integrity = []
    for item in saved["files"]:
        current, copied = snapshot_paths(root, item)
        integrity.append({"source": str(current), "unchanged":
                          hashlib.sha256(current.read_bytes()).hexdigest() == item["sha256"],
                          "snapshot_verified": hashlib.sha256(copied.read_bytes()).hexdigest() == item["sha256"]})
    with (baseline / "accepted_final_samples.csv").open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    labels = json.loads((baseline / "label_mapping.json").read_text(encoding="utf-8"))
    baseline_counts = {label: {split: sum(row["label"] == label and row["split"] == split for row in rows)
                               for split in ("train", "validation", "test")} for label in labels}
    counts = baseline_counts
    holds = []
    candidate_dir = args.dataset_dir or active / "dataset"
    dataset_files = {split: candidate_dir / f"{split}.jsonl" for split in ("train", "validation", "test")}
    if not all(path.is_file() for path in dataset_files.values()):
        holds.append("No complete newly approved six-group train/validation/test dataset has been produced")
        if baseline_counts["HARDCODED_CREDENTIALS"]["validation"] == 0:
            holds.append("Sixth group has no validation examples in the original split")
        holds.append("Original samples are vulnerability classes only; clean/all-zero controls are not established")
    else:
        counts = {label: {split: 0 for split in dataset_files} for label in labels}
        controls = {split: 0 for split in dataset_files}
        identifiers = {split: {kind: set() for kind in ("repository", "fix_commit", "advisory", "code")}
                       for split in dataset_files}
        malformed = 0
        unreviewed = 0
        for split, path in dataset_files.items():
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                target = record.get("label_vector")
                code = record.get("code")
                if not isinstance(target, list) or len(target) != 6 or any(value not in (0, 1) for value in target) or not isinstance(code, str) or not code.strip():
                    malformed += 1
                    continue
                if record.get("training_approved") is not True:
                    unreviewed += 1
                for label, index in labels.items():
                    counts[label][split] += int(target[index])
                if not any(target) and record.get("verified_control") is True:
                    controls[split] += 1
                repo = record.get("repository", "").lower()
                commit = record.get("fix_commit", "")
                advisory = record.get("advisory_ids", [])
                if isinstance(advisory, str):
                    advisory = advisory.split(";")
                if not repo or not commit or not advisory:
                    malformed += 1
                if repo:
                    identifiers[split]["repository"].add(repo)
                if commit:
                    identifiers[split]["fix_commit"].add(repo + ":" + commit)
                identifiers[split]["advisory"].update(advisory)
                identifiers[split]["code"].add(hashlib.sha256(code.encode("utf-8")).hexdigest())
        if malformed:
            holds.append(f"Malformed labels, code or missing provenance: {malformed} records")
        if unreviewed:
            holds.append(f"Records without explicit training approval: {unreviewed}")
        for label in labels:
            for split in dataset_files:
                if counts[label][split] == 0:
                    holds.append(f"No positive sample for {label} in {split}")
        for split, count in controls.items():
            if not count:
                holds.append(f"No verified all-zero controls in {split}")
        splits = list(dataset_files)
        for index, split in enumerate(splits):
            for other in splits[index + 1:]:
                for kind in identifiers[split]:
                    overlap = identifiers[split][kind] & identifiers[other][kind]
                    if overlap:
                        holds.append(f"Cross-split {kind} overlap {split}/{other}: {len(overlap)}")
        protected = {kind: set() for kind in identifiers["train"]}
        for old in rows:
            if old["split"] != "test":
                continue
            repo = old["repository"].lower()
            protected["repository"].add(repo)
            protected["fix_commit"].add(repo + ":" + old["fix_commit"])
            protected["advisory"].update(value for value in old["advisory_ids"].split(";") if value)
            protected["code"].add(hashlib.sha256(old["code"].encode("utf-8")).hexdigest())
        for kind in protected:
            overlap = protected[kind] & identifiers["train"][kind]
            if overlap:
                holds.append(f"Old held-out test cases moved into new training ({kind}): {len(overlap)}")
        if not (candidate_dir / "dataset_manifest.json").is_file():
            holds.append("New dataset version/provenance manifest is missing")
    checkpoint = args.checkpoint
    if checkpoint is None or not checkpoint.is_dir():
        holds.append("Existing model checkpoint directory is not supplied or does not exist")
    else:
        mapping_file = checkpoint / "label_mapping.json"
        if not mapping_file.is_file():
            holds.append("Checkpoint label_mapping.json is missing; old outputs cannot be safely mapped")
        else:
            mapping = json.loads(mapping_file.read_text(encoding="utf-8"))
            valid_sets = (set(labels), set(labels) - {"HARDCODED_CREDENTIALS"})
            if set(mapping) not in valid_sets or set(mapping.values()) != set(range(len(mapping))):
                holds.append("Checkpoint label mapping is incompatible with the five/six target groups")
        if not any((checkpoint / name).is_file() for name in ("model.safetensors", "pytorch_model.bin", "model.safetensors.index.json", "pytorch_model.bin.index.json")):
            holds.append("No supported saved model weights were found in checkpoint directory")
    if not all(item["unchanged"] and item["snapshot_verified"] for item in integrity):
        holds.append("Original/snapshot integrity changed; audit before training")
    report = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
              "status": "HOLD_DO_NOT_START_DEPLOYMENT_TRAINING" if holds else "BASIC_PREREQUISITES_PASS_NOT_A_QUALITY_CLAIM",
              "reasons": holds,
              "baseline_label_split_counts": baseline_counts,
              "candidate_label_split_counts": counts,
              "baseline_files_unchanged": all(item["unchanged"] for item in integrity),
              "snapshot_integrity_verified": all(item["snapshot_verified"] for item in integrity),
              "verified_snapshot_file_count": len(integrity), "integrity_details": integrity,
              "training_started": False,
              "note": "No statistical adequacy claim is made from class counts alone"}
    output = active / "reports/training_readiness.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("status", "baseline_files_unchanged",
                                                 "snapshot_integrity_verified", "verified_snapshot_file_count",
                                                 "training_started")}, indent=2))
    return 2 if holds else 0


if __name__ == "__main__":
    raise SystemExit(main())
