from __future__ import annotations
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from prepare_six_group_workspace import copy_verified, digest
from merge_python_advisory_candidates import normalize_direct
from workspace_paths import legacy_data, legacy_readme, snapshot_paths


class PreparationTests(unittest.TestCase):
    def test_fresh_checkout_without_private_baseline_returns_hold(self):
        with tempfile.TemporaryDirectory(prefix="six-group-checkout-test-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            source_scripts = Path(__file__).resolve().parents[1] / "scripts"
            for name in ("check_six_group_readiness.py", "workspace_paths.py"):
                shutil.copyfile(source_scripts / name, root / "scripts" / name)
            result = subprocess.run(
                [sys.executable, str(root / "scripts/check_six_group_readiness.py")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "HOLD_LOCAL_BASELINE_NOT_AVAILABLE")
            self.assertFalse(report["training_started"])
            self.assertTrue((root / "active/six-groups-v2/reports/training_readiness.json").is_file())

    def test_archived_inputs_and_historical_manifest_paths(self):
        with tempfile.TemporaryDirectory(prefix="six-group-path-test-") as directory:
            root = Path(directory)
            (root / "archive/legacy-data").mkdir(parents=True)
            (root / "archive/legacy-readme.md").touch()
            self.assertEqual(legacy_data(root), root / "archive/legacy-data")
            self.assertEqual(legacy_readme(root), root / "archive/legacy-readme.md")
            for category, filename, expected in (
                ("dataset", "test.jsonl", root / "archive/legacy-data/python-advisories/phase-5c/test.jsonl"),
                ("scripts", "collect_python_advisories.py", root / "scripts/collect_python_advisories.py"),
                ("config", "cwe_families.json", root / "config/cwe_families.json"),
            ):
                item = {"snapshot": f"C:/old/checkout/archive/phase5c-v1/{category}/{filename}"}
                current, copied = snapshot_paths(root, item)
                self.assertEqual(current, expected)
                self.assertEqual(copied, root / "archive/phase5c-v1" / category / filename)
            current, _ = snapshot_paths(root, {"snapshot": "C:/old/archive/phase5c-v1/README.md"})
            self.assertEqual(current, root / "archive/legacy-readme.md")

    def test_snapshot_preserves_source_and_detects_conflicting_copy(self):
        with tempfile.TemporaryDirectory(prefix="six-group-snapshot-test-") as directory:
            base = Path(directory)
            source = base / "source.json"
            source.write_text(json.dumps({"version": 1}), encoding="utf-8")
            target = base / "archive/source.json"
            prior = source.read_bytes()
            entry = copy_verified(source, target)
            self.assertEqual(source.read_bytes(), prior)
            self.assertEqual(digest(target), entry["sha256"])
            self.assertEqual(copy_verified(source, target), entry)
            target.write_text("different", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                copy_verified(source, target)
            self.assertEqual(source.read_bytes(), prior)
            self.assertEqual(target.read_text(encoding="utf-8"), "different")

    def test_advisory_normalization_does_not_approve_training_label(self):
        rows = normalize_direct([{"ghsa_id": "GHSA-test-test-test", "cwe_id": "CWE-798",
                                  "model_label": "HARDCODED_CREDENTIALS",
                                  "commit_urls": "[]"}])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["review_status"], "PENDING_FIX_COMMIT_REVIEW")
        self.assertEqual(rows[0]["resolved_cwe_id"], "")
        self.assertNotIn("training_approved", rows[0])


if __name__ == "__main__":
    unittest.main()
