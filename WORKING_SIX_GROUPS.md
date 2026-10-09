# Working on the six-group model

Use `active/six-groups-v2/` for the next dataset version. Original collection
scripts remain unchanged; historical data now lives in `archive/legacy-data/`.

## What is retained

- `archive/phase5c-v1/`: hash-verified snapshot of the original dataset,
  configuration and collection scripts. This is not a five-group model checkpoint.
- Existing advisory, patch, source, license and deduplication evidence remains
  in `archive/legacy-data/`; it is needed to reproduce and verify samples.
- No comparison script or model checkpoint was found in this dataset folder.
  Do not delete results held in another project without identifying them first.

## Active workflow

1. Run `python scripts/prepare_six_group_workspace.py` once to create the snapshot
   and active working directories. The script refuses to overwrite a different
   snapshot file.
2. Search only the existing hardcoded-credentials allowlist: CWE-259, CWE-321,
   CWE-798. Save new public advisories to `active/six-groups-v2/discovery/`.
3. Inspect production Python before/after code, the credential literal and its
   real authentication/signing use. Do not label every hunk in a security commit
   as hardcoded credentials. Module bindings and their use may require context
   beyond a single function.
4. Review the fix, provenance, license and tokenized context. Advisory matches
   and automatically detected security words alone are not verified labels.
5. Create a versioned dataset only after review. Deduplicate against all old
   splits and keep existing test data out of training. Related repository,
   advisory and fix-commit cases must not cross splits.
6. Validate six-group coverage. Existing hardcoded-credentials coverage is four
   training samples, zero validation samples and one test sample from two repos.
   This is not sufficient evidence of reliable six-group detection.
7. Supply the existing five-group checkpoint and label mapping. If it has five
   outputs, expand the head while preserving the encoder and correctly mapped
   old outputs. Fine-tune on old and new TRAIN data, not only the new class.
8. Choose thresholds on validation and evaluate all groups on held-out test.
   Do not train a deployment-ready vulnerability detector without reviewed
   negative/control examples. Fixed code is evidence, not automatically SAFE.

Training remains on HOLD until the prerequisites above are resolved. Reports
must distinguish the completed five-group comparison from the new six-group
model; the previous comparison cannot establish performance of the sixth group.

## Progress on 2026-10-09

- Snapshot: 33 original files copied and SHA-256 verified. No original file was
  deleted, moved or rewritten.
- GitHub refresh: 21 reviewed PyPI advisories, 23 advisory/CWE rows. They were
  already in the original discovery queue; they are not 21 new training cases.
- Patch checks: 14 commit references, 13 change Python. 11 commits have
  confirmed/provisional evidence for further inspection; this is not label approval.
- Extracted 320 hunks. Full-context review returned 2 automatic passes, 30
  review cases and 288 rejections. Automatic passes are still candidates.
- Bounded source retrieval obtained 94 of 95 requested source blobs. One
  incomplete retrieval remains visible in the reports.
- Three supplementary context pairs from the other local PyVul project were
  staged in `active/six-groups-v2/review/supplementary_context_pairs.jsonl`.
  The source spans, AST equivalence and token lengths were checked for Django,
  PraisonAI and Crawl4AI. Verbatim span concatenations are retained separately
  from the old formatted pair text. No record was added to the final dataset.
- `scripts/check_six_group_readiness.py` checks the new JSONL splits, explicit
  six-label targets and review approval, clean controls, cross-split overlap,
  old-test protection, snapshot integrity and checkpoint mapping. Exit status
  2 means HOLD, not a training job. Passing only establishes basic prerequisites,
  not statistical adequacy or deployment safety.
- Training has not started. Current blockers are the pending source/label
  review, missing sixth-group validation/control coverage and missing model
  checkpoint directory. A CPU-only PyTorch/Transformers environment is present
  at `D:/PyVul-main/PyVul-main/.venv/Scripts/python.exe`.

## Workspace cleanup on 2026-10-09

- Moved all 6,913 historical data files from `data/` into `archive/legacy-data/`.
- Moved the 10 old root PowerShell runners into `archive/legacy-runners/`.
- Preserved the original README at `archive/legacy-readme.md`; the root README
  now explains the active workspace.
- Updated the active helper input paths and portable snapshot path resolution.
- No permanent deletion, dataset approval, label change, or training occurred.
- Archived runners contain historical paths; do not run them unchanged.
