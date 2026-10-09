from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import shutil
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable


USER_AGENT = "PyVul-CWE-Taxonomy/1.0 (+research dataset builder)"
DECISIONS = {"SELECT", "REVIEW", "EXCLUDE"}


def normalize_cwe_id(value: str | int) -> str:
    text = str(value).strip().upper()
    if text.startswith("CWE-"):
        text = text[4:]
    if not text.isdigit():
        raise ValueError(f"Invalid CWE ID: {value!r}")
    return f"CWE-{int(text)}"


def numeric_id(value: str) -> str:
    return normalize_cwe_id(value).split("-", 1)[1]


def clean_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return re.sub(r"\s+", " ", " ".join(element.itertext())).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, destination: Path, refresh: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not refresh:
        return
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    temporary = destination.with_suffix(destination.suffix + ".part")
    with urllib.request.urlopen(request, timeout=90) as response, temporary.open("wb") as output:
        shutil.copyfileobj(response, output)
    temporary.replace(destination)


def read_catalog(zip_path: Path) -> tuple[ET.Element, dict[str, str]]:
    with zipfile.ZipFile(zip_path) as archive:
        xml_names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
        if len(xml_names) != 1:
            raise ValueError(f"Expected one XML file in {zip_path}; found {xml_names}")
        root = ET.fromstring(archive.read(xml_names[0]))
    metadata = {
        "catalog_name": root.attrib.get("Name", ""),
        "catalog_version": root.attrib.get("Version", ""),
        "catalog_date": root.attrib.get("Date", ""),
        "catalog_sha256": sha256_file(zip_path),
    }
    return root, metadata


def namespace_for(root: ET.Element) -> dict[str, str]:
    if "}" not in root.tag:
        raise ValueError("MITRE XML namespace not found")
    return {"c": root.tag.split("}", 1)[0].lstrip("{")}


def parse_weaknesses(
    root: ET.Element, view_id: str
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, str]]]]:
    ns = namespace_for(root)
    weaknesses: dict[str, dict[str, Any]] = {}
    children: dict[str, list[dict[str, str]]] = defaultdict(list)

    for weakness in root.findall(".//c:Weakness", ns):
        cwe_id = normalize_cwe_id(weakness.attrib["ID"])
        usage = clean_text(weakness.find("./c:Mapping_Notes/c:Usage", ns))
        applicable = weakness.find("./c:Applicable_Platforms", ns)
        platforms: list[str] = []
        if applicable is not None:
            for item in applicable:
                tag = item.tag.split("}")[-1]
                value = item.attrib.get("Name") or item.attrib.get("Class") or ""
                if value:
                    platforms.append(f"{tag}:{value}")

        relationships: list[dict[str, str]] = []
        related = weakness.find("./c:Related_Weaknesses", ns)
        if related is not None:
            for relation in related:
                if relation.attrib.get("View_ID") != view_id:
                    continue
                item = {
                    "nature": relation.attrib.get("Nature", ""),
                    "target_cwe": normalize_cwe_id(relation.attrib.get("CWE_ID", "")),
                    "ordinal": relation.attrib.get("Ordinal", ""),
                }
                relationships.append(item)
                if item["nature"] == "ChildOf":
                    children[item["target_cwe"]].append(
                        {
                            "child_cwe": cwe_id,
                            "ordinal": item["ordinal"],
                        }
                    )

        weaknesses[cwe_id] = {
            "cwe_id": cwe_id,
            "name": weakness.attrib.get("Name", ""),
            "abstraction": weakness.attrib.get("Abstraction", ""),
            "structure": weakness.attrib.get("Structure", ""),
            "status": weakness.attrib.get("Status", ""),
            "description": clean_text(weakness.find("./c:Description", ns)),
            "extended_description": clean_text(
                weakness.find("./c:Extended_Description", ns)
            ),
            "mapping_usage": usage,
            "mapping_rationale": clean_text(
                weakness.find("./c:Mapping_Notes/c:Rationale", ns)
            ),
            "mapping_comments": clean_text(
                weakness.find("./c:Mapping_Notes/c:Comments", ns)
            ),
            "applicable_platforms": "; ".join(platforms),
            "relationships": relationships,
        }

    for parent in children:
        children[parent].sort(key=lambda item: int(numeric_id(item["child_cwe"])))
    return weaknesses, children


def descendants(
    root_cwe: str,
    children: dict[str, list[dict[str, str]]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {
        root_cwe: {
            "parent_cwe": "",
            "depth": 0,
            "path_from_root": root_cwe,
            "relation": "Root",
            "ordinal": "",
        }
    }
    queue: deque[str] = deque([root_cwe])
    while queue:
        parent = queue.popleft()
        parent_info = result[parent]
        for relation in children.get(parent, []):
            child = relation["child_cwe"]
            candidate = {
                "parent_cwe": parent,
                "depth": int(parent_info["depth"]) + 1,
                "path_from_root": f"{parent_info['path_from_root']} > {child}",
                "relation": "ChildOf",
                "ordinal": relation.get("ordinal", ""),
            }
            if child in result and int(result[child]["depth"]) <= int(candidate["depth"]):
                continue
            result[child] = candidate
            queue.append(child)
    return result


def under_excluded_subtree(cwe_id: str, path_from_root: str, excluded: set[str]) -> str:
    path_ids = {part.strip() for part in path_from_root.split(">")}
    matches = sorted(path_ids & excluded, key=lambda value: int(numeric_id(value)))
    return matches[0] if matches else ""


def decide(
    cwe_id: str,
    node: dict[str, Any],
    family: dict[str, Any],
) -> tuple[str, str]:
    root_cwe = normalize_cwe_id(family["root_cwe"])
    include_ids = {normalize_cwe_id(value) for value in family.get("include_ids", [])}
    review_ids = {normalize_cwe_id(value) for value in family.get("review_ids", [])}
    exclude_ids = {normalize_cwe_id(value) for value in family.get("exclude_ids", [])}
    exclude_subtrees = {
        normalize_cwe_id(value) for value in family.get("exclude_subtrees", [])
    }
    notes = {
        normalize_cwe_id(key): value
        for key, value in family.get("decision_notes", {}).items()
    }

    excluded_root = under_excluded_subtree(
        cwe_id, str(node.get("path_from_root") or cwe_id), exclude_subtrees
    )
    if cwe_id in exclude_ids:
        return "EXCLUDE", notes.get(cwe_id, "Explicitly excluded by family policy")
    if excluded_root:
        return "EXCLUDE", notes.get(
            excluded_root, f"Excluded subtree rooted at {excluded_root}"
        )
    if cwe_id in review_ids:
        return "REVIEW", notes.get(cwe_id, "Explicit semantic review required")
    if cwe_id in include_ids:
        return "SELECT", notes.get(cwe_id, "Explicitly selected by family policy")
    if cwe_id == root_cwe:
        decision = str(family.get("root_decision", "REVIEW")).upper()
        if decision not in DECISIONS:
            raise ValueError(f"Invalid root_decision {decision!r} for {root_cwe}")
        return decision, notes.get(cwe_id, f"Configured root decision: {decision}")
    if node.get("relation") == "ConfiguredRelated":
        return "REVIEW", str(node.get("related_note") or "Related, not a descendant")
    if family.get("auto_select_descendants"):
        return "SELECT", "Exact descendant of the configured CWE family root"
    return "REVIEW", "Descendant found automatically; semantic family review required"


def pending_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}.pending{path.suffix}")


def write_bytes_if_changed(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.exists() and path.read_bytes() == payload:
            return
        path.write_bytes(payload)
    except PermissionError as error:
        fallback = pending_path(path)
        fallback.write_bytes(payload)
        raise PermissionError(
            f"Cannot update '{path}' because it is open in Excel/WPS or another "
            f"application. Close that file and run the command again. The new "
            f"content was saved to '{fallback}'."
        ) from error


def write_text_if_changed(path: Path, text: str, encoding: str = "utf-8") -> None:
    write_bytes_if_changed(path, text.encode(encoding))


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    # utf-8-sig keeps Vietnamese text readable when opened directly in Excel/WPS.
    write_bytes_if_changed(path, buffer.getvalue().encode("utf-8-sig"))


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    payload = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    write_text_if_changed(path, payload)


def build_family_rows(
    label: str,
    family: dict[str, Any],
    weaknesses: dict[str, dict[str, Any]],
    children: dict[str, list[dict[str, str]]],
    catalog: dict[str, str],
) -> list[dict[str, Any]]:
    root_cwe = normalize_cwe_id(family["root_cwe"])
    if root_cwe not in weaknesses:
        raise KeyError(f"{root_cwe} not found in MITRE catalog")
    nodes = descendants(root_cwe, children)

    for raw_id, note in family.get("related_candidates", {}).items():
        cwe_id = normalize_cwe_id(raw_id)
        if cwe_id not in weaknesses:
            raise KeyError(f"Configured related candidate {cwe_id} not found")
        nodes.setdefault(
            cwe_id,
            {
                "parent_cwe": "",
                "depth": "",
                "path_from_root": f"{root_cwe} ~ {cwe_id}",
                "relation": "ConfiguredRelated",
                "ordinal": "",
                "related_note": note,
            },
        )

    rows: list[dict[str, Any]] = []
    for cwe_id, node in nodes.items():
        weakness = weaknesses[cwe_id]
        decision, reason = decide(cwe_id, node, family)
        rows.append(
            {
                "model_label": label,
                "family_slug": family["slug"],
                "root_cwe": root_cwe,
                "cwe_id": cwe_id,
                "name": weakness["name"],
                "decision": decision,
                "decision_reason": reason,
                "relation_to_family": node.get("relation", ""),
                "parent_cwe": node.get("parent_cwe", ""),
                "depth": node.get("depth", ""),
                "ordinal": node.get("ordinal", ""),
                "path_from_root": node.get("path_from_root", ""),
                "abstraction": weakness["abstraction"],
                "structure": weakness["structure"],
                "status": weakness["status"],
                "mapping_usage": weakness["mapping_usage"],
                "description": weakness["description"],
                "mapping_rationale": weakness["mapping_rationale"],
                "mapping_comments": weakness["mapping_comments"],
                "applicable_platforms": weakness["applicable_platforms"],
                "python_scope": "REQUIRES_REAL_PYTHON_CODE_EVIDENCE",
                "next_gate": "SEARCH_CVE_GHSA_THEN_APPLY_TC01_TC08",
                "definition_url": f"https://cwe.mitre.org/data/definitions/{numeric_id(cwe_id)}.html",
                **catalog,
            }
        )
    rows.sort(
        key=lambda row: (
            {"SELECT": 0, "REVIEW": 1, "EXCLUDE": 2}[row["decision"]],
            int(numeric_id(row["cwe_id"])),
        )
    )
    return rows


FIELDS = [
    "model_label",
    "family_slug",
    "root_cwe",
    "cwe_id",
    "name",
    "decision",
    "decision_reason",
    "relation_to_family",
    "parent_cwe",
    "depth",
    "ordinal",
    "path_from_root",
    "abstraction",
    "structure",
    "status",
    "mapping_usage",
    "description",
    "mapping_rationale",
    "mapping_comments",
    "applicable_platforms",
    "python_scope",
    "next_gate",
    "definition_url",
    "catalog_name",
    "catalog_version",
    "catalog_date",
    "catalog_sha256",
]


def validate_selected_overlaps(
    rows: list[dict[str, Any]], precedence: list[str]
) -> list[dict[str, Any]]:
    rank = {label: index for index, label in enumerate(precedence)}
    selected_by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["decision"] == "SELECT":
            selected_by_cwe[row["cwe_id"]].append(row)

    conflicts: list[dict[str, Any]] = []
    for cwe_id, items in selected_by_cwe.items():
        labels = sorted({str(item["model_label"]) for item in items})
        if len(labels) < 2:
            continue
        winner = min(labels, key=lambda label: rank.get(label, 999))
        conflicts.append(
            {
                "cwe_id": cwe_id,
                "selected_labels": ";".join(labels),
                "precedence_winner": winner,
                "resolution": "CONFIG_ERROR_REVIEW_REQUIRED",
            }
        )
    return conflicts


def main() -> None:
    script_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Download MITRE CWE View 1000, crawl six CWE families, and filter taxonomy candidates."
    )
    parser.add_argument(
        "--config", type=Path, default=script_root / "config" / "cwe_families.json"
    )
    parser.add_argument("--output-dir", type=Path, default=script_root / "data" / "mitre-cwe")
    parser.add_argument("--refresh", action="store_true", help="Redownload the MITRE catalog")
    parser.add_argument(
        "--catalog-zip",
        type=Path,
        help="Use an existing 1000.xml.zip instead of downloading",
    )
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    cache_path = args.output_dir / "cache" / "research-concepts-1000.xml.zip"
    if args.catalog_zip:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        if args.catalog_zip.resolve() != cache_path.resolve():
            shutil.copy2(args.catalog_zip, cache_path)
    else:
        download(str(config["catalog_url"]), cache_path, args.refresh)

    root, catalog = read_catalog(cache_path)
    weaknesses, children = parse_weaknesses(root, str(config.get("view_id", "1000")))

    all_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for label, family in config["families"].items():
        rows = build_family_rows(label, family, weaknesses, children, catalog)
        all_rows.extend(rows)
        family_dir = args.output_dir / family["slug"]
        write_csv(family_dir / "taxonomy_all.csv", rows, FIELDS)
        write_jsonl(family_dir / "taxonomy_all.jsonl", rows)
        for decision, filename in (
            ("SELECT", "selected_cwes.csv"),
            ("REVIEW", "review_cwes.csv"),
            ("EXCLUDE", "excluded_cwes.csv"),
        ):
            selected = [row for row in rows if row["decision"] == decision]
            write_csv(family_dir / filename, selected, FIELDS)
        summary = {
            "model_label": label,
            "family_slug": family["slug"],
            "root_cwe": normalize_cwe_id(family["root_cwe"]),
            "candidates": len(rows),
            "selected": sum(row["decision"] == "SELECT" for row in rows),
            "review": sum(row["decision"] == "REVIEW" for row in rows),
            "excluded": sum(row["decision"] == "EXCLUDE" for row in rows),
            **catalog,
        }
        summaries.append(summary)
        write_text_if_changed(
            family_dir / "summary.json",
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        )

    combined_dir = args.output_dir / "combined"
    write_csv(combined_dir / "all_candidates.csv", all_rows, FIELDS)
    write_jsonl(combined_dir / "all_candidates.jsonl", all_rows)
    write_csv(
        combined_dir / "selected_cwe_to_model_label.csv",
        [row for row in all_rows if row["decision"] == "SELECT"],
        FIELDS,
    )
    write_csv(
        combined_dir / "review_queue.csv",
        [row for row in all_rows if row["decision"] == "REVIEW"],
        FIELDS,
    )
    write_csv(
        combined_dir / "excluded_cwes.csv",
        [row for row in all_rows if row["decision"] == "EXCLUDE"],
        FIELDS,
    )
    write_csv(
        combined_dir / "family_summary.csv",
        summaries,
        list(summaries[0].keys()),
    )
    conflicts = validate_selected_overlaps(
        all_rows, list(config.get("family_precedence", []))
    )
    write_csv(
        combined_dir / "selected_overlap_conflicts.csv",
        conflicts,
        ["cwe_id", "selected_labels", "precedence_winner", "resolution"],
    )

    manifest = {
        "catalog": catalog,
        "catalog_url": config["catalog_url"],
        "view_id": config.get("view_id", "1000"),
        "family_count": len(summaries),
        "rows": len(all_rows),
        "selected": sum(row["decision"] == "SELECT" for row in all_rows),
        "review": sum(row["decision"] == "REVIEW" for row in all_rows),
        "excluded": sum(row["decision"] == "EXCLUDE" for row in all_rows),
        "selected_overlap_conflicts": len(conflicts),
        "summaries": summaries,
    }
    write_text_if_changed(
        combined_dir / "run_manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
    )

    print(f"MITRE catalog: CWE {catalog['catalog_version']} ({catalog['catalog_date']})")
    for summary in summaries:
        print(
            f"{summary['model_label']}: candidates={summary['candidates']} "
            f"SELECT={summary['selected']} REVIEW={summary['review']} "
            f"EXCLUDE={summary['excluded']}"
        )
    print(f"Selected overlap conflicts: {len(conflicts)}")
    print(f"Output: {args.output_dir}")


if __name__ == "__main__":
    main()
