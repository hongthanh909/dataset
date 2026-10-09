"""Resolve retained historical inputs after the workspace cleanup."""
from pathlib import Path, PureWindowsPath


def legacy_data(root: Path) -> Path:
    archived = root / "archive/legacy-data"
    return archived if archived.is_dir() else root / "data"


def legacy_readme(root: Path) -> Path:
    archived = root / "archive/legacy-readme.md"
    return archived if archived.is_file() else root / "README.md"


def snapshot_paths(root: Path, item: dict) -> tuple[Path, Path]:
    # Old manifests contain absolute Windows paths. Preserve them as historical
    # records, but resolve the known snapshot layout relative to this checkout.
    parts = PureWindowsPath(item["snapshot"]).parts
    index = parts.index("phase5c-v1")
    relative = Path(*parts[index + 1:])
    copied = root / "archive/phase5c-v1" / relative
    category = relative.parts[0]
    if category == "dataset":
        current = legacy_data(root) / "python-advisories/phase-5c" / relative.name
    elif category in ("config", "scripts"):
        current = root / relative
    elif relative == Path("README.md"):
        current = legacy_readme(root)
    else:
        raise ValueError(f"Unknown snapshot entry: {relative}")
    return current, copied
