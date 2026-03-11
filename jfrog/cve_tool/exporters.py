from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict


def export_json(data: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _write_csv(path: Path, rows: list[dict[str, Any]], field_order: list[str]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=field_order)
        writer.writeheader()
        for row in rows:
            # Only keep known fields; others are ignored.
            writer.writerow({field: row.get(field, "") for field in field_order})


def export_csv_sets(data: Dict[str, Any], base_dir: Path) -> Dict[str, Path]:
    """
    Write artifacts/builds/repos (and optionally violations) CSVs to base_dir.

    Returns a mapping of logical name -> path for convenience.
    """
    paths: Dict[str, Path] = {}

    artifacts = data.get("artifacts") or []
    if artifacts:
        path = base_dir / "artifacts.csv"
        fields = ["repo", "path", "package_type", "name", "version", "component_id"]
        _write_csv(path, artifacts, fields)
        paths["artifacts"] = path

    builds = data.get("builds") or []
    if builds:
        path = base_dir / "builds.csv"
        fields = ["name", "number", "project"]
        _write_csv(path, builds, fields)
        paths["builds"] = path

    repos = data.get("repos") or []
    if repos:
        path = base_dir / "repos.csv"
        fields = ["key", "type", "project"]
        _write_csv(path, repos, fields)
        paths["repos"] = path

    # Optional: flatten violations_raw if present and reasonably shaped.
    violations_raw = data.get("violations_raw")
    if isinstance(violations_raw, dict) and violations_raw.get("violations"):
        rows = []
        for v in violations_raw.get("violations", []):
            rows.append(
                {
                    "violation_id": v.get("id"),
                    "policy": v.get("policy_name") or v.get("policy"),
                    "severity": v.get("severity"),
                    "watch": v.get("watch") or v.get("watch_name"),
                    "components": ",".join(v.get("components", []))
                    if isinstance(v.get("components"), list)
                    else v.get("components", ""),
                }
            )
        path = base_dir / "violations.csv"
        fields = ["violation_id", "policy", "severity", "watch", "components"]
        _write_csv(path, rows, fields)
        paths["violations"] = path

    return paths

