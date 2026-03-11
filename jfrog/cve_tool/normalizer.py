from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .xray_client import XrayClient


@dataclass
class ImpactedArtifact:
    repo: str
    path: str
    package_type: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    component_id: Optional[str] = None


@dataclass
class ImpactedBuild:
    name: str
    number: str
    project: Optional[str] = None


@dataclass
class ImpactedRepo:
    key: str
    type: Optional[str] = None
    project: Optional[str] = None


def _extract_impacted_artifacts(report_json: Dict[str, Any]) -> List[ImpactedArtifact]:
    artifacts: List[ImpactedArtifact] = []

    # The exact schema depends on Xray version; we look for common shapes.
    items = report_json.get("data") or report_json.get("artifacts") or []
    for item in items:
        repo = item.get("repo") or item.get("repo_key") or ""
        path = item.get("path") or item.get("name") or ""
        if not repo and not path:
            continue

        artifacts.append(
            ImpactedArtifact(
                repo=repo,
                path=path,
                package_type=item.get("pkg_type") or item.get("package_type"),
                name=item.get("name"),
                version=item.get("version"),
                component_id=item.get("component_id"),
            )
        )

    return artifacts


def _extract_impacted_builds(report_json: Dict[str, Any]) -> List[ImpactedBuild]:
    builds: List[ImpactedBuild] = []

    builds_section = report_json.get("builds") or []
    for item in builds_section:
        name = item.get("name") or ""
        number = str(item.get("number") or "")
        if not name:
            continue

        builds.append(
            ImpactedBuild(
                name=name,
                number=number,
                project=item.get("project") or item.get("project_key"),
            )
        )

    return builds


def _extract_impacted_repos(report_json: Dict[str, Any]) -> List[ImpactedRepo]:
    repos: List[ImpactedRepo] = []

    repos_section = report_json.get("repos") or report_json.get("repositories") or []
    for item in repos_section:
        key = item.get("key") or item.get("repo_key") or ""
        if not key:
            continue

        repos.append(
            ImpactedRepo(
                key=key,
                type=item.get("type"),
                project=item.get("project") or item.get("project_key"),
            )
        )

    return repos


def normalize_cve_report(
    cve_id: str,
    report_json: Dict[str, Any],
    client: XrayClient,
    include_violations: bool = False,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Turn the raw report + optional enrichment into a normalized structure.
    """
    artifacts = _extract_impacted_artifacts(report_json)
    builds = _extract_impacted_builds(report_json)
    repos = _extract_impacted_repos(report_json)

    components_by_cve: Dict[str, Any] = {}
    violations_by_cve: Dict[str, Any] = {}

    try:
        if verbose:
            print("Fetching component details via searchByCves ...")
        components_by_cve = client.search_components_by_cves([cve_id])
    except Exception:
        # Enrichment is best-effort; failures shouldn't break the core flow.
        if verbose:
            print("Warning: failed to enrich with searchByCves; continuing without it.")

    if include_violations:
        try:
            if verbose:
                print("Fetching violations for CVE ...")
            violations_by_cve = client.get_violations_for_cves([cve_id])
        except Exception:
            if verbose:
                print("Warning: failed to fetch violations; continuing without them.")

    normalized = {
        "cve": cve_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": [asdict(a) for a in artifacts],
        "builds": [asdict(b) for b in builds],
        "repos": [asdict(r) for r in repos],
        "components_raw": components_by_cve,
        "violations_raw": violations_by_cve,
        "report_raw": report_json,
    }

    return normalized

