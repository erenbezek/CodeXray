"""Orchestration and parsing for the external ``pip-audit`` tool."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DependencyVulnerability:
    package: str
    installed_version: str
    vuln_id: str
    aliases: tuple[str, ...]
    fix_versions: tuple[str, ...]
    description: str


class PipAuditUnavailable(RuntimeError):
    """Raised when the external pip-audit module cannot be started."""


class DependencyAuditError(RuntimeError):
    """Raised when pip-audit fails for a reason other than findings."""


def _load_report(json_text: str) -> dict[str, Any]:
    try:
        report = json.loads(json_text)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid pip-audit JSON: {error.msg}") from error

    if not isinstance(report, dict) or not isinstance(
        report.get("dependencies"), list
    ):
        raise ValueError("invalid pip-audit JSON: dependencies must be a list")
    return report


def parse_pip_audit_json(
    json_text: str,
) -> tuple[DependencyVulnerability, ...]:
    """Parse pip-audit JSON without starting a process or using the network."""
    report = _load_report(json_text)
    vulnerabilities: list[DependencyVulnerability] = []

    for dependency in report["dependencies"]:
        if not isinstance(dependency, dict):
            raise ValueError("invalid pip-audit JSON: dependency must be an object")
        package = dependency.get("name")
        installed_version = dependency.get("version")
        raw_vulnerabilities = dependency.get("vulns", [])
        if not isinstance(package, str) or not isinstance(installed_version, str):
            raise ValueError(
                "invalid pip-audit JSON: dependency name and version are required"
            )
        if not isinstance(raw_vulnerabilities, list):
            raise ValueError("invalid pip-audit JSON: vulns must be a list")

        for vulnerability in raw_vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError(
                    "invalid pip-audit JSON: vulnerability must be an object"
                )
            vuln_id = vulnerability.get("id")
            if not isinstance(vuln_id, str):
                raise ValueError("invalid pip-audit JSON: vulnerability id is required")
            aliases = vulnerability.get("aliases", [])
            fix_versions = vulnerability.get("fix_versions", [])
            if not isinstance(aliases, list) or not isinstance(fix_versions, list):
                raise ValueError(
                    "invalid pip-audit JSON: aliases and fix_versions must be lists"
                )
            vulnerabilities.append(
                DependencyVulnerability(
                    package=package,
                    installed_version=installed_version,
                    vuln_id=vuln_id,
                    aliases=tuple(str(alias) for alias in aliases),
                    fix_versions=tuple(str(version) for version in fix_versions),
                    description=str(vulnerability.get("description", "")),
                )
            )

    return tuple(vulnerabilities)


def count_pip_audit_packages(json_text: str) -> int:
    """Return the number of dependency entries, including clean packages."""
    return len(_load_report(json_text)["dependencies"])


def run_pip_audit(requirements_path: Path) -> str:
    """Run pip-audit and return its JSON stdout.

    ``pip-audit`` returns 1 when vulnerabilities are found, so both 0 and 1
    are successful process outcomes for this orchestration boundary.
    """
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(requirements_path),
        "--no-deps",
        "-f",
        "json",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, ModuleNotFoundError) as error:
        raise PipAuditUnavailable(
            "pip-audit kurulu değil. Kurmak için: python -m pip install pip-audit"
        ) from error

    stderr = completed.stderr.strip()
    if "No module named pip_audit" in stderr:
        raise PipAuditUnavailable(
            "pip-audit kurulu değil. Kurmak için: python -m pip install pip-audit"
        )
    if completed.returncode not in (0, 1):
        raise DependencyAuditError(stderr or "pip-audit başarısız oldu")
    return completed.stdout
