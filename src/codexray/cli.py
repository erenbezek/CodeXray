"""Command-line scanner for CodeXray.

A file that cannot be analyzed -- a syntax error, or a path that cannot be
read at all -- is reported on stderr and skipped; a directory scan continues
and keeps the findings collected so far.  Such files are counted in the
summary but do not change the exit status: the status is 0 when no finding
exists and 1 when at least one finding exists.  Exit status 2 is reserved for
command-line usage errors, including a missing path.

Source is handed to :func:`ast.parse` as bytes so that Python itself applies
the file's coding declaration.  A ``# -*- coding: latin-1 -*-`` file and a
UTF-8 file carrying a BOM are therefore analyzed rather than skipped.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

from .dependency_audit import (
    DependencyAuditError,
    DependencyVulnerability,
    PipAuditUnavailable,
    count_pip_audit_packages,
    parse_pip_audit_json,
    run_pip_audit,
)
from .rule_model import RuleEngine
from .rules import ALL_RULES
from .taint_engine import Finding, TaintAnalyzer


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codexray")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan Python source files")
    scan.add_argument("path", type=Path)
    scan.add_argument("--json", action="store_true", dest="as_json")
    audit = subparsers.add_parser("audit", help="audit Python dependencies")
    audit.add_argument("requirements", type=Path)
    audit.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _files_to_scan(path: Path) -> list[Path] | None:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.rglob("*.py"), key=lambda item: str(item))
    return None


def _scan_file(path: Path) -> tuple[list[Finding], bool]:
    try:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    except SyntaxError as error:
        line = error.lineno if error.lineno is not None else "?"
        print(f"{path}:{line}: syntax error: {error.msg}", file=sys.stderr)
        return [], True
    except (OSError, ValueError) as error:
        # Unreadable path (a directory named `*.py`, a permission error) or a
        # source `ast.parse` rejects outright.  One such file must not take the
        # whole scan -- and the findings already collected -- down with it.
        print(f"{path}: cannot be read: {error}", file=sys.stderr)
        return [], True

    analyzer = TaintAnalyzer(RuleEngine(list(ALL_RULES)), filename=str(path))
    analyzer.visit(tree)
    return analyzer.findings, False


def _finding_schema(finding: Finding) -> dict[str, object]:
    return {
        "file": finding.filename,
        "line": finding.lineno,
        "rule_id": finding.rule_id,
        "cwe": finding.cwe,
        "severity": finding.severity,
        "kind": finding.kind,
        "taint_path": list(finding.path),
    }


def _print_human(
    findings: list[Finding], files_scanned: int, skipped_files: int
) -> None:
    for finding in findings:
        kind = f"  [{finding.kind}]" if finding.kind else ""
        print(
            f"{finding.filename}:{finding.lineno}  "
            f"{finding.severity}  {finding.rule_id}  {finding.cwe}{kind}"
        )
        print(f"    {' -> '.join(finding.path)}")

    if findings:
        summary = f"{len(findings)} bulgu / {files_scanned} dosya tarandı"
    else:
        summary = f"Bulgu yok / {files_scanned} dosya tarandı"
    if skipped_files:
        summary += f" ({skipped_files} dosya atlandı)"
    print(summary)


def _print_json(
    findings: list[Finding], files_scanned: int, skipped_files: int
) -> None:
    payload = {
        "findings": [_finding_schema(finding) for finding in findings],
        "summary": {
            "files_scanned": files_scanned,
            "findings": len(findings),
            "skipped_files": skipped_files,
        },
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _scan(path: Path, as_json: bool) -> int:
    files = _files_to_scan(path)
    if files is None:
        print(f"codexray: path does not exist: {path}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    skipped_files = 0
    for file_path in files:
        file_findings, was_skipped = _scan_file(file_path)
        findings.extend(file_findings)
        skipped_files += int(was_skipped)

    if as_json:
        _print_json(findings, len(files), skipped_files)
    else:
        _print_human(findings, len(files), skipped_files)
    return 1 if findings else 0


def _dependency_schema(
    vulnerability: DependencyVulnerability,
) -> dict[str, object]:
    return {
        "package": vulnerability.package,
        "installed_version": vulnerability.installed_version,
        "vuln_id": vulnerability.vuln_id,
        "aliases": list(vulnerability.aliases),
        "fix_versions": list(vulnerability.fix_versions),
        "description": vulnerability.description,
    }


def _print_dependency_human(
    vulnerabilities: tuple[DependencyVulnerability, ...],
    packages_scanned: int,
) -> None:
    for vulnerability in vulnerabilities:
        fixes = ", ".join(vulnerability.fix_versions) or "-"
        print(
            f"{vulnerability.package} {vulnerability.installed_version}  "
            f"{vulnerability.vuln_id}  -> {fixes}"
        )
        if vulnerability.aliases:
            print(f"    {', '.join(vulnerability.aliases)}")

    if vulnerabilities:
        print(f"{len(vulnerabilities)} zafiyet / {packages_scanned} paket")
    else:
        print(f"Zafiyet yok / {packages_scanned} paket")


def _print_dependency_json(
    vulnerabilities: tuple[DependencyVulnerability, ...],
    packages_scanned: int,
) -> None:
    payload = {
        "vulnerabilities": [
            _dependency_schema(vulnerability) for vulnerability in vulnerabilities
        ],
        "summary": {
            "packages_scanned": packages_scanned,
            "vulnerabilities": len(vulnerabilities),
        },
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _audit(
    requirements: Path,
    as_json: bool,
    runner=None,
) -> int:
    if not requirements.is_file():
        print(
            f"codexray: requirements file does not exist: {requirements}",
            file=sys.stderr,
        )
        return 2

    try:
        output = (runner or run_pip_audit)(requirements)
    except (PipAuditUnavailable, FileNotFoundError, ModuleNotFoundError) as error:
        if isinstance(error, (FileNotFoundError, ModuleNotFoundError)):
            message = (
                "pip-audit kurulu değil. Kurmak için: "
                "python -m pip install pip-audit"
            )
        else:
            message = str(error)
        print(f"codexray audit: {message}", file=sys.stderr)
        return 2
    except DependencyAuditError as error:
        print(f"codexray audit: {error}", file=sys.stderr)
        return 2

    try:
        vulnerabilities = parse_pip_audit_json(output)
        packages_scanned = count_pip_audit_packages(output)
    except ValueError as error:
        print(f"codexray audit: {error}", file=sys.stderr)
        return 2

    if as_json:
        _print_dependency_json(vulnerabilities, packages_scanned)
    else:
        _print_dependency_human(vulnerabilities, packages_scanned)
    return 1 if vulnerabilities else 0


def _force_utf8_output() -> None:
    """Keep a scan from dying on the console's codepage.

    The report text is Turkish, and `tarandı` carries U+0131.  A console or a
    redirected pipe running cp1252 or cp437 cannot encode it, so `print`
    raised UnicodeEncodeError and the process exited 1 -- on clean code, with
    an empty stdout.  A CI gate then went red with no findings and no way to
    tell that apart from a real one.  Measured: cp1254 and utf-8 exit 0,
    cp1252 and cp437 crashed.

    UTF-8 is correct in a redirected file, which is where CI reads it.
    `errors="replace"` is defense only and is not reachable through this
    path -- UTF-8 encodes every character the report can contain, so nothing
    is ever replaced. It is left in so a future stream that cannot be given
    UTF-8 degrades instead of raising. A mutation flipping it to "strict"
    survives the suite, which is expected rather than a coverage gap.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            # A stream that refuses reconfiguration (already detached, or a
            # test double) is left alone rather than taking the run down.
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)

    if args.command == "scan":
        return _scan(args.path, args.as_json)
    if args.command == "audit":
        return _audit(args.requirements, args.as_json)
    return 2
