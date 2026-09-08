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

from .rule_model import RuleEngine
from .rules import ALL_RULES
from .taint_engine import Finding, TaintAnalyzer


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codexray")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan Python source files")
    scan.add_argument("path", type=Path)
    scan.add_argument("--json", action="store_true", dest="as_json")
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


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)

    if args.command == "scan":
        return _scan(args.path, args.as_json)
    return 2
