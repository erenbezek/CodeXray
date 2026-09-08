"""Command-line scanner for CodeXray.

Syntax errors are reported per file and do not abort a directory scan.  They
are counted in the summary, but do not change the exit status: the status is
0 when no finding exists and 1 when at least one finding exists.  Exit status
2 is reserved for command-line usage errors, including a missing path.
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
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as error:
        line = error.lineno if error.lineno is not None else "?"
        print(f"{path}:{line}: syntax error: {error.msg}", file=sys.stderr)
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
        "message": finding.message,
        "taint_path": list(finding.path),
    }


def _print_human(
    findings: list[Finding], files_scanned: int, parse_errors: int
) -> None:
    for finding in findings:
        print(
            f"{finding.filename}:{finding.lineno}  "
            f"{finding.severity}  {finding.rule_id}  {finding.cwe}"
        )
        print(f"    {' -> '.join(finding.path)}")
        print(f"    {finding.message}")

    if findings:
        summary = f"{len(findings)} bulgu / {files_scanned} dosya tarandı"
    else:
        summary = f"Bulgu yok / {files_scanned} dosya tarandı"
    if parse_errors:
        summary += f" ({parse_errors} parse hatası)"
    print(summary)


def _print_json(
    findings: list[Finding], files_scanned: int, parse_errors: int
) -> None:
    payload = {
        "findings": [_finding_schema(finding) for finding in findings],
        "summary": {
            "files_scanned": files_scanned,
            "findings": len(findings),
            "parse_errors": parse_errors,
        },
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _scan(path: Path, as_json: bool) -> int:
    files = _files_to_scan(path)
    if files is None:
        print(f"codexray: path does not exist: {path}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    parse_errors = 0
    for file_path in files:
        file_findings, had_syntax_error = _scan_file(file_path)
        findings.extend(file_findings)
        parse_errors += int(had_syntax_error)

    if as_json:
        _print_json(findings, len(files), parse_errors)
    else:
        _print_human(findings, len(files), parse_errors)
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
