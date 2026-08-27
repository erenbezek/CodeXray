import ast
from pathlib import Path

from codexray.rule_model import RuleEngine
from codexray.taint_engine import TaintAnalyzer
from rules.sql_injection import SQL_INJECTION_RULE

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _analyze(path: Path):
    tree = ast.parse(path.read_text())
    analyzer = TaintAnalyzer(RuleEngine([SQL_INJECTION_RULE]))
    analyzer.visit(tree)
    return analyzer.findings


def test_vulnerable_example_produces_finding():
    findings = _analyze(EXAMPLES_DIR / "vulnerable" / "sql_injection.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "sql-injection"
    assert findings[0].cwe == "CWE-89"


def test_safe_example_produces_no_finding():
    findings = _analyze(EXAMPLES_DIR / "safe" / "sql_injection.py")
    assert findings == []
