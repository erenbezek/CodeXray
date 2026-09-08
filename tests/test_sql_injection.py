import ast
from pathlib import Path

import pytest

from codexray.rule_model import RuleEngine
from codexray.taint_engine import TaintAnalyzer
from codexray.rules.sql_injection import SQL_INJECTION_RULE

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _analyze(path: Path):
    tree = ast.parse(path.read_text())
    analyzer = TaintAnalyzer(RuleEngine([SQL_INJECTION_RULE]))
    analyzer.visit(tree)
    return analyzer.findings


def _findings(code: str):
    analyzer = TaintAnalyzer(RuleEngine([SQL_INJECTION_RULE]))
    analyzer.visit(ast.parse(code))
    return analyzer.findings


def test_vulnerable_example_produces_finding():
    findings = _analyze(EXAMPLES_DIR / "vulnerable" / "sql_injection.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "sql-injection"
    assert findings[0].cwe == "CWE-89"


def test_safe_example_produces_no_finding():
    findings = _analyze(EXAMPLES_DIR / "safe" / "sql_injection.py")
    assert findings == []


def test_request_values_now_reaches_sql_sink(tmp_path):
    path = tmp_path / "request_values.py"
    path.write_text("q = request.values['n']\ncursor.execute(q)\n")

    findings = _analyze(path)

    assert len(findings) == 1
    assert findings[0].rule_id == "sql-injection"


@pytest.mark.parametrize(
    "receiver",
    ["cursor", "c", "cur", "db", "conn", "session", "self.cursor"],
)
def test_sql_sink_matches_any_cursor_variable_name(receiver: str):
    """The sink is `.execute`, not `cursor.execute`.

    Measured on a real Flask app: the rule required the receiver variable to
    be literally named `cursor`, so `c.execute(...)` -- what real code writes
    -- matched nothing. Every test and example used `cursor`, which is why it
    went unnoticed from M4 until the engine was first run on real code.
    """
    findings = _findings(
        f"value = request.args['q']\n{receiver}.execute(value)\n"
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "sql-injection"


def test_executemany_is_also_a_sql_sink():
    findings = _findings("value = request.args['q']\ncur.executemany(value)\n")

    assert len(findings) == 1


def test_sanitized_value_is_still_safe_on_any_receiver():
    findings = _findings("value = request.args['q']\nc.execute(escape_sql(value))\n")

    assert findings == []
