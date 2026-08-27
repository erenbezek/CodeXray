import ast

from codexray.rule_model import RuleEngine
from codexray.taint_engine import TaintAnalyzer
from rules.sql_injection import SQL_INJECTION_RULE


def _analyze(code: str) -> TaintAnalyzer:
    analyzer = TaintAnalyzer(RuleEngine([SQL_INJECTION_RULE]))
    analyzer.visit(ast.parse(code))
    return analyzer


def test_source_is_tainted():
    a = _analyze("x = request.args['username']\n")
    assert a.env["x"].tainted
    assert a.env["x"].source == "request.args"


def test_multi_hop_assignment_propagation():
    a = _analyze(
        "x = request.args['username']\n"
        "y = x\n"
        "z = y\n"
    )
    assert a.env["z"].tainted
    assert a.env["z"].path == ("request.args", "x", "y", "z")


def test_binop_propagates_taint():
    a = _analyze("x = request.args['username']\nq = 'SELECT ' + x\n")
    assert a.env["q"].tainted


def test_joinedstr_propagates_taint():
    a = _analyze("x = request.args['username']\nq = f'SELECT {x}'\n")
    assert a.env["q"].tainted


def test_constant_is_clean():
    a = _analyze("x = 'sabit-deger'\n")
    assert not a.env["x"].tainted


def test_unknown_variable_reads_as_clean():
    a = _analyze("y = x\n")  # x hiç tanımlanmadı
    assert not a.env["y"].tainted


def test_sanitizer_marks_sanitized_for_without_clearing_taint():
    a = _analyze("x = request.args['username']\nsafe = escape_sql(x)\n")
    state = a.env["safe"]
    assert state.tainted  # geçmiş silinmiyor
    assert "sql" in state.sanitized_for


def test_sink_with_tainted_argument_produces_finding():
    a = _analyze("x = request.args['username']\ncursor.execute(x)\n")
    assert len(a.findings) == 1
    assert a.findings[0].rule_id == "sql-injection"
    assert a.findings[0].path == ("request.args", "x", "cursor.execute")


def test_sink_with_sanitized_argument_produces_no_finding():
    a = _analyze(
        "x = request.args['username']\n"
        "safe = escape_sql(x)\n"
        "cursor.execute(safe)\n"
    )
    assert a.findings == []


def test_sink_with_clean_argument_produces_no_finding():
    a = _analyze("cursor.execute('SELECT 1')\n")
    assert a.findings == []
