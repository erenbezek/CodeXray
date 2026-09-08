import ast

import pytest

from codexray.rule_model import CallTarget, Rule, RuleEngine, SinkPattern, SourcePattern
from codexray.taint_engine import TaintAnalyzer, TaintState
from codexray.rules.sql_injection import SQL_INJECTION_RULE


def _analyze(code: str) -> TaintAnalyzer:
    analyzer = TaintAnalyzer(RuleEngine([SQL_INJECTION_RULE]))
    analyzer.visit(ast.parse(code))
    return analyzer


def _kind_rule(kind: str, source: str) -> Rule:
    return Rule(
        id=f"{kind}-rule",
        cwe="CWE-000",
        severity="LOW",
        sources=(
            SourcePattern(
                id=f"{kind}-source",
                kind=kind,
                targets=(CallTarget(source),),
            ),
        ),
        sanitizers=(),
        sinks=(
            SinkPattern(
                id="shared-sink",
                targets=(CallTarget("sink"),),
                dangerous_arguments=(0,),
            ),
        ),
    )


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


@pytest.mark.parametrize(
    "source",
    [
        "request.cookies",
        "request.headers",
        "request.data",
        "request.files",
    ],
)
def test_additional_flask_request_sources_are_tainted(source: str):
    analyzer = _analyze(f"value = {source}\n")

    assert analyzer.env["value"].tainted
    assert analyzer.env["value"].source == source


def test_get_json_is_an_additional_source():
    analyzer = _analyze("value = request.get_json()\n")

    assert analyzer.env["value"].tainted
    assert analyzer.env["value"].source == "request.get_json"


def test_sink_kind_isolation_selects_only_the_matching_rule():
    user_rule = _kind_rule("user-input", "request.args")
    sensitive_rule = _kind_rule("sensitive", "secret")
    analyzer = TaintAnalyzer(RuleEngine([user_rule, sensitive_rule]))
    analyzer.visit(ast.parse("value = request.args['q']\nsink(value)\n"))

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].rule_id == "user-input-rule"


def test_sensitive_kind_reaches_its_own_sink():
    analyzer = TaintAnalyzer(
        RuleEngine([_kind_rule("sensitive", "secret.value")])
    )
    analyzer.visit(ast.parse("value = secret.value\nsink(value)\n"))

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].rule_id == "sensitive-rule"


def test_kindless_taint_is_not_filtered():
    analyzer = TaintAnalyzer(RuleEngine([_kind_rule("sensitive", "secret")]))
    analyzer.env["value"] = TaintState(
        tainted=True,
        source="manual",
        path=("manual",),
    )
    analyzer.visit(ast.parse("sink(value)\n"))

    assert len(analyzer.findings) == 1
