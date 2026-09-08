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


def _two_family_engine() -> RuleEngine:
    return RuleEngine(
        [
            _kind_rule("user-input", "request.args"),
            _kind_rule("sensitive", "secret.value"),
        ]
    )


@pytest.mark.parametrize(
    "expression",
    ["user + secret_value", "secret_value + user"],
    ids=("user-first", "secret-first"),
)
def test_merged_value_keeps_every_contributing_kind(expression: str):
    """Order of operands must not decide which family's sinks can fire.

    A single `kind` field made this order-dependent: merge_states took the
    first tainted part's kind, so one family was silently dropped.
    """
    analyzer = TaintAnalyzer(_two_family_engine())
    analyzer.visit(
        ast.parse(
            "user = request.args['q']\n"
            "secret_value = secret.value\n"
            f"merged = {expression}\n"
        )
    )

    assert analyzer.env["merged"].kinds == frozenset({"user-input", "sensitive"})


@pytest.mark.parametrize(
    "expression",
    ["user + secret_value", "secret_value + user"],
    ids=("user-first", "secret-first"),
)
def test_merged_value_reaches_both_families_sinks(expression: str):
    analyzer = TaintAnalyzer(_two_family_engine())
    analyzer.visit(
        ast.parse(
            "user = request.args['q']\n"
            "secret_value = secret.value\n"
            f"merged = {expression}\n"
            "sink(merged)\n"
        )
    )

    assert {finding.rule_id for finding in analyzer.findings} == {
        "user-input-rule",
        "sensitive-rule",
    }


def test_finding_reports_the_kind_that_matched_not_a_primary():
    analyzer = TaintAnalyzer(_two_family_engine())
    analyzer.visit(
        ast.parse(
            "user = request.args['q']\n"
            "secret_value = secret.value\n"
            "merged = user + secret_value\n"
            "sink(merged)\n"
        )
    )

    reported = {finding.rule_id: finding.kind for finding in analyzer.findings}
    assert reported == {
        "user-input-rule": "user-input",
        "sensitive-rule": "sensitive",
    }


def test_kinds_survive_call_model_propagation():
    analyzer = TaintAnalyzer(_two_family_engine())
    analyzer.visit(
        ast.parse(
            "user = request.args['q']\n"
            "secret_value = secret.value\n"
            "merged = user + secret_value\n"
            "carried = merged.upper()\n"
        )
    )

    assert analyzer.env["carried"].kinds == frozenset({"user-input", "sensitive"})


def test_taint_state_has_no_singular_kind_field():
    """A singular `kind` is the footgun this model exists to remove.

    Reintroducing it invites `state.kind == "sensitive"`, which is exactly the
    order-dependent read that dropped findings.
    """
    assert not hasattr(TaintState(tainted=False), "kind")
