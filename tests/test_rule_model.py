import ast

from codexray.rule_model import (
    CallTarget,
    Rule,
    RuleEngine,
    SanitizerPattern,
    SinkPattern,
    SourcePattern,
)
from codexray.rules.sources import FLASK_REQUEST_INPUT
from codexray.rules.sql_injection import SQL_INJECTION_RULE
from codexray.rules.xss import XSS_RULE


def _dummy_rule() -> Rule:
    return Rule(
        id="dummy",
        cwe="CWE-000",
        severity="LOW",
        sources=(
            SourcePattern(
                id="src", kind="user-input", targets=(CallTarget("request.args"),)
            ),
        ),
        sanitizers=(
            SanitizerPattern(
                id="san", sanitizes_for=("dummy",), targets=(CallTarget("clean"),)
            ),
        ),
        sinks=(
            SinkPattern(
                id="sink",
                targets=(CallTarget("danger.run"),),
                dangerous_arguments=(0,),
                requires_sanitization_for=("dummy",),
            ),
        ),
    )


def _node(expr: str) -> ast.AST:
    return ast.parse(expr, mode="eval").body


def test_classify_matches_source():
    engine = RuleEngine([_dummy_rule()])
    matches = engine.classify(_node("request.args"))
    assert any(m.role == "source" for m in matches)


def test_classify_matches_sink_via_suffix():
    # "self.danger.run" da hedef "danger.run" ile eşleşmeli (suffix matching)
    engine = RuleEngine([_dummy_rule()])
    matches = engine.classify(_node("self.danger.run(x)"))
    assert any(m.role == "sink" for m in matches)


def test_classify_no_match_for_unrelated_call():
    engine = RuleEngine([_dummy_rule()])
    matches = engine.classify(_node("print(x)"))
    assert matches == []


def test_flask_request_source_is_shared_by_sql_and_xss():
    assert SQL_INJECTION_RULE.sources[0] is FLASK_REQUEST_INPUT
    assert XSS_RULE.sources[0] is FLASK_REQUEST_INPUT
    assert len(FLASK_REQUEST_INPUT.targets) == 9
    assert FLASK_REQUEST_INPUT.id == "flask-request-input"
    assert FLASK_REQUEST_INPUT.kind == "user-input"
