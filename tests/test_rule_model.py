import ast

from codexray.rule_model import (
    CallTarget,
    Rule,
    RuleEngine,
    SanitizerPattern,
    SinkPattern,
    SourcePattern,
)


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
