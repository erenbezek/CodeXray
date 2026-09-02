import ast

import pytest

from codexray.rule_model import RuleEngine
from codexray.taint_engine import TaintAnalyzer
from rules.xss import XSS_RULE


def _analyze(code: str) -> TaintAnalyzer:
    analyzer = TaintAnalyzer(RuleEngine([XSS_RULE]))
    analyzer.visit(ast.parse(code))
    return analyzer


def test_return_expression_detects_nested_response_sink():
    analyzer = _analyze("v = request.args['q']\nreturn Response(v)\n")

    assert analyzer.env["v"].tainted
    assert len(analyzer.findings) == 1


def test_return_value_is_not_a_sink():
    analyzer = _analyze("v = request.args['q']\nreturn v\n")

    assert analyzer.env["v"].tainted
    assert analyzer.findings == []


def test_augassign_propagates_new_taint_to_existing_clean_name():
    analyzer = _analyze("v = request.args['q']\nx = ''\nx += v\n")

    assert analyzer.env["v"].tainted
    assert analyzer.env["x"].tainted


def test_augassign_preserves_existing_taint_with_clean_value():
    analyzer = _analyze("v = request.args['q']\nx = v\nx += 'sabit'\n")

    assert analyzer.env["v"].tainted
    assert analyzer.env["x"].tainted


def test_augassign_preserves_html_sanitization():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "x = ''\n"
        "x += html.escape(v)\n"
        "Response(x)\n"
    )

    assert analyzer.env["x"].tainted
    assert analyzer.env["x"].sanitized_for == ("html-text",)
    assert analyzer.findings == []


def test_annotated_assignment_propagates_taint():
    analyzer = _analyze("v = request.args['q']\nx: str = v\n")

    assert analyzer.env["v"].tainted
    assert analyzer.env["x"].tainted


def test_annotation_without_value_leaves_environment_unchanged():
    analyzer = _analyze("x: str\n")

    assert "x" not in analyzer.env


def test_raise_expression_detects_nested_response_sink():
    analyzer = _analyze("v = request.args['q']\nraise E(Response(v))\n")

    assert analyzer.env["v"].tainted
    assert len(analyzer.findings) == 1


def test_assert_expression_detects_response_sink():
    analyzer = _analyze("v = request.args['q']\nassert Response(v)\n")

    assert analyzer.env["v"].tainted
    assert len(analyzer.findings) == 1


@pytest.mark.parametrize(
    "expression",
    [
        "[Response(v) for i in y]",
        "{Response(v) for i in y}",
        "{i: Response(v) for i in y}",
        "(Response(v) for i in y)",
        "[i for i in [Response(v)]]",
    ],
    ids=("list", "set", "dict", "generator", "generator-iter"),
)
def test_comprehension_expression_slots_detect_response_sink(expression: str):
    analyzer = _analyze(f"v = request.args['q']\n{expression}\n")

    assert analyzer.env["v"].tainted
    assert len(analyzer.findings) == 1


def test_comprehension_container_result_remains_clean():
    analyzer = _analyze("v = request.args['q']\nx = [v for i in y]\n")

    assert analyzer.env["v"].tainted
    assert not analyzer.env["x"].tainted


@pytest.mark.parametrize(
    "statement",
    [
        "if c:\n    Response(v)",
        "for i in y:\n    Response(v)",
        "while c:\n    Response(v)",
        "try:\n    Response(v)\nexcept:\n    pass",
        "with c:\n    Response(v)",
        "def f():\n    Response(v)",
    ],
    ids=("if", "for", "while", "try", "with", "function"),
)
def test_existing_body_statement_traversal_is_preserved(statement: str):
    analyzer = _analyze(f"v = request.args['q']\n{statement}\n")

    assert analyzer.env["v"].tainted
    assert len(analyzer.findings) == 1
