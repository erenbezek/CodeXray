import ast
from pathlib import Path

import pytest

from codexray.rule_model import RuleEngine
from codexray.taint_engine import TaintAnalyzer
from rules.sql_injection import SQL_INJECTION_RULE
from rules.xss import XSS_RULE


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _analyze(code: str) -> TaintAnalyzer:
    analyzer = TaintAnalyzer(RuleEngine([XSS_RULE]))
    analyzer.visit(ast.parse(code))
    return analyzer


@pytest.mark.parametrize("sink", ["Response", "make_response", "Markup"])
def test_tainted_input_reaching_html_response_produces_finding(sink: str):
    analyzer = _analyze(
        "value = request.args['q']\n"
        f"response = {sink}(value)\n"
    )

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].rule_id == "xss"
    assert analyzer.findings[0].cwe == "CWE-79"
    assert analyzer.findings[0].path == ("request.args", "value", sink)


def test_html_escape_prevents_xss_finding():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "safe = html.escape(value)\n"
        "response = Response(safe)\n"
    )

    assert analyzer.findings == []
    assert analyzer.env["safe"].tainted
    assert "html-text" in analyzer.env["safe"].sanitized_for


def test_markupsafe_escape_prevents_xss_finding():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "safe = markupsafe.escape(value)\n"
        "response = make_response(safe)\n"
    )

    assert analyzer.findings == []
    assert "html-text" in analyzer.env["safe"].sanitized_for


def test_markup_escape_prevents_xss_finding():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "safe = Markup.escape(value)\n"
        "response = Markup(safe)\n"
    )

    assert analyzer.findings == []
    assert "html-text" in analyzer.env["safe"].sanitized_for


def test_assignment_and_string_interpolation_propagate_xss_taint():
    analyzer = _analyze(
        "value = request.form['q']\n"
        "alias = value\n"
        "body = '<p>' + alias\n"
        "response = Response(body)\n"
    )

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].path == (
        "request.form",
        "value",
        "alias",
        "body",
        "Response",
    )


def test_f_string_propagates_xss_taint():
    analyzer = _analyze(
        "value = request.values['q']\n"
        "body = f'<p>{value}</p>'\n"
        "response = make_response(body)\n"
    )

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].path == (
        "request.values",
        "value",
        "body",
        "make_response",
    )


@pytest.mark.parametrize("source", ["request.args", "request.form", "request.values", "request.json"])
def test_flask_request_sources_are_tainted(source: str):
    analyzer = _analyze(f"value = {source}['q']\n")

    assert analyzer.env["value"].tainted
    assert analyzer.env["value"].source == source


def test_sql_sanitizer_does_not_sanitize_for_xss():
    analyzer = TaintAnalyzer(RuleEngine([SQL_INJECTION_RULE, XSS_RULE]))
    analyzer.visit(
        ast.parse(
            "value = request.args['q']\n"
            "safe = escape_sql(value)\n"
            "response = Response(safe)\n"
        )
    )

    assert len(analyzer.findings) == 1


def test_vulnerable_example_produces_finding():
    code = (EXAMPLES_DIR / "vulnerable" / "xss.py").read_text()
    assert len(_analyze(code).findings) == 1


def test_safe_example_produces_no_finding():
    code = (EXAMPLES_DIR / "safe" / "xss.py").read_text()
    assert _analyze(code).findings == []


@pytest.mark.parametrize(
    "code",
    [
        "Response(request.args['q']).upper()\n",
        "Response(request.args['q']).unknown_method()\n",
        "result = Response(request.args['q']).upper()\n",
    ],
)
def test_receiver_expression_is_analyzed_once_for_nested_sinks(code: str):
    analyzer = _analyze(code)

    assert len(analyzer.findings) == 1


def test_nested_receiver_chain_does_not_double_report():
    analyzer = _analyze("Response(Response(request.args['q']).upper())\n")

    assert len(analyzer.findings) == 1


def test_receiver_method_output_reaches_xss_sink():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "result = value.upper()\n"
        "Response(result)\n"
    )

    assert len(analyzer.findings) == 1


def test_html_sanitization_is_not_preserved_through_receiver_method():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "safe = html.escape(value)\n"
        "result = safe.upper()\n"
        "Response(result)\n"
    )

    assert len(analyzer.findings) == 1


@pytest.mark.parametrize(
    "expression",
    [
        "request.args.get('q')",
        "request.form.get('q')",
        "request.args.getlist('q')",
    ],
)
def test_request_receiver_methods_propagate_taint(expression: str):
    analyzer = _analyze(f"result = {expression}\n")

    assert analyzer.env["result"].tainted
