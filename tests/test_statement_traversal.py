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


def test_annotated_attribute_assignment_still_analyzes_value():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "obj.attr: str = Response(v)\n"
    )

    assert analyzer.env["v"].tainted
    assert len(analyzer.findings) == 1


def test_augmented_attribute_assignment_still_analyzes_value():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "obj.attr += Response(v)\n"
    )

    assert analyzer.env["v"].tainted
    assert len(analyzer.findings) == 1


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


def test_list_literal_analyzes_nested_sink():
    analyzer = _analyze("v = request.args['q']\nx = [Response(v)]\n")

    assert analyzer.env["x"].tainted is False
    assert len(analyzer.findings) == 1


def test_tuple_literal_analyzes_nested_sink():
    analyzer = _analyze("v = request.args['q']\nx = (Response(v),)\n")

    assert analyzer.env["x"].tainted is False
    assert len(analyzer.findings) == 1


def test_set_literal_analyzes_nested_sink():
    analyzer = _analyze("v = request.args['q']\nx = {Response(v)}\n")

    assert analyzer.env["x"].tainted is False
    assert len(analyzer.findings) == 1


def test_dict_literal_analyzes_nested_value_sink():
    analyzer = _analyze("v = request.args['q']\nx = {'k': Response(v)}\n")

    assert analyzer.env["x"].tainted is False
    assert len(analyzer.findings) == 1


def test_dict_literal_analyzes_nested_key_sink():
    analyzer = _analyze("v = request.args['q']\nx = {Response(v): 'val'}\n")

    assert analyzer.env["x"].tainted is False
    assert len(analyzer.findings) == 1


def test_nested_container_literal_analyzes_nested_sink():
    analyzer = _analyze("v = request.args['q']\nx = [[Response(v)]]\n")

    assert analyzer.env["x"].tainted is False
    assert len(analyzer.findings) == 1


def test_container_literals_remain_clean_even_with_tainted_elements():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "list_value = [v]\n"
        "tuple_value = (v,)\n"
        "dict_value = {'k': v}\n"
    )

    assert analyzer.env["list_value"].tainted is False
    assert analyzer.env["tuple_value"].tainted is False
    assert analyzer.env["dict_value"].tainted is False


def test_starred_argument_analyzes_nested_sink():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "f(*[Response(v)])\n"
    )

    assert len(analyzer.findings) == 1


@pytest.mark.parametrize(
    ("expression", "expected_tainted"),
    [
        ("v or 'default'", True),
        ("'default' or v", True),
        ("v and 'default'", True),
        ("'a' or 'b'", False),
    ],
    ids=("tainted-left-or", "tainted-right-or", "tainted-left-and", "clean"),
)
def test_boolop_merges_all_operand_states(expression: str, expected_tainted: bool):
    analyzer = _analyze(
        "v = request.args['q']\n"
        f"x = {expression}\n"
    )

    assert analyzer.env["x"].tainted is expected_tainted


def test_boolop_result_reaching_sink_produces_finding():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "Response(v or 'default')\n"
    )

    assert len(analyzer.findings) == 1


def test_boolop_analyzes_nested_sink_operand():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "x = Response(v) or y\n"
    )

    assert analyzer.env["x"].tainted is False
    assert len(analyzer.findings) == 1


def test_boolop_mixed_sanitization_is_not_preserved():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "s = html.escape(v) or v\n"
        "Response(s)\n"
    )

    assert analyzer.env["s"].tainted
    assert analyzer.env["s"].sanitized_for == ()
    assert len(analyzer.findings) == 1


def test_boolop_shared_sanitization_is_preserved():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "s = html.escape(v) or html.escape(v)\n"
        "Response(s)\n"
    )

    assert analyzer.env["s"].tainted
    assert analyzer.env["s"].sanitized_for == ("html-text",)
    assert analyzer.findings == []


@pytest.mark.parametrize(
    ("expression", "expected_tainted"),
    [
        ("v if c else 'sabit'", True),
        ("'sabit' if c else v", True),
        ("'a' if c else 'b'", False),
        ("'a' if v else 'b'", False),
    ],
    ids=("tainted-body", "tainted-orelse", "clean-branches", "no-implicit-flow"),
)
def test_ifexp_merges_only_result_branches(
    expression: str, expected_tainted: bool
):
    analyzer = _analyze(
        "v = request.args['q']\n"
        f"x = {expression}\n"
    )

    assert analyzer.env["x"].tainted is expected_tainted


def test_ifexp_analyzes_test_for_nested_sink_without_tainting_result():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "x = 'a' if Response(v) else 'b'\n"
    )

    assert analyzer.env["x"].tainted is False
    assert len(analyzer.findings) == 1


def test_ifexp_result_reaching_sink_produces_finding():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "Response(v if c else 'default')\n"
    )

    assert len(analyzer.findings) == 1


def test_ifexp_mixed_sanitization_is_not_preserved():
    analyzer = _analyze(
        "v = request.args['q']\n"
        "s = html.escape(v) if c else v\n"
        "Response(s)\n"
    )

    assert analyzer.env["s"].tainted
    assert analyzer.env["s"].sanitized_for == ()
    assert len(analyzer.findings) == 1


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
