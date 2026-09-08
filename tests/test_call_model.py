import ast

import pytest

from codexray.call_model import CallModel, CallModelRegistry
from codexray.rule_model import (
    CallTarget,
    Rule,
    RuleEngine,
    SanitizerPattern,
    SinkPattern,
    SourcePattern,
)
from codexray.taint_engine import TaintAnalyzer
from codexray.rules.xss import XSS_RULE


def _rule() -> Rule:
    return Rule(
        id="generic-call-model-test",
        cwe="CWE-000",
        severity="LOW",
        sources=(
            SourcePattern(
                id="request-source",
                kind="user-input",
                targets=(CallTarget("request.args"),),
            ),
        ),
        sanitizers=(
            SanitizerPattern(
                id="html-sanitizer",
                sanitizes_for=("html",),
                targets=(CallTarget("sanitize"),),
            ),
        ),
        sinks=(
            SinkPattern(
                id="test-sink",
                targets=(CallTarget("sink"),),
                dangerous_arguments=(0,),
                requires_sanitization_for=("html",),
            ),
        ),
    )


def _analyze(
    code: str, call_model_registry: CallModelRegistry | None = None
) -> TaintAnalyzer:
    analyzer = TaintAnalyzer(
        RuleEngine([_rule()]), call_model_registry=call_model_registry
    )
    analyzer.visit(ast.parse(code))
    return analyzer


def _analyze_xss(code: str) -> TaintAnalyzer:
    analyzer = TaintAnalyzer(RuleEngine([XSS_RULE]))
    analyzer.visit(ast.parse(code))
    return analyzer


def test_modelled_value_preserving_call_propagates_taint_to_sink():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = str(user_input)\n"
        "sink(result)\n"
    )

    assert analyzer.env["result"].tainted
    assert len(analyzer.findings) == 1


def test_json_dumps_is_an_explicit_value_preserving_model():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = json.dumps(user_input)\n"
        "sink(result)\n"
    )

    assert analyzer.env["result"].tainted
    assert len(analyzer.findings) == 1


def test_modelled_call_boundary_is_in_taint_path():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = str(user_input)\n"
        "sink(result)\n"
    )

    assert analyzer.findings[0].path == (
        "request.args",
        "user_input",
        "str",
        "result",
        "sink",
    )


def test_explicit_non_propagating_model_does_not_taint_return_value():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = len(user_input)\n"
        "sink(result)\n",
    )

    assert not analyzer.env["result"].tainted
    assert analyzer.findings == []


@pytest.mark.parametrize(
    ("preserves_sanitization", "expected_finding"),
    [(True, False), (False, True)],
)
def test_sanitization_is_preserved_only_when_model_allows_it(
    preserves_sanitization: bool, expected_finding: bool
):
    registry = CallModelRegistry(
        [
            CallModel(
                target=CallTarget("identity"),
                preserves_sanitization=preserves_sanitization,
            )
        ]
    )
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "safe = sanitize(user_input)\n"
        "result = identity(safe)\n"
        "sink(result)\n",
        call_model_registry=registry,
    )

    assert analyzer.env["safe"].sanitized_for == ("html",)
    assert analyzer.env["result"].tainted
    assert bool(analyzer.findings) is expected_finding
    if not expected_finding:
        assert analyzer.env["result"].sanitized_for == ("html",)
    else:
        assert analyzer.env["result"].sanitized_for == ()


def test_unknown_call_does_not_automatically_propagate_taint():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = unknown_helper(user_input)\n"
        "sink(result)\n"
    )

    assert not analyzer.env["result"].tainted
    assert analyzer.findings == []


def test_registry_matches_qualified_call_target():
    registry = CallModelRegistry([CallModel(target=CallTarget("str"))])
    node = ast.parse("str(value)", mode="eval").body

    assert registry.match(node) is not None
    assert registry.match(node).target_name == "str"


@pytest.mark.parametrize("method", ["upper", "lower", "strip", "getlist"])
def test_receiver_method_models_propagate_taint(method: str):
    analyzer = _analyze(
        "value = request.args['q']\n"
        f"result = value.{method}()\n"
    )

    assert analyzer.env["result"].tainted
    # The path records the qualified call name, not the bare method name, so
    # a report shows which value the method was called on.
    assert f"value.{method}" in analyzer.env["result"].path


def test_receiver_method_chain_propagates_taint():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "result = value.lower().strip()\n"
    )

    assert analyzer.env["result"].tainted
    assert analyzer.env["result"].path[-2:] == ("value.lower.strip", "result")


def test_get_default_argument_is_an_additional_return_input():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "mapping = {}\n"
        "result = mapping.get('q', value)\n"
    )

    assert analyzer.env["result"].tainted


def test_clean_receiver_without_default_stays_clean():
    analyzer = _analyze("mapping = {}\nresult = mapping.get('q')\n")

    assert not analyzer.env["result"].tainted


def test_replace_propagates_replacement_argument():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "template = 'clean'\n"
        "result = template.replace('x', value)\n"
    )

    assert analyzer.env["result"].tainted


@pytest.mark.parametrize("name", ["strip", "upper", "get"])
def test_receiver_model_does_not_apply_to_a_bare_function_call(name: str):
    """Target names match by suffix, so a bare `strip(x)` also matches the
    `strip` model -- but a bare call has no receiver to propagate from, and
    its argument is not an input of that model.  The result stays clean."""
    analyzer = _analyze(
        "value = request.args['q']\n"
        f"result = {name}(value)\n"
    )

    assert not analyzer.env["result"].tainted


def test_literal_receiver_cannot_be_matched():
    """A literal has no qualified name, so no model can match a call on it.

    `resolve_qualified_name` builds a dotted name out of Name/Attribute links;
    a Constant contributes nothing, so `'clean'.replace(...)` resolves to None
    and reaches no model.  Documented in design-decisions.md as a known limit
    of qualified-name matching -- assign the literal to a name and it works,
    as the test above shows.
    """
    analyzer = _analyze(
        "value = request.args['q']\n"
        "result = 'clean'.replace('x', value)\n"
    )

    assert not analyzer.env["result"].tainted


@pytest.mark.parametrize(
    ("expression", "expected_findings"),
    [
        ("os.path.join('/b', value)", 1),
        ("os.path.join(value, 'a', 'b')", 1),
        ("os.path.join('/b', '/c')", 0),
        ("os.path.join('/b', *parts)", 0),
        ("os.path.join(*parts, 'a')", 0),
        ("template.format(value)", 1),
        ("template.format('s', value)", 1),
        ("template.format(n=value)", 1),
        ("template.format('s', n=value)", 1),
        ("template.format(n='s')", 0),
        ("template.format(**{'n': value})", 0),
        ("template.format(**value)", 1),
        ("value.format('s')", 1),
        ("'SELECT {}'.format(value)", 0),
    ],
    ids=(
        "join-clean-first-tainted-second",
        "join-tainted-first",
        "join-all-clean",
        "join-starred-container",
        "join-starred-container-first",
        "format-positional",
        "format-tainted-second",
        "format-keyword",
        "format-positional-and-keyword",
        "format-clean-keyword",
        "format-dict-literal",
        "format-tainted-mapping",
        "format-tainted-receiver",
        "format-literal-receiver",
    ),
)
def test_variadic_models_match_acceptance_cases(
    expression: str, expected_findings: int
):
    analyzer = _analyze(
        "value = request.args['q']\n"
        "parts = [value]\n"
        "template = 'clean'\n"
        f"result = {expression}\n"
        "sink(result)\n"
    )

    assert len(analyzer.findings) == expected_findings


def test_format_resets_sanitization_before_xss_sink():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "safe = sanitize(value)\n"
        "template = 'clean'\n"
        "result = template.format(safe)\n"
        "sink(result)\n"
    )

    assert analyzer.env["safe"].sanitized_for == ("html",)
    assert analyzer.env["result"].sanitized_for == ()
    assert len(analyzer.findings) == 1


def test_os_path_join_preserves_sanitization_for_xss_sink():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "safe = html.escape(value)\n"
        "result = os.path.join('/a', safe)\n"
        "Response(result)\n"
    )

    assert analyzer.env["result"].tainted
    assert analyzer.env["result"].sanitized_for == ("html-text",)
    assert analyzer.findings == []


def test_os_path_join_still_propagates_unsanitized_taint():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "result = os.path.join('/a', value)\n"
        "Response(result)\n"
    )

    assert analyzer.env["result"].tainted
    assert analyzer.findings


@pytest.mark.parametrize(
    ("expression", "expected_tainted"),
    [
        ("Path(value)", True),
        ("Path('/b', value)", True),
        ("Path('sabit')", False),
    ],
)
def test_path_model_propagates_taint_and_sanitization(
    expression: str, expected_tainted: bool
):
    analyzer = _analyze(
        "value = request.args['q']\n"
        f"result = {expression}\n"
        "sink(result)\n"
    )

    assert analyzer.env["result"].tainted is expected_tainted
    if expected_tainted:
        assert len(analyzer.findings) == 1
    else:
        assert analyzer.findings == []


def test_format_tainted_request_json_mapping_reaches_response_sink():
    analyzer = _analyze_xss(
        "template = 'clean'\n"
        "result = template.format(**request.json)\n"
        "Response(result)\n"
    )

    assert len(analyzer.findings) == 1


def test_predicate_method_remains_non_propagating():
    analyzer = _analyze(
        "value = request.args['q']\n"
        "result = value.startswith('x')\n"
    )

    assert not analyzer.env["result"].tainted
