"""Shared call-argument binding: the binder itself plus its three consumers
(CallModel, sink, sanitizer).
"""

import ast

import pytest

from codexray.call_arguments import (
    ArgumentSelector,
    CallArgumentBinder,
    as_selector,
    keyword,
    parameter,
    positional,
)
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
from rules.sql_injection import SQL_INJECTION_RULE
from rules.xss import XSS_RULE


def _call(code: str) -> ast.Call:
    return ast.parse(code, mode="eval").body


def _rule() -> Rule:
    return Rule(
        id="argument-binding-test",
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
                # TEK parametre, iki yazim.
                input_selectors=(parameter(0, "value"),),
            ),
        ),
        sinks=(
            SinkPattern(
                id="test-sink",
                targets=(CallTarget("sink"),),
                # IKI ayri parametre -- yukaridakiyle ayni sozdizimi degil.
                dangerous_arguments=(parameter(0), parameter(name="body")),
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


# ---- binder ----


def test_plain_int_selector_still_means_positional():
    assert as_selector(0) == positional(0)


def test_helpers_are_shorthands_for_one_parameter():
    assert positional(0) == parameter(0)
    assert keyword("s") == parameter(name="s")
    assert parameter(0, "s") == ArgumentSelector(index=0, name="s")


def test_a_selector_must_name_something():
    with pytest.raises(ValueError):
        parameter()


def test_parameter_binds_the_positional_spelling():
    binder = CallArgumentBinder(_call("f(a)"))

    assert binder.bind(parameter(0, "s")).id == "a"


def test_parameter_binds_the_keyword_spelling():
    binder = CallArgumentBinder(_call("f(s=a)"))

    assert binder.bind(parameter(0, "s")).id == "a"


def test_one_parameter_never_merges_two_spellings():
    """`f(a, s=b)` is invalid Python -- one parameter cannot receive two values.
    The binder must pick one rather than treat it as two inputs; positional
    wins.  Before the parameter model this bound both and merged them."""
    binder = CallArgumentBinder(_call("f(a, s=b)"))

    assert binder.bind(parameter(0, "s")).id == "a"


def test_keyword_only_parameter_does_not_bind_positionally():
    binder = CallArgumentBinder(_call("f(a)"))

    assert binder.bind(parameter(name="s")) is None


def test_positional_only_parameter_does_not_bind_by_keyword():
    binder = CallArgumentBinder(_call("f(s=a)"))

    assert binder.bind(parameter(0)) is None


def test_parameter_falls_back_to_keyword_when_star_args_blocks_the_position():
    """`*rest` makes position 0 unresolvable, but `s=b` is still unambiguous."""
    binder = CallArgumentBinder(_call("f(*rest, s=b)"))

    assert binder.bind(parameter(0, "s")).id == "b"


def test_binder_resolves_positional_and_keyword_arguments():
    binder = CallArgumentBinder(_call("f(a, b, key=c)"))

    assert binder.bind(0).id == "a"
    assert binder.bind(positional(1)).id == "b"
    assert binder.bind(keyword("key")).id == "c"


def test_binder_returns_none_for_unresolvable_selectors():
    binder = CallArgumentBinder(_call("f(a, key=b)"))

    assert binder.bind(5) is None
    assert binder.bind(positional(-1)) is None
    assert binder.bind(keyword("missing")) is None


def test_binder_refuses_positions_at_or_after_star_args():
    binder = CallArgumentBinder(_call("f(a, *rest, c)"))

    assert binder.bind(0).id == "a"  # before the unpacking: still resolvable
    assert binder.bind(1) is None  # the *args entry itself
    assert binder.bind(2) is None  # shifted by an unknown amount


def test_binder_does_not_bind_a_keyword_selector_to_kwargs_unpacking():
    binder = CallArgumentBinder(_call("f(**payload)"))

    assert binder.bind(keyword("anything")) is None


def test_bind_all_drops_unresolved_selectors():
    binder = CallArgumentBinder(_call("f(a, value=b)"))

    bound = binder.bind_all((parameter(0), parameter(name="value"), keyword("missing")))
    assert [node.id for node in bound] == ["a", "b"]


# ---- sink ----


def test_keyword_sink_argument_produces_finding():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "sink(body=user_input)\n"
    )

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].path == ("request.args", "user_input", "sink")


def test_positional_sink_argument_still_produces_finding():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "sink(user_input)\n"
    )

    assert len(analyzer.findings) == 1


def test_each_selected_sink_argument_is_reported_separately():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "sink(user_input, body=user_input)\n"
    )

    assert len(analyzer.findings) == 2


def test_unselected_keyword_argument_is_not_a_sink_argument():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "sink(headers=user_input)\n"
    )

    assert analyzer.findings == []


def test_kwargs_unpacking_does_not_bind_a_sink_argument():
    """`payload` itself is tainted, so a binder that guessed at the contents of
    `**kwargs` would report a finding here.  The first assertion keeps the setup
    honest: if `request.args` ever stopped being a source, this test would fail
    loudly instead of passing for the wrong reason."""
    analyzer = _analyze(
        "payload = request.args\n"
        "sink(**payload)\n"
    )

    assert analyzer.env["payload"].tainted
    assert analyzer.findings == []


# ---- sanitizer ----


def test_keyword_sanitizer_argument_applies_sanitization():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "safe = sanitize(value=user_input)\n"
        "sink(safe)\n"
    )

    assert analyzer.env["safe"].tainted
    assert analyzer.env["safe"].sanitized_for == ("html",)
    assert analyzer.findings == []


def test_positional_sanitizer_argument_still_applies_sanitization():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "safe = sanitize(user_input)\n"
        "sink(safe)\n"
    )

    assert analyzer.env["safe"].sanitized_for == ("html",)
    assert analyzer.findings == []


def test_sanitizer_with_no_selectable_argument_does_not_sanitize():
    """An input we cannot see is not an input we can claim to have sanitized."""
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "safe = sanitize(other=user_input)\n"
        "sink(safe)\n"
    )

    assert not analyzer.env["safe"].tainted
    assert analyzer.env["safe"].sanitized_for == ()
    assert analyzer.findings == []


# ---- call model ----


def test_modelled_keyword_argument_propagates_taint_to_return_value():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = json.dumps(obj=user_input)\n"
        "sink(result)\n"
    )

    assert analyzer.env["result"].tainted
    assert len(analyzer.findings) == 1


def test_call_model_merges_two_distinct_parameters():
    registry = CallModelRegistry(
        [
            CallModel(
                target=CallTarget("combine"),
                # IKI ayri parametre -- merge dogru davranis.
                input_selectors=(parameter(0), parameter(name="extra")),
            )
        ]
    )
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = combine('constant', extra=user_input)\n"
        "sink(result)\n",
        call_model_registry=registry,
    )

    assert analyzer.env["result"].tainted
    assert len(analyzer.findings) == 1


def test_call_model_with_no_bindable_selector_returns_clean():
    registry = CallModelRegistry(
        [CallModel(target=CallTarget("wrap"), input_selectors=(keyword("value"),))]
    )
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = wrap(user_input)\n"
        "sink(result)\n",
        call_model_registry=registry,
    )

    assert not analyzer.env["result"].tainted
    assert analyzer.findings == []


def test_unknown_call_with_keyword_argument_does_not_propagate_taint():
    analyzer = _analyze(
        "user_input = request.args['q']\n"
        "result = unknown_helper(value=user_input)\n"
        "sink(result)\n"
    )

    assert not analyzer.env["result"].tainted
    assert analyzer.findings == []


# ---- real rules ----


def test_flask_response_keyword_argument_produces_xss_finding():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "response = Response(response=value)\n"
    )

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].cwe == "CWE-79"
    assert analyzer.findings[0].path == ("request.args", "value", "Response")


def test_response_with_both_spellings_reports_one_finding_not_two():
    """`Response` names ONE parameter, so even invalid code supplying both
    spellings is a single data flow.  Under the previous selector model this
    bound twice and reported the same sink twice."""
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "response = Response(value, response=value)\n"
    )

    assert len(analyzer.findings) == 1


def test_html_escape_keyword_argument_prevents_xss_finding():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "safe = html.escape(s=value)\n"
        "response = Response(response=safe)\n"
    )

    assert analyzer.findings == []
    assert "html-text" in analyzer.env["safe"].sanitized_for


def test_nested_sink_in_non_dangerous_sql_argument_is_analyzed_once():
    analyzer = TaintAnalyzer(RuleEngine([SQL_INJECTION_RULE, XSS_RULE]))
    analyzer.visit(
        ast.parse(
            "value = request.args['q']\n"
            "cursor.execute('SELECT 1', Response(value))\n"
        )
    )

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].rule_id == "xss"


def test_nested_sink_in_unknown_positional_call_is_analyzed():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "unknown(Response(value))\n"
    )

    assert len(analyzer.findings) == 1


def test_nested_sink_in_unknown_keyword_call_is_analyzed():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "unknown(payload=Response(value))\n"
    )

    assert len(analyzer.findings) == 1


def test_nested_sink_in_kwargs_value_is_analyzed():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "unknown(**{'payload': Response(value)})\n"
    )

    assert len(analyzer.findings) == 1


def test_nested_sink_in_sink_argument_is_not_reported_twice():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "Response(Response(value))\n"
    )

    assert len(analyzer.findings) == 1


def test_nested_sink_in_sanitizer_argument_is_not_reported_twice():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "html.escape(Response(value))\n"
    )

    assert len(analyzer.findings) == 1


def test_nested_sink_in_call_model_argument_is_not_reported_twice():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "json.dumps(Response(value))\n"
    )

    assert len(analyzer.findings) == 1


def test_nested_sinks_in_positional_and_keyword_arguments_are_both_reported():
    analyzer = _analyze_xss(
        "value = request.args['q']\n"
        "Response(value, status=Response(value))\n"
    )

    assert len(analyzer.findings) == 2
