import ast
from pathlib import Path

import pytest

from codexray.cli import main
from codexray.rule_model import RuleEngine
from codexray.rules import ALL_RULES
from codexray.rules.sensitive_data import SENSITIVE_DATA_RULE
from codexray.taint_engine import TaintAnalyzer


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _analyze(code: str, rules=(SENSITIVE_DATA_RULE,)) -> TaintAnalyzer:
    analyzer = TaintAnalyzer(RuleEngine(list(rules)))
    analyzer.visit(ast.parse(code))
    return analyzer


@pytest.mark.parametrize(
    "code",
    [
        "s = os.environ['SECRET']\nprint(s)\n",
        "s = os.environ['SECRET']\nlogging.error(s)\n",
        "pw = getpass.getpass()\nprint(pw)\n",
        "k = settings.SECRET_KEY\nprint(k)\n",
        "p = user.password\nlogging.info(p)\n",
    ],
)
def test_sensitive_values_reaching_console_or_log_produce_findings(code):
    analyzer = _analyze(code)

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].rule_id == "sensitive-data-exposure"


def test_sensitive_value_reaching_http_response_produces_finding():
    analyzer = _analyze(
        "s = os.environ['SECRET']\n"
        "Response(s)\n"
    )

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].rule_id == "sensitive-data-exposure"


def test_sensitive_source_path_identifies_broad_environment_source():
    analyzer = _analyze("s = os.environ['SECRET']\nprint(s)\n")

    assert analyzer.findings[0].path == ("os.environ", "s", "print")


def test_sensitive_source_path_identifies_named_attribute_source():
    analyzer = _analyze("s = settings.SECRET_KEY\nprint(s)\n")

    assert analyzer.findings[0].path == ("settings.SECRET_KEY", "s", "print")


def test_clean_console_value_produces_no_finding():
    assert _analyze("print('sabit')\n").findings == []


def test_unknown_redaction_call_does_not_produce_finding():
    analyzer = _analyze("print(redact(os.environ['SECRET']))\n")

    assert analyzer.findings == []


@pytest.mark.parametrize(
    ("code", "expected_findings"),
    [
        ("s = os.environ['SECRET']\ncursor.execute(s)\n", 0),
        ("s = os.environ['SECRET']\nopen(s)\n", 0),
        ("v = request.args['q']\nprint(v)\n", 0),
        ("v = request.args['q']\nResponse(v)\n", 1),
        ("v = request.args['q']\ncursor.execute(v)\n", 1),
        ("v = request.args['q']\nopen(v)\n", 1),
    ],
    ids=(
        "sensitive-does-not-trigger-sql",
        "sensitive-does-not-trigger-path",
        "user-input-does-not-trigger-sensitive",
        "user-input-triggers-xss",
        "user-input-triggers-sql",
        "user-input-triggers-path",
    ),
)
def test_rules_are_isolated_by_source_kind(code, expected_findings):
    analyzer = _analyze(code, ALL_RULES)

    assert len(analyzer.findings) == expected_findings
    if expected_findings:
        assert analyzer.findings[0].rule_id in {
            "xss",
            "sql-injection",
            "path-manipulation",
        }


def test_cli_registers_sensitive_data_rule(capsys):
    vulnerable = EXAMPLES_DIR / "vulnerable" / "sensitive_data.py"

    assert main(["scan", str(vulnerable)]) == 1
    assert "sensitive-data-exposure" in capsys.readouterr().out


def test_sensitive_data_examples_have_expected_results():
    vulnerable = (EXAMPLES_DIR / "vulnerable" / "sensitive_data.py").read_text()
    safe = (EXAMPLES_DIR / "safe" / "sensitive_data.py").read_text()

    assert len(_analyze(vulnerable).findings) == 1
    assert _analyze(safe).findings == []


@pytest.mark.parametrize(
    "expression",
    [
        "settings.SECRET_KEY",
        "settings.API_TOKEN",
        "settings.PASSWORD",
        "config.SECRET",
        "config.TOKEN",
        "app.config.API_KEY",
        "creds.PRIVATE_KEY",
        "settings.DATABASE_PASSWORD",
    ],
)
def test_uppercase_config_constants_are_sensitive_sources(expression: str):
    """Django and Flask name config constants in upper case by convention.

    Matching is case sensitive, so the upper-case spellings are listed
    separately; without them the rule missed the most common shape of the
    thing it looks for.
    """
    analyzer = _analyze(f"value = {expression}\nprint(value)\n")

    assert len(analyzer.findings) == 1
    assert analyzer.findings[0].rule_id == "sensitive-data-exposure"


@pytest.mark.parametrize(
    "expression",
    [
        "settings.DEBUG",
        "config.TIMEOUT",
        "settings.ALLOWED_HOSTS",
        "user.name",
        "config.DATABASE_URL",
    ],
)
def test_upper_case_alone_does_not_make_a_value_sensitive(expression: str):
    analyzer = _analyze(f"value = {expression}\nprint(value)\n")

    assert analyzer.findings == []
