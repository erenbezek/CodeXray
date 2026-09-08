import ast
from pathlib import Path

import pytest

from codexray.cli import main
from codexray.rule_model import RuleEngine
from codexray.rules.path_manipulation import PATH_MANIPULATION_RULE
from codexray.rules.sql_injection import SQL_INJECTION_RULE
from codexray.rules.xss import XSS_RULE
from codexray.taint_engine import TaintAnalyzer


EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _analyze(code: str, rules=(PATH_MANIPULATION_RULE,)) -> TaintAnalyzer:
    analyzer = TaintAnalyzer(RuleEngine(list(rules)))
    analyzer.visit(ast.parse(code))
    return analyzer


@pytest.mark.parametrize(
    ("expression", "expected_findings"),
    [
        ("open(p)", 1),
        ("with open(p) as f:\n    pass", 1),
        ("open(file=p)", 1),
        ("f = open(p)", 1),
        ("send_file(p)", 1),
        ("send_file(path_or_file=p)", 1),
        ("send_from_directory('/up', p)", 1),
        ("send_from_directory('/up', path=p)", 1),
        ("send_from_directory(p, 'x')", 0),
        ("open('/etc/hosts')", 0),
    ],
    ids=(
        "open-positional",
        "open-header",
        "open-keyword",
        "open-assignment",
        "send-file-positional",
        "send-file-keyword",
        "send-from-directory-positional",
        "send-from-directory-keyword",
        "send-from-directory-directory-is-safe",
        "open-literal-is-safe",
    ),
)
def test_path_sinks_use_their_declared_argument(expression, expected_findings):
    analyzer = _analyze(
        "p = request.args['f']\n"
        f"{expression}\n"
    )

    assert len(analyzer.findings) == expected_findings


@pytest.mark.parametrize(
    "expression",
    [
        "open(secure_filename(p))",
        "open(secure_filename(filename=p))",
        "open(os.path.basename(p))",
    ],
)
def test_safe_basename_sanitizers_prevent_path_finding(expression):
    analyzer = _analyze(
        "p = request.args['f']\n"
        f"{expression}\n"
    )

    assert analyzer.findings == []


def test_path_rule_declares_both_safe_basename_targets():
    targets = PATH_MANIPULATION_RULE.sanitizers[0].targets

    assert {target.qualified_name for target in targets} == {
        "secure_filename",
        "os.path.basename",
    }


def test_path_becomes_unsafe_again_after_concatenation():
    analyzer = _analyze(
        "p = request.args['f']\n"
        "q = request.args['g']\n"
        "open(secure_filename(p) + q)\n"
    )

    assert len(analyzer.findings) == 1


@pytest.mark.parametrize(
    ("code", "expected_findings"),
    [
        (
            "n = secure_filename(p)\n"
            "open(os.path.join('/up', n))\n",
            0,
        ),
        ("open(os.path.join('/up', secure_filename(p)))\n", 0),
        ("open(os.path.join('/b', p))\n", 1),
        (
            "q = request.args['g']\n"
            "open(os.path.join(q, secure_filename(p)))\n",
            1,
        ),
        (
            "open(os.path.join('/a', os.path.join('/b', secure_filename(p))))\n",
            0,
        ),
    ],
    ids=(
        "join-sanitized-variable",
        "join-inline-sanitizer",
        "join-raw-input",
        "join-tainted-base",
        "nested-join-sanitized",
    ),
)
def test_join_preserves_only_surviving_path_sanitization(code, expected_findings):
    analyzer = _analyze("p = request.args['f']\n" + code)

    assert len(analyzer.findings) == expected_findings


@pytest.mark.parametrize(
    ("expression", "expected_findings"),
    [
        ("open(Path(p))", 1),
        ("open(Path('/b', p))", 1),
        ("open(Path('/b') / p)", 1),
        ("open(Path('/b') / secure_filename(p))", 0),
        ("open(Path(secure_filename(p)))", 0),
        ("open(Path('/etc/hosts'))", 0),
        ("Path(p).read_text()", 0),
    ],
    ids=(
        "path-input",
        "path-multiple-input",
        "path-operator-input",
        "path-operator-sanitized",
        "path-sanitized",
        "path-literal",
        "path-receiver-sink-gap",
    ),
)
def test_pathlib_cases(expression, expected_findings):
    analyzer = _analyze(
        "p = request.args['f']\n"
        f"{expression}\n"
    )

    assert len(analyzer.findings) == expected_findings


@pytest.mark.parametrize(
    ("rules", "code", "expected_findings"),
    [
        (
            (SQL_INJECTION_RULE,),
            "q = request.args['n']\ncursor.execute(q)\n",
            1,
        ),
        (
            (XSS_RULE,),
            "v = request.args['n']\nResponse(v)\n",
            1,
        ),
        (
            (SQL_INJECTION_RULE,),
            "q = request.args['n']\ncursor.execute(escape_sql(q))\n",
            0,
        ),
        (
            (XSS_RULE,),
            "v = request.args['n']\nResponse(html.escape(v))\n",
            0,
        ),
    ],
)
def test_existing_rules_remain_unchanged(rules, code, expected_findings):
    assert len(_analyze(code, rules).findings) == expected_findings


def test_path_examples_have_expected_results():
    vulnerable = (EXAMPLES_DIR / "vulnerable" / "path_manipulation.py").read_text()
    safe = (EXAMPLES_DIR / "safe" / "path_manipulation.py").read_text()

    assert len(_analyze(vulnerable).findings) == 1
    assert _analyze(safe).findings == []


def test_cli_registers_path_manipulation_rule(capsys):
    vulnerable = EXAMPLES_DIR / "vulnerable" / "path_manipulation.py"

    assert main(["scan", str(vulnerable)]) == 1
    assert "path-manipulation" in capsys.readouterr().out
