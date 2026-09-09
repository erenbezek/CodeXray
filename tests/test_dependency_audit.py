import json
import subprocess
import sys

import pytest

from codexray import cli
from codexray import dependency_audit
from codexray.dependency_audit import (
    DependencyVulnerability,
    parse_pip_audit_json,
)


PIP_AUDIT_FIXTURE = """
{
  "dependencies": [
    {
      "name": "flask",
      "version": "0.12.2",
      "vulns": [
        {
          "id": "PYSEC-2019-179",
          "fix_versions": ["1.0"],
          "aliases": ["GHSA-5wv5-4vpf-pj6m", "CVE-2019-1010083"],
          "description": "A Flask issue allows an attacker to cause unexpected behavior."
        },
        {"id": "PYSEC-2019-180", "fix_versions": ["1.0"], "aliases": ["CVE-2019-1010084"], "description": "Issue two."},
        {"id": "PYSEC-2019-181", "fix_versions": ["1.0"], "aliases": ["CVE-2019-1010085"], "description": "Issue three."},
        {"id": "PYSEC-2019-182", "fix_versions": ["1.0"], "aliases": ["CVE-2019-1010086"], "description": "Issue four."},
        {"id": "PYSEC-2019-183", "fix_versions": ["1.0"], "aliases": ["CVE-2019-1010087"], "description": "Issue five."}
      ]
    },
    {
      "name": "jinja2",
      "version": "2.10",
      "vulns": [
        {"id": "PYSEC-2019-184", "fix_versions": ["2.10.1"], "aliases": ["CVE-2019-1010088"], "description": "Issue six."},
        {"id": "PYSEC-2019-185", "fix_versions": ["2.10.1"], "aliases": ["CVE-2019-1010089"], "description": "Issue seven."},
        {"id": "PYSEC-2019-186", "fix_versions": ["2.10.1"], "aliases": ["CVE-2019-1010090"], "description": "Issue eight."},
        {"id": "PYSEC-2019-187", "fix_versions": ["2.10.1"], "aliases": ["CVE-2019-1010091"], "description": "Issue nine."},
        {"id": "PYSEC-2019-188", "fix_versions": ["2.10.1"], "aliases": ["CVE-2019-1010092"], "description": "Issue ten."}
      ]
    }
  ],
  "fixes": []
}
"""

CLEAN_FIXTURE = '{"dependencies": [{"name": "safe", "version": "1.0", "vulns": []}]}'


def _requirements_file(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("flask==0.12.2\n", encoding="utf-8")
    return requirements


def test_parse_pip_audit_fixture_flattens_ten_vulnerabilities():
    vulnerabilities = parse_pip_audit_json(PIP_AUDIT_FIXTURE)

    assert len(vulnerabilities) == 10
    assert vulnerabilities[0] == DependencyVulnerability(
        package="flask",
        installed_version="0.12.2",
        vuln_id="PYSEC-2019-179",
        aliases=("GHSA-5wv5-4vpf-pj6m", "CVE-2019-1010083"),
        fix_versions=("1.0",),
        description="A Flask issue allows an attacker to cause unexpected behavior.",
    )
    assert vulnerabilities[-1].package == "jinja2"


def test_packages_with_no_vulnerabilities_are_omitted():
    assert parse_pip_audit_json(CLEAN_FIXTURE) == ()


def test_empty_dependencies_produce_no_vulnerabilities():
    assert parse_pip_audit_json('{"dependencies": []}') == ()


def test_broken_json_raises_a_clear_value_error():
    with pytest.raises(ValueError, match="invalid pip-audit JSON"):
        parse_pip_audit_json("not json")


def test_audit_json_output_has_explicit_schema(capsys, monkeypatch, tmp_path):
    requirements = _requirements_file(tmp_path)
    monkeypatch.setattr(cli, "run_pip_audit", lambda _: PIP_AUDIT_FIXTURE)

    exit_code = cli.main(["audit", str(requirements), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["summary"] == {
        "packages_scanned": 2,
        "vulnerabilities": 10,
    }
    assert set(payload["vulnerabilities"][0]) == {
        "package",
        "installed_version",
        "vuln_id",
        "aliases",
        "fix_versions",
        "description",
    }
    assert payload["vulnerabilities"][0]["aliases"] == [
        "GHSA-5wv5-4vpf-pj6m",
        "CVE-2019-1010083",
    ]


def test_audit_human_output_contains_fix_and_aliases(capsys, monkeypatch, tmp_path):
    requirements = _requirements_file(tmp_path)
    monkeypatch.setattr(cli, "run_pip_audit", lambda _: PIP_AUDIT_FIXTURE)

    assert cli.main(["audit", str(requirements)]) == 1
    output = capsys.readouterr().out
    assert "flask 0.12.2  PYSEC-2019-179  -> 1.0" in output
    assert "CVE-2019-1010083" in output
    assert "10 zafiyet / 2 paket" in output


def test_audit_with_no_vulnerabilities_returns_zero(capsys, monkeypatch, tmp_path):
    requirements = _requirements_file(tmp_path)
    monkeypatch.setattr(cli, "run_pip_audit", lambda _: CLEAN_FIXTURE)

    assert cli.main(["audit", str(requirements)]) == 0
    assert capsys.readouterr().out == "Zafiyet yok / 1 paket\n"


def test_audit_missing_requirements_file_returns_two(capsys, tmp_path):
    missing = tmp_path / "missing.txt"

    assert cli.main(["audit", str(missing)]) == 2
    assert str(missing) in capsys.readouterr().err


def test_audit_invalid_tool_output_returns_two(capsys, monkeypatch, tmp_path):
    requirements = _requirements_file(tmp_path)
    monkeypatch.setattr(cli, "run_pip_audit", lambda _: "not json")

    assert cli.main(["audit", str(requirements)]) == 2
    assert "invalid pip-audit JSON" in capsys.readouterr().err


def test_audit_missing_pip_audit_returns_two_with_install_hint(
    capsys, monkeypatch, tmp_path
):
    requirements = _requirements_file(tmp_path)

    def missing_runner(_):
        raise ModuleNotFoundError("pip_audit")

    monkeypatch.setattr(cli, "run_pip_audit", missing_runner)

    assert cli.main(["audit", str(requirements)]) == 2
    error = capsys.readouterr().err
    assert "pip-audit kurulu değil" in error
    assert "python -m pip install pip-audit" in error


def test_runner_uses_no_deps_and_accepts_vulnerability_exit_code(
    monkeypatch, tmp_path
):
    requirements = _requirements_file(tmp_path)
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 1, CLEAN_FIXTURE, "")

    monkeypatch.setattr(dependency_audit.subprocess, "run", fake_run)

    output = dependency_audit.run_pip_audit(requirements)

    assert output == CLEAN_FIXTURE
    assert captured["command"] == [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(requirements),
        "--no-deps",
        "-f",
        "json",
    ]
    assert captured["kwargs"] == {
        "capture_output": True,
        "text": True,
        "check": False,
    }
