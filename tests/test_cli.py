import json
from pathlib import Path

from codexray.cli import main


REPO_ROOT = Path(__file__).parents[1]
VULNERABLE_EXAMPLES = REPO_ROOT / "examples" / "vulnerable"
SAFE_EXAMPLES = REPO_ROOT / "examples" / "safe"


def test_scan_vulnerable_directory_returns_one_and_reports_findings(capsys):
    exit_code = main(["scan", str(VULNERABLE_EXAMPLES)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "bulgu" in captured.out
    assert "dosya tarandı" in captured.out
    assert "request.args" in captured.out


def test_scan_safe_directory_returns_zero(capsys):
    exit_code = main(["scan", str(SAFE_EXAMPLES)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.startswith("Bulgu yok")
    assert "dosya tarandı" in captured.out


def test_scan_missing_path_returns_two(capsys, tmp_path):
    missing = tmp_path / "does-not-exist"

    exit_code = main(["scan", str(missing)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert str(missing) in captured.err


def test_scan_accepts_a_single_file_and_a_directory(capsys):
    file_exit_code = main(
        ["scan", str(VULNERABLE_EXAMPLES / "sql_injection.py")]
    )
    capsys.readouterr()
    directory_exit_code = main(["scan", str(VULNERABLE_EXAMPLES)])

    assert file_exit_code == 1
    assert directory_exit_code == 1


def test_json_output_has_explicit_file_and_taint_path_schema(capsys):
    file_path = VULNERABLE_EXAMPLES / "sql_injection.py"

    exit_code = main(["scan", str(file_path), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["summary"] == {
        "files_scanned": 1,
        "findings": len(payload["findings"]),
        "skipped_files": 0,
    }
    finding = payload["findings"][0]
    assert finding["file"] == str(file_path)
    assert finding["line"] == 4
    assert finding["taint_path"] == [
        "request.args",
        "username",
        "query",
        "cursor.execute",
    ]
    assert "path" not in finding


def test_finding_filename_is_the_scanned_file(capsys, tmp_path):
    source = tmp_path / "input.py"
    source.write_text(
        "value = request.args['q']\nResponse(value)\n", encoding="utf-8"
    )

    main(["scan", str(source), "--json"])

    finding = json.loads(capsys.readouterr().out)["findings"][0]
    assert finding["file"] == str(source)


def test_scan_isolates_analyzers_between_files(capsys, tmp_path):
    (tmp_path / "a_source.py").write_text(
        "value = request.args['q']\n", encoding="utf-8"
    )
    (tmp_path / "b_sink.py").write_text(
        "Response(value)\n", encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.startswith("Bulgu yok")


def test_syntax_error_does_not_abort_other_files(capsys, tmp_path):
    (tmp_path / "01_broken.py").write_text(
        "def broken(:\n", encoding="utf-8"
    )
    good = tmp_path / "02_good.py"
    good.write_text(
        "value = request.args['q']\nResponse(value)\n", encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "syntax error" in captured.err
    assert str(good) in captured.out
    assert "(1 dosya atlandı)" in captured.out


def test_directory_scan_order_is_deterministic(capsys, monkeypatch, tmp_path):
    (tmp_path / "z.py").write_text(
        "value = request.args['z']\nResponse(value)\n", encoding="utf-8"
    )
    (tmp_path / "a.py").write_text(
        "value = request.args['a']\nResponse(value)\n", encoding="utf-8"
    )
    original_rglob = Path.rglob
    monkeypatch.setattr(
        Path,
        "rglob",
        lambda path, pattern: list(original_rglob(path, pattern))[::-1],
    )

    first_code = main(["scan", str(tmp_path)])
    first_output = capsys.readouterr().out
    second_code = main(["scan", str(tmp_path)])
    second_output = capsys.readouterr().out

    assert first_code == second_code == 1
    assert first_output == second_output
    assert first_output.index(str(tmp_path / "a.py")) < first_output.index(
        str(tmp_path / "z.py")
    )


def test_latin1_source_with_coding_declaration_is_scanned(capsys, tmp_path):
    """A coding declaration is Python's own contract; such a file is real
    source, not an unreadable one, and must be analyzed rather than skipped."""
    source = tmp_path / "latin1.py"
    source.write_bytes(
        b"# -*- coding: latin-1 -*-\n"
        b'value = request.args["q"]\n'
        b'Response(value + "\xe7\xf6\xfc")\n'
    )

    exit_code = main(["scan", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert str(source) in captured.out
    assert "dosya atlandı" not in captured.out


def test_utf8_bom_source_is_scanned(capsys, tmp_path):
    source = tmp_path / "bom.py"
    source.write_bytes(
        b"\xef\xbb\xbf" b'value = request.args["q"]\n' b"Response(value)\n"
    )

    exit_code = main(["scan", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert str(source) in captured.out
    assert "dosya atlandı" not in captured.out


def test_unreadable_path_does_not_abort_the_scan(capsys, tmp_path):
    """A directory named `*.py` is matched by rglob but cannot be read.  It
    must not take the scan -- or the findings already collected -- down."""
    (tmp_path / "01_unreadable.py").mkdir()
    good = tmp_path / "02_good.py"
    good.write_text(
        'value = request.args["q"]\nResponse(value)\n', encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "cannot be read" in captured.err
    assert str(good) in captured.out
    assert "1 bulgu" in captured.out


def test_unreadable_path_is_reported_in_json_summary(capsys, tmp_path):
    (tmp_path / "01_unreadable.py").mkdir()
    (tmp_path / "02_good.py").write_text(
        'value = request.args["q"]\nResponse(value)\n', encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["summary"]["findings"] == 1
    assert payload["summary"]["skipped_files"] == 1
