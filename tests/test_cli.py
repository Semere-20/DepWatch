"""Tests for depwatch/cli.py: argument parsing and the full flow with a fake OSV."""

import json
import subprocess
import sys

import pandas as pd
import pytest
import requests

from depwatch import __version__
from depwatch.cli import build_arg_parser, main
from tests.conftest import FakeResponse, RouterSession, make_vuln

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.fixture
def req_file(tmp_path):
    """A small requirements file with one package of every kind."""
    path = tmp_path / "requirements.txt"
    path.write_text("django==3.2.0\nflask==3.0.0\nrequests>=2\n-r other.txt\n", encoding="utf-8")
    return path


def django_session(level_vector=CRITICAL_VECTOR, label=None):
    """Fake OSV: django has one vulnerability, everything else is clean."""
    return RouterSession({
        "django": FakeResponse(200, {"vulns": [
            make_vuln("GHSA-dj", vector=level_vector, label=label, package="django", fixed=["3.2.19"])
        ]}),
    })


# --- argument parsing -------------------------------------------------------

def test_defaults():
    args = build_arg_parser().parse_args(["scan", "req.txt"])
    assert (args.output_dir, args.format, args.min_severity, args.fail_on, args.timeout, args.no_chart) == (
        "reports", "all", "low", "high", 10.0, False)


def test_all_options():
    args = build_arg_parser().parse_args([
        "scan", "r.txt", "--output-dir", "out", "--format", "json", "--min-severity", "critical",
        "--fail-on", "none", "--timeout", "2.5", "--no-chart"])
    assert (args.output_dir, args.format, args.min_severity, args.fail_on, args.timeout, args.no_chart) == (
        "out", "json", "critical", "none", 2.5, True)


@pytest.mark.parametrize("bad", [["scan", "r.txt", "--timeout", "0"], ["scan", "r.txt", "--timeout", "abc"],
                                 ["scan", "r.txt", "--fail-on", "extreme"], ["scan"], []])
def test_bad_arguments_exit_2(bad):
    with pytest.raises(SystemExit) as exc:
        main(bad)
    assert exc.value.code == 2


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"depwatch {__version__}"


def test_help_has_description_and_example(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    out = capsys.readouterr().out
    assert "python -m depwatch scan requirements.txt" in out and "--fail-on" in out and "exit codes" in out


# --- end-to-end with fake OSV ------------------------------------------------

def test_end_to_end_writes_all_outputs(req_file, tmp_path, capsys):
    out_dir = tmp_path / "out"
    code = main(["scan", str(req_file), "--output-dir", str(out_dir)], session=django_session())
    out = capsys.readouterr().out

    assert code == 1  # a Critical finding and --fail-on high (default)
    assert (out_dir / "report.csv").exists() and (out_dir / "report.json").exists()
    assert (out_dir / "chart.png").exists()
    assert "GHSA-dj" in out and "Scan complete" in out and "Exit code: 1" in out

    csv = pd.read_csv(out_dir / "report.csv", keep_default_na=False)
    assert list(csv["status"]) == ["vulnerable", "no_known_vulns", "unpinned", "skipped"]
    assert csv.loc[0, "severity_source"] == "cvss_v3" and csv.loc[0, "fixed_versions"] == "3.2.19"


def test_fail_on_critical_with_medium_finding_exits_0(req_file, tmp_path):
    session = django_session(level_vector=None, label="MODERATE")
    assert main(["scan", str(req_file), "--output-dir", str(tmp_path), "--fail-on", "critical"], session=session) == 0


def test_error_makes_scan_incomplete(req_file, tmp_path, capsys):
    session = RouterSession({"django": requests.ConnectionError("down")})
    code = main(["scan", str(req_file), "--output-dir", str(tmp_path), "--fail-on", "none"], session=session)
    assert code == 2
    assert "SCAN INCOMPLETE" in capsys.readouterr().out
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["scan_complete"] is False


def test_missing_file_exits_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing.txt")], session=RouterSession({})) == 2
    assert "not found" in capsys.readouterr().err


def test_empty_file_exits_0_and_skips_chart(tmp_path, capsys):
    path = tmp_path / "requirements.txt"
    path.write_text("# nothing here\n", encoding="utf-8")
    assert main(["scan", str(path), "--output-dir", str(tmp_path / "o")], session=RouterSession({})) == 0
    out = capsys.readouterr().out
    assert "Nothing to scan" in out and "Chart skipped" in out
    assert not (tmp_path / "o" / "chart.png").exists()


def test_format_table_only_writes_no_files(req_file, tmp_path, capsys):
    out_dir = tmp_path / "o"
    main(["scan", str(req_file), "--output-dir", str(out_dir), "--format", "table", "--no-chart"],
         session=django_session())
    assert list(out_dir.iterdir()) == []
    assert "GHSA-dj" in capsys.readouterr().out


def test_format_csv_only(req_file, tmp_path):
    main(["scan", str(req_file), "--output-dir", str(tmp_path), "--format", "csv", "--no-chart"],
         session=django_session())
    assert sorted(p.name for p in tmp_path.iterdir() if p.is_file() and p.suffix != ".txt") == ["report.csv"]


def test_min_severity_hides_lower_findings_but_not_exit_code(req_file, tmp_path):
    session = django_session(level_vector=None, label="HIGH")
    code = main(["scan", str(req_file), "--output-dir", str(tmp_path), "--min-severity", "critical"],
                session=session)
    csv = pd.read_csv(tmp_path / "report.csv", keep_default_na=False)
    assert "GHSA-dj" not in set(csv["vuln_id"])  # hidden from the report...
    assert code == 1  # ...but still fails the run


def test_python_dash_m_entry_point():
    # Runs the real `python -m depwatch --version` in a subprocess (no network needed).
    result = subprocess.run([sys.executable, "-m", "depwatch", "--version"], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.strip() == f"depwatch {__version__}"
