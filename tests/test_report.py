"""Tests for depwatch/report.py and depwatch/scanner.py."""

import json

import pandas as pd
import pytest
import requests

from depwatch.parser import parse_requirements_text
from depwatch.report import (
    build_dataframe,
    compute_exit_code,
    filter_by_min_severity,
    format_summary,
    format_table,
    make_chart,
    severity_counts,
    status_counts,
    write_csv,
    write_json,
)
from depwatch.scanner import PackageResult, scan_requirements
from depwatch.severity import Finding, Severity
from tests.conftest import FakeResponse, RouterSession, make_vuln


def finding(vuln_id, level, score=None, source="cvss_v3"):
    """Small helper to build a Finding."""
    return Finding(vuln_id, [], f"summary of {vuln_id}", Severity(level, score, source), [])


def sample_results():
    """A realistic mix of every status."""
    return [
        PackageResult("zlib-pkg", "1.0", "vulnerable", "2", 1,
                      [finding("Z-LOW", "Low", 3.1), finding("Z-UNK", "Unknown", None, "none")]),
        PackageResult("alpha", "2.0", "vulnerable", "2", 2,
                      [finding("A-HIGH", "High", 7.5), finding("A-HIGH-LABEL", "High", None, "advisory_label")]),
        PackageResult("beta", "1.0", "vulnerable", "2", 3,
                      [finding("B-HIGH", "High", 8.8), finding("B-CRIT", "Critical", 9.8)]),
        PackageResult("clean", "1.0", "no_known_vulns", "none", 4),
        PackageResult("loose", None, "unpinned", "no version specified", 5),
        PackageResult("-r x.txt", None, "skipped", "includes another file", 6),
        PackageResult("broken", "1.0", "error", "request timed out after 10s", 7),
    ]


# --- sorting -----------------------------------------------------------------

def test_sort_order():
    df = build_dataframe(sample_results())
    assert list(df["vuln_id"]) == ["B-CRIT", "B-HIGH", "A-HIGH", "A-HIGH-LABEL", "Z-LOW", "Z-UNK", "", "", "", ""]
    assert list(df["status"][-4:]) == ["no_known_vulns", "unpinned", "skipped", "error"]


def test_same_severity_and_score_sorted_by_package():
    results = [
        PackageResult("zeta", "1", "vulnerable", "", 1, [finding("Z", "High", 7.5)]),
        PackageResult("alpha", "1", "vulnerable", "", 2, [finding("A", "High", 7.5)]),
    ]
    assert list(build_dataframe(results)["package"]) == ["alpha", "zeta"]


def test_empty_report_has_columns_and_no_crash(tmp_path):
    df = build_dataframe([])
    assert df.empty and "severity_source" in df.columns
    created, message = make_chart(df, tmp_path / "chart.png", "t")
    assert created is False and "skipped" in message
    assert not (tmp_path / "chart.png").exists()
    assert format_table(df) == "(no rows to show)"
    assert filter_by_min_severity(df, "high").empty


def test_chart_skipped_when_no_vulnerabilities(tmp_path):
    df = build_dataframe([PackageResult("clean", "1.0", "no_known_vulns", "", 1)])
    created, message = make_chart(df, tmp_path / "chart.png", "t")
    assert created is False
    assert message == "Chart skipped: no vulnerabilities to plot."


def test_chart_is_created(tmp_path):
    created, message = make_chart(build_dataframe(sample_results()), tmp_path / "chart.png", "t")
    assert created is True and (tmp_path / "chart.png").stat().st_size > 1000


# --- filtering, counts, summary ------------------------------------------------

def test_min_severity_filter_keeps_unknown_and_non_findings():
    df = filter_by_min_severity(build_dataframe(sample_results()), "high")
    assert "Z-LOW" not in set(df["vuln_id"])
    assert "Z-UNK" in set(df["vuln_id"])  # Unknown is never hidden
    assert {"unpinned", "error"} <= set(df["status"])


def test_status_counts():
    assert status_counts(sample_results()) == {
        "vulnerable": 3, "no_known_vulns": 1, "unpinned": 1, "skipped": 1, "error": 1,
    }


def test_severity_counts():
    assert severity_counts(sample_results()) == {"Critical": 1, "High": 3, "Medium": 0, "Low": 1, "Unknown": 1}


def test_summary_says_incomplete_when_errors():
    text = format_summary(sample_results())
    assert "SCAN INCOMPLETE: 1 package(s)" in text
    assert "2 entries were not scanned" in text


def test_summary_complete_when_no_errors():
    text = format_summary([PackageResult("clean", "1.0", "no_known_vulns", "", 1)])
    assert "Scan complete: all 1 pinned package(s)" in text and "INCOMPLETE" not in text


def test_summary_warns_when_nothing_was_checked():
    # Found in a real run (ansible): every line unpinned, so OSV was never asked.
    text = format_summary([PackageResult("jinja2", None, "unpinned", "not an exact pin (>=3.1)", 1)])
    assert "WARNING: no package was checked" in text and "Scan complete" not in text


def test_table_truncates_long_summary():
    results = [PackageResult("p", "1", "vulnerable", "", 1,
                             [Finding("X", [], "a" * 100, Severity("High", 7.5, "cvss_v3"), ["2.0"])])]
    table = format_table(build_dataframe(results), max_summary=20)
    assert "a" * 17 + "..." in table and "7.5" in table


def test_table_shortens_long_fixed_versions():
    fixes = [f"{n}.0.1" for n in range(10)]  # "0.0.1; 1.0.1; ..." is 68 characters
    results = [PackageResult("p", "1", "vulnerable", "", 1,
                             [Finding("X", [], "s", Severity("High", 7.5, "cvss_v3"), fixes)])]
    table = format_table(build_dataframe(results), max_fixed=12)
    assert "0.0.1; 1...." in table and "9.0.1" not in table


# --- exit codes -----------------------------------------------------------------

def vuln_result(level):
    return [PackageResult("p", "1", "vulnerable", "", 1, [finding("X", level, None)])]


@pytest.mark.parametrize(
    "results, fail_on, expected",
    [
        (vuln_result("High"), "high", 1),
        (vuln_result("Critical"), "high", 1),
        (vuln_result("Medium"), "high", 0),
        (vuln_result("Medium"), "medium", 1),
        (vuln_result("Low"), "low", 1),
        (vuln_result("Unknown"), "low", 0),  # Unknown never triggers --fail-on
        (vuln_result("Critical"), "none", 0),
        ([PackageResult("p", "1", "no_known_vulns", "", 1)], "low", 0),
        (sample_results(), "none", 2),  # an error makes the scan incomplete, even with --fail-on none
        ([], "high", 0),
    ],
)
def test_exit_codes(results, fail_on, expected):
    assert compute_exit_code(results, fail_on) == expected


# --- CSV / JSON ---------------------------------------------------------------

def test_csv_and_json_written(tmp_path):
    results = sample_results()
    df = build_dataframe(results)
    write_csv(df, tmp_path / "report.csv")
    write_json(df, results, tmp_path / "report.json", "requirements.txt", "1.0.0")

    csv = pd.read_csv(tmp_path / "report.csv")
    assert list(csv.columns)[:4] == ["package", "version", "status", "severity"]
    assert len(csv) == 10

    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["scan_complete"] is False
    assert data["status_counts"]["error"] == 1
    assert data["rows"][0]["vuln_id"] == "B-CRIT"
    assert data["rows"][-1]["score"] is None  # NaN became null


# --- scanner -------------------------------------------------------------------

def test_scanner_gives_one_status_per_package():
    reqs = parse_requirements_text("vulnpkg==1.0\nsafe==2.0\nbroken==3.0\nloose>=1\n-r other.txt\n")
    session = RouterSession({
        "vulnpkg": FakeResponse(200, {"vulns": [
            make_vuln("GHSA-1", aliases=["PYSEC-1"], label="HIGH", package="vulnpkg", fixed=["1.1"]),
            make_vuln("PYSEC-1", aliases=["GHSA-1"], package="vulnpkg"),
        ]}),
        "safe": FakeResponse(200, {}),
        "broken": requests.Timeout("slow"),
    })
    progress = []
    results = scan_requirements(reqs, session=session, sleep=lambda s: None, on_progress=progress.append)

    assert [(r.name, r.status) for r in results] == [
        ("vulnpkg", "vulnerable"), ("safe", "no_known_vulns"), ("broken", "error"),
        ("loose", "unpinned"), ("-r other.txt", "skipped"),
    ]
    assert results[0].reason == "1 known vulnerability"  # GHSA + PYSEC merged
    assert results[2].reason == "request timed out after 10s"
    assert session.calls == ["vulnpkg", "safe", "broken"]  # unpinned/skipped never hit the network
    assert len(progress) == 5 and "[1/5] vulnpkg==1.0: vulnerable" in progress[0]


def test_scanner_plural_reason():
    reqs = parse_requirements_text("p==1.0")
    session = RouterSession({"p": FakeResponse(200, {"vulns": [make_vuln("A"), make_vuln("B")]})})
    assert scan_requirements(reqs, session=session)[0].reason == "2 known vulnerabilities"


def test_scanner_creates_session_when_none_given(monkeypatch):
    created = []

    def fake_make_session():
        created.append(True)
        return RouterSession({})

    monkeypatch.setattr("depwatch.scanner.make_session", fake_make_session)
    results = scan_requirements(parse_requirements_text("p==1.0"))
    assert created == [True] and results[0].status == "no_known_vulns"
