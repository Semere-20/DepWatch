"""Tests for depwatch/severity.py: the three severity rules and alias merging."""

import pytest

from depwatch.severity import (
    assess_severity,
    build_findings,
    find_cvss_v3_vector,
    fixed_versions,
    group_aliases,
    label_level,
)
from tests.conftest import make_vuln

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
MEDIUM_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 6.1


# --- rule 1: CVSS v3 -------------------------------------------------------

def test_cvss_vector_wins_over_label():
    sev = assess_severity(make_vuln("X", vector=CRITICAL_VECTOR, label="LOW"))
    assert (sev.level, sev.score, sev.source) == ("Critical", 9.8, "cvss_v3")


def test_cvss_vector_inside_affected_is_found():
    vuln = {"id": "X", "affected": [{"severity": [{"type": "CVSS_V3", "score": MEDIUM_VECTOR}]}]}
    assert find_cvss_v3_vector(vuln) == MEDIUM_VECTOR
    assert assess_severity(vuln).level == "Medium"


def test_cvss_v4_only_falls_back_to_label():
    vuln = {"id": "X", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}],
            "database_specific": {"severity": "HIGH"}}
    sev = assess_severity(vuln)
    assert (sev.level, sev.source) == ("High", "advisory_label")


def test_broken_cvss_vector_falls_back_to_label():
    sev = assess_severity(make_vuln("X", vector="CVSS:3.1/AV:N/garbage", label="MODERATE"))
    assert (sev.level, sev.score, sev.source) == ("Medium", None, "advisory_label")


def test_zero_score_falls_back_to_label():
    zero = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    sev = assess_severity(make_vuln("X", vector=zero, label="LOW"))
    assert (sev.level, sev.source) == ("Low", "advisory_label")


# --- rule 2: advisory label -------------------------------------------------

@pytest.mark.parametrize(
    "label, level",
    [("CRITICAL", "Critical"), ("HIGH", "High"), ("MODERATE", "Medium"), ("medium", "Medium"), ("LOW", "Low")],
)
def test_label_mapping(label, level):
    sev = assess_severity(make_vuln("X", label=label))
    assert (sev.level, sev.score, sev.source) == (level, None, "advisory_label")


@pytest.mark.parametrize("database_specific", [None, "text", {"severity": 5}, {"severity": "WHATEVER"}])
def test_unusable_labels(database_specific):
    assert label_level({"database_specific": database_specific}) is None


# --- rule 3: nothing --------------------------------------------------------

def test_no_severity_is_unknown():
    sev = assess_severity({"id": "X"})
    assert (sev.level, sev.score, sev.source) == ("Unknown", None, "none")


# --- fixed versions ---------------------------------------------------------

def test_fixed_versions_collected():
    assert fixed_versions(make_vuln("X", fixed=["3.2.19", "4.1.11"], package="Django"), "django") == ["3.2.19", "4.1.11"]


def test_git_commit_fixes_are_ignored():
    # Found in a real run: gevent's record also lists a fixing commit hash.
    vuln = {"affected": [{"package": {"name": "gevent"}, "ranges": [
        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "2f53c851eaf926767fbac62385615efd4886221c"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "23.9.0"}]},
    ]}]}
    assert fixed_versions(vuln, "gevent") == ["23.9.0"]


def test_no_fixed_version():
    assert fixed_versions(make_vuln("X", fixed=[]), "demo") == []


def test_fixed_versions_ignore_other_packages_and_bad_data():
    vuln = {"affected": [
        {"package": {"name": "other"}, "ranges": [{"events": [{"fixed": "9.9"}]}]},
        "not a dict",
        {"package": "weird", "ranges": ["bad", {"events": ["bad", {"fixed": "1.2"}]}]},
    ]}
    assert fixed_versions(vuln, "demo") == ["1.2"]


# --- alias merging ----------------------------------------------------------

def test_group_aliases_merges_ghsa_and_pysec():
    ghsa = make_vuln("GHSA-1", aliases=["CVE-1", "PYSEC-1"])
    pysec = make_vuln("PYSEC-1", aliases=["CVE-1", "GHSA-1"])
    other = make_vuln("GHSA-2")
    groups = group_aliases([ghsa, other, pysec])
    assert [[v["id"] for v in g] for g in groups] == [["GHSA-1", "PYSEC-1"], ["GHSA-2"]]


def test_group_aliases_joins_two_groups_through_a_bridge():
    a = make_vuln("A", aliases=["CVE-1"])
    b = make_vuln("B", aliases=["CVE-2"])
    bridge = make_vuln("C", aliases=["CVE-1", "CVE-2"])
    groups = group_aliases([a, b, bridge])
    assert len(groups) == 1 and len(groups[0]) == 3


def test_build_findings_keeps_record_with_best_severity():
    pysec = make_vuln("PYSEC-1", aliases=["CVE-1"], fixed=["2.0"], summary="")
    ghsa = make_vuln("GHSA-1", aliases=["CVE-1", "PYSEC-1"], vector=CRITICAL_VECTOR, fixed=["2.0", "1.9.9"],
                     summary="SQL injection\nmore details")
    findings = build_findings([pysec, ghsa], "demo")
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_id == "GHSA-1"
    assert f.aliases == ["CVE-1", "PYSEC-1"]
    assert f.severity.level == "Critical"
    assert f.fixed_versions == ["2.0", "1.9.9"]
    assert f.summary == "SQL injection"  # first line only


def test_build_findings_with_missing_fields():
    findings = build_findings([{}], "demo")
    assert findings[0].vuln_id == "(no id)"
    assert findings[0].summary == ""
    assert findings[0].severity.level == "Unknown"
    assert findings[0].fixed_versions == []


def test_build_findings_uses_details_when_no_summary():
    findings = build_findings([{"id": "X", "details": "  Long details text\nline 2"}], "demo")
    assert findings[0].summary == "Long details text"
