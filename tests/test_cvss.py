"""Tests for depwatch/cvss.py.

Expected scores are the published NVD/FIRST base scores for these vectors.
"""

import pytest

from depwatch.cvss import base_score, parse_vector, roundup, score_to_level


@pytest.mark.parametrize(
    "vector, expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # classic remote code execution
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # scope changed, capped at 10
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # typical reflected XSS
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),  # local privilege escalation
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),  # remote denial of service
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),  # small information leak
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),  # low
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),  # PR:L with scope changed uses 0.68
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # v3.0 prefix accepted
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),  # no impact at all
    ],
)
def test_known_scores(vector, expected):
    assert base_score(vector) == expected


def test_temporal_metrics_are_ignored():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C"
    assert base_score(vector) == 9.8


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # v4 not supported
        "AV:N/AC:L/Au:N/C:P/I:P/A:P",  # CVSS v2 has no prefix
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A",  # malformed part
    ],
)
def test_invalid_vectors_raise(vector):
    with pytest.raises(ValueError):
        base_score(vector)


def test_parse_vector():
    assert parse_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")["AV"] == "P"


@pytest.mark.parametrize("value, expected", [(4.0, 4.0), (4.02, 4.1), (4.000000001, 4.0), (9.81, 9.9), (0.0, 0.0)])
def test_roundup(value, expected):
    assert roundup(value) == expected


@pytest.mark.parametrize(
    "score, level",
    [(10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"), (6.9, "Medium"),
     (4.0, "Medium"), (3.9, "Low"), (0.1, "Low"), (0.0, None)],
)
def test_score_to_level_boundaries(score, level):
    assert score_to_level(score) == level
