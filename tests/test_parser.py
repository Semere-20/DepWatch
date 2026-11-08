"""Tests for depwatch/parser.py."""

from pathlib import Path

import pytest

from depwatch.parser import (
    RequirementsError,
    normalize_name,
    parse_requirements_file,
    parse_requirements_text,
    strip_comment,
)


def by_name(reqs):
    """Index parsed requirements by name for easy lookups in tests."""
    return {r.name: r for r in reqs}


# --- file handling ---------------------------------------------------------

def test_empty_file_gives_no_requirements(tmp_path: Path):
    path = tmp_path / "requirements.txt"
    path.write_text("", encoding="utf-8")
    assert parse_requirements_file(path) == []


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(RequirementsError, match="not found"):
        parse_requirements_file(tmp_path / "nope.txt")


def test_directory_instead_of_file_raises(tmp_path: Path):
    with pytest.raises(RequirementsError):
        parse_requirements_file(tmp_path)


def test_non_utf8_file_raises(tmp_path: Path):
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"django==3.2\n\xff\xfe\xfa bad bytes\n")
    with pytest.raises(RequirementsError, match="UTF-8"):
        parse_requirements_file(path)


def test_unreadable_file_raises(tmp_path: Path, monkeypatch):
    path = tmp_path / "requirements.txt"
    path.write_text("django==3.2\n", encoding="utf-8")

    def deny(*args, **kwargs):
        raise PermissionError("access denied")

    monkeypatch.setattr(Path, "read_text", deny)  # pretend the OS refuses to open the file
    with pytest.raises(RequirementsError, match="could not read"):
        parse_requirements_file(path)


def test_bom_is_removed(tmp_path: Path):
    path = tmp_path / "requirements.txt"
    path.write_bytes("﻿Django==3.2.0\n".encode("utf-8"))
    reqs = parse_requirements_file(path)
    assert [(r.name, r.version) for r in reqs] == [("django", "3.2.0")]


def test_bom_in_text_is_removed():
    reqs = parse_requirements_text("﻿flask==2.0.0")
    assert reqs[0].name == "flask"


# --- comments and blank lines --------------------------------------------

def test_comments_only_and_blank_lines():
    text = "# a comment\n\n   \n    # indented comment\n"
    assert parse_requirements_text(text) == []


def test_inline_comment_is_removed():
    reqs = parse_requirements_text("requests==2.31.0  # http client\n")
    assert (reqs[0].name, reqs[0].version, reqs[0].status) == ("requests", "2.31.0", None)


def test_hash_inside_url_is_not_a_comment():
    assert strip_comment("git+https://x.org/repo.git#egg=foo") == "git+https://x.org/repo.git#egg=foo"


# --- pinned, extras, markers ----------------------------------------------

def test_exact_pin_is_scannable():
    req = parse_requirements_text("numpy==1.26.4")[0]
    assert (req.name, req.version, req.status, req.line_number) == ("numpy", "1.26.4", None, 1)


def test_extras_are_stripped():
    req = parse_requirements_text("requests[security,socks]==2.25.0")[0]
    assert (req.name, req.version) == ("requests", "2.25.0")


def test_environment_marker_is_ignored_but_package_scanned():
    req = parse_requirements_text('tomli==2.0.1 ; python_version < "3.11"')[0]
    assert (req.name, req.version, req.status) == ("tomli", "2.0.1", None)


def test_spaces_around_operator():
    req = parse_requirements_text("flask == 2.0.1")[0]
    assert req.version == "2.0.1"


def test_hash_options_and_line_continuation():
    text = "django==4.2.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nflask==2.0.0\n"
    reqs = parse_requirements_text(text)
    assert [(r.name, r.version, r.line_number) for r in reqs] == [("django", "4.2.0", 1), ("flask", "2.0.0", 4)]


def test_dangling_backslash_at_end_of_file():
    reqs = parse_requirements_text("django==4.2.0 \\")
    assert reqs[0].version == "4.2.0"


# --- name normalization and duplicates -----------------------------------

@pytest.mark.parametrize(
    "raw, expected",
    [("Django", "django"), ("my_pkg", "my-pkg"), ("My.Pkg", "my-pkg"), ("a__b--c", "a-b-c")],
)
def test_normalize_name(raw, expected):
    assert normalize_name(raw) == expected


def test_duplicates_same_version_are_merged():
    reqs = parse_requirements_text("Django==3.2.0\ndjango==3.2.0\n")
    assert len(reqs) == 1 and reqs[0].version == "3.2.0"


def test_duplicates_written_differently_are_merged():
    reqs = parse_requirements_text("my_pkg==1.0\nMy-Pkg==1.0\n")
    assert [r.name for r in reqs] == ["my-pkg"]


def test_conflicting_pins_are_skipped():
    req = parse_requirements_text("django==3.2\nDjango==4.0\n")[0]
    assert req.status == "skipped"
    assert req.reason == "conflicting pins: 3.2, 4.0"
    assert req.version is None


def test_pinned_wins_over_unpinned_duplicate():
    reqs = parse_requirements_text("django\ndjango==4.2.1\n")
    assert (reqs[0].version, reqs[0].status) == ("4.2.1", None)


def test_unpinned_duplicates_keep_first():
    reqs = parse_requirements_text("django>=3\ndjango<5\n")
    assert len(reqs) == 1 and reqs[0].reason == "not an exact pin (>=3)"


# --- unpinned cases --------------------------------------------------------

@pytest.mark.parametrize(
    "line, reason",
    [
        ("requests", "no version specified"),
        ("requests>=2.0", "not an exact pin (>=2.0)"),
        ("requests~=2.31", "not an exact pin (~=2.31)"),
        ("requests<3", "not an exact pin (<3)"),
        ("requests>=2,<3", "not an exact pin (>=2,<3)"),
        ("requests!=2.0", "not an exact pin (!=2.0)"),
        ("requests==2.*", "not an exact pin (==2.*)"),
        ("requests===2.0", "not an exact pin (===2.0)"),
        ("requests[socks]", "no version specified"),
    ],
)
def test_unpinned(line, reason):
    req = parse_requirements_text(line)[0]
    assert (req.status, req.reason, req.version) == ("unpinned", reason, None)


# --- skipped cases ---------------------------------------------------------

@pytest.mark.parametrize(
    "line, reason_start",
    [
        ("-r requirements_test.txt", "includes another file"),
        ("--requirement=other.txt", "includes another file"),
        ("-c constraints.txt", "constraints file"),
        ("-e .", "editable install"),
        ("-e git+https://github.com/x/y.git#egg=y", "editable install"),
        ("--index-url https://pypi.org/simple", "pip option line"),
        ("git+https://github.com/x/y.git", "URL requirement"),
        ("https://example.com/pkg-1.0.tar.gz", "URL requirement"),
        ("mypkg @ https://example.com/mypkg.zip", "direct reference"),
        ("mypkg@file:///tmp/mypkg", "direct reference"),
        ("./libs/mypkg", "local path"),
        ("../shared", "local path"),
        ("libs/mypkg", "local path"),
        ("mypkg-1.0-py3-none-any.whl", "local archive file"),
        ("django 3.2", "could not parse"),
        ("flask==", "could not parse"),
        ("!!!", "could not parse"),
    ],
)
def test_skipped(line, reason_start):
    req = parse_requirements_text(line)[0]
    assert req.status == "skipped"
    assert req.reason.startswith(reason_start)


def test_mixed_file_keeps_order_and_line_numbers():
    text = "# header\nflask==2.0.0\n\n-r base.txt\nrequests>=2\n"
    reqs = parse_requirements_text(text)
    assert [(r.name, r.status, r.line_number) for r in reqs] == [
        ("flask", None, 2),
        ("-r base.txt", "skipped", 4),
        ("requests", "unpinned", 5),
    ]
