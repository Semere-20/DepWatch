"""Read a requirements.txt file and turn it into a list of Requirement objects.

Why this file exists:
    A requirements.txt can contain much more than "package==version". It can have
    comments, blank lines, version ranges, links to other files, URLs, and so on.
    DepWatch can only look up a vulnerability when it knows the EXACT version, so
    this module decides, line by line, which packages can be scanned and which
    cannot, and writes down a short reason for every package it cannot scan.

The rule we follow: only an exact pin (`==1.2.3`) counts as a version. We never
guess a version and never look at what is installed on this computer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Status values the parser can assign. (The scanner adds the other three:
# "vulnerable", "no_known_vulns" and "error".)
# ---------------------------------------------------------------------------
STATUS_UNPINNED = "unpinned"  # a real package, but no exact version (e.g. "requests>=2.0")
STATUS_SKIPPED = "skipped"  # a line we deliberately do not scan (e.g. "-r other.txt")

# A package name per PEP 508: starts and ends with a letter/digit, may contain . _ -
# Example matches: "django", "my_pkg", "zope.interface"
NAME_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"

# Splits a requirement into: name, optional [extras], and the rest (the version part).
#   "requests[security] >= 2.0"  ->  name="requests", extras="[security]", rest=">= 2.0"
REQUIREMENT_RE = re.compile(
    rf"^(?P<name>{NAME_PATTERN})\s*(?P<extras>\[[^\]]*\])?\s*(?P<rest>.*)$"
)

# An exact pin: "==" followed by one version with no wildcard and nothing after it.
#   "==2.31.0" matches,  "==2.*" does not,  "==1.0,<2" does not.
EXACT_PIN_RE = re.compile(r"^==\s*(?P<version>[A-Za-z0-9.!+_-]+)$")

# Version operators that mean "a range of versions" rather than one exact version.
RANGE_OPERATORS = ("===", "==", "!=", ">=", "<=", "~=", ">", "<")

# File endings that mean "this is a file on disk, not a package name".
LOCAL_FILE_ENDINGS = (".whl", ".tar.gz", ".zip", ".tar.bz2", ".tgz")


class RequirementsError(Exception):
    """Raised when the requirements file itself cannot be read (bad input -> exit code 2)."""


@dataclass
class Requirement:
    """One package (or one unscannable line) from requirements.txt.

    Attributes:
        name: Normalized package name (e.g. "django"). For a skipped line that has
            no package name (like "-r other.txt"), this is the line text itself.
        version: The exact pinned version, or None if the package is not pinned.
        status: None means "ready to scan". Otherwise "unpinned" or "skipped".
        reason: Short human explanation when status is unpinned/skipped.
        line_number: Where the package first appeared (helps the user find it).
    """

    name: str
    version: str | None
    status: str | None
    reason: str
    line_number: int


def normalize_name(name: str) -> str:
    """Return the standard form of a package name (PEP 503).

    PyPI treats "Django", "django", "My_Pkg" and "my-pkg" as the same package.
    We lowercase the name and turn every run of "-", "_" or "." into a single "-",
    so duplicates written differently are recognized as one package.

    Args:
        name: The package name as written in the file.

    Returns:
        The normalized name, e.g. normalize_name("My_Pkg") == "my-pkg".
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def strip_comment(line: str) -> str:
    """Remove a comment from a line and return what is left, trimmed.

    pip's rule: "#" starts a comment if it is at the start of the line or has
    whitespace before it. A "#" glued to other text (like in a URL "...#egg=x")
    is NOT a comment, so we leave it alone.

    Args:
        line: One line from the file.

    Returns:
        The line without its comment, with surrounding spaces removed.
    """
    # (^|\s)# means: a "#" at the very start, or a "#" right after a space/tab.
    return re.sub(r"(^|\s)#.*$", "", line).strip()


def join_continuation_lines(text: str) -> list[tuple[int, str]]:
    """Split file text into logical lines, joining lines that end with a backslash.

    pip allows a long line to continue on the next line by ending it with "\\".
    Tools like pip-compile use this for hashes. We glue those pieces together.

    Args:
        text: The whole file as one string.

    Returns:
        A list of (line_number, line_text) pairs. line_number is where the
        logical line starts (1-based), so error messages point to the right place.
    """
    logical_lines: list[tuple[int, str]] = []
    buffer = ""  # text collected so far for the current logical line
    start_line = 0  # line number where the current logical line started

    for number, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start_line = number  # a new logical line starts here
        if raw.rstrip().endswith("\\"):
            # Drop the trailing backslash and keep collecting.
            buffer += raw.rstrip()[:-1] + " "
            continue
        logical_lines.append((start_line, buffer + raw))
        buffer = ""

    if buffer:  # file ended with a dangling backslash; keep what we have
        logical_lines.append((start_line, buffer))
    return logical_lines


def classify_option_line(line: str) -> str:
    """Return the skip reason for a line that starts with "-" (a pip option).

    Args:
        line: A comment-free line that starts with "-".

    Returns:
        A short reason string explaining why the line is not scanned.
    """
    # Look only at the first word, e.g. "-r" from "-r requirements_test.txt".
    first_word = line.split()[0]
    if first_word in ("-r", "--requirement") or first_word.startswith(("-r", "--requirement=")):
        return "includes another file (-r); scan that file separately"
    if first_word in ("-c", "--constraint") or first_word.startswith(("-c", "--constraint=")):
        return "constraints file (-c); scan that file separately"
    if first_word in ("-e", "--editable") or first_word.startswith(("-e", "--editable=")):
        return "editable install (-e); no released version to check"
    return "pip option line, not a package"


def looks_like_url_or_path(line: str) -> str | None:
    """Return a skip reason if the line is a URL, a direct reference or a local path.

    Args:
        line: A comment-free, marker-free requirement line.

    Returns:
        A reason string if the line should be skipped, otherwise None.
    """
    if " @ " in line or re.match(rf"^{NAME_PATTERN}\s*(\[[^\]]*\])?\s*@", line):
        # PEP 508 direct reference, e.g. "mypkg @ https://example.com/mypkg.zip"
        return "direct reference (name @ url); no released version to check"
    if "://" in line:
        return "URL requirement; no released version to check"
    if line.startswith((".", "/", "~")) or "\\" in line or "/" in line:
        return "local path; no released version to check"
    if line.lower().endswith(LOCAL_FILE_ENDINGS):
        return "local archive file; no released version to check"
    return None


def parse_line(line: str, line_number: int) -> Requirement | None:
    """Turn one logical line into a Requirement, or None if the line is empty.

    Args:
        line: One logical line of the file (comments still included).
        line_number: The 1-based line number, kept for the report.

    Returns:
        A Requirement (pinned, unpinned or skipped), or None for blank/comment lines.
    """
    text = strip_comment(line)
    if not text:
        return None  # blank line or a line that was only a comment

    # 1) pip options: -r, -c, -e, --index-url, ...
    if text.startswith("-"):
        return Requirement(text, None, STATUS_SKIPPED, classify_option_line(text), line_number)

    # 2) Cut off environment markers: 'pkg==1.0; python_version < "3.10"'.
    #    We still scan the package; the marker only says WHEN pip installs it.
    text = text.split(";", 1)[0].strip()

    # 3) Cut off per-requirement options such as "--hash=sha256:..." (pip-compile output).
    text = re.split(r"\s--", text, maxsplit=1)[0].strip()

    # 4) URLs, direct references and local paths cannot be looked up by version.
    url_reason = looks_like_url_or_path(text)
    if url_reason:
        return Requirement(text, None, STATUS_SKIPPED, url_reason, line_number)

    # 5) Split into name / extras / version part.
    match = REQUIREMENT_RE.match(text)
    if not match:
        return Requirement(text, None, STATUS_SKIPPED, "could not parse this line", line_number)

    name = normalize_name(match.group("name"))
    rest = match.group("rest").strip()  # the version specifier, e.g. "==2.0" or ">=1,<2"

    # 6) Decide pinned / unpinned / malformed.
    if not rest:
        return Requirement(name, None, STATUS_UNPINNED, "no version specified", line_number)

    pin = EXACT_PIN_RE.match(rest)
    if pin:
        return Requirement(name, pin.group("version"), None, "", line_number)

    if rest.startswith(RANGE_OPERATORS) and re.search(r"[A-Za-z0-9]", rest):
        # Some kind of range or wildcard: valid, but not one exact version.
        return Requirement(name, None, STATUS_UNPINNED, f"not an exact pin ({rest})", line_number)

    # Anything else, e.g. "django 3.2" or "flask==", is malformed.
    return Requirement(text, None, STATUS_SKIPPED, "could not parse this line", line_number)


def merge_duplicates(requirements: list[Requirement]) -> list[Requirement]:
    """Combine entries that refer to the same package, keeping the first position.

    Rules:
        - Same package pinned to the same version twice -> one entry.
        - Same package pinned to DIFFERENT versions -> "skipped" with reason
          "conflicting pins: a, b" (we refuse to pick one for the user).
        - Exactly one pinned version plus unpinned mentions -> the pinned one wins.
        - Never pinned -> keep the first entry.
        - Skipped lines with no package name (e.g. "-r x.txt") are never merged.

    Args:
        requirements: Entries in file order, possibly with duplicates.

    Returns:
        A new list with one entry per package, in order of first appearance.
    """
    groups: dict[str, list[Requirement]] = {}  # normalized name -> all its entries
    for req in requirements:
        groups.setdefault(req.name, []).append(req)  # dicts keep insertion order

    merged: list[Requirement] = []
    for name, entries in groups.items():
        first = entries[0]
        # Collect distinct pinned versions, in the order they appeared.
        pinned_versions: list[str] = []
        for entry in entries:
            if entry.version and entry.version not in pinned_versions:
                pinned_versions.append(entry.version)

        if len(pinned_versions) > 1:
            reason = "conflicting pins: " + ", ".join(pinned_versions)
            merged.append(Requirement(name, None, STATUS_SKIPPED, reason, first.line_number))
        elif len(pinned_versions) == 1:
            pinned_entry = next(e for e in entries if e.version == pinned_versions[0])
            merged.append(pinned_entry)
        else:
            merged.append(first)
    return merged


def parse_requirements_text(text: str) -> list[Requirement]:
    """Parse the text of a requirements file (already read into memory).

    Kept separate from file reading so tests can pass strings directly.

    Args:
        text: File contents. A leading UTF-8 BOM is removed if present.

    Returns:
        One Requirement per package / unscannable line, duplicates merged.
    """
    text = text.lstrip("﻿")  # BOM: an invisible marker some Windows editors add
    parsed: list[Requirement] = []
    for line_number, line in join_continuation_lines(text):
        requirement = parse_line(line, line_number)
        if requirement is not None:
            parsed.append(requirement)
    return merge_duplicates(parsed)


def parse_requirements_file(path: str | Path) -> list[Requirement]:
    """Read a requirements file from disk and parse it.

    Args:
        path: Path to the requirements.txt file.

    Returns:
        The parsed list of Requirement objects (may be empty).

    Raises:
        RequirementsError: if the file is missing, is a folder, or is not UTF-8 text.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise RequirementsError(f"requirements file not found: {file_path}")
    try:
        # "utf-8-sig" also strips a BOM; we strip it again in the text step for safety.
        text = file_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RequirementsError(f"file is not valid UTF-8 text: {file_path} ({exc})") from exc
    except OSError as exc:  # e.g. permission denied
        raise RequirementsError(f"could not read {file_path}: {exc}") from exc
    return parse_requirements_text(text)
