"""Connect the pieces: parsed requirements -> OSV lookups -> rated findings.

Why this file exists:
    The parser, the OSV client and the severity rules each do one job. This module
    runs them in order for every package and gives each package exactly ONE status:

        vulnerable      OSV answered and listed at least one vulnerability
        no_known_vulns  OSV answered and listed none (for this exact version)
        unpinned        no exact version in requirements.txt, not scanned
        skipped         a line we do not scan (include, URL, path, conflict...)
        error           we could not get a trustworthy answer from OSV
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from depwatch.osv_client import OSVError, make_session, query_package
from depwatch.parser import Requirement
from depwatch.severity import Finding, build_findings

STATUS_VULNERABLE = "vulnerable"
STATUS_CLEAN = "no_known_vulns"
STATUS_ERROR = "error"

# Every status, in the order we print them in the summary.
ALL_STATUSES = ["vulnerable", "no_known_vulns", "unpinned", "skipped", "error"]


@dataclass
class PackageResult:
    """The outcome for one requirement.

    Attributes:
        name: Normalized package name (or line text for nameless skipped lines).
        version: Pinned version, or None.
        status: One of ALL_STATUSES.
        reason: Short explanation of the status.
        line_number: Line in requirements.txt where it appeared.
        findings: Vulnerabilities found (only for status "vulnerable").
    """

    name: str
    version: str | None
    status: str
    reason: str
    line_number: int
    findings: list[Finding] = field(default_factory=list)


def scan_one(
    requirement: Requirement,
    session: Any,
    timeout: float,
    sleep: Callable[[float], None],
) -> PackageResult:
    """Scan a single requirement and return its result.

    Args:
        requirement: A parsed requirement.
        session: requests.Session (or a fake in tests).
        timeout: Seconds per OSV request.
        sleep: Wait function for retries.

    Returns:
        A PackageResult with exactly one status.
    """
    # Unpinned and skipped entries were already decided by the parser.
    if requirement.status is not None or requirement.version is None:
        return PackageResult(
            requirement.name,
            requirement.version,
            requirement.status or "skipped",
            requirement.reason,
            requirement.line_number,
        )

    try:
        vulns = query_package(session, requirement.name, requirement.version, timeout, sleep)
    except OSVError as exc:
        # A failed lookup is an ERROR, never "no vulnerabilities".
        return PackageResult(requirement.name, requirement.version, STATUS_ERROR, str(exc), requirement.line_number)

    if not vulns:
        return PackageResult(
            requirement.name,
            requirement.version,
            STATUS_CLEAN,
            "OSV lists no known vulnerabilities for this version",
            requirement.line_number,
        )

    findings = build_findings(vulns, requirement.name)
    reason = f"{len(findings)} known vulnerabilit{'y' if len(findings) == 1 else 'ies'}"
    return PackageResult(
        requirement.name, requirement.version, STATUS_VULNERABLE, reason, requirement.line_number, findings
    )


def scan_requirements(
    requirements: list[Requirement],
    session: Any | None = None,
    timeout: float = 10,
    sleep: Callable[[float], None] = time.sleep,
    on_progress: Callable[[str], None] | None = None,
) -> list[PackageResult]:
    """Scan every requirement, one at a time, and return all results in order.

    Args:
        requirements: Output of the parser.
        session: Optional session; a real one is created if not given.
        timeout: Seconds per OSV request.
        sleep: Wait function for retries (tests pass a no-op).
        on_progress: Optional function called with a progress line per package.

    Returns:
        One PackageResult per requirement.
    """
    if session is None:
        session = make_session()

    results: list[PackageResult] = []
    total = len(requirements)
    for index, requirement in enumerate(requirements, start=1):
        result = scan_one(requirement, session, timeout, sleep)
        results.append(result)
        if on_progress:
            label = f"{result.name}=={result.version}" if result.version else result.name
            on_progress(f"  [{index}/{total}] {label}: {result.status} ({result.reason})")
    return results
