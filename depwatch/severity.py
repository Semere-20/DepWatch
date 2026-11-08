"""Decide how severe each vulnerability is, and merge duplicate advisories.

Why this file exists:
    OSV records come from many sources and do not all describe severity the same
    way. We apply three rules, in order, and record which rule was used
    (`severity_source`) so every ranking can be explained:

        1. cvss_v3        - the record has a CVSS v3.x vector -> compute the score
                            with our own calculator (cvss.py) and map it to a band.
        2. advisory_label - otherwise, use the advisory's own label
                            (database_specific.severity), e.g. "HIGH".
                            "MODERATE" (GitHub's word) is mapped to "Medium".
        3. none           - otherwise the severity is "Unknown". Unknown findings
                            are shown and ranked last, never dropped.

It also merges aliases: OSV often returns the same flaw twice for a PyPI package
(e.g. GHSA-xxxx from GitHub and PYSEC-yyyy from the Python advisory database),
and each lists the other as an alias. Counting both would double the numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from depwatch.cvss import base_score, score_to_level
from depwatch.parser import normalize_name

# Severity levels from most to least severe. The position is the sort rank.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]
SEVERITY_RANK = {level: index for index, level in enumerate(SEVERITY_ORDER)}

# How advisory labels map to our levels. Anything not listed -> no label.
LABEL_TO_LEVEL = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MODERATE": "Medium",  # GitHub Security Advisories use "MODERATE"
    "MEDIUM": "Medium",
    "LOW": "Low",
}

# Which severity source we trust most when choosing between duplicate advisories.
SOURCE_PREFERENCE = {"cvss_v3": 0, "advisory_label": 1, "none": 2}


@dataclass
class Severity:
    """The result of rating one vulnerability.

    Attributes:
        level: "Critical", "High", "Medium", "Low" or "Unknown".
        score: The CVSS base score if we calculated one, else None.
        source: "cvss_v3", "advisory_label" or "none" (which rule decided).
    """

    level: str
    score: float | None
    source: str


@dataclass
class Finding:
    """One vulnerability affecting one package, after alias merging.

    Attributes:
        vuln_id: The OSV id we kept as the main one (e.g. "GHSA-xxxx").
        aliases: All other ids for the same flaw (CVE, PYSEC, GHSA...), sorted.
        summary: One-line description from the advisory ("" if missing).
        severity: The Severity rating.
        fixed_versions: Versions that fix it, e.g. ["3.2.19", "4.1.11"].
    """

    vuln_id: str
    aliases: list[str]
    summary: str
    severity: Severity
    fixed_versions: list[str] = field(default_factory=list)


def find_cvss_v3_vector(vuln: dict) -> str | None:
    """Return the first CVSS v3 vector found in an OSV record, or None.

    OSV puts severity in a top-level "severity" list, and sometimes inside each
    "affected" entry instead. Each item looks like:
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}

    Args:
        vuln: One OSV vulnerability record.

    Returns:
        The vector string, or None if there is no CVSS v3 entry.
    """
    # Build one list of severity entries: top-level first, then per-affected.
    entries = list(vuln.get("severity") or [])
    for affected in vuln.get("affected") or []:
        if isinstance(affected, dict):
            entries.extend(affected.get("severity") or [])

    for entry in entries:
        if isinstance(entry, dict) and entry.get("type") == "CVSS_V3" and isinstance(entry.get("score"), str):
            return entry["score"]
    return None


def label_level(vuln: dict) -> str | None:
    """Return our level for the advisory's own severity label, or None.

    Args:
        vuln: One OSV vulnerability record.

    Returns:
        "Critical"/"High"/"Medium"/"Low", or None if there is no usable label.
    """
    database_specific = vuln.get("database_specific")
    if not isinstance(database_specific, dict):
        return None
    label = database_specific.get("severity")
    if not isinstance(label, str):
        return None
    return LABEL_TO_LEVEL.get(label.strip().upper())


def assess_severity(vuln: dict) -> Severity:
    """Rate one OSV record using the three rules (cvss_v3 -> advisory_label -> none).

    Args:
        vuln: One OSV vulnerability record.

    Returns:
        A Severity with level, score and source.
    """
    # Rule 1: CVSS v3 vector -> our own calculator.
    vector = find_cvss_v3_vector(vuln)
    if vector:
        try:
            score = base_score(vector)
        except ValueError:
            score = None  # broken vector: ignore it and fall through to rule 2
        if score is not None:
            level = score_to_level(score)
            if level is not None:  # a 0.0 score has no band, so fall through
                return Severity(level, score, "cvss_v3")

    # Rule 2: the advisory's own label.
    level = label_level(vuln)
    if level is not None:
        return Severity(level, None, "advisory_label")

    # Rule 3: nothing usable.
    return Severity("Unknown", None, "none")


def fixed_versions(vuln: dict, package_name: str) -> list[str]:
    """List the versions that fix this vulnerability for one package.

    OSV describes affected versions as "events": {"introduced": "1.0"} then
    {"fixed": "1.5"}. We collect every "fixed" value for our package.

    Args:
        vuln: One OSV vulnerability record.
        package_name: Normalized package name we are scanning.

    Returns:
        Fixed versions in the order they appear, without duplicates.
        An empty list means OSV lists no fix.
    """
    fixes: list[str] = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        package = package if isinstance(package, dict) else {}
        # Skip entries about a different package (records can cover several).
        if package.get("name") and normalize_name(str(package["name"])) != package_name:
            continue
        for version_range in affected.get("ranges") or []:
            if not isinstance(version_range, dict):
                continue  # malformed range: ignore it rather than crash
            if version_range.get("type") == "GIT":
                continue  # GIT ranges list commit hashes, not versions you can pip install
            for event in version_range.get("events") or []:
                fixed = event.get("fixed") if isinstance(event, dict) else None
                if fixed and fixed not in fixes:
                    fixes.append(str(fixed))
    return fixes


def group_aliases(vulns: list[dict]) -> list[list[dict]]:
    """Group OSV records that describe the same flaw (they share an id or alias).

    Example: GHSA-1 has aliases [CVE-9, PYSEC-2]; PYSEC-2 has aliases [CVE-9, GHSA-1].
    They share ids, so they end up in one group.

    Args:
        vulns: OSV records for one package.

    Returns:
        A list of groups; each group is a list of records, in first-seen order.
    """
    groups: list[tuple[set[str], list[dict]]] = []  # (all ids in group, records)
    for vuln in vulns:
        ids = {str(vuln.get("id", ""))} | {str(a) for a in vuln.get("aliases") or []}
        ids.discard("")
        # Find every existing group that shares at least one id with this record.
        matching = [g for g in groups if g[0] & ids]
        if not matching:
            groups.append((ids, [vuln]))
            continue
        # Merge all matching groups (and this record) into the first one.
        target_ids, target_records = matching[0]
        target_ids |= ids
        target_records.append(vuln)
        for other in matching[1:]:
            target_ids |= other[0]
            target_records.extend(other[1])
            groups.remove(other)
    return [records for _, records in groups]


def best_record(records: list[tuple[dict, Severity]]) -> tuple[dict, Severity]:
    """Pick the record with the most trustworthy severity from a group of aliases.

    Order: better source (cvss_v3 > advisory_label > none), then higher score,
    then alphabetical id (so the choice is always the same for the same input).

    Args:
        records: (OSV record, its Severity) pairs for one flaw.

    Returns:
        The chosen (record, Severity) pair.
    """

    def sort_key(pair: tuple[dict, Severity]) -> tuple[int, float, str]:
        vuln, severity = pair
        score = severity.score if severity.score is not None else -1.0
        return (SOURCE_PREFERENCE[severity.source], -score, str(vuln.get("id", "")))

    return sorted(records, key=sort_key)[0]


def build_findings(vulns: list[dict], package_name: str) -> list[Finding]:
    """Turn raw OSV records for one package into merged, rated Findings.

    Args:
        vulns: OSV records returned for one package version.
        package_name: Normalized package name.

    Returns:
        One Finding per distinct flaw.
    """
    findings: list[Finding] = []
    for group in group_aliases(vulns):
        rated = [(vuln, assess_severity(vuln)) for vuln in group]
        chosen, severity = best_record(rated)
        chosen_id = str(chosen.get("id") or "(no id)")

        # Collect every other id/alias in the group so nothing is lost.
        all_ids: set[str] = set()
        fixes: list[str] = []
        for vuln, _ in rated:
            all_ids.add(str(vuln.get("id", "")))
            all_ids.update(str(a) for a in vuln.get("aliases") or [])
            for fix in fixed_versions(vuln, package_name):
                if fix not in fixes:
                    fixes.append(fix)
        all_ids.discard("")
        all_ids.discard(chosen_id)

        summary = chosen.get("summary") or chosen.get("details") or ""
        summary = str(summary).strip().splitlines()[0] if str(summary).strip() else ""

        findings.append(Finding(chosen_id, sorted(all_ids), summary, severity, fixes))
    return findings
