"""Turn scan results into a sorted table, a summary, CSV/JSON files, a chart and an exit code.

Why this file exists:
    The scanner produces Python objects. People need something they can read and
    machines need something they can parse. This module uses pandas to build one
    table (a DataFrame) and then writes it out in several formats.

Sort order of the report:
    1. Findings by severity level (Critical, High, Medium, Low, Unknown),
       then by score (highest first; no score goes last), then package name.
    2. After the findings, the packages without findings, grouped by status
       (no_known_vulns, unpinned, skipped, error), then by package name.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # draw to files only; no window needed (works on servers and in CI)
import matplotlib.pyplot as plt  # noqa: E402  (must come after matplotlib.use)
import pandas as pd  # noqa: E402

from depwatch.scanner import ALL_STATUSES, STATUS_ERROR, STATUS_VULNERABLE, PackageResult  # noqa: E402
from depwatch.severity import SEVERITY_ORDER, SEVERITY_RANK  # noqa: E402

# Columns of the report, in the order they appear in the CSV.
COLUMNS = [
    "package",
    "version",
    "status",
    "severity",
    "score",
    "severity_source",
    "vuln_id",
    "aliases",
    "fixed_versions",
    "summary",
    "reason",
    "line",
]

# Bar colors for the chart, from most to least severe.
CHART_COLORS = {
    "Critical": "#8b0000",
    "High": "#d9480f",
    "Medium": "#f2a900",
    "Low": "#4c8bf5",
    "Unknown": "#9e9e9e",
}

# Exit codes (also documented in the README).
EXIT_OK = 0
EXIT_VULNERABLE = 1
EXIT_INCOMPLETE = 2


def build_dataframe(results: list[PackageResult]) -> pd.DataFrame:
    """Build the full, sorted report table.

    One row per vulnerability for vulnerable packages, and one row per package
    for every other status (so unpinned, skipped and error packages are visible).

    Args:
        results: Output of scanner.scan_requirements.

    Returns:
        A pandas DataFrame with the columns in COLUMNS, sorted (see module doc).
    """
    rows: list[dict] = []
    for result in results:
        base = {
            "package": result.name,
            "version": result.version or "",
            "status": result.status,
            "reason": result.reason,
            "line": result.line_number,
        }
        if result.status == STATUS_VULNERABLE:
            for finding in result.findings:
                rows.append(
                    {
                        **base,  # copy the package columns into this row
                        "severity": finding.severity.level,
                        "score": finding.severity.score,
                        "severity_source": finding.severity.source,
                        "vuln_id": finding.vuln_id,
                        "aliases": "; ".join(finding.aliases),
                        "fixed_versions": "; ".join(finding.fixed_versions) or "no fix listed",
                        "summary": finding.summary,
                    }
                )
        else:
            rows.append({**base, "severity": "", "score": None, "severity_source": "",
                         "vuln_id": "", "aliases": "", "fixed_versions": "", "summary": ""})

    df = pd.DataFrame(rows, columns=COLUMNS)
    if df.empty:
        return df
    df["score"] = pd.to_numeric(df["score"])  # None becomes NaN ("not a number")

    # Helper column for sorting: findings get 0-4 from their severity, other rows
    # come after them (5 + their position in ALL_STATUSES).
    df["_rank"] = [
        SEVERITY_RANK[sev] if status == STATUS_VULNERABLE else len(SEVERITY_ORDER) + ALL_STATUSES.index(status)
        for sev, status in zip(df["severity"], df["status"])
    ]
    df = df.sort_values(
        by=["_rank", "score", "package"],
        ascending=[True, False, True],  # score: highest first
        na_position="last",  # rows without a score go after rows with one
        kind="stable",  # keep the original order when everything else is equal
    )
    return df.drop(columns="_rank").reset_index(drop=True)


def filter_by_min_severity(df: pd.DataFrame, min_severity: str) -> pd.DataFrame:
    """Hide findings below a chosen severity (display only).

    Findings with "Unknown" severity are never hidden, because we cannot say they
    are low. Rows that are not findings (unpinned, errors, ...) are always kept.

    Args:
        df: The full report table.
        min_severity: "low", "medium", "high" or "critical".

    Returns:
        A filtered copy of the table.
    """
    if df.empty:
        return df
    threshold = SEVERITY_RANK[min_severity.capitalize()]
    keep = [
        status != STATUS_VULNERABLE or sev == "Unknown" or SEVERITY_RANK[sev] <= threshold
        for sev, status in zip(df["severity"], df["status"])
    ]
    return df[keep].reset_index(drop=True)


def status_counts(results: list[PackageResult]) -> dict[str, int]:
    """Count packages per status, including statuses with zero packages.

    Args:
        results: Scan results.

    Returns:
        e.g. {"vulnerable": 2, "no_known_vulns": 5, "unpinned": 1, "skipped": 0, "error": 0}
    """
    counter = Counter(result.status for result in results)
    return {status: counter.get(status, 0) for status in ALL_STATUSES}


def severity_counts(results: list[PackageResult]) -> dict[str, int]:
    """Count findings per severity level (all findings, not filtered).

    Args:
        results: Scan results.

    Returns:
        e.g. {"Critical": 1, "High": 3, "Medium": 0, "Low": 0, "Unknown": 2}
    """
    counter = Counter(f.severity.level for r in results for f in r.findings)
    return {level: counter.get(level, 0) for level in SEVERITY_ORDER}


def is_incomplete(results: list[PackageResult]) -> bool:
    """Return True if at least one package could not be checked (status "error")."""
    return any(result.status == STATUS_ERROR for result in results)


def compute_exit_code(results: list[PackageResult], fail_on: str) -> int:
    """Choose the process exit code.

    Rules (checked in this order):
        2 - the scan is incomplete (any package has status "error").
        1 - a finding is at or above `fail_on` ("Unknown" findings never count,
            because we cannot know their level).
        0 - otherwise. `fail_on="none"` means vulnerabilities never fail the run.

    Args:
        results: Scan results.
        fail_on: "low", "medium", "high", "critical" or "none".

    Returns:
        0, 1 or 2.
    """
    if is_incomplete(results):
        return EXIT_INCOMPLETE
    if fail_on == "none":
        return EXIT_OK
    threshold = SEVERITY_RANK[fail_on.capitalize()]
    for result in results:
        for finding in result.findings:
            level = finding.severity.level
            if level != "Unknown" and SEVERITY_RANK[level] <= threshold:
                return EXIT_VULNERABLE
    return EXIT_OK


def format_summary(results: list[PackageResult]) -> str:
    """Build the human-readable summary printed at the end of a scan.

    Args:
        results: Scan results.

    Returns:
        A multi-line string.
    """
    counts = status_counts(results)
    lines = [f"Summary ({len(results)} packages/lines):"]
    for status, count in counts.items():
        lines.append(f"  {status:<15} {count}")
    sev = severity_counts(results)
    lines.append("Findings by severity: " + ", ".join(f"{level} {n}" for level, n in sev.items()))
    not_scanned = counts["unpinned"] + counts["skipped"]
    if not_scanned:
        lines.append(f"Note: {not_scanned} entries were not scanned (unpinned/skipped); see the report for reasons.")
    checked = counts["vulnerable"] + counts["no_known_vulns"]  # packages OSV actually answered for
    if is_incomplete(results):
        lines.append(
            f"SCAN INCOMPLETE: {counts['error']} package(s) could not be checked. "
            "Do not treat this as a clean result."
        )
    elif checked == 0:
        lines.append(
            "WARNING: no package was checked against OSV (nothing was pinned with ==). "
            "This is not a clean result."
        )
    else:
        lines.append(f"Scan complete: all {checked} pinned package(s) got an answer from OSV.")
    return "\n".join(lines)


def shorten(text: str, limit: int) -> str:
    """Cut text to `limit` characters, ending with "..." if it was cut.

    Args:
        text: Any string.
        limit: Maximum length of the result.

    Returns:
        The original text, or a shortened version ending in "...".
    """
    return text if len(text) <= limit else text[: limit - 3] + "..."


def format_table(df: pd.DataFrame, max_summary: int = 60, max_fixed: int = 24) -> str:
    """Render the report as a plain-text table for the terminal.

    Long text is shortened so the table stays readable; the CSV/JSON keep the full text.

    Args:
        df: The (possibly filtered) report table.
        max_summary: Long summaries are cut to this many characters.
        max_fixed: Long fixed-version lists are cut to this many characters.

    Returns:
        The table as a string, or a short message if there are no rows.
    """
    if df.empty:
        return "(no rows to show)"
    view = df[["package", "version", "status", "severity", "score", "vuln_id", "fixed_versions", "summary"]].copy()
    view["score"] = [f"{s:.1f}" if pd.notna(s) else "" for s in view["score"]]
    view["fixed_versions"] = [shorten(s, max_fixed) for s in view["fixed_versions"]]
    view["summary"] = [shorten(s, max_summary) for s in view["summary"]]
    return view.to_string(index=False)


def write_csv(df: pd.DataFrame, path: Path) -> None:
    """Write the report table to a CSV file (opens in Excel / Google Sheets).

    Args:
        df: Report table.
        path: Destination file.
    """
    df.to_csv(path, index=False, columns=COLUMNS)


def write_json(df: pd.DataFrame, results: list[PackageResult], path: Path, scanned_file: str, version: str) -> None:
    """Write the report and summary as JSON (easy for other programs to read).

    Args:
        df: Report table (possibly filtered).
        results: All scan results (used for the summary counts).
        path: Destination file.
        scanned_file: The requirements file that was scanned.
        version: DepWatch version.
    """
    # pandas uses NaN for "no value"; JSON should use null instead.
    records = df.astype(object).where(df.notna(), None).to_dict(orient="records")
    document = {
        "tool": "depwatch",
        "version": version,
        "scanned_file": scanned_file,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan_complete": not is_incomplete(results),
        "status_counts": status_counts(results),
        "severity_counts": severity_counts(results),
        "rows": records,
    }
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")


def make_chart(df: pd.DataFrame, path: Path, title: str) -> tuple[bool, str]:
    """Draw a bar chart of findings per severity level and save it as PNG.

    Uses pandas groupby: take only the vulnerability rows, group them by
    "severity", and count the rows in each group.

    Args:
        df: Report table (possibly filtered).
        path: Destination PNG file.
        title: Chart title.

    Returns:
        (True, message) if the chart was saved, (False, message) if skipped
        because there were no findings to draw.
    """
    findings = df[df["status"] == STATUS_VULNERABLE] if not df.empty else df
    if findings.empty:
        return False, "Chart skipped: no vulnerabilities to plot."

    # groupby("severity").size() -> how many rows per severity level.
    # reindex puts the levels in our fixed order and fills missing ones with 0.
    counts = findings.groupby("severity").size().reindex(SEVERITY_ORDER, fill_value=0)

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(counts.index, counts.values, color=[CHART_COLORS[level] for level in counts.index])
    ax.bar_label(bars)  # write the number on top of each bar
    ax.set_title(title)
    ax.set_xlabel("Severity")
    ax.set_ylabel("Number of vulnerabilities")
    ax.yaxis.get_major_locator().set_params(integer=True)  # whole numbers only on the y axis
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)  # free memory; important when making many charts
    return True, f"Chart saved: {path}"
