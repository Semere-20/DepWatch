"""The command-line interface: `python -m depwatch scan requirements.txt`.

Why this file exists:
    It reads the user's options (with argparse), runs the parser, scanner and
    report steps in order, prints the results, and returns the exit code.
    It contains no scanning logic of its own, which keeps it easy to test.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from depwatch import __version__
from depwatch.parser import RequirementsError, parse_requirements_file
from depwatch.report import (
    EXIT_INCOMPLETE,
    build_dataframe,
    compute_exit_code,
    filter_by_min_severity,
    format_summary,
    format_table,
    make_chart,
    write_csv,
    write_json,
)
from depwatch.scanner import scan_requirements

SEVERITY_CHOICES = ["low", "medium", "high", "critical"]

EPILOG = """\
examples:
  python -m depwatch scan requirements.txt
  python -m depwatch scan requirements.txt --fail-on critical --output-dir out/
  python -m depwatch scan requirements.txt --format table --no-chart

exit codes:
  0  scan finished, no vulnerability at or above --fail-on
  1  at least one vulnerability at or above --fail-on
  2  scan incomplete (a package could not be checked) or bad input
"""


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser with the `scan` subcommand and all options.

    Returns:
        A configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="depwatch",
        description="Check a requirements.txt against the OSV vulnerability database "
        "and rank what it finds by severity.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,  # keep the epilog's line breaks
    )
    parser.add_argument("--version", action="version", version=f"depwatch {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True, metavar="command")
    scan = subparsers.add_parser(
        "scan",
        help="scan a requirements file",
        description="Scan a requirements file. Only exact pins (==) are checked; "
        "everything else is listed as unpinned or skipped with a reason.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument("requirements_file", help="path to the requirements.txt to scan")
    scan.add_argument(
        "--output-dir", default="reports", help="folder for report.csv, report.json and chart.png (default: reports/)"
    )
    scan.add_argument(
        "--format",
        choices=["table", "csv", "json", "all"],
        default="all",
        help="what to produce: print a table, write CSV, write JSON, or all three (default: all)",
    )
    scan.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        default="low",
        help="hide findings below this level in the table, files and chart "
        "(Unknown is always shown; does not change the exit code) (default: low)",
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES + ["none"],
        default="high",
        help="exit with code 1 if any finding is at or above this level; 'none' never fails (default: high)",
    )
    scan.add_argument(
        "--timeout", type=positive_float, default=10.0, help="seconds to wait for each OSV request (default: 10)"
    )
    scan.add_argument("--no-chart", action="store_true", help="do not create chart.png")
    return parser


def positive_float(text: str) -> float:
    """argparse type: accept only numbers greater than zero (used for --timeout).

    Args:
        text: The raw command-line value.

    Returns:
        The value as a float.

    Raises:
        argparse.ArgumentTypeError: if the value is not a positive number.
    """
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def run_scan(args: argparse.Namespace, session: Any = None) -> int:
    """Run the full scan flow for parsed arguments and return the exit code.

    Args:
        args: Parsed command-line arguments.
        session: Optional session object (tests pass a fake one).

    Returns:
        The exit code (0, 1 or 2).
    """
    # 1) Parse the requirements file.
    try:
        requirements = parse_requirements_file(args.requirements_file)
    except RequirementsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INCOMPLETE

    print(f"DepWatch {__version__}: scanning {args.requirements_file} ({len(requirements)} entries)")
    if not requirements:
        print("Nothing to scan: the file has no packages (only blank lines or comments).")

    # 2) Scan every package against OSV.
    results = scan_requirements(requirements, session=session, timeout=args.timeout, on_progress=print)

    # 3) Build the report and apply the display filter.
    full = build_dataframe(results)
    shown = filter_by_min_severity(full, args.min_severity)

    # 4) Write outputs.
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)  # create the folder if needed
    print()
    if args.format in ("table", "all"):
        print(format_table(shown))
        print()
    if args.format in ("csv", "all"):
        write_csv(shown, output_dir / "report.csv")
        print(f"CSV saved: {output_dir / 'report.csv'}")
    if args.format in ("json", "all"):
        write_json(shown, results, output_dir / "report.json", str(args.requirements_file), __version__)
        print(f"JSON saved: {output_dir / 'report.json'}")
    if not args.no_chart:
        req_path = Path(args.requirements_file)
        # Show the folder too ("pygoat/requirements.txt"): most files are just called requirements.txt.
        title = f"DepWatch: {req_path.parent.name}/{req_path.name}" if req_path.parent.name else f"DepWatch: {req_path.name}"
        _, message = make_chart(shown, output_dir / "chart.png", title)
        print(message)

    # 5) Summary and exit code.
    print()
    print(format_summary(results))
    exit_code = compute_exit_code(results, args.fail_on)
    print(f"Exit code: {exit_code}")
    return exit_code


def main(argv: list[str] | None = None, session: Any = None) -> int:
    """Program entry point.

    Args:
        argv: Command-line arguments (None means use sys.argv). Tests pass a list.
        session: Optional session object for tests.

    Returns:
        The exit code. argparse itself exits with code 2 for invalid arguments,
        which matches our "bad input" code.
    """
    args = build_arg_parser().parse_args(argv)
    if args.command == "scan":
        return run_scan(args, session=session)
    return EXIT_INCOMPLETE  # pragma: no cover  (argparse requires a command)
