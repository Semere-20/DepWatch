"""Talk to the OSV vulnerability database (https://api.osv.dev).

Why this file exists:
    All network code lives here, in one place, so that:
      1. every way a request can fail is turned into one clear error (OSVError), and
      2. tests can replace the network with a fake "session" object.

The most important rule: a failed request must NEVER look like "no vulnerabilities".
`query_package` either returns a list of vulnerabilities (possibly empty, which
means OSV really answered "nothing known") or raises OSVError.
"""

from __future__ import annotations

import time
from typing import Any, Callable

import requests

# The OSV endpoint that answers "which vulnerabilities affect package X at version Y?"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# How many times to retry after a 429 (rate limit) or 5xx (server) response.
MAX_RETRIES = 3

# Never wait longer than this between retries, even if the server asks for more.
MAX_WAIT_SECONDS = 30

# OSV splits very long answers into pages. This is a safety stop so a buggy
# server can never make us loop forever.
MAX_PAGES = 20

# HTTP status codes that usually mean "try again later".
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class OSVError(Exception):
    """Any failure to get a trustworthy answer from OSV. The message is the reason."""


def backoff_seconds(attempt: int, retry_after_header: str | None) -> float:
    """Decide how long to wait before retry number `attempt` (0-based).

    If the server sent a Retry-After header with a number of seconds, we honor it
    (capped at MAX_WAIT_SECONDS). Otherwise we use exponential backoff: 1s, 2s, 4s.
    Waiting longer each time gives an overloaded server room to recover.

    Args:
        attempt: 0 for the first retry, 1 for the second, ...
        retry_after_header: The raw Retry-After header value, or None.

    Returns:
        Number of seconds to sleep.
    """
    if retry_after_header is not None:
        try:
            return min(float(retry_after_header), MAX_WAIT_SECONDS)
        except ValueError:
            pass  # Retry-After can also be a date; we just fall back to our own timing.
    return float(2**attempt)  # 2**0=1, 2**1=2, 2**2=4


def post_with_retries(
    session: Any,
    payload: dict,
    timeout: float,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Send one POST request to OSV, retrying on 429/5xx, and return the JSON body.

    Args:
        session: Anything with a requests-style `.post(url, json=..., timeout=...)`
            method. In real runs it is a requests.Session; in tests it is a fake.
        payload: The JSON body to send.
        timeout: Seconds to wait for the server before giving up.
        sleep: Function used to wait between retries (tests pass a no-op).

    Returns:
        The decoded JSON response, which must be a dict.

    Raises:
        OSVError: on timeout, connection error, HTTP error, rate limit after all
            retries, invalid JSON, or a response that is not a JSON object.
    """
    for attempt in range(MAX_RETRIES + 1):  # first try + MAX_RETRIES retries
        try:
            response = session.post(OSV_QUERY_URL, json=payload, timeout=timeout)
        except requests.Timeout as exc:
            raise OSVError(f"request timed out after {timeout}s") from exc
        except requests.ConnectionError as exc:
            raise OSVError(f"connection error: {exc.__class__.__name__}") from exc
        except requests.RequestException as exc:  # any other problem inside requests
            raise OSVError(f"request failed: {exc.__class__.__name__}") from exc

        status = response.status_code
        if status in RETRYABLE_STATUS_CODES and attempt < MAX_RETRIES:
            # Temporary problem: wait, then loop around and try again.
            sleep(backoff_seconds(attempt, response.headers.get("Retry-After")))
            continue

        if status == 429:
            raise OSVError(f"rate limited by OSV (HTTP 429) after {MAX_RETRIES} retries")
        if status >= 400:
            raise OSVError(f"OSV returned HTTP {status}")

        try:
            data = response.json()
        except ValueError as exc:  # requests raises a ValueError subclass for bad JSON
            raise OSVError("OSV returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise OSVError("OSV returned an unexpected response (not a JSON object)")
        return data

    # The loop always returns or raises; this line only satisfies type checkers.
    raise OSVError("retries exhausted")  # pragma: no cover


def query_package(
    session: Any,
    name: str,
    version: str,
    timeout: float = 10,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    """Ask OSV for every known vulnerability affecting one PyPI package version.

    Args:
        session: requests.Session (or a fake one in tests).
        name: Normalized package name, e.g. "django".
        version: Exact version, e.g. "3.2.0".
        timeout: Seconds per request.
        sleep: Wait function used between retries.

    Returns:
        A list of OSV vulnerability records (dicts). An empty list means OSV
        answered successfully and knows of no vulnerabilities for this version.

    Raises:
        OSVError: if any request fails or the answer has the wrong shape.
    """
    payload: dict = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    vulns: list[dict] = []

    for _ in range(MAX_PAGES):
        data = post_with_retries(session, payload, timeout, sleep)

        page = data.get("vulns", [])  # OSV omits "vulns" entirely when there are none
        if not isinstance(page, list) or not all(isinstance(v, dict) for v in page):
            raise OSVError("OSV returned an unexpected response ('vulns' is not a list of objects)")
        vulns.extend(page)

        token = data.get("next_page_token")
        if not token:
            return vulns  # no more pages: we have everything
        payload["page_token"] = token  # ask for the next page

    raise OSVError(f"OSV returned more than {MAX_PAGES} pages; stopped to be safe")


def make_session() -> requests.Session:
    """Create a requests.Session for talking to OSV.

    A Session reuses the same network connection for many requests, which is
    faster than opening a new one for every package.

    Returns:
        A configured requests.Session.
    """
    session = requests.Session()
    # Identify ourselves politely; servers like knowing which tool is calling.
    session.headers["User-Agent"] = "depwatch (https://github.com/Semere-20/DepWatch)"
    return session
