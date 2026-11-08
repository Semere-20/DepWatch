"""Tests for depwatch/osv_client.py. All network calls go to fake sessions."""

import pytest
import requests

from depwatch.osv_client import (
    MAX_RETRIES,
    OSV_QUERY_URL,
    OSVError,
    backoff_seconds,
    make_session,
    query_package,
)
from tests.conftest import FakeResponse, SequenceSession


def test_success_returns_vulns_and_sends_correct_payload(no_sleep):
    session = SequenceSession([FakeResponse(200, {"vulns": [{"id": "GHSA-1"}]})])
    vulns = query_package(session, "django", "3.2.0", timeout=5, sleep=no_sleep.append)
    assert vulns == [{"id": "GHSA-1"}]
    assert session.payloads[0] == {"package": {"name": "django", "ecosystem": "PyPI"}, "version": "3.2.0"}


def test_no_vulns_returns_empty_list(no_sleep):
    # OSV answers {} when nothing is known: that is a real "clean" answer.
    session = SequenceSession([FakeResponse(200, {})])
    assert query_package(session, "flask", "3.0.0", sleep=no_sleep.append) == []


def test_timeout_raises_osverror(no_sleep):
    session = SequenceSession([requests.Timeout("slow")])
    with pytest.raises(OSVError, match="timed out after 7s"):
        query_package(session, "flask", "1.0", timeout=7, sleep=no_sleep.append)


def test_connection_error_raises_osverror(no_sleep):
    session = SequenceSession([requests.ConnectionError("dns failure")])
    with pytest.raises(OSVError, match="connection error"):
        query_package(session, "flask", "1.0", sleep=no_sleep.append)


def test_other_request_exception_raises_osverror(no_sleep):
    session = SequenceSession([requests.TooManyRedirects("loop")])
    with pytest.raises(OSVError, match="request failed: TooManyRedirects"):
        query_package(session, "flask", "1.0", sleep=no_sleep.append)


def test_http_500_retried_then_error(no_sleep):
    session = SequenceSession([FakeResponse(500)] * (MAX_RETRIES + 1))
    with pytest.raises(OSVError, match="HTTP 500"):
        query_package(session, "flask", "1.0", sleep=no_sleep.append)
    assert len(session.payloads) == MAX_RETRIES + 1
    assert no_sleep == [1.0, 2.0, 4.0]  # exponential backoff


def test_http_404_is_not_retried(no_sleep):
    session = SequenceSession([FakeResponse(404)])
    with pytest.raises(OSVError, match="HTTP 404"):
        query_package(session, "flask", "1.0", sleep=no_sleep.append)
    assert no_sleep == []


def test_429_then_success(no_sleep):
    session = SequenceSession([FakeResponse(429), FakeResponse(429), FakeResponse(200, {"vulns": []})])
    assert query_package(session, "flask", "1.0", sleep=no_sleep.append) == []
    assert no_sleep == [1.0, 2.0]


def test_429_honors_retry_after_header(no_sleep):
    session = SequenceSession([FakeResponse(429, headers={"Retry-After": "3"}), FakeResponse(200, {})])
    query_package(session, "flask", "1.0", sleep=no_sleep.append)
    assert no_sleep == [3.0]


def test_429_every_time_is_an_error(no_sleep):
    session = SequenceSession([FakeResponse(429)] * (MAX_RETRIES + 1))
    with pytest.raises(OSVError, match="rate limited"):
        query_package(session, "flask", "1.0", sleep=no_sleep.append)


def test_invalid_json_raises_osverror(no_sleep):
    session = SequenceSession([FakeResponse(200, bad_json=True)])
    with pytest.raises(OSVError, match="invalid JSON"):
        query_package(session, "flask", "1.0", sleep=no_sleep.append)


def test_json_not_an_object_raises(no_sleep):
    session = SequenceSession([FakeResponse(200, ["not", "a", "dict"])])
    with pytest.raises(OSVError, match="not a JSON object"):
        query_package(session, "flask", "1.0", sleep=no_sleep.append)


@pytest.mark.parametrize("bad_vulns", ["oops", [1, 2], {"id": "x"}])
def test_vulns_with_wrong_shape_raises(no_sleep, bad_vulns):
    session = SequenceSession([FakeResponse(200, {"vulns": bad_vulns})])
    with pytest.raises(OSVError, match="unexpected response"):
        query_package(session, "flask", "1.0", sleep=no_sleep.append)


def test_missing_fields_in_vuln_are_passed_through(no_sleep):
    # A record with no severity/summary is still a vulnerability; severity.py handles it.
    session = SequenceSession([FakeResponse(200, {"vulns": [{}]})])
    assert query_package(session, "flask", "1.0", sleep=no_sleep.append) == [{}]


def test_pagination_follows_next_page_token(no_sleep):
    session = SequenceSession([
        FakeResponse(200, {"vulns": [{"id": "A"}], "next_page_token": "tok1"}),
        FakeResponse(200, {"vulns": [{"id": "B"}]}),
    ])
    vulns = query_package(session, "django", "1.0", sleep=no_sleep.append)
    assert [v["id"] for v in vulns] == ["A", "B"]
    assert session.payloads[1]["page_token"] == "tok1"


def test_endless_pagination_is_stopped(no_sleep):
    class EndlessSession:
        def post(self, url, json, timeout):
            return FakeResponse(200, {"vulns": [], "next_page_token": "again"})

    with pytest.raises(OSVError, match="more than"):
        query_package(EndlessSession(), "django", "1.0", sleep=no_sleep.append)


@pytest.mark.parametrize(
    "attempt, header, expected",
    [(0, None, 1.0), (2, None, 4.0), (0, "5", 5.0), (0, "999", 30.0), (1, "Wed, 21 Oct 2015 07:28:00 GMT", 2.0)],
)
def test_backoff_seconds(attempt, header, expected):
    assert backoff_seconds(attempt, header) == expected


def test_make_session_sets_user_agent():
    session = make_session()
    assert session.headers["User-Agent"].startswith("depwatch")
    assert OSV_QUERY_URL == "https://api.osv.dev/v1/query"
