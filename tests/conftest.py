"""Shared test helpers: fake HTTP responses and fake sessions.

The real code calls `session.post(url, json=..., timeout=...)`. In tests we pass
these fake objects instead, so no test ever touches the network.
"""

from __future__ import annotations

from typing import Any

import pytest


class FakeResponse:
    """Stands in for requests.Response with only the parts DepWatch uses."""

    def __init__(self, status_code: int = 200, json_data: Any = None, headers: dict | None = None,
                 bad_json: bool = False) -> None:
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.headers = headers or {}
        self._bad_json = bad_json

    def json(self) -> Any:
        """Return the stored data, or raise ValueError like requests does for bad JSON."""
        if self._bad_json:
            raise ValueError("Expecting value: line 1 column 1")
        return self._json_data


class SequenceSession:
    """Returns (or raises) the given items one per call, in order. Records every payload."""

    def __init__(self, items: list[Any]) -> None:
        self.items = list(items)
        self.payloads: list[dict] = []

    def post(self, url: str, json: dict, timeout: float) -> FakeResponse:
        self.payloads.append(dict(json))  # copy, because the caller may change it later
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class RouterSession:
    """Answers by package name: routes = {"django": FakeResponse(...) or Exception}."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def post(self, url: str, json: dict, timeout: float) -> FakeResponse:
        name = json["package"]["name"]
        self.calls.append(name)
        item = self.routes.get(name, FakeResponse(200, {}))
        if isinstance(item, Exception):
            raise item
        return item


def make_vuln(vuln_id: str, *, aliases: list[str] | None = None, vector: str | None = None,
              label: str | None = None, fixed: list[str] | None = None, package: str = "demo",
              summary: str = "Example flaw") -> dict:
    """Build a small OSV-shaped vulnerability record for tests."""
    vuln: dict = {"id": vuln_id, "summary": summary, "aliases": aliases or []}
    if vector:
        vuln["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if label:
        vuln["database_specific"] = {"severity": label}
    events: list[dict] = [{"introduced": "0"}] + [{"fixed": f} for f in (fixed or [])]
    vuln["affected"] = [{"package": {"name": package, "ecosystem": "PyPI"},
                         "ranges": [{"type": "ECOSYSTEM", "events": events}]}]
    return vuln


@pytest.fixture
def no_sleep() -> list[float]:
    """A list that records requested waits; pass `no_sleep.append` as the sleep function."""
    return []
