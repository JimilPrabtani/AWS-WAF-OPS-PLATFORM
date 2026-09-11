"""The regression tests for the prototype's most damaging bug.

Every one of these would have passed incorrectly under the original harness,
which returned blocked=True from both of its exception handlers.
"""

from __future__ import annotations

import requests

from wafops.verdict import Verdict, classify, probe


class FakeElapsed:
    def total_seconds(self) -> float:
        return 0.05


class FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text
        self.elapsed = FakeElapsed()


def test_waf_block_is_recognised_by_its_body():
    response = FakeResponse(403, '{"error": "blocked", "message": "Request blocked by WAF security rules."}')
    assert classify(response).verdict is Verdict.BLOCKED_BY_WAF


def test_rate_limit_body_also_counts():
    response = FakeResponse(429, '{"error": "rate_limited", "message": "Too many requests."}')
    assert classify(response).verdict is Verdict.BLOCKED_BY_WAF


def test_bare_403_is_not_credited_to_the_waf():
    """A 403 from S3 or the ALB must not be reported as a WAF block."""
    response = FakeResponse(403, "<Error><Code>AccessDenied</Code></Error>")
    result = classify(response)
    assert result.verdict is Verdict.ALLOWED
    assert "not the WAF" in result.detail


def test_normal_response_is_allowed():
    assert classify(FakeResponse(200, "<html>hello</html>")).verdict is Verdict.ALLOWED


def test_connection_error_is_an_error_not_a_block(monkeypatch):
    class Boom:
        def request(self, *args, **kwargs):
            raise requests.exceptions.ConnectionError("no route to host")

    result = probe(Boom(), "GET", "https://example.invalid/")
    assert result.verdict is Verdict.ERROR


def test_timeout_is_an_error_not_a_block():
    class Slow:
        def request(self, *args, **kwargs):
            raise requests.exceptions.Timeout()

    result = probe(Slow(), "GET", "https://example.invalid/")
    assert result.verdict is Verdict.ERROR
    assert "not be deployed" in result.detail
