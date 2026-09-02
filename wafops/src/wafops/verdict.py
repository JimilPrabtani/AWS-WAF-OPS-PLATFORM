"""Deciding what actually happened to a request.

THIS MODULE EXISTS BECAUSE OF A BUG IN THE PROTOTYPE.

Its test harness looked like this:

    try:
        response = requests.request(...)
        return {"blocked": response.status_code in (403, 429)}
    except requests.exceptions.ConnectionError:
        return {"blocked": True}          # <-- here
    except Exception:
        return {"blocked": True}          # <-- and here

A timeout, a DNS failure, or a CloudFront distribution that had not finished
deploying all scored as "the WAF blocked it". Since most tests expected a block,
those tests PASSED. The suite could report green against infrastructure that did
not exist.

Two fixes, both load-bearing:

1. Transport failure is its own outcome (ERROR) and always fails the run. It is
   never silently folded into success.

2. A block is only credited to the WAF when the response carries the custom JSON
   body the Web ACL is configured to return. A bare 403 could equally be S3
   denying an object, the ALB rejecting a malformed request, or a missing file --
   status code alone cannot prove the WAF acted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

import requests

# Must stay in step with local.blocked_body / local.rate_limited_body in
# modules/waf/main.tf. The Terraform side is the source of truth.
WAF_BODY_MARKERS = ("\"error\": \"blocked\"", "\"error\": \"rate_limited\"")


class Verdict(str, Enum):
    """What happened to one request."""

    BLOCKED_BY_WAF = "blocked_by_waf"
    ALLOWED = "allowed"
    #: Transport failure. Never counts as a pass, whatever the test expected.
    ERROR = "error"


@dataclass(frozen=True)
class Probe:
    verdict: Verdict
    status_code: int | None
    detail: str
    elapsed_ms: float | None = None

    @property
    def is_error(self) -> bool:
        return self.verdict is Verdict.ERROR


def classify(response: requests.Response) -> Probe:
    """Classify a response that actually came back."""
    body = response.text or ""
    elapsed = response.elapsed.total_seconds() * 1000 if response.elapsed else None

    if response.status_code in (403, 429) and _looks_like_waf(body):
        return Probe(
            Verdict.BLOCKED_BY_WAF,
            response.status_code,
            "WAF custom response body present",
            elapsed,
        )

    if response.status_code in (403, 429):
        # Deliberately NOT a WAF block. Something denied the request, but the
        # WAF's fingerprint is absent, so crediting the WAF would be a lie.
        return Probe(
            Verdict.ALLOWED,
            response.status_code,
            f"{response.status_code} without the WAF response body - denied by the origin, not the WAF",
            elapsed,
        )

    return Probe(Verdict.ALLOWED, response.status_code, "reached the origin", elapsed)


def _looks_like_waf(body: str) -> bool:
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return any(marker.replace(" ", "") in body.replace(" ", "") for marker in WAF_BODY_MARKERS)

    return isinstance(payload, dict) and payload.get("error") in {"blocked", "rate_limited"}


def probe(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: float = 10.0,
    **kwargs,
) -> Probe:
    """Send one request and classify the outcome.

    Transport failures return Verdict.ERROR rather than raising, so a suite can
    report every result -- but they can never be mistaken for a block.
    """
    try:
        response = session.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
    except requests.exceptions.Timeout:
        return Probe(Verdict.ERROR, None, "timed out - target may not be deployed yet")
    except requests.exceptions.ConnectionError as exc:
        return Probe(Verdict.ERROR, None, f"connection failed: {exc.__class__.__name__}")
    except requests.exceptions.RequestException as exc:
        return Probe(Verdict.ERROR, None, f"request failed: {exc}")

    return classify(response)
