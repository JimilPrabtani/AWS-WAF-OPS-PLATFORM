"""Running the payload catalogs against a deployed environment."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml

from .config import EnvConfig
from .verdict import Probe, Verdict, probe

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


@dataclass
class Result:
    id: str
    expected: str
    actual: str
    status_code: int | None
    detail: str
    passed: bool


def _load(name: str) -> list[dict]:
    text = resources.files("wafops.payloads").joinpath(name).read_text(encoding="utf-8")
    return yaml.safe_load(text)


def _session() -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = BROWSER_UA
    return session


def _judge(case_id: str, expected: str, result: Probe) -> Result:
    # An ERROR is never a pass, whatever the case expected. This is the whole
    # point of the three-state verdict -- see verdict.py.
    if result.verdict is Verdict.ERROR:
        passed = False
    elif expected == "blocked":
        passed = result.verdict is Verdict.BLOCKED_BY_WAF
    else:
        passed = result.verdict is Verdict.ALLOWED

    return Result(
        id=case_id,
        expected=expected,
        actual=result.verdict.value,
        status_code=result.status_code,
        detail=result.detail,
        passed=passed,
    )


def run_attacks(config: EnvConfig) -> list[Result]:
    session = _session()
    results: list[Result] = []

    for case in _load("attack.yaml"):
        location = case.get("location", "query")
        url = config.target_url + "/"
        kwargs: dict = {}

        if location == "query":
            kwargs["params"] = {"q": case["payload"]}
        elif location == "uri":
            url = f"{config.target_url}/{case['payload']}"
        elif location == "header":
            kwargs["headers"] = {case.get("header", "X-Test"): case["payload"]}
        elif location == "body":
            kwargs["data"] = case["payload"]

        method = case.get("method", "POST" if location == "body" else "GET")
        results.append(_judge(case["id"], case["expect"], probe(session, method, url, **kwargs)))

    return results


def run_benign(config: EnvConfig) -> list[Result]:
    session = _session()
    origin = f"{urlparse(config.target_url).scheme}://{urlparse(config.target_url).netloc}"
    results: list[Result] = []

    for case in _load("benign.yaml"):
        url = config.target_url + case.get("path", "/")
        kwargs: dict = {"headers": {}}

        if case.get("user_agent"):
            kwargs["headers"]["User-Agent"] = case["user_agent"]

        # State-changing requests carry an Origin, because the origin_check rule
        # is supposed to let first-party traffic through.
        if case.get("origin"):
            kwargs["headers"]["Origin"] = origin

        if case.get("query"):
            kwargs["params"] = case["query"]

        if case.get("query_repeat"):
            key, (chunk, times) = next(iter(case["query_repeat"].items()))
            kwargs["params"] = {key: chunk * times}

        if case.get("json"):
            kwargs["json"] = case["json"]
        elif case.get("body"):
            kwargs["data"] = case["body"]

        results.append(
            _judge(case["id"], case["expect"], probe(session, case.get("method", "GET"), url, **kwargs))
        )

    return results


def verify_origin_bypass(config: EnvConfig) -> Result:
    """The most important assertion in the repository.

    In the prototype the origin bucket was public and served the site directly,
    so the WAF could be skipped entirely. This confirms that is no longer true.
    """
    if not config.origin_bypass_url:
        return Result(
            id="origin-bypass",
            expected="not-applicable",
            actual="skipped",
            status_code=None,
            detail="This environment has no separate origin to bypass (the ALB serves its own response).",
            passed=True,
        )

    result = probe(_session(), "GET", config.origin_bypass_url)

    passed = result.status_code == 403
    return Result(
        id="origin-bypass",
        expected="403 from the direct origin URL",
        actual=str(result.status_code),
        status_code=result.status_code,
        detail=(
            "Origin is private; the WAF cannot be bypassed."
            if passed
            else "ORIGIN IS REACHABLE DIRECTLY. The WAF can be skipped entirely."
        ),
        passed=passed,
    )


def write_report(path: Path, config: EnvConfig, sections: dict[str, list[Result]]) -> dict:
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": config.env,
        "target_url": config.target_url,
        "web_acl": config.web_acl_name,
        "web_acl_capacity_wcu": config.web_acl_capacity,
        "rules": config.rule_summary,
        "results": {name: [asdict(r) for r in items] for name, items in sections.items()},
        "summary": {
            name: {
                "total": len(items),
                "passed": sum(1 for r in items if r.passed),
                "failed": sum(1 for r in items if not r.passed),
            }
            for name, items in sections.items()
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
