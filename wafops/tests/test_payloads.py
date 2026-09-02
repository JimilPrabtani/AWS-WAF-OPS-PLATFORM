"""The payload catalogs are data, so they get schema tests like any other data."""

from __future__ import annotations

from importlib import resources

import pytest
import yaml

VALID_EXPECT = {"blocked", "allowed"}


def _load(name: str):
    return yaml.safe_load(resources.files("wafops.payloads").joinpath(name).read_text("utf-8"))


@pytest.mark.parametrize("name", ["attack.yaml", "benign.yaml"])
def test_ids_are_unique(name):
    cases = _load(name)
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"


@pytest.mark.parametrize("name", ["attack.yaml", "benign.yaml"])
def test_every_case_declares_an_expectation(name):
    for case in _load(name):
        assert case.get("expect") in VALID_EXPECT, f"{case['id']} has no valid expect"


def test_attack_cases_cite_a_reference():
    """If a payload is worth testing, there is a CVE or CWE explaining why."""
    for case in _load("attack.yaml"):
        assert case.get("reference"), f"{case['id']} has no reference"


def test_benign_suite_expects_everything_to_be_allowed():
    for case in _load("benign.yaml"):
        assert case["expect"] == "allowed", f"{case['id']} is in the benign suite but expects a block"
