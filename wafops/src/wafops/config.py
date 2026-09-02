"""Environment configuration, read from Terraform.

The prototype kept deployment state in a gitignored local JSON file, which meant
no second machine and no CI runner ever had it. Terraform outputs are the
contract instead: the infrastructure declares what it built, and this reads it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class EnvConfig:
    env: str
    target_url: str
    web_acl_name: str
    log_group_name: str | None
    blocked_ip_set: dict | None
    origin_bypass_url: str | None
    rule_summary: list[dict]
    web_acl_capacity: int | None


def repo_root(start: Path | None = None) -> Path:
    here = (start or Path.cwd()).resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "envs").is_dir() and (candidate / "modules").is_dir():
            return candidate
    raise ConfigError("Could not locate the repository root (no envs/ and modules/ above here).")


def load_env(env: str, root: Path | None = None) -> EnvConfig:
    root = root or repo_root()
    chdir = root / "envs" / env
    if not chdir.is_dir():
        raise ConfigError(f"No such environment: envs/{env}")

    binary = shutil.which("terraform") or shutil.which("tofu")
    if binary is None:
        raise ConfigError("Neither terraform nor tofu is on PATH.")

    result = subprocess.run(
        [binary, f"-chdir={chdir}", "output", "-json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ConfigError(
            f"Could not read outputs for '{env}'. Is it deployed?\n{result.stderr.strip()}"
        )

    raw = {key: value["value"] for key, value in json.loads(result.stdout).items()}

    missing = {"target_url", "web_acl_name"} - raw.keys()
    if missing:
        raise ConfigError(f"Environment '{env}' is missing outputs: {sorted(missing)}")

    return EnvConfig(
        env=env,
        target_url=raw["target_url"].rstrip("/"),
        web_acl_name=raw["web_acl_name"],
        log_group_name=raw.get("log_group_name"),
        blocked_ip_set=raw.get("blocked_ip_set"),
        origin_bypass_url=raw.get("origin_bypass_url"),
        rule_summary=raw.get("rule_summary") or [],
        web_acl_capacity=raw.get("web_acl_capacity"),
    )
