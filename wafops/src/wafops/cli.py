"""wafops command line."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import ConfigError, load_env
from .suites import Result, run_attacks, run_benign, verify_origin_bypass, write_report

app = typer.Typer(help="Test and operate the WAF Ops Platform.", no_args_is_help=True)
attack_app = typer.Typer(help="Attack vector suite.")
falsepos_app = typer.Typer(help="Legitimate traffic suite.")
verify_app = typer.Typer(help="Structural assertions about the deployment.")
report_app = typer.Typer(help="Evidence bundles.")

app.add_typer(attack_app, name="attack")
app.add_typer(falsepos_app, name="falsepos")
app.add_typer(verify_app, name="verify")
app.add_typer(report_app, name="report")

console = Console()


def _render(title: str, results: list[Result]) -> int:
    table = Table(title=title, header_style="bold")
    table.add_column("case")
    table.add_column("expected")
    table.add_column("actual")
    table.add_column("code", justify="right")
    table.add_column("", justify="center")

    for result in results:
        mark = "[green]pass[/]" if result.passed else "[red]FAIL[/]"
        table.add_row(
            result.id,
            result.expected,
            result.actual,
            str(result.status_code or "-"),
            mark,
        )

    console.print(table)

    failed = [r for r in results if not r.passed]
    errors = [r for r in results if r.actual == "error"]

    if errors:
        console.print(
            f"[yellow]{len(errors)} case(s) could not reach the target. "
            "These count as failures -- a transport error is not a block.[/]"
        )
    if failed:
        console.print(f"[red]{len(failed)} of {len(results)} failed[/]")
    else:
        console.print(f"[green]all {len(results)} passed[/]")

    return 1 if failed else 0


def _load(env: str):
    try:
        return load_env(env)
    except ConfigError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc


@attack_app.command("run")
def attack_run(
    env: str = typer.Option("dev", "--env"),
    report: Path | None = typer.Option(None, "--report", help="Write JSON results here."),
) -> None:
    """Fire the attack catalog at the deployed target."""
    config = _load(env)
    results = run_attacks(config)
    code = _render(f"Attack vectors - {env}", results)
    if report:
        write_report(report, config, {"attack": results})
    raise typer.Exit(code)


@falsepos_app.command("run")
def falsepos_run(
    env: str = typer.Option("dev", "--env"),
    report: Path | None = typer.Option(None, "--report"),
) -> None:
    """Confirm legitimate traffic still gets through. The one that matters."""
    config = _load(env)
    results = run_benign(config)
    code = _render(f"Legitimate traffic - {env}", results)
    if report:
        write_report(report, config, {"falsepos": results})
    raise typer.Exit(code)


@verify_app.command("bypass")
def verify_bypass(env: str = typer.Option("prod", "--env")) -> None:
    """Assert the origin cannot be reached without going through the WAF."""
    config = _load(env)
    raise typer.Exit(_render(f"Origin bypass - {env}", [verify_origin_bypass(config)]))


@report_app.command("generate")
def report_generate(
    env: str = typer.Option("dev", "--env"),
    out: Path = typer.Option(Path("reports/evidence.json"), "--out"),
) -> None:
    """Run everything and write the evidence bundle."""
    config = _load(env)
    sections = {
        "attack": run_attacks(config),
        "falsepos": run_benign(config),
        "origin_bypass": [verify_origin_bypass(config)],
    }
    for name, results in sections.items():
        _render(f"{name} - {env}", results)

    write_report(out, config, sections)
    console.print(f"[green]Evidence written to {out}[/]")


if __name__ == "__main__":
    app()
