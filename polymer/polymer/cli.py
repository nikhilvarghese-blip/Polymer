from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
import os
import shutil
import sys
from typing import Any, Callable, TypeVar, cast

import click
import typer
import yaml
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from polymer.core.events import ScanEvent
from polymer.core.audit import ScanAuditLog
from polymer.core.targets import parse_targets
from polymer.core.orchestrator import Orchestrator
from polymer.core.timing import ScanWindow, ntp_sync_status, resolve_end_time, server_now
from polymer.intelligence.correlation import CorrelationEngine
from polymer.intelligence.delta import compare_assets
from polymer.intelligence.enrichment import VulnerabilityIntelligence
from polymer.intelligence.io import load_assets
from polymer.reporting.json_report import (
    write_analysis_report,
    write_delta_report,
    write_ip_grouped_report,
    write_per_ip,
)
from polymer.reporting.csv_report import write_csv_reports

app = typer.Typer(
    help="Polymer asset-centric security assessment orchestrator",
    no_args_is_help=True,
)
console = Console()
_DEBUG = False
F = TypeVar("F", bound=Callable[..., Any])


@app.callback()
def main(
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Show full tracebacks for command and configuration failures.",
    ),
) -> None:
    """Run authorized, asset-centric security assessments."""
    global _DEBUG
    _DEBUG = debug


def cli_errors(function: F) -> F:
    """Turn runtime failures into concise CLI errors, with opt-in tracebacks."""

    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except (typer.Exit, click.ClickException):
            raise
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Interrupted by user.[/bold yellow]")
            raise typer.Exit(code=130)
        except Exception as exc:
            if _DEBUG:
                console.print_exception(show_locals=False)
            else:
                console.print(
                    f"[bold red]Error:[/bold red] {type(exc).__name__}: {exc}"
                )
                console.print("[dim]Re-run with --debug for a traceback.[/dim]")
            raise typer.Exit(code=1) from exc

    return cast(F, wrapped)


def load_config(path: Path) -> dict:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"configuration root must be a mapping: {path}")
    for section in ("project", "scope", "scan", "intelligence"):
        value = payload.get(section)
        if value is not None and not isinstance(value, dict):
            raise ValueError(f"configuration section {section!r} must be a mapping")
    return payload


def load_profile(
    config: dict,
    profile_name: str | None,
    config_path: Path,
) -> set[str] | None:
    name = profile_name or config.get("scan", {}).get("profile")
    if not name:
        return None
    configured_path = config.get("scan", {}).get("profiles_file")
    path = Path(configured_path) if configured_path else config_path.parent / "profiles.yaml"
    if not path.exists():
        raise ValueError(f"scan profile {name!r} requested but {path} does not exist")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid profile YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"profile file root must be a mapping: {path}")
    profile = data.get(name)
    if not isinstance(profile, dict):
        raise typer.BadParameter(f"unknown scan profile: {name}")
    scanners = profile.get("scanners", [])
    if not isinstance(scanners, list) or not all(isinstance(item, str) for item in scanners):
        raise ValueError(f"profile {name!r} must contain a list of scanner names")
    return set(scanners)


def run_directory(config: dict, prefix: str) -> Path:
    stamp = utc_run_stamp()
    return Path(config.get("project", {}).get("output_dir", "output")) / f"{prefix}-{stamp}"


def utc_run_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def scan_window(started_at: datetime, end_time: str | None) -> tuple[ScanWindow, bool | None]:
    """Build the scan window, prompting only when attached to a terminal."""

    ntp_status = ntp_sync_status()
    server_zone = started_at.tzname() or str(started_at.tzinfo)
    value = end_time
    if value is None and sys.stdin.isatty():
        console.print(
            f"[cyan]Server time:[/cyan] {started_at:%Y-%m-%d %H:%M:%S} "
            f"{server_zone} (NTP synchronized: "
            f"{'yes' if ntp_status is True else 'no' if ntp_status is False else 'unknown'})"
        )
        value = typer.prompt(
            f"Scan end time in server {server_zone} (HH:MM; earlier times mean tomorrow)"
        )
    elif value is None:
        console.print(
            "[yellow]No interactive terminal detected; scan deadline is disabled. "
            "Use --end-time HH:MM for unattended runs.[/yellow]"
        )

    end_at = None
    if value is not None:
        try:
            end_at = resolve_end_time(value, started_at)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--end-time") from exc
        console.print(
            f"[cyan]Scan window:[/cyan] {started_at:%Y-%m-%d %H:%M:%S %Z} "
            f"to {end_at:%Y-%m-%d %H:%M:%S %Z}"
        )
    if ntp_status is False:
        console.print(
            "[bold yellow]Warning:[/bold yellow] the server reports that its clock "
            "is not currently NTP-synchronized."
        )
    return ScanWindow(started_at=started_at, end_at=end_at), ntp_status


def progress_display() -> Progress:
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("{task.description}"),
        BarColumn(
            bar_width=None,
            complete_style="bright_cyan",
            finished_style="bright_green",
        ),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        expand=True,
    )


class ScanProgress:
    """Translate core scan events into a detailed Rich progress task."""

    def __init__(self, progress: Progress, detail_task: int):
        self.progress = progress
        self.detail_task = detail_task

    def begin_asset(self, ip: str) -> None:
        self.progress.reset(
            self.detail_task,
            total=1,
            completed=0,
            description=f"[cyan]Scan[/cyan] {ip} [yellow]discovery[/yellow]",
            visible=True,
        )

    def __call__(self, event: ScanEvent) -> None:
        if event.kind == "scanner_started":
            self.progress.update(
                self.detail_task,
                description=(
                    f"[cyan]Scan[/cyan] {event.asset_ip} "
                    f"[yellow]{event.scanner or 'scanner'}[/yellow]"
                ),
            )
        elif event.kind == "scan_planned" and event.scanner_total is not None:
            self.progress.update(self.detail_task, total=event.scanner_total)
        elif event.kind == "scanner_completed":
            self.progress.advance(self.detail_task)
            if event.result and event.result.status in {"failed", "unavailable"}:
                color = "red" if event.result.status == "failed" else "yellow"
                detail = event.result.message or "no details"
                self.progress.console.print(
                    f"[{color}]{event.asset_ip} {event.scanner}: "
                    f"{event.result.status}[/{color}] [dim]{detail}[/dim]"
                )


def build_engine(cfg: dict, run_dir: Path) -> CorrelationEngine:
    icfg = cfg.get("intelligence", {})
    enabled = bool(icfg.get("enabled", True))
    intel = None
    if enabled and bool(icfg.get("enrichment", {}).get("enabled", True)):
        intel = VulnerabilityIntelligence(
            icfg.get("enrichment", {}),
            run_dir / "cache" / "vuln_intel",
        )
    return CorrelationEngine(icfg, intel=intel)


def print_analysis_summary(assets) -> None:
    table = Table(title="Polymer Phase 3 correlated findings")
    table.add_column("IP")
    table.add_column("Critical")
    table.add_column("High")
    table.add_column("Medium")
    table.add_column("Low")
    table.add_column("KEV")
    table.add_column("Correlated")
    for asset in assets:
        rs = asset.risk_summary
        table.add_row(
            asset.ip,
            str(rs.get("critical", 0)),
            str(rs.get("high", 0)),
            str(rs.get("medium", 0)),
            str(rs.get("low", 0)),
            str(rs.get("kev", 0)),
            str(rs.get("total_correlated", 0)),
        )
    console.print(table)


@app.command()
@cli_errors
def doctor(config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True)):
    """Check Polymer and external scanner prerequisites."""
    cfg = load_config(config)
    table = Table(title="Polymer Phase 3 environment")
    table.add_column("Component")
    table.add_column("State")
    table.add_column("Details")
    binaries = {
        "nmap": "nmap", "nuclei": "nuclei", "ssh_audit": "ssh-audit",
        "testssl": "testssl", "nikto": "nikto", "enum4linux": "enum4linux-ng",
    }
    for key, default in binaries.items():
        scfg = cfg.get("scan", {}).get(key, {})
        if not scfg.get("enabled", False):
            table.add_row(key, "disabled", "disabled in config")
            continue
        binary = scfg.get("binary", default)
        found = shutil.which(binary)
        state = "[green]ready[/green]" if found else "[red]missing[/red]"
        table.add_row(key, state, found or f"{binary} not found in PATH")

    wcfg = cfg.get("scan", {}).get("wazuh", {})
    if not wcfg.get("enabled", False):
        table.add_row("wazuh_sca", "disabled", "enable after configuring Wazuh API")
    else:
        uenv = wcfg.get("username_env", "POLYMER_WAZUH_USERNAME")
        penv = wcfg.get("password_env", "POLYMER_WAZUH_PASSWORD")
        ok = bool(wcfg.get("url") and os.getenv(uenv) and os.getenv(penv))
        table.add_row("wazuh_sca", "ready" if ok else "incomplete", wcfg.get("url") if ok else "URL/credential env vars required")

    gcfg = cfg.get("scan", {}).get("greenbone", {})
    if not gcfg.get("enabled", False):
        table.add_row("greenbone", "disabled", "optional; enable after GVM setup")
    else:
        sock = Path(gcfg.get("socket", "/run/gvmd/gvmd.sock"))
        creds = bool(os.getenv(gcfg.get("username_env", "POLYMER_GVM_USERNAME")) and os.getenv(gcfg.get("password_env", "POLYMER_GVM_PASSWORD")))
        try:
            import gvm  # noqa: F401
            py = True
        except Exception:
            py = False
        ok = sock.exists() and creds and py
        table.add_row("greenbone", "ready" if ok else "incomplete", f"socket={sock.exists()}, python-gvm={py}, credentials={creds}")

    ecfg = cfg.get("intelligence", {}).get("enrichment", {})
    if not cfg.get("intelligence", {}).get("enabled", True):
        table.add_row("phase3_intelligence", "disabled", "intelligence.enabled=false")
    elif ecfg.get("offline", False):
        table.add_row("phase3_intelligence", "offline", "cache-only NVD/CISA enrichment")
    else:
        api_key_env = ecfg.get("nvd_api_key_env", "NVD_API_KEY")
        table.add_row("phase3_intelligence", "ready", f"NVD/CISA enabled; {api_key_env}={'set' if os.getenv(api_key_env) else 'not set (optional)'}")
    console.print(table)


@app.command()
@cli_errors
def validate(
    targets: Path = typer.Option(..., exists=True, readable=True),
    config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True),
):
    cfg = load_config(config)
    scope = cfg.get("scope", {})
    values = parse_targets(targets, int(scope.get("max_expanded_hosts", 4096)), bool(scope.get("allow_public_ips", False)))
    console.print(f"[green]Scope valid:[/green] {len(values)} unique IP addresses")


@app.command()
@cli_errors
def plan(
    targets: Path = typer.Option(..., exists=True, readable=True),
    config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True),
    profile: str | None = typer.Option(None),
):
    """Run discovery only and show which scanners would execute."""
    cfg = load_config(config)
    scope = cfg.get("scope", {})
    values = parse_targets(targets, int(scope.get("max_expanded_hosts", 4096)), bool(scope.get("allow_public_ips", False)))
    run_dir = run_directory(cfg, "plan")
    orch = Orchestrator(cfg, run_dir, load_profile(cfg, profile, config))
    table = Table(title="Polymer execution plan")
    table.add_column("IP")
    table.add_column("Status")
    table.add_column("Services")
    table.add_column("Planned scanners")
    with progress_display() as progress:
        task = progress.add_task("[cyan]Discovery plan[/cyan]", total=len(values))
        for ip in values:
            progress.update(task, description=f"[cyan]Discovering[/cyan] {ip}")
            asset = orch.discover_asset(ip)
            services = ", ".join(
                f"{s.port}/{s.protocol}:{s.name or '?'}" for s in asset.services
            ) or "-"
            table.add_row(
                ip,
                asset.status,
                services,
                ", ".join(orch.plan_asset(asset)) or "none",
            )
            progress.advance(task)
        progress.update(task, description="[green]Discovery plan complete[/green]")
    console.print(table)


@app.command()
@cli_errors
def analyze(
    input: Path = typer.Option(..., "--input", exists=True, readable=True, help="Existing Polymer polymer.json"),
    config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True),
    output: Path | None = typer.Option(None, help="Directory for Phase 3 analysis files"),
    baseline: Path | None = typer.Option(None, exists=True, readable=True, help="Optional earlier Polymer JSON for delta comparison"),
):
    """Run Phase 3 correlation/enrichment against an existing Polymer result without rescanning."""
    cfg = load_config(config)
    assets = load_assets(input)
    out_dir = output or input.parent / f"analysis-{utc_run_stamp()}"
    engine = build_engine(cfg, out_dir)
    delta = None
    total_steps = 2 + int(baseline is not None)
    with progress_display() as progress:
        task = progress.add_task("[magenta]Correlating findings[/magenta]", total=total_steps)
        engine.analyze_assets(assets)
        progress.advance(task)

        if baseline:
            progress.update(task, description="[yellow]Comparing baseline[/yellow]")
            baseline_assets = load_assets(baseline)
            engine.analyze_assets(baseline_assets)
            delta = compare_assets(assets, baseline_assets)
            write_delta_report(delta, out_dir / "delta.json")
            progress.advance(task)

        progress.update(task, description="[blue]Writing analysis reports[/blue]")
        write_analysis_report(assets, out_dir / "analysis.json")
        write_ip_grouped_report(assets, out_dir / "polymer-enriched.json")
        write_per_ip(assets, out_dir / "by_ip")
        write_csv_reports(assets, out_dir)
        progress.advance(task)
        progress.update(task, description="[green]Analysis complete[/green]")

    if delta:
        console.print(
            f"[green]Delta:[/green] new={delta['summary']['new']} "
            f"resolved={delta['summary']['resolved']} "
            f"unchanged={delta['summary']['unchanged']}"
        )

    print_analysis_summary(assets)
    console.print(f"[green]Phase 3 results:[/green] {out_dir}")
    console.print(f"[green]CSV report:[/green] {out_dir / 'polymer.csv'}")


@app.command()
@cli_errors
def scan(
    targets: Path = typer.Option(..., exists=True, readable=True),
    config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True),
    profile: str | None = typer.Option(None),
    baseline: Path | None = typer.Option(None, exists=True, readable=True, help="Optional earlier polymer.json for new/resolved comparison"),
    end_time: str | None = typer.Option(
        None,
        "--end-time",
        help="Scan deadline as HH:MM in the server timezone; prompted in a terminal.",
    ),
    no_intelligence: bool = typer.Option(False, "--no-intelligence", help="Skip Phase 3 correlation/enrichment"),
    fail_on_tool_error: bool = typer.Option(
        False,
        "--fail-on-tool-error",
        help="Exit with status 2 if any selected scanner fails or is unavailable.",
    ),
):
    command_started_at = server_now()
    cfg = load_config(config)
    scope = cfg.get("scope", {})
    values = parse_targets(targets, int(scope.get("max_expanded_hosts", 4096)), bool(scope.get("allow_public_ips", False)))
    if baseline and no_intelligence:
        raise ValueError("--baseline cannot be combined with --no-intelligence")
    window, ntp_status = scan_window(command_started_at, end_time)
    run_dir = run_directory(cfg, "run")
    selected_profile = load_profile(cfg, profile, config)
    intelligence_enabled = (
        not no_intelligence and cfg.get("intelligence", {}).get("enabled", True)
    )
    assets = []
    delta = None
    partial_report = run_dir / "polymer.partial.json"
    total_steps = len(values) + int(intelligence_enabled) + 1
    deadline_reached = False
    with ScanAuditLog(
        run_dir / "scan.log",
        started_at=command_started_at,
        end_at=window.end_at,
        ntp_synchronized=ntp_status,
        target_count=len(values),
    ) as audit:
        with progress_display() as progress:
            overall = progress.add_task("[magenta]Overall scan[/magenta]", total=total_steps)
            detail = progress.add_task("", total=1, visible=False)
            scan_progress = ScanProgress(progress, detail)

            def record_event(event: ScanEvent) -> None:
                scan_progress(event)
                audit(event)

            orch = Orchestrator(
                cfg,
                run_dir,
                selected_profile,
                progress_callback=record_event,
                scan_window=window,
            )

            for number, ip in enumerate(values, start=1):
                if window.expired():
                    deadline_reached = True
                    reason = "scan end time reached before target could start"
                    for remaining_ip in values[number - 1:]:
                        audit.target_not_started(remaining_ip, reason)
                    break
                scan_progress.begin_asset(ip)
                audit.begin_asset(ip)
                assets.append(orch.scan_asset(ip))
                # Keep an atomic checkpoint so a long run remains debuggable after
                # interruption or a later scanner/reporting failure.
                write_ip_grouped_report(assets, partial_report)
                progress.advance(overall)
                progress.update(
                    overall,
                    description=(
                        f"[magenta]Overall scan[/magenta] "
                        f"[cyan]{number}/{len(values)} targets[/cyan]"
                    ),
                )

            deadline_reached = deadline_reached or window.expired()
            progress.update(detail, visible=False)
            if intelligence_enabled:
                audit.phase("correlation_and_intelligence", "started")
                progress.update(
                    overall,
                    description="[magenta]Overall[/magenta] [yellow]correlation & intelligence[/yellow]",
                )
                engine = build_engine(cfg, run_dir)
                engine.analyze_assets(assets)
                write_analysis_report(assets, run_dir / "analysis.json")
                if baseline:
                    baseline_assets = load_assets(baseline)
                    engine.analyze_assets(baseline_assets)
                    delta = compare_assets(assets, baseline_assets)
                    write_delta_report(delta, run_dir / "delta.json")
                progress.advance(overall)
                audit.phase("correlation_and_intelligence", "completed")

            audit.phase("reporting", "started")
            progress.update(
                overall,
                description="[magenta]Overall[/magenta] [blue]writing reports[/blue]",
            )
            write_ip_grouped_report(assets, run_dir / "polymer.json")
            write_per_ip(assets, run_dir / "by_ip")
            write_csv_reports(assets, run_dir)
            partial_report.unlink(missing_ok=True)
            progress.advance(overall)
            audit.phase("reporting", "completed")
            progress.update(overall, description="[green]Polymer scan complete[/green]")
        audit.finish(
            "deadline_reached" if deadline_reached else "completed",
            targets_scanned=len(assets),
            targets_not_started=len(values) - len(assets),
        )

    if delta:
        console.print(
            f"[green]Delta:[/green] new={delta['summary']['new']} "
            f"resolved={delta['summary']['resolved']} "
            f"unchanged={delta['summary']['unchanged']}"
        )

    table = Table(title="Polymer scan summary")
    table.add_column("IP")
    table.add_column("Status")
    table.add_column("Services")
    table.add_column("Raw findings")
    table.add_column("Correlated")
    table.add_column("Tools")
    for asset in assets:
        count = sum(len(x.findings) for x in asset.tools.values())
        table.add_row(
            asset.ip,
            f"[green]{asset.status}[/green]" if asset.status == "up" else f"[yellow]{asset.status}[/yellow]",
            str(len(asset.services)),
            str(count),
            str(len(asset.correlated_findings)),
            ", ".join(
                f"{name}:[{'green' if result.status == 'completed' else 'yellow' if result.status in {'skipped', 'not_applicable'} else 'red'}]{result.status}[/]"
                for name, result in asset.tools.items()
            ),
        )
    console.print(table)
    if intelligence_enabled:
        print_analysis_summary(assets)
    console.print(f"[green]Results:[/green] {run_dir}")
    console.print(f"[green]CSV report:[/green] {run_dir / 'polymer.csv'}")
    console.print(f"[green]Detailed scan log:[/green] {run_dir / 'scan.log'}")
    if deadline_reached:
        console.print(
            f"[yellow]Scan deadline reached; {len(values) - len(assets)} "
            "target(s) were not started.[/yellow]"
        )
    tool_errors = [
        (asset.ip, name, result.status)
        for asset in assets
        for name, result in asset.tools.items()
        if result.status in {"failed", "unavailable"}
    ]
    if tool_errors:
        console.print(
            f"[yellow]Completed with {len(tool_errors)} scanner issue(s).[/yellow] "
            "Details are preserved in polymer.json and scanner_status.csv."
        )
        if fail_on_tool_error:
            raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
