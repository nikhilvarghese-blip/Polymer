from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
import shutil
import yaml
import typer
from rich.console import Console
from rich.table import Table

from polymer.core.targets import parse_targets
from polymer.core.orchestrator import Orchestrator
from polymer.reporting.json_report import write_ip_grouped_report, write_per_ip

app = typer.Typer(help="Polymer asset-centric security assessment orchestrator")
console = Console()


def load_config(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}


def load_profile(config: dict, profile_name: str | None) -> set[str] | None:
    name = profile_name or config.get("scan", {}).get("profile")
    if not name:
        return None
    path = Path("config/profiles.yaml")
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text()) or {}
    profile = data.get(name)
    if not profile:
        raise typer.BadParameter(f"unknown scan profile: {name}")
    return set(profile.get("scanners", []))


@app.command()
def doctor(config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True)):
    """Check Polymer and external scanner prerequisites."""
    cfg = load_config(config)
    table = Table(title="Polymer Phase 2 environment")
    table.add_column("Component"); table.add_column("State"); table.add_column("Details")
    binaries = {
        "nmap": "nmap", "nuclei": "nuclei", "ssh_audit": "ssh-audit",
        "testssl": "testssl", "nikto": "nikto", "enum4linux": "enum4linux-ng",
    }
    for key, default in binaries.items():
        scfg = cfg.get("scan", {}).get(key, {})
        if not scfg.get("enabled", False):
            table.add_row(key, "disabled", "disabled in config"); continue
        binary=scfg.get("binary", default); found=shutil.which(binary)
        table.add_row(key, "ready" if found else "missing", found or f"{binary} not found in PATH")

    wcfg=cfg.get("scan",{}).get("wazuh",{})
    if not wcfg.get("enabled",False): table.add_row("wazuh_sca","disabled","enable after configuring Wazuh API")
    else:
        uenv=wcfg.get("username_env","POLYMER_WAZUH_USERNAME"); penv=wcfg.get("password_env","POLYMER_WAZUH_PASSWORD")
        ok=bool(wcfg.get("url") and os.getenv(uenv) and os.getenv(penv))
        table.add_row("wazuh_sca","ready" if ok else "incomplete",wcfg.get("url") if ok else "URL/credential env vars required")

    gcfg=cfg.get("scan",{}).get("greenbone",{})
    if not gcfg.get("enabled",False): table.add_row("greenbone","disabled","optional; enable after GVM setup")
    else:
        sock=Path(gcfg.get("socket","/run/gvmd/gvmd.sock")); creds=bool(os.getenv(gcfg.get("username_env","POLYMER_GVM_USERNAME")) and os.getenv(gcfg.get("password_env","POLYMER_GVM_PASSWORD")))
        try:
            import gvm  # noqa
            py=True
        except Exception: py=False
        ok=sock.exists() and creds and py
        table.add_row("greenbone","ready" if ok else "incomplete",f"socket={sock.exists()}, python-gvm={py}, credentials={creds}")
    console.print(table)


@app.command()
def validate(targets: Path = typer.Option(..., exists=True, readable=True), config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True)):
    cfg=load_config(config); scope=cfg.get("scope",{})
    values=parse_targets(targets,int(scope.get("max_expanded_hosts",4096)),bool(scope.get("allow_public_ips",False)))
    console.print(f"[green]Scope valid:[/green] {len(values)} unique IP addresses")


@app.command()
def plan(targets: Path = typer.Option(..., exists=True, readable=True), config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True), profile: str | None = typer.Option(None)):
    """Run discovery only and show which Phase 2 scanners would execute."""
    cfg=load_config(config); scope=cfg.get("scope",{})
    values=parse_targets(targets,int(scope.get("max_expanded_hosts",4096)),bool(scope.get("allow_public_ips",False)))
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir=Path(cfg.get("project",{}).get("output_dir","output"))/f"plan-{stamp}"
    orch=Orchestrator(cfg,run_dir,load_profile(cfg,profile))
    table=Table(title="Polymer execution plan"); table.add_column("IP"); table.add_column("Status"); table.add_column("Services"); table.add_column("Planned scanners")
    for ip in values:
        asset=orch.discover_asset(ip)
        services=", ".join(f"{s.port}/{s.protocol}:{s.name or '?'}" for s in asset.services) or "-"
        table.add_row(ip,asset.status,services,", ".join(orch.plan_asset(asset)) or "none")
    console.print(table)


@app.command()
def scan(targets: Path = typer.Option(..., exists=True, readable=True), config: Path = typer.Option(Path("config/polymer.yaml"), exists=True, readable=True), profile: str | None = typer.Option(None)):
    cfg=load_config(config); scope=cfg.get("scope",{})
    values=parse_targets(targets,int(scope.get("max_expanded_hosts",4096)),bool(scope.get("allow_public_ips",False)))
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir=Path(cfg.get("project",{}).get("output_dir","output"))/f"run-{stamp}"
    orch=Orchestrator(cfg,run_dir,load_profile(cfg,profile))
    assets=[]
    for ip in values:
        console.print(f"[cyan]Scanning[/cyan] {ip}")
        assets.append(orch.scan_asset(ip))
    write_ip_grouped_report(assets,run_dir/"polymer.json"); write_per_ip(assets,run_dir/"by_ip")
    table=Table(title="Polymer scan summary"); table.add_column("IP"); table.add_column("Status"); table.add_column("Services"); table.add_column("Findings"); table.add_column("Tools")
    for asset in assets:
        count=sum(len(x.findings) for x in asset.tools.values())
        table.add_row(asset.ip,asset.status,str(len(asset.services)),str(count),", ".join(f"{k}:{v.status}" for k,v in asset.tools.items()))
    console.print(table); console.print(f"[green]Results:[/green] {run_dir}")


if __name__ == "__main__": app()
