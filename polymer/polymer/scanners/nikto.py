from __future__ import annotations

import json
import shutil
from polymer.core.services import web_endpoints
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import run_command


class NiktoScanner(Scanner):
    name="nikto"

    def available(self)->bool:
        return shutil.which(self.config.get("binary","nikto")) is not None

    def run(self, asset: Asset)->ToolResult:
        if not self.available(): return ToolResult(tool=self.name,status="unavailable",message="nikto not found")
        endpoints=web_endpoints(asset)
        if not endpoints: return ToolResult(tool=self.name,status="not_applicable",message="no HTTP(S) service detected")
        findings=[]; artifacts=[]
        for url,port in endpoints:
            outfile=self.workdir / f"{asset.ip}_{port}.json"
            cmd=[self.config.get("binary","nikto"),"-host",url,"-nointeractive","-Format","json","-output",str(outfile)]
            tuning=self.config.get("tuning")
            if tuning: cmd += ["-Tuning", str(tuning)]
            proc=run_command(cmd,timeout=int(self.config.get("timeout",900)))
            if not outfile.exists():
                continue
            artifacts.append(str(outfile))
            try: data=json.loads(outfile.read_text(errors="replace"))
            except json.JSONDecodeError: continue
            vulns=data.get("vulnerabilities") or data.get("items") or [] if isinstance(data,dict) else []
            if isinstance(vulns,dict): vulns=list(vulns.values())
            for v in vulns:
                if not isinstance(v,dict): continue
                msg=v.get("msg") or v.get("message") or v.get("description") or v.get("OSVDB")
                if not msg: continue
                findings.append(Finding(tool=self.name,title=str(msg),severity="unknown",category="web",port=port,protocol="tcp",evidence={k:v.get(k) for k in ("id","url","method","OSVDB") if v.get(k) is not None}))
        return ToolResult(tool=self.name,status="completed",findings=findings,raw_artifact=", ".join(artifacts) or None)
