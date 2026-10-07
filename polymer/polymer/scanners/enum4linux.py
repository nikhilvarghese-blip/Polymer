from __future__ import annotations

import json
import shutil
from polymer.core.services import smb_present
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import run_command


class Enum4LinuxScanner(Scanner):
    name="enum4linux"

    def available(self)->bool:
        return shutil.which(self.config.get("binary","enum4linux-ng")) is not None

    def run(self, asset: Asset)->ToolResult:
        if not self.available(): return ToolResult(tool=self.name,status="unavailable",message="enum4linux-ng not found")
        if not smb_present(asset): return ToolResult(tool=self.name,status="not_applicable",message="no SMB service detected")
        base=self.workdir / asset.ip
        cmd=[self.config.get("binary","enum4linux-ng"),"-As","-oJ",str(base),asset.ip]
        proc=run_command(cmd,timeout=int(self.config.get("timeout",600)))
        candidates=[base.with_suffix('.json'), self.workdir / f"{asset.ip}.json"]
        outfile=next((p for p in candidates if p.exists()),None)
        if outfile is None:
            return ToolResult(tool=self.name,status="failed" if proc.returncode else "completed",message=proc.stderr.strip() or "no JSON artifact produced")
        try: data=json.loads(outfile.read_text(errors="replace"))
        except json.JSONDecodeError:
            return ToolResult(tool=self.name,status="failed",raw_artifact=str(outfile),message="invalid enum4linux JSON")
        findings=[]
        # Conservative: report clearly risky SMB observations only, keep the rest in raw evidence.
        text=json.dumps(data).lower()
        if 'signing' in text and ('disabled' in text or 'not required' in text):
            findings.append(Finding(tool=self.name,title="SMB signing appears disabled or not required",severity="medium",category="smb",port=445,protocol="tcp",evidence={"raw_artifact":str(outfile)}))
        if 'anonymous' in text and ('allowed' in text or 'success' in text):
            findings.append(Finding(tool=self.name,title="Anonymous SMB/NetBIOS access may be available",severity="medium",category="smb",port=445,protocol="tcp",evidence={"raw_artifact":str(outfile)}))
        return ToolResult(tool=self.name,status="completed",findings=findings,raw_artifact=str(outfile))
