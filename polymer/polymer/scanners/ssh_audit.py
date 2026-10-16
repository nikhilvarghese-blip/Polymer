from __future__ import annotations

from collections import defaultdict
import json
import shutil
from typing import Any

from polymer.core.services import ssh_ports
from polymer.models.schema import Asset, Finding, ToolResult
from polymer.scanners.base import Scanner
from polymer.utils.command import CommandExecutionError, run_command


ALGORITHM_LABELS = {
    "kex": "key exchange",
    "key": "host key",
    "enc": "encryption",
    "mac": "message authentication code (MAC)",
}

SEVERITY_MAP = {
    # ssh-audit's labels are retained in evidence. These values only normalize
    # them to Polymer's report schema.
    "critical": "critical",
    "fail": "high",
    "warning": "medium",
    "warn": "medium",
    "informational": "info",
    "info": "info",
}

SEVERITY_RANK = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

ACTION_VERBS = {
    "del": "remove",
    "add": "add",
    "chg": "change",
}


def _strings(value: object) -> list[str]:
    """Return scanner-provided text without stringifying objects into reports."""
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, list):
        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]
    return []


class SSHAuditScanner(Scanner):
    name = "ssh_audit"

    def available(self) -> bool:
        return shutil.which(self.config.get("binary", "ssh-audit")) is not None

    @staticmethod
    def _recommendations(data: dict[str, Any]) -> list[dict[str, str]]:
        """Flatten ssh-audit's severity/action/type recommendation hierarchy."""
        output: list[dict[str, str]] = []
        recommendations = data.get("recommendations")
        if not isinstance(recommendations, dict):
            return output

        for source_level, actions in recommendations.items():
            severity = SEVERITY_MAP.get(str(source_level).lower())
            if severity is None or not isinstance(actions, dict):
                continue
            for action, algorithm_types in actions.items():
                action = str(action).lower()
                if action not in ACTION_VERBS or not isinstance(algorithm_types, dict):
                    continue
                for algorithm_type, entries in algorithm_types.items():
                    algorithm_type = str(algorithm_type).lower()
                    if algorithm_type not in ALGORITHM_LABELS:
                        continue
                    if isinstance(entries, dict):
                        entries = [
                            {
                                "name": name,
                                **(details if isinstance(details, dict) else {}),
                            }
                            for name, details in entries.items()
                        ]
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        if isinstance(entry, str):
                            name = entry.strip()
                            notes = ""
                        elif isinstance(entry, dict):
                            raw_name = entry.get("name") or entry.get("algorithm")
                            name = (
                                raw_name.strip()
                                if isinstance(raw_name, str)
                                else ""
                            )
                            notes = "; ".join(_strings(entry.get("notes")))
                        else:
                            continue
                        if not name:
                            continue
                        output.append(
                            {
                                "source_level": str(source_level).lower(),
                                "severity": severity,
                                "action": action,
                                "algorithm_type": algorithm_type,
                                "name": name,
                                "notes": notes,
                            }
                        )
        return output

    @staticmethod
    def _algorithm_issues(data: dict[str, Any]) -> list[dict[str, object]]:
        """Extract only ssh-audit failure/warning notes, excluding informational notes."""
        output: list[dict[str, object]] = []
        for algorithm_type in ALGORITHM_LABELS:
            block = data.get(algorithm_type)
            if isinstance(block, dict):
                entries: list[dict[str, Any]] = []
                for name, details in block.items():
                    if not isinstance(details, dict):
                        continue
                    entries.append({"algorithm": name, **details})
            elif isinstance(block, list):
                entries = [entry for entry in block if isinstance(entry, dict)]
            else:
                continue

            for entry in entries:
                raw_name = entry.get("algorithm") or entry.get("name")
                name = raw_name.strip() if isinstance(raw_name, str) else ""
                if not name:
                    continue
                notes = entry.get("notes")
                labeled_notes = notes if isinstance(notes, dict) else {}
                failures = _strings(labeled_notes.get("fail")) + _strings(
                    entry.get("fail")
                )
                warnings = _strings(labeled_notes.get("warn")) + _strings(
                    entry.get("warn")
                )
                warnings += _strings(entry.get("warnings"))
                if not failures and not warnings:
                    continue
                output.append(
                    {
                        "algorithm_type": algorithm_type,
                        "name": name,
                        "fail": list(dict.fromkeys(failures)),
                        "warn": list(dict.fromkeys(warnings)),
                    }
                )
        return output

    @staticmethod
    def _remediation(recommendation: dict[str, str]) -> str:
        label = ALGORITHM_LABELS[recommendation["algorithm_type"]]
        verb = ACTION_VERBS[recommendation["action"]]
        action = (
            f"{verb.capitalize()} SSH {label} algorithm "
            f"'{recommendation['name']}'"
        )
        if recommendation["notes"]:
            action += f": {recommendation['notes']}"
        return "ssh-audit recommendation: " + action + "."

    @classmethod
    def _findings(cls, data: dict[str, Any], port: int) -> list[Finding]:
        recommendations = cls._recommendations(data)
        issues = cls._algorithm_issues(data)
        recommendations_by_algorithm: dict[
            tuple[str, str], list[dict[str, str]]
        ] = defaultdict(list)
        for recommendation in recommendations:
            recommendations_by_algorithm[
                (recommendation["algorithm_type"], recommendation["name"])
            ].append(recommendation)

        issue_by_algorithm = {
            (str(issue["algorithm_type"]), str(issue["name"])): issue
            for issue in issues
        }
        ordered_keys = list(issue_by_algorithm)
        ordered_keys.extend(
            key
            for key in recommendations_by_algorithm
            if key not in issue_by_algorithm
        )

        findings: list[Finding] = []
        for algorithm_type, name in ordered_keys:
            issue = issue_by_algorithm.get((algorithm_type, name), {})
            matching_recommendations = recommendations_by_algorithm.get(
                (algorithm_type, name), []
            )
            failure_notes = list(issue.get("fail", []))
            warning_notes = list(issue.get("warn", []))
            source_levels = [
                *("fail" for _note in failure_notes),
                *("warn" for _note in warning_notes),
                *(item["source_level"] for item in matching_recommendations),
            ]
            normalized_severities = [
                SEVERITY_MAP[level]
                for level in source_levels
                if level in SEVERITY_MAP
            ]
            severity = max(
                normalized_severities,
                key=lambda value: SEVERITY_RANK[value],
                default="unknown",
            )

            descriptions = list(dict.fromkeys([*failure_notes, *warning_notes]))
            descriptions.extend(
                item["notes"]
                for item in matching_recommendations
                if item["notes"] and item["notes"] not in descriptions
            )
            remediation = "; ".join(
                dict.fromkeys(
                    cls._remediation(item) for item in matching_recommendations
                )
            )
            label = ALGORITHM_LABELS[algorithm_type]
            if matching_recommendations:
                actions = list(
                    dict.fromkeys(
                        ACTION_VERBS[item["action"]]
                        for item in matching_recommendations
                    )
                )
                title = (
                    f"SSH recommendation to {'/'.join(actions)} "
                    f"{label} algorithm: {name}"
                )
            else:
                title = f"SSH {label} algorithm security issue: {name}"

            if descriptions:
                description = "; ".join(descriptions)
            else:
                levels = ", ".join(dict.fromkeys(source_levels))
                actions = ", ".join(
                    dict.fromkeys(
                        ACTION_VERBS[item["action"]]
                        for item in matching_recommendations
                    )
                )
                description = (
                    f"ssh-audit recommendation: level={levels}; "
                    f"action={actions}; algorithm type={label}."
                )

            findings.append(
                Finding(
                    tool=cls.name,
                    title=title,
                    severity=severity,
                    category="ssh",
                    port=port,
                    protocol="tcp",
                    check_id=f"{algorithm_type}:{name}",
                    evidence={
                        "description": description,
                        "algorithm": name,
                        "algorithm_type": algorithm_type,
                        "ssh_audit_levels": list(dict.fromkeys(source_levels)),
                        "scanner_notes": {
                            "fail": failure_notes,
                            "warn": warning_notes,
                        },
                        "scanner_recommendations": matching_recommendations,
                    },
                    remediation=remediation or None,
                )
            )
        return findings

    def run(self, asset: Asset) -> ToolResult:
        if not self.available():
            return ToolResult(
                tool=self.name,
                status="unavailable",
                message="ssh-audit not found",
            )
        ports = ssh_ports(asset)
        if not ports:
            return ToolResult(
                tool=self.name,
                status="not_applicable",
                message="no SSH service detected",
            )

        findings: list[Finding] = []
        artifacts: list[str] = []
        errors: list[str] = []
        successful = 0
        for port in ports:
            outfile = self.workdir / f"{asset.ip}_{port}.json"
            try:
                proc = run_command(
                    [
                        self.config.get("binary", "ssh-audit"),
                        "-j",
                        f"{asset.ip}:{port}",
                    ],
                    timeout=self.timeout(float(self.config.get("timeout", 120))),
                )
            except CommandExecutionError as exc:
                errors.append(f"{asset.ip}:{port}: {exc}")
                continue
            raw = proc.stdout.strip()
            if raw:
                outfile.write_text(raw, encoding="utf-8", errors="replace")
                artifacts.append(str(outfile))
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    errors.append(f"{asset.ip}:{port}: invalid JSON: {exc}")
                    continue
                if not isinstance(data, dict):
                    errors.append(f"{asset.ip}:{port}: JSON root is not an object")
                    continue
                successful += 1
                findings.extend(self._findings(data, port))
            elif proc.returncode != 0:
                errors.append(
                    proc.stderr.strip()
                    or f"ssh-audit exited with code {proc.returncode}"
                )
            else:
                errors.append(f"{asset.ip}:{port}: ssh-audit returned no JSON")
        status = "completed" if successful else "failed"
        return ToolResult(
            tool=self.name,
            status=status,
            findings=findings,
            raw_artifact=", ".join(artifacts) or None,
            message="; ".join(errors) or None,
        )
