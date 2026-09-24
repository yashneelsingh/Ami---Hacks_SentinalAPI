"""Generate JSON and Markdown reports from confirmed SentinelAPI findings."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import Finding
from .redaction import redact_value
from .reproduction import build_curl
from .severity import sort_key


REPORT_SCHEMA_VERSION = "1.2"
_REPORT_WRITE_LOCK = threading.Lock()


class JsonReporter:
    """Default implementation of the typed reporting boundary."""

    def build(self, findings: Iterable[Finding], target_name: str, *, secrets: Iterable[str] = ()) -> dict:
        return build_report(findings, target_name, secrets=secrets)


def _summary(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity: counts.get(severity, 0) for severity in ("Critical", "High", "Medium", "Low", "Pass")}


def build_report(findings: Iterable[Finding], target_name: str, *, secrets: Iterable[str] = ()) -> dict:
    ordered = sorted(list(findings), key=sort_key, reverse=True)
    report = {
        "tool": "SentinelAPI",
        "version": REPORT_SCHEMA_VERSION,
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": target_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": _summary(ordered),
        "findings": [finding.to_dict() for finding in ordered],
    }
    return redact_value(report, secrets)


def markdown_report(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# SentinelAPI Scan Report",
        "",
        f"**Schema version:** {report.get('schema_version', report['version'])}",
        f"**Target:** {report['target']}",
        f"**Generated:** {report['generated_at']}",
        f"**Scan status:** {report.get('scan_status', 'completed').capitalize()}",
        f"**Result:** {report.get('result', 'findings' if report.get('findings') else 'clean').capitalize()}",
        "",
        "## Summary",
        "",
        "| Critical | High | Medium | Low | Pass |",
        "| --- | --- | --- | --- | --- |",
        f"| {summary['Critical']} | {summary['High']} | {summary['Medium']} | {summary['Low']} | {summary['Pass']} |",
        "",
    ]
    outcome_counts = report.get("outcome_counts")
    if outcome_counts:
        lines.extend([
            "## Endpoint outcomes",
            "",
            "| Pass | Fail | Inconclusive | Error |",
            "| --- | --- | --- | --- |",
            f"| {outcome_counts['pass']} | {outcome_counts['fail']} | {outcome_counts['inconclusive']} | {outcome_counts['error']} |",
            "",
        ])
    tested_endpoints = report.get("tested_endpoints", [])
    if tested_endpoints:
        lines.extend(["## Tested endpoints", ""])
        for endpoint in tested_endpoints:
            lines.append(f"- `{endpoint['method']} {endpoint['endpoint']}`: {endpoint['outcome']}; {endpoint.get('reason', '')}")
            if "owner_a_id" in endpoint and "owner_b_id" in endpoint:
                lines.append(f"  - Selected IDs: User A `{endpoint['owner_a_id']}`, User B `{endpoint['owner_b_id']}`; cross-user HTTP `{endpoint.get('cross_user_status', 'not tested')}`.")
        lines.append("")
    if "fixture_version" in report:
        lines.extend([f"**Fixture version:** {report['fixture_version']}", ""])
    findings = report["findings"]
    if not findings:
        message = (
            "The scan completed successfully with no confirmed findings."
            if report.get("result", "clean") == "clean"
            else "The scan was incomplete or inconclusive; review the endpoint outcomes."
        )
        lines.extend(["## Findings", "", message])
        return "\n".join(lines) + "\n"

    lines.extend(["## Findings", ""])
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. [{finding['severity']}] {finding['title']}",
                "",
                f"- **Endpoint:** `{finding['method']} {finding['endpoint']}`",
                f"- **Score:** {finding['score']}/10",
                f"- **Evidence:** {finding['evidence']}",
                f"- **Expected:** {finding['expected_result']}",
                f"- **Observed:** {finding['actual_result']}",
                f"- **Fix:** {finding['remediation']}",
                "",
                "**Safe reproduction command**",
                "",
                "```bash",
                build_curl(finding["request"]),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def write_reports(report: dict, output_dir: str | Path) -> tuple[Path, Path]:
    """Stage both formats before replacing reports, serializing concurrent writers."""
    json_text = json.dumps(report, indent=2) + "\n"
    markdown_text = markdown_report(report)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "sentinel_report.json"
    markdown_path = output / "sentinel_report.md"
    staged: list[Path] = []
    backups: dict[Path, Path] = {}
    with _REPORT_WRITE_LOCK:
        try:
            for content in (json_text, markdown_text):
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=output, prefix=".sentinel-stage-", delete=False) as file:
                    staged.append(Path(file.name))
                    file.write(content)
            for destination in (json_path, markdown_path):
                if destination.exists():
                    with tempfile.NamedTemporaryFile(dir=output, prefix=".sentinel-backup-", delete=False) as file:
                        backup = Path(file.name)
                    backups[destination] = backup
                    shutil.copyfile(destination, backup)
            replaced: list[Path] = []
            try:
                for source, destination in zip(staged, (json_path, markdown_path)):
                    os.replace(source, destination)
                    replaced.append(destination)
            except OSError:
                for destination in reversed(replaced):
                    backup = backups.get(destination)
                    if backup is not None:
                        os.replace(backup, destination)
                    else:
                        destination.unlink(missing_ok=True)
                raise
        finally:
            for path in (*staged, *backups.values()):
                path.unlink(missing_ok=True)
    return json_path, markdown_path

