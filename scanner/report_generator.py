"""Generate JSON and Markdown reports from confirmed SentinelAPI findings."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import Finding
from .redaction import redact_value
from .reproduction import build_curl
from .severity import sort_key


REPORT_SCHEMA_VERSION = "1.1"


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
    findings = report["findings"]
    if not findings:
        message = (
            "The scan completed successfully with no confirmed findings."
            if report.get("result", "clean") == "clean"
            else "The scan completed, but the ownership comparison was inconclusive."
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
    """Write machine-readable JSON and human-readable Markdown reports."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "sentinel_report.json"
    markdown_path = output / "sentinel_report.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown_report(report), encoding="utf-8")
    return json_path, markdown_path

