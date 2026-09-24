# SentinelAPI Scanner Module

This repository currently contains the reporting module for SentinelAPI. It evaluates evidence produced by the local sandbox scanner, assigns transparent severity, creates safe reproduction commands, and writes JSON and Markdown reports.

## Run the demo

```powershell
python -m scanner.demo
```

The command creates these files:

```text
reports/sentinel_report.json
reports/sentinel_report.md
```

## Run tests

```powershell
python -m unittest discover -s tests -v
```

The module is local-only. It does not scan real targets and its secondary checks never issue network requests.
