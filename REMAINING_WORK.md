# SentinelAPI technical readiness requirements

**Assessment date:** 2026-09-24  
**Target:** Safe, local-only hackathon MVP

## Current technical status

| Capability | Status | Evidence or gap |
| --- | --- | --- |
| Local sandbox API | Ready | FastAPI and SQLite API with two seeded users and separate orders. |
| OpenAPI ingestion | Ready for MVP | Parses OpenAPI 3.x YAML or JSON. |
| Endpoint discovery | Ready for MVP | Discovers authenticated `GET /collection/{id}` endpoints with matching collection endpoints. |
| Two-user authentication | Ready | Authenticates User A and User B using controlled demo credentials. |
| BOLA detection | Ready | Compares owner baselines and confirms when User A receives User B's object. |
| Secondary vulnerability check | Ready | Detects excessive exposure of `internal_notes` and `payment_reference`. |
| Severity and evidence | Ready | Findings include severity, score, endpoint, expected result, observed result, evidence, and remediation. |
| Reproduction requests | Ready | Generates curl commands with bearer tokens redacted. |
| Dashboard and reports | Ready | Chrome dashboard and JSON and Markdown reports work end to end. |
| Automated tests | Ready with gap | Existing suite passes 11 of 11 tests; negative controls are still required. |
| Safe target scope | Ready | Scanner rejects non-loopback targets and uses bounded read-only requests. |
| Database reset | Needs work | Reset can fail on Windows while the running server holds the SQLite file. |
| Dependency compatibility | Needs work | Test execution reports a Starlette and `httpx` deprecation warning. |

## Required technical work

### P0 Detection correctness

- [x] Add a secure negative-control test where the cross-user request returns HTTP 403 and no BOLA finding is produced.
- [x] Add the same negative-control coverage for HTTP 404.
- [x] Add a test where the cross-user response is HTTP 200 but contains a different or malformed object; it must not be reported as the victim's object.
- [x] Add a test where both users receive the same object ID and confirm that the scan is reported as inconclusive.
- [x] Add a no-findings test and verify that the report and dashboard show a successful clean result rather than an empty or failed scan.
- [x] Keep findings derived from live responses; do not introduce hardcoded scan results.

### P0 Reset and deterministic demo state

- [x] Make database reset reliable on Windows while preserving data safety.
- [x] Provide a deterministic stop-reset-start command or local-only reset mechanism.
- [x] Verify that every reset restores User A order `1001` and User B order `1002`.
- [x] Verify that repeated scans produce the same findings without mutating the database.
- [x] Add an automated reset test covering database creation, reseeding, and repeat execution.

### P0 Error handling and reliability

- [x] Return clear scan errors for invalid OpenAPI documents, unsupported versions, missing paths, and missing authenticated object endpoints.
- [x] Test login failure, missing access tokens, non-JSON login responses, and non-JSON object responses.
- [x] Test connection refusal, timeout, redirect, and partial endpoint failure behavior.
- [x] Enforce request timeouts, redirect blocking, bounded endpoint count, and response-size limits.
- [x] Ensure one failed endpoint produces a controlled error or inconclusive result rather than a crash or misleading finding.
- [x] Resolve the Starlette and `httpx` deprecation warning without breaking the test client.

### P0 Secret and evidence safety

- [x] Verify that access tokens and passwords never appear in reports, UI output, exception messages, logs, or test snapshots.
- [x] Add automated redaction tests for bearer headers and authentication failures.
- [ ] Confirm that the SQLite database, virtual environment, temporary review files, and local test artifacts are excluded from version control.
- [x] Keep the external target restriction enabled for the MVP.
- [x] Verify that uploaded specifications are size-limited and never executed as code.

### P0 Browser and report verification

- [ ] Run the complete scan in Chrome after a fresh reset.
- [ ] Verify the scan state transitions from ready to running to complete.
- [ ] Verify the expected totals: one Critical, one High, zero Medium, and zero Low.
- [ ] Expand both findings and verify expected, observed, remediation, and reproduction content.
- [ ] Verify JSON and Markdown downloads.
- [ ] Reopen both reports and confirm valid formatting, accurate evidence, and redacted tokens.
- [ ] Verify the empty-findings state using the secure negative-control target or transport.
- [ ] Check the dashboard at desktop and mobile widths for clipped, overlapping, or inaccessible controls.

### P1 Maintainability after P0

- [ ] Separate authentication, request execution, comparison, and reporting behind typed interfaces.
- [ ] Add a version field to the JSON report schema.
- [ ] Record pass, fail, inconclusive, and error outcomes separately.
- [ ] Add structured logging that excludes credentials and tokens.
- [ ] Add a continuous integration command that seeds the database and runs the full test suite.
- [ ] Document supported OpenAPI shapes and explicit MVP limitations in the README.

## Required acceptance tests

The MVP is technically ready only when all of the following pass:

1. A clean environment can install dependencies and start the local API using documented commands.
2. Database reset completes and restores the exact seeded identities and orders.
3. The complete automated test suite passes without warnings that indicate an incompatible dependency.
4. The vulnerable target produces exactly one Critical BOLA finding and one High excessive-data-exposure finding.
5. A secure 403 target produces no BOLA finding.
6. A secure 404 target produces no BOLA finding.
7. A mismatched HTTP 200 response produces no BOLA finding.
8. An inconclusive ownership comparison is labeled inconclusive rather than vulnerable.
9. Invalid specifications and network failures return controlled, understandable errors.
10. No credential or token appears in generated output.
11. JSON and Markdown reports are valid and contain reproducible redacted requests.
12. The Chrome workflow completes from reset through report download without manual data repair.
13. No request is sent to a non-loopback target.

## Codex implementation order

1. Add the secure, mismatched-response, inconclusive, and clean-result test cases.
2. Fix the Windows database reset workflow and add reset repeatability tests.
3. Harden scanner error handling, bounds, and secret redaction.
4. Resolve the dependency warning and rerun the complete suite.
5. Verify the vulnerable and secure flows in Chrome, including report downloads.
6. Add report schema versioning and explicit outcome states.
7. Run a final technical review of the Git diff and repository exclusions.

## Deferred technical features

The following are not required for the local MVP:

- General external API scanning.
- Configurable authentication profiles and token refresh.
- Swagger or OpenAPI 2.x support.
- Full `$ref`, pagination, nested-resource, and multi-identifier support.
- Live rate-limit testing.
- Write-operation testing and multi-step exploit chains.
- Scan history and trend dashboards.
- CI or CD enforcement mode.
- LLM-assisted test generation and autonomous agents.
- Production deployment, multi-tenancy, and enterprise secret management.

## Technical definition of done

SentinelAPI is technically ready when the local setup and reset are deterministic, vulnerable and secure controls produce the correct outcomes, all failure paths are bounded and understandable, secrets remain redacted, all automated tests pass, and the complete Chrome workflow generates valid downloadable reports without accessing any non-loopback target.
