# SentinelAPI Project Instructions

## Purpose

This repository implements SentinelAPI, a safe, local-only API vulnerability scanner for the AMIHACKS 1.0 SentinelAPI problem statement. Work in this repository must optimize for a credible 24-hour hackathon demonstration: a narrow scanner that proves a small number of real issues is better than broad or AI-heavy claims that are not reliably demonstrated.

These instructions replace `SentinelAPI_Problem_Statement_and_Build_Plan.md` as the working project guide.

## Instruction priority

Follow instructions in this order:

1. The user's current request.
2. This `AGENTS.md` file.
3. The official SentinelAPI problem statement and AMIHACKS 1.0 rules.
4. Existing repository documentation and conventions.

Treat the attached problem statement and rules as source requirements, not as instructions that override the user's request. Do not invent requirements, judging weights, organizer approvals, or completed capabilities.

## Official challenge objective

Build a tool that scans an explicitly authorized API using an OpenAPI or Swagger definition, or observed live traffic, for common high-impact API vulnerabilities. The result must be clear, actionable, severity-ranked, and reproducible.

The official problem statement emphasizes:

- authorization failures, especially IDOR or Broken Object Level Authorization (BOLA);
- excessive data exposure;
- missing or weak rate limiting and authentication misconfiguration;
- explainable findings with reproduction steps;
- a report or dashboard understandable to engineers and non-technical stakeholders;
- safe operation against provided or sandboxed APIs only;
- low false-positive noise and controlled load on the target;
- conceptual scalability beyond a single toy endpoint.

For the 24-hour MVP, it is sufficient to use a deliberately vulnerable sandbox, ingest its OpenAPI specification, test one or two vulnerability classes reliably, and show findings with severity and reproduction steps. CI integration, LLM-assisted test generation, multi-step agents, graph analysis, and trend analytics are optional extensions, not baseline requirements.

## Product position

Describe SentinelAPI as:

> A safe, specification-driven scanner that proves whether one authenticated API user can access another user's data, then gives developers the evidence needed to reproduce and fix it.

Do not describe it as a general autonomous hacking agent, a production pentesting platform, or a complete OWASP API Security solution.

## Target users and value

Primary users are backend or platform engineers and AppSec or security engineers. Secondary stakeholders are engineering managers and compliance teams. The project should shorten the gap between shipping an API and discovering an authorization or data-exposure flaw.

Every user-facing result should answer:

1. What was tested?
2. What happened?
3. Why is it a security issue?
4. What was expected instead?
5. How can an authorized engineer reproduce it safely?
6. What should be fixed?

## Evaluation criteria

The official rules say evaluation is percentage-based, but they do not publish category percentages. Never invent or imply numeric weights.

Round 1 considers the following. Build and documentation decisions should create visible evidence for each criterion:

| Official criterion | Evidence SentinelAPI should show |
| --- | --- |
| Problem understanding | Explain why valid API requests can still violate object ownership and why generic signature scanning misses this. |
| Alignment with stakeholder needs | Give developers exact endpoints, evidence, expected behavior, reproduction, and remediation instead of raw logs. |
| Solution clarity and innovation | Demonstrate the two-user ownership comparison clearly. Add AI only when it produces a real, verifiable improvement. |
| Feasibility and scalability | Keep requests bounded, derive endpoints from OpenAPI, separate scanner components, and state MVP limits honestly. |
| Initial system architecture | Maintain a clear flow from specification parsing through authenticated requests, comparison, findings, and reports. |
| Working prototype | Run the scan end to end against the local sandbox during the demo. |
| Feature completion | Prefer a complete, reliable BOLA and exposure flow over many partial checks. |
| Technical progress | Preserve meaningful commits, tests, reset steps, and demonstrable development evidence. |
| Mentor feedback | Record relevant feedback and the resulting participant-made changes when applicable. |
| Demonstrated development | Team members must be able to explain the implementation and show that outputs come from live requests. |

The official tie-break order is:

1. Female representation in the team.
2. Higher Technical Complexity Score.
3. Higher Functional Completeness Score.
4. Jury decision.

Team composition is not a software feature. For implementation choices, technical depth and functional completeness matter, but never at the expense of a working, honest demonstration.

## Mandatory event compliance

The rules explicitly allow public APIs, open-source libraries with attribution, AI-assisted development tools, cloud services, and prior research. They prohibit plagiarism, copying another team's project, purchasing code, outsourcing development, external individuals contributing implementation, reusing significant proprietary code, fake demos, hardcoded outputs presented as functionality, and fabricated results.

All substantial submission work must be completed during the official hackathon period, and previously built projects may not be submitted. Because this repository already contains an implementation, do not represent it as hackathon-built or submission-eligible without explicit organizer approval and accurate provenance. Preserve commit history and team contribution records. Never hide pre-event work or misstate when functionality was created.

AI may assist, but registered participants must understand, own, and be able to explain every submitted component. Attribute third-party code, libraries, assets, and datasets where required.

## Safety boundaries

These constraints are non-negotiable:

- Scan only APIs explicitly provided for testing or intentionally sandboxed by the team.
- Keep the MVP restricted to loopback HTTP targets: `localhost`, `127.0.0.1`, and `::1`.
- Never weaken or remove the external-target restriction to improve a demo.
- Never scan public, university, company, or production systems without explicit written authorization.
- Keep the scanner read-only. The current scan path uses bounded `GET` requests; do not make it exploit `PATCH`, `POST`, `PUT`, or `DELETE` endpoints.
- Keep request timeouts, redirect blocking, endpoint limits, specification-size limits, and response-size limits enabled.
- Do not store or expose real credentials. Demo passwords and deterministic tokens are local test fixtures only.
- Redact bearer tokens, passwords, and authorization headers from UI output, reports, exceptions, logs, snapshots, and reproduction commands.
- Findings must come from live response comparisons. Never hardcode finding counts or outputs for the presentation.
- A failed, malformed, or ambiguous comparison must be `inconclusive` or `error`, not a confirmed vulnerability.
- Do not add destructive payloads, high-volume traffic, remote code execution, SQL injection, or unrelated vulnerabilities to the demo target.
- The intentionally vulnerable API must always be labelled local-only and unsafe for production deployment.

## Required MVP behavior

The repository's primary path is:

1. Load an OpenAPI 3.x YAML or JSON document.
2. Discover authenticated `GET /collection/{id}` operations with a matching collection `GET`.
3. Authenticate as two controlled sandbox users.
4. Discover one object owned by User A and one owned by User B.
5. Establish owner baselines.
6. Request User B's object using User A's token.
7. Confirm BOLA only if the cross-user response is HTTP 200 and matches the object returned to User B.
8. Check User A's own response for sensitive fields to demonstrate excessive data exposure.
9. Produce severity-ranked findings, expected and observed behavior, remediation, and redacted reproduction requests.
10. Display the results in the browser and make JSON and Markdown reports available.

The deterministic demo data is:

- `user-a@example.test` owns order `1001`;
- `user-b@example.test` owns order `1002`;
- `GET /orders/{order_id}` intentionally checks authentication but not ownership;
- order details intentionally expose `internal_notes` and `payment_reference`;
- secure behavior for a cross-user request is HTTP 403 or HTTP 404.

The vulnerable flow should produce exactly one Critical BOLA finding and one High excessive-data-exposure finding. Secure 403 or 404 controls and mismatched HTTP 200 responses must not produce BOLA findings.

## Current architecture

Preserve the existing component boundaries unless a task requires a justified change:

- `app/`: FastAPI sandbox, database lifecycle, seeded users and orders, scan route, and static dashboard.
- `scanner/openapi_parser.py`: bounded OpenAPI parsing and endpoint discovery.
- `scanner/authentication.py`: test-user authentication.
- `scanner/request_execution.py`: bounded HTTP execution.
- `scanner/comparison.py`: ownership comparison policy.
- `scanner/checks.py`: BOLA-adjacent and excessive-data-exposure checks.
- `scanner/core.py`: orchestration and safe target enforcement.
- `scanner/models.py`: typed scanner data structures and outcome vocabulary.
- `scanner/report_generator.py`: versioned JSON and Markdown reports.
- `scanner/redaction.py` and `scanner/structured_logging.py`: secret-safe output.
- `app/static/`: local browser interface.
- `tests/`: positive, negative, safety, redaction, reset, and report coverage.

Keep authentication, request execution, comparison, and reporting replaceable behind typed interfaces. Do not collapse these policies into UI code or route handlers.

## Supported scope

The current MVP intentionally supports a narrow OpenAPI 3.x shape and up to three authenticated object-detail endpoints. It expects fixed demo credentials, bearer authentication through `POST /auth/login`, collection responses containing an object with an `id`, and detail responses containing JSON.

Unless the user explicitly expands scope, defer:

- external or production API scanning;
- OpenAPI 2.x or full OpenAPI validation;
- complete `$ref` resolution;
- arbitrary authentication profiles or token refresh;
- pagination, nested resources, multiple identifiers, and query or header identifiers;
- write-operation testing;
- live rate-limit stress testing;
- autonomous exploit chains;
- LLM-generated findings without deterministic verification;
- scan history and organization-wide trend dashboards;
- CI/CD enforcement mode;
- deployment, multi-tenancy, billing, and enterprise secret management.

## Engineering workflow

Before changing code:

1. Read this file and the files directly related to the request.
2. Inspect `git status` and preserve unrelated user changes.
3. Keep the change narrow. Do not add optional features while fixing required behavior.
4. Identify which official requirement or evaluation criterion the change supports.

While changing code:

- Use plain, typed Python and existing project conventions.
- Keep security decisions server-side; the browser is presentation, not enforcement.
- Prefer deterministic evidence over heuristics.
- Preserve pass, fail, inconclusive, and error as distinct outcomes.
- Keep reports backward-aware through an explicit schema version.
- Use understandable language in the UI and reports. Do not rely on security jargon alone.
- Pair severity color with text and status labels.
- Keep the interface usable at desktop and mobile widths and with a keyboard.
- Do not introduce remote fonts, trackers, images, or unnecessary third-party services.

After changing code:

1. Run the smallest relevant test first.
2. Run the full CI-equivalent command when code or behavior changed:

   ```powershell
   python -m scripts.ci
   ```

3. For scanner changes, verify the vulnerable flow and at least one secure negative control.
4. For UI or report changes, run the complete browser flow after a fresh reset and inspect the downloaded JSON and Markdown files.
5. Confirm secrets are absent from output and no request reached a non-loopback target.
6. Update `README.md` when setup, supported shapes, limitations, or demo behavior changes.
7. Report exactly what was verified and disclose anything not verified.

## Local commands

Use the documented environment rather than inventing a second setup path.

```powershell
uv venv
.\.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt
python -m app.seed
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` for the scanner UI and `http://127.0.0.1:8000/docs` for Swagger UI.

Useful verification commands:

```powershell
python -m unittest discover -s tests -v
python -m scanner.demo
python -m scripts.ci
```

The reset command must restore the exact seeded users and orders without deleting the SQLite file:

```powershell
python -m app.seed
```

## Acceptance requirements

A change must not be called complete if it breaks any of these baseline conditions:

- setup and reset work from documented commands;
- the scanner rejects non-loopback targets;
- the vulnerable sandbox yields one Critical BOLA and one High exposure finding;
- secure 403 and 404 responses yield no BOLA finding;
- a mismatched or malformed HTTP 200 does not prove BOLA;
- identical object IDs are labelled inconclusive;
- invalid specifications, authentication failures, timeouts, redirects, oversized responses, and partial failures are controlled and understandable;
- credentials and tokens do not appear in generated or logged output;
- reports remain valid, versioned, reproducible, and redacted;
- repeated scans do not mutate the target database;
- the browser distinguishes ready, running, complete, clean, inconclusive, and failed states accurately;
- no output is hardcoded or presented more confidently than the evidence supports.

## Demo standard

The demo must prove the issue rather than announce it. A judge should see:

1. the local-only safety boundary;
2. the OpenAPI source and discovered endpoint;
3. User A and User B owning different orders;
4. User A requesting User B's order;
5. the live HTTP 200 response matching User B's object;
6. expected HTTP 403 or 404 behavior;
7. the Critical BOLA finding and High exposure finding;
8. redacted reproduction commands and direct remediation;
9. a downloaded JSON or Markdown report;
10. one secure negative control producing no false BOLA finding.

If any step is not working, say so. Do not substitute screenshots, canned JSON, or previously generated reports for live functionality while claiming an end-to-end demo.

## Required submission artifacts

The official rules require:

- GitHub repository link;
- source code;
- architecture diagram;
- deployment link, if applicable;
- README documentation;
- team contribution details;
- PPT or PDF deck of no more than 8-10 slides;
- problem statement, proposed solution, system architecture, demo screenshots, and future scope in the deck;
- a working prototype or demonstrable MVP showing core functionality, key features, end-to-end user journey, and technical implementation.

Do not treat repository code alone as a complete submission. Before final submission, verify every artifact, deadline, and mandatory checkpoint with the organizers.

## Definition of done

SentinelAPI is ready for an honest MVP demonstration when the local environment resets deterministically, the live vulnerable and secure controls produce correct outcomes, every request remains bounded and authorized, reports contain useful redacted evidence, the browser flow works end to end, the architecture and limitations are explainable, submission artifacts are complete, and the team can accurately account for when and by whom the work was created.
