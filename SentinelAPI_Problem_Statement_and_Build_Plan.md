# SentinelAPI Problem Statement and Build Plan

## What SentinelAPI Is

SentinelAPI is a zero-trust API vulnerability scanner for authorized, sandboxed APIs. It should help engineering and security teams find high-impact API security weaknesses before the API is released or exploited.

The core problem is that API security reviews are often manual, infrequent, and too expensive for smaller teams. Generic web scanners also miss business-logic flaws such as one authenticated user accessing another user's resource.

## Hackathon Problem Statement Requirements

Build a tool that accepts an API definition, preferably an OpenAPI or Swagger specification, and tests the API for common high-impact vulnerabilities. It must return clear, severity-ranked, explainable findings rather than only raw logs.

### Required capabilities

- Ingest an OpenAPI or Swagger specification. Live traffic input is optional.
- Test for authorization flaws, especially IDOR or BOLA, by changing object identifiers between two authenticated users.
- Detect at least one additional issue, such as excessive data exposure, weak authentication configuration, or missing rate limiting.
- Produce findings with severity, affected endpoint, evidence, and clear reproduction steps.
- Generate a reproducible proof-of-concept request for every finding.
- Show results in a simple report or dashboard.

### Safety requirements

- Test only APIs explicitly provided for the event or intentionally sandboxed for testing.
- Never scan a real production API without written authorization.
- Do not store credentials or tokens insecurely.
- Keep test traffic controlled so the scanner does not crash or degrade the target API.

## Recommended 24-Hour MVP

Do not try to build a complete commercial API-security platform. Build one reliable, demonstrable scanning path.

### Demo target

Provide an intentionally vulnerable demo API with:

- Two test accounts: User A and User B.
- Resources owned by each user, such as `/orders/{id}` or `/profiles/{id}`.
- At least one IDOR or BOLA vulnerability: User A can retrieve or modify User B's resource by changing an ID.
- One additional seeded issue, ideally excessive data exposure or missing rate limiting.
- An OpenAPI specification for the API.

## Test API To Be Developed by Gemini or Claude

Gemini or Claude will develop the API used only for SentinelAPI testing. This API is not a production service and must be clearly labelled as an intentionally vulnerable local sandbox.

### Required API characteristics

- Use a simple local stack, such as Node.js with Express and SQLite, or Python with FastAPI and SQLite.
- Run locally with seeded test data only. Do not connect it to real accounts, external payment systems, or production databases.
- Include an OpenAPI 3.x specification at `/openapi.json` or as a checked-in `openapi.yaml` file.
- Include a README with setup commands, test credentials, endpoint list, and the intentional vulnerabilities.
- Include a reset or seed command so the demo can always return to its original state.

### Recommended data model

Use an order-management API because object ownership is easy to demonstrate:

```text
User
- id
- email
- password (test-only)
- role

Order
- id
- ownerId
- itemName
- amount
- shippingAddress
- internalNotes
- paymentReference
```

### Required endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /auth/login` | Returns a test token for User A or User B. |
| `GET /orders` | Returns orders for the logged-in user. |
| `GET /orders/{id}` | Fetches one order. This is the primary BOLA test endpoint. |
| `PATCH /orders/{id}` | Updates an order. Optional second BOLA test endpoint. |
| `GET /profile` | Returns the current user profile. Useful for an excessive-data-exposure test. |
| `GET /health` | Simple health endpoint for the demo and scanner. |

### Seeded test identities and data

- `user-a@example.test` owns order `1001`.
- `user-b@example.test` owns order `1002`.
- SentinelAPI authenticates as User A, reads order `1001`, then tries order `1002`.
- The intentionally vulnerable version must incorrectly return HTTP 200 and User B's order data for User A's request to `GET /orders/1002`.
- The expected secure behaviour is HTTP 403 or HTTP 404.

### Intentional vulnerabilities

Include only controlled, documented flaws needed for the demo:

1. **Primary: BOLA / IDOR** - `GET /orders/{id}` checks that a token exists but does not verify that the order belongs to the authenticated user.
2. **Optional: excessive data exposure** - `GET /profile` or `GET /orders/{id}` returns fields such as `internalNotes` or `paymentReference` that should not be exposed to a normal user.
3. **Optional: weak rate limiting** - a safe test endpoint has no rate limiting, allowing SentinelAPI to demonstrate a low-volume threshold check. Do not use high-volume requests.

Do not add unrelated vulnerabilities such as remote code execution, SQL injection, real credential handling, or publicly accessible deployment. The goal is a deterministic and safe scanner demo.

### Copyable prompt for Gemini or Claude

```text
Build a local-only, intentionally vulnerable order-management REST API for a hackathon security demo. Use [Express + SQLite / FastAPI + SQLite]. Include OpenAPI 3.x documentation, a README, seed/reset scripts, and two test users: user-a@example.test and user-b@example.test.

Implement POST /auth/login, GET /orders, GET /orders/{id}, PATCH /orders/{id}, GET /profile, and GET /health. Seed order 1001 for User A and order 1002 for User B.

Intentionally make GET /orders/{id} vulnerable to broken object-level authorization: any authenticated user can retrieve any order by ID, including User A retrieving order 1002. Clearly mark this as an intentional local-only vulnerability in comments and the README. Also optionally expose internalNotes and paymentReference in one normal-user response to demonstrate excessive data exposure.

Do not deploy the API, do not use real credentials or external services, and do not include vulnerabilities beyond those needed for the controlled demo. Provide setup commands, test credentials, a reset command, and openapi.yaml.
```

### Scanner flow

1. Upload or select the OpenAPI specification.
2. Parse endpoints, path parameters, request fields, and authentication requirements.
3. Authenticate as User A and User B using event-provided test credentials.
4. Call an endpoint with User A's own object ID to establish expected behaviour.
5. Replace that ID with User B's object ID and repeat the request.
6. Compare the response with the expected authorization outcome.
7. Create a finding if User A can read, change, or delete User B's data.
8. Run one secondary check, such as looking for sensitive response fields or testing a rate-limit threshold safely.
9. Generate a report containing severity, evidence, affected endpoint, and a copyable reproduction request.

## Definition of a Good Demo

The demo should prove a real vulnerability, not merely claim one.

For example:

```text
Finding: Critical - Broken Object Level Authorization
Endpoint: GET /orders/{id}
Authenticated user: user-a@example.test
Changed identifier: 1042 to 1043
Observed result: HTTP 200 and User B's order details returned
Expected result: HTTP 403 or HTTP 404
Reproduction: curl command generated by SentinelAPI
```

## Suggested Technical Architecture

```text
OpenAPI specification
        |
        v
Endpoint and parameter parser
        |
        v
Authenticated request runner using two sandbox users
        |
        +--> BOLA / IDOR test module
        +--> Excessive data exposure check
        +--> Optional safe rate-limit check
        |
        v
Finding scorer and evidence collector
        |
        v
HTML dashboard or Markdown/JSON report
```

## Four-Person Build Split

Each person owns one working part of the demo. Agree on the OpenAPI format, request/response structure, and finding JSON schema before implementation begins.

### Person 1 - Test API and environment owner

- Use Gemini or Claude to generate the local intentionally vulnerable order API from the prompt above.
- Verify the two test users, orders `1001` and `1002`, login, reset script, and OpenAPI file all work locally.
- Confirm that User A can incorrectly retrieve User B's order through the seeded BOLA vulnerability.
- Write the setup README and share the base URL, test credentials, and OpenAPI location with the team.
- Keep the target local-only and resettable before every final demo.

### Person 2 - OpenAPI parser and BOLA scanner owner

- Parse `openapi.yaml` or `/openapi.json` to discover endpoints, path parameters, and authentication requirements.
- Implement login and authenticated request handling for User A and User B.
- Build the core BOLA or IDOR test: access an object owned by User A, replace its ID with User B's ID, then compare the result.
- Save request, response status, response body evidence, and expected secure behaviour in a structured finding.
- This is the most important ownership area: it must work reliably before extra features are added.

### Person 3 - Secondary checks and report engine owner

- Implement one secondary check: excessive data exposure is recommended because it is deterministic and easy to show.
- Add severity scoring: `Critical`, `High`, `Medium`, or `Pass`.
- Generate a reproducible curl command or raw HTTP request for each confirmed finding.
- Define a shared finding JSON format containing title, severity, endpoint, evidence, expected result, actual result, and remediation.
- Produce a Markdown or JSON report even if the dashboard is unfinished.

### Person 4 - Dashboard, integration, and demo owner

- Build the simple UI: choose/upload spec, start scan, show scan progress, and display findings.
- Render findings in judge-friendly language: what was accessed, why it is dangerous, and how to reproduce it.
- Integrate the scanner and report output from Persons 2 and 3; do not duplicate scanning logic in the frontend.
- Own end-to-end testing, reset the sandbox API before demos, and prepare the final 2-minute demonstration flow.
- Prepare slides or a short narrative only after the end-to-end scan works.

### Shared schedule

| Time | Whole-team target |
| --- | --- |
| Hours 0-2 | Agree on stack, OpenAPI contract, seeded data, and the finding JSON schema. |
| Hours 2-6 | Test API works; User A can access User B's order; scanner makes authenticated calls. |
| Hours 6-12 | Confirmed BOLA finding and generated reproduction command. |
| Hours 12-18 | Secondary check, severity scoring, dashboard integration. |
| Hours 18-24 | End-to-end testing, reset/rehearsal, and final demo polish. |

## Priorities

### Must have

- A sandbox API with a real seeded BOLA or IDOR flaw.
- OpenAPI-based endpoint discovery.
- Two-user authenticated comparison.
- One confirmed finding with evidence and reproduction steps.
- Clear report or dashboard.

### Nice to have

- Excessive-data-exposure check.
- Severity scoring.
- Scan history.
- CI/CD integration mock-up.
- LLM-assisted test-case suggestions.
- Multi-step exploit chains.

### Do not build in 24 hours

- Real production scanning.
- Broad autonomous pentesting.
- A full vulnerability-management platform.
- Complex organization login, billing, or team management.
- Claims that the tool covers every OWASP API risk.

## Judging Message

Present SentinelAPI as:

> A safe, specification-driven scanner that proves whether one authenticated API user can access another user's data, then gives developers the exact evidence needed to fix it.

This is more credible than presenting it as a general AI hacking agent.
