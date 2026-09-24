# SentinelAPI Local Demo

This is an **intentionally vulnerable, local-only** order-management API for authorized SentinelAPI scanner demonstrations. Do not deploy it, expose it publicly, or connect it to real user data.

Repository: <https://github.com/yashneelsingh/Ami---Hacks_SentinalAPI>

## Setup

```powershell
uv venv
.\.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt
python -m app.seed
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` for the local scanner UI. Enter the local API base URL, optionally choose its OpenAPI 3.x YAML or JSON file, then click **Run authorized scan**. The default uses the checked-in OpenAPI document and current local server. The scanner logs in as both seeded users, discovers their order IDs from `GET /orders`, and tests User A's access to User B's order. Only `http://localhost`, `http://127.0.0.1`, and `http://[::1]` origins are accepted.

The dashboard uses only checked-in HTML, CSS, and JavaScript. It does not load fonts, icons, trackers, or images from third-party services. Its results view shows the live owner baselines, cross-user HTTP response, endpoint outcome, and confirmed findings separately. Changing the target or specification clears the prior result. After a completed scan, JSON and Markdown download buttons fetch the latest server-generated report with caching disabled.

The live API definition is at `http://127.0.0.1:8000/openapi.json`; the checked-in copy is [`openapi.yaml`](openapi.yaml). Swagger UI is at `http://127.0.0.1:8000/docs`.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the system flow and safety boundaries.
The optional hosted persistence foundation has a separate operational runbook in
[`HOSTED_DATABASE.md`](HOSTED_DATABASE.md). Record participant-owned work in
[`TEAM_CONTRIBUTIONS.md`](TEAM_CONTRIBUTIONS.md) and complete
[`SUBMISSION_CHECKLIST.md`](SUBMISSION_CHECKLIST.md) before submission.
The event-period Git boundary and assistance disclosure are recorded in
[`PROVENANCE.md`](PROVENANCE.md).

Submission-ready repository artifacts are indexed in
[`submission/README.md`](submission/README.md), including the validated 9-slide
PowerPoint deck and current desktop/mobile demo screenshots. A public deployment
link is **not applicable** to this MVP: the vulnerable target and scanner are
deliberately restricted to local loopback hosts and must not be publicly hosted.

## Live secure negative control

Run the secure control target in a second terminal to demonstrate that the same scanner does not report BOLA when ownership checks are present:

```powershell
uvicorn app.secure_main:app --host 127.0.0.1 --port 8011
```

In the scanner UI, choose [`openapi-secure.yaml`](openapi-secure.yaml), set the local API base URL to `http://127.0.0.1:8011`, and run the scan. The secure target returns HTTP 403 when User A requests order `1002`, excludes `internal_notes` and `payment_reference` from owner responses, and should produce a completed clean report with zero confirmed findings.

## Test identities

| User | Password | Order |
| --- | --- | --- |
| `user-a@example.test` | `demo-password-a` | `1001` |
| `user-b@example.test` | `demo-password-b` | `1002` |

Tokens returned by login are deterministic demo tokens. They are not authentication guidance for any real system.

## Endpoints

- `POST /auth/login`
- `GET /orders`
- `GET /orders/{order_id}`
- `GET /orders/{order_id}/summary`
- `GET /orders/{order_id}/tracking`
- `GET /orders/{order_id}/receipt`
- `GET /orders/{order_id}/items`
- `GET /profile`
- `GET /health`

The separate secure control target intentionally implements only the read-only endpoints needed for the negative-control scan.

## Supported OpenAPI shape

The scanner accepts YAML or JSON documents whose root contains an OpenAPI `3.x`
version string and a `paths` object. This is targeted endpoint discovery, not a
complete OpenAPI validator. A discoverable object endpoint must have this shape:

```yaml
openapi: 3.1.0
paths:
  /orders:
    get: {}
  /orders/{order_id}:
    get:
      security: [{ bearerAuth: [] }]
      parameters:
        - name: order_id
          in: path
```

The detail route must end in one path-parameter segment, have a matching
collection route with `GET`, and declare the matching path parameter either on
the path item or the detail `GET`. Authentication must be declared by a non-empty
`security` value on the detail `GET` or at the document root. The scanner can
discover at most three matching detail endpoints per scan.

At runtime, the collection `GET` must return HTTP 200 and a non-empty JSON array;
the first item must be an object with an `id` field. The MVP assumes this first
item belongs to the authenticated user; it does not infer ownership or paginate.
Both selected IDs appear in the endpoint audit and reports. Each owner detail
`GET` must return an HTTP 200 JSON object with the selected ID. A BOLA finding
is confirmed only when User A's request for User B's ID returns HTTP 200 with
the same JSON object returned to User B. Identical IDs, failed baselines, and
ambiguous responses cannot produce a BOLA finding.

## MVP limitations

- Scans only an HTTP origin on `localhost`, `127.0.0.1`, or `::1`. The OpenAPI
  `servers` value does not select the target.
- Uses the two fixed demo identities, logs in through `POST /auth/login`, expects
  an `access_token` in the JSON response, and sends it as a bearer token. Other
  authentication flows and token refresh are not supported.
- Tests only discovered collection and detail `GET` operations. It does not test
  `POST`, `PUT`, `PATCH`, or `DELETE`, follow pagination, or execute multi-step
  workflows.
- Does not resolve `$ref` entries or support nested-resource templates,
  multiple identifiers, query/header/cookie identifiers, or schema-driven ID
  extraction. It inspects only the first collection item and its `id` field.
- Accepts UI-uploaded specifications up to 250,000 bytes, scans at most three
  discovered endpoints, limits each response to 1,000,000 bytes, uses a
  five-second request timeout, and blocks redirects. OpenAPI paths must be
  origin-relative; the executor checks the final scheme, host, and port before
  each request and ignores environment proxy settings. The accepted `localhost`
  alias is pinned to `127.0.0.1` so host-file or DNS changes cannot redirect it.
- OpenAPI 2.x/Swagger documents, external targets, and rate-limit testing are
  outside this local scanner MVP. A separate hosted persistence foundation now
  supports multi-tenant scan history and jobs without expanding target access.

An offline compatibility check of Swagger API's public
[Swagger Petstore OpenAPI 3.0 specification](https://github.com/swagger-api/swagger-petstore/blob/master/src/main/resources/openapi.yaml)
on 25 September 2026 parsed its 13 paths but discovered zero supported endpoint
pairs. Its OAuth2 and API-key security definitions do not match SentinelAPI's
fixed local `POST /auth/login` flow. The public API itself was not scanned.

## Seeded vulnerabilities

`GET /orders/{order_id}` authenticates a request but **deliberately does not
verify order ownership**. A request using User A's token for `/orders/1002`
returns HTTP 200 with User B's order. A secure API should return HTTP 403 or
HTTP 404 instead. The unused vulnerable `PATCH` route was removed so the demo
target exposes only the read-only behavior needed by the scanner.

The order detail endpoints also deliberately expose `internal_notes` and `payment_reference`, providing a secondary excessive-data-exposure finding. `GET /profile` exposes the otherwise internal `role` field as a smaller additional example.

## Reproduce the primary BOLA finding

```powershell
$body = @{ email = 'user-a@example.test'; password = 'demo-password-a' } | ConvertTo-Json
$token = (Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/login -ContentType 'application/json' -Body $body).access_token
Invoke-RestMethod -Uri http://127.0.0.1:8000/orders/1002 -Headers @{ Authorization = "Bearer $token" }
```

The response is User B's order (`owner_id: 2`) despite User A's authenticated token.

## Reset and test

Reset seeded data before tests or a demo rehearsal. The reset is local-only and
rewrites the fixed `data/sentinel_demo.db` database in one transaction; it does
not delete or replace the database file, so it is safe to run on Windows while
the local server process has the file open:

```powershell
python -m app.seed
```

The command verifies that User A owns order `1001` and User B owns order `1002`.
For a fully deterministic stop-reset-start cycle, stop Uvicorn with `Ctrl+C`, then
run:

```powershell
python -m app.seed
uvicorn app.main:app --reload
```

Run the automated checks separately:

```powershell
python -m unittest discover -s tests -v
python -m scanner.demo
```

For the CI-equivalent check, use one command. It resets and verifies the exact
seed data before discovering and running the complete test suite:

```powershell
python -m scripts.ci
```

Scanner lifecycle events are written as one JSON object per line. Logs contain
event names, outcomes, endpoint templates, and counts; structured credentials,
authorization headers, passwords, and known token values are redacted.

The SQLite database is created locally at `data/sentinel_demo.db` and is excluded from version control.
Running a scan writes JSON and Markdown reports to `reports/`. The scanner uses bounded GET requests for the ownership comparison and reports BOLA only when User A receives the same object User B receives. The secondary data-exposure check runs on User A's own order response.
Authentication, bounded request execution, ownership comparison, and report
construction implement typed interfaces so each policy can be tested or replaced
independently. Reports retain the endpoint audit list and also group `pass`,
`fail`, `inconclusive`, and `error` outcomes with explicit counts.
