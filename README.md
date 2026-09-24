# SentinelAPI Local Demo

This is an **intentionally vulnerable, local-only** order-management API for authorized SentinelAPI scanner demonstrations. Do not deploy it, expose it publicly, or connect it to real user data.

## Setup

```powershell
uv venv
.\.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt
python -m app.seed
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` for the V0 scanner UI. Click **Run scan** to parse the checked-in OpenAPI document, log in as both seeded users, discover their order IDs from `GET /orders`, and test User A's access to User B's order. You can also choose a local OpenAPI 3.x YAML or JSON file in the UI; scans still target the local sandbox using the two seeded identities.

The live API definition is at `http://127.0.0.1:8000/openapi.json`; the checked-in copy is [`openapi.yaml`](openapi.yaml). Swagger UI is at `http://127.0.0.1:8000/docs`.

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
- `PATCH /orders/{order_id}`
- `GET /profile`
- `GET /health`

## Seeded vulnerabilities

`GET /orders/{order_id}` and `PATCH /orders/{order_id}` authenticate a request but **deliberately do not verify order ownership**. A request using User A's token for `/orders/1002` returns HTTP 200 with User B's order. A secure API should return HTTP 403 or HTTP 404 instead.

The order detail endpoints also deliberately expose `internal_notes` and `payment_reference`, providing a secondary excessive-data-exposure finding. `GET /profile` exposes the otherwise internal `role` field as a smaller additional example.

## Reproduce the primary BOLA finding

```powershell
$body = @{ email = 'user-a@example.test'; password = 'demo-password-a' } | ConvertTo-Json
$token = (Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/login -ContentType 'application/json' -Body $body).access_token
Invoke-RestMethod -Uri http://127.0.0.1:8000/orders/1002 -Headers @{ Authorization = "Bearer $token" }
```

The response is User B's order (`owner_id: 2`) despite User A's authenticated token.

## Reset and test

Reset seeded data after tests or a `PATCH` request. The reset is local-only and
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

The SQLite database is created locally at `data/sentinel_demo.db` and is excluded from version control.
Running a scan writes JSON and Markdown reports to `reports/`. The scanner uses bounded GET requests for the ownership comparison and reports BOLA only when User A receives the same object User B receives. The secondary data-exposure check runs on User A's own order response.
