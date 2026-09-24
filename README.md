# SentinelAPI Vulnerable Demo API

This is an **intentionally vulnerable, local-only** order-management API for authorized SentinelAPI scanner demonstrations. Do not deploy it, expose it publicly, or connect it to real user data.

## Setup

```powershell
uv venv
.\.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt
python -m app.seed
uvicorn app.main:app --reload
```

The API runs at `http://127.0.0.1:8000`. Its live OpenAPI 3.x document is at `http://127.0.0.1:8000/openapi.json`; a checked-in copy is [`openapi.yaml`](openapi.yaml).

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

Reset seeded data after tests or a `PATCH` request:

```powershell
python -m app.seed
python -m unittest discover -s tests -v
python -m scanner.demo
```

The SQLite database is created locally at `data/sentinel_demo.db` and is excluded from version control.
The report module writes compatible JSON and Markdown reports to `reports/` using the API's
`http://127.0.0.1:8000` base URL, `/orders/{order_id}` path template, and seeded response fields.
