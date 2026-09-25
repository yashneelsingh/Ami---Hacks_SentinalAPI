# SentinelAPI

SentinelAPI is a local-only, specification-driven API security scanner built for the AMIHACKS SentinelAPI challenge.

It demonstrates whether one authenticated sandbox user can access another user's object (Broken Object Level Authorization, or BOLA) and flags sensitive fields returned unnecessarily by an API.

## Safety

- Scans only loopback targets: `localhost`, `127.0.0.1`, and `::1`.
- Uses bounded, read-only `GET` requests.
- Uses only the included intentionally vulnerable and secure local sandbox APIs.
- Redacts credentials and bearer tokens from reports and output.

## Run locally

```powershell
uv venv
.\.venv\Scripts\Activate.ps1
uv pip install -r requirements.txt
python -m app.seed
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` to use the scanner dashboard.

## Verification

```powershell
python -m unittest discover -s tests -v
python -m scanner.demo
python -m scripts.ci
```

The vulnerable sandbox should report one Critical BOLA finding and one High excessive-data-exposure finding. For a secure negative control, start `app.secure_main` on port `8011` and scan `openapi-secure.yaml`.
