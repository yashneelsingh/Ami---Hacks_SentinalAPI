# SentinelAPI hosted database runbook

The hosted persistence layer is separate from `data/sentinel_demo.db`. The demo
database remains intentionally vulnerable and deterministic; hosted identity,
scan history, job state, credentials, findings, and audit data use the models in
`app/hosted/` and the migrations in `migrations/`.

The scanner's safety boundary is unchanged: even in a hosted deployment, a
worker may scan only an explicitly authorized loopback sandbox. This database
architecture does not enable public-target scanning.

## Storage model

- `organizations` and `application_users` provide tenant ownership. Passwords
  are Argon2 hashes; plaintext application passwords are never stored.
- `application_sessions` contains expiring, revocable opaque session-token
  digests. A raw token is returned once and never stored.
- `scans` has UUID identifiers, a bounded request budget, deadline, retention
  expiry, state, result summary, worker lease, and attempt count.
- `tested_endpoints` stores one redacted outcome per scan/method/path.
- `findings` stores redacted evidence and uses a per-scan fingerprint to make
  retries idempotent.
- `scan_credentials` stores a Fernet-encrypted JSON payload with a short TTL.
  The row is removed on completion, failure, cancellation, or expiry.
- `audit_events` records event names, identifiers, counts, and redacted safe
  metadata. Request bodies, response bodies, authorization headers, passwords,
  and tokens are not audit fields.

All repository reads and writes require an `organization_id`. A record from a
different organization is returned as not found rather than disclosed.

## Environments

| Environment | Database | Requirement |
| --- | --- | --- |
| `development` | SQLite by default | Local development only |
| `test` | Explicit temporary SQLite URL | Automated tests |
| `staging` | PostgreSQL | `SENTINEL_DATABASE_URL` required |
| `production` | PostgreSQL | `SENTINEL_DATABASE_URL` required |

Set configuration outside source control:

```powershell
$env:SENTINEL_ENV = 'production'
$env:SENTINEL_DATABASE_URL = 'postgresql+psycopg://sentinel:<password>@db.internal/sentinel'
$env:SENTINEL_CREDENTIAL_KEYS = '<current-fernet-key>,<previous-fernet-key>'
```

Additional pool controls are `SENTINEL_DB_POOL_SIZE`,
`SENTINEL_DB_MAX_OVERFLOW`, `SENTINEL_DB_POOL_TIMEOUT_SECONDS`, and
`SENTINEL_DB_SLOW_QUERY_MS`. Production defaults are a five-connection pool,
ten overflow connections, a ten-second pool wait, and a 250 ms slow-query
threshold.

Generate a credential key without printing or committing application secrets:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store it in the deployment secret manager. For rotation, prepend the new key to
`SENTINEL_CREDENTIAL_KEYS`, deploy, allow all old short-lived credential rows to
expire, then remove the old key. Encryption always uses the first key and
decryption accepts the remaining rotation keys.

## Migrations and startup

Install dependencies and migrate before starting application workers:

```powershell
uv pip install -r requirements.txt
python -m alembic upgrade head
python -m scripts.hosted_db health
```

Do not use `Base.metadata.create_all()` in a deployment. It exists only for
isolated unit tests. Each schema change must be an reviewed Alembic revision.
The health command checks connectivity and verifies all required migrated
tables. A failed migration or health check must keep the deployment out of
service.

## Worker lifecycle

1. Create a `queued` scan with an unpredictable UUID, deadline, request budget,
   and retention expiry.
2. Store target credentials only in the encrypted short-lived credential row.
3. A worker claims work transactionally. PostgreSQL uses `FOR UPDATE SKIP
   LOCKED`; a conditional update prevents duplicate ownership on SQLite tests.
4. Move `validating` to `running`. Increment the database request counter before
   each target request; the update fails once the budget or deadline is reached.
5. Persist redacted endpoint outcomes and findings. Unique fingerprints prevent
   retry duplication.
6. Finish as `completed`, `failed`, `cancelled`, or `expired`. Every terminal
   transition deletes the credential row.

Allowed states are deliberately finite: `queued`, `validating`, `running`,
`completed`, `failed`, `cancelled`, and `expired`. Partial or malformed scanner
results remain endpoint `inconclusive` or `error` outcomes; persistence does not
promote them to findings.

## Retention and scheduled maintenance

Run these commands from a trusted scheduler at least every five minutes:

```powershell
python -m scripts.hosted_db expire-jobs
python -m scripts.hosted_db purge
```

`expire-jobs` closes jobs whose deadline elapsed and deletes their credentials.
`purge` deletes expired or revoked application sessions, expired credential
rows, and terminal scans past their configured retention date. Cascading
foreign keys remove their endpoint, finding, and audit children. Active scans
are never removed by retention cleanup.

## Backup and restore

Create a backup to an encrypted, access-controlled destination:

```powershell
python -m scripts.hosted_db backup D:\secure-backups\sentinel.dump
```

PostgreSQL uses `pg_dump --format=custom`; its password is passed through the
child process environment rather than the command line. Development SQLite uses
the online SQLite backup API.

Restore is intentionally explicit and destructive to the selected database:

```powershell
python -m scripts.hosted_db restore D:\secure-backups\sentinel.dump
python -m alembic upgrade head
python -m scripts.hosted_db health
```

Before production restore, stop API and worker writes, snapshot the current
database, confirm the selected environment and backup checksum, restore into a
new database when possible, migrate it, run health and tenant-isolation smoke
tests, then switch traffic. A reasonable starting objective is daily encrypted
backups with a 24-hour recovery-point objective and a four-hour recovery-time
objective; tighten both from actual business requirements. Test restores at
least quarterly and record the result.

## Observability

The engine uses pre-ping connections and bounded pool waits. Slow-query logs
contain only the SQL operation type and elapsed milliseconds—never SQL text,
parameters, credentials, or response bodies. Monitor:

- health-check failures and pool timeouts;
- p95/p99 query duration and slow-query counts;
- database size, table growth, dead tuples, and remaining disk;
- queued job age, expired leases, retry counts, and deadline expirations;
- backup age, backup failures, and restore-test age.

Use the managed PostgreSQL service's metrics and alerts for connections,
storage, replication, and backup health. Do not enable parameter-value SQL
logging in staging or production.
