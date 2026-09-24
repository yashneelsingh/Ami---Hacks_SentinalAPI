# SentinelAPI Database Work

## Status summary

The local SQLite demo database and the separate hosted persistence foundation
are implemented and verified. The demo remains deterministic and intentionally
vulnerable; hosted identity, tenant isolation, scan jobs, encrypted credentials,
redacted results, retention, migrations, and operations live under
`app/hosted/`. See `HOSTED_DATABASE.md` for the production runbook.

## Priority 0: verify before the live demo

- [x] Create a completely fresh virtual environment and confirm that the
  documented installation creates and seeds the SQLite database successfully.
- [x] Run `python -m app.seed` and verify that it restores exactly two users and
  two orders with ownership split between User A and User B.
- [x] Run `python -m scripts.ci` from the documented environment and retain the
  passing output as development evidence.
- [x] Run two vulnerable scans consecutively and confirm that the rows in
  `users` and `orders` are unchanged.
- [x] Run the secure control target and confirm it uses the same seeded data but
  returns HTTP 403 for a cross-user order request.
- [x] Confirm that `data/sentinel_demo.db` remains excluded from version control
  and that no generated database file is included in the submission.
- [x] Confirm that reports and logs do not expose the seeded passwords, bearer
  tokens, or authorization headers.
- [x] Record the exact reset command in the demo checklist so the team can
  recover quickly if data is changed during rehearsal.

### Verification evidence (2026-09-24)

- Final `.\.venv\Scripts\python.exe -m scripts.ci` after hosted persistence and
  submission-artifact completion: `Ran 49 tests in 1.183s` followed by `OK`.
- Dedicated consecutive-scan database test: two scans each produced the
  expected two findings, the before/after user and order rows matched, and the
  test finished with `Ran 1 test in 0.077s` followed by `OK`.
- Secure control verification returned HTTP 403 for User A requesting User B's
  order while the owner response remained allowlisted.
- `git check-ignore` confirmed `data/sentinel_demo.db` is covered by `*.db`, and
  `git ls-files` found no tracked SQLite database files.
- The redaction suite passed, and a repository search found no seeded password
  or token values in generated reports or log files.

## Priority 1: small hardening tasks if time remains

- [x] Add an explicit schema or seed version constant so reports and debugging
  information can identify which deterministic fixture set was used.
- [x] Add a startup integrity check for the expected tables and columns. The
  current startup logic only creates the database when the file is absent; it
  does not repair an existing malformed database automatically.
- [x] Add a controlled error message for a corrupt or unreadable SQLite file.
- [x] Add a test showing that foreign-key enforcement rejects an order whose
  `owner_id` does not exist.
- [x] Add a test showing that a failed transaction rolls back all changes.
- [x] Decide whether the intentionally vulnerable `PATCH /orders/{order_id}`
  endpoint is needed for the demonstration. The scanner does not call it, so it
  was removed to keep the demo read-only and narrowly scoped.

These tasks are useful but must not displace work on the live BOLA flow,
redacted evidence, secure negative control, or submission artifacts.

## Post-MVP database work

This section was implemented as a separate hosted subsystem after the product
scope was explicitly expanded. It does not change the local-only scan target
safety boundary.

### Scan and report persistence

- [x] Create a `scans` table with an unpredictable scan ID, target identifier,
  status, timestamps, bounded request count, and final result.
- [x] Create tables for tested endpoints, outcomes, and confirmed findings.
- [x] Store only redacted evidence. Never persist bearer tokens, passwords,
  authorization headers, login bodies, or unredacted response bodies.
- [x] Add report retention and automatic expiry policies.
- [x] Add cancellation and failure states without converting partial or
  ambiguous results into confirmed findings.

### Identity and isolation

- [x] Add real application-user and organization models.
- [x] Add authorization rules that prevent one user or organization from
  reading another user's scans or reports.
- [x] Replace plaintext demo passwords and deterministic tokens with a real
  identity system and password hashing where passwords are locally managed.
- [x] Store temporary target credentials in an appropriate secret store or
  encrypted short-lived job context, then delete them when the scan finishes.
- [x] Add an audit trail that records safe metadata without recording secrets.

### Database platform and lifecycle

- [x] Move from SQLite to PostgreSQL only when concurrent users, background
  workers, or multi-instance deployment actually require it.
- [x] Introduce a migration tool such as Alembic before maintaining multiple
  deployed schema versions.
- [x] Add indexes based on repository query paths, including ownership and scan-status
  lookups where appropriate.
- [x] Add connection pooling, health checks, backup, restore, and disaster
  recovery procedures.
- [x] Define development, test, staging, and production database separation.
- [x] Add database observability for slow queries, failures, storage growth, and
  connection exhaustion without collecting sensitive API data.

### Background job support

- [x] Persist bounded scan-job states such as queued, validating, running,
  completed, failed, cancelled, and expired.
- [x] Make job claiming atomic so two workers cannot execute the same scan.
- [x] Add per-job request budgets and deadlines enforced outside browser state.
- [x] Ensure retries cannot duplicate findings or exceed the authorized request
  budget.

## Local MVP runtime remains independent of hosted services

- PostgreSQL
- SQLAlchemy or another ORM
- Redis, Celery, or RabbitMQ
- Multi-tenancy
- Production user accounts
- Long-term scan history
- Cloud database deployment
- Analytics or trend tables

Hosted database capabilities are isolated from the demo where implemented.
Redis, Celery, RabbitMQ, cloud deployment, billing, and analytics remain
deliberately unnecessary: PostgreSQL itself provides durable atomic job claims,
and infrastructure provisioning is an operator concern rather than database
application code. The local MVP continues to use `data/sentinel_demo.db`.

## Completion criteria

The MVP database work can be considered verified when:

1. `python -m app.seed` reliably restores the exact deterministic fixtures.
2. `python -m scripts.ci` passes from the documented environment.
3. The vulnerable scan produces the expected live findings without changing
   database state.
4. The secure control produces no BOLA finding.
5. No database, report, log, or reproduction command exposes credentials or
   bearer tokens.
6. The team can explain that SQLite is intentionally used for a local,
   deterministic demonstration rather than presented as a production data
   platform.
