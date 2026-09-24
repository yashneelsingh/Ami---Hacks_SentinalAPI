# Hosted database migrations

Run `alembic upgrade head` after setting `SENTINEL_ENV` and
`SENTINEL_DATABASE_URL`. For an explicit one-off URL, use
`alembic -x database_url=<URL> upgrade head`. Never put credentials in
`alembic.ini` or commit them to the repository.
