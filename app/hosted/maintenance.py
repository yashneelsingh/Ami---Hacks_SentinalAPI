"""Retention and backup operations for hosted database deployments."""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path

from sqlalchemy import Engine


def backup_database(engine: Engine, destination: str | Path) -> Path:
    output = Path(destination).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if engine.dialect.name == "sqlite":
        database_path = engine.url.database
        if not database_path or database_path == ":memory:":
            raise ValueError("An in-memory SQLite database cannot be backed up to a durable file")
        with closing(sqlite3.connect(database_path)) as source, closing(sqlite3.connect(output)) as target:
            source.backup(target)
        return output
    if engine.dialect.name == "postgresql":
        _postgres_tool("pg_dump", engine, output, restore=False)
        return output
    raise ValueError(f"Backup is not supported for the {engine.dialect.name} dialect")


def restore_database(engine: Engine, source: str | Path) -> None:
    backup = Path(source).resolve()
    if not backup.is_file():
        raise FileNotFoundError(f"Backup file does not exist: {backup}")
    if engine.dialect.name == "sqlite":
        database_path = engine.url.database
        if not database_path or database_path == ":memory:":
            raise ValueError("An in-memory SQLite database cannot be restored")
        engine.dispose()
        with closing(sqlite3.connect(backup)) as source_connection, closing(sqlite3.connect(database_path)) as target:
            source_connection.backup(target)
        return
    if engine.dialect.name == "postgresql":
        _postgres_tool("pg_restore", engine, backup, restore=True)
        return
    raise ValueError(f"Restore is not supported for the {engine.dialect.name} dialect")


def _postgres_tool(tool: str, engine: Engine, path: Path, *, restore: bool) -> None:
    executable = shutil.which(tool)
    if executable is None:
        raise RuntimeError(f"{tool} is required and was not found on PATH")
    url = engine.url
    if not url.database:
        raise ValueError("The PostgreSQL database name is missing")
    environment = os.environ.copy()
    if url.password:
        environment["PGPASSWORD"] = url.password
    if url.host:
        environment["PGHOST"] = url.host
    if url.port:
        environment["PGPORT"] = str(url.port)
    if url.username:
        environment["PGUSER"] = url.username
    command = [executable]
    if restore:
        command.extend(["--clean", "--if-exists", "--no-owner", "--dbname", url.database, str(path)])
    else:
        command.extend(["--format=custom", "--no-owner", "--file", str(path), url.database])
    subprocess.run(command, env=environment, check=True)
