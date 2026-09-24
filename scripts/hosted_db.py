"""Operational CLI for the hosted SentinelAPI persistence layer."""

from __future__ import annotations

import argparse
import json

from app.hosted.config import HostedDatabaseSettings
from app.hosted.database import (
    create_hosted_engine,
    health_check,
    hosted_session_factory,
    verify_schema_integrity,
)
from app.hosted.maintenance import backup_database, restore_database
from app.hosted.repository import HostedRepository


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subcommands = value.add_subparsers(dest="command", required=True)
    subcommands.add_parser("health", help="Check connectivity and migrated schema")
    subcommands.add_parser("purge", help="Delete expired credentials and retained terminal scans")
    subcommands.add_parser("expire-jobs", help="Expire active jobs whose deadlines elapsed")
    backup = subcommands.add_parser("backup", help="Create a SQLite or PostgreSQL backup")
    backup.add_argument("destination")
    restore = subcommands.add_parser("restore", help="Restore a SQLite or PostgreSQL backup")
    restore.add_argument("source")
    return value


def main() -> int:
    args = parser().parse_args()
    settings = HostedDatabaseSettings.from_env()
    engine = create_hosted_engine(settings)
    try:
        if args.command == "restore":
            restore_database(engine, args.source)
            print("Restore completed. Run the health command before accepting traffic.")
            return 0
        verify_schema_integrity(engine)
        if args.command == "health":
            print(json.dumps(health_check(engine), sort_keys=True))
        elif args.command == "backup":
            print(backup_database(engine, args.destination))
        else:
            repository = HostedRepository(hosted_session_factory(engine))
            result = repository.purge_expired() if args.command == "purge" else {
                "expired_jobs": repository.expire_overdue_jobs()
            }
            print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
