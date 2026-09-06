"""Operator command for creating local accounts without exposing passwords."""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import create_engine

from threat_hunting.auth.service import AccountService
from threat_hunting.config import load_database_url
from threat_hunting.services.workflow import workflow_metadata


def main(argv: list[str] | None = None) -> int:
    """Create one local account from a hidden prompt or protected stdin."""

    parser = argparse.ArgumentParser(description="Create a threat-hunting local account")
    parser.add_argument("username")
    parser.add_argument("--display-name", default=None)
    parser.add_argument("--password-fd", type=int, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    password = getpass.getpass("Password: ") if args.password_fd is None else os.fdopen(args.password_fd, "r", closefd=False).readline().rstrip("\n")
    if not password:
        parser.error("password must not be empty")
    engine = create_engine(load_database_url().get_secret_value(), pool_pre_ping=True)
    try:
        # The CLI is run after migrations in production; create_all is useful only
        # for an explicitly supplied local SQLite test database and never broadens
        # the production startup path.
        if engine.dialect.name == "sqlite":
            workflow_metadata.create_all(engine)
        account = AccountService(engine).create_account(args.username, password, display_name=args.display_name)
    except Exception as exc:
        print(f"account creation failed: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    print(f"created account {account['username']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
