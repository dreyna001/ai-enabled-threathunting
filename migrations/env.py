"""Alembic environment configured from the database URL secret file."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from threat_hunting.config import load_database_url

config = context.config
if config.config_file_name is not None and config.attributes.get("connection") is None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = None


def run_migrations_offline() -> None:
    url = load_database_url().get_secret_value()
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def _run_with_connection(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        _run_with_connection(supplied_connection)
        return
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = load_database_url().get_secret_value()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    try:
        with connectable.connect() as connection:
            _run_with_connection(connection)
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

