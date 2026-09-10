"""Explicit, disposable PostgreSQL schemas for database integration tests."""

import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.schema import CreateSchema, DropSchema


@pytest.fixture
def postgres_engine():
    url_file = os.getenv("THREAT_HUNTING_TEST_DATABASE_URL_FILE")
    raw_url = Path(url_file).read_text().strip() if url_file else os.getenv("THREAT_HUNTING_TEST_DATABASE_URL")
    if not raw_url:
        pytest.skip("set THREAT_HUNTING_TEST_DATABASE_URL_FILE or THREAT_HUNTING_TEST_DATABASE_URL")
    url = make_url(raw_url)
    if url.get_backend_name() != "postgresql" or not (url.database or "").endswith("_test"):
        pytest.fail("integration tests require an explicitly configured PostgreSQL database ending in _test")
    schema = f"test_{uuid4().hex}"
    administration = create_engine(url)
    with administration.begin() as connection:
        connection.execute(CreateSchema(schema))
    engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        yield engine
    finally:
        engine.dispose()
        with administration.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True))
        administration.dispose()
