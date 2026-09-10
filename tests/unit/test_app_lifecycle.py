"""Each FastAPI instance owns its dependencies and releases its resources."""

import asyncio
import threading
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from threat_hunting.api.workflow import create_upload
from threat_hunting.main import create_app


def test_creating_another_app_does_not_replace_auth_or_workflow_dependencies(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("THREAT_HUNTING_UPLOAD_ROOT", str(tmp_path / "uploads-a"))
    first_engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    second_engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    try:
        with TestClient(create_app(first_engine, local_demo=True, demo_password="first-test-password")) as first:
            assert first.post("/api/auth/login", json={"username": "analyst", "password": "first-test-password"}).status_code == 200
            monkeypatch.setenv("THREAT_HUNTING_UPLOAD_ROOT", str(tmp_path / "uploads-b"))
            with TestClient(create_app(second_engine, local_demo=True, demo_password="second-test-password")) as second:
                assert second.post("/api/auth/login", json={"username": "analyst", "password": "second-test-password"}).status_code == 200
                assert first.get("/api/auth/me").status_code == 200
                assert second.get("/api/auth/me").status_code == 200
                assert first.get("/api/hunts").status_code == 200
    finally:
        first_engine.dispose()
        second_engine.dispose()


def test_app_shutdown_closes_adapters_but_keeps_a_caller_owned_engine(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("THREAT_HUNTING_UPLOAD_ROOT", str(tmp_path / "uploads"))
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    closed, disposed = [], []
    app = create_app(engine, local_demo=True, demo_password="test-password")
    app.state.workflow_service.model_adapter = SimpleNamespace(close=lambda: closed.append(True))
    dispose = engine.dispose
    monkeypatch.setattr(engine, "dispose", lambda: disposed.append(True))
    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
    assert closed == [True]
    assert not disposed
    dispose()


def test_upload_database_parsing_and_disk_work_run_off_the_event_loop() -> None:
    loop_thread = threading.get_ident()
    threads = []

    def get_hunt(*args):
        threads.append(threading.get_ident())
        return {"hunt_id": "hunt"}

    def save(*args, **kwargs):
        threads.append(threading.get_ident())
        return {"upload_id": "upload"}

    async def receive():
        assert threading.get_ident() == loop_thread
        return {"type": "http.request", "body": b"synthetic", "more_body": False}

    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []}, receive)
    result = asyncio.run(create_upload(
        "hunt", request, filename="sample.txt", user_id="owner",
        service=SimpleNamespace(get_hunt=get_hunt),
        uploads=SimpleNamespace(limits=SimpleNamespace(per_file_bytes=100), save=save),
    ))
    assert result == {"upload_id": "upload"}
    assert len(threads) == 2 and all(thread != loop_thread for thread in threads)
