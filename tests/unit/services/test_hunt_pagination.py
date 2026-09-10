"""List pages stay bounded and cannot load detail blobs or cross owners."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event

from threat_hunting.services.workflow import Validation, WorkflowService, hunts, workflow_metadata


@pytest.fixture(params=["sqlite", "postgresql"])
def listing_service(request, tmp_path):
    engine = request.getfixturevalue("postgres_engine") if request.param == "postgresql" else create_engine(f"sqlite:///{tmp_path / 'pages.db'}")
    if request.param == "sqlite":
        workflow_metadata.create_all(engine)
    yield WorkflowService(engine)
    if request.param == "sqlite":
        engine.dispose()


def test_summary_pages_are_bounded_stable_and_exclude_detail_blobs(listing_service):
    service = listing_service
    owner = str(uuid4())
    stamp = datetime(2026, 9, 8, tzinfo=timezone.utc)
    ids = [str(uuid4()) for _ in range(105)]
    with service.engine.begin() as connection:
        connection.execute(hunts.insert(), [dict(
            hunt_id=id, owner_id=owner, title="Summary", hypothesis="h" * 4000, objective="o",
            state="created", results={"evidence": ["large"] * 1000}, report_pdf=b"private report",
            created_at_utc=stamp, updated_at_utc=stamp,
        ) for id in ids])
    statements = []
    def capture(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(service.engine, "before_cursor_execute", capture)
    try:
        first = service.list_hunts(owner)
        assert len(first) == 50
        assert len(first[0]["hypothesis"]) == 500
        assert set(first[0]) == {"hunt_id", "title", "hypothesis", "state", "created_at_utc", "updated_at_utc"}
        second = service.list_hunts(owner, cursor=first[-1]["hunt_id"])
        third = service.list_hunts(owner, cursor=second[-1]["hunt_id"])
    finally:
        event.remove(service.engine, "before_cursor_execute", capture)
    assert [row["hunt_id"] for row in first + second + third] == sorted(ids, reverse=True)
    assert all("workflow_hunts.results" not in sql and "workflow_hunts.report_pdf" not in sql for sql in statements)
    service.create_hunt(owner, title="Newer", hypothesis="h", objective="o")
    assert service.list_hunts(owner, cursor=first[-1]["hunt_id"]) == second
    assert service.list_hunts(owner, cursor=third[-1]["hunt_id"]) == []


def test_page_limits_and_cursors_cannot_bypass_owner_scope(listing_service):
    service = listing_service
    hunt = service.create_hunt("owner-a", title="Private", hypothesis="h", objective="o")
    assert service.list_hunts("owner-b") == []
    for cursor in (hunt["hunt_id"], str(uuid4())):
        with pytest.raises(Validation, match="invalid hunt page cursor"):
            service.list_hunts("owner-b", cursor=cursor)
    for limit in (0, -1, 101):
        with pytest.raises(Validation, match="limit"):
            service.list_hunts("owner-a", limit=limit)
