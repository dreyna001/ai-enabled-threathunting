"""Regression coverage for atomic plan-version transitions."""

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from threat_hunting.services.workflow import Conflict, WorkflowService, hunts


def _service() -> tuple[WorkflowService, str, dict[str, object]]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    service = WorkflowService(engine, local_demo=True, demo_password="test-only-password")
    service.initialize_demo()
    session = service.login("analyst", "test-only-password")
    owner_id = service.authenticate(str(session["access_token"]))
    hunt = service.create_hunt(owner_id, title="Race test", hypothesis="h", objective="o")
    return service, owner_id, service.discover(owner_id, str(hunt["hunt_id"]))


def test_approval_fails_if_plan_version_changes_before_atomic_update(monkeypatch) -> None:
    service, owner_id, hunt = _service()
    original_update = service._update

    def racing_update(owner: str, hunt_id: str, **values: object) -> None:
        if values.get("state") == "approved":
            with service.engine.begin() as connection:
                connection.execute(
                    update(hunts)
                    .where(hunts.c.hunt_id == hunt_id, hunts.c.owner_id == owner)
                    .values(plan_version=int(hunt["plan_version"]) + 1)
                )
        original_update(owner, hunt_id, **values)

    monkeypatch.setattr(service, "_update", racing_update)

    with pytest.raises(Conflict, match="changed"):
        service.approve(owner_id, str(hunt["hunt_id"]), "reviewed")

    stored = service.get_hunt(owner_id, str(hunt["hunt_id"]))
    assert stored["state"] == "awaiting_plan_review"
    assert stored["approval"] is None
