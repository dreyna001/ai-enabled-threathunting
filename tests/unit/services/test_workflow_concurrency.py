"""Regression coverage for atomic plan-version transitions."""

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.pool import StaticPool

from threat_hunting.services.workflow import Conflict, Validation, WorkflowService, audit_records, hunts


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


@pytest.mark.parametrize("question_ids", [["unknown"], [" UNKNOWN "], [""], [None], ["q1", "q1"]])
@pytest.mark.parametrize("operation", ["save", "approve"])
def test_invalid_question_ids_rejected_before_save_or_approval(question_ids: list[str | None], operation: str) -> None:
    service, owner_id, hunt = _service()
    hid = str(hunt["hunt_id"])
    plan = hunt["plan"]
    plan["questions"] = [{**plan["questions"][0], "question_id": value} for value in question_ids]
    if operation == "approve":
        with service.engine.begin() as connection:
            connection.execute(update(hunts).where(hunts.c.hunt_id == hid).values(plan=plan))

    with pytest.raises(Validation, match="question IDs"):
        if operation == "save":
            service.save_plan(owner_id, hid, expected_version=int(hunt["plan_version"]), plan=plan)
        else:
            service.approve(owner_id, hid, "reviewed")

    stored = service.get_hunt(owner_id, hid)
    assert stored["state"] == "awaiting_plan_review"
    assert stored["approval"] is None
    assert stored["plan_version"] == hunt["plan_version"]


def test_saving_plan_preserves_existing_valid_question_ids() -> None:
    service, owner_id, hunt = _service()
    plan = hunt["plan"]
    plan["questions"][0]["question_id"] = "existing-question-id"
    saved = service.save_plan(owner_id, str(hunt["hunt_id"]), expected_version=int(hunt["plan_version"]), plan=plan)
    assert saved["plan"]["questions"][0]["question_id"] == "existing-question-id"


def test_hunt_mutations_are_audited_with_state_and_object_binding() -> None:
    service, owner_id, hunt = _service()
    hunt_id = str(hunt["hunt_id"])
    service.approve(owner_id, hunt_id, "reviewed")
    service.cancel(owner_id, hunt_id)
    service.cancel(owner_id, hunt_id)

    with service.engine.connect() as connection:
        rows = connection.execute(
            select(
                audit_records.c.action,
                audit_records.c.hunt_id,
                audit_records.c.prior_state,
                audit_records.c.resulting_state,
                audit_records.c.outcome,
            )
            .where(audit_records.c.hunt_id == hunt_id)
            .order_by(audit_records.c.timestamp_utc, audit_records.c.audit_id)
        ).mappings().all()
    assert rows
    assert all(row["hunt_id"] == hunt_id for row in rows)
    assert any(row["action"] == "hunt_state_changed" and row["resulting_state"] == "approved" for row in rows)
    assert rows[-1]["action"] == "hunt_cancel_requested"
    assert rows[-1]["outcome"] == "already_cancelled"


def test_policy_rejection_checkpoint_retains_proposal_and_reason_codes() -> None:
    service, owner_id, hunt = _service()
    hunt_id = str(hunt["hunt_id"])
    proposal = {"spl": "search index=outside sourcetype=sysmon | head 1"}

    service._persist_policy_rejections(
        owner_id,
        hunt_id,
        [{"query_id": "query-1", "proposal": proposal, "reason_codes": ["index_outside_scope"]}],
        expected_state="awaiting_plan_review",
    )

    result = service.results(owner_id, hunt_id)
    assert result["query_policy_rejections"][0]["proposal"] == proposal
    assert result["query_policy_rejections"][0]["reason_codes"] == ["index_outside_scope"]
    with service.engine.connect() as connection:
        audit = connection.execute(
            select(audit_records.c.action, audit_records.c.outcome, audit_records.c.metadata)
            .where(audit_records.c.hunt_id == hunt_id, audit_records.c.action == "query_policy_rejected")
        ).mappings().one()
    assert audit["outcome"] == "rejected"
    assert audit["metadata"]["reason_codes"] == ["index_outside_scope"]
