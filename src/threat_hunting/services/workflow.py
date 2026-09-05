"""Persisted, policy-gated threat-hunt vertical-slice workflow."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, MetaData, String, Table, Text, select, update
from sqlalchemy.engine import Engine

from threat_hunting.domain.state import HuntState


workflow_metadata = MetaData()
CONTEXT_INPUT_MAX_LENGTH = 50_000

users = Table(
    "workflow_users", workflow_metadata,
    Column("user_id", String(36), primary_key=True),
    Column("username", String(100), nullable=False, unique=True),
    Column("display_name", String(200), nullable=False),
    Column("password_hash", String(512), nullable=False),
)
sessions = Table(
    "workflow_sessions", workflow_metadata,
    Column("token_hash", String(64), primary_key=True),
    Column("user_id", String(36), ForeignKey("workflow_users.user_id"), nullable=False),
    Column("expires_at_utc", DateTime(timezone=True), nullable=False),
)
hunts = Table(
    "workflow_hunts", workflow_metadata,
    Column("hunt_id", String(36), primary_key=True),
    Column("owner_id", String(36), nullable=False, index=True),
    Column("title", String(200), nullable=False),
    Column("hypothesis", Text, nullable=False),
    Column("objective", Text, nullable=False),
    Column("threat_intelligence", Text, nullable=False, default=""),
    Column("synthetic_data", Text, nullable=False, default=""),
    Column("state", String(32), nullable=False),
    Column("plan_version", Integer, nullable=True),
    Column("plan", JSON, nullable=True),
    Column("discovery_snapshot", JSON, nullable=True),
    Column("approval", JSON, nullable=True),
    Column("results", JSON, nullable=True),
    Column("report_id", String(36), nullable=True),
    Column("report_version", Integer, nullable=True),
    Column("report_state", String(32), nullable=True),
    Column("report_content", JSON, nullable=True),
    Column("report_pdf", LargeBinary, nullable=True),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    Column("updated_at_utc", DateTime(timezone=True), nullable=False),
)


class WorkflowError(RuntimeError):
    """Base workflow failure with a stable HTTP-facing category."""


class NotFound(WorkflowError):
    pass


class Conflict(WorkflowError):
    pass


class Validation(WorkflowError):
    pass


class IntegrationUnavailable(WorkflowError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_report_content(content: Mapping[str, Any], results: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate bounded report structure and retained-evidence references."""

    normalized = _json_copy(content)
    required = {"hypothesis", "objective_and_scope", "data_sources_used", "findings", "selected_evidence", "entities", "timeline", "coverage_and_limitations", "conclusion_and_disposition", "query_appendix"}
    if not isinstance(normalized, dict) or required.difference(normalized):
        raise Validation("report is missing required sections")
    if len(json.dumps(normalized, ensure_ascii=False).encode("utf-8")) > 1024 * 1024:
        raise Validation("report content exceeds the 1 MiB limit")
    for key in ("hypothesis", "objective_and_scope", "conclusion_and_disposition"):
        if not isinstance(normalized.get(key), str) or not normalized[key].strip():
            raise Validation(f"report section {key!r} must contain text")
    for key in ("data_sources_used", "findings", "selected_evidence", "entities", "timeline", "coverage_and_limitations", "query_appendix"):
        if not isinstance(normalized.get(key), list):
            raise Validation(f"report section {key!r} must be an array")
    available_evidence = {str(item.get("evidence_id")) for item in (results or {}).get("evidence", [])}
    cited_evidence = {str(item.get("evidence_id")) for item in normalized["selected_evidence"] if isinstance(item, dict)}
    if not cited_evidence.issubset(available_evidence):
        raise Validation("report references unavailable evidence")
    return normalized


def _minimal_pdf(title: str, body: str) -> bytes:
    """Return a small valid PDF containing escaped printable report text."""

    safe = f"{title} - {body}".replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    safe = "".join(character if 32 <= ord(character) <= 126 else "?" for character in safe)
    stream = f"BT /F1 11 Tf 50 750 Td ({safe}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    output.extend(b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:]))
    output.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


class WorkflowService:
    """Transactional workflow facade; every hunt operation is owner scoped."""

    def __init__(self, engine: Engine, *, local_demo: bool = False, demo_password: str | None = None) -> None:
        self.engine = engine
        self.local_demo = local_demo
        self.demo_password = demo_password
        self.password_hasher = PasswordHasher()

    def initialize_demo(self) -> None:
        """Create local/test tables and the one documented demo principal."""

        if not self.local_demo:
            return
        workflow_metadata.create_all(self.engine)
        if not self.demo_password:
            raise IntegrationUnavailable("local demo credentials are not configured")
        with self.engine.begin() as connection:
            exists = connection.execute(select(users.c.user_id).where(users.c.username == "analyst")).first()
            if exists is None:
                connection.execute(users.insert().values(
                    user_id=str(uuid4()), username="analyst", display_name="SOC Analyst",
                    password_hash=self.password_hasher.hash(self.demo_password),
                ))

    def login(self, username: str, password: str) -> dict[str, Any]:
        if not self.local_demo:
            raise IntegrationUnavailable("authentication provider is not configured")
        with self.engine.connect() as connection:
            user = connection.execute(select(users).where(users.c.username == username)).mappings().first()
        if user is None:
            raise Validation("invalid username or password")
        try:
            self.password_hasher.verify(str(user["password_hash"]), password)
        except (VerifyMismatchError, VerificationError):
            raise Validation("invalid username or password") from None
        now = _now()
        token = secrets.token_urlsafe(32)
        with self.engine.begin() as connection:
            connection.execute(sessions.insert().values(token_hash=_token_hash(token), user_id=user["user_id"], expires_at_utc=now + timedelta(hours=8)))
        public_user = {key: value for key, value in user.items() if key != "password_hash"}
        return {"access_token": token, "token_type": "bearer", "user": public_user}

    def authenticate(self, token: str) -> str:
        with self.engine.connect() as connection:
            row = connection.execute(select(sessions.c.user_id, sessions.c.expires_at_utc).where(sessions.c.token_hash == _token_hash(token))).mappings().first()
        expires = None if row is None else row["expires_at_utc"]
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if row is None or expires <= _now():
            raise Validation("invalid or expired bearer token")
        return str(row["user_id"])

    def list_hunts(self, owner_id: str) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            rows = connection.execute(select(hunts).where(hunts.c.owner_id == owner_id).order_by(hunts.c.created_at_utc.desc())).mappings().all()
        return [self._public(row) for row in rows]

    def create_hunt(
        self, owner_id: str, *, title: str, hypothesis: str, objective: str,
        threat_intelligence: str = "", synthetic_data: str = "",
    ) -> dict[str, Any]:
        if len(threat_intelligence) > CONTEXT_INPUT_MAX_LENGTH:
            raise Validation("threat intelligence exceeds the 50000 character limit")
        if len(synthetic_data) > CONTEXT_INPUT_MAX_LENGTH:
            raise Validation("synthetic data exceeds the 50000 character limit")
        now, hunt_id = _now(), str(uuid4())
        values = dict(
            hunt_id=hunt_id, owner_id=owner_id, title=title, hypothesis=hypothesis,
            objective=objective, threat_intelligence=threat_intelligence, synthetic_data=synthetic_data,
            state=HuntState.CREATED.value, created_at_utc=now, updated_at_utc=now,
        )
        with self.engine.begin() as connection:
            connection.execute(hunts.insert().values(**values))
        return self.get_hunt(owner_id, hunt_id)

    def get_hunt(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        with self.engine.connect() as connection:
            row = connection.execute(select(hunts).where(hunts.c.hunt_id == hunt_id, hunts.c.owner_id == owner_id)).mappings().first()
        if row is None:
            raise NotFound("hunt not found")
        return self._public(row)

    def discover(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        if not self.local_demo:
            raise IntegrationUnavailable("Splunk discovery adapter is not configured")
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] != HuntState.CREATED.value:
            raise Conflict("discovery requires a newly created hunt")
        now = _now()
        snapshot_id = str(uuid4())
        input_context = {"threat_intelligence": row["threat_intelligence"], "synthetic_data": row["synthetic_data"], "classification": "analyst_supplied_context"}
        snapshot = {"snapshot_id": snapshot_id, "discovered_at_utc": _rfc3339(now), "indexes": ["main", "security"], "sourcetypes": ["WinEventLog:Security", "sysmon"], "fields": ["_time", "host", "user", "src_ip", "EventCode"], "input_context": input_context, "coverage_limitations": ["Local demo metadata; not production Splunk discovery."], "mode": "deterministic_local_demo"}
        earliest, latest = now - timedelta(hours=24), now
        plan = {"hypothesis": row["hypothesis"], "objective": row["objective"], "input_context": input_context, "scope": {"earliest_utc": _rfc3339(earliest), "latest_utc": _rfc3339(latest), "indexes": snapshot["indexes"], "sourcetypes": snapshot["sourcetypes"]}, "questions": [{"question_id": "q1", "question": "Which scoped authentication activity supports or refutes the hypothesis?", "rationale": "Start with observable authentication telemetry.", "expected_information_gain": "Identify unusual host, user, and source-IP combinations."}], "query_strategy": ["Use bounded aggregate searches before representative events."], "coverage_limitations": snapshot["coverage_limitations"]}
        self._update(owner_id, hunt_id, expected_state=HuntState.CREATED.value, state=HuntState.DISCOVERING.value, updated_at_utc=now)
        self._update(owner_id, hunt_id, expected_state=HuntState.DISCOVERING.value, state=HuntState.PLAN_DRAFT.value, discovery_snapshot=snapshot, plan=plan, plan_version=1, updated_at_utc=now)
        self._update(owner_id, hunt_id, expected_state=HuntState.PLAN_DRAFT.value, state=HuntState.AWAITING_PLAN_REVIEW.value, updated_at_utc=now)
        return self.get_hunt(owner_id, hunt_id)

    def save_plan(self, owner_id: str, hunt_id: str, *, expected_version: int, plan: Mapping[str, Any]) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] not in {HuntState.AWAITING_PLAN_REVIEW.value, HuntState.PLAN_DRAFT.value}:
            raise Conflict("plan editing is not allowed in the current state")
        if row["plan_version"] != expected_version:
            raise Conflict("plan version is stale")
        normalized = self._validate_plan(plan)
        self._update(owner_id, hunt_id, expected_plan_version=expected_version, state=HuntState.AWAITING_PLAN_REVIEW.value, plan=normalized, plan_version=expected_version + 1, approval=None, updated_at_utc=_now())
        return self.get_hunt(owner_id, hunt_id)

    def revise_plan(self, owner_id: str, hunt_id: str, instruction: str) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] not in {HuntState.AWAITING_PLAN_REVIEW.value, HuntState.PLAN_DRAFT.value}:
            raise Conflict("plan revision is not allowed in the current state")
        plan = _json_copy(row["plan"])
        plan["coverage_limitations"] = [*plan.get("coverage_limitations", []), f"Analyst revision request: {instruction}"]
        self._update(owner_id, hunt_id, expected_plan_version=int(row["plan_version"]), state=HuntState.AWAITING_PLAN_REVIEW.value, plan=plan, plan_version=int(row["plan_version"]) + 1, approval=None, updated_at_utc=_now())
        return self.get_hunt(owner_id, hunt_id)

    def approve(self, owner_id: str, hunt_id: str, note: str | None) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] != HuntState.AWAITING_PLAN_REVIEW.value:
            raise Conflict("only a plan awaiting review can be approved")
        canonical = json.dumps(row["plan"], sort_keys=True, separators=(",", ":")).encode()
        approval = {"approval_id": str(uuid4()), "plan_version": row["plan_version"], "plan_sha256": hashlib.sha256(canonical).hexdigest(), "approved_by_user_id": owner_id, "approved_at_utc": _rfc3339(_now()), "analyst_note": note or "unknown"}
        self._update(owner_id, hunt_id, expected_state=HuntState.AWAITING_PLAN_REVIEW.value, expected_plan_version=int(row["plan_version"]), state=HuntState.APPROVED.value, approval=approval, updated_at_utc=_now())
        return self.get_hunt(owner_id, hunt_id)

    def reject(self, owner_id: str, hunt_id: str, note: str) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] != HuntState.AWAITING_PLAN_REVIEW.value:
            raise Conflict("only a plan awaiting review can be rejected")
        plan = _json_copy(row["plan"])
        plan["coverage_limitations"] = [*plan.get("coverage_limitations", []), f"Rejected for revision: {note}"]
        self._update(owner_id, hunt_id, expected_state=HuntState.AWAITING_PLAN_REVIEW.value, expected_plan_version=int(row["plan_version"]), state=HuntState.PLAN_DRAFT.value, plan=plan, approval=None, updated_at_utc=_now())
        return self.get_hunt(owner_id, hunt_id)

    def execute(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] != HuntState.APPROVED.value or not row["approval"]:
            raise Conflict("execution requires approval of the current plan version")
        if row["approval"]["plan_version"] != row["plan_version"]:
            raise Conflict("approved plan version no longer matches the current plan")
        if not self.local_demo:
            raise IntegrationUnavailable("Splunk execution adapter is not configured")
        now, query_id, evidence_id, finding_id = _now(), str(uuid4()), str(uuid4()), str(uuid4())
        evidence = {"evidence_id": evidence_id, "query_id": query_id, "source": "deterministic_local_demo", "event_time_utc": _rfc3339(now - timedelta(minutes=14)), "selected_result": {"host": "demo-workstation-17", "user": "demo\\analyst", "src_ip": "192.0.2.17", "EventCode": "4624"}, "disclaimer": "Deterministic local demo evidence; not a production observation."}
        results = {"findings": [{"finding_id": finding_id, "title": "Local demo authentication lead", "classification": "hunt_lead", "statement": "The deterministic demo dataset contains one scoped authentication event for analyst review.", "confidence": "low", "evidence_ids": [evidence_id], "query_ids": [query_id], "inference": "Local demonstration only."}], "evidence": [evidence], "entities": [{"entity_id": str(uuid4()), "entity_type": "host", "value": "demo-workstation-17", "evidence_ids": [evidence_id]}, {"entity_id": str(uuid4()), "entity_type": "ip", "value": "192.0.2.17", "evidence_ids": [evidence_id]}], "timeline": [{"timestamp_utc": evidence["event_time_utc"], "summary": "Local demo authentication event", "evidence_ids": [evidence_id]}], "queries": [{"query_id": query_id, "purpose": "Answer q1", "spl": "index=security sourcetype=WinEventLog:Security EventCode=4624 | head 100", "status": "completed", "result_count": 1}], "mode": "deterministic_local_demo"}
        content = {"hypothesis": row["hypothesis"], "objective_and_scope": row["objective"], "data_sources_used": ["Local demo Splunk adapter"], "findings": results["findings"], "selected_evidence": results["evidence"], "entities": results["entities"], "timeline": results["timeline"], "coverage_and_limitations": ["Deterministic local demo results; production integrations were not invoked."], "conclusion_and_disposition": "One low-confidence hunt lead requires analyst validation.", "query_appendix": results["queries"]}
        self._update(owner_id, hunt_id, expected_state=HuntState.APPROVED.value, state=HuntState.QUEUED.value, updated_at_utc=now)
        self._update(owner_id, hunt_id, expected_state=HuntState.QUEUED.value, state=HuntState.RUNNING.value, updated_at_utc=now)
        self._update(owner_id, hunt_id, expected_state=HuntState.RUNNING.value, state=HuntState.SYNTHESIZING.value, results=results, updated_at_utc=now)
        self._update(owner_id, hunt_id, expected_state=HuntState.SYNTHESIZING.value, state=HuntState.REPORT_DRAFT.value, report_id=str(uuid4()), report_version=1, report_state=HuntState.REPORT_DRAFT.value, report_content=content, updated_at_utc=now)
        return self.get_hunt(owner_id, hunt_id)

    def results(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["results"] is None:
            raise Conflict("hunt results are not available")
        return _json_copy(row["results"])

    def report(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["report_id"] is None:
            raise Conflict("report is not available")
        return {"hunt_id": hunt_id, "report_id": row["report_id"], "version": row["report_version"], "state": row["report_state"], "content": _json_copy(row["report_content"])}

    def save_report(self, owner_id: str, hunt_id: str, *, expected_version: int, content: Mapping[str, Any]) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["report_state"] != HuntState.REPORT_DRAFT.value:
            raise Conflict("finalized reports cannot be edited")
        if row["report_version"] != expected_version:
            raise Conflict("report version is stale")
        normalized = _validate_report_content(content, row["results"])
        self._update(owner_id, hunt_id, expected_state=HuntState.REPORT_DRAFT.value, expected_report_state=HuntState.REPORT_DRAFT.value, expected_report_version=expected_version, report_content=normalized, report_version=expected_version + 1, updated_at_utc=_now())
        return self.report(owner_id, hunt_id)

    def finalize_report(self, owner_id: str, hunt_id: str, *, expected_version: int) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["report_state"] != HuntState.REPORT_DRAFT.value or row["report_version"] != expected_version:
            raise Conflict("report is finalized or its version is stale")
        content = _validate_report_content(row["report_content"], row["results"])
        body = json.dumps(content, ensure_ascii=False, sort_keys=True)
        pdf = _minimal_pdf(row["title"], body)
        self._update(owner_id, hunt_id, expected_state=HuntState.REPORT_DRAFT.value, expected_report_state=HuntState.REPORT_DRAFT.value, expected_report_version=expected_version, state=HuntState.FINALIZED.value, report_state=HuntState.FINALIZED.value, report_pdf=pdf, updated_at_utc=_now())
        return self.report(owner_id, hunt_id)

    def pdf(self, owner_id: str, hunt_id: str) -> bytes:
        row = self._owned_row(owner_id, hunt_id)
        if row["report_state"] != HuntState.FINALIZED.value or row["report_pdf"] is None:
            raise Conflict("report must be finalized before PDF download")
        return bytes(row["report_pdf"])

    @staticmethod
    def _validate_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
        normalized = _json_copy(plan)
        required = {"hypothesis", "objective", "scope", "questions", "query_strategy", "coverage_limitations"}
        if not isinstance(normalized, dict) or required.difference(normalized):
            raise Validation("plan is missing required fields")
        if not normalized["questions"] or not isinstance(normalized["scope"], dict):
            raise Validation("plan requires scope and at least one question")
        return normalized

    def _owned_row(self, owner_id: str, hunt_id: str) -> Mapping[str, Any]:
        with self.engine.connect() as connection:
            row = connection.execute(select(hunts).where(hunts.c.hunt_id == hunt_id, hunts.c.owner_id == owner_id)).mappings().first()
        if row is None:
            raise NotFound("hunt not found")
        return row

    def _update(self, owner_id: str, hunt_id: str, *, expected_state: str | None = None, expected_plan_version: int | None = None, expected_report_state: str | None = None, expected_report_version: int | None = None, **values: Any) -> None:
        predicate = (hunts.c.hunt_id == hunt_id) & (hunts.c.owner_id == owner_id)
        if expected_state is not None:
            predicate &= hunts.c.state == expected_state
        if expected_plan_version is not None:
            predicate &= hunts.c.plan_version == expected_plan_version
        if expected_report_state is not None:
            predicate &= hunts.c.report_state == expected_report_state
        if expected_report_version is not None:
            predicate &= hunts.c.report_version == expected_report_version
        with self.engine.begin() as connection:
            result = connection.execute(update(hunts).where(predicate).values(**values))
        if result.rowcount != 1:
            raise Conflict("hunt changed before the operation completed")

    @staticmethod
    def _public(row: Mapping[str, Any]) -> dict[str, Any]:
        return {key: _json_copy(value) for key, value in row.items() if key not in {"owner_id", "report_pdf"}}


__all__ = ["Conflict", "IntegrationUnavailable", "NotFound", "Validation", "WorkflowService", "workflow_metadata"]
