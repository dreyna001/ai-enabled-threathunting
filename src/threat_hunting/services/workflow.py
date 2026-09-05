"""Persisted, policy-gated threat-hunt vertical-slice workflow."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import UUID, uuid4

from pydantic import TypeAdapter

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, MetaData, String, Table, Text, select, update
from sqlalchemy.engine import Engine

from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.contracts import HuntPlan, QueryProposal
from threat_hunting.domain.errors import FailureCategory
from threat_hunting.domain.spl_policy import SPLPolicy
from threat_hunting.domain.state import HuntState
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models.base import ModelAdapter
from threat_hunting.integrations.splunk import SplunkConnector
from threat_hunting.services.orchestration import (
    ModelContractError,
    ProductionHuntExecutor,
    ProductionOrchestrator,
    StrictModelRunner,
    sha256_json,
)
from threat_hunting.services.jobs import JobConflict, JobService


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
    Column("csrf_hash", String(64), nullable=False, default=""),
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


class _HuntCancellationToken:
    """Cooperative token backed by the durable hunt and fenced job lease."""

    def __init__(self, service: "WorkflowService", lease: Any) -> None:
        self.service = service
        self.lease = lease

    def is_cancelled(self) -> bool:
        signal = getattr(self.lease, "cancellation_token", None)
        if signal is not None and signal.is_cancelled():
            return True
        try:
            self.service.jobs.require_lease(
                self.lease.job_id,
                self.lease.worker_id,
                generation=getattr(self.lease, "generation", None),
                deployment_scope_id=getattr(self.lease, "deployment_scope_id", None),
            )
            row = self.service._owned_row(self.lease.owner_id, self.lease.hunt_id)
            return row["state"] == HuntState.CANCELLED.value
        except (JobConflict, NotFound):
            return True


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

    def __init__(
        self,
        engine: Engine,
        *,
        local_demo: bool = False,
        demo_password: str | None = None,
        splunk_connector: SplunkConnector | None = None,
        model_adapter: ModelAdapter | None = None,
        budget_limits: BudgetLimits | None = None,
        execution_config: Mapping[str, Any] | None = None,
    ) -> None:
        self.engine = engine
        self.local_demo = local_demo
        self.demo_password = demo_password
        self.password_hasher = PasswordHasher()
        self.cookie_secure = not local_demo
        self.splunk_connector = splunk_connector
        self.model_adapter = model_adapter
        self.budget_limits = budget_limits or BudgetLimits()
        self.execution_config = _json_copy(execution_config or {})
        raw_poll_interval = self.execution_config.get("splunk_poll_interval_seconds", 1.0)
        if isinstance(raw_poll_interval, bool):
            raise ValueError("splunk_poll_interval_seconds must be a positive number")
        self.splunk_poll_interval_seconds = float(raw_poll_interval)
        if not 0 < self.splunk_poll_interval_seconds <= 30:
            raise ValueError("splunk_poll_interval_seconds must be greater than 0 and at most 30")
        self.deployment_scope_id = str(self.execution_config.get("deployment_scope_id", "default"))
        self.jobs = JobService(engine, deployment_scope_id=self.deployment_scope_id, max_active_hunts=self.budget_limits.max_active_hunts)

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

    def cancel(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        """Cancel one owned hunt atomically; repeated cancellation is idempotent."""
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] == HuntState.CANCELLED.value:
            return self.get_hunt(owner_id, hunt_id)
        if row["state"] in {HuntState.FINALIZED.value, HuntState.FAILED.value}:
            raise Conflict("terminal hunts cannot be cancelled")
        self._update(owner_id, hunt_id, expected_state=str(row["state"]), state=HuntState.CANCELLED.value, updated_at_utc=_now())
        if not self.local_demo:
            self.jobs.request_cancel(owner_id, hunt_id)
        return self.get_hunt(owner_id, hunt_id)

    def job_status(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        self._owned_row(owner_id, hunt_id)
        job = self.jobs.get_for_owner(owner_id, hunt_id)
        if job is None:
            raise NotFound("execution job not found")
        return {key: value for key, value in job.items() if key != "payload"}

    def _discover_demo(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
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

    def discover(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        """Discover Splunk metadata and draft a strictly validated production plan."""

        if self.local_demo:
            return self._discover_demo(owner_id, hunt_id)
        if self.splunk_connector is None or self.model_adapter is None:
            raise IntegrationUnavailable("production Splunk and model adapters are not configured")
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] != HuntState.CREATED.value:
            raise Conflict("discovery requires a newly created hunt")
        now = _now()
        self._update(owner_id, hunt_id, expected_state=HuntState.CREATED.value, state=HuntState.DISCOVERING.value, updated_at_utc=now)
        try:
            orchestrator = ProductionOrchestrator(self.splunk_connector, self.model_adapter, limits=self.budget_limits)
            discovery, discovery_snapshot = orchestrator.discover()
            execution_snapshot = orchestrator.execution_snapshot(self._execution_binding_payload())
            plan_id, snapshot_id, config_id = uuid4(), discovery_snapshot.snapshot_id, execution_snapshot.snapshot_id
            context = {
                "hunt_id": str(row["hunt_id"]),
                "hypothesis": row["hypothesis"],
                "objective": row["objective"],
                "analyst_supplied_context": {
                    "threat_intelligence": row["threat_intelligence"],
                    "customer_context": row["synthetic_data"],
                },
                "discovery_snapshot": discovery_snapshot.to_dict(),
                "application_assigned_ids": {
                    "plan_id": str(plan_id),
                    "discovery_snapshot_id": str(snapshot_id),
                    "execution_config_snapshot_id": str(config_id),
                },
            }
            counters = BudgetCounters()
            plan = orchestrator.draft_plan(
                runner=StrictModelRunner(self.model_adapter, counters=counters, limits=self.budget_limits),
                context=context,
            )
            if plan.plan_id != plan_id or plan.hunt_id != UUID(str(row["hunt_id"])) or plan.discovery_snapshot_id != snapshot_id or plan.execution_config_snapshot_id != config_id:
                raise Validation("model plan identifiers do not match application-assigned snapshots")
            if plan.plan_version != 1:
                raise Validation("production discovery requires plan_version 1")
            snapshot = discovery_snapshot.to_dict()
            snapshot["execution_config_snapshot"] = execution_snapshot.to_dict()
            snapshot["input_context"] = context["analyst_supplied_context"]
            snapshot["mode"] = "production"
            plan_payload = plan.model_dump(mode="json")
            self._update(owner_id, hunt_id, expected_state=HuntState.DISCOVERING.value, state=HuntState.PLAN_DRAFT.value, discovery_snapshot=snapshot, plan=plan_payload, plan_version=1, updated_at_utc=now)
            self._update(owner_id, hunt_id, expected_state=HuntState.PLAN_DRAFT.value, state=HuntState.AWAITING_PLAN_REVIEW.value, updated_at_utc=_now())
            return self.get_hunt(owner_id, hunt_id)
        except (AdapterError, ModelContractError, ValueError) as exc:
            # Keep provider details out of the API and leave the hunt explicitly failed.
            try:
                self._update(owner_id, hunt_id, expected_state=HuntState.DISCOVERING.value, state=HuntState.FAILED.value, updated_at_utc=_now())
            except Conflict:
                pass
            raise IntegrationUnavailable("production discovery failed") from exc

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
        snapshot = row.get("discovery_snapshot") or {}
        config_snapshot = snapshot.get("execution_config_snapshot") if isinstance(snapshot, Mapping) else None
        if isinstance(config_snapshot, Mapping):
            approval["execution_config_snapshot_id"] = config_snapshot.get("snapshot_id")
            approval["execution_config_sha256"] = config_snapshot.get("sha256")
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
            snapshot = row.get("discovery_snapshot") or {}
            config_snapshot = snapshot.get("execution_config_snapshot") if isinstance(snapshot, Mapping) else None
            if not isinstance(config_snapshot, Mapping) or row["approval"].get("execution_config_snapshot_id") != config_snapshot.get("snapshot_id") or row["approval"].get("execution_config_sha256") != config_snapshot.get("sha256"):
                raise Conflict("approved execution configuration binding is invalid")
            self._validate_execution_snapshot(config_snapshot)
            now = _now()
            job = self.jobs.enqueue(owner_id, hunt_id, idempotency_key=f"hunt:{hunt_id}:execution", payload={"hunt_id": hunt_id, "plan_version": row["plan_version"], "plan_sha256": row["approval"]["plan_sha256"], "execution_config_snapshot_id": row["approval"].get("execution_config_snapshot_id"), "execution_config_sha256": row["approval"].get("execution_config_sha256")})
            try:
                self._update(owner_id, hunt_id, expected_state=HuntState.APPROVED.value, state=HuntState.QUEUED.value, updated_at_utc=now)
            except Exception:
                # If the state transition loses a race or the write fails, do
                # not leave an executable orphan in the queue.
                self.jobs.request_cancel(owner_id, hunt_id)
                raise
            return self.get_hunt(owner_id, hunt_id) | {"job": {key: value for key, value in job.items() if key not in {"payload"}}}
        now, query_id, evidence_id, finding_id = _now(), str(uuid4()), str(uuid4()), str(uuid4())
        evidence = {"evidence_id": evidence_id, "query_id": query_id, "source": "deterministic_local_demo", "event_time_utc": _rfc3339(now - timedelta(minutes=14)), "selected_result": {"host": "demo-workstation-17", "user": "demo\\analyst", "src_ip": "192.0.2.17", "EventCode": "4624"}, "disclaimer": "Deterministic local demo evidence; not a production observation."}
        results = {"findings": [{"finding_id": finding_id, "title": "Local demo authentication lead", "classification": "hunt_lead", "statement": "The deterministic demo dataset contains one scoped authentication event for analyst review.", "confidence": "low", "evidence_ids": [evidence_id], "query_ids": [query_id], "inference": "Local demonstration only."}], "evidence": [evidence], "entities": [{"entity_id": str(uuid4()), "entity_type": "host", "value": "demo-workstation-17", "evidence_ids": [evidence_id]}, {"entity_id": str(uuid4()), "entity_type": "ip", "value": "192.0.2.17", "evidence_ids": [evidence_id]}], "timeline": [{"timestamp_utc": evidence["event_time_utc"], "summary": "Local demo authentication event", "evidence_ids": [evidence_id]}], "queries": [{"query_id": query_id, "purpose": "Answer q1", "spl": "index=security sourcetype=WinEventLog:Security EventCode=4624 | head 100", "status": "completed", "result_count": 1}], "mode": "deterministic_local_demo"}
        content = {"hypothesis": row["hypothesis"], "objective_and_scope": row["objective"], "data_sources_used": ["Local demo Splunk adapter"], "findings": results["findings"], "selected_evidence": results["evidence"], "entities": results["entities"], "timeline": results["timeline"], "coverage_and_limitations": ["Deterministic local demo results; production integrations were not invoked."], "conclusion_and_disposition": "One low-confidence hunt lead requires analyst validation.", "query_appendix": results["queries"]}
        self._update(owner_id, hunt_id, expected_state=HuntState.APPROVED.value, state=HuntState.QUEUED.value, updated_at_utc=now)
        self._update(owner_id, hunt_id, expected_state=HuntState.QUEUED.value, state=HuntState.RUNNING.value, updated_at_utc=now)
        self._update(owner_id, hunt_id, expected_state=HuntState.RUNNING.value, state=HuntState.SYNTHESIZING.value, results=results, updated_at_utc=now)
        self._update(owner_id, hunt_id, expected_state=HuntState.SYNTHESIZING.value, state=HuntState.REPORT_DRAFT.value, report_id=str(uuid4()), report_version=1, report_state=HuntState.REPORT_DRAFT.value, report_content=content, updated_at_utc=now)
        return self.get_hunt(owner_id, hunt_id)

    def start_execution(self, owner_id: str, hunt_id: str, job_id: str, worker_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        """Atomically move one owned queued hunt to running under its lease."""
        now = now or _now()
        try:
            lease = self.jobs.require_lease(job_id, worker_id, now=now)
        except JobConflict as exc:
            raise Conflict(str(exc)) from exc
        if str(lease["hunt_id"]) != hunt_id or str(lease["owner_id"]) != owner_id:
            raise Conflict("job lease is not scoped to this hunt")
        self._update(owner_id, hunt_id, expected_state=HuntState.QUEUED.value, state=HuntState.RUNNING.value, updated_at_utc=now)
        return self.get_hunt(owner_id, hunt_id)

    def persist_execution_result(
        self, owner_id: str, hunt_id: str, results: Mapping[str, Any], report_content: Mapping[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        """Persist bounded worker output and advance running→synthesizing→report draft."""
        now = now or _now()
        normalized_results = _json_copy(results)
        normalized_report = _json_copy(report_content)
        if not isinstance(normalized_results, dict) or not isinstance(normalized_report, dict):
            raise Validation("execution results and report content must be JSON objects")
        if len(json.dumps(normalized_results, ensure_ascii=False).encode()) > 8 * 1024 * 1024:
            raise Validation("execution results exceed the 8 MiB limit")
        if len(json.dumps(normalized_report, ensure_ascii=False).encode()) > 1024 * 1024:
            raise Validation("report content exceeds the 1 MiB limit")
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] == HuntState.CANCELLED.value:
            raise Conflict("cancelled hunts cannot accept late execution results")
        if row["state"] == HuntState.REPORT_DRAFT.value:
            return self.get_hunt(owner_id, hunt_id)
        if row["state"] == HuntState.RUNNING.value:
            self._update(owner_id, hunt_id, expected_state=HuntState.RUNNING.value, state=HuntState.SYNTHESIZING.value, results=normalized_results, updated_at_utc=now)
        elif row["state"] != HuntState.SYNTHESIZING.value:
            raise Conflict("execution result is not valid for the current hunt state")
        self._update(owner_id, hunt_id, expected_state=HuntState.SYNTHESIZING.value, state=HuntState.REPORT_DRAFT.value, report_id=str(uuid4()), report_version=1, report_state=HuntState.REPORT_DRAFT.value, report_content=normalized_report, updated_at_utc=now)
        return self.get_hunt(owner_id, hunt_id)

    def fail_execution(self, owner_id: str, hunt_id: str, reason: str, *, now: datetime | None = None) -> dict[str, Any]:
        """Persist a bounded worker failure without reviving cancelled work."""
        now = now or _now()
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] == HuntState.CANCELLED.value:
            return self.get_hunt(owner_id, hunt_id)
        if row["state"] in {HuntState.FINALIZED.value, HuntState.FAILED.value}:
            return self.get_hunt(owner_id, hunt_id)
        detail = (reason or "execution failed")[:2000]
        failure_results = dict(row["results"] or {}) if isinstance(row["results"], Mapping) else {}
        failure_results["failure"] = detail
        self._update(owner_id, hunt_id, expected_state=str(row["state"]), state=HuntState.FAILED.value, updated_at_utc=now, results=failure_results)
        return self.get_hunt(owner_id, hunt_id)

    def execute_job(self, lease: Any) -> None:
        """Run one claimed production execution job and persist its artifacts."""

        if self.local_demo:
            raise IntegrationUnavailable("demo executions are handled synchronously")
        if self.splunk_connector is None or self.model_adapter is None:
            raise IntegrationUnavailable("production Splunk and model adapters are not configured")
        try:
            self.jobs.require_lease(
                lease.job_id,
                lease.worker_id,
                generation=getattr(lease, "generation", None),
                deployment_scope_id=getattr(lease, "deployment_scope_id", None),
            )
        except JobConflict as exc:
            raise Conflict(str(exc)) from exc
        row = self._owned_row(lease.owner_id, lease.hunt_id)
        if row["state"] == HuntState.CANCELLED.value:
            return
        if row["state"] != HuntState.QUEUED.value:
            raise Conflict("execution job is not queued")
        approval = row["approval"] or {}
        canonical = json.dumps(row["plan"], sort_keys=True, separators=(",", ":")).encode()
        if approval.get("plan_sha256") != hashlib.sha256(canonical).hexdigest() or approval.get("plan_version") != row["plan_version"]:
            raise Conflict("approved plan binding is invalid")
        snapshot = row["discovery_snapshot"] or {}
        config_snapshot = snapshot.get("execution_config_snapshot") if isinstance(snapshot, Mapping) else None
        if not isinstance(config_snapshot, Mapping):
            raise Conflict("execution configuration snapshot is missing")
        if approval.get("execution_config_snapshot_id") != config_snapshot.get("snapshot_id") or approval.get("execution_config_sha256") != config_snapshot.get("sha256"):
            raise Conflict("approved execution configuration binding is invalid")
        self._validate_execution_snapshot(config_snapshot)
        try:
            self.jobs.require_lease(lease.job_id, lease.worker_id, generation=getattr(lease, "generation", None), deployment_scope_id=getattr(lease, "deployment_scope_id", None))
            self._update(row["owner_id"], lease.hunt_id, expected_state=HuntState.QUEUED.value, state=HuntState.RUNNING.value, updated_at_utc=_now())
        except JobConflict as exc:
            raise Conflict(str(exc)) from exc
        counters = BudgetCounters()
        token = _HuntCancellationToken(self, lease)
        deadline = _now() + timedelta(seconds=self.budget_limits.hard_hunt_seconds)
        try:
            discovery = snapshot.get("payload", snapshot) if isinstance(snapshot, Mapping) else {}
            plan = HuntPlan.model_validate(row["plan"])
            if str(plan.execution_config_snapshot_id) != str(config_snapshot.get("snapshot_id")):
                raise Conflict("plan execution configuration binding is invalid")
            policy = SPLPolicy(
                discovered_indexes=set(str(item) for item in discovery.get("indexes", [])),
                discovered_sourcetypes=set(str(item) for item in discovery.get("sourcetypes", [])),
                discovered_fields=set(str(item) for item in discovery.get("fields", [])),
                approved_indexes=set(plan.scope.indexes),
                approved_sourcetypes=set(plan.scope.sourcetypes),
                approved_earliest_utc=plan.scope.earliest_utc,
                approved_latest_utc=plan.scope.latest_utc,
                connection_id=str(self.execution_config.get("deployment_scope_id", "configured")),
                execution_config_snapshot_id=str(plan.execution_config_snapshot_id),
                max_bytes=self.budget_limits.max_cached_bytes_per_query,
                timeout_seconds=self.budget_limits.splunk_query_timeout_seconds,
            )
            query_contract = TypeAdapter(list[QueryProposal])
            runner = StrictModelRunner(self.model_adapter, counters=counters, limits=self.budget_limits, deadline=deadline, cancellation_token=token)
            proposals = runner.run(
                query_contract,
                user_payload={"approved_plan": plan.model_dump(mode="json"), "remaining_budget": self.budget_limits.model_dump(mode="json")},
                contract_name="QueryProposal[]",
            )
            query_records: list[dict[str, Any]] = []
            evidence_records: list[dict[str, Any]] = []

            def on_submitted(query_id: UUID, sid: str, proposal: QueryProposal) -> None:
                if token.is_cancelled():
                    raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="splunk.submit")
                self.jobs.require_lease(lease.job_id, lease.worker_id, generation=getattr(lease, "generation", None), deployment_scope_id=getattr(lease, "deployment_scope_id", None))
                current = self._owned_row(row["owner_id"], lease.hunt_id)
                result_payload = dict(current["results"] or {}) if isinstance(current["results"], Mapping) else {}
                ledger = list(result_payload.get("query_ledger", []))
                ledger.append({"query_id": str(query_id), "splunk_job_id": sid, "purpose": proposal.purpose, "spl": proposal.spl, "status": "submitted", "submitted_at_utc": _rfc3339(_now())})
                result_payload["query_ledger"] = ledger
                result_payload["usage"] = counters.model_dump(mode="json")
                result_payload["mode"] = "production"
                self._update(row["owner_id"], lease.hunt_id, expected_state=HuntState.RUNNING.value, results=result_payload, updated_at_utc=_now())

            executor = ProductionHuntExecutor(self.splunk_connector, policy, counters=counters, limits=self.budget_limits, cancellation_token=token, deadline=deadline, on_submitted=on_submitted, poll_interval_seconds=self.splunk_poll_interval_seconds)
            for proposal in proposals:
                if token.is_cancelled():
                    raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="splunk.submit")
                execution = executor.execute_query(proposal)
                evidence = executor.evidence_for_query(execution, hunt_id=UUID(lease.hunt_id), proposal=proposal)
                evidence_records.extend(item.model_dump(mode="json") for item in evidence)
                query_records.append({"query_id": str(execution.query_id), "splunk_job_id": execution.splunk_job_id, "purpose": proposal.purpose, "spl": proposal.spl, "status": "completed", "result_count": len(execution.rows), "result_bytes": execution.result_bytes, "truncated": execution.truncated})
            if token.is_cancelled():
                raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="execution.complete")
            results = {"findings": [], "evidence": evidence_records, "entities": [], "timeline": [], "queries": query_records, "query_ledger": query_records, "usage": counters.model_dump(mode="json"), "mode": "production"}
            content = {"hypothesis": row["hypothesis"], "objective_and_scope": row["objective"], "data_sources_used": ["Configured Splunk"], "findings": [], "selected_evidence": evidence_records, "entities": [], "timeline": [], "coverage_and_limitations": list(plan.coverage_limitations), "conclusion_and_disposition": "Evidence is retained for analyst review; findings require contract-grounded synthesis.", "query_appendix": query_records}
            self.jobs.require_lease(lease.job_id, lease.worker_id, generation=getattr(lease, "generation", None), deployment_scope_id=getattr(lease, "deployment_scope_id", None))
            self._update(row["owner_id"], lease.hunt_id, expected_state=HuntState.RUNNING.value, state=HuntState.SYNTHESIZING.value, results=results, updated_at_utc=_now())
            self.jobs.require_lease(lease.job_id, lease.worker_id, generation=getattr(lease, "generation", None), deployment_scope_id=getattr(lease, "deployment_scope_id", None))
            self._update(row["owner_id"], lease.hunt_id, expected_state=HuntState.SYNTHESIZING.value, state=HuntState.REPORT_DRAFT.value, report_id=str(uuid4()), report_version=1, report_state=HuntState.REPORT_DRAFT.value, report_content=content, updated_at_utc=_now())
        except Exception:
            try:
                self.jobs.require_lease(lease.job_id, lease.worker_id, generation=getattr(lease, "generation", None), deployment_scope_id=getattr(lease, "deployment_scope_id", None))
                current = self._owned_row(row["owner_id"], lease.hunt_id)
                if current["state"] == HuntState.RUNNING.value:
                    failure_results = dict(current["results"] or {}) if isinstance(current["results"], Mapping) else {}
                    failure_results["usage"] = counters.model_dump(mode="json")
                    failure_results["mode"] = "production"
                    self._update(row["owner_id"], lease.hunt_id, expected_state=HuntState.RUNNING.value, state=HuntState.FAILED.value, results=failure_results, updated_at_utc=_now())
            except (Conflict, JobConflict):
                pass
            raise

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

    def _execution_binding_payload(self) -> dict[str, Any]:
        """Return the exact non-secret configuration and budget binding."""
        return {
            "execution_config": _json_copy(self.execution_config),
            "budget_limits": self.budget_limits.model_dump(mode="json"),
        }

    def _validate_execution_snapshot(self, snapshot: Mapping[str, Any]) -> None:
        """Fail closed when approved config or budget limits drift."""
        expected_payload = self._execution_binding_payload()
        if snapshot.get("payload") != expected_payload:
            raise Conflict("approved execution configuration content no longer matches current settings")
        expected_hash = sha256_json({"kind": "execution_configuration", "payload": expected_payload})
        if snapshot.get("sha256") != expected_hash:
            raise Conflict("approved execution configuration hash is invalid")

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
