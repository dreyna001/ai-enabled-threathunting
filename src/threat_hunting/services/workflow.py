"""Persisted, policy-gated threat-hunt vertical-slice workflow."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Sequence
from uuid import UUID, uuid4

from pydantic import TypeAdapter

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, LargeBinary, MetaData, String, Table, Text, and_, func, or_, select, update
from sqlalchemy.engine import Connection, Engine

from threat_hunting.db import bounded_audit_metadata
from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.contracts import FindingProposal, FollowUpDecision, HuntPlan, QueryAssessment, QueryProposal
from threat_hunting.domain.errors import FailureCategory, failure_metadata
from threat_hunting.domain.spl_policy import ALLOWED_EVAL_FUNCTIONS, ALLOWED_STATS_FUNCTIONS, SPLPolicy, parse_spl
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
from threat_hunting.services.threat_intel import query_ioc_context, intelligence_sources, validate_intelligence_refs
from threat_hunting.services.evidence import query_source_coverage
from threat_hunting.services.uploads import UploadLimits



from threat_hunting.domain.errors import (Conflict as Conflict, IntegrationUnavailable as IntegrationUnavailable, NotFound as NotFound, Validation as Validation, WorkflowError as WorkflowError)
from threat_hunting.services.reports import (
    _concise_report_content,
    _derive_report_limitations,
    _formatted_pdf,
    _execution_report_content,
    _validate_report_content,
)
from threat_hunting.services.investigation import (
    _assessment_context,
    _assessment_repair_context,
    _balanced_evidence_sample,
    _completed_query_questions,
    _flatten_scalar_values,
    _follow_up_decision_contract,
    _materialize_findings,
    _materialize_question_answers,
    _materialize_follow_up_questions,
    _question_synthesis_contract,
    _retained_synthesis_pages,
    _synthesis_context,
    _pending_investigation_questions,
    _follow_up_proposal_errors,
)

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
login_rate_limits = Table(
    "login_rate_limits", workflow_metadata,
    Column("bucket_hash", String(64), primary_key=True),
    Column("failure_count", Integer, nullable=False),
    Column("window_started_at_utc", DateTime(timezone=True), nullable=False),
    Column("blocked_until_utc", DateTime(timezone=True), nullable=True),
    Column("updated_at_utc", DateTime(timezone=True), nullable=False),
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
Index("ix_workflow_hunts_owner_created_id", hunts.c.owner_id, hunts.c.created_at_utc, hunts.c.hunt_id)

audit_records = Table(
    "audit_records", workflow_metadata,
    Column("audit_id", String(36), primary_key=True),
    Column("hunt_id", String(36), nullable=True),
    Column("owner_id", String(36), nullable=True),
    Column("request_id", String(128), nullable=True),
    Column("actor_type", String(32), nullable=False),
    Column("actor_id", String(200), nullable=True),
    Column("action", String(100), nullable=False),
    Column("object_type", String(100), nullable=True),
    Column("object_id", String(200), nullable=True),
    Column("prior_state", String(32), nullable=True),
    Column("resulting_state", String(32), nullable=True),
    Column("outcome", String(32), nullable=False),
    Column("detail", String(2000), nullable=True),
    Column("metadata", JSON, nullable=True),
    Column("timestamp_utc", DateTime(timezone=True), nullable=False),
)


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
        upload_limits: UploadLimits | None = None,
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
        self.upload_limits = upload_limits or UploadLimits()
        self.execution_config = _json_copy(execution_config or {})
        raw_poll_interval = self.execution_config.get("splunk_poll_interval_seconds", 1.0)
        if isinstance(raw_poll_interval, bool):
            raise ValueError("splunk_poll_interval_seconds must be a positive number")
        self.splunk_poll_interval_seconds = float(raw_poll_interval)
        if not 0 < self.splunk_poll_interval_seconds <= 30:
            raise ValueError("splunk_poll_interval_seconds must be greater than 0 and at most 30")
        self.deployment_scope_id = str(self.execution_config.get("deployment_scope_id", "default"))
        self.jobs = JobService(engine, deployment_scope_id=self.deployment_scope_id, max_active_hunts=self.budget_limits.max_active_hunts)

    def close(self) -> None:
        """Release application adapters; the composing caller owns the engine."""
        for adapter in (self.model_adapter, self.splunk_connector):
            close = getattr(adapter, "close", None)
            if callable(close):
                close()

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
                user_id = str(uuid4())
                now = _now()
                connection.execute(users.insert().values(
                    user_id=user_id, username="analyst", display_name="SOC Analyst",
                    password_hash=self.password_hasher.hash(self.demo_password),
                ))
                connection.execute(audit_records.insert().values(
                    audit_id=str(uuid4()),
                    owner_id=user_id,
                    actor_type="system",
                    actor_id=user_id,
                    action="account_initialized",
                    object_type="account",
                    object_id=user_id,
                    outcome="success",
                    detail="local demo account initialized",
                    metadata=None,
                    timestamp_utc=now,
                ))

    def login(self, username: str, password: str) -> dict[str, Any]:
        if not self.local_demo:
            raise IntegrationUnavailable("authentication provider is not configured")
        with self.engine.connect() as connection:
            user = connection.execute(select(users).where(users.c.username == username)).mappings().first()
        if user is None:
            with self.engine.begin() as connection:
                connection.execute(audit_records.insert().values(
                    audit_id=str(uuid4()),
                    actor_type="analyst",
                    actor_id=username[:200],
                    action="login_failed",
                    object_type="session",
                    outcome="failure",
                    detail="invalid credentials",
                    metadata=None,
                    timestamp_utc=_now(),
                ))
            raise Validation("invalid username or password")
        try:
            self.password_hasher.verify(str(user["password_hash"]), password)
        except (VerifyMismatchError, VerificationError):
            with self.engine.begin() as connection:
                connection.execute(audit_records.insert().values(
                    audit_id=str(uuid4()),
                    owner_id=str(user["user_id"]),
                    actor_type="analyst",
                    actor_id=str(user["user_id"]),
                    action="login_failed",
                    object_type="session",
                    outcome="failure",
                    detail="invalid credentials",
                    metadata=None,
                    timestamp_utc=_now(),
                ))
            raise Validation("invalid username or password") from None
        now = _now()
        token = secrets.token_urlsafe(32)
        with self.engine.begin() as connection:
            connection.execute(sessions.insert().values(token_hash=_token_hash(token), user_id=user["user_id"], expires_at_utc=now + timedelta(hours=8)))
            connection.execute(audit_records.insert().values(
                audit_id=str(uuid4()),
                owner_id=str(user["user_id"]),
                actor_type="analyst",
                actor_id=str(user["user_id"]),
                action="login_succeeded",
                object_type="session",
                object_id=_token_hash(token),
                outcome="success",
                detail=None,
                metadata=None,
                timestamp_utc=now,
            ))
        public_user = {key: value for key, value in user.items() if key != "password_hash"}
        return {"access_token": token, "token_type": "bearer", "user": public_user}

    def authenticate(self, token: str) -> str:
        with self.engine.connect() as connection:
            row = connection.execute(select(sessions.c.user_id, sessions.c.expires_at_utc).where(sessions.c.token_hash == _token_hash(token))).mappings().first()
        expires = None if row is None else row["expires_at_utc"]
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if row is None or expires is None or expires <= _now():
            raise Validation("invalid or expired bearer token")
        return str(row["user_id"])

    def list_hunts(self, owner_id: str, *, limit: int = 50, cursor: str | None = None) -> list[dict[str, Any]]:
        """Return a bounded summary page, ordered by immutable creation time and ID."""
        if not 1 <= limit <= 100:
            raise Validation("limit must be between 1 and 100")
        statement = select(
            hunts.c.hunt_id, hunts.c.title, func.substr(hunts.c.hypothesis, 1, 500).label("hypothesis"),
            hunts.c.state, hunts.c.created_at_utc, hunts.c.updated_at_utc,
        ).where(hunts.c.owner_id == owner_id)
        with self.engine.connect() as connection:
            if cursor is not None:
                cursor_time = connection.execute(select(hunts.c.created_at_utc).where(
                    hunts.c.owner_id == owner_id, hunts.c.hunt_id == cursor,
                )).scalar_one_or_none()
                if cursor_time is None:
                    raise Validation("invalid hunt page cursor")
                statement = statement.where(or_(
                    hunts.c.created_at_utc < cursor_time,
                    and_(hunts.c.created_at_utc == cursor_time, hunts.c.hunt_id < cursor),
                ))
            rows = connection.execute(statement.order_by(
                hunts.c.created_at_utc.desc(), hunts.c.hunt_id.desc(),
            ).limit(limit)).mappings().all()
        return [dict(row) for row in rows]

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
            connection.execute(audit_records.insert().values(
                audit_id=str(uuid4()),
                hunt_id=hunt_id,
                owner_id=owner_id,
                actor_type="analyst",
                actor_id=owner_id,
                action="hunt_created",
                object_type="hunt",
                object_id=hunt_id,
                prior_state=None,
                resulting_state=HuntState.CREATED.value,
                outcome="success",
                detail=None,
                metadata=None,
                timestamp_utc=now,
            ))
        return self.get_hunt(owner_id, hunt_id)

    def get_hunt(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        with self.engine.connect() as connection:
            row = connection.execute(select(hunts).where(hunts.c.hunt_id == hunt_id, hunts.c.owner_id == owner_id)).mappings().first()
        if row is None:
            raise NotFound("hunt not found")
        return self._public(dict(row))

    def cancel(self, owner_id: str, hunt_id: str) -> dict[str, Any]:
        """Cancel one owned hunt atomically; repeated cancellation is idempotent."""
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] == HuntState.CANCELLED.value:
            with self.engine.begin() as connection:
                connection.execute(audit_records.insert().values(
                    audit_id=str(uuid4()),
                    hunt_id=hunt_id,
                    owner_id=owner_id,
                    actor_type="analyst",
                    actor_id=owner_id,
                    action="hunt_cancel_requested",
                    object_type="hunt",
                    object_id=hunt_id,
                    prior_state=HuntState.CANCELLED.value,
                    resulting_state=HuntState.CANCELLED.value,
                    outcome="already_cancelled",
                    detail=None,
                    metadata=None,
                    timestamp_utc=_now(),
                ))
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
                    "intelligence_sources": intelligence_sources(str(row["hunt_id"]), str(row["threat_intelligence"] or "")),
                    "advisory_iocs": query_ioc_context(str(row["threat_intelligence"] or "")),
                    "customer_context": row["synthetic_data"],
                },
                "discovery_snapshot": discovery_snapshot.to_dict(),
                "application_assigned_ids": {
                    "plan_id": str(plan_id),
                    "discovery_snapshot_id": str(snapshot_id),
                    "execution_config_snapshot_id": str(config_id),
                },
                "planning_rules": [
                    "The application owns intelligence_refs and attaches references to the supplied advisory content. Omit intelligence_refs from the response; do not invent document names, IDs or external source provenance.",
                    "Question IDs are application-owned. Use unknown for draft question_id values; the application assigns unique IDs before plan review. Do not reference draft IDs elsewhere in the plan.",
                    "Frame questions around the hypothesis, available telemetry, and the approved scope.",
                    "Exact advisory file hashes can be matched directly in a shared hash field. Do not prescribe additional hash-type filters from advisory algorithm names, or assume categorical telemetry values from field names; discover unknown values when needed.",
                    "When the hypothesis could involve compromise or spread, include a question that assesses scope and spread across related hosts, users, source or destination IPs, and processes; answer it with available telemetry or record the limitation.",
                    "When relevant, examine activity before and after a suspicious lead to establish a bounded timeline.",
                    "Cover observable behaviors relevant to the advisory and hypothesis; do not attempt every ATT&CK tactic or require unsupported telemetry.",
                    "Treat blast-radius questions as unanswered until scoped evidence supports an assessment; record telemetry gaps and uncertainty.",
                    "Distinguish an advisory or IOC match from observed execution or activity and from a confirmed incident; do not treat one as proof of the next.",
                    "Use NIST SP 800-61 Rev. 3 DE.AE-03, DE.AE-04, and RS.AN-08, together with MITRE TTP-Based Hunting section 2.4.3.6, as general guidance only; do not claim framework compliance.",
                ],
            }
            counters = BudgetCounters()
            runner = StrictModelRunner(self.model_adapter, counters=counters, limits=self.budget_limits)
            required_scope = None
            required_pairs: set[tuple[str, str]] | None = None
            context["planning_stage"] = "scope_draft"
            context["planning_rules"].append(
                "Catalog metadata may omit search-time fields. Do not infer that a source cannot provide a field merely because it is missing from metadata or a sample. The application samples the proposed sources and dates before final plan review."
            )
            for _ in range(2):
                plan = orchestrator.draft_plan(runner=runner, context=context)
                if plan.plan_id != plan_id or plan.hunt_id != UUID(str(row["hunt_id"])) or plan.discovery_snapshot_id != snapshot_id or plan.execution_config_snapshot_id != config_id:
                    raise Validation("model plan identifiers do not match application-assigned snapshots")
                if plan.plan_version != 1:
                    raise Validation("production discovery requires plan_version 1")
                pairs = {(source.index, kind) for source in plan.data_sources for kind in source.sourcetypes}
                if (not set(plan.scope.indexes).issubset(discovery.indexes)
                        or not set(plan.scope.sourcetypes).issubset(discovery.sourcetypes)
                        or any(index not in plan.scope.indexes or kind not in plan.scope.sourcetypes for index, kind in pairs)):
                    raise Validation("proposed plan sources are outside discovery or plan scope")
                if required_scope is not None:
                    if (plan.scope.earliest_utc != required_scope.earliest_utc or plan.scope.latest_utc != required_scope.latest_utc
                            or set(plan.scope.indexes) != set(required_scope.indexes)
                            or set(plan.scope.sourcetypes) != set(required_scope.sourcetypes) or pairs != required_pairs):
                        raise Validation("grounded plan changed the sampled scope or source pairs")
                    break
                required_scope, required_pairs = plan.scope, pairs
                scoped_discovery, scoped_snapshot = orchestrator.discover(plan=plan)
                fields_changed = (set(scoped_discovery.fields) != set(discovery.fields)
                                  or scoped_discovery.representative_schemas != discovery.representative_schemas)
                discovery, discovery_snapshot = scoped_discovery, scoped_snapshot
                snapshot_id = discovery_snapshot.snapshot_id
                if not fields_changed:
                    # Identities are application-owned and the field context
                    # is unchanged; no second model call is necessary.
                    plan.discovery_snapshot_id = snapshot_id
                    break
                context["planning_stage"] = "grounded_plan"
                context["discovery_snapshot"] = discovery_snapshot.to_dict()
                context["application_assigned_ids"]["discovery_snapshot_id"] = str(snapshot_id)
                context["required_scope"] = required_scope.model_dump(mode="json")
                context["required_source_pairs"] = sorted(pairs)
                context["planning_rules"].append(
                    "Finish the plan using the refreshed field context. Preserve required_scope and required_source_pairs exactly; revise questions and limitations to reflect observed field availability. Use the new application-assigned discovery_snapshot_id."
                )
            plan.coverage_limitations = list(dict.fromkeys([*plan.coverage_limitations, *discovery.coverage_limitations]))
            # Initial identities belong to the application, not the model.
            # Assign only before review; never renumber saved or approved plans.
            for number, question in enumerate(plan.questions, start=1):
                question.question_id = f"q{number}"
            snapshot = discovery_snapshot.to_dict()
            snapshot["execution_config_snapshot"] = execution_snapshot.to_dict()
            snapshot["input_context"] = context["analyst_supplied_context"]
            snapshot["mode"] = "production"
            plan_payload = self._validate_plan(plan.model_dump(mode="json"))
            self._update(owner_id, hunt_id, expected_state=HuntState.DISCOVERING.value, state=HuntState.PLAN_DRAFT.value, discovery_snapshot=snapshot, plan=plan_payload, plan_version=1, updated_at_utc=now)
            self._update(owner_id, hunt_id, expected_state=HuntState.PLAN_DRAFT.value, state=HuntState.AWAITING_PLAN_REVIEW.value, updated_at_utc=_now())
            return self.get_hunt(owner_id, hunt_id)
        except (AdapterError, ModelContractError, ValueError, Validation) as exc:
            # Keep provider details out of the API and leave the hunt explicitly failed.
            try:
                self._update(owner_id, hunt_id, expected_state=HuntState.DISCOVERING.value, state=HuntState.FAILED.value, updated_at_utc=_now())
            except Conflict:
                pass
            if isinstance(exc, AdapterError) and exc.category == FailureCategory.BUDGET_EXHAUSTED:
                raise IntegrationUnavailable(f"production discovery failed: {exc}") from exc
            raise IntegrationUnavailable("production discovery failed") from exc

    def save_plan(self, owner_id: str, hunt_id: str, *, expected_version: int, plan: Mapping[str, Any]) -> dict[str, Any]:
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] not in {HuntState.AWAITING_PLAN_REVIEW.value, HuntState.PLAN_DRAFT.value}:
            raise Conflict("plan editing is not allowed in the current state")
        if row["plan_version"] != expected_version:
            raise Conflict("plan version is stale")
        normalized = self._validate_plan(plan)
        updates: dict[str, Any] = {}
        if not self.local_demo:
            previous = HuntPlan.model_validate(row["plan"])
            try:
                revised = HuntPlan.model_validate(normalized)
                validate_intelligence_refs(revised.intelligence_refs, row["discovery_snapshot"].get("input_context", {}).get("intelligence_sources", []))
            except ValueError as exc:
                raise Validation("edited plan does not satisfy the production plan contract or supplied intelligence reference boundary") from exc
            for key in ("hunt_id", "plan_id", "discovery_snapshot_id", "execution_config_snapshot_id"):
                if getattr(revised, key) != getattr(previous, key):
                    raise Validation("plan editing cannot replace application-assigned identities")
            previous_pairs = {(source.index, kind) for source in previous.data_sources for kind in source.sourcetypes}
            revised_pairs = {(source.index, kind) for source in revised.data_sources for kind in source.sourcetypes}
            if any(index not in revised.scope.indexes or kind not in revised.scope.sourcetypes for index, kind in revised_pairs):
                raise Validation("edited plan data sources are outside its scope")
            if revised.scope != previous.scope or revised_pairs != previous_pairs:
                if self.splunk_connector is None or self.model_adapter is None:
                    raise IntegrationUnavailable("scoped discovery is not configured")
                original_snapshot = row["discovery_snapshot"]
                catalog = original_snapshot["payload"]
                if (not set(revised.scope.indexes).issubset(catalog["indexes"])
                        or not set(revised.scope.sourcetypes).issubset(catalog["sourcetypes"])):
                    raise Validation("edited plan sources are outside the discovered catalog")
                orchestrator = ProductionOrchestrator(self.splunk_connector, self.model_adapter, limits=self.budget_limits)
                try:
                    discovery, snapshot = orchestrator.discover(plan=revised)
                except AdapterError as exc:
                    raise IntegrationUnavailable("scoped discovery failed; the previous plan is unchanged") from exc
                revised.discovery_snapshot_id = snapshot.snapshot_id
                revised.coverage_limitations = list(dict.fromkeys([*revised.coverage_limitations, *discovery.coverage_limitations]))
                updates["discovery_snapshot"] = snapshot.to_dict() | {
                    key: original_snapshot[key] for key in ("execution_config_snapshot", "input_context", "mode")
                }
            revised.plan_version = expected_version + 1
            normalized = revised.model_dump(mode="json")
        self._update(owner_id, hunt_id, expected_plan_version=expected_version, state=HuntState.AWAITING_PLAN_REVIEW.value, plan=normalized, plan_version=expected_version + 1, approval=None, updated_at_utc=_now(), **updates)
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
        self._validate_plan(row["plan"])
        if not self.local_demo:
            try:
                validate_intelligence_refs(row["plan"].get("intelligence_refs", []), (row.get("discovery_snapshot") or {}).get("input_context", {}).get("intelligence_sources", []))
            except ValueError as exc:
                raise Conflict("plan intelligence reference is not bound to a supplied source; edit the plan before approval") from exc
        discovery_payload = (row.get("discovery_snapshot") or {}).get("payload", {})
        if not self.local_demo and discovery_payload.get("schema_requested_scope") is not None:
            reviewed = HuntPlan.model_validate(row["plan"])
            if (reviewed.scope.model_dump(mode="json") != discovery_payload["schema_requested_scope"]
                    or {(source.index, kind) for source in reviewed.data_sources for kind in source.sourcetypes}
                    != {tuple(pair) for pair in discovery_payload["schema_sampling_scope"]["source_pairs"]}):
                raise Conflict("plan scope does not match its discovery snapshot; save the plan to refresh discovery")
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
        self._validate_plan(row["plan"])
        if not self.local_demo:
            snapshot = row.get("discovery_snapshot") or {}
            try:
                validate_intelligence_refs(row["plan"].get("intelligence_refs", []), snapshot.get("input_context", {}).get("intelligence_sources", []))
            except ValueError as exc:
                raise Conflict("plan intelligence reference is not bound to a supplied source") from exc
            config_snapshot = snapshot.get("execution_config_snapshot") if isinstance(snapshot, Mapping) else None
            if not isinstance(config_snapshot, Mapping) or row["approval"].get("execution_config_snapshot_id") != config_snapshot.get("snapshot_id") or row["approval"].get("execution_config_sha256") != config_snapshot.get("sha256"):
                raise Conflict("approved execution configuration binding is invalid")
            self._validate_execution_snapshot(config_snapshot)
            now = _now()
            with self.engine.begin() as connection:
                self._update(owner_id, hunt_id, expected_state=HuntState.APPROVED.value, expected_plan_version=int(row["plan_version"]), state=HuntState.QUEUED.value, updated_at_utc=now, connection=connection)
                job = self.jobs.enqueue(owner_id, hunt_id, idempotency_key=f"hunt:{hunt_id}:execution", payload={"hunt_id": hunt_id, "plan_version": row["plan_version"], "plan_sha256": row["approval"]["plan_sha256"], "execution_config_snapshot_id": row["approval"].get("execution_config_snapshot_id"), "execution_config_sha256": row["approval"].get("execution_config_sha256")}, connection=connection)
            return self.get_hunt(owner_id, hunt_id) | {"job": {key: value for key, value in job.items() if key not in {"payload"}}}
        now, query_id, evidence_id, finding_id = _now(), str(uuid4()), str(uuid4()), str(uuid4())
        evidence = {"evidence_id": evidence_id, "query_id": query_id, "source": "deterministic_local_demo", "event_time_utc": _rfc3339(now - timedelta(minutes=14)), "selected_result": {"host": "demo-workstation-17", "user": "demo\\analyst", "src_ip": "192.0.2.17", "EventCode": "4624"}, "disclaimer": "Deterministic local demo evidence; not a production observation."}
        results = {"findings": [{"finding_id": finding_id, "title": "Local demo authentication lead", "classification": "hunt_lead", "statement": "The deterministic demo dataset contains one scoped authentication event for analyst review.", "confidence": "low", "evidence_ids": [evidence_id], "query_ids": [query_id], "inference": "Local demonstration only."}], "evidence": [evidence], "entities": [{"entity_id": str(uuid4()), "entity_type": "host", "value": "demo-workstation-17", "evidence_ids": [evidence_id]}, {"entity_id": str(uuid4()), "entity_type": "ip", "value": "192.0.2.17", "evidence_ids": [evidence_id]}], "timeline": [{"timestamp_utc": evidence["event_time_utc"], "summary": "Local demo authentication event", "evidence_ids": [evidence_id]}], "queries": [{"query_id": query_id, "purpose": "Answer q1", "spl": "index=security sourcetype=WinEventLog:Security EventCode=4624 | head 100", "status": "completed", "result_count": 1}], "mode": "deterministic_local_demo"}
        content = _concise_report_content(
            hypothesis=row["hypothesis"],
            objective=row["objective"],
            data_sources=["Local demo Splunk adapter"],
            results=results,
            coverage_and_limitations=["Deterministic local demo results; production integrations were not invoked."],
            conclusion_and_disposition="One low-confidence hunt lead requires analyst validation.",
        )
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
        row = self._owned_row(owner_id, hunt_id)
        if row["state"] == HuntState.CANCELLED.value:
            raise Conflict("cancelled hunts cannot accept late execution results")
        normalized_report = _validate_report_content(normalized_report, normalized_results)
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

    def _persist_policy_rejections(
        self,
        owner_id: str,
        hunt_id: str,
        rejections: Sequence[Mapping[str, Any]],
        *,
        expected_state: str,
    ) -> None:
        """Durably retain rejected proposals and deterministic reason codes."""

        if not rejections:
            return
        current = self._owned_row(owner_id, hunt_id)
        payload = dict(current["results"] or {}) if isinstance(current["results"], Mapping) else {}
        prior = payload.get("query_policy_rejections", [])
        if not isinstance(prior, list):
            prior = []
        payload["query_policy_rejections"] = [*prior, *[_json_copy(item) for item in rejections]]
        audit_rejections: list[dict[str, Any]] = []
        for rejection in rejections:
            item = {
                "query_id": rejection.get("query_id"),
                "reason_codes": list(rejection.get("reason_codes", [])),
                "query_policy_version": rejection.get("query_policy_version"),
                "proposal": rejection.get("proposal"),
            }
            try:
                bounded_audit_metadata({"rejection": item})
            except ValueError:
                # Keep the exact proposal in the durable results checkpoint,
                # while audit metadata remains bounded and non-sensitive.
                item = {
                    "query_id": rejection.get("query_id"),
                    "reason_codes": list(rejection.get("reason_codes", [])),
                    "query_policy_version": rejection.get("query_policy_version"),
                    "proposal_sha256": sha256_json(rejection.get("proposal", {})),
                }
            audit_rejections.append(item)
        reason_codes: list[str] = []
        for rejection in rejections:
            for reason in rejection.get("reason_codes", []):
                normalized_reason = str(reason)
                if normalized_reason not in reason_codes:
                    reason_codes.append(normalized_reason)
        audit_metadata: dict[str, Any] = {
            "reason_codes": reason_codes,
            "rejections": audit_rejections,
        }
        try:
            bounded_audit_metadata(audit_metadata)
        except ValueError:
            audit_metadata = {
                "reason_codes": reason_codes,
                "rejections": [
                    {
                        "query_id": rejection.get("query_id"),
                        "reason_codes": list(rejection.get("reason_codes", [])),
                        "query_policy_version": rejection.get("query_policy_version"),
                        "proposal_sha256": sha256_json(rejection.get("proposal", {})),
                    }
                    for rejection in rejections
                ],
            }
            # Reason codes and digests are intentionally retained even when
            # the raw proposal set cannot fit the audit metadata bound.
            if len(json.dumps(audit_metadata, ensure_ascii=False).encode("utf-8")) > 32_768:
                audit_metadata["rejections"] = audit_metadata["rejections"][:100]
        self._update(
            owner_id,
            hunt_id,
            expected_state=expected_state,
            results=payload,
            action="query_policy_rejected",
            audit_outcome="rejected",
            detail="deterministic SPL policy rejected proposal",
            audit_metadata=audit_metadata,
            updated_at_utc=_now(),
        )

    def _draft_execution_ledger(
        self, *, lease: Any, row: Mapping[str, Any], plan: HuntPlan, policy: SPLPolicy,
        discovery_scope: Mapping[str, Any], open_question_ids: list[str],
        counters: BudgetCounters, token: _HuntCancellationToken,
    ) -> list[dict[str, Any]]:
        """Generate initial queries and repair policy violations before publication."""
        assert self.model_adapter is not None
        runner = StrictModelRunner(
            self.model_adapter,
            counters=counters,
            limits=self.budget_limits,
            cancellation_token=token,
        )
        proposal_context = {
            "approved_plan": plan.model_dump(mode="json"),
            "discovery_scope": discovery_scope,
            "open_question_ids": open_question_ids,
            "advisory_iocs": query_ioc_context(str(row["threat_intelligence"] or "")),
            "proposal_rules": [
                "Use only approved indexes and sourcetypes from discovery_scope.",
                "Use only discovery_scope.fields in requested_fields and SPL field references; use representative_schemas to select fields for each sourcetype.",
                "Use only open_question_ids and the approved UTC range from discovery_scope.",
                "Cover independent approved questions before proposing repeated pivots. Defer only questions needing evidence from earlier searches; the application will revisit unsearched approved questions.",
                "When useful for an open question, query for the extent of activity across related hosts, users, source or destination IPs, and processes, and for activity before or after an observed lead.",
                "Cover relevant observable behaviors from the hypothesis and advisory; do not attempt every ATT&CK tactic or add arbitrary extra searches.",
                "Do not invent fields, telemetry, identifiers, facts, or scope.",
                "For IOC comparisons, use literal values from advisory_iocs; never emit placeholder IOC values.",
                "For a shared hash field, compare advisory_iocs.file_hashes directly without an additional hash-algorithm/type filter. Advisory algorithm names do not establish telemetry enum values. Use algorithm-specific hash fields only when the discovered schema supports them.",
                "Do not guess categorical filter values from field names or advisory terminology. Use analyst-supplied values or observed telemetry; when unknown, first issue a bounded aggregate or omit the unnecessary categorical predicate.",
            ],
            "remaining_budget": self.budget_limits.model_dump(mode="json"),
        }
        proposals = runner.run(
            TypeAdapter(list[QueryProposal]),
            user_payload=proposal_context,
            contract_name="QueryProposal[]",
        )
        rejected: list[dict[str, Any]] = []
        ledger: list[dict[str, Any]] = []
        for proposal in proposals:
            validation = policy.validate(proposal, open_question_ids=open_question_ids)
            if not validation.allowed:
                rejected.append({
                    "query_id": str(validation.query_id),
                    "proposal": proposal.model_dump(mode="json"),
                    "reason_codes": list(validation.reason_codes),
                    "query_policy_version": validation.query_policy_version,
                })
        if rejected:
            self._persist_policy_rejections(
                row["owner_id"], lease.hunt_id, rejected,
                expected_state=HuntState.QUEUED.value,
            )
            repair_context: dict[str, Any] = {
                "approved_plan": plan.model_dump(mode="json"),
                "discovery_scope": discovery_scope,
                "open_question_ids": open_question_ids,
                "policy_reason_codes": sorted({
                    code for item in rejected for code in item["reason_codes"]
                }),
                "rejected_proposals": rejected,
                "remaining_budget": self.budget_limits.model_dump(mode="json"),
            }
            repair_instruction = (
                "The previous QueryProposal[] violated deterministic SPL policy. "
                "Return one complete replacement QueryProposal[] and make exactly the "
                "following policy repairs. Preserve the approved plan and discovery "
                "scope exactly: use only its open question IDs, approved/discovered "
                "indexes and sourcetypes, discovered fields, and approved time range. "
                "Use only policy-allowed SPL commands, positive exact index and "
                "sourcetype predicates, and no inline earliest/latest predicates. "
                "Do not add facts, telemetry, identifiers, or scope. Address every "
                f"reason code listed in the rejection records: {', '.join(sorted({code for item in rejected for code in item['reason_codes']}))}. "
                "Return exactly {\"QueryProposal\": [...]} as JSON."
            )
            try:
                proposals = runner.repair_once(
                    TypeAdapter(list[QueryProposal]),
                    user_payload=repair_context,
                    previous_output=[item["proposal"] for item in rejected],
                    repair_instruction=repair_instruction,
                    contract_name="QueryProposal[]",
                )
            except ModelContractError:
                raise
            repaired_rejections: list[dict[str, Any]] = []
            for proposal in proposals:
                validation = policy.validate(proposal, open_question_ids=open_question_ids)
                if not validation.allowed:
                    repaired_rejections.append({
                        "query_id": str(validation.query_id),
                        "proposal": proposal.model_dump(mode="json"),
                        "reason_codes": list(validation.reason_codes),
                        "query_policy_version": validation.query_policy_version,
                    })
            if repaired_rejections:
                self._persist_policy_rejections(
                    row["owner_id"], lease.hunt_id, repaired_rejections,
                    expected_state=HuntState.QUEUED.value,
                )
                reason_codes = sorted({
                    code for item in repaired_rejections for code in item["reason_codes"]
                })
                raise AdapterError(
                    FailureCategory.QUERY_POLICY_REJECTED,
                    "SPL query rejected by deterministic policy: " + ", ".join(reason_codes),
                    operation="splunk.validate_query",
                )
        for proposal in proposals:
            validation = policy.validate(proposal, open_question_ids=open_question_ids)
            if not validation.allowed:
                # Defensive invariant: all rejected proposals must have
                # been handled above before they can reach the ledger.
                raise AdapterError(
                    FailureCategory.QUERY_POLICY_REJECTED,
                    "SPL query rejected by deterministic policy",
                    operation="splunk.validate_query",
                )
            ledger.append(
                {
                    "query_id": str(validation.query_id),
                    "proposal": proposal.model_dump(mode="json"),
                    "status": "planned",
                }
            )
        return ledger

    def _run_checkpoint_queries(
        self, *, lease: Any, executor: ProductionHuntExecutor,
        counters: BudgetCounters, require_lease: Callable[[], None],
        query_start_deadline: datetime | None = None,
    ) -> None:
        """Resume submitted searches and checkpoint each completed result exactly once."""
        checkpoint = self._owned_row(lease.owner_id, lease.hunt_id)
        checkpoint_results = dict(checkpoint["results"] or {}) if isinstance(checkpoint["results"], Mapping) else {}
        checkpoint_ledger = list(checkpoint_results.get("query_ledger", []))
        for position in range(len(checkpoint_ledger)):
            current = self._owned_row(lease.owner_id, lease.hunt_id)
            payload = dict(current["results"] or {}) if isinstance(current["results"], Mapping) else {}
            current_ledger = list(payload.get("query_ledger", []))
            if position >= len(current_ledger):
                raise Conflict("query checkpoint changed during recovery")
            entry = current_ledger[position]
            status = str(entry.get("status", ""))
            if status in {"completed", "skipped_time_cutoff", "skipped_budget", "timed_out"}:
                continue
            if status not in {"planned", "submitted"} or not isinstance(entry.get("proposal"), Mapping):
                raise Conflict("query checkpoint is not recoverable")
            proposal = QueryProposal.model_validate(entry["proposal"])
            query_id = UUID(str(entry.get("query_id")))
            existing_sid = entry.get("splunk_job_id") if status == "submitted" else None
            if existing_sid is not None and not isinstance(existing_sid, str):
                raise Conflict("recorded Splunk job ID is malformed")
            stop_status = None
            if status == "planned" and query_start_deadline is not None and _now() >= query_start_deadline:
                stop_status = "skipped_time_cutoff"
            else:
                submitted_at = None
                if existing_sid is not None:
                    try:
                        submitted_at = datetime.fromisoformat(str(entry["submitted_at_utc"]).replace("Z", "+00:00"))
                        if submitted_at.tzinfo is None or submitted_at.utcoffset() is None:
                            raise ValueError("naive query submission time")
                    except (KeyError, ValueError) as exc:
                        raise Conflict("recorded query submission time is malformed") from exc
                try:
                    execution = executor.execute_query(
                        proposal, query_id=query_id, existing_job_id=existing_sid,
                        submitted_at_utc=submitted_at,
                    )
                except AdapterError as exc:
                    if exc.category not in {FailureCategory.HARD_TIMEOUT, FailureCategory.BUDGET_EXHAUSTED}:
                        raise
                    stop_status = "timed_out" if exc.category is FailureCategory.HARD_TIMEOUT else "skipped_budget"
            if stop_status is not None:
                require_lease()
                current = self._owned_row(lease.owner_id, lease.hunt_id)
                payload = dict(current["results"] or {})
                for item in payload["query_ledger"]:
                    if str(item.get("query_id")) == str(query_id):
                        item.update(status=stop_status, completed_at_utc=_rfc3339(_now()))
                payload["usage"] = counters.model_dump(mode="json")
                self._update(
                    lease.owner_id, lease.hunt_id, expected_state=HuntState.RUNNING.value,
                    results=payload, updated_at_utc=_now(),
                )
                continue
            evidence = executor.evidence_for_query(
                execution, hunt_id=UUID(lease.hunt_id), proposal=proposal
            )
            evidence_values = [item.model_dump(mode="json") for item in evidence]
            query_record = {
                "query_id": str(execution.query_id),
                "question_id": proposal.question_id,
                "splunk_job_id": execution.splunk_job_id,
                "purpose": proposal.purpose,
                "spl": execution.normalized_spl,
                "earliest_utc": _rfc3339(proposal.earliest_utc),
                "latest_utc": _rfc3339(proposal.latest_utc),
                "status": "completed",
                "result_count": len(execution.rows),
                "result_bytes": execution.result_bytes,
                "truncated": execution.truncated,
                "available_result_count": execution.available_result_count,
                "retrieval_stop_reason": execution.retrieval_stop_reason,
                "result_pages": execution.result_pages,
                "result_mode": proposal.result_mode.value,
            }
            require_lease()
            current = self._owned_row(lease.owner_id, lease.hunt_id)
            payload = dict(current["results"] or {}) if isinstance(current["results"], Mapping) else {}
            current_ledger = list(payload.get("query_ledger", []))
            matched = False
            for item in current_ledger:
                if str(item.get("query_id")) == str(query_id):
                    item.update(
                        {
                            "splunk_job_id": execution.splunk_job_id,
                            "status": "completed",
                            "completed_at_utc": _rfc3339(_now()),
                            "result_count": len(execution.rows),
                            "result_bytes": execution.result_bytes,
                            "truncated": execution.truncated,
                            "available_result_count": execution.available_result_count,
                            "retrieval_stop_reason": execution.retrieval_stop_reason,
                            "result_pages": execution.result_pages,
                        }
                    )
                    matched = True
                    break
            if not matched:
                raise Conflict("completed query is missing from the checkpoint")
            queries = [
                item for item in list(payload.get("queries", []))
                if str(item.get("query_id")) != str(query_id)
            ]
            queries.append(query_record)
            retained_evidence = [
                item for item in list(payload.get("evidence", []))
                if str(item.get("query_id")) != str(query_id)
            ]
            retained_evidence.extend(evidence_values)
            payload.update(
                {
                    "query_ledger": current_ledger,
                    "queries": queries,
                    "evidence": retained_evidence,
                    "usage": counters.model_dump(mode="json"),
                }
            )
            self._update(
                lease.owner_id,
                lease.hunt_id,
                expected_state=HuntState.RUNNING.value,
                results=payload,
                updated_at_utc=_now(),
            )


    def _assess_execution_round(
        self, *, lease: Any, plan: HuntPlan, policy: SPLPolicy,
        discovery_scope: Mapping[str, Any], counters: BudgetCounters,
        token: _HuntCancellationToken, deadline: datetime, require_lease: Callable[[], None],
    ) -> bool:
        """Assess new results and checkpoint bounded, grounded follow-up decisions."""
        open_question_ids = [question.question_id for question in plan.questions]
        assert self.model_adapter is not None
        require_lease()
        current = self._owned_row(lease.owner_id, lease.hunt_id)
        adaptive_results = (
            dict(current["results"] or {})
            if isinstance(current["results"], Mapping)
            else {}
        )
        if not adaptive_results.get("adaptive_complete"):
            # Source starvation is a result-selection problem. Narrow the
            # existing search deterministically before asking the model to
            # assess it; keep the original predicates, pipeline and bounds.
            source_coverage = query_source_coverage(adaptive_results)
            available_queries = self.budget_limits.max_splunk_queries - counters.splunk_queries
            if (available_queries > 0 and counters.model_calls + 1 < self.budget_limits.max_model_calls
                    and counters.agent_cycles < self.budget_limits.max_agent_cycles):
                ledger = list(adaptive_results.get("query_ledger", []))
                by_query = {str(item.get("query_id")): item for item in ledger}
                coverage_ledger: list[dict[str, Any]] = []
                for coverage in source_coverage:
                    for source in coverage["sources"]:
                        if (not source["needs_source_check"] or source["coverage_query_id"] is not None
                                or coverage["query_id"] not in by_query or len(coverage_ledger) >= available_queries):
                            continue
                        original = QueryProposal.model_validate(by_query[coverage["query_id"]]["proposal"])
                        parsed = parse_spl(original.spl)
                        pair = [source["index"], source["sourcetype"]]
                        constrained = (
                            f'search ({parsed.command_segments[0][1]}) AND index="{pair[0]}" AND sourcetype="{pair[1]}"'
                            + "".join(f" | {command} {args}".rstrip() for command, args in parsed.command_segments[1:])
                        )
                        proposal = original.model_copy(update={
                            "spl": constrained,
                            "purpose": f"Check {pair[0]} ({pair[1]}) omitted from truncated query {coverage['query_id']}",
                        })
                        validation = policy.validate(proposal)
                        if not validation.allowed:
                            raise AdapterError(FailureCategory.QUERY_POLICY_REJECTED,
                                               "Source coverage search rejected: " + ", ".join(validation.reason_codes),
                                               operation="splunk.validate_query")
                        coverage_ledger.append({
                            "query_id": str(validation.query_id), "proposal": proposal.model_dump(mode="json"),
                            "status": "planned", "phase": "source_coverage",
                            "source_query_id": coverage["query_id"], "source_pair": pair,
                            "decision_source": "application_source_coverage",
                        })
                if coverage_ledger:
                    adaptive_results.update({
                        "query_ledger": [*ledger, *coverage_ledger], "usage": counters.model_dump(mode="json"),
                        "adaptive_status": "source_coverage_planned", "adaptive_complete": False,
                    })
                    require_lease()
                    self._update(lease.owner_id, lease.hunt_id, expected_state=HuntState.RUNNING.value,
                                 results=adaptive_results, updated_at_utc=_now())
                    return True
            completed_queries = [
                item
                for item in adaptive_results.get("queries", [])
                if isinstance(item, Mapping) and item.get("status") == "completed"
            ]
            assessed_query_ids = {
                str(value) for value in adaptive_results.get("assessed_query_ids", [])
            }
            pending_query_ids = {
                str(item.get("query_id"))
                for item in completed_queries
                if item.get("query_id")
                and str(item.get("query_id")) not in assessed_query_ids
            }
            outstanding_questions = _pending_investigation_questions(plan, adaptive_results)
            follow_up_questions: list[dict[str, Any]] = []
            assessments_payload: list[dict[str, Any]] = []
            adaptive_status = "no_unassessed_queries"
            can_run_adaptive_round = (
                bool(pending_query_ids or outstanding_questions)
                and counters.agent_cycles < self.budget_limits.max_agent_cycles
                and counters.model_calls + (2 if pending_query_ids else 1) < self.budget_limits.max_model_calls
                and counters.splunk_queries < self.budget_limits.max_splunk_queries
            )
            if can_run_adaptive_round:
                counters.record_cycle()
                adaptive_runner = StrictModelRunner(
                    self.model_adapter,
                    counters=counters,
                    # Assessment, follow-ups, and their repairs share this
                    # allowance; reserve a final call and half the remaining
                    # tokens for evidence-grounded synthesis.
                    limits=self.budget_limits.model_copy(update={
                        "max_model_calls": self.budget_limits.max_model_calls - 1,
                        "max_model_input_tokens": counters.model_input_tokens + (
                            self.budget_limits.max_model_input_tokens - counters.model_input_tokens) // 2,
                        "max_model_output_tokens": counters.model_output_tokens + (
                            self.budget_limits.max_model_output_tokens - counters.model_output_tokens) // 2,
                    }),
                    deadline=deadline,
                    cancellation_token=token,
                )
                assessment_context = _assessment_context(
                    plan, adaptive_results, query_ids=pending_query_ids,
                    threat_intelligence=str(current["threat_intelligence"] or ""),
                    limit=self.budget_limits.max_representative_events,
                )
                assessment_context["discovery_scope"] = discovery_scope
                assessment_context["usage"] = counters.model_dump(mode="json")
                assessment_context["budget_limits"] = self.budget_limits.model_dump(mode="json")
                # Validation and repair must use the same evidence snapshot the model saw.
                assessment_results = {
                    **adaptive_results,
                    "evidence": [
                        evidence
                        for group in assessment_context["completed_queries"]
                        for evidence in group["retained_evidence"]
                    ],
                }
                assessments = adaptive_runner.run(
                    TypeAdapter(list[QueryAssessment]),
                    user_payload=assessment_context,
                    contract_name="QueryAssessment[]",
                ) if pending_query_ids else []
                try:
                    assessments_payload, follow_up_questions = _materialize_follow_up_questions(
                        assessments, assessment_results, query_ids=pending_query_ids
                    )
                except Validation as exc:
                    counters.model_output_checks[-1].grounding_valid = False
                    rejection = {
                        "reason": str(exc),
                        "assessments": [item.model_dump(mode="json") for item in assessments],
                        "repair_outcome": "pending",
                    }
                    adaptive_results.setdefault("assessment_validation_rejections", []).append(rejection)
                    self._update(
                        lease.owner_id, lease.hunt_id,
                        expected_state=HuntState.RUNNING.value,
                        results=adaptive_results, updated_at_utc=_now(),
                    )
                    try:
                        repair_context = _assessment_repair_context(
                            assessment_context, assessments, assessment_results,
                        )
                        repair_query_ids = {str(value) for value in repair_context["validation_errors"]}
                        rejection["repair_query_ids"] = sorted(repair_query_ids)
                        repaired = adaptive_runner.repair_once(
                            TypeAdapter(list[QueryAssessment]),
                            user_payload=repair_context,
                            previous_output=[
                                item.model_dump(mode="json") for item in assessments
                                if str(item.query_id) in repair_query_ids
                            ],
                            repair_instruction=(
                                "Correct only the failed assessments in completed_queries, using "
                                "their validation_errors. Return one assessment per supplied query; "
                                "do not return or revise other assessments. Preserve each exact "
                                "query_id; the application derives question_id. Each citation must be copied from that "
                                "query's allowed_evidence_ids. Each entity value must equal a complete scalar "
                                "value in this query's supplied rows; the application derives entity result_row_refs. "
                                "Do not return entity result_row_refs or add facts. "
                                "Return exactly {\"QueryAssessment\": [...]} as JSON."
                            ),
                            contract_name="QueryAssessment[]",
                        )
                        rejection["repaired_assessments"] = [item.model_dump(mode="json") for item in repaired]
                        _materialize_follow_up_questions(
                            repaired, assessment_results, query_ids=repair_query_ids,
                        )
                        corrected_by_query = {str(item.query_id): item for item in repaired}
                        corrected_by_query.update({
                            str(item.query_id): item for item in assessments
                            if str(item.query_id) not in repair_query_ids
                        })
                        assessments = [
                            corrected_by_query[str(group["query_id"])]
                            for group in assessment_context["completed_queries"]
                        ]
                        assessments_payload, follow_up_questions = _materialize_follow_up_questions(
                            assessments, assessment_results, query_ids=pending_query_ids
                        )
                        rejection["repair_outcome"] = "accepted"
                    except (Validation, ModelContractError) as repair_error:
                        counters.model_output_checks[-1].grounding_valid = False
                        rejection["repair_outcome"] = "rejected"
                        rejection["repair_reason"] = str(repair_error)
                        raise
                    finally:
                        self._update(
                            lease.owner_id, lease.hunt_id,
                            expected_state=HuntState.RUNNING.value,
                            results=adaptive_results, updated_at_utc=_now(),
                        )
                if pending_query_ids:
                    counters.model_output_checks[-1].grounding_valid = True
                assessed_query_ids.update(pending_query_ids)
                remaining_queries = (
                    self.budget_limits.max_splunk_queries - counters.splunk_queries
                )
                questions_for_decision = _pending_investigation_questions(
                    plan, adaptive_results, follow_up_questions,
                )[:remaining_queries]
                adaptive_results["latest_assessment_round"] = {
                    "query_assessments": assessments_payload,
                    "follow_up_questions": follow_up_questions,
                }
                self._update(
                    lease.owner_id, lease.hunt_id,
                    expected_state=HuntState.RUNNING.value,
                    results=adaptive_results, updated_at_utc=_now(),
                )
                adaptive_status = "assessed"
                if questions_for_decision:
                    follow_up_ids = [item["question_id"] for item in questions_for_decision]
                    preferred_ids = {
                        str(ref) for question in questions_for_decision
                        for ref in question.get("source_evidence_ids", [])
                    }
                    pivot_evidence, _ = _balanced_evidence_sample(
                        adaptive_results.get("evidence", []), completed_queries,
                        preferred_evidence_ids=preferred_ids,
                        limit=self.budget_limits.max_targeted_events,
                    )
                    follow_up_context: dict[str, Any] = {
                        "approved_plan": plan.model_dump(mode="json"),
                        "discovery_scope": discovery_scope,
                        "follow_up_questions": questions_for_decision,
                        "query_assessments": assessments_payload,
                        "completed_queries": [
                            {key: query[key] for key in ("query_id", "question_id", "purpose", "spl", "earliest_utc", "latest_utc", "result_count", "truncated") if key in query}
                            for query in completed_queries
                        ],
                        "source_coverage": query_source_coverage(adaptive_results, supplied_evidence=pivot_evidence),
                        "retained_evidence": [dict(item) for item in pivot_evidence],
                        "advisory_iocs": query_ioc_context(str(current["threat_intelligence"] or "")),
                        "proposal_rules": [
                            "Use only follow_up_questions question IDs and the approved discovery scope.",
                            "Questions marked approved_question are unsearched parts of the approved plan and take priority. Query them using discovered telemetry, advisory_iocs, and available evidence; they do not require a source_evidence_ids pivot.",
                            "Use only discovered indexes, sourcetypes, fields, representative schemas, and the approved UTC range.",
                            "Match advisory_iocs.file_hashes directly in a shared hash field without an additional algorithm/type predicate. Ground other categorical filters in supplied context or retained telemetry; discover unknown values with a bounded aggregate instead of guessing.",
                            "Use relevant literal entities from grounded_entities OR the matching question's source_evidence_ids in retained_evidence. Inspect those rows (including JSON _raw) for hosts, users, or IPs suited to the target source; you are not limited to the assessment's extracted entity types.",
                            "Use a follow-up to examine related hosts, users, source or destination IPs, processes, or activity before or after the observed lead when that is the useful unanswered pivot.",
                            "Cover the relevant behavior and scope question only; do not attempt every ATT&CK tactic or add arbitrary extra searches.",
                            "Do not repeat a completed query or invent fields, values, telemetry, identifiers, or scope.",
                            "Return exactly one FollowUpDecision for every follow-up question: proposal with skip_reason=null, or proposal=null with a specific skip_reason explaining the telemetry, scope, duplicate-query, or evidence limitation. Never silently omit a question or return an empty list.",
                            "A skipped question may return after additional queries complete. Reassess it against the current evidence; a previous dependency deferral does not mean the question was answered or permanently removed.",
                            "Prefer a useful bounded query when the supplied evidence and discovered schema support it. An incomplete entity list alone is not a reason to skip: inspect the cited rows for the needed pivot.",
                        ],
                        "remaining_budget": {
                            "splunk_queries": remaining_queries,
                            "model_calls": self.budget_limits.max_model_calls - counters.model_calls,
                            "agent_cycles": self.budget_limits.max_agent_cycles - counters.agent_cycles,
                        },
                    }
                    decision_contract = _follow_up_decision_contract(follow_up_ids)
                    decisions = adaptive_runner.run(
                        decision_contract,
                        user_payload=follow_up_context,
                        contract_name="FollowUpDecision[]",
                    )
                    by_question = {decision.question_id: decision for decision in decisions}
                    decisions = [by_question[identifier] for identifier in follow_up_ids]
                    follow_up_proposals = [d.proposal for d in decisions if d.proposal is not None]
                    proposal_errors = _follow_up_proposal_errors(
                        follow_up_proposals, questions_for_decision,
                        evidence=follow_up_context["retained_evidence"],
                    )
                    rejected: list[dict[str, Any]] = [
                        {"proposal": proposal.model_dump(mode="json"), "reason_codes": [proposal_errors[proposal.question_id]]}
                        for proposal in follow_up_proposals if proposal.question_id in proposal_errors
                    ]
                    allowed_question_ids = [*open_question_ids, *follow_up_ids]
                    for proposal in follow_up_proposals:
                        validation = policy.validate(
                            proposal, open_question_ids=allowed_question_ids
                        )
                        if not validation.allowed:
                            rejected.append({
                                "query_id": str(validation.query_id),
                                "proposal": proposal.model_dump(mode="json"),
                                "reason_codes": list(validation.reason_codes),
                                "query_policy_version": validation.query_policy_version,
                            })
                    if rejected:
                        self._persist_policy_rejections(
                            lease.owner_id,
                            lease.hunt_id,
                            rejected,
                            expected_state=HuntState.RUNNING.value,
                        )
                        rejected_ids = {item["proposal"]["question_id"] for item in rejected}
                        accepted_decisions = [decision for decision in decisions if decision.question_id not in rejected_ids]
                        repair_ids = [identifier for identifier in follow_up_ids if identifier in rejected_ids]
                        repaired_decisions = adaptive_runner.repair_once(
                            _follow_up_decision_contract(repair_ids),
                            user_payload={
                                **follow_up_context,
                                "follow_up_questions": [item for item in questions_for_decision if item["question_id"] in rejected_ids],
                                "accepted_proposals": [decision.proposal.model_dump(mode="json") for decision in accepted_decisions if decision.proposal is not None],
                                "policy_reason_codes": sorted({
                                    code for item in rejected for code in item["reason_codes"]
                                }),
                                "rejected_proposals": rejected,
                            },
                            previous_output=[d.model_dump(mode="json") for d in decisions if d.question_id in rejected_ids],
                            repair_instruction=(
                                "Correct only the rejected follow-up decisions. The application preserves accepted_proposals; "
                                "do not return, change, or duplicate them. They are planned, not completed searches. "
                                "Address each proposal's own reason codes using its question ID, evidence-grounded values, "
                                "approved scope, and policy-allowed read-only SPL. A duplicate rejection applies only to "
                                "that proposal, not to all queries for the question. Return exactly "
                                "{\"FollowUpDecision\": [...]} as JSON, one decision for each supplied follow_up_question, "
                                "with either a valid proposal or a specific skip_reason."
                            ),
                            contract_name="FollowUpDecision[]",
                        )
                        merged_decisions = {d.question_id: d for d in [*accepted_decisions, *repaired_decisions]}
                        decisions = [merged_decisions[identifier] for identifier in follow_up_ids]
                        follow_up_proposals = [d.proposal for d in decisions if d.proposal is not None]
                        proposal_errors = _follow_up_proposal_errors(
                            follow_up_proposals, questions_for_decision,
                            evidence=follow_up_context["retained_evidence"],
                        )
                        if proposal_errors:
                            self._persist_policy_rejections(
                                lease.owner_id, lease.hunt_id,
                                [{"proposal": proposal.model_dump(mode="json"), "reason_codes": [proposal_errors[proposal.question_id]]}
                                 for proposal in follow_up_proposals if proposal.question_id in proposal_errors],
                                expected_state=HuntState.RUNNING.value,
                            )
                            raise Validation("; ".join(sorted(set(proposal_errors.values()))))
                    # Exact duplicate execution is an application decision.
                    # The policy cache identity includes normalized SPL, UTC
                    # bounds and result limits; changed windows/caps are new work.
                    seen_queries: dict[tuple[str, str], str] = {}
                    completed_ids = {str(query["query_id"]) for query in completed_queries}
                    for entry in adaptive_results.get("query_ledger", []):
                        if str(entry.get("query_id")) not in completed_ids or not isinstance(entry.get("proposal"), Mapping):
                            continue
                        prior = QueryProposal.model_validate(entry["proposal"])
                        prior_validation = policy.validate(prior)
                        if prior_validation.allowed and prior_validation.cache_key:
                            seen_queries[(prior_validation.cache_key, prior.result_mode.value)] = f"completed query {entry['query_id']}"
                    duplicate_skips: dict[str, str] = {}
                    follow_up_ledger: list[dict[str, Any]] = []
                    final_rejections: list[dict[str, Any]] = []
                    for proposal in follow_up_proposals:
                        validation = policy.validate(
                            proposal, open_question_ids=allowed_question_ids
                        )
                        if not validation.allowed:
                            final_rejections.append({
                                "query_id": str(validation.query_id),
                                "proposal": proposal.model_dump(mode="json"),
                                "reason_codes": list(validation.reason_codes),
                                "query_policy_version": validation.query_policy_version,
                            })
                            continue
                        assert validation.cache_key is not None
                        identity = (validation.cache_key, proposal.result_mode.value)
                        if identity in seen_queries:
                            duplicate_skips[proposal.question_id] = (
                                f"Application skipped an identical search already covered by {seen_queries[identity]}; "
                                "SPL, time bounds, result mode and limits are unchanged. This question was not separately searched."
                            )
                            continue
                        seen_queries[identity] = f"planned question {proposal.question_id}"
                        follow_up_ledger.append({
                            "query_id": str(validation.query_id),
                            "proposal": proposal.model_dump(mode="json"),
                            "status": "planned",
                            "phase": "adaptive_follow_up",
                        })
                    if final_rejections:
                        self._persist_policy_rejections(
                            lease.owner_id,
                            lease.hunt_id,
                            final_rejections,
                            expected_state=HuntState.RUNNING.value,
                        )
                        reason_codes = sorted({
                            code for item in final_rejections for code in item["reason_codes"]
                        })
                        raise AdapterError(
                            FailureCategory.QUERY_POLICY_REJECTED,
                            "SPL follow-up query rejected by deterministic policy: "
                            + ", ".join(reason_codes),
                            operation="splunk.validate_query",
                        )
                    current = self._owned_row(lease.owner_id, lease.hunt_id)
                    adaptive_results = (
                        dict(current["results"] or {})
                        if isinstance(current["results"], Mapping)
                        else {}
                    )
                    adaptive_results["query_ledger"] = [
                        *list(adaptive_results.get("query_ledger", [])),
                        *follow_up_ledger,
                    ]
                    adaptive_results.setdefault("follow_up_decisions", []).extend(
                        ({"question_id": d.question_id, "proposal": None, "skip_reason": duplicate_skips[d.question_id],
                          "decision_source": "application_duplicate_suppression"}
                         if d.question_id in duplicate_skips else {
                             **d.model_dump(mode="json"),
                             "considered_query_ids": sorted(str(query["query_id"]) for query in completed_queries),
                         })
                        for d in decisions
                    )
                    adaptive_status = (
                        "follow_up_planned" if follow_up_ledger else "no_follow_up_query"
                    )
            elif pending_query_ids or outstanding_questions:
                adaptive_status = "budget_reserved_for_synthesis"
            existing_assessments = list(adaptive_results.get("query_assessments", []))
            existing_questions = list(adaptive_results.get("follow_up_questions", []))
            adaptive_results.update({
                "query_assessments": [*existing_assessments, *assessments_payload],
                "follow_up_questions": [*existing_questions, *follow_up_questions],
                "assessed_query_ids": sorted(assessed_query_ids),
                "usage": counters.model_dump(mode="json"),
            })
            adaptive_results["pending_question_ids"] = [
                item["question_id"] for item in _pending_investigation_questions(plan, adaptive_results)
            ]
            if adaptive_status == "no_follow_up_query" and adaptive_results["pending_question_ids"]:
                adaptive_status = "questions_pending"
            continue_investigation = adaptive_status in {"follow_up_planned", "questions_pending"}
            adaptive_results["adaptive_complete"] = not continue_investigation
            adaptive_results["adaptive_status"] = adaptive_status
            self._update(
                lease.owner_id,
                lease.hunt_id,
                expected_state=HuntState.RUNNING.value,
                results=adaptive_results,
                updated_at_utc=_now(),
            )
            if continue_investigation:
                # Re-enter through the durable checkpoint for planned searches
                # or questions deferred beyond an explicitly skipped batch.
                return True

        return False

    def execute_job(self, lease: Any) -> None:
        """Run or resume one fenced production job from its durable checkpoint."""

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
        state = str(row["state"])
        if state in {HuntState.CANCELLED.value, HuntState.REPORT_DRAFT.value}:
            return
        if state not in {HuntState.QUEUED.value, HuntState.RUNNING.value, HuntState.SYNTHESIZING.value}:
            raise Conflict("execution job is not recoverable")
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
        plan = HuntPlan.model_validate(self._validate_plan(row["plan"]))
        if str(plan.execution_config_snapshot_id) != str(config_snapshot.get("snapshot_id")):
            raise Conflict("plan execution configuration binding is invalid")
        token = _HuntCancellationToken(self, lease)

        def require_lease() -> None:
            self.jobs.require_lease(
                lease.job_id,
                lease.worker_id,
                generation=getattr(lease, "generation", None),
                deployment_scope_id=getattr(lease, "deployment_scope_id", None),
            )

        counters = BudgetCounters()
        try:
            if state == HuntState.SYNTHESIZING.value:
                results = dict(row["results"] or {}) if isinstance(row["results"], Mapping) else {}
                require_lease()
                self._update(
                    row["owner_id"],
                    lease.hunt_id,
                    expected_state=HuntState.SYNTHESIZING.value,
                    state=HuntState.REPORT_DRAFT.value,
                    report_id=str(uuid4()),
                    report_version=1,
                    report_state=HuntState.REPORT_DRAFT.value,
                    report_content=_execution_report_content(row, plan, results),
                    updated_at_utc=_now(),
                )
                return

            discovery = snapshot.get("payload", snapshot) if isinstance(snapshot, Mapping) else {}
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
            open_question_ids = [question.question_id for question in plan.questions]
            discovery_scope = {
                "indexes": sorted(policy.discovered_indexes),
                "sourcetypes": sorted(policy.discovered_sourcetypes),
                "fields": sorted(policy.discovered_fields),
                "representative_schemas": _json_copy(
                    discovery.get("representative_schemas", {})
                    if isinstance(discovery.get("representative_schemas", {}), Mapping)
                    else {}
                ),
                "approved_indexes": sorted(policy.approved_indexes),
                "approved_sourcetypes": sorted(policy.approved_sourcetypes),
                "earliest_utc": _rfc3339(policy.approved_earliest_utc),
                "latest_utc": _rfc3339(policy.approved_latest_utc),
                "query_execution_rules": [
                    "For general endpoint chronology, retain relevant process lifecycle and module events; do not restrict the search to process_start OR image_load when that would omit process_end or other observed relevant actions. Preserve explicitly targeted action-specific searches.",
                    "stats BY nullable fields can discard events missing any grouping value. Authentication logoffs may lack logon_type or authentication_method. For complete authentication chronology, prefer bounded raw records unless the supported query explicitly preserves missing groups; do not confuse missing fields with absent events.",
                    "Allowed pipeline commands are search, where, fields, table, stats, timechart, sort, head, dedup, rename, eval, regex. No other commands are supported.",
                    "Allowed eval/where functions: " + ", ".join(sorted(ALLOWED_EVAL_FUNCTIONS)) + ". Function arguments must reference discovered inputs or fields defined earlier in the pipeline. Do not use lookup, searchmatch, customer functions or dynamic eval field names.",
                    "Allowed aggregate functions: " + ", ".join(sorted(ALLOWED_STATS_FUNCTIONS)) + "; percentile functions pN, percN, exactpercN and upperpercN for integer N from 0 through 100 are also allowed. Use eval(...) inside an aggregate when needed and give calculated results explicit aliases.",
                    "Set time bounds only in earliest_utc/latest_utc proposal fields within the approved range; do not put earliest/latest in SPL.",
                    "Use a simple read-only pipeline with exact positive index and sourcetype predicates. Subsearches, macros, joins, and placeholder variables are unsupported.",
                    "Correlate sources through separate queries using literal entities observed in completed searches; defer dependent questions until those results exist.",
                    "requested_fields lists discovered input fields, not generated stats/eval output aliases. Keep requested fields from discovery_scope.fields even when the SPL produces aggregates.",
                    "Every query must explicitly constrain BOTH indexes and sourcetypes; list exactly those values in proposal metadata. For multiple sources use OR predicates, never append/subsearches or index/sourcetype IN predicates.",
                    "SPL search evaluates OR before AND. Parenthesize each compound source alternative: ((index=one sourcetype=first) OR (index=two sourcetype=second)). Every alternative must constrain both source fields, and the source conditions must be satisfiable. Use only real approved values in place of this illustrative syntax.",
                    "For an unsearched approved question about activity, scope, or spread, survey the approved time range with bounded aggregates or representative results before narrowing to a lead. A lead's observed timestamps are not the boundaries of related activity. Narrow pivots must consider useful activity before and after the lead, stay within approval, and explain their time choice in purpose. Empty results establish only what that exact search and window returned, not absence throughout the approved range.",
                ],
                "approved_scope_predicate_example": "(" + " OR ".join(
                    f'index="{value}"' for value in sorted(policy.approved_indexes)
                ) + ") AND (" + " OR ".join(
                    f'sourcetype="{value}"' for value in sorted(policy.approved_sourcetypes)
                ) + ")",
            }
            if state == HuntState.QUEUED.value:
                ledger = self._draft_execution_ledger(
                    lease=lease, row=row, plan=plan, policy=policy, discovery_scope=discovery_scope,
                    open_question_ids=open_question_ids, counters=counters, token=token,
                )
                started = _now()
                progress: dict[str, Any] = {
                    "findings": [],
                    "evidence": [],
                    "entities": [],
                    "timeline": [],
                    "queries": [],
                    "query_ledger": ledger,
                    "usage": counters.model_dump(mode="json"),
                    "mode": "production",
                    "execution_started_at_utc": _rfc3339(started),
                }
                checkpoint = self._owned_row(row["owner_id"], lease.hunt_id)
                if isinstance(checkpoint["results"], Mapping) and isinstance(checkpoint["results"].get("query_policy_rejections"), list):
                    progress["query_policy_rejections"] = _json_copy(checkpoint["results"]["query_policy_rejections"])
                require_lease()
                self._update(
                    row["owner_id"],
                    lease.hunt_id,
                    expected_state=HuntState.QUEUED.value,
                    state=HuntState.RUNNING.value,
                    results=progress,
                    updated_at_utc=started,
                )
            else:
                progress = dict(row["results"] or {}) if isinstance(row["results"], Mapping) else {}
                if "query_ledger" not in progress or "execution_started_at_utc" not in progress:
                    raise Conflict("running execution is missing a recoverable query checkpoint")
                ledger_value = progress.get("query_ledger")
                if not isinstance(ledger_value, list):
                    raise Conflict("running execution query checkpoint is malformed")
                counters = BudgetCounters.model_validate(progress.get("usage", {}))
                try:
                    started = datetime.fromisoformat(
                        str(progress["execution_started_at_utc"]).replace("Z", "+00:00")
                    )
                except ValueError as exc:
                    raise Conflict("running execution start time is malformed") from exc
                if started.tzinfo is None or started.utcoffset() is None:
                    raise Conflict("running execution start time is malformed")

            deadline = started.astimezone(timezone.utc) + timedelta(
                seconds=self.budget_limits.hard_hunt_seconds
            )
            query_start_deadline = started.astimezone(timezone.utc) + timedelta(
                seconds=self.budget_limits.query_start_cutoff_seconds
            )
            investigation_deadline = min(
                query_start_deadline + timedelta(seconds=self.budget_limits.max_inflight_query_seconds_after_cutoff),
                deadline - timedelta(seconds=self.budget_limits.synthesis_allowance_seconds),
            )

            def on_submitted(query_id: UUID, sid: str, proposal: QueryProposal) -> None:
                if token.is_cancelled():
                    raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="splunk.submit")
                require_lease()
                current = self._owned_row(row["owner_id"], lease.hunt_id)
                payload = dict(current["results"] or {}) if isinstance(current["results"], Mapping) else {}
                current_ledger = list(payload.get("query_ledger", []))
                found = False
                for item in current_ledger:
                    if str(item.get("query_id")) == str(query_id):
                        if item.get("status") != "planned":
                            raise Conflict("query checkpoint changed before submission was recorded")
                        item.update(
                            {
                                "splunk_job_id": sid,
                                "status": "submitted",
                                "submitted_at_utc": _rfc3339(_now()),
                            }
                        )
                        found = True
                        break
                if not found:
                    raise Conflict("submitted query is missing from the checkpoint")
                payload["query_ledger"] = current_ledger
                payload["usage"] = counters.model_dump(mode="json")
                self._update(
                    row["owner_id"],
                    lease.hunt_id,
                    expected_state=HuntState.RUNNING.value,
                    results=payload,
                    updated_at_utc=_now(),
                )

            def on_rejected(proposal: QueryProposal, validation: Any) -> None:
                self._persist_policy_rejections(
                    row["owner_id"],
                    lease.hunt_id,
                    [{
                        "query_id": str(validation.query_id),
                        "proposal": proposal.model_dump(mode="json"),
                        "reason_codes": list(validation.reason_codes),
                        "query_policy_version": validation.query_policy_version,
                    }],
                    expected_state=HuntState.RUNNING.value,
                )

            runtime_question_ids = [*open_question_ids]
            for item in progress.get("follow_up_questions", []):
                if isinstance(item, Mapping) and isinstance(item.get("question_id"), str):
                    runtime_question_ids.append(item["question_id"])
            executor = ProductionHuntExecutor(
                self.splunk_connector,
                policy,
                counters=counters,
                limits=self.budget_limits,
                cancellation_token=token,
                deadline=investigation_deadline,
                on_submitted=on_submitted,
                on_rejected=on_rejected,
                open_question_ids=runtime_question_ids,
                poll_interval_seconds=self.splunk_poll_interval_seconds,
            )
            self._run_checkpoint_queries(
                lease=lease, executor=executor, counters=counters, require_lease=require_lease,
                query_start_deadline=query_start_deadline,
            )

            if _now() < query_start_deadline:
                continue_investigation = False
                try:
                    continue_investigation = self._assess_execution_round(
                        lease=lease, plan=plan, policy=policy, discovery_scope=discovery_scope,
                        counters=counters, token=token, deadline=query_start_deadline, require_lease=require_lease,
                    )
                except AdapterError as exc:
                    if exc.category == FailureCategory.BUDGET_EXHAUSTED:
                        require_lease()
                        current = self._owned_row(row["owner_id"], lease.hunt_id)
                        stopped_results = dict(current["results"] or {})
                        stopped_results.update(
                            adaptive_complete=True, adaptive_status="budget_reserved_for_synthesis",
                            usage=counters.model_dump(mode="json"),
                        )
                        self._update(
                            row["owner_id"], lease.hunt_id, expected_state=HuntState.RUNNING.value,
                            results=stopped_results, updated_at_utc=_now(),
                        )
                    elif exc.category != FailureCategory.HARD_TIMEOUT or _now() < query_start_deadline:
                        raise
                if continue_investigation:
                    self.execute_job(lease)
                    return
            if _now() >= query_start_deadline:
                require_lease()
                current = self._owned_row(row["owner_id"], lease.hunt_id)
                stopped_results = dict(current["results"] or {})
                stopped_results.update(
                    adaptive_complete=True, adaptive_status="time_reserved_for_synthesis",
                    usage=counters.model_dump(mode="json"),
                )
                self._update(
                    row["owner_id"], lease.hunt_id, expected_state=HuntState.RUNNING.value,
                    results=stopped_results, updated_at_utc=_now(),
                )

            if token.is_cancelled():
                raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="execution.complete")
            require_lease()
            current = self._owned_row(row["owner_id"], lease.hunt_id)
            results = dict(current["results"] or {}) if isinstance(current["results"], Mapping) else {}
            while True:
                completed_questions = {item["question_id"] for item in results.get("question_answers", [])}
                pending = [question for question in plan.questions if question.question_id not in completed_questions]
                if not pending:
                    break
                focused_plan = plan.model_copy(update={"questions": pending})
                remaining_seconds = (deadline - _now()).total_seconds()
                remaining_input = self.budget_limits.max_model_input_tokens - counters.model_input_tokens
                remaining_output = self.budget_limits.max_model_output_tokens - counters.model_output_tokens
                allow_retrieval = (
                    self.budget_limits.max_model_calls - counters.model_calls >= 3
                    and remaining_seconds > self.budget_limits.synthesis_allowance_seconds
                    and remaining_input > 4096 and remaining_output > 1024
                    and results.get("synthesis_retrieval_status") not in {"no_new_pages", "final_only"}
                )
                # A retrieval-capable step leaves one call and half of remaining
                # tokens plus the configured synthesis time for a final answer.
                # Repairs share these same limits.
                step_limits = self.budget_limits.model_copy(update={
                    "max_model_calls": self.budget_limits.max_model_calls - 1,
                    "max_model_input_tokens": counters.model_input_tokens + remaining_input // 2,
                    "max_model_output_tokens": counters.model_output_tokens + remaining_output // 2,
                }) if allow_retrieval else self.budget_limits
                synthesis_runner = StrictModelRunner(
                    self.model_adapter, counters=counters, limits=step_limits,
                    deadline=deadline - timedelta(seconds=self.budget_limits.synthesis_allowance_seconds) if allow_retrieval else deadline,
                    cancellation_token=token,
                )
                try:
                    answer = None
                    if allow_retrieval:
                        full_context = _synthesis_context(
                            plan=focused_plan, threat_intelligence=str(row["threat_intelligence"] or ""),
                            results=results, limit=self.budget_limits.max_targeted_events,
                        )
                        if not any(item["sample_omitted"] for item in full_context["evidence_coverage"]):
                            # Try the complete final request before reserving
                            # capacity for pages it would already contain.
                            # No context builder means preflight cannot sample.
                            calls_before = counters.model_calls
                            try:
                                answer = StrictModelRunner(
                                    self.model_adapter, counters=counters, limits=self.budget_limits,
                                    deadline=deadline, cancellation_token=token,
                                ).run(_question_synthesis_contract(focused_plan),
                                      user_payload=full_context, contract_name="QuestionSynthesis")
                            except AdapterError as exc:
                                if exc.category != FailureCategory.BUDGET_EXHAUSTED or counters.model_calls != calls_before:
                                    # A submitted final call (including its
                                    # repair) must not be replayed as retrieval.
                                    allow_retrieval = False
                                    raise
                    if answer is None:
                        answer = synthesis_runner.run(
                            _question_synthesis_contract(focused_plan, allow_retrieval=allow_retrieval),
                            user_payload={}, contract_name="QuestionSynthesis",
                            context_builder=lambda limit: _synthesis_context(
                                plan=focused_plan, threat_intelligence=str(row["threat_intelligence"] or ""),
                                results=results, limit=limit,
                            ),
                        )
                    pages = _retained_synthesis_pages(answer, focused_plan, results)
                    generated = _materialize_question_answers(answer, focused_plan, results)
                except AdapterError as exc:
                    if allow_retrieval and exc.category in {FailureCategory.BUDGET_EXHAUSTED, FailureCategory.HARD_TIMEOUT}:
                        results["synthesis_retrieval_status"] = "final_only"
                        results["usage"] = counters.model_dump(mode="json")
                        require_lease()
                        self._update(row["owner_id"], lease.hunt_id, expected_state=HuntState.RUNNING.value,
                                     results=results, updated_at_utc=_now())
                        continue
                    if exc.category != FailureCategory.BUDGET_EXHAUSTED:
                        raise
                    # A smaller context was already attempted. Preserve completed
                    # answers and expose missing analysis instead of inventing it.
                    pages = []
                    generated = {"findings": [], "question_answers": [{
                        "question_id": question.question_id, "question": question.question,
                        "summary": "This question remains unanswered because the synthesis budget was exhausted.",
                        "finding_ids": [], "limitations": ["The remaining call, context or token budget could not support a complete answer."],
                    } for question in pending]}
                    results["synthesis_retrieval_status"] = "budget_limited"
                except Validation:
                    counters.model_output_checks[-1].grounding_valid = False
                    raise
                else:
                    counters.model_output_checks[-1].grounding_valid = True
                for key in ("findings", "question_answers"):
                    results.setdefault(key, []).extend(generated[key])
                previous_pages = results.setdefault("synthesis_retrievals", [])
                added_page = False
                for page in pages:
                    existing = next((prior for prior in previous_pages
                                     if {key: value for key, value in prior.items() if key != "retrieval_round"} == page), None)
                    if existing is None:
                        existing = dict(page)
                        previous_pages.append(existing)
                        added_page = True
                    # Repeated pages still get priority in the final answer,
                    # including when they were omitted from a previous sample.
                    existing["retrieval_round"] = counters.model_calls
                if pages and not added_page:
                    results["synthesis_retrieval_status"] = "no_new_pages"
                results["usage"] = counters.model_dump(mode="json")
                require_lease()
                self._update(row["owner_id"], lease.hunt_id, expected_state=HuntState.RUNNING.value,
                             results=results, updated_at_utc=_now())
            question_order = {question.question_id: position for position, question in enumerate(plan.questions)}
            results["question_answers"].sort(key=lambda item: question_order[item["question_id"]])
            results["usage"] = counters.model_dump(mode="json")
            self._update(
                row["owner_id"],
                lease.hunt_id,
                expected_state=HuntState.RUNNING.value,
                state=HuntState.SYNTHESIZING.value,
                results=results,
                updated_at_utc=_now(),
            )
            require_lease()
            self._update(
                row["owner_id"],
                lease.hunt_id,
                expected_state=HuntState.SYNTHESIZING.value,
                state=HuntState.REPORT_DRAFT.value,
                report_id=str(uuid4()),
                report_version=1,
                report_state=HuntState.REPORT_DRAFT.value,
                report_content=_execution_report_content(row, plan, results),
                updated_at_utc=_now(),
            )
        except Exception as exc:
            diagnostic = failure_metadata(exc)
            logging.getLogger(__name__).error(
                "hunt execution failed hunt_id=%s job_id=%s category=%s error_type=%s",
                lease.hunt_id, lease.job_id, diagnostic["category"], diagnostic["error_type"],
            )
            try:
                require_lease()
                current = self._owned_row(row["owner_id"], lease.hunt_id)
                if current["state"] in {HuntState.QUEUED.value, HuntState.RUNNING.value, HuntState.SYNTHESIZING.value}:
                    failure_results = dict(current["results"] or {}) if isinstance(current["results"], Mapping) else {}
                    failure_results["usage"] = counters.model_dump(mode="json")
                    failure_results["mode"] = "production"
                    failure_results["failure"] = diagnostic
                    self._update(
                        row["owner_id"],
                        lease.hunt_id,
                        expected_state=str(current["state"]),
                        state=HuntState.FAILED.value,
                        results=failure_results,
                        updated_at_utc=_now(),
                    )
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
        pdf = _formatted_pdf(row["title"], content)
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
        if not isinstance(normalized["questions"], list) or not normalized["questions"] or not isinstance(normalized["scope"], dict):
            raise Validation("plan requires scope and at least one question")
        question_ids = [
            question.get("question_id") if isinstance(question, Mapping) else None
            for question in normalized["questions"]
        ]
        if any(
            not isinstance(value, str) or not value.strip() or value != value.strip()
            or value.casefold() == "unknown"
            for value in question_ids
        ) or len(set(question_ids)) != len(question_ids):
            raise Validation("plan question IDs must be nonempty, unique, and not unknown")
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
        return dict(row)

    def _update(
        self,
        owner_id: str,
        hunt_id: str,
        *,
        connection: Connection | None = None,
        expected_state: str | None = None,
        expected_plan_version: int | None = None,
        expected_report_state: str | None = None,
        expected_report_version: int | None = None,
        actor_type: str = "system",
        action: str | None = None,
        detail: str | None = None,
        audit_outcome: str = "success",
        audit_metadata: Mapping[str, Any] | None = None,
        **values: Any,
    ) -> None:
        predicate = (hunts.c.hunt_id == hunt_id) & (hunts.c.owner_id == owner_id)
        if expected_state is not None:
            predicate &= hunts.c.state == expected_state
        if expected_plan_version is not None:
            predicate &= hunts.c.plan_version == expected_plan_version
        if expected_report_state is not None:
            predicate &= hunts.c.report_state == expected_report_state
        if expected_report_version is not None:
            predicate &= hunts.c.report_version == expected_report_version
        with (self.engine.begin() if connection is None else nullcontext(connection)) as connection:
            previous = connection.execute(
                select(
                    hunts.c.state,
                    hunts.c.plan_version,
                    hunts.c.report_state,
                    hunts.c.report_version,
                ).where(predicate)
            ).mappings().first()
            if previous is None:
                raise Conflict("hunt changed before the operation completed")
            result = connection.execute(update(hunts).where(predicate).values(**values))
            if result.rowcount != 1:
                raise Conflict("hunt changed before the operation completed")
            changed_fields = [
                field
                for field in ("state", "plan_version", "report_state", "report_version", "results")
                if field in values and values[field] != previous.get(field)
            ]
            if changed_fields:
                prior_state = str(previous["state"])
                resulting_state = str(values.get("state", previous["state"]))
                if action is None:
                    if "state" in changed_fields:
                        action = "hunt_state_changed"
                    elif "plan_version" in changed_fields:
                        action = "plan_updated"
                    elif "report_version" in changed_fields:
                        action = "report_updated"
                    else:
                        action = "execution_checkpoint"
                connection.execute(audit_records.insert().values(
                    audit_id=str(uuid4()),
                    hunt_id=hunt_id,
                    owner_id=owner_id,
                    actor_type=actor_type,
                    actor_id=owner_id,
                    action=action,
                    object_type="hunt",
                    object_id=hunt_id,
                    prior_state=prior_state,
                    resulting_state=resulting_state,
                    outcome=audit_outcome,
                    detail=(detail or None),
                    metadata=bounded_audit_metadata({
                        "changed_fields": changed_fields,
                        **(dict(audit_metadata) if audit_metadata is not None else {}),
                    }),
                    timestamp_utc=values.get("updated_at_utc") or _now(),
                ))

    @staticmethod
    def _public(row: Mapping[str, Any]) -> dict[str, Any]:
        return {key: _json_copy(value) for key, value in row.items() if key not in {"owner_id", "report_pdf"}}


__all__ = ["Conflict", "IntegrationUnavailable", "NotFound", "Validation", "WorkflowService", "audit_records", "workflow_metadata"]
