"""Versioned, strict Pydantic contracts for model and report payloads.

These models mirror the canonical JSON structures in section 7 of the MVP
specification.  They are intentionally independent of API and persistence
layers; application code assigns identifiers and validates references before
constructing a contract.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import ConfigDict, Field, StrictBool, StrictInt, StrictStr, field_validator, model_validator

from .common import (
    DomainModel,
    UTCDateTime,
    UnknownOrUTCDateTime,
    validate_non_empty_mapping,
    validate_sha256,
)

SchemaVersion = Literal["1.0"]
Identifier = Annotated[StrictStr, Field(min_length=1)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
Sha256 = Annotated[StrictStr, Field(min_length=64, max_length=64), ...]


class EntityType(StrEnum):
    """Entity kinds that may be supplied to a model or report."""

    HOST = "host"
    USER = "user"
    IP = "ip"
    PROCESS = "process"
    FILE = "file"
    DOMAIN = "domain"
    OTHER = "other"


class ResultMode(StrEnum):
    """Bounded result modes supported by query proposals."""

    AGGREGATE = "aggregate"
    REPRESENTATIVE = "representative"
    TARGETED = "targeted"


QUERY_RESULT_LIMITS = MappingProxyType({
    ResultMode.AGGREGATE: 500,
    ResultMode.REPRESENTATIVE: 10_000,
    ResultMode.TARGETED: 10_000,
})


class FindingClassification(StrEnum):
    """Permitted finding classifications."""

    HUNT_LEAD = "hunt_lead"
    SUPPORTED_OBSERVATION = "supported_observation"
    NOT_SUPPORTED_WITHIN_SCOPE = "not_supported_within_scope"


FINDING_GROUNDING_FIELDS = MappingProxyType({
    FindingClassification.HUNT_LEAD: "evidence_ids",
    FindingClassification.SUPPORTED_OBSERVATION: "evidence_ids",
    FindingClassification.NOT_SUPPORTED_WITHIN_SCOPE: "query_ids",
})


class Confidence(StrEnum):
    """Finding confidence levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Disposition(StrEnum):
    """Final hunt dispositions that may be selected by a model stop decision."""

    SUPPORTED = "supported"
    NOT_SUPPORTED_WITHIN_SCOPE = "not_supported_within_scope"
    INCONCLUSIVE = "inconclusive"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


class StopReasonCode(StrEnum):
    """Deterministic reasons for ending an investigation."""

    HYPOTHESIS_DISPOSED = "hypothesis_disposed"
    PLAN_EXHAUSTED = "plan_exhausted"
    LOW_YIELD = "low_yield"
    BUDGET_REACHED = "budget_reached"
    UNRECOVERABLE_ERROR = "unrecoverable_error"


class HuntScope(DomainModel):
    """Time and telemetry scope for a plan."""

    earliest_utc: UTCDateTime
    latest_utc: UTCDateTime
    indexes: list[Identifier]
    sourcetypes: list[Identifier]

    @model_validator(mode="after")
    def validate_order(self) -> "HuntScope":
        """Require a non-empty, chronologically ordered time range."""

        if self.latest_utc <= self.earliest_utc:
            raise ValueError("latest_utc must be later than earliest_utc")
        return self


class ScopeEntity(DomainModel):
    """An entity value pinned to the approved hunt scope."""

    field: Identifier
    value: Identifier


class PlanDataSource(DomainModel):
    """A Splunk data source and its purpose in a plan."""

    index: Identifier
    sourcetypes: list[Identifier]
    purpose: Identifier


class PlanQuestion(DomainModel):
    """A question that a hunt plan intends to answer."""

    question_id: Identifier
    question: Identifier
    rationale: Identifier
    expected_information_gain: Identifier


class HuntPlan(DomainModel):
    """Canonical structured hunt plan."""

    schema_version: SchemaVersion
    plan_id: UUID
    plan_version: PositiveInt
    hunt_id: UUID
    discovery_snapshot_id: UUID
    execution_config_snapshot_id: UUID
    hypothesis: Identifier
    objective: Identifier
    scope: HuntScope
    intelligence_refs: list[Identifier]
    data_sources: list[PlanDataSource]
    questions: list[PlanQuestion]
    query_strategy: list[Identifier]
    coverage_limitations: list[Identifier]
    created_at_utc: UTCDateTime


class PlanApproval(DomainModel):
    """Immutable approval of one exact plan and execution snapshot."""

    schema_version: SchemaVersion
    approval_id: UUID
    hunt_id: UUID
    plan_id: UUID
    plan_version: PositiveInt
    plan_sha256: Annotated[StrictStr, Field(min_length=64, max_length=64)]
    execution_config_snapshot_id: UUID
    execution_config_sha256: Annotated[StrictStr, Field(min_length=64, max_length=64)]
    approved_by_user_id: UUID
    approved_at_utc: UTCDateTime
    analyst_note: StrictStr | Literal["unknown"]

    _validate_plan_sha256 = field_validator("plan_sha256", "execution_config_sha256")(
        validate_sha256
    )


class QueryProposal(DomainModel):
    """Bounded query request proposed for one existing plan question."""

    model_config = ConfigDict(json_schema_extra={
        "allOf": [
            {
                "if": {"properties": {"result_mode": {"const": mode.value}}},
                "then": {"properties": {"max_results": {"maximum": cap}}},
            }
            for mode, cap in QUERY_RESULT_LIMITS.items()
        ],
    })

    question_id: Identifier
    purpose: Identifier
    expected_information_gain: Identifier
    spl: Identifier
    earliest_utc: UTCDateTime
    latest_utc: UTCDateTime
    indexes: list[Identifier]
    sourcetypes: list[Identifier]
    requested_fields: list[Identifier]
    result_mode: ResultMode
    max_results: Annotated[StrictInt, Field(
        gt=0, le=max(QUERY_RESULT_LIMITS.values()),
        description="Maximum retained rows by mode: " + ", ".join(
            f"{mode.value}={cap}" for mode, cap in QUERY_RESULT_LIMITS.items()
        ) + ". Raw results are fetched in pages of at most 500 rows. This is the total retrieval "
        "ceiling, independent of the smaller evidence batch shown to the model. Request enough "
        "rows to cover the question; use a smaller ceiling only when sufficient.",
    )]

    @model_validator(mode="after")
    def validate_query(self) -> "QueryProposal":
        """Enforce time ordering and result-mode-specific row caps."""

        if self.latest_utc <= self.earliest_utc:
            raise ValueError("latest_utc must be later than earliest_utc")
        cap = QUERY_RESULT_LIMITS[self.result_mode]
        if self.max_results > cap:
            raise ValueError(f"max_results exceeds {self.result_mode.value} cap of {cap}")
        return self


class FollowUpDecision(DomainModel):
    """One executable proposal or explicit reason for skipping a generated question."""

    question_id: Identifier
    proposal: QueryProposal | None
    skip_reason: Annotated[StrictStr, Field(min_length=1, max_length=2000)] | None

    @model_validator(mode="after")
    def validate_decision(self) -> "FollowUpDecision":
        if (self.proposal is None) == (self.skip_reason is None):
            raise ValueError("provide exactly one of proposal or skip_reason")
        if self.skip_reason is not None and not self.skip_reason.strip():
            raise ValueError("skip_reason must explain why the question cannot proceed")
        if self.proposal is not None and self.proposal.question_id != self.question_id:
            raise ValueError("proposal question_id must match its decision")
        return self


class EnforcedQueryLimits(DomainModel):
    """Limits applied by deterministic query-policy code."""

    max_results: PositiveInt
    max_bytes: PositiveInt
    timeout_seconds: PositiveInt


class QueryValidationResult(DomainModel):
    """Deterministic validation result for a proposed query."""

    schema_version: SchemaVersion
    query_id: UUID
    allowed: StrictBool
    normalized_spl: Identifier
    earliest_utc: UTCDateTime
    latest_utc: UTCDateTime
    cache_key: Annotated[StrictStr, Field(min_length=64, max_length=64)] | None
    reason_codes: list[Identifier]
    enforced_limits: EnforcedQueryLimits
    query_policy_version: Identifier

    _validate_cache_key = field_validator("cache_key")(
        lambda value: None if value is None else validate_sha256(value)
    )

    @model_validator(mode="after")
    def validate_allowed_fields(self) -> "QueryValidationResult":
        """Tie execution-only fields to the allowed/rejected result."""

        if self.latest_utc <= self.earliest_utc:
            raise ValueError("latest_utc must be later than earliest_utc")
        if self.allowed and self.cache_key is None:
            raise ValueError("an allowed query requires a cache_key")
        if self.allowed and self.reason_codes:
            raise ValueError("an allowed query cannot contain reason_codes")
        if not self.allowed and self.cache_key is not None:
            raise ValueError("a rejected query must have a null cache_key")
        if not self.allowed and not self.reason_codes:
            raise ValueError("a rejected query requires at least one reason_code")
        return self


class AssessmentEntity(DomainModel):
    """Entity selected from an exact scalar value in a cited query result."""

    entity_type: EntityType
    value: Identifier = Field(description=(
        "Copy a complete scalar field value or list element from this query's supplied evidence. "
        "Do not derive substrings, parse file paths from command lines, or remove "
        "quotes/arguments. Select an observed file_name or process value instead; "
        "command-line interpretation belongs in the evidence-backed summary."
    ))
    result_row_refs: list[Identifier]


class ProposedNextQuestion(DomainModel):
    """Optional follow-up question returned by an assessment."""

    question: Identifier
    rationale: Identifier
    expected_information_gain: Identifier


class QueryAssessment(DomainModel):
    """Structured assessment of one completed query."""

    query_id: UUID
    question_id: Identifier
    answered_question: StrictBool
    material_progress: StrictBool
    summary: Identifier = Field(description=(
        "State observed actions and identifiers, then label any interpretation and its basis. "
        "Familiar names, ports, or successful events do not establish normality, authorization, "
        "benignness, or intent. Shared hosts/accounts alone do not establish a process or session link."
    ))
    new_entities: list[AssessmentEntity]
    evidence_candidate_row_refs: list[Identifier]
    coverage_changes: list[Identifier]
    limitations: list[Identifier]
    proposed_next_question: ProposedNextQuestion | None


class EvidenceKind(StrEnum):
    """Retained evidence row kinds."""

    RAW_EVENT = "raw_event"
    AGGREGATE_ROW = "aggregate_row"


class EvidenceTruncation(DomainModel):
    """Bounded-result metadata retained with an evidence record."""

    truncated: StrictBool = False
    reason: StrictStr | Literal["unknown"] = "unknown"
    source_row_count: StrictInt | None = Field(default=None, ge=0)
    retained_row_count: StrictInt | None = Field(default=None, ge=0)
    source_byte_count: StrictInt | None = Field(default=None, ge=0)
    retained_byte_count: StrictInt | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> "EvidenceTruncation":
        if (
            self.source_row_count is not None
            and self.retained_row_count is not None
            and self.retained_row_count > self.source_row_count
        ):
            raise ValueError("retained_row_count cannot exceed source_row_count")
        if (
            self.source_byte_count is not None
            and self.retained_byte_count is not None
            and self.retained_byte_count > self.source_byte_count
        ):
            raise ValueError("retained_byte_count cannot exceed source_byte_count")
        if self.truncated and self.reason == "unknown":
            raise ValueError("truncated evidence requires a reason")
        return self


class EvidenceRecord(DomainModel):
    """Retained, hashed evidence selected from a non-empty result row."""

    schema_version: SchemaVersion
    evidence_id: UUID
    hunt_id: UUID
    query_id: UUID
    splunk_job_id: Identifier
    evidence_kind: EvidenceKind
    index: Identifier
    sourcetype: StrictStr | Literal["unknown"]
    event_time_utc: UnknownOrUTCDateTime
    collected_at_utc: UTCDateTime
    source_event_ref: StrictStr | Literal["unknown"]
    selected_result: Annotated[dict[str, Any], Field(min_length=1)]
    truncation: EvidenceTruncation = Field(default_factory=EvidenceTruncation)
    sha256: Annotated[StrictStr, Field(min_length=64, max_length=64)]

    _validate_result = field_validator("selected_result")(validate_non_empty_mapping)
    _validate_sha = field_validator("sha256")(validate_sha256)


class Finding(DomainModel):
    """A finding grounded in retained evidence or completed queries."""

    finding_id: UUID
    title: Identifier
    classification: FindingClassification
    statement: Identifier
    confidence: Confidence
    evidence_ids: list[UUID]
    query_ids: list[UUID]
    inference: StrictStr | Literal["unknown"]
    limitations: list[Identifier]

    @model_validator(mode="after")
    def validate_grounding(self) -> "Finding":
        """Require grounding appropriate to the finding classification."""

        required_field = FINDING_GROUNDING_FIELDS[self.classification]
        if not getattr(self, required_field):
            reason = (
                "this finding classification requires evidence_ids"
                if required_field == "evidence_ids"
                else "not_supported_within_scope requires completed query_ids"
            )
            raise ValueError(reason)
        return self


class FindingProposal(DomainModel):
    """Model-produced finding before the application assigns its identifier."""

    title: Identifier = Field(description=(
        "A concise description of the supported observation or precisely scoped search outcome. "
        "Keep uncertainty in the title when the relationship or interpretation is unconfirmed."
    ))
    classification: FindingClassification
    statement: Identifier = Field(description=(
        "State only facts established by the cited records or the selected completed searches. "
        "Describe observed actions and the actual relationship keys; shared hosts/accounts and "
        "overlapping times do not prove the same process, session, or cause. A positive observation "
        "must not also assert absence of malicious behavior. Normality, benignness, authorization, "
        "and intent require their own supplied support, not familiar names or successful events."
    ))
    confidence: Confidence
    evidence_ids: list[UUID]
    query_ids: list[UUID]
    inference: StrictStr | Literal["unknown"] = Field(description=(
        "A tentative interpretation that names its supporting observations and unresolved alternatives, "
        "or unknown. This field is not permission to invent facts or intent. Report a supplied "
        "baseline comparison or authorization within its documented scope; otherwise leave those "
        "properties unknown. A caveat here or in limitations does not repair an overstated title or statement."
    ))
    limitations: list[Identifier]

    @model_validator(mode="after")
    def validate_grounding(self) -> "FindingProposal":
        required_field = FINDING_GROUNDING_FIELDS[self.classification]
        if not getattr(self, required_field):
            reason = (
                "this finding classification requires evidence_ids"
                if required_field == "evidence_ids"
                else "not_supported_within_scope requires completed query_ids"
            )
            raise ValueError(reason)
        return self


class QuestionAnswer(DomainModel):
    """Evidence-grounded response for one application-assigned question slot."""

    summary: Identifier = Field(description=(
        "A concise answer to this question, normally one to three sentences. Summarize the "
        "material conclusions across all its findings and the limits on those conclusions; "
        "do not enumerate every finding or introduce claims unsupported by them. Preserve "
        "uncertainty and distinguish observations from inference. This is presentation text, "
        "not a limit on the findings or evidence retained for the investigation."
    ))
    findings: list[FindingProposal]
    limitations: list[Identifier] = Field(description=(
        "Missing evidence or scope limits that prevent answering this question fully. "
        "If findings is empty, explain why the question cannot be answered. "
        "A populated answer slot does not establish factual correctness or complete coverage."
    ))

    @model_validator(mode="after")
    def require_answer_or_limitation(self) -> "QuestionAnswer":
        if not self.findings and not self.limitations:
            raise ValueError("each question requires a supported finding or an explicit limitation")
        return self


class StopDecision(DomainModel):
    """Structured decision to stop investigation and synthesize a report."""

    disposition: Disposition
    reason_code: StopReasonCode
    summary: Identifier
    evidence_ids: list[UUID]
    query_ids: list[UUID]
    coverage: list[Identifier]
    limitations: list[Identifier]
    open_questions: list[Identifier]

    @model_validator(mode="after")
    def validate_grounding(self) -> "StopDecision":
        """Require grounded outcomes and coherent terminal reasons."""

        if self.disposition == Disposition.SUPPORTED and not self.evidence_ids:
            raise ValueError("supported stop decisions require evidence_ids")
        if (
            self.disposition == Disposition.NOT_SUPPORTED_WITHIN_SCOPE
            and not self.query_ids
        ):
            raise ValueError("not_supported_within_scope requires query_ids")

        if self.reason_code == StopReasonCode.BUDGET_REACHED:
            if self.disposition != Disposition.BUDGET_EXHAUSTED:
                raise ValueError("budget_reached requires budget_exhausted disposition")
        elif self.disposition == Disposition.BUDGET_EXHAUSTED:
            raise ValueError("budget_exhausted requires budget_reached reason_code")

        if self.reason_code == StopReasonCode.UNRECOVERABLE_ERROR:
            if self.disposition != Disposition.FAILED:
                raise ValueError("unrecoverable_error requires failed disposition")
        elif self.disposition == Disposition.FAILED:
            raise ValueError("failed requires unrecoverable_error reason_code")

        meaningful_coverage = any(value.strip() for value in self.coverage)
        meaningful_limitations = any(value.strip() for value in self.limitations)
        if self.disposition in {
            Disposition.NOT_SUPPORTED_WITHIN_SCOPE,
            Disposition.INCONCLUSIVE,
            Disposition.BUDGET_EXHAUSTED,
        } and not (meaningful_coverage or meaningful_limitations):
            raise ValueError(
                "negative, inconclusive, and budget stop decisions require coverage or limitations"
            )
        return self


class ReportEntity(DomainModel):
    """Entity reference included in report content."""

    entity_type: EntityType
    value: Identifier
    evidence_ids: list[UUID]


class ReportTimelineEntry(DomainModel):
    """Timeline event in report content."""

    time_utc: UnknownOrUTCDateTime
    description: Identifier
    evidence_ids: list[UUID]


class ReportConclusion(DomainModel):
    """Grounded report conclusion."""

    text: Identifier
    finding_ids: list[UUID]
    evidence_ids: list[UUID]
    query_ids: list[UUID]


class ReportContent(DomainModel):
    """Canonical editable report content for one completed hunt."""

    schema_version: SchemaVersion
    hunt_id: UUID
    approved_plan_id: UUID
    approved_plan_version: PositiveInt
    approved_plan_sha256: Annotated[StrictStr, Field(min_length=64, max_length=64)]
    execution_config_snapshot_id: UUID
    execution_config_sha256: Annotated[StrictStr, Field(min_length=64, max_length=64)]
    hypothesis: Identifier
    objective_and_scope: Identifier
    data_sources_used: list[Identifier]
    finding_ids: list[UUID]
    evidence_ids: list[UUID]
    query_ids: list[UUID]
    entities: list[ReportEntity]
    timeline: list[ReportTimelineEntry]
    coverage: list[Identifier]
    limitations: list[Identifier]
    conclusion: ReportConclusion
    disposition: Disposition

    _validate_sha = field_validator("approved_plan_sha256", "execution_config_sha256")(
        validate_sha256
    )


# Public aliases make the domain vocabulary discoverable without duplicating
# model classes, and preserve the names used by integrations that call the
# execution snapshot a "scope" or a query validation "result".
Scope = HuntScope
DataSource = PlanDataSource
Question = PlanQuestion
Entity = AssessmentEntity
TimelineEntry = ReportTimelineEntry
Conclusion = ReportConclusion
QueryLimits = EnforcedQueryLimits
