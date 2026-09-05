"""Pure, bounded query-candidate selectivity and ranking decisions.

This module does not execute queries or persist state.  It consumes the
already-approved plan, discovery metadata, deterministic SPL policy, and
optional completed-query observations to produce a replayable shadow ranking.
Unknown inputs are represented explicitly and cause the caller to retain
approved plan order.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pydantic import ValidationError

from threat_hunting.domain.common import ensure_utc, utc_now
from threat_hunting.domain.contracts import QueryProposal, ScopeEntity
from threat_hunting.domain.spl_policy import BUILTIN_FIELDS, SPLPolicy


STRATEGY_VERSION = "1.0"
DEFAULT_CANDIDATE_CAP = 8
MAX_CANDIDATE_CAP = 32


class QueryStrategyError(ValueError):
    """Raised when a candidate set cannot be safely bounded or normalized."""

    def __init__(self, message: str, *, reason_code: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class SelectivityConfidence(StrEnum):
    """Confidence of a deterministic estimate basis."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


_SCORE_COMPONENTS = {
    "unresolved_question": 30,
    "approved_telemetry": 20,
    "evidence_pivot": 20,
    "scope_specificity": 15,
    "selectivity": 10,
    "not_already_answered": 5,
}
_FILTER_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_.:-])([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*"
    r"(?:\"([^\"]*)\"|'([^']*)'|([^\s|,()]+))"
)
_NON_FILTER_FIELDS = frozenset({"index", "sourcetype", "earliest", "latest"})


def _bounded_int(value: Any, *, minimum: int = 0, maximum: int | None = None) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        return None
    if maximum is not None and value > maximum:
        return None
    return value


def _round_half_up(value: float) -> int:
    return math.floor(value + 0.5)


def _clamp(value: int | float, minimum: int | float, maximum: int | float) -> int | float:
    return min(maximum, max(minimum, value))


def _string_sequence(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return None
    values = tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
    return values


def _scope_entities(value: Any) -> tuple[ScopeEntity, ...] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return None
    entities: list[ScopeEntity] = []
    for item in value:
        if isinstance(item, ScopeEntity):
            entities.append(item)
            continue
        if not isinstance(item, Mapping):
            return None
        try:
            entities.append(ScopeEntity.model_validate(dict(item)))
        except ValidationError:
            return None
    return tuple(entities)


def _canonical_proposal(proposal: QueryProposal) -> dict[str, Any]:
    return proposal.model_dump(mode="json")


def candidate_id(hunt_id: str, proposal: QueryProposal) -> str:
    """Return the stable application-derived identity for one proposal.

    The material intentionally matches the runner's existing query
    idempotency material.  Provider-supplied IDs and other raw metadata are
    never included.
    """

    if not isinstance(hunt_id, str) or not hunt_id.strip():
        raise QueryStrategyError("hunt_id must be non-empty", reason_code="missing_hunt_id")
    if not isinstance(proposal, QueryProposal):
        raise QueryStrategyError("proposal must be a QueryProposal", reason_code="candidate_invalid")
    material = json.dumps(
        {"hunt_id": hunt_id, "proposal": _canonical_proposal(proposal)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"query:{hashlib.sha256(material).hexdigest()}"


@dataclass(frozen=True, slots=True)
class QueryHistoryObservation:
    """One completed query observation eligible for exact reuse comparison."""

    query_id: str
    cache_key: str | None
    normalized_spl: str | None
    result_rows: int
    result_bytes: int
    state: str
    outcome: str | None
    truncated: bool
    partial_fetch: bool
    expires_at: datetime | None

    def __post_init__(self) -> None:
        if not self.query_id:
            raise ValueError("query history query_id must be non-empty")
        if self.result_rows < 0 or self.result_bytes < 0:
            raise ValueError("query history result counters must be non-negative")


@dataclass(frozen=True, slots=True)
class SelectivityEstimate:
    """Bounded deterministic estimate used only as ranking input."""

    candidate_id: str
    estimated_rows: int | None
    estimated_bytes: int | None
    estimated_cost: int | None
    confidence: SelectivityConfidence
    basis: tuple[str, ...] = ()
    unknown_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise ValueError("selectivity candidate_id must be non-empty")
        for name in ("estimated_rows", "estimated_bytes"):
            value = getattr(self, name)
            if value is not None and _bounded_int(value) is None:
                raise ValueError(f"{name} must be a non-negative integer or None")
        if self.estimated_cost is not None and _bounded_int(self.estimated_cost, maximum=100) is None:
            raise ValueError("estimated_cost must be between 0 and 100 or None")
        if len(set(self.basis)) != len(self.basis):
            raise ValueError("selectivity basis must be unique")
        if len(set(self.unknown_reasons)) != len(self.unknown_reasons):
            raise ValueError("selectivity unknown reasons must be unique")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe shadow record."""

        return {
            "algorithm_version": STRATEGY_VERSION,
            "candidate_id": self.candidate_id,
            "estimated_rows": self.estimated_rows,
            "estimated_bytes": self.estimated_bytes,
            "estimated_cost": self.estimated_cost,
            "confidence": self.confidence.value,
            "basis": list(self.basis),
            "unknown_reasons": list(self.unknown_reasons),
        }


@dataclass(frozen=True, slots=True)
class RejectedCandidate:
    """One candidate rejected before ranking, with a stable reason."""

    source_index: int
    candidate_id: str | None
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe rejection record."""

        return {
            "source_index": self.source_index,
            "candidate_id": self.candidate_id,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class RankedQueryCandidate:
    """One normalized candidate and its deterministic shadow rank."""

    candidate_id: str
    proposal: QueryProposal
    approved_question_position: int
    shadow_rank: int
    score: int | None
    score_components: Mapping[str, int | None]
    selectivity: SelectivityEstimate
    fallback_reason: str | None = None

    def __post_init__(self) -> None:
        if self.approved_question_position < 0:
            raise ValueError("approved question position must be non-negative")
        if self.shadow_rank <= 0:
            raise ValueError("shadow rank must be positive")
        if self.score is not None and _bounded_int(self.score, maximum=100) is None:
            raise ValueError("score must be between 0 and 100 or None")
        if set(self.score_components) != set(_SCORE_COMPONENTS):
            raise ValueError("score components do not match the ranking contract")
        for name, maximum in _SCORE_COMPONENTS.items():
            value = self.score_components[name]
            if value is not None and _bounded_int(value, maximum=maximum) is None:
                raise ValueError(f"score component {name} is outside its bound")
        object.__setattr__(self, "score_components", MappingProxyType(dict(self.score_components)))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe shadow ranking record."""

        return {
            "algorithm_version": STRATEGY_VERSION,
            "candidate_id": self.candidate_id,
            "proposal": self.proposal.model_dump(mode="json"),
            "approved_question_position": self.approved_question_position,
            "shadow_rank": self.shadow_rank,
            "score": self.score,
            "score_components": dict(self.score_components),
            "selectivity": self.selectivity.to_dict(),
            "fallback_reason": self.fallback_reason,
        }


@dataclass(frozen=True, slots=True)
class QueryRankingResult:
    """Complete bounded ranking result, including rejected and duplicate data."""

    ranked: tuple[RankedQueryCandidate, ...]
    rejected: tuple[RejectedCandidate, ...] = ()
    duplicates_removed: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe shadow ranking result."""

        return {
            "algorithm_version": STRATEGY_VERSION,
            "ranked": [item.to_dict() for item in self.ranked],
            "rejected": [item.to_dict() for item in self.rejected],
            "duplicates_removed": list(self.duplicates_removed),
        }


def _coerce_proposal(value: Any) -> QueryProposal:
    if isinstance(value, QueryProposal):
        return value
    if not isinstance(value, Mapping):
        raise QueryStrategyError("candidate must be an object", reason_code="candidate_invalid")
    payload = dict(value)
    # These fields are accepted by the runner as application metadata but are
    # deliberately excluded from the strict proposal identity.
    payload.pop("idempotency_key", None)
    payload.pop("query_id", None)
    try:
        return QueryProposal.model_validate(payload)
    except ValidationError as exc:
        raise QueryStrategyError("candidate does not match QueryProposal", reason_code="candidate_invalid") from exc


def _parse_history(value: QueryHistoryObservation | Mapping[str, Any]) -> QueryHistoryObservation | None:
    if isinstance(value, QueryHistoryObservation):
        return value
    if not isinstance(value, Mapping):
        return None
    query_id = value.get("query_id", value.get("id"))
    if not isinstance(query_id, str) or not query_id.strip():
        return None
    expires_raw = value.get("expires_at", value.get("cache_expires_at"))
    expires_at: datetime | None = None
    if expires_raw is not None:
        try:
            expires_at = ensure_utc(expires_raw)
        except (TypeError, ValueError):
            return None
    rows = _bounded_int(value.get("result_rows", value.get("result_count", 0)))
    bytes_ = _bounded_int(value.get("result_bytes", 0))
    if rows is None or bytes_ is None:
        return None
    try:
        return QueryHistoryObservation(
            query_id=query_id,
            cache_key=str(value["cache_key"]) if value.get("cache_key") is not None else None,
            normalized_spl=(
                str(value["normalized_spl"])
                if value.get("normalized_spl") is not None
                else None
            ),
            result_rows=rows,
            result_bytes=bytes_,
            state=str(value.get("state", "")),
            outcome=str(value["outcome"]) if value.get("outcome") is not None else None,
            truncated=bool(value.get("truncated", False)),
            partial_fetch=bool(value.get("partial_fetch", value.get("partial", False))),
            expires_at=expires_at,
        )
    except (TypeError, ValueError):
        return None


def _eligible_history(
    history: Sequence[QueryHistoryObservation | Mapping[str, Any]],
    *,
    cache_key: str | None,
    normalized_spl: str,
    now: datetime | None,
) -> tuple[QueryHistoryObservation, ...]:
    if cache_key is None or now is None:
        return ()
    current = ensure_utc(now)
    eligible: list[QueryHistoryObservation] = []
    for item in history:
        observation = _parse_history(item)
        if observation is None:
            continue
        if observation.state not in {"completed", "cached"}:
            continue
        if observation.outcome not in {None, "success", "succeeded"}:
            continue
        if observation.truncated or observation.partial_fetch:
            continue
        if observation.expires_at is None or observation.expires_at <= current:
            continue
        if observation.cache_key != cache_key:
            continue
        if observation.normalized_spl is not None and observation.normalized_spl != normalized_spl:
            continue
        eligible.append(observation)
    return tuple(eligible)


def _extract_filters(proposal: QueryProposal) -> tuple[tuple[str, str], ...]:
    """Extract only explicit search/where equality filters from SPL."""

    try:
        from threat_hunting.domain.spl_policy import parse_spl

        parsed = parse_spl(proposal.spl)
    except (TypeError, ValueError):
        return ()
    filters: list[tuple[str, str]] = []
    for command, args in parsed.command_segments:
        if command not in {"search", "where", "regex"}:
            continue
        for match in _FILTER_ASSIGNMENT.finditer(args):
            field = match.group(1)
            if field.casefold() in _NON_FILTER_FIELDS:
                continue
            value = next((part for part in match.groups()[1:] if part is not None), "")
            if value:
                filters.append((field, value))
    return tuple(dict.fromkeys(filters))


def _scope_values(scope: Mapping[str, Any] | None) -> tuple[Any, ...] | None:
    if scope is None:
        return None
    return (
        scope.get("earliest_utc"),
        scope.get("latest_utc"),
        _string_sequence(scope.get("indexes")),
        _string_sequence(scope.get("sourcetypes")),
        _scope_entities(scope.get("entities")),
    )


def _telemetry_confirmed(
    proposal: QueryProposal,
    *,
    scope: Mapping[str, Any] | None,
    discovery: Mapping[str, Any] | None,
) -> tuple[bool | None, str | None]:
    if discovery is None:
        return None, "discovery_unknown"
    complete = discovery.get("complete")
    if complete is not True:
        return None, "discovery_partial" if complete is False else "discovery_unknown"
    discovered_indexes = _string_sequence(discovery.get("indexes"))
    discovered_sources = _string_sequence(discovery.get("sourcetypes"))
    discovered_fields = _string_sequence(discovery.get("fields"))
    approved_indexes = _string_sequence(scope.get("indexes")) if scope is not None else None
    approved_sources = _string_sequence(scope.get("sourcetypes")) if scope is not None else None
    if None in {discovered_indexes, discovered_sources, discovered_fields, approved_indexes, approved_sources}:
        return None, "telemetry_scope_unknown"
    known_fields = set(discovered_fields or ()) | set(BUILTIN_FIELDS)
    return (
        set(proposal.indexes).issubset(set(discovered_indexes or ()))
        and set(proposal.sourcetypes).issubset(set(discovered_sources or ()))
        and set(proposal.requested_fields).issubset(known_fields)
        and set(proposal.indexes).issubset(set(approved_indexes or ()))
        and set(proposal.sourcetypes).issubset(set(approved_sources or ())),
        None,
    )


def _scope_specificity(
    proposal: QueryProposal,
    *,
    scope: Mapping[str, Any] | None,
    filters: Sequence[tuple[str, str]],
) -> tuple[int | None, str | None, int]:
    values = _scope_values(scope)
    if values is None:
        return None, "approved_scope_unknown", 0
    earliest_raw, latest_raw, indexes, sourcetypes, entities = values
    if earliest_raw is None or latest_raw is None or indexes is None or sourcetypes is None or entities is None:
        return None, "approved_scope_incomplete", 0
    try:
        approved_earliest = ensure_utc(earliest_raw)
        approved_latest = ensure_utc(latest_raw)
    except (TypeError, ValueError):
        return None, "approved_scope_time_invalid", 0
    approved_seconds = (approved_latest - approved_earliest).total_seconds()
    candidate_seconds = (proposal.latest_utc - proposal.earliest_utc).total_seconds()
    if approved_seconds <= 0 or candidate_seconds <= 0:
        return None, "scope_time_invalid", 0
    time_narrowness = _clamp(1 - candidate_seconds / approved_seconds, 0.0, 1.0)
    matched_entities = sum(
        1 for entity in entities if (entity.field, entity.value) in set(filters)
    )
    entity_narrowness = (
        matched_entities / len(entities)
        if entities
        else 0.0
    )
    points = _round_half_up(15 * (0.5 * time_narrowness + 0.5 * entity_narrowness))
    return int(_clamp(points, 0, 15)), None, matched_entities


def _selectivity_cost(
    proposal: QueryProposal,
    *,
    scope: Mapping[str, Any] | None,
    policy: SPLPolicy | None,
    filters: Sequence[tuple[str, str]],
    matched_entities: int,
) -> tuple[int | None, tuple[str, ...], tuple[str, ...]]:
    values = _scope_values(scope)
    if values is None:
        return None, (), ("approved_scope_unknown",)
    earliest_raw, latest_raw, indexes, sourcetypes, _entities = values
    if earliest_raw is None or latest_raw is None or indexes is None or sourcetypes is None:
        return None, (), ("approved_scope_incomplete",)
    try:
        approved_seconds = (ensure_utc(latest_raw) - ensure_utc(earliest_raw)).total_seconds()
    except (TypeError, ValueError):
        return None, (), ("approved_scope_time_invalid",)
    candidate_seconds = (proposal.latest_utc - proposal.earliest_utc).total_seconds()
    if approved_seconds <= 0 or candidate_seconds <= 0:
        return None, (), ("scope_time_invalid",)
    if not indexes or not sourcetypes:
        return None, (), ("approved_telemetry_scope_unknown",)

    cap = policy.max_results_by_mode.get(proposal.result_mode.value, proposal.max_results) if policy is not None else proposal.max_results
    if cap <= 0:
        return None, (), ("result_cap_unknown",)
    known_fields = set(BUILTIN_FIELDS)
    if policy is not None:
        known_fields.update(policy.discovered_fields)
    valid_non_entity_filters = sum(
        1 for field, _value in filters if field in known_fields
    )
    filter_quality = _clamp((2 * matched_entities + valid_non_entity_filters) / 8, 0.0, 1.0)
    time_ratio = _clamp(candidate_seconds / approved_seconds, 0.0, 1.0)
    index_ratio = _clamp(len(proposal.indexes) / len(indexes), 0.0, 1.0)
    source_ratio = _clamp(len(proposal.sourcetypes) / len(sourcetypes), 0.0, 1.0)
    result_ratio = _clamp(proposal.max_results / cap, 0.0, 1.0)
    cost = _round_half_up(
        40 * time_ratio
        + 15 * index_ratio
        + 15 * source_ratio
        + 20 * result_ratio
        + 10 * (1 - filter_quality)
    )
    return int(_clamp(cost, 0, 100)), (
        "fixed_time_scope",
        "approved_index_scope",
        "approved_sourcetype_scope",
        "valid_filters",
    ), ()


def estimate_selectivity(
    proposal: QueryProposal,
    *,
    hunt_id: str,
    approved_scope: Mapping[str, Any] | None,
    discovery: Mapping[str, Any] | None,
    policy: SPLPolicy | None = None,
    history: Sequence[QueryHistoryObservation | Mapping[str, Any]] | None = None,
    open_question_ids: Sequence[str] | None = None,
    now: datetime | None = None,
) -> SelectivityEstimate:
    """Estimate one candidate without calling a provider or external system.

    Exact compatible history supplies observed rows and bytes.  Otherwise the
    result is a low-confidence relative cost heuristic; rows and bytes stay
    unknown instead of being fabricated.
    """

    cid = candidate_id(hunt_id, proposal)
    basis: list[str] = []
    unknown: list[str] = []
    if policy is None:
        unknown.append("policy_unavailable")
    else:
        validation = policy.validate(proposal, open_question_ids=open_question_ids)
        if not validation.allowed:
            unknown.append("policy_rejected")
        else:
            basis.append("policy_validated")
    telemetry, telemetry_reason = _telemetry_confirmed(
        proposal, scope=approved_scope, discovery=discovery,
    )
    if telemetry is True:
        basis.append("complete_discovery")
    elif telemetry_reason is not None:
        unknown.append(telemetry_reason)

    filters = _extract_filters(proposal)
    _scope_score, scope_reason, matched_entities = _scope_specificity(
        proposal, scope=approved_scope, filters=filters,
    )
    if scope_reason is not None:
        unknown.append(scope_reason)
    cost, cost_basis, cost_unknown = _selectivity_cost(
        proposal,
        scope=approved_scope,
        policy=policy,
        filters=filters,
        matched_entities=matched_entities,
    )
    basis.extend(cost_basis)
    unknown.extend(cost_unknown)

    validation = policy.validate(proposal, open_question_ids=open_question_ids) if policy is not None else None
    cache_key = validation.cache_key if validation is not None and validation.allowed else None
    normalized_spl = validation.normalized_spl if validation is not None else proposal.spl
    eligible = _eligible_history(
        history or (),
        cache_key=cache_key,
        normalized_spl=normalized_spl,
        now=now,
    )
    rows: int | None = None
    bytes_: int | None = None
    if eligible:
        observation = sorted(eligible, key=lambda item: item.query_id)[0]
        rows = observation.result_rows
        bytes_ = observation.result_bytes
        if policy is not None:
            row_limit = max(policy.max_results_by_mode.values(), default=1)
            byte_limit = max(policy.max_bytes, 1)
            cost = int(_clamp(_round_half_up(
                50 * rows / max(row_limit, 1) + 50 * bytes_ / byte_limit
            ), 0, 100))
        basis.append("exact_compatible_history")
    elif history is None:
        unknown.append("history_unavailable")
    elif now is None:
        unknown.append("history_time_unknown")
    else:
        basis.append("no_exact_compatible_history")

    unique_unknown = tuple(dict.fromkeys(unknown))
    confidence = (
        SelectivityConfidence.HIGH
        if rows is not None and bytes_ is not None and not unique_unknown
        else SelectivityConfidence.LOW
        if cost is not None and not unique_unknown
        else SelectivityConfidence.UNKNOWN
    )
    if confidence is SelectivityConfidence.LOW and telemetry is False:
        confidence = SelectivityConfidence.UNKNOWN
    return SelectivityEstimate(
        candidate_id=cid,
        estimated_rows=rows,
        estimated_bytes=bytes_,
        estimated_cost=cost if confidence is not SelectivityConfidence.UNKNOWN else None,
        confidence=confidence,
        basis=tuple(dict.fromkeys(basis)),
        unknown_reasons=unique_unknown,
    )


def _pivot_match(filters: Sequence[tuple[str, str]], pivots: Sequence[Any]) -> bool:
    values: set[str] = set()
    for pivot in pivots:
        if isinstance(pivot, Mapping):
            value = pivot.get("value")
        else:
            value = getattr(pivot, "value", None)
        if isinstance(value, str) and value:
            values.add(value)
    return any(value in values for _field, value in filters)


def rank_query_candidates(
    proposals: Sequence[QueryProposal | Mapping[str, Any]],
    *,
    hunt_id: str,
    approved_question_order: Sequence[str],
    open_question_ids: Sequence[str] | None,
    approved_scope: Mapping[str, Any] | None,
    discovery: Mapping[str, Any] | None,
    policy: SPLPolicy | None,
    linked_pivots: Sequence[Any] | None = None,
    history: Sequence[QueryHistoryObservation | Mapping[str, Any]] | None = None,
    now: datetime | None = None,
    candidate_cap: int = DEFAULT_CANDIDATE_CAP,
) -> QueryRankingResult:
    """Normalize and rank a bounded candidate set for shadow comparison.

    Approved question order is always the primary ordering key.  If any
    non-structural ranking input is unknown, the candidate receives no score
    and the returned order remains approved question order followed by its
    stable candidate ID.
    """

    if not isinstance(proposals, Sequence) or isinstance(proposals, (str, bytes, bytearray)):
        raise QueryStrategyError("proposals must be a finite sequence", reason_code="candidate_set_invalid")
    if not isinstance(candidate_cap, int) or isinstance(candidate_cap, bool) or not 1 <= candidate_cap <= MAX_CANDIDATE_CAP:
        raise QueryStrategyError(
            f"candidate_cap must be between 1 and {MAX_CANDIDATE_CAP}",
            reason_code="candidate_cap_invalid",
        )
    if len(proposals) > candidate_cap:
        raise QueryStrategyError(
            f"candidate set exceeds cap of {candidate_cap}",
            reason_code="candidate_cap_exceeded",
        )
    if not isinstance(hunt_id, str) or not hunt_id.strip():
        raise QueryStrategyError("hunt_id must be non-empty", reason_code="missing_hunt_id")
    plan_order = tuple(item.strip() for item in approved_question_order if isinstance(item, str) and item.strip())
    if not plan_order or len(set(plan_order)) != len(plan_order):
        raise QueryStrategyError(
            "approved question order must contain unique non-empty IDs",
            reason_code="approved_question_order_invalid",
        )
    open_questions = (
        tuple(item.strip() for item in open_question_ids if isinstance(item, str) and item.strip())
        if open_question_ids is not None
        else None
    )
    if open_questions is not None and len(set(open_questions)) != len(open_questions):
        raise QueryStrategyError("open question IDs must be unique", reason_code="open_questions_invalid")

    normalized: list[tuple[int, QueryProposal, str]] = []
    rejected: list[RejectedCandidate] = []
    seen: set[str] = set()
    duplicates: list[str] = []
    for index, raw in enumerate(proposals):
        try:
            proposal = _coerce_proposal(raw)
            cid = candidate_id(hunt_id, proposal)
        except QueryStrategyError as exc:
            raise QueryStrategyError(
                f"candidate {index} is invalid: {exc}",
                reason_code=exc.reason_code,
            ) from exc
        if cid in seen:
            duplicates.append(cid)
            continue
        seen.add(cid)
        normalized.append((index, proposal, cid))

    provisional: list[tuple[tuple[Any, ...], RankedQueryCandidate]] = []
    for source_index, proposal, cid in normalized:
        question_position = plan_order.index(proposal.question_id) if proposal.question_id in plan_order else len(plan_order)
        if proposal.question_id not in plan_order:
            rejected.append(RejectedCandidate(source_index, cid, "question_not_in_approved_plan"))
            continue
        if open_questions is None:
            question_component: int | None = None
            question_reason = "open_questions_unknown"
        elif proposal.question_id in open_questions:
            question_component = _SCORE_COMPONENTS["unresolved_question"]
            question_reason = None
        else:
            rejected.append(RejectedCandidate(source_index, cid, "question_not_open"))
            continue

        if policy is None:
            rejected.append(RejectedCandidate(source_index, cid, "policy_unavailable"))
            continue
        validation = policy.validate(proposal, open_question_ids=open_questions)
        if not validation.allowed:
            rejected.append(RejectedCandidate(source_index, cid, "policy_rejected"))
            continue
        telemetry, telemetry_reason = _telemetry_confirmed(
            proposal, scope=approved_scope, discovery=discovery,
        )
        telemetry_component = _SCORE_COMPONENTS["approved_telemetry"] if telemetry is True else None
        filters = _extract_filters(proposal)
        scope_component, scope_reason, matched_entities = _scope_specificity(
            proposal, scope=approved_scope, filters=filters,
        )
        selectivity = estimate_selectivity(
            proposal,
            hunt_id=hunt_id,
            approved_scope=approved_scope,
            discovery=discovery,
            policy=policy,
            history=history,
            open_question_ids=open_questions,
            now=now,
        )
        if linked_pivots is None:
            pivot_component: int | None = None
            pivot_reason = "linked_pivots_unknown"
        else:
            pivot_component = _SCORE_COMPONENTS["evidence_pivot"] if _pivot_match(filters, linked_pivots) else 0
            pivot_reason = None
        if history is None:
            duplicate_component: int | None = None
            duplicate_reason = "history_unknown"
        else:
            duplicate_component = _SCORE_COMPONENTS["not_already_answered"]
            if selectivity.estimated_rows is not None:
                duplicate_component = 0
                duplicate_reason = "equivalent_completed_query"
            else:
                duplicate_reason = None
        selectivity_component = (
            _round_half_up(
                _SCORE_COMPONENTS["selectivity"]
                * (1 - selectivity.estimated_cost / 100)
            )
            if selectivity.estimated_cost is not None
            else None
        )
        components: dict[str, int | None] = {
            "unresolved_question": question_component,
            "approved_telemetry": telemetry_component,
            "evidence_pivot": pivot_component,
            "scope_specificity": scope_component,
            "selectivity": selectivity_component,
            "not_already_answered": duplicate_component,
        }
        unknown_reasons = list(selectivity.unknown_reasons)
        unknown_reasons.extend(
            reason
            for reason in (question_reason, telemetry_reason, scope_reason, pivot_reason, duplicate_reason)
            if reason is not None
        )
        unknown_reasons = list(dict.fromkeys(unknown_reasons))
        score = sum(components.values()) if not unknown_reasons and all(value is not None for value in components.values()) else None
        fallback_reason = None if score is not None else (unknown_reasons[0] if unknown_reasons else "ranking_input_unknown")
        ranked = RankedQueryCandidate(
            candidate_id=cid,
            proposal=proposal,
            approved_question_position=question_position,
            shadow_rank=0,
            score=score,
            score_components=components,
            selectivity=selectivity,
            fallback_reason=fallback_reason,
        )
        # Unknown scores deliberately sort after known scores only within the
        # same approved question; the approved question position is primary.
        sort_key = (
            question_position,
            0 if score is not None else 1,
            -(score or 0),
            cid,
        )
        provisional.append((sort_key, ranked))

    provisional.sort(key=lambda item: item[0])
    ranked_items: list[RankedQueryCandidate] = []
    for rank, (_sort_key, item) in enumerate(provisional, start=1):
        ranked_items.append(item.__class__(
            candidate_id=item.candidate_id,
            proposal=item.proposal,
            approved_question_position=item.approved_question_position,
            shadow_rank=rank,
            score=item.score,
            score_components=item.score_components,
            selectivity=item.selectivity,
            fallback_reason=item.fallback_reason,
        ))
    return QueryRankingResult(
        ranked=tuple(ranked_items),
        rejected=tuple(rejected),
        duplicates_removed=tuple(duplicates),
    )


__all__ = [
    "DEFAULT_CANDIDATE_CAP",
    "MAX_CANDIDATE_CAP",
    "QueryHistoryObservation",
    "QueryRankingResult",
    "QueryStrategyError",
    "RankedQueryCandidate",
    "RejectedCandidate",
    "STRATEGY_VERSION",
    "SelectivityConfidence",
    "SelectivityEstimate",
    "candidate_id",
    "estimate_selectivity",
    "rank_query_candidates",
]
