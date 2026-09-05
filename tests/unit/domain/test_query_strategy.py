"""Deterministic query-strategy domain tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("threat_hunting.domain.spl_policy")

from threat_hunting.domain.contracts import QueryProposal
from threat_hunting.domain.query_strategy import (
    QueryStrategyError,
    SelectivityConfidence,
    candidate_id,
    estimate_selectivity,
    rank_query_candidates,
)
from threat_hunting.domain.spl_policy import SPLPolicy


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def timestamp(minutes: int = 0) -> datetime:
    """Return one deterministic timezone-aware timestamp."""

    return BASE_TIME + timedelta(minutes=minutes)


def proposal(
    question_id: str = "q-1",
    *,
    earliest: int = 0,
    latest: int = 60,
    max_results: int = 20,
    filter_text: str = "host=server1",
    purpose: str = "Find representative process events.",
) -> QueryProposal:
    """Build one policy-valid candidate proposal."""

    return QueryProposal.model_validate(
        {
            "question_id": question_id,
            "purpose": purpose,
            "expected_information_gain": "Identify affected hosts and processes.",
            "spl": f"search index=main sourcetype=sysmon {filter_text} | table host process_name",
            "earliest_utc": timestamp(earliest),
            "latest_utc": timestamp(latest),
            "indexes": ["main"],
            "sourcetypes": ["sysmon"],
            "requested_fields": ["host", "process_name"],
            "result_mode": "representative",
            "max_results": max_results,
        }
    )


@pytest.fixture
def scope() -> dict[str, object]:
    """Return the complete approved hunt scope."""

    return {
        "earliest_utc": timestamp(),
        "latest_utc": timestamp(60),
        "indexes": ["main"],
        "sourcetypes": ["sysmon"],
        "entities": [{"field": "host", "value": "server1"}],
    }


@pytest.fixture
def discovery() -> dict[str, object]:
    """Return complete discovery metadata for the approved scope."""

    return {
        "complete": True,
        "indexes": ["main"],
        "sourcetypes": ["sysmon"],
        "fields": ["host", "process_name", "event_id"],
    }


@pytest.fixture
def policy() -> SPLPolicy:
    """Return an immutable policy pinned to the test scope."""

    return SPLPolicy(
        discovered_indexes={"main"},
        discovered_sourcetypes={"sysmon"},
        discovered_fields={"host", "process_name", "event_id"},
        approved_indexes={"main"},
        approved_sourcetypes={"sysmon"},
        approved_earliest_utc=timestamp(),
        approved_latest_utc=timestamp(60),
        connection_id="connection-test",
        execution_config_snapshot_id="config-test",
    )


def rank_kwargs(scope: dict[str, object], discovery: dict[str, object], policy: SPLPolicy) -> dict[str, object]:
    """Return common deterministic ranking inputs."""

    return {
        "hunt_id": "hunt-test",
        "approved_question_order": ["q-1", "q-2"],
        "open_question_ids": ["q-1", "q-2"],
        "approved_scope": scope,
        "discovery": discovery,
        "policy": policy,
        "linked_pivots": [],
        "history": [],
        "now": timestamp(1),
    }


def test_malformed_candidate_set_fails_closed(scope, discovery, policy) -> None:
    """Malformed candidate input must not become an executable fallback."""

    raw = proposal().model_dump(mode="json")
    del raw["spl"]
    with pytest.raises(QueryStrategyError, match="invalid") as error:
        rank_query_candidates([raw], **rank_kwargs(scope, discovery, policy))
    assert error.value.reason_code == "candidate_invalid"


def test_unknown_inputs_are_explicit_and_preserve_approved_order(scope, policy) -> None:
    """Unknown discovery, pivots, history, and open questions never reorder."""

    first = proposal("q-1")
    second = proposal("q-2", filter_text="event_id=1")
    result = rank_query_candidates(
        [second, first],
        hunt_id="hunt-test",
        approved_question_order=["q-1", "q-2"],
        open_question_ids=None,
        approved_scope=scope,
        discovery=None,
        policy=policy,
        linked_pivots=None,
        history=None,
        now=None,
    )

    assert [item.proposal.question_id for item in result.ranked] == ["q-1", "q-2"]
    assert all(item.score is None for item in result.ranked)
    assert all(item.fallback_reason for item in result.ranked)
    assert all(item.selectivity.confidence is SelectivityConfidence.UNKNOWN for item in result.ranked)
    assert "discovery_unknown" in result.ranked[0].selectivity.unknown_reasons


def test_approved_question_is_primary_over_misleading_cheap_query(scope, discovery, policy) -> None:
    """A narrow, cheap later-question query cannot outrank the first question."""

    broad_first = proposal("q-1", latest=60, max_results=100)
    cheap_later = proposal("q-2", latest=1, max_results=1)
    result = rank_query_candidates(
        [cheap_later, broad_first],
        **rank_kwargs(scope, discovery, policy),
    )

    assert [item.proposal.question_id for item in result.ranked] == ["q-1", "q-2"]
    assert result.ranked[1].selectivity.estimated_cost is not None


def test_ties_use_stable_candidate_id_and_are_input_order_independent(scope, discovery, policy) -> None:
    """Equal candidates use their app-derived ID as a deterministic tie-break."""

    left = proposal("q-1", filter_text="event_id=1", purpose="A")
    right = proposal("q-1", filter_text="event_id=2", purpose="B")
    kwargs = rank_kwargs(scope, discovery, policy)
    forward = rank_query_candidates([left, right], **kwargs)
    reverse = rank_query_candidates([right, left], **kwargs)
    expected = sorted(candidate_id("hunt-test", item) for item in (left, right))

    assert [item.candidate_id for item in forward.ranked] == expected
    assert [item.candidate_id for item in reverse.ranked] == expected
    assert forward.to_dict() == reverse.to_dict()


def test_duplicate_candidates_are_deduplicated_by_stable_id(scope, discovery, policy) -> None:
    """Provider metadata cannot create a second identity for one proposal."""

    raw = proposal().model_dump(mode="json")
    raw["query_id"] = "provider-query-id"
    raw["idempotency_key"] = "provider-idempotency-key"
    result = rank_query_candidates(
        [raw, dict(raw)],
        **rank_kwargs(scope, discovery, policy),
    )

    cid = candidate_id("hunt-test", proposal())
    assert [item.candidate_id for item in result.ranked] == [cid]
    assert result.duplicates_removed == (cid,)


def test_candidate_cap_rejects_oversized_input(scope, discovery, policy) -> None:
    """The bounded contract rejects before any ranking work occurs."""

    with pytest.raises(QueryStrategyError) as error:
        rank_query_candidates(
            [proposal("q-1"), proposal("q-2")],
            candidate_cap=1,
            **rank_kwargs(scope, discovery, policy),
        )
    assert error.value.reason_code == "candidate_cap_exceeded"


def test_selectivity_unknown_inputs_return_no_fabricated_estimate(scope) -> None:
    """Missing policy, discovery, and history produce explicit unknowns."""

    estimate = estimate_selectivity(
        proposal(),
        hunt_id="hunt-test",
        approved_scope=scope,
        discovery=None,
        policy=None,
        history=None,
        now=None,
    )

    assert estimate.estimated_rows is None
    assert estimate.estimated_bytes is None
    assert estimate.estimated_cost is None
    assert estimate.confidence is SelectivityConfidence.UNKNOWN
    assert {"policy_unavailable", "discovery_unknown", "history_unavailable"} <= set(estimate.unknown_reasons)


def test_exact_compatible_history_supplies_observed_selectivity(scope, discovery, policy) -> None:
    """Only unexpired, complete, exact-cache observations supply rows/bytes."""

    candidate = proposal()
    validation = policy.validate(candidate, open_question_ids=["q-1"])
    assert validation.allowed and validation.cache_key is not None
    estimate = estimate_selectivity(
        candidate,
        hunt_id="hunt-test",
        approved_scope=scope,
        discovery=discovery,
        policy=policy,
        open_question_ids=["q-1"],
        history=[
            {
                "query_id": "ledger-1",
                "cache_key": validation.cache_key,
                "normalized_spl": validation.normalized_spl,
                "result_rows": 2,
                "result_bytes": 1024,
                "state": "completed",
                "outcome": "success",
                "truncated": False,
                "partial_fetch": False,
                "expires_at": timestamp(10),
            }
        ],
        now=timestamp(1),
    )

    assert estimate.estimated_rows == 2
    assert estimate.estimated_bytes == 1024
    assert estimate.confidence is SelectivityConfidence.HIGH
    assert estimate.unknown_reasons == ()
    assert "exact_compatible_history" in estimate.basis


def test_incomplete_history_is_ignored_without_fabricating_rows(scope, discovery, policy) -> None:
    """Truncated or malformed observations remain non-authoritative."""

    candidate = proposal()
    validation = policy.validate(candidate, open_question_ids=["q-1"])
    assert validation.allowed and validation.cache_key is not None
    estimate = estimate_selectivity(
        candidate,
        hunt_id="hunt-test",
        approved_scope=scope,
        discovery=discovery,
        policy=policy,
        open_question_ids=["q-1"],
        history=[
            {
                "query_id": "ledger-truncated",
                "cache_key": validation.cache_key,
                "normalized_spl": validation.normalized_spl,
                "result_rows": 99,
                "result_bytes": 999,
                "state": "completed",
                "outcome": "success",
                "truncated": True,
                "partial_fetch": False,
                "expires_at": timestamp(10),
            },
            {"query_id": "ledger-malformed", "result_rows": "not-an-int"},
        ],
        now=timestamp(1),
    )

    assert estimate.estimated_rows is None
    assert estimate.estimated_bytes is None
    assert estimate.confidence is SelectivityConfidence.LOW
    assert "no_exact_compatible_history" in estimate.basis


def test_scores_and_components_are_bounded(scope, discovery, policy) -> None:
    """The complete score is a bounded sum of bounded components."""

    result = rank_query_candidates([proposal()], **rank_kwargs(scope, discovery, policy))
    item = result.ranked[0]

    assert item.score is not None
    assert 0 <= item.score <= 100
    assert sum(value for value in item.score_components.values() if value is not None) == item.score
    assert item.selectivity.estimated_cost is not None
