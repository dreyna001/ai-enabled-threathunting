"""Regression tests for textual SPL scope enforcement."""

from datetime import datetime, timezone

from threat_hunting.domain.contracts import QueryProposal, ResultMode
from threat_hunting.domain.spl_policy import SPLPolicy


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _policy() -> SPLPolicy:
    return SPLPolicy(
        discovered_indexes={"main"},
        discovered_sourcetypes={"sysmon"},
        discovered_fields={"host"},
        approved_indexes={"main"},
        approved_sourcetypes={"sysmon"},
        approved_earliest_utc=NOW,
        approved_latest_utc=datetime(2026, 1, 2, tzinfo=timezone.utc),
        connection_id="splunk-local",
        execution_config_snapshot_id="snapshot-1",
    )


def _proposal(spl: str, *, indexes: list[str] | None = None) -> QueryProposal:
    return QueryProposal(
        question_id="q1",
        purpose="answer approved question",
        expected_information_gain="identify scoped hosts",
        spl=spl,
        earliest_utc=NOW,
        latest_utc=datetime(2026, 1, 2, tzinfo=timezone.utc),
        indexes=["main"] if indexes is None else indexes,
        sourcetypes=["sysmon"],
        requested_fields=["host"],
        result_mode=ResultMode.REPRESENTATIVE,
        max_results=100,
    )


def test_spl_text_cannot_contradict_approved_metadata() -> None:
    result = _policy().validate(
        _proposal("search index=secret sourcetype=sysmon | head 100")
    )

    assert not result.allowed
    assert "index_metadata_mismatch" in result.reason_codes


def test_spl_requires_explicit_scope_and_typed_time_authority() -> None:
    result = _policy().validate(
        _proposal(
            "search sourcetype=sysmon earliest=-30d | head 100",
            indexes=[],
        )
    )

    assert not result.allowed
    assert {"index_scope_missing", "inline_time_not_allowed"} <= set(result.reason_codes)
