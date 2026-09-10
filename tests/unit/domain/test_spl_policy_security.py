"""Regression tests for textual SPL scope enforcement."""

from datetime import datetime, timezone

import pytest

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


def test_raw_projection_preserves_source_identity_and_time():
    proposal = _proposal("search index=main sourcetype=sysmon | table host | fields host | sort 0 host")
    result = _policy().validate(proposal)
    assert result.allowed
    assert result.normalized_spl == (
        "search index=main sourcetype=sysmon | table host index sourcetype _time _cd"
        " | fields host index sourcetype _time _cd | sort 0 host"
    )
    assert proposal.spl.endswith("table host | fields host | sort 0 host")


def test_aggregate_projection_does_not_change_grouping_or_counts():
    spl = "search index=main sourcetype=sysmon | stats count by host | table host count"
    proposal = _proposal(spl).model_copy(update={"result_mode": ResultMode.AGGREGATE})
    result = _policy().validate(proposal)
    assert result.allowed and result.normalized_spl == spl


@pytest.mark.parametrize("pipeline", [
    "fields - index", "fields -index", "fields - source*", "fields - _*", "fields - *", "fields -*",
    "eval index=\"invented\"", "eval _time=0", "rename sourcetype as source_kind", "rename host AS index",
])
def test_raw_query_cannot_remove_or_rewrite_source_metadata(pipeline):
    result = _policy().validate(_proposal("search index=main sourcetype=sysmon | " + pipeline))
    assert not result.allowed and "source_metadata_modified" in result.reason_codes


@pytest.mark.parametrize("mode,cap", [("aggregate", 500), ("representative", 10_000), ("targeted", 10_000)])
def test_policy_enforces_shared_result_caps(mode: str, cap: int) -> None:
    proposal = _proposal("search index=main sourcetype=sysmon | fields host")
    values = proposal.model_dump() | {"result_mode": mode, "max_results": cap}
    proposal = QueryProposal.model_validate(values)
    result = _policy().validate(proposal)
    assert result.allowed
    assert result.enforced_limits.max_results == cap
    # Policy still rejects an oversized proposal if a caller bypasses Pydantic.
    invalid = proposal.model_copy(update={"max_results": cap + 1})
    assert not _policy().validate(invalid).allowed


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


@pytest.mark.parametrize(
    "spl",
    [
        "search index=main OR index=* sourcetype=sysmon | head 100",
        "search index=main sourcetype=sysmon OR NOT index=main | head 100",
        "search index=main* sourcetype=sysmon | head 100",
        "search index=main sourcetype=sysmon OR sourcetype!=sysmon | head 100",
    ],
)
def test_spl_rejects_non_exact_or_negated_scope_predicates(spl: str) -> None:
    result = _policy().validate(_proposal(spl))

    assert not result.allowed
    assert {"index_scope_not_exact", "sourcetype_scope_not_exact"}.intersection(result.reason_codes)


def test_spl_allows_scope_fields_in_post_search_aggregation() -> None:
    result = _policy().validate(
        _proposal("search index=main sourcetype=sysmon | stats count by index sourcetype")
    )

    assert result.allowed
    assert result.reason_codes == []


@pytest.mark.parametrize("depth", [1, 2, 5])
def test_grouped_implicit_search_is_normalized_for_the_splunk_api(depth: int) -> None:
    expression = "(" * depth + "index=main sourcetype=sysmon" + ")" * depth + " | table index sourcetype host"
    result = _policy().validate(_proposal(expression))
    explicit = _policy().validate(_proposal("search " + expression))
    assert result.allowed
    assert result.normalized_spl == explicit.normalized_spl == "search " + expression + " _time _cd"
    assert result.cache_key == explicit.cache_key


@pytest.mark.parametrize("expression", [
    '(index=main sourcetype=sysmon) OR host="unbounded"',
    '(index=secret sourcetype=sysmon)',
    '(index=main sourcetype=sysmon) | delete',
    '(index=main sourcetype=sysmon',
])
def test_grouped_implicit_search_retains_source_and_command_guards(expression: str) -> None:
    assert not _policy().validate(_proposal(expression)).allowed


def test_multisource_search_rejects_contradiction_from_spl_or_precedence() -> None:
    policy = SPLPolicy(
        discovered_indexes={"dns", "network"}, discovered_sourcetypes={"dns:events", "net:events"},
        discovered_fields={"host"}, approved_indexes={"dns", "network"},
        approved_sourcetypes={"dns:events", "net:events"}, approved_earliest_utc=NOW,
        approved_latest_utc=datetime(2026, 1, 2, tzinfo=timezone.utc),
        connection_id="splunk-local", execution_config_snapshot_id="snapshot-1",
    )
    proposal = _proposal(
        'search (index=dns sourcetype="dns:events" OR index=network sourcetype="net:events") '
        '(host="ws-01" OR host="srv-05") | stats count by index sourcetype'
    ).model_copy(update={"indexes": ["dns", "network"], "sourcetypes": ["dns:events", "net:events"]})
    rejected = policy.validate(proposal)
    assert not rejected.allowed
    assert "source_scope_contradictory" in rejected.reason_codes
    corrected = proposal.model_copy(update={"spl": proposal.spl.replace(
        '(index=dns sourcetype="dns:events" OR index=network sourcetype="net:events")',
        '((index=dns sourcetype="dns:events") OR (index=network sourcetype="net:events"))',
    )})
    assert policy.validate(corrected).allowed


@pytest.mark.parametrize("spl", [
    'search (index=main sourcetype=sysmon) OR host="unbounded"',
    'search index=main (sourcetype=sysmon OR host="unbounded")',
    'search sourcetype=sysmon (index=main OR host="unbounded")',
])
def test_every_boolean_branch_must_constrain_both_sources(spl: str) -> None:
    result = _policy().validate(_proposal(spl))
    assert not result.allowed
    assert "source_scope_unbounded" in result.reason_codes


@pytest.mark.parametrize("spl", [
    'search index=main sourcetype=sysmon (host="AND" OR host="OR")',
    'search (index = "main") AND (sourcetype = "sysmon") NOT (host="a" OR host="b")',
    'search index=main OR host="other" sourcetype=sysmon index=main',
])
def test_boolean_scope_proof_preserves_bounded_search_filters(spl: str) -> None:
    assert _policy().validate(_proposal(spl)).allowed


@pytest.mark.parametrize("expression", [
    '(index=main sourcetype=sysmon', 'index=main sourcetype=sysmon)',
    'index=main sourcetype=sysmon OR', 'index=main AND AND sourcetype=sysmon',
    'NOT (host="a" OR (index=main sourcetype=sysmon))',
    '(' * 40 + 'index=main sourcetype=sysmon' + ')' * 40,
])
def test_unprovable_source_expressions_are_rejected(expression: str) -> None:
    assert not _policy().validate(_proposal('search ' + expression)).allowed
