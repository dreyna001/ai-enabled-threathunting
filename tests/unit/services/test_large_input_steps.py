from __future__ import annotations

import json
from uuid import uuid4

import pytest
from pydantic import TypeAdapter

from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.contracts import FollowUpDecision, HuntPlan, QueryAssessment, QueryProposal
from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models.base import ModelRequest
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.services.model_output import prepare_model_context, structured_response_format
from threat_hunting.services.orchestration import StrictModelRunner

REJECT_PADDING_CHARS = 900_000
ASSESSMENT_QUERY_ID = "0b1414b0-9ac7-42f5-b399-4fec5a0bd833"
SCOPE = {
    "earliest_utc": "2026-01-05T00:00:00Z",
    "latest_utc": "2026-01-09T00:00:00Z",
    "indexes": [
        "th_real_v1_endpoint",
        "th_real_v1_auth",
        "th_real_v1_dns",
        "th_real_v1_network",
    ],
    "sourcetypes": [
        "lab:normalized:endpoint",
        "lab:normalized:auth",
        "lab:normalized:dns",
        "lab:normalized:network",
    ],
}
DATA_SOURCES = [
    {"index": "th_real_v1_endpoint", "sourcetypes": ["lab:normalized:endpoint"], "purpose": "Endpoint execution and module loading."},
    {"index": "th_real_v1_auth", "sourcetypes": ["lab:normalized:auth"], "purpose": "Authentication activity for related hosts and users."},
    {"index": "th_real_v1_dns", "sourcetypes": ["lab:normalized:dns"], "purpose": "DNS activity associated with related processes and hosts."},
    {"index": "th_real_v1_network", "sourcetypes": ["lab:normalized:network"], "purpose": "Network connections involving related hosts and sessions."},
]
DISCOVERY_FIELDS = [
    "action", "answer_ip", "authentication_method", "collected_time_utc", "command_line", "dest_ip", "dest_port",
    "direction", "dns_query", "event_id", "event_time_utc", "file_hash", "file_name", "hash_type", "host", "image",
    "image_loaded", "index", "logon_type", "parent_process", "process", "process_guid", "process_id", "query_type",
    "result", "session_id", "source", "sourcetype", "src_ip", "transport", "user",
]
REPRESENTATIVE_SCHEMAS = {
    "lab:normalized:endpoint": ["action", "command_line", "event_id", "event_time_utc", "file_hash", "file_name", "host", "process", "process_guid", "user"],
    "lab:normalized:auth": ["action", "authentication_method", "event_id", "event_time_utc", "host", "logon_type", "result", "session_id", "user"],
    "lab:normalized:dns": ["answer_ip", "dns_query", "event_id", "event_time_utc", "host", "process", "query_type", "src_ip", "user"],
    "lab:normalized:network": ["dest_ip", "dest_port", "direction", "event_id", "event_time_utc", "host", "process", "src_ip", "transport", "user"],
}
ADVISORY_IOCS = {
    "file_hashes": [
        "0E408AED1ACF902A9F97ABF71CF0DD354024109C5D52A79054C421BE35D93549",
        "7DEA671BE77A2CA5772B86CF8831B02BFF0567BCE6A3AE023825AA40354F8ACA",
    ],
    "file_names": ["HRsword.exe", "SVCHost.dll"],
    "domains": [],
}
THREAT_INTELLIGENCE = (
    "Advisory context only: supplied Play ransomware indicator patterns are leads, not observed evidence.\n"
    "[(file:hashes.'SHA-256' = '0E408AED1ACF902A9F97ABF71CF0DD354024109C5D52A79054C421BE35D93549') AND file:name = 'HRsword.exe']\n"
    "[file:hashes.'SHA-256' = '7DEA671BE77A2CA5772B86CF8831B02BFF0567BCE6A3AE023825AA40354F8ACA']"
)
CUSTOMER_CONTEXT = (
    "Authorized non-production synthetic lab hunt of normalized endpoint, auth, DNS, and network telemetry "
    "during 2026-01-05T00:00:00Z through 2026-01-09T00:00:00Z exclusive."
)


def _expanded_limits() -> BudgetLimits:
    return BudgetLimits(
        hard_hunt_seconds=3600,
        query_start_cutoff_seconds=2880,
        max_inflight_query_seconds_after_cutoff=120,
        synthesis_allowance_seconds=600,
        max_model_calls=48,
        max_context_characters=800_000,
        max_model_input_tokens=5_000_000,
        max_model_output_tokens=512_000,
        max_model_output_tokens_per_call=64_000,
        max_model_call_timeout_seconds=600,
        max_representative_events=500,
        max_targeted_events=500,
    )


def _adaptive_limits(base: BudgetLimits, counters: BudgetCounters) -> BudgetLimits:
    return base.model_copy(update={
        "max_model_calls": base.max_model_calls - 1,
        "max_model_input_tokens": counters.model_input_tokens + (base.max_model_input_tokens - counters.model_input_tokens) // 2,
        "max_model_output_tokens": counters.model_output_tokens + (base.max_model_output_tokens - counters.model_output_tokens) // 2,
    })


def _preflight(
    runner: StrictModelRunner,
    contract: type | TypeAdapter,
    payload: dict[str, object],
    contract_name: str,
) -> dict[str, object]:
    context, references = prepare_model_context(payload, contract_name)
    body = json.dumps(context, ensure_ascii=False, sort_keys=True, default=str)
    response_format = structured_response_format(contract, contract_name, references)
    schema = json.dumps(response_format["json_schema"]["schema"], ensure_ascii=False, sort_keys=True)
    wrapper_key = contract_name.removesuffix("[]") if contract_name.endswith("[]") else None
    wrapper_instruction = (
        f' Because the response must be a JSON object, wrap the list exactly as {{"{wrapper_key}": [...]}}.'
        if wrapper_key is not None
        else ""
    )
    system = f"{runner.system_instruction} Required contract: {contract_name}.{wrapper_instruction} JSON Schema: {schema}"
    request = ModelRequest(
        system=system,
        messages=[{"role": "user", "content": body}],
        temperature=0,
        max_output_tokens=runner._output_allowance(),
        response_format=response_format,
    )
    characters, estimated_tokens = runner._request_sizes(request)
    return {
        "fits": runner._request_fits(request),
        "context_characters": characters,
        "estimated_input_tokens": estimated_tokens,
    }


def _query_proposal() -> dict[str, object]:
    return QueryProposal.model_validate({
        "question_id": "q1",
        "purpose": "Identify direct advisory hash or filename matches in scoped endpoint telemetry.",
        "expected_information_gain": "Returns event identifiers and contextual fields for each lead.",
        "spl": (
            'search index=th_real_v1_endpoint sourcetype=lab:normalized:endpoint '
            '(file_hash="0E408AED1ACF902A9F97ABF71CF0DD354024109C5D52A79054C421BE35D93549" '
            'OR file_name="HRsword.exe") '
            "| table event_id event_time_utc host user process file_name file_hash action"
        ),
        "earliest_utc": SCOPE["earliest_utc"],
        "latest_utc": SCOPE["latest_utc"],
        "indexes": ["th_real_v1_endpoint"],
        "sourcetypes": ["lab:normalized:endpoint"],
        "requested_fields": ["event_id", "event_time_utc", "host", "user", "process", "file_name", "file_hash", "action"],
        "result_mode": "representative",
        "max_results": 100,
    }).model_dump(mode="json")


def _build_fixture() -> tuple[dict[str, object], dict[str, object], HuntPlan]:
    hunt_id = str(uuid4())
    snapshot_id = str(uuid4())
    execution_config_snapshot_id = str(uuid4())
    intelligence_ref = "analyst-intelligence:02b6f32ae041530a05f6ab27d90d661686a254c4b8a057da1b12604fbfb32b7b"
    plan_payload = {
        "schema_version": "1.0",
        "plan_id": str(uuid4()),
        "plan_version": 1,
        "hunt_id": hunt_id,
        "discovery_snapshot_id": snapshot_id,
        "execution_config_snapshot_id": execution_config_snapshot_id,
        "hypothesis": "Activity associated with supplied advisory indicators may be present in scoped synthetic telemetry.",
        "objective": "Find matching observable activity and report scoped negative results without treating an IOC match as proof of an incident.",
        "scope": SCOPE,
        "intelligence_refs": [intelligence_ref],
        "data_sources": DATA_SOURCES,
        "questions": [
            {
                "question_id": "q1",
                "question": "Do scoped endpoint records contain an exact advisory hash or filename match?",
                "rationale": "Exact observable matches provide an auditable lead.",
                "expected_information_gain": "Identifies whether advisory observables occur in scope.",
            },
            {
                "question_id": "q2",
                "question": "What related endpoint execution records occur around each lead?",
                "rationale": "Endpoint telemetry can distinguish indicator matches from observed execution.",
                "expected_information_gain": "Establishes supported execution relationships and temporal sequencing.",
            },
            {
                "question_id": "q3",
                "question": "What authentication activity is associated with related hosts and users?",
                "rationale": "Authentication records can corroborate session context for endpoint leads.",
                "expected_information_gain": "Identifies related logon activity and session identifiers.",
            },
            {
                "question_id": "q4",
                "question": "What DNS and network activity is associated with related processes and hosts?",
                "rationale": "Communications records can support or limit spread conclusions.",
                "expected_information_gain": "Identifies observed communications involving related entities.",
            },
        ],
        "query_strategy": ["Start with exact advisory matches, then pivot on observed entities."],
        "coverage_limitations": ["Synthetic lab telemetry only; fixture provenance is not evidence of intent."],
        "created_at_utc": "2026-01-05T00:00:00Z",
    }
    plan = HuntPlan.model_validate(plan_payload)
    input_context = {
        "threat_intelligence": THREAT_INTELLIGENCE,
        "intelligence_sources": [{
            "source_id": intelligence_ref,
            "kind": "analyst_supplied_context",
            "content_field": "threat_intelligence",
            "content_sha256": "6b7111463ebaf23bc7d853b4752dc99ef9a1b3b7eca6cc7170d4d83fb07ef674",
        }],
        "advisory_iocs": ADVISORY_IOCS,
        "customer_context": CUSTOMER_CONTEXT,
    }
    discovery_payload = {
        "indexes": SCOPE["indexes"] + ["main", "summary"],
        "sourcetypes": SCOPE["sourcetypes"] + ["sysmon", "wineventlog", "stream:dns", "stream:tcp"],
        "fields": DISCOVERY_FIELDS,
        "representative_schemas": REPRESENTATIVE_SCHEMAS,
        "coverage_limitations": ["Field samples are not exhaustive."],
        "complete": True,
        "errors": [],
    }
    hunt = {
        "hunt_id": hunt_id,
        "hypothesis": plan_payload["hypothesis"],
        "objective": plan_payload["objective"],
        "threat_intelligence": THREAT_INTELLIGENCE,
        "plan": plan_payload,
        "discovery_snapshot": {
            "snapshot_id": snapshot_id,
            "kind": "splunk_discovery",
            "input_context": input_context,
            "payload": discovery_payload,
        },
    }
    proposal = _query_proposal()
    evidence_id = str(uuid4())
    results = {
        "queries": [{
            "query_id": ASSESSMENT_QUERY_ID,
            "question_id": "q1",
            "status": "completed",
            "purpose": proposal["purpose"],
            "spl": proposal["spl"],
            "result_count": 1,
            "truncated": False,
        }],
        "query_ledger": [{
            "query_id": ASSESSMENT_QUERY_ID,
            "status": "completed",
            "proposal": proposal,
        }],
        "evidence": [{
            "evidence_id": evidence_id,
            "query_id": ASSESSMENT_QUERY_ID,
            "event_time_utc": "2026-01-06T13:07:43Z",
            "evidence_kind": "raw_event",
            "index": "th_real_v1_endpoint",
            "sourcetype": "lab:normalized:endpoint",
            "selected_result": {
                "event_id": str(uuid4()),
                "event_time_utc": "2026-01-06T13:07:43Z",
                "action": "process_start",
                "host": "ws-17.corp.example",
                "user": "CORP\\j.smith",
                "session_id": "3cc97923-2cf1-5465-be13-735f603e5311",
                "process_guid": "7b0a41a9-acc0-5565-8176-81b3ca99829a",
                "process": "HRsword.exe",
                "file_name": "HRsword.exe",
                "file_hash": "0E408AED1ACF902A9F97ABF71CF0DD354024109C5D52A79054C421BE35D93549",
                "hash_type": "sha256",
            },
        }],
    }
    return hunt, results, plan


def _planning_context(hunt: dict[str, object], *, padding: int = 0) -> dict[str, object]:
    snapshot = hunt["discovery_snapshot"]
    plan = hunt["plan"]
    pairs = sorted({(source["index"], kind) for source in plan["data_sources"] for kind in source["sourcetypes"]})
    context = {
        "hunt_id": hunt["hunt_id"],
        "hypothesis": hunt["hypothesis"],
        "objective": hunt["objective"],
        "analyst_supplied_context": snapshot["input_context"],
        "discovery_snapshot": snapshot,
        "application_assigned_ids": {
            "plan_id": str(uuid4()),
            "discovery_snapshot_id": snapshot["snapshot_id"],
            "execution_config_snapshot_id": plan["execution_config_snapshot_id"],
        },
        "planning_rules": ["Preserve required scope exactly."],
        "planning_stage": "grounded_plan",
        "required_scope": plan["scope"],
        "required_source_pairs": pairs,
    }
    if padding:
        context["boundary_padding"] = "x" * padding
    return context


def _query_context(hunt: dict[str, object], plan: HuntPlan, *, padding: int = 0) -> dict[str, object]:
    discovery = hunt["discovery_snapshot"]["payload"]
    context = {
        "approved_plan": plan.model_dump(mode="json"),
        "discovery_scope": {
            "indexes": sorted(discovery["indexes"]),
            "sourcetypes": sorted(discovery["sourcetypes"]),
            "fields": sorted(discovery["fields"]),
            "representative_schemas": discovery.get("representative_schemas", {}),
            "approved_indexes": sorted(plan.scope.indexes),
            "approved_sourcetypes": sorted(plan.scope.sourcetypes),
            "earliest_utc": plan.scope.earliest_utc.isoformat().replace("+00:00", "Z"),
            "latest_utc": plan.scope.latest_utc.isoformat().replace("+00:00", "Z"),
        },
        "open_question_ids": [question.question_id for question in plan.questions],
        "advisory_iocs": snapshot_iocs(hunt),
        "proposal_rules": ["Use only approved scope."],
        "remaining_budget": {},
    }
    if padding:
        context["boundary_padding"] = "x" * padding
    return context


def snapshot_iocs(hunt: dict[str, object]) -> dict[str, object]:
    return hunt["discovery_snapshot"]["input_context"]["advisory_iocs"]


def _discovery_scope(hunt: dict[str, object], plan: HuntPlan) -> dict[str, object]:
    discovery = hunt["discovery_snapshot"]["payload"]
    return {
        "indexes": sorted(discovery["indexes"]),
        "sourcetypes": sorted(discovery["sourcetypes"]),
        "fields": sorted(discovery["fields"]),
        "representative_schemas": discovery.get("representative_schemas", {}),
        "approved_indexes": sorted(plan.scope.indexes),
        "approved_sourcetypes": sorted(plan.scope.sourcetypes),
        "earliest_utc": plan.scope.earliest_utc.isoformat().replace("+00:00", "Z"),
        "latest_utc": plan.scope.latest_utc.isoformat().replace("+00:00", "Z"),
    }


def _grounded_assessment(results: dict[str, object]) -> QueryAssessment:
    evidence = results["evidence"][0]
    evidence_id = str(evidence["evidence_id"])
    host = str(evidence["selected_result"]["host"])
    return QueryAssessment.model_validate({
        "query_id": ASSESSMENT_QUERY_ID,
        "question_id": "q1",
        "answered_question": True,
        "material_progress": True,
        "summary": "Observed one advisory-matched endpoint lead on the scoped host.",
        "new_entities": [{
            "entity_type": "host",
            "value": host,
            "result_row_refs": [evidence_id],
        }],
        "evidence_candidate_row_refs": [evidence_id],
        "coverage_changes": [],
        "limitations": ["Scripted assessment; not analytical output."],
        "proposed_next_question": {
            "question": "What related endpoint execution records occur around the observed host?",
            "rationale": "Endpoint telemetry can distinguish indicator matches from observed execution.",
            "expected_information_gain": "Establishes supported execution relationships and temporal sequencing.",
        },
    })


def _assessment_payload(hunt, plan, results, *, padding: int = 0) -> dict[str, object]:
    from threat_hunting.services.investigation import _assessment_context

    context = _assessment_context(
        plan,
        results,
        query_ids={ASSESSMENT_QUERY_ID},
        threat_intelligence=str(hunt["threat_intelligence"] or ""),
        limit=_expanded_limits().max_representative_events,
    )
    if padding:
        context["advisory_context"] = "x" * padding
    return context


def _follow_up_payload(hunt, plan, results, *, padding: int = 0) -> dict[str, object]:
    from threat_hunting.services.evidence import query_source_coverage
    from threat_hunting.services.investigation import (
        _balanced_evidence_sample,
        _materialize_follow_up_questions,
        _pending_investigation_questions,
    )
    from threat_hunting.services.threat_intel import query_ioc_context

    assessment = _grounded_assessment(results)
    assessments_payload, follow_up_questions = _materialize_follow_up_questions(
        [assessment], results, query_ids={ASSESSMENT_QUERY_ID},
    )
    completed_queries = [
        {
            key: query[key]
            for key in (
                "query_id", "question_id", "purpose", "spl", "earliest_utc",
                "latest_utc", "result_count", "truncated",
            )
            if key in query
        }
        for query in results["queries"]
    ]
    preferred_ids = {
        str(ref)
        for question in follow_up_questions
        for ref in question.get("source_evidence_ids", [])
    }
    pivot_evidence, _ = _balanced_evidence_sample(
        results.get("evidence", []),
        results.get("queries", []),
        preferred_evidence_ids=preferred_ids,
        limit=_expanded_limits().max_targeted_events,
    )
    context = {
        "approved_plan": plan.model_dump(mode="json"),
        "discovery_scope": _discovery_scope(hunt, plan),
        "follow_up_questions": _pending_investigation_questions(plan, results, follow_up_questions),
        "query_assessments": assessments_payload,
        "completed_queries": completed_queries,
        "source_coverage": query_source_coverage(results, supplied_evidence=pivot_evidence),
        "retained_evidence": [dict(item) for item in pivot_evidence],
        "advisory_iocs": query_ioc_context(str(hunt["threat_intelligence"] or "")),
        "proposal_rules": ["Use only follow_up_questions question IDs and the approved discovery scope."],
        "remaining_budget": {"splunk_queries": 10, "model_calls": 10, "agent_cycles": 5},
    }
    if padding:
        context["boundary_padding"] = "x" * padding
    return context


@pytest.fixture(scope="module")
def large_input_fixture():
    return _build_fixture()


def test_planning_fits_under_expanded_profile(large_input_fixture):
    hunt, _, plan = large_input_fixture
    limits = _expanded_limits()
    payload = _planning_context(hunt)
    adapter = FakeModelAdapter(responses=[json.dumps(plan.model_dump(mode="json"))] * 2)
    runner = StrictModelRunner(adapter, limits=limits)
    preflight = _preflight(runner, HuntPlan, payload, "HuntPlan")
    assert preflight["fits"] is True
    assert preflight["context_characters"] <= limits.max_context_characters
    runner.run(HuntPlan, user_payload=payload, contract_name="HuntPlan")
    assert adapter.call_count == 1


def test_planning_rejects_oversized_context_before_adapter_call(large_input_fixture):
    hunt, _, _ = large_input_fixture
    limits = _expanded_limits()
    payload = _planning_context(hunt, padding=REJECT_PADDING_CHARS)
    adapter = FakeModelAdapter(responses=["{}"])
    runner = StrictModelRunner(adapter, limits=limits)
    preflight = _preflight(runner, HuntPlan, payload, "HuntPlan")
    assert preflight["fits"] is False
    with pytest.raises(AdapterError, match="input budget") as error:
        runner.run(HuntPlan, user_payload=payload, contract_name="HuntPlan")
    assert error.value.category == FailureCategory.BUDGET_EXHAUSTED
    assert adapter.call_count == 0


def test_query_generation_fits_under_expanded_profile(large_input_fixture):
    hunt, results, plan = large_input_fixture
    limits = _expanded_limits()
    payload = _query_context(hunt, plan)
    adapter = FakeModelAdapter(responses=[json.dumps({"QueryProposal": [results["query_ledger"][0]["proposal"]]})])
    runner = StrictModelRunner(adapter, limits=limits)
    preflight = _preflight(runner, TypeAdapter(list[QueryProposal]), payload, "QueryProposal[]")
    assert preflight["fits"] is True
    runner.run(TypeAdapter(list[QueryProposal]), user_payload=payload, contract_name="QueryProposal[]")
    assert adapter.call_count == 1


def test_query_generation_rejects_oversized_context_before_adapter_call(large_input_fixture):
    hunt, _, plan = large_input_fixture
    limits = _expanded_limits()
    payload = _query_context(hunt, plan, padding=REJECT_PADDING_CHARS)
    adapter = FakeModelAdapter(responses=["[]"])
    runner = StrictModelRunner(adapter, limits=limits)
    preflight = _preflight(runner, TypeAdapter(list[QueryProposal]), payload, "QueryProposal[]")
    assert preflight["fits"] is False
    with pytest.raises(AdapterError, match="input budget") as error:
        runner.run(TypeAdapter(list[QueryProposal]), user_payload=payload, contract_name="QueryProposal[]")
    assert error.value.category == FailureCategory.BUDGET_EXHAUSTED
    assert adapter.call_count == 0


def test_assessment_fits_under_adaptive_reservation(large_input_fixture):
    hunt, results, plan = large_input_fixture
    limits = _expanded_limits()
    counters = BudgetCounters()
    payload = _assessment_payload(hunt, plan, results)
    def assessment_response(request: ModelRequest) -> str:
        context = json.loads(request.messages[0]["content"])
        query = context["completed_queries"][0]
        return json.dumps({"QueryAssessment": [{
            "query_id": query["query_id"],
            "question_id": query["question_id"],
            "answered_question": True,
            "material_progress": True,
            "summary": "Offline preflight only.",
            "new_entities": [],
            "evidence_candidate_row_refs": [],
            "coverage_changes": [],
            "limitations": ["Scripted assessment; not analytical output."],
            "proposed_next_question": None,
        }]})

    adapter = FakeModelAdapter(responses=[assessment_response] * 2)
    runner = StrictModelRunner(adapter, counters=counters, limits=_adaptive_limits(limits, counters))
    preflight = _preflight(runner, TypeAdapter(list[QueryAssessment]), payload, "QueryAssessment[]")
    assert preflight["fits"] is True
    runner.run(TypeAdapter(list[QueryAssessment]), user_payload=payload, contract_name="QueryAssessment[]")
    assert adapter.call_count == 1


def test_assessment_rejects_oversized_context_before_adapter_call(large_input_fixture):
    hunt, results, plan = large_input_fixture
    limits = _expanded_limits()
    counters = BudgetCounters()
    payload = _assessment_payload(hunt, plan, results, padding=REJECT_PADDING_CHARS)
    adapter = FakeModelAdapter(responses=["[]"])
    runner = StrictModelRunner(adapter, counters=counters, limits=_adaptive_limits(limits, counters))
    preflight = _preflight(runner, TypeAdapter(list[QueryAssessment]), payload, "QueryAssessment[]")
    assert preflight["fits"] is False
    with pytest.raises(AdapterError, match="input budget") as error:
        runner.run(TypeAdapter(list[QueryAssessment]), user_payload=payload, contract_name="QueryAssessment[]")
    assert error.value.category == FailureCategory.BUDGET_EXHAUSTED
    assert adapter.call_count == 0


# End-to-end synthesis reservation after oversized assessment rejection is covered by
# tests/integration/test_production_composition.py::test_oversized_assessment_preserves_retained_evidence_for_final_synthesis


def test_follow_up_decision_fits_under_adaptive_reservation(large_input_fixture):
    hunt, results, plan = large_input_fixture
    limits = _expanded_limits()
    counters = BudgetCounters()
    payload = _follow_up_payload(hunt, plan, results)

    def follow_up_response(request: ModelRequest) -> str:
        context = json.loads(request.messages[0]["content"])
        decisions = []
        for question in context["follow_up_questions"]:
            question_id = question["question_id"]
            if question.get("approved_question"):
                decisions.append({
                    "question_id": question_id,
                    "proposal": None,
                    "skip_reason": "Offline preflight only.",
                })
                continue
            proposal = dict(_query_proposal())
            proposal["question_id"] = question_id
            decisions.append({
                "question_id": question_id,
                "proposal": proposal,
                "skip_reason": None,
            })
        return json.dumps({"FollowUpDecision": decisions})

    adapter = FakeModelAdapter(responses=[follow_up_response] * 2)
    runner = StrictModelRunner(adapter, counters=counters, limits=_adaptive_limits(limits, counters))
    preflight = _preflight(runner, TypeAdapter(list[FollowUpDecision]), payload, "FollowUpDecision[]")
    assert preflight["fits"] is True
    runner.run(TypeAdapter(list[FollowUpDecision]), user_payload=payload, contract_name="FollowUpDecision[]")
    assert adapter.call_count == 1


def test_follow_up_decision_rejects_oversized_context_before_adapter_call(large_input_fixture):
    hunt, results, plan = large_input_fixture
    limits = _expanded_limits()
    counters = BudgetCounters()
    payload = _follow_up_payload(hunt, plan, results, padding=REJECT_PADDING_CHARS)
    adapter = FakeModelAdapter(responses=["[]"])
    runner = StrictModelRunner(adapter, counters=counters, limits=_adaptive_limits(limits, counters))
    preflight = _preflight(runner, TypeAdapter(list[FollowUpDecision]), payload, "FollowUpDecision[]")
    assert preflight["fits"] is False
    with pytest.raises(AdapterError, match="input budget") as error:
        runner.run(TypeAdapter(list[FollowUpDecision]), user_payload=payload, contract_name="FollowUpDecision[]")
    assert error.value.category == FailureCategory.BUDGET_EXHAUSTED
    assert adapter.call_count == 0
