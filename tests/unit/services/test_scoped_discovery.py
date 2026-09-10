"""Historical hunt schemas and reviewed discovery bindings."""

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.integrations.splunk import SplunkDiscovery
from threat_hunting.services.orchestration import sha256_json
from threat_hunting.services.workflow import Conflict, IntegrationUnavailable, WorkflowService, hunts, workflow_metadata


SCOPE = {"earliest_utc": "2026-01-01T00:00:00Z", "latest_utc": "2026-01-05T00:00:00Z",
         "indexes": ["network"], "sourcetypes": ["network:events"]}


class HistoricalDiscovery:
    def __init__(self):
        self.calls = []

    def discover(self, **kwargs):
        self.calls.append(kwargs)
        scoped = "source_pairs" in kwargs
        fields = ["host", "dest_ip", "dest_port"] if scoped else ["host"]
        return SplunkDiscovery(
            discovered_at_utc=datetime(2026, 9, 9, tzinfo=timezone.utc),
            indexes=["network"], sourcetypes=["network:events"], fields=fields,
            representative_schemas={"network:events": fields} if scoped else {},
            time_coverage={"network": {"earliest": SCOPE["earliest_utc"], "latest": "2026-01-12T00:10:00Z"}},
            accelerated_data_models=[], tstats_available=None, errors=[], complete=True,
            coverage_limitations=["Field samples are not exhaustive."] if scoped else [],
        )


def setup_hunt(*, change_final_scope=False, threat_intelligence="", omit_intelligence_refs=False):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    connector = HistoricalDiscovery()
    contexts = []

    def response(request):
        context = json.loads(request.messages[0]["content"])
        contexts.append(context)
        ids = context["application_assigned_ids"]
        scope = dict(context.get("required_scope", SCOPE))
        if change_final_scope and context["planning_stage"] == "grounded_plan":
            scope["latest_utc"] = "2026-01-06T00:00:00Z"
        output = {
            "schema_version": "1.0", "plan_id": ids["plan_id"], "plan_version": 1,
            "hunt_id": context["hunt_id"], "discovery_snapshot_id": ids["discovery_snapshot_id"],
            "execution_config_snapshot_id": ids["execution_config_snapshot_id"],
            "hypothesis": "Investigate historical network activity", "objective": "Identify observed destinations",
            "scope": scope, "intelligence_refs": [],
            "data_sources": [{"index": "network", "sourcetypes": ["network:events"], "purpose": "Network activity"}],
            "questions": [{"question_id": "unknown", "question": "Which destinations were contacted?",
                           "rationale": "Scope assessment", "expected_information_gain": "Observed destination IPs and ports"}],
            "query_strategy": ["Use observed destination fields"], "coverage_limitations": [],
            "created_at_utc": "2026-09-09T00:00:00Z",
        }
        if omit_intelligence_refs:
            assert "intelligence_refs" not in request.response_format["json_schema"]["schema"]["properties"]
            output.pop("intelligence_refs")
        return json.dumps(output)

    service = WorkflowService(engine, splunk_connector=connector, model_adapter=FakeModelAdapter(responses=[response, response]),
                              execution_config={"provider": "fake", "model_name": "fixture"})
    hunt = service.create_hunt("owner", title="Historical network", hypothesis="h", objective="o", threat_intelligence=threat_intelligence)
    return service, hunt["hunt_id"], connector, contexts


def test_application_binds_supplied_advisory_to_plan_without_model_copying_its_id():
    service, identifier, _, contexts = setup_hunt(threat_intelligence="Advisory text supplied by the analyst.", omit_intelligence_refs=True)
    result = service.discover("owner", identifier)
    sources = result["discovery_snapshot"]["input_context"]["intelligence_sources"]
    assert len(sources) == 1
    assert sources[0]["kind"] == "analyst_supplied_context"
    assert result["plan"]["intelligence_refs"] == [sources[0]["source_id"]]
    assert all(context["analyst_supplied_context"]["intelligence_sources"] == sources for context in contexts)


def test_plan_edits_cannot_invent_an_advisory_reference():
    service, identifier, _, _ = setup_hunt()
    result = service.discover("owner", identifier)
    plan = json.loads(json.dumps(result["plan"]))
    plan["intelligence_refs"] = ["local_stix_play_ransomware_advisory"]
    from threat_hunting.services.workflow import Validation
    with pytest.raises(Validation, match="intelligence reference"):
        service.save_plan("owner", identifier, expected_version=1, plan=plan)
    assert service.get_hunt("owner", identifier)["plan"] == result["plan"]


def test_approval_rejects_an_unbound_historical_advisory_reference():
    service, identifier, _, _ = setup_hunt()
    result = service.discover("owner", identifier)
    plan = result["plan"]
    plan["intelligence_refs"] = ["invented-source"]
    with service.engine.begin() as connection:
        connection.execute(update(hunts).where(hunts.c.hunt_id == identifier).values(plan=plan))
    with pytest.raises(Conflict, match="intelligence reference"):
        service.approve("owner", identifier, "reviewed")
    assert service.get_hunt("owner", identifier)["state"] == "awaiting_plan_review"


def test_final_plan_receives_historical_fields_and_binds_the_scoped_snapshot():
    service, identifier, connector, contexts = setup_hunt()
    result = service.discover("owner", identifier)
    assert len(contexts) == 2
    assert connector.calls[0] == {"include_indexed_sources": True}  # No raw-event search before scope selection.
    assert connector.calls[1]["earliest_utc"].isoformat() == "2026-01-01T00:00:00+00:00"
    assert connector.calls[1]["latest_utc"].isoformat() == "2026-01-05T00:00:00+00:00"
    assert connector.calls[1]["source_pairs"] == [("network", "network:events")]
    assert "dest_port" in contexts[1]["discovery_snapshot"]["payload"]["representative_schemas"]["network:events"]
    assert contexts[1]["required_scope"] == SCOPE
    snapshot = result["discovery_snapshot"]
    assert result["plan"]["discovery_snapshot_id"] == snapshot["snapshot_id"]
    assert snapshot["sha256"] == sha256_json({"kind": snapshot["kind"], "payload": snapshot["payload"]})
    assert result["state"] == "awaiting_plan_review"
    assert "Field samples are not exhaustive." in result["plan"]["coverage_limitations"]
    assert service.approve("owner", identifier, "reviewed")["state"] == "approved"


def test_final_model_response_cannot_change_the_sampled_scope():
    service, identifier, connector, contexts = setup_hunt(change_final_scope=True)
    with pytest.raises(IntegrationUnavailable):
        service.discover("owner", identifier)
    assert len(contexts) == 2
    assert len(connector.calls) == 2
    assert service.get_hunt("owner", identifier)["state"] == "failed"


def test_analyst_scope_edit_refreshes_discovery_without_rewriting_their_plan():
    service, identifier, connector, contexts = setup_hunt()
    result = service.discover("owner", identifier)
    old_snapshot = result["discovery_snapshot"]["snapshot_id"]
    plan = result["plan"]
    plan["scope"]["latest_utc"] = "2026-01-04T00:00:00Z"
    plan["questions"][0]["question"] = "Analyst's exact investigation question"
    saved = service.save_plan("owner", identifier, expected_version=1, plan=plan)
    assert len(contexts) == 2  # Editing does not invoke a model.
    assert len(connector.calls) == 3
    assert connector.calls[-1]["latest_utc"].isoformat() == "2026-01-04T00:00:00+00:00"
    assert saved["plan"]["questions"][0]["question"] == "Analyst's exact investigation question"
    assert saved["plan_version"] == saved["plan"]["plan_version"] == 2
    assert saved["plan"]["discovery_snapshot_id"] != old_snapshot
    assert saved["plan"]["discovery_snapshot_id"] == saved["discovery_snapshot"]["snapshot_id"]
    assert service.approve("owner", identifier, "reviewed edited plan")["state"] == "approved"


def test_approval_rejects_a_stale_scope_binding():
    service, identifier, _, _ = setup_hunt()
    result = service.discover("owner", identifier)
    plan = result["plan"]
    plan["scope"]["latest_utc"] = "2026-01-04T00:00:00Z"
    with service.engine.begin() as connection:
        connection.execute(update(hunts).where(hunts.c.hunt_id == identifier).values(plan=plan))
    with pytest.raises(Conflict, match="discovery snapshot"):
        service.approve("owner", identifier, "reviewed")


def test_scope_edit_discovery_failure_preserves_the_reviewed_plan(monkeypatch):
    service, identifier, connector, _ = setup_hunt()
    original = service.discover("owner", identifier)
    edited = json.loads(json.dumps(original["plan"]))
    edited["scope"]["latest_utc"] = "2026-01-04T00:00:00Z"

    def unavailable(**kwargs):
        raise AdapterError(FailureCategory.TEMPORARY_NETWORK, "unavailable", operation="discover")

    monkeypatch.setattr(connector, "discover", unavailable)
    with pytest.raises(IntegrationUnavailable, match="previous plan is unchanged"):
        service.save_plan("owner", identifier, expected_version=1, plan=edited)
    persisted = service.get_hunt("owner", identifier)
    assert persisted["plan"] == original["plan"]
    assert persisted["discovery_snapshot"] == original["discovery_snapshot"]
    assert persisted["plan_version"] == 1
    assert persisted["state"] == "awaiting_plan_review"
