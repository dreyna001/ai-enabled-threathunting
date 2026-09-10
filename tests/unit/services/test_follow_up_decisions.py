import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from threat_hunting.domain.contracts import QueryProposal
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.services.orchestration import StrictModelRunner
from threat_hunting.services.reports import _derive_report_limitations
from threat_hunting.services.investigation import _follow_up_decision_contract, _follow_up_proposal_errors


def test_empty_follow_up_output_requires_repair_and_explicit_skip_reason():
    decision = {"question_id": "q-next", "proposal": None, "skip_reason": "Authentication telemetry is unavailable in approved scope."}
    model = FakeModelAdapter(responses=["[]", json.dumps([decision])])
    runner = StrictModelRunner(model)
    result = runner.run(
        _follow_up_decision_contract(["q-next"]),
        user_payload={"follow_up_questions": [{"question_id": "q-next"}]},
        contract_name="FollowUpDecision[]",
    )
    assert runner.counters.model_repair_attempts == 1
    assert result[0].skip_reason == decision["skip_reason"]
    limitations = _derive_report_limitations({
        "queries": [], "follow_up_questions": [{"question_id": "q-next"}],
        "follow_up_decisions": [result[0].model_dump(mode="json")],
    })
    assert any(decision["skip_reason"] in item for item in limitations)


@pytest.mark.parametrize("decisions", [
    [],
    [{"question_id": "other", "proposal": None, "skip_reason": "Unavailable."}],
    [{"question_id": "q-next", "proposal": None, "skip_reason": "   "}],
    [{"question_id": "q-next", "proposal": None, "skip_reason": None}],
    [{"question_id": "q-next", "proposal": None, "skip_reason": "Unavailable."}] * 2,
])
def test_every_follow_up_requires_one_valid_decision(decisions):
    with pytest.raises(ValidationError):
        _follow_up_decision_contract(["q-next"]).validate_python(decisions)


def test_authentication_pivot_can_use_user_in_source_evidence_not_only_extracted_process():
    now = datetime.now(timezone.utc)
    proposal = QueryProposal(
        question_id="q-next", purpose="Trace the observed account", expected_information_gain="Account activity",
        spl='index=auth sourcetype=auth user="alice"',
        earliest_utc=now, latest_utc=now + timedelta(hours=1),
        indexes=["auth"], sourcetypes=["auth"], requested_fields=["user"], result_mode="targeted", max_results=10,
    )
    questions = [{
        "question_id": "q-next", "source_query_id": "source-query", "source_evidence_ids": ["row-1"],
        "grounded_entities": [{"entity_type": "process", "value": "tool.exe"}],
    }]
    evidence = [{"evidence_id": "row-1", "query_id": "source-query", "selected_result": {"_raw": '{"user":"alice","process":"tool.exe"}'}}]
    assert _follow_up_proposal_errors([proposal], questions, evidence=evidence) == {}
    assert "evidence-grounded pivot" in _follow_up_proposal_errors(
        [proposal.model_copy(update={"spl": 'index=auth sourcetype=auth user="invented"'})],
        questions, evidence=evidence,
    )["q-next"]
    assert "evidence-grounded pivot" in _follow_up_proposal_errors(
        [proposal], questions, evidence=[{**evidence[0], "query_id": "wrong-query"}],
    )["q-next"]
