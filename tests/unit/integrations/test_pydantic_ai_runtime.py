import json

from pydantic import BaseModel

from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.integrations.models.pydantic_ai_runtime import complete_structured
from threat_hunting.services.orchestration import StrictModelRunner


class _Answer(BaseModel):
    observed: bool


def test_structured_step_uses_one_pydantic_ai_request():
    adapter = FakeModelAdapter(responses=[json.dumps({"observed": True})])
    result = StrictModelRunner(adapter).run(_Answer, user_payload={"facts": "untrusted"})
    assert result == _Answer(observed=True)
    assert adapter.call_count == 1


def test_complete_structured_returns_the_adapter_response():
    adapter = FakeModelAdapter(responses=[json.dumps({"observed": False})])
    from threat_hunting.integrations.models.base import ModelRequest

    response = complete_structured(
        adapter,
        ModelRequest(messages=[{"role": "user", "content": "{}"}], system="Return JSON."),
    )
    assert response.structured == {"observed": False}
    assert adapter.call_count == 1
