"""Failures remain diagnosable without retaining credential-bearing error text."""

import logging
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from threat_hunting.domain.errors import FailureCategory, failure_metadata
from threat_hunting.integrations.models.base import BaseModelAdapter, ModelRequest
from threat_hunting.integrations.models.bedrock import BedrockModelAdapter
from threat_hunting.main import create_app
from threat_hunting.services.orchestration import ModelContractError


def test_failure_metadata_never_persists_exception_text():
    secret = "token=not-a-real-credential"
    assert failure_metadata(RuntimeError(secret)) == {"category": "unknown", "error_type": "RuntimeError"}
    metadata = failure_metadata(ModelContractError("Test", secret, attempts=1))
    assert metadata["category"] == "model_output_invalid"
    assert secret not in str(metadata)


@pytest.mark.parametrize("provider", ["openai", "bedrock"])
def test_bad_provider_configuration_is_nonretryable_and_logs_no_response_body(provider, caplog):
    class ProviderError(Exception):
        pass
    error = ProviderError("sensitive request and credential")
    if provider == "openai":
        error.status_code = 400
    else:
        error.response = {"ResponseMetadata": {"HTTPStatusCode": 400}, "Error": {"Message": "sensitive"}}
    with caplog.at_level(logging.WARNING):
        normalized = BaseModelAdapter.normalize_provider_error(error, operation="complete")
    assert normalized.category == FailureCategory.INVALID_CONFIGURATION
    assert "sensitive" not in caplog.text
    assert "status=400" in caplog.text


def test_http_diagnostics_use_template_paths_and_server_generated_request_ids(caplog, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = create_app()
    @app.get("/diagnostic/{item}")
    def diagnostic(item: str):
        return {"ok": True}
    with caplog.at_level(logging.INFO), TestClient(app) as client:
        response = client.get("/diagnostic/private-input?token=private-query", headers={"X-Request-ID": "untrusted-request-id"})
    assert response.status_code == 200
    UUID(response.headers["X-Request-ID"])
    records = [record.getMessage() for record in caplog.records if record.name == "threat_hunting.main"]
    assert any("route=/diagnostic/{item}" in message for message in records)
    assert all("private-input" not in message and "private-query" not in message for message in records)


def test_bedrock_transport_uses_the_call_deadline_and_disables_hidden_retries(monkeypatch):
    import boto3
    clients, configurations = [], []
    def factory(**kwargs):
        configurations.append(kwargs["config"])
        client = SimpleNamespace(
            closed=False,
            converse=lambda **_: {"output": {"message": {"content": [{"text": "{}"}]}}},
        )
        client.close = lambda: setattr(client, "closed", True)
        clients.append(client)
        return client
    monkeypatch.setattr(boto3, "client", factory)
    adapter = BedrockModelAdapter("test", region_name="us-east-1", timeout_seconds=30)
    request = ModelRequest(messages=[{"role": "user", "content": "synthetic"}])
    try:
        adapter.complete(request, timeout_seconds=2)
        adapter.complete(request, timeout_seconds=1)
        assert [config.read_timeout for config in configurations] == [2, 1]
        assert all(config.retries["max_attempts"] == 0 for config in configurations)
        assert clients[0].closed
    finally:
        adapter.close()
    assert clients[-1].closed


@pytest.mark.parametrize("body", [
    {"code": "credit_balance_exhausted", "type": "insufficient_quota"},
    {"code": "insufficient_quota"},
    {"error": {"type": "insufficient_quota"}},
])
def test_exhausted_provider_quota_is_distinct_nonretryable_and_safe(body, caplog):
    import httpx
    from openai import RateLimitError
    from threat_hunting.domain.errors import max_retries_for
    from threat_hunting.integrations.models.openai import OpenAIModelAdapter
    from threat_hunting.integrations.errors import AdapterError
    from threat_hunting.services.orchestration import StrictModelRunner
    from threat_hunting.domain.contracts import HuntPlan

    body = {**body, "message": "private billing account and token=secret"}
    provider_error = RateLimitError("private billing account and token=secret", body=body,
        response=httpx.Response(429, request=httpx.Request("POST", "https://model.example/chat/completions")))
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        raise provider_error

    adapter = OpenAIModelAdapter("test-model", client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    runner = StrictModelRunner(adapter)
    try:
        with caplog.at_level(logging.WARNING), pytest.raises(AdapterError) as error:
            runner.run(HuntPlan, user_payload={})
    finally:
        adapter.close()
    assert error.value.category == FailureCategory.PROVIDER_QUOTA_EXHAUSTED
    assert max_retries_for(error.value.category) == 0
    assert "restore API capacity" in str(error.value)
    assert len(calls) == runner.counters.failed_model_calls == 1
    assert runner.counters.model_repair_attempts == 0
    assert failure_metadata(error.value)["category"] == "provider_quota_exhausted"
    assert "private billing" not in caplog.text + str(error.value)
    assert "token=secret" not in caplog.text + str(error.value)


@pytest.mark.parametrize("body", [None, "unexpected", {"code": "rate_limit_exceeded"},
    {"message": "insufficient_quota in unrelated text"}, {"error": []}, {"code": ["insufficient_quota"]}])
def test_temporary_rate_limits_remain_distinct_from_quota(body):
    from threat_hunting.domain.errors import max_retries_for

    error = RuntimeError("provider message must not determine classification")
    error.status_code = 429
    error.body = body
    normalized = BaseModelAdapter.normalize_provider_error(error, operation="complete")
    assert normalized.category == FailureCategory.RATE_LIMITED
    assert max_retries_for(normalized.category) == 1
