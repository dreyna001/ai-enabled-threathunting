from __future__ import annotations

import ssl
import threading

import pytest

from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models import (
    BaseModelAdapter,
    BedrockModelAdapter,
    FakeModelAdapter,
    LiteLLMModelAdapter,
    ModelConfiguration,
    ModelFactory,
    ModelRequest,
    ModelUsage,
    OpenAIModelAdapter,
)


def request() -> ModelRequest:
    return ModelRequest(
        messages=[{"role": "user", "content": "Return JSON"}],
        max_output_tokens=50,
        response_format={"type": "json_object"},
    )


class FakeOpenAIClient:
    class Chat:
        class Completions:
            @staticmethod
            def create(**kwargs: object) -> object:
                FakeOpenAIClient.last_payload = kwargs
                return {
                    "id": "req-1",
                    "model": "gpt-test",
                    "choices": [{"message": {"content": '{"answer":"ok"}'}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                }

        completions = Completions()

    chat = Chat()
    last_payload: dict[str, object] = {}


class FakeBedrockClient:
    def converse(self, **kwargs: object) -> object:
        self.last_payload = kwargs
        return {
            "output": {"message": {"content": [{"text": '{"answer":"ok"}'}]}},
            "usage": {"inputTokens": 3, "outputTokens": 2, "totalTokens": 5},
            "stopReason": "end_turn",
            "ResponseMetadata": {"RequestId": "req-2"},
        }


def test_openai_adapter_normalizes_structured_response_and_usage() -> None:
    client = FakeOpenAIClient()
    response = OpenAIModelAdapter("gpt-test", api_key="secret", client=client).complete(request())
    assert response.provider_name == "openai"
    assert response.model_name == "gpt-test"
    assert response.structured == {"answer": "ok"}
    assert response.usage == ModelUsage(3, 2, 5)
    assert FakeOpenAIClient.last_payload["model"] == "gpt-test"
    assert "secret" not in repr(response)


def test_openai_adapter_allows_explicit_lab_tls_override() -> None:
    adapter = OpenAIModelAdapter(
        "gpt-test",
        api_key="secret",
        verify_tls=False,
        allow_insecure=True,
        client=FakeOpenAIClient(),
    )

    assert adapter.verify_tls is False


def test_model_request_rejects_caller_supplied_system_message() -> None:
    with pytest.raises(ValueError, match="system field"):
        ModelRequest(messages=[{"role": "system", "content": "untrusted"}])


def test_model_request_snapshots_messages_after_role_validation() -> None:
    messages = [{"role": "user", "content": {"parts": ["safe"]}}]
    model_request = ModelRequest(messages=messages)

    messages[0]["role"] = "system"
    messages[0]["content"]["parts"].append("forged")

    assert model_request.as_messages() == [
        {"role": "user", "content": {"parts": ["safe"]}},
    ]


def test_openai_payload_prepends_trusted_system_and_preserves_supported_roles() -> None:
    model_request = ModelRequest(
        system="trusted instruction",
        messages=[
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": "answer"},
            {"role": "tool", "content": "result", "tool_call_id": "call-1"},
        ],
    )

    payload = OpenAIModelAdapter._request_payload(model_request, "gpt-test")

    assert payload["messages"] == [
        {"role": "system", "content": "trusted instruction"},
        {"role": "user", "content": "question"},
        {"role": "assistant", "content": "answer"},
        {"role": "tool", "content": "result", "tool_call_id": "call-1"},
    ]


def test_openai_payload_uses_completion_token_field_for_newer_models() -> None:
    model_request = ModelRequest(
        messages=[{"role": "user", "content": "question"}],
        max_output_tokens=32,
    )

    payload = OpenAIModelAdapter._request_payload(model_request, "gpt-5.5")

    assert payload["max_completion_tokens"] == 32
    assert "max_tokens" not in payload


def test_bedrock_adapter_uses_converse_contract() -> None:
    client = FakeBedrockClient()
    response = BedrockModelAdapter("anthropic.test", region_name="us-east-1", client=client).complete(request())
    assert response.provider_name == "bedrock"
    assert response.structured == {"answer": "ok"}
    assert response.usage.total_tokens == 5
    assert client.last_payload["modelId"] == "anthropic.test"


@pytest.mark.parametrize(
    "endpoint",
    [
        "not-a-url",
        "ftp://bedrock.example/runtime",
        "https://user:password@bedrock.example/runtime",
        "https://",
        "http://bedrock.example/runtime",
        "https://bedrock.example/runtime?token=secret",
        "https://bedrock.example/runtime#fragment",
    ],
)
def test_bedrock_endpoint_validation_rejects_unsafe_urls(endpoint: str) -> None:
    with pytest.raises(ValueError):
        ModelConfiguration(provider="bedrock", model_name="anthropic.test", endpoint=endpoint)
    with pytest.raises(ValueError):
        BedrockModelAdapter("anthropic.test", endpoint=endpoint, client=FakeBedrockClient())


def test_bedrock_metadata_exposes_safe_origin() -> None:
    response = BedrockModelAdapter(
        "anthropic.test",
        region_name="us-east-1",
        endpoint="https://bedrock.example/runtime",
        client=FakeBedrockClient(),
    ).complete(request())

    assert response.provider_metadata == {
        "region": "us-east-1",
        "endpoint": "https://bedrock.example",
    }


def test_litellm_adapter_preserves_local_endpoint() -> None:
    client = FakeOpenAIClient()
    response = LiteLLMModelAdapter("local-model", endpoint="https://llm.example/v1", api_key="local", client=client).complete(request())
    assert response.provider_name == "litellm"
    assert response.provider_metadata["endpoint"] == "https://llm.example"


@pytest.mark.parametrize(
    "endpoint",
    [
        "not-a-url",
        "ftp://llm.example/v1",
        "https://user:password@llm.example/v1",
        "https://",
        "http://llm.example/v1",
        "https://llm.example/v1?token=secret",
        "https://llm.example/v1#fragment",
    ],
)
def test_openai_compatible_endpoint_validation_rejects_unsafe_urls(endpoint: str) -> None:
    with pytest.raises(ValueError):
        ModelConfiguration(provider="litellm", model_name="local-model", endpoint=endpoint)
    with pytest.raises(ValueError):
        LiteLLMModelAdapter("local-model", endpoint=endpoint, client=FakeOpenAIClient())


def test_openai_compatible_metadata_exposes_safe_origin() -> None:
    response = LiteLLMModelAdapter(
        "local-model",
        endpoint="https://llm.example/v1",
        client=FakeOpenAIClient(),
    ).complete(request())

    assert response.provider_metadata == {"endpoint": "https://llm.example"}


def test_model_configuration_masks_plaintext_api_key() -> None:
    configuration = ModelConfiguration(provider="openai", model_name="gpt-test", api_key="secret")

    assert "secret" not in repr(configuration)
    assert configuration.api_key is not None
    assert configuration.api_key.get_secret_value() == "secret"


def test_http_endpoint_is_rejected_even_when_tls_verification_is_disabled() -> None:
    with pytest.raises(ValueError, match="https"):
        ModelConfiguration(
            provider="litellm",
            model_name="local-model",
            endpoint="http://llm.example/v1",
            verify_tls=False,
            ca_bundle_path="/tmp/lab-ca.pem",
        )


def test_model_adapter_classifies_tls_failures_before_oserror() -> None:
    error = BaseModelAdapter.normalize_provider_error(
        ssl.SSLCertVerificationError("certificate verify failed"),
        operation="complete",
    )

    assert error.category is FailureCategory.TLS_CERTIFICATE_FAILURE


def test_fake_adapter_is_deterministic_and_records_calls() -> None:
    adapter = FakeModelAdapter(responses=['{"step":1}', '{"step":2}'])
    first = adapter.complete(request())
    second = adapter.complete(request())
    assert first.structured == {"step": 1}
    assert second.structured == {"step": 2}
    assert adapter.call_count == 2


def test_factory_selects_provider_without_implicit_failover() -> None:
    fake = ModelFactory.create({"provider": "fake", "model_name": "test"})
    assert isinstance(fake, FakeModelAdapter)
    local = ModelFactory.create({"provider": "local", "model_name": "test", "endpoint": "https://llm.example/v1"})
    assert isinstance(local, LiteLLMModelAdapter)
    with pytest.raises(ValueError):
        ModelFactory.create({"provider": "litellm", "model_name": "test"})


class MalformedOpenAIClient:
    class Chat:
        class Completions:
            @staticmethod
            def create(**kwargs: object) -> object:
                return {"choices": {"message": {"content": "not a list"}}}

        completions = Completions()

    chat = Chat()


class SlowOpenAIClient:
    started = threading.Event()
    release = threading.Event()

    class Chat:
        class Completions:
            @staticmethod
            def create(**kwargs: object) -> object:
                SlowOpenAIClient.started.set()
                SlowOpenAIClient.release.wait(timeout=1)
                return {"choices": [{"message": {"content": "late"}}]}

        completions = Completions()

    chat = Chat()


class NonNumericStatusError(Exception):
    status_code = "service-unavailable"


def test_openai_malformed_response_is_a_safe_adapter_error() -> None:
    with pytest.raises(AdapterError) as error:
        OpenAIModelAdapter("gpt-test", client=MalformedOpenAIClient()).complete(request())

    assert error.value.category is FailureCategory.UNKNOWN
    assert "malformed" in str(error.value)


def test_model_timeout_is_bounded_and_normalized() -> None:
    SlowOpenAIClient.started.clear()
    SlowOpenAIClient.release.clear()
    try:
        with pytest.raises(AdapterError) as error:
            OpenAIModelAdapter("gpt-test", client=SlowOpenAIClient(), timeout_seconds=0.01).complete(request())
    finally:
        SlowOpenAIClient.release.set()

    assert error.value.category is FailureCategory.HARD_TIMEOUT


def test_provider_status_with_non_numeric_value_does_not_crash_normalization() -> None:
    error = BaseModelAdapter.normalize_provider_error(NonNumericStatusError(), operation="complete")

    assert error.category is FailureCategory.UNKNOWN


def test_failed_model_call_is_recorded_before_a_caller_retry() -> None:
    adapter = FakeModelAdapter(errors=[TimeoutError("provider timeout")], responses=["{\"ok\":true}"])

    with pytest.raises(AdapterError) as error:
        adapter.complete(request())
    assert error.value.category is FailureCategory.HARD_TIMEOUT
    assert adapter.call_count == 1

    response = adapter.complete(request())
    assert response.structured == {"ok": True}
    assert adapter.call_count == 2
