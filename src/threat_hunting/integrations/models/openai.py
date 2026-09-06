"""OpenAI and OpenAI-compatible model adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from pydantic import SecretStr

from threat_hunting.domain.errors import FailureCategory

from ..errors import AdapterError
from .base import (
    BaseModelAdapter,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    _as_secret,
    _usage_from_mapping,
    parse_structured,
)


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _content_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        text = value.get("text") or value.get("content")
        return text if isinstance(text, str) else ""
    if isinstance(value, (list, tuple)):
        return "".join(_content_text(part) for part in value)
    return str(value)


def _validate_endpoint(endpoint: str, *, verify_tls: bool) -> str:
    """Validate a model endpoint and return its safe origin."""

    if not isinstance(endpoint, str) or not endpoint or endpoint != endpoint.strip():
        raise ValueError("model endpoint must be an absolute http(s) URL")
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("model endpoint must be an absolute http(s) URL") from exc
    if parsed.scheme != "https" or not hostname or any(char.isspace() for char in hostname):
        raise ValueError("model endpoint must be an absolute https URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("model endpoint must not embed credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("model endpoint must not include a query or fragment")
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    return f"{parsed.scheme}://{host}{f':{port}' if port is not None else ''}"


class OpenAIModelAdapter(BaseModelAdapter):
    """Thin wrapper over ``openai.OpenAI`` chat completions.

    A client can be injected for tests.  The SDK import and credential use are
    lazy, which keeps unit tests independent of provider packages and secrets.
    """

    provider = ModelProvider.OPENAI

    def __init__(
        self,
        model_name: str,
        *,
        api_key: SecretStr | str | None = None,
        endpoint: str | None = None,
        verify_tls: bool = True,
        ca_bundle_path: str | Path | None = None,
        allow_insecure: bool = False,
        timeout_seconds: float = 120.0,
        client: Any | None = None,
    ) -> None:
        if not model_name.strip():
            raise ValueError("model_name must not be empty")
        endpoint_origin = "openai"
        if endpoint is not None:
            endpoint_origin = _validate_endpoint(endpoint, verify_tls=verify_tls)
        if not verify_tls and ca_bundle_path is None and not allow_insecure:
            # An explicit lab override is owned by runtime configuration.  The
            # adapter accepts verify=False only when its caller deliberately
            # supplies the override through ``allow_insecure`` below.
            raise ValueError("TLS verification cannot be disabled without a CA or explicit lab override")
        if timeout_seconds <= 0 or timeout_seconds > 600:
            raise ValueError("timeout_seconds is outside the supported bound")
        self.model_name = model_name
        self.api_key = _as_secret(api_key)
        self.endpoint = endpoint
        self._endpoint_origin = endpoint_origin
        self.verify_tls = verify_tls
        self.ca_bundle_path = Path(ca_bundle_path) if ca_bundle_path is not None else None
        self.allow_insecure = allow_insecure
        self.timeout_seconds = timeout_seconds
        self._client = client

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AdapterError(FailureCategory.INVALID_CONFIGURATION, "the openai package is not installed", operation="connect") from exc
        kwargs: dict[str, Any] = {
            "api_key": self.api_key.get_secret_value() if self.api_key else None,
            "base_url": self.endpoint,
            "timeout": self.timeout_seconds,
        }
        # OpenAI's client accepts an httpx client for custom CA bundles.  Keep
        # the import optional and fail clearly if a custom bundle is unusable.
        if self.ca_bundle_path is not None or not self.verify_tls:
            try:
                import httpx

                kwargs["http_client"] = httpx.Client(
                    verify=str(self.ca_bundle_path) if self.ca_bundle_path else self.verify_tls,
                    timeout=self.timeout_seconds,
                )
            except (ImportError, OSError) as exc:
                raise AdapterError(FailureCategory.INVALID_CONFIGURATION, "model TLS configuration is unavailable", operation="connect") from exc
        try:
            self._client = OpenAI(**kwargs)
        except Exception as exc:  # noqa: BLE001 - no provider detail is exposed
            raise self.normalize_provider_error(exc, operation="connect") from exc
        return self._client

    @staticmethod
    def _request_payload(request: ModelRequest, model_name: str) -> dict[str, Any]:
        messages = request.as_messages()
        if request.system is not None:
            messages.insert(0, {"role": "system", "content": request.system})
        payload: dict[str, Any] = {"model": model_name, "messages": messages}
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.max_output_tokens is not None:
            token_field = "max_completion_tokens" if model_name.lower().startswith(("gpt-5", "gpt-6")) else "max_tokens"
            payload[token_field] = request.max_output_tokens
        if request.response_format is not None:
            payload["response_format"] = dict(request.response_format)
        if request.tools:
            payload["tools"] = [dict(tool) for tool in request.tools]
        return payload

    def complete(
        self,
        request: ModelRequest,
        *,
        timeout_seconds: float | None = None,
        cancellation_token: Any = None,
    ) -> ModelResponse:
        payload = self._request_payload(request, self.model_name)
        client = self._get_client()

        def call() -> Any:
            chat = getattr(client, "chat", None)
            completions = getattr(chat, "completions", None) if chat is not None else None
            create = getattr(completions, "create", None) if completions is not None else None
            if not callable(create):
                responses = getattr(client, "responses", None)
                create = getattr(responses, "create", None) if responses is not None else None
            if not callable(create):
                raise RuntimeError("OpenAI client does not expose a supported completion method")
            try:
                return create(timeout=timeout_seconds or self.timeout_seconds, **payload)
            except TypeError:
                # Simple fakes and older SDKs may not accept a per-call timeout;
                # the surrounding bounded call still enforces one.
                return create(**payload)

        response = self._bounded_call(
            "complete",
            call,
            timeout_seconds=timeout_seconds,
            cancellation_token=cancellation_token,
        )
        choices_value = _get(response, "choices", None)
        output_text = _get(response, "output_text", None)
        if choices_value is None:
            choices: list[Any] = []
        elif isinstance(choices_value, (list, tuple)):
            choices = list(choices_value)
        else:
            raise AdapterError(FailureCategory.UNKNOWN, "model provider returned a malformed response", operation="complete")
        first = choices[0] if choices else None
        if first is None and (not isinstance(output_text, str) or not output_text):
            raise AdapterError(FailureCategory.UNKNOWN, "model provider returned a malformed response", operation="complete")
        message = _get(first, "message", first)
        text = _content_text(_get(message, "content", output_text if isinstance(output_text, str) else ""))
        tool_calls_raw = _get(message, "tool_calls", []) or []
        tool_calls = [dict(call) for call in tool_calls_raw if isinstance(call, Mapping)]
        response_model = _get(response, "model", self.model_name)
        usage = _usage_from_mapping(_get(response, "usage"))
        request_id = _get(response, "id") or _get(response, "request_id")
        finish_reason = _get(first, "finish_reason") if first is not None else _get(response, "stop_reason")
        return ModelResponse(
            provider=self.provider,
            model_name=str(response_model or self.model_name),
            text=text,
            structured=parse_structured(text),
            usage=usage,
            finish_reason=str(finish_reason) if finish_reason is not None else None,
            request_id=str(request_id) if request_id is not None else None,
            tool_calls=tool_calls,
            provider_metadata={"endpoint": self._endpoint_origin},
        )


class LiteLLMModelAdapter(OpenAIModelAdapter):
    """OpenAI-compatible adapter for a local LiteLLM/vLLM endpoint."""

    provider = ModelProvider.LITELLM

    def __init__(
        self,
        model_name: str,
        *,
        endpoint: str,
        api_key: SecretStr | str | None = None,
        verify_tls: bool = True,
        ca_bundle_path: str | Path | None = None,
        allow_insecure: bool = False,
        timeout_seconds: float = 120.0,
        client: Any | None = None,
    ) -> None:
        if not endpoint:
            raise ValueError("LiteLLM endpoint is required")
        super().__init__(
            model_name,
            api_key=api_key,
            endpoint=endpoint,
            verify_tls=verify_tls,
            ca_bundle_path=ca_bundle_path,
            allow_insecure=allow_insecure,
            timeout_seconds=timeout_seconds,
            client=client,
        )


OpenAIAdapter = OpenAIModelAdapter
LocalOpenAICompatibleAdapter = LiteLLMModelAdapter
LiteLLMAdapter = LiteLLMModelAdapter


__all__ = [
    "LiteLLMAdapter",
    "LiteLLMModelAdapter",
    "LocalOpenAICompatibleAdapter",
    "OpenAIAdapter",
    "OpenAIModelAdapter",
]
