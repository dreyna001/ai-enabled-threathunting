"""Amazon Bedrock Converse model adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from pydantic import SecretStr

from threat_hunting.domain.errors import FailureCategory

from ..errors import AdapterError
from .base import (
    BaseModelAdapter,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    _usage_from_mapping,
    parse_structured,
)
from .openai import _validate_endpoint


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return value.get("text", "") if isinstance(value.get("text", ""), str) else ""
    return str(value) if value is not None else ""


class BedrockModelAdapter(BaseModelAdapter):
    """Thin, provider-neutral wrapper over Bedrock Runtime ``converse``."""

    provider = ModelProvider.BEDROCK

    def __init__(
        self,
        model_name: str,
        *,
        region_name: str | None = None,
        endpoint: str | None = None,
        verify_tls: bool = True,
        ca_bundle_path: str | Path | None = None,
        allow_insecure: bool = False,
        timeout_seconds: float = 120.0,
        client: Any | None = None,
    ) -> None:
        if not model_name.strip():
            raise ValueError("model_name must not be empty")
        endpoint_origin = "bedrock"
        if endpoint is not None:
            endpoint_origin = _validate_endpoint(endpoint, verify_tls=verify_tls)
        if not verify_tls and ca_bundle_path is None and not allow_insecure:
            raise ValueError("TLS verification cannot be disabled without an explicit lab override")
        if timeout_seconds <= 0 or timeout_seconds > 600:
            raise ValueError("timeout_seconds is outside the supported bound")
        self.model_name = model_name
        self.region_name = region_name
        self.endpoint = endpoint
        self._endpoint_origin = endpoint_origin
        self.verify_tls = verify_tls
        self.ca_bundle_path = Path(ca_bundle_path) if ca_bundle_path is not None else None
        self.timeout_seconds = timeout_seconds
        self._client = client

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3  # type: ignore[import-not-found]
            from botocore.config import Config  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AdapterError(FailureCategory.INVALID_CONFIGURATION, "the boto3 package is not installed", operation="connect") from exc
        config = Config(
            connect_timeout=int(self.timeout_seconds),
            read_timeout=int(self.timeout_seconds),
            retries={"max_attempts": 0, "mode": "standard"},
        )
        kwargs: dict[str, Any] = {
            "service_name": "bedrock-runtime",
            "region_name": self.region_name,
            "config": config,
            "verify": str(self.ca_bundle_path) if self.ca_bundle_path else self.verify_tls,
        }
        if self.endpoint:
            kwargs["endpoint_url"] = self.endpoint
        try:
            self._client = boto3.client(**kwargs)
        except Exception as exc:  # noqa: BLE001 - normalized without credential detail
            raise self.normalize_provider_error(exc, operation="connect") from exc
        return self._client

    @staticmethod
    def _request_payload(request: ModelRequest) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        system_parts: list[dict[str, str]] = []
        if request.system:
            system_parts.append({"text": request.system})
        for source in request.messages:
            role = str(source["role"])
            content = source.get("content")
            if role == "system":
                if isinstance(content, str):
                    system_parts.append({"text": content})
                continue
            if isinstance(content, str):
                blocks: list[dict[str, Any]] = [{"text": content}]
            elif isinstance(content, list):
                blocks = [dict(block) for block in content if isinstance(block, Mapping)]
            else:
                blocks = [{"text": str(content)}]
            messages.append({"role": role, "content": blocks})
        payload: dict[str, Any] = {"messages": messages}
        if system_parts:
            payload["system"] = system_parts
        inference: dict[str, Any] = {}
        if request.temperature is not None:
            inference["temperature"] = request.temperature
        if request.max_output_tokens is not None:
            inference["maxTokens"] = request.max_output_tokens
        if inference:
            payload["inferenceConfig"] = inference
        if request.tools:
            payload["toolConfig"] = {"tools": [dict(tool) for tool in request.tools]}
        return payload

    def complete(
        self,
        request: ModelRequest,
        *,
        timeout_seconds: float | None = None,
        cancellation_token: Any = None,
    ) -> ModelResponse:
        payload = self._request_payload(request)
        client = self._get_client()

        def call() -> Any:
            converse = getattr(client, "converse", None)
            if not callable(converse):
                raise RuntimeError("Bedrock client does not expose converse")
            return converse(modelId=self.model_name, **payload)

        response = self._bounded_call(
            "complete",
            call,
            timeout_seconds=timeout_seconds,
            cancellation_token=cancellation_token,
        )
        output = _get(response, "output", {}) or {}
        message = _get(output, "message", output) or {}
        blocks = _get(message, "content", []) or []
        texts = [_text(block) for block in blocks]
        text = "".join(part for part in texts if part)
        tool_calls: list[Mapping[str, Any]] = []
        for block in blocks:
            tool_use = _get(block, "toolUse")
            if isinstance(tool_use, Mapping):
                tool_calls.append(dict(tool_use))
        usage = _usage_from_mapping(_get(response, "usage"))
        request_id = _get(response, "ResponseMetadata", {})
        if isinstance(request_id, Mapping):
            request_id = request_id.get("RequestId")
        request_id = request_id or _get(response, "requestId")
        stop_reason = _get(response, "stopReason")
        provider_metadata = {"region": self.region_name or "default"}
        if self.endpoint is not None:
            provider_metadata["endpoint"] = self._endpoint_origin
        return ModelResponse(
            provider=self.provider,
            model_name=self.model_name,
            text=text,
            structured=parse_structured(text),
            usage=usage,
            finish_reason=str(stop_reason) if stop_reason is not None else None,
            request_id=str(request_id) if request_id is not None else None,
            tool_calls=tool_calls,
            provider_metadata=provider_metadata,
        )


BedrockAdapter = BedrockModelAdapter


__all__ = ["BedrockAdapter", "BedrockModelAdapter"]
