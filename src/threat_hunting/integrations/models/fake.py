"""Deterministic model fake used by unit and component tests."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from typing import Any, Deque, Mapping

from threat_hunting.domain.errors import FailureCategory

from ..errors import AdapterError
from .base import BaseModelAdapter, ModelProvider, ModelRequest, ModelResponse, ModelUsage, parse_structured


class FakeModelAdapter(BaseModelAdapter):
    """Queue-based fake that records requests and never contacts a provider."""

    provider = ModelProvider.FAKE

    def __init__(
        self,
        model_name: str = "fake-model",
        *,
        responses: Iterable[ModelResponse | Mapping[str, Any] | str | Callable[[ModelRequest], Any]] | None = None,
        errors: Iterable[Exception] | None = None,
        default_text: str = '{"ok": true}',
        timeout_seconds: float = 120.0,
    ) -> None:
        if not model_name.strip():
            raise ValueError("model_name must not be empty")
        super().__init__()
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds
        self._responses: Deque[Any] = deque(responses or ())
        self._errors: Deque[Exception] = deque(errors or ())
        self.default_text = default_text
        self.requests: list[ModelRequest] = []

    @property
    def call_count(self) -> int:
        return len(self.requests)

    def complete(
        self,
        request: ModelRequest,
        *,
        timeout_seconds: float | None = None,
        cancellation_token: Any = None,
    ) -> ModelResponse:
        if cancellation_token is not None:
            check = getattr(cancellation_token, "is_cancelled", None)
            if callable(check) and check():
                raise AdapterError(FailureCategory.CANCELLED, "model operation cancelled", operation="complete")
        self.requests.append(request)
        if self._errors:
            error = self._errors.popleft()
            if isinstance(error, AdapterError):
                raise error
            raise self.normalize_provider_error(error, operation="complete") from error
        value = self._responses.popleft() if self._responses else self.default_text
        if callable(value):
            value = value(request)
        if isinstance(value, Exception):
            raise value
        if isinstance(value, ModelResponse):
            return value
        if isinstance(value, Mapping):
            text = value.get("text") or value.get("output") or ""
            structured = value.get("structured")
            usage_value = value.get("usage") or {}
            if isinstance(usage_value, ModelUsage):
                usage = usage_value
            else:
                usage = ModelUsage(
                    input_tokens=int(usage_value.get("input_tokens", 0)),
                    output_tokens=int(usage_value.get("output_tokens", 0)),
                    total_tokens=int(usage_value.get("total_tokens", 0)),
                )
            return ModelResponse(
                provider=ModelProvider.FAKE,
                model_name=str(value.get("model_name", self.model_name)),
                text=str(text),
                structured=structured if structured is not None else parse_structured(str(text)),
                usage=usage,
                finish_reason=value.get("finish_reason"),
                request_id=value.get("request_id"),
                tool_calls=list(value.get("tool_calls", [])),
            )
        text = str(value)
        return ModelResponse(
            provider=ModelProvider.FAKE,
            model_name=self.model_name,
            text=text,
            structured=parse_structured(text),
            usage=ModelUsage(),
        )


FakeAdapter = FakeModelAdapter


__all__ = ["FakeAdapter", "FakeModelAdapter"]
