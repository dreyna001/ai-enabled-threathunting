"""Provider-neutral model call contracts and adapter helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod

import json
import ssl
import threading
import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, Sequence

from pydantic import SecretStr

from threat_hunting.domain.errors import FailureCategory

from ..errors import AdapterError


class ModelProvider(StrEnum):
    OPENAI = "openai"
    BEDROCK = "bedrock"
    LITELLM = "litellm"
    FAKE = "fake"


class ModelCancellationToken:
    """Cooperative cancellation signal for model requests."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        return self.is_cancelled()


CancellationToken = ModelCancellationToken


def is_cancelled(token: Any) -> bool:
    if token is None:
        return False
    check = getattr(token, "is_cancelled", None)
    if callable(check):
        return bool(check())
    check = getattr(token, "is_set", None)
    if callable(check):
        return bool(check())
    return bool(getattr(token, "cancelled", False))


def _as_secret(value: SecretStr | str | None) -> SecretStr | None:
    if value is None:
        return None
    return value if isinstance(value, SecretStr) else SecretStr(value)


def _freeze_message_value(value: Any) -> Any:
    """Snapshot message content so validated roles cannot be changed later."""

    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_message_value(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_message_value(item) for item in value)
    return value


def _thaw_message_value(value: Any) -> Any:
    """Return provider-owned mutable payloads without exposing the snapshot."""

    if isinstance(value, Mapping):
        return {key: _thaw_message_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_message_value(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ModelUsage:
    """Provider usage normalized to token counts, without raw responses."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    def __post_init__(self) -> None:
        for value in (self.input_tokens, self.output_tokens, self.total_tokens):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("model usage token counts must be non-negative integers")
        total = self.input_tokens + self.output_tokens
        if self.total_tokens == 0 and total:
            object.__setattr__(self, "total_tokens", total)


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """Portable request shape shared by all provider adapters."""

    messages: Sequence[Mapping[str, Any]]
    system: str | None = None
    temperature: float | None = None
    max_output_tokens: int | None = None
    response_format: Mapping[str, Any] | None = None
    tools: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.messages:
            raise ValueError("messages must contain at least one message")
        for message in self.messages:
            if not isinstance(message, Mapping):
                raise ValueError("messages must be mappings")
            role = message.get("role")
            if role not in {"user", "assistant", "tool"}:
                raise ValueError("message role is not supported; use the system field for system instructions")
            if "content" not in message:
                raise ValueError("each message must contain content")
        if self.system is not None and not isinstance(self.system, str):
            raise ValueError("system must be a string when provided")
        if self.temperature is not None and not 0 <= self.temperature <= 2:
            raise ValueError("temperature must be between 0 and 2")
        if self.max_output_tokens is not None and (
            isinstance(self.max_output_tokens, bool) or self.max_output_tokens <= 0
        ):
            raise ValueError("max_output_tokens must be positive")
        object.__setattr__(
            self,
            "messages",
            tuple(_freeze_message_value(message) for message in self.messages),
        )

    def as_messages(self) -> list[dict[str, Any]]:
        return [_thaw_message_value(message) for message in self.messages]


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """Stable internal response preserving safe provider/model metadata."""

    provider: ModelProvider | str
    model_name: str
    text: str
    structured: Mapping[str, Any] | list[Any] | None = None
    usage: ModelUsage = field(default_factory=ModelUsage)
    finish_reason: str | None = None
    request_id: str | None = None
    tool_calls: list[Mapping[str, Any]] = field(default_factory=list)
    provider_metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.model_name, str) or not self.model_name.strip():
            raise ValueError("model_name must not be empty")
        if not isinstance(self.text, str):
            raise ValueError("model response text must be a string")
        object.__setattr__(self, "provider", ModelProvider(self.provider))
        object.__setattr__(self, "tool_calls", [dict(call) for call in self.tool_calls])
        object.__setattr__(self, "provider_metadata", dict(self.provider_metadata))

    @property
    def provider_name(self) -> str:
        return ModelProvider(self.provider).value

    @property
    def output(self) -> str:
        return self.text

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": ModelProvider(self.provider).value,
            "model_name": self.model_name,
            "text": self.text,
            "structured": self.structured,
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "output_tokens": self.usage.output_tokens,
                "total_tokens": self.usage.total_tokens,
            },
            "finish_reason": self.finish_reason,
            "request_id": self.request_id,
            "tool_calls": list(self.tool_calls),
            "provider_metadata": dict(self.provider_metadata),
        }


class ModelAdapter(Protocol):
    provider: ModelProvider
    model_name: str

    def complete(
        self,
        request: ModelRequest,
        *,
        timeout_seconds: float | None = None,
        cancellation_token: Any = None,
    ) -> ModelResponse: ...


def parse_structured(text: str) -> Mapping[str, Any] | list[Any] | None:
    """Parse a JSON model response without accepting arbitrary prose."""

    if not text.strip():
        return None
    try:
        value = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _usage_from_mapping(value: Any) -> ModelUsage:
    if value is None:
        return ModelUsage()
    if not isinstance(value, Mapping):
        input_tokens = getattr(value, "prompt_tokens", None) or getattr(value, "input_tokens", 0)
        output_tokens = getattr(value, "completion_tokens", None) or getattr(value, "output_tokens", 0)
        total_tokens = getattr(value, "total_tokens", 0)
    else:
        input_tokens = value.get(
            "prompt_tokens",
            value.get("input_tokens", value.get("inputTokens", 0)),
        )
        output_tokens = value.get(
            "completion_tokens",
            value.get("output_tokens", value.get("outputTokens", 0)),
        )
        total_tokens = value.get("total_tokens", 0)
    def integer(raw: Any) -> int:
        return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0 else 0
    return ModelUsage(integer(input_tokens), integer(output_tokens), integer(total_tokens))


class BaseModelAdapter(ABC):
    """Bound provider work, including work that outlives its caller's deadline."""

    provider: ModelProvider
    model_name: str
    timeout_seconds: float = 120.0
    _client: Any = None

    @abstractmethod
    def complete(self, request: ModelRequest, *, timeout_seconds: float | None = None, cancellation_token: Any = None) -> ModelResponse:
        """Each concrete adapter must transport and normalize one request."""
        raise NotImplementedError

    def __init__(self) -> None:
        self._call_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="model-adapter")
        self._in_flight: Future[Any] | None = None
        self._closed = False

    @property
    def outstanding_calls(self) -> int:
        with self._call_lock:
            return int(self._in_flight is not None and not self._in_flight.done())

    def close(self) -> None:
        """Stop admission and release the SDK client after active work finishes."""
        with self._call_lock:
            if self._closed:
                return
            self._closed = True
            future = self._in_flight
            self._executor.shutdown(wait=False, cancel_futures=True)
        if future is not None and not future.done():
            future.add_done_callback(lambda _future: self._close_client())
        else:
            self._close_client()

    def _close_client(self) -> None:
        client = getattr(self, "_client", None)
        close = getattr(client, "close", None)
        if callable(close):
            try:
                close()
            except Exception as exc:  # SDK boundary; never log credential-bearing details.
                logging.getLogger(__name__).warning(
                    "model client cleanup failed", extra={"error_type": type(exc).__name__},
                )
        self._client = None

    def _bounded_call(
        self,
        operation: str,
        callback: Callable[[], Any],
        *,
        timeout_seconds: float | None,
        cancellation_token: Any,
    ) -> Any:
        if is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "model operation cancelled", operation=operation)
        timeout = timeout_seconds if timeout_seconds is not None else self.timeout_seconds
        if timeout <= 0 or timeout > 600:
            raise AdapterError(FailureCategory.INVALID_CONFIGURATION, "model timeout is outside the supported bound", operation=operation)
        deadline = time.monotonic() + timeout
        with self._call_lock:
            if self._closed:
                raise AdapterError(FailureCategory.INVALID_CONFIGURATION, "model adapter is closed", operation=operation)
            if self._in_flight is not None and not self._in_flight.done():
                raise AdapterError(
                    FailureCategory.BUDGET_EXHAUSTED,
                    "model capacity is occupied by an outstanding call; no additional work was started",
                    operation=operation,
                )
            future = self._executor.submit(callback)
            self._in_flight = future
        try:
            while True:
                if is_cancelled(cancellation_token):
                    future.cancel()
                    raise AdapterError(FailureCategory.CANCELLED, "model operation cancelled", operation=operation)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    future.cancel()
                    raise AdapterError(FailureCategory.HARD_TIMEOUT, "model operation exceeded its timeout", operation=operation)
                try:
                    value = future.result(timeout=min(remaining, 0.05))
                    break
                except FutureTimeout:
                    if future.done():
                        raise
        except AdapterError:
            raise
        except Exception as exc:  # Provider-specific errors are normalized at this boundary.
            raise self.normalize_provider_error(exc, operation=operation) from exc
        # A running Future cannot be cancelled. It remains the admission gate
        # until it actually finishes; caller timeout never frees that capacity.
        if is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "model operation cancelled", operation=operation)
        return value

    @staticmethod
    def normalize_provider_error(exc: Exception, *, operation: str) -> AdapterError:
        name = type(exc).__name__.lower()
        status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
        response = getattr(exc, "response", None)
        if status is None and isinstance(response, Mapping):
            metadata = response.get("ResponseMetadata", {})
            if isinstance(metadata, Mapping):
                status = metadata.get("HTTPStatusCode")
        if isinstance(status, str) and status.isdigit():
            status = int(status)
        numeric_status = status if isinstance(status, int) and not isinstance(status, bool) else None
        # Inspect only stable error codes. Provider messages can contain private
        # account or request details and must never become application errors.
        body = getattr(exc, "body", None)
        details = body.get("error", body) if isinstance(body, Mapping) else {}
        quota_exhausted = isinstance(details, Mapping) and any(
            details.get(key) in ("insufficient_quota", "credit_balance_exhausted")
            for key in ("code", "type")
        )
        if numeric_status in {401, 403} or "auth" in name or "credential" in name:
            category = FailureCategory.INVALID_CREDENTIALS if numeric_status != 403 else FailureCategory.PERMISSION_DENIED
            message = "model provider authentication failed" if category is FailureCategory.INVALID_CREDENTIALS else "model provider permission denied"
        elif numeric_status in {400, 404, 422}:
            category, message = FailureCategory.INVALID_CONFIGURATION, "model provider rejected the request configuration"
        elif numeric_status == 429 and quota_exhausted:
            category = FailureCategory.PROVIDER_QUOTA_EXHAUSTED
            message = "model provider account credits or quota exhausted; restore API capacity before retrying"
        elif numeric_status == 429 or "rate" in name or "thrott" in name:
            category, message = FailureCategory.RATE_LIMITED, "model provider rate limit reached"
        elif numeric_status is not None and numeric_status >= 500:
            category, message = FailureCategory.PROVIDER_SERVER_ERROR, "model provider returned a server error"
        elif isinstance(exc, (TimeoutError, FutureTimeout)) or "timeout" in name:
            category, message = FailureCategory.HARD_TIMEOUT, "model operation exceeded its timeout"
        elif isinstance(exc, ssl.SSLError) or any(marker in name for marker in ("ssl", "certificate", "tls")):
            category, message = FailureCategory.TLS_CERTIFICATE_FAILURE, "model provider TLS verification failed"
        elif isinstance(exc, (ConnectionError, OSError)) or any(marker in name for marker in ("connection", "network", "transport")):
            category, message = FailureCategory.TEMPORARY_NETWORK, "model provider connection failed"
        else:
            category, message = FailureCategory.UNKNOWN, "model provider operation failed"
        logging.getLogger(__name__).warning(
            "model provider failure operation=%s category=%s status=%s error_type=%s",
            operation, category.value, numeric_status, type(exc).__name__,
        )
        return AdapterError(category, message, operation=operation)

    def generate(self, request: ModelRequest, **kwargs: Any) -> ModelResponse:
        """Compatibility spelling used by orchestration code."""

        return self.complete(request, **kwargs)


__all__ = [
    "BaseModelAdapter",
    "CancellationToken",
    "ModelAdapter",
    "ModelCancellationToken",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ModelUsage",
    "_as_secret",
    "_usage_from_mapping",
    "is_cancelled",
    "parse_structured",
]
