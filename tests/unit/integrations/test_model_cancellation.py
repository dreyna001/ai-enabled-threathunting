"""Caller cancellation must not admit additional unbounded provider work."""

import sys
import threading
from types import SimpleNamespace

import pytest

from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models.base import ModelCancellationToken, ModelRequest
from threat_hunting.integrations.models.openai import OpenAIModelAdapter


def request() -> ModelRequest:
    return ModelRequest(messages=[{"role": "user", "content": "Synthetic test"}])


class HeldClient:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.closed = threading.Event()
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.calls += 1
        self.started.set()
        self.release.wait(timeout=5)
        self.finished.set()
        return {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}]}

    def close(self) -> None:
        self.closed.set()


def test_timeout_keeps_capacity_reserved_until_provider_work_finishes() -> None:
    client = HeldClient()
    adapter = OpenAIModelAdapter("test", client=client)
    try:
        with pytest.raises(AdapterError) as first:
            adapter.complete(request(), timeout_seconds=0.05)
        assert first.value.category == FailureCategory.HARD_TIMEOUT
        assert client.started.is_set() and not client.finished.is_set()
        with pytest.raises(AdapterError) as second:
            adapter.complete(request(), timeout_seconds=0.05)
        assert second.value.category == FailureCategory.BUDGET_EXHAUSTED
        assert client.calls == 1
    finally:
        client.release.set()
        client.finished.wait(timeout=2)
        close = getattr(adapter, "close", None)
        if close:
            close()


def test_cancellation_returns_before_a_noncooperative_provider_finishes() -> None:
    client = HeldClient()
    adapter = OpenAIModelAdapter("test", client=client)
    token = ModelCancellationToken()
    returned = threading.Event()
    errors = []

    def run() -> None:
        try:
            adapter.complete(request(), timeout_seconds=4, cancellation_token=token)
        except AdapterError as exc:
            errors.append(exc.category)
        finally:
            returned.set()

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert client.started.wait(timeout=2)
        token.cancel()
        cancelled_promptly = returned.wait(timeout=1)
        still_running = not client.finished.is_set()
    finally:
        client.release.set()
        thread.join(timeout=5)
        close = getattr(adapter, "close", None)
        if close:
            close()
    assert cancelled_promptly and still_running
    assert errors == [FailureCategory.CANCELLED]


def test_close_waits_for_active_work_to_release_the_client() -> None:
    client = HeldClient()
    adapter = OpenAIModelAdapter("test", client=client)
    try:
        with pytest.raises(AdapterError):
            adapter.complete(request(), timeout_seconds=0.05)
        adapter.close()
        assert not client.closed.is_set()
        with pytest.raises(AdapterError) as failure:
            adapter.complete(request())
        assert failure.value.category == FailureCategory.INVALID_CONFIGURATION
    finally:
        client.release.set()
        client.finished.wait(timeout=2)
    assert client.closed.wait(timeout=2)


def test_sdk_retries_are_disabled_and_call_deadline_is_forwarded(monkeypatch) -> None:
    constructor = {}
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return {"choices": [{"message": {"content": "{}"}}]}

    def factory(**kwargs):
        constructor.update(kwargs)
        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=factory))
    adapter = OpenAIModelAdapter("test", api_key="test-only", timeout_seconds=30)
    adapter.complete(request(), timeout_seconds=2)
    assert constructor["max_retries"] == 0
    assert calls[0]["timeout"] == 2
    adapter.close()


def test_provider_type_error_does_not_trigger_an_unbudgeted_second_call() -> None:
    calls = []

    def fail(**kwargs):
        calls.append(kwargs)
        raise TypeError("provider implementation error")

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=fail)))
    adapter = OpenAIModelAdapter("test", client=client)
    with pytest.raises(AdapterError):
        adapter.complete(request())
    assert len(calls) == 1
