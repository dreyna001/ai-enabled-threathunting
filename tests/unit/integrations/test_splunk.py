from __future__ import annotations

import ssl
import threading
import time

import pytest

from threat_hunting.domain.errors import FailureCategory, RetryClassification, retry_classification
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.splunk import (
    CancellationToken,
    SplunkConnectionConfig,
    SplunkConnector,
)


class FakeSplunkClient:
    def __init__(self) -> None:
        self.search_calls = 0
        self.get_calls: list[str] = []
        self.indexes = [
            {
                "name": "main",
                "content": {"earliestTime": "2024-01-01T00:00:00Z", "latestTime": "2024-01-02T00:00:00Z"},
            }
        ]

    def get(self, path: str, **_: object) -> object:
        self.get_calls.append(path)
        return {
            "data/sourcetypes": {"entry": [{"name": "syslog", "content": {"fields": ["host", "message"]}}]},
            "data/fields": {"entry": [{"name": "host"}, {"name": "message"}]},
            "data/models": {"entry": [{"name": "Endpoint", "content": {"accelerated": True}}]},
            "server/info": {"entry": [{"name": "splunk"}]},
        }.get(path, {"entry": []})

    def search(self, *_: object, **__: object) -> object:
        self.search_calls += 1
        raise AssertionError("metadata discovery must never submit a search")


def make_connector(client: object) -> SplunkConnector:
    return SplunkConnector(
        SplunkConnectionConfig(endpoint="https://splunk.example", token="unit-test-token"),
        client=client,
    )


def test_discovery_uses_metadata_only_and_normalizes_catalog() -> None:
    client = FakeSplunkClient()
    result = make_connector(client).discover()

    assert result.complete is True
    assert result.indexes == ("main",)
    assert result.sourcetypes == ("syslog",)
    assert "host" in result.fields
    assert result.accelerated_data_models == ("Endpoint",)
    assert result.tstats_available is True
    assert result.time_coverage["main"]["earliest"].endswith("Z")
    assert client.search_calls == 0
    assert "search/jobs" not in client.get_calls


def test_discovery_snapshot_is_deeply_immutable_and_serializes_as_before() -> None:
    result = make_connector(FakeSplunkClient()).discover()

    assert result.indexes == ("main",)
    assert result.to_dict()["indexes"] == ["main"]
    assert result.to_dict()["representative_schemas"] == {"syslog": ["host", "message"]}

    with pytest.raises(TypeError):
        list.append(result.indexes, "forged")
    with pytest.raises(TypeError):
        list.append(result.representative_schemas["syslog"], "forged")
    with pytest.raises(TypeError):
        result.time_coverage["main"]["earliest"] = "forged"
    with pytest.raises(TypeError):
        list.append(result.errors, "forged")

    serialized = result.to_dict()
    serialized["indexes"].append("forged")
    serialized["representative_schemas"]["syslog"].append("forged")
    assert result.indexes == ("main",)
    assert result.representative_schemas["syslog"] == ("host", "message")


def test_discovery_threads_cancellation_into_in_flight_metadata_calls() -> None:
    token = CancellationToken()

    class CancellingClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            token.cancel()
            return super().get(path, **kwargs)

    with pytest.raises(AdapterError) as caught:
        make_connector(CancellingClient()).discover(cancellation_token=token)

    assert caught.value.category is FailureCategory.CANCELLED


def test_endpoint_iterables_are_consumed_only_to_the_discovery_item_limit() -> None:
    class LazyRows:
        def __init__(self) -> None:
            self.consumed = 0

        def __iter__(self):
            while True:
                self.consumed += 1
                yield {"name": f"field-{self.consumed}"}

    rows = LazyRows()

    class LazyClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            if path == "data/fields":
                return rows
            return super().get(path, **kwargs)

    connector = SplunkConnector(
        SplunkConnectionConfig(
            endpoint="https://splunk.example",
            token="unit-test-token",
            max_discovery_items=3,
        ),
        client=LazyClient(),
    )

    result = connector.discover()

    assert rows.consumed == 3
    assert {"field-1", "field-2", "field-3"}.issubset(result.fields)


def test_streamed_discovery_response_is_read_with_a_byte_cap() -> None:
    class OversizedResponse:
        requested_size: int | None = None

        def read(self, size: int) -> bytes:
            self.requested_size = size
            return b"x" * size

    response = OversizedResponse()

    class OversizedClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            if path == "data/fields":
                return response
            return super().get(path, **kwargs)

    connector = SplunkConnector(
        SplunkConnectionConfig(
            endpoint="https://splunk.example",
            token="unit-test-token",
            max_discovery_bytes=64,
        ),
        client=OversizedClient(),
    )

    result = connector.discover()

    assert response.requested_size == 65
    assert result.complete is False
    assert any(error.startswith("fields:") for error in result.errors)


def test_partial_discovery_is_explicit_and_safe() -> None:
    class FailingMetadata(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            if path == "data/fields":
                raise TimeoutError
            return super().get(path, **kwargs)

    result = make_connector(FailingMetadata()).discover()
    assert result.complete is False
    assert any("partial" in limitation for limitation in result.coverage_limitations)
    assert any(error.startswith("fields:") for error in result.errors)


def test_cancellation_is_reported_without_calling_splunk() -> None:
    token = CancellationToken()
    token.cancel()
    client = FakeSplunkClient()
    with pytest.raises(Exception) as caught:
        make_connector(client).discover(cancellation_token=token)
    assert caught.value.category is FailureCategory.CANCELLED
    assert client.get_calls == []


def test_transport_timeout_is_bounded() -> None:
    class SlowClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            if path == "data/sourcetypes":
                time.sleep(0.1)
            return super().get(path, **kwargs)

    connector = SplunkConnector(
        SplunkConnectionConfig(endpoint="https://splunk.example", token="unit-test-token", timeout_seconds=0.02),
        client=SlowClient(),
    )
    result = connector.discover()
    assert result.complete is False
    assert any(error.startswith("sourcetypes:") for error in result.errors)


def test_tls_certificate_errors_are_non_retryable_before_oserror() -> None:
    class TLSClient:
        def get(self, path: str, **kwargs: object) -> object:
            raise ssl.SSLCertVerificationError("certificate verify failed")

    health = make_connector(TLSClient()).healthcheck()

    assert health.available is False
    assert health.error_category is FailureCategory.TLS_CERTIFICATE_FAILURE
    assert retry_classification(health.error_category) is RetryClassification.NON_RETRYABLE


class CancellableJob:
    def __init__(self) -> None:
        self.cancel_calls = 0

    def cancel(self) -> None:
        self.cancel_calls += 1

    def results(self, **_: object) -> list[object]:
        raise AssertionError("cancelled fetch must not reach Splunk")


class CancellableClient(FakeSplunkClient):
    def __init__(self) -> None:
        super().__init__()
        self.job = CancellableJob()
        self.jobs = {"job-123": self.job}


def test_cancel_reaches_splunk_after_hunt_cancellation() -> None:
    token = CancellationToken()
    token.cancel()
    client = CancellableClient()

    assert make_connector(client).cancel("job-123", cancellation_token=token) is True
    assert client.job.cancel_calls == 1


def test_submit_and_fetch_keep_pre_action_cancellation() -> None:
    token = CancellationToken()
    token.cancel()
    client = CancellableClient()
    connector = make_connector(client)

    with pytest.raises(AdapterError) as submit_error:
        connector.submit("| makeresults", cancellation_token=token)
    with pytest.raises(AdapterError) as fetch_error:
        connector.fetch_results("job-123", cancellation_token=token)

    assert submit_error.value.category is FailureCategory.CANCELLED
    assert fetch_error.value.category is FailureCategory.CANCELLED
    assert client.search_calls == 0
    assert client.job.cancel_calls == 0


def test_streamed_results_are_read_with_the_policy_byte_cap() -> None:
    class OversizedResults:
        requested_size: int | None = None

        def read(self, size: int) -> bytes:
            self.requested_size = size
            return b"x" * size

    response = OversizedResults()

    class Job(CancellableJob):
        def results(self, **_: object) -> OversizedResults:
            return response

    client = CancellableClient()
    client.jobs["job-123"] = Job()

    with pytest.raises(AdapterError) as caught:
        make_connector(client).fetch_results("job-123", max_bytes=64)

    assert caught.value.category is FailureCategory.BUDGET_EXHAUSTED
    assert response.requested_size == 65


def test_tls_and_endpoint_validation_rejects_unsafe_configuration() -> None:
    with pytest.raises(ValueError):
        SplunkConnectionConfig(endpoint="http://splunk.example", token="x")
    with pytest.raises(ValueError):
        SplunkConnectionConfig(endpoint="https://splunk.example", verify_tls=False, token="x")
