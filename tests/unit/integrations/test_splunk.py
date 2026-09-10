from __future__ import annotations

from io import BytesIO
import json
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
            "authentication/current-context": {"entry": [{"content": {"roles": ["searcher"]}}]},
            "authorization/roles/searcher": {"entry": [{"name": "searcher", "content": {"srchIndexesAllowed": ["*"]}}]},
            "saved/sourcetypes": {"entry": [{"name": "syslog", "content": {"fields": ["host", "message"]}}]},
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


@pytest.mark.parametrize("role_content,expected", [
    ({"srchIndexesAllowed": ["*"], "srchIndexesDisallowed": ["restricted"]}, ("main",)),
    ({"imported_srchIndexesAllowed": ["*", "_*"]}, ("main", "restricted", "_internal")),
    ({"srchIndexesAllowed": ["*", "_*"], "imported_srchIndexesDisallowed": ["restricted", "_*"]}, ("main",)),
])
def test_discovery_respects_effective_search_permissions_and_internal_index_wildcards(role_content, expected):
    class Client(FakeSplunkClient):
        def __init__(self):
            super().__init__()
            self.indexes.extend([{"name": "restricted"}, {"name": "_internal"}])

        def get(self, path, **kwargs):
            if path == "authentication/current-context":
                return {"entry": [{"content": {"roles": ["searcher"]}}]}
            if path == "authorization/roles/searcher":
                return {"entry": [{"name": "searcher", "content": role_content}]}
            return super().get(path, **kwargs)

    client = Client()
    discovery = make_connector(client).discover()
    assert discovery.indexes == expected
    assert set(discovery.time_coverage).issubset(expected)
    assert client.search_calls == 0


@pytest.mark.parametrize("response", [
    {"entry": []},
    *({"entry": [{"content": {"roles": roles}}]} for roles in ("unknown", [".."], ["."], ["searcher/../../admin"])),
])
def test_missing_or_malformed_search_permissions_do_not_authorize_catalog_indexes(response):
    class Client(FakeSplunkClient):
        def get(self, path, **kwargs):
            return response if path == "authentication/current-context" else super().get(path, **kwargs)

    discovery = make_connector(Client()).discover()
    assert not discovery.complete
    assert discovery.indexes == ()
    assert any(error.startswith("index_scope:") for error in discovery.errors)


def test_role_permission_failure_does_not_submit_discovery_searches():
    class Client(FakeSplunkClient):
        def get(self, path, **kwargs):
            if path.startswith("authorization/roles/"):
                raise PermissionError("role metadata denied")
            return super().get(path, **kwargs)

    client = Client()
    discovery = make_connector(client).discover(include_indexed_sources=True)
    assert not discovery.complete
    assert discovery.indexes == ()
    assert client.search_calls == 0
    assert any(error.startswith("index_scope:") for error in discovery.errors)


def test_repeated_sourcetype_metadata_preserves_all_observed_fields():
    class Client(FakeSplunkClient):
        def get(self, path, **kwargs):
            if path == "saved/sourcetypes":
                return {"entry": [{"name": "syslog", "content": {"fields": fields}}
                                  for fields in (["host", "message"], ["host", "process"])]}
            return super().get(path, **kwargs)

    discovery = make_connector(Client()).discover()
    assert set(discovery.representative_schemas["syslog"]) == {"host", "message", "process"}
    assert any("differing" in note and "syslog" in note for note in discovery.coverage_limitations)


def test_indexed_source_catalog_includes_sources_without_saved_configuration() -> None:
    class IndexedClient(FakeSplunkClient):
        def search(self, query, **kwargs):
            self.search_calls += 1
            assert query == '| tstats count WHERE (index="main") BY sourcetype | head 1000'
            assert kwargs["earliest_time"] == "0"
            assert kwargs["latest_time"].endswith("Z")
            return [{"sourcetype": "lab:normalized:endpoint", "count": "70"}]

    client = IndexedClient()
    result = make_connector(client).discover(include_indexed_sources=True)
    assert set(result.sourcetypes) == {"syslog", "lab:normalized:endpoint"}
    assert client.search_calls == 1
    assert "count" not in result.fields
    assert any("configured" in note and "indexed" in note for note in result.coverage_limitations)


@pytest.mark.parametrize("rows", [[], [{"sourcetype": "observed", "count": "1"}]])
def test_successful_indexed_probe_establishes_tstats_without_data_model_metadata(rows) -> None:
    class Client(FakeSplunkClient):
        def get(self, path, **kwargs):
            return {"entry": []} if path == "data/models" else super().get(path, **kwargs)

        def search(self, *args, **kwargs):
            return rows

    result = make_connector(Client()).discover(include_indexed_sources=True)
    assert result.tstats_available is True
    assert not any("availability was not exposed" in note for note in result.coverage_limitations)
    assert result.accelerated_data_models == ()


@pytest.mark.parametrize("no_indexes", [False, True])
def test_failed_or_unexecuted_indexed_probe_does_not_establish_tstats(no_indexes) -> None:
    class Client(FakeSplunkClient):
        def get(self, path, **kwargs):
            return {"entry": []} if path == "data/models" else super().get(path, **kwargs)

        def search(self, *args, **kwargs):
            raise PermissionError("denied")

    client = Client()
    if no_indexes:
        client.indexes = []
    result = make_connector(client).discover(include_indexed_sources=True)
    assert result.tstats_available is None
    assert any("availability was not exposed" in note for note in result.coverage_limitations)


def test_indexed_source_discovery_failure_is_observable_and_keeps_configured_metadata() -> None:
    class DeniedClient(FakeSplunkClient):
        def search(self, *args, **kwargs):
            raise PermissionError("denied")

    result = make_connector(DeniedClient()).discover(include_indexed_sources=True)
    assert result.sourcetypes == ("syslog",)
    assert result.complete is False
    assert any("indexed_sourcetypes" in error for error in result.errors)


def test_indexed_source_discovery_rejects_catalog_values_containing_spl() -> None:
    client = FakeSplunkClient()
    client.indexes = [{"name": 'main\" | collect index=other'}]
    result = make_connector(client).discover(include_indexed_sources=True)
    assert client.search_calls == 0
    assert result.complete is False
    assert any("indexed_sourcetypes" in error for error in result.errors)


def test_indexed_source_discovery_cancels_a_job_created_during_cancellation() -> None:
    token = CancellationToken()

    class Job:
        cancelled = False

        def cancel(self):
            self.cancelled = True

    job = Job()

    class Client(FakeSplunkClient):
        def search(self, *args, **kwargs):
            token.cancel()
            return job

    with pytest.raises(AdapterError) as error:
        make_connector(Client()).discover(include_indexed_sources=True, cancellation_token=token)
    assert error.value.category is FailureCategory.CANCELLED
    assert job.cancelled


def test_indexed_source_limit_marks_catalog_partial():
    class Client(FakeSplunkClient):
        def search(self, *args, **kwargs):
            return [{"sourcetype": "source:one"}]

    connector = SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="unit-test-token", max_discovery_items=1), client=Client())
    result = connector.discover(include_indexed_sources=True)
    assert result.complete is False
    assert any("indexed sourcetype result limit" in note for note in result.coverage_limitations)


def test_discovery_can_read_bounded_representative_search_schema_for_approved_scope() -> None:
    class SchemaClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            if path == "saved/sourcetypes":
                return {"entry": [{"name": "syslog"}]}
            return super().get(path, **kwargs)

        def search(self, query: str, **kwargs: object) -> object:
            self.search_calls += 1
            assert query == 'search index="main" sourcetype="syslog" | head 1 | fieldsummary'
            assert kwargs == {
                "earliest_time": "2024-01-01T00:00:00Z",
                "latest_time": "2024-01-02T00:00:00Z",
                "output_mode": "json",
                "max_count": 1_000,
            }
            return [{"field": "host"}, {"field": "src_ip"}]

    client = SchemaClient()
    result = make_connector(client).discover(
        approved_indexes=("main",),
        approved_sourcetypes=("syslog",),
        earliest_utc="2024-01-01T00:00:00Z",
        latest_utc="2024-01-02T00:00:00Z",
    )

    assert result.representative_schemas == {"syslog": ("host", "src_ip")}
    assert {"host", "src_ip"}.issubset(result.fields)
    assert client.search_calls == 1


def test_discovery_keeps_metadata_schema_without_representative_search() -> None:
    client = FakeSplunkClient()
    result = make_connector(client).discover(
        approved_indexes=("main",),
        approved_sourcetypes=("syslog",),
        earliest_utc="2024-01-01T00:00:00Z",
        latest_utc="2024-01-02T00:00:00Z",
    )

    assert result.representative_schemas["syslog"] == ("host", "message")
    assert client.search_calls == 0


def test_scoped_schema_discovery_uses_exact_pairs_and_hunt_dates() -> None:
    class HistoricalClient(FakeSplunkClient):
        def __init__(self):
            super().__init__()
            self.indexes = [{"name": name, "content": {"earliestTime": "2026-01-01T00:00:00Z", "latestTime": "2026-01-12T00:10:00Z"}}
                            for name in ("endpoint", "auth", "dns", "network")]
            self.queries = []

        def get(self, path, **kwargs):
            if path == "saved/sourcetypes":
                return {"entry": [{"name": name} for name in ("process:events", "auth:events", "dns:events", "network:events")]}
            return super().get(path, **kwargs)

        def search(self, query, **kwargs):
            self.queries.append(query)
            assert kwargs["earliest_time"] == "2026-01-01T00:00:00Z"
            assert kwargs["latest_time"] == "2026-01-05T00:00:00Z"
            return [{"field": "host"}, {"field": "dest_ip"}, {"field": "dest_port"}]

    client = HistoricalClient()
    pairs = [("endpoint", "process:events"), ("auth", "auth:events"), ("dns", "dns:events"), ("network", "network:events")]
    result = make_connector(client).discover(
        approved_indexes=[pair[0] for pair in pairs], approved_sourcetypes=[pair[1] for pair in pairs],
        source_pairs=pairs, earliest_utc="2026-01-01T00:00:00Z", latest_utc="2026-01-05T00:00:00Z",
    )
    assert len(client.queries) == 4  # No 4x4 cross-product starving later sources.
    assert client.queries == [f'search index="{index}" sourcetype="{source}" | head 1 | fieldsummary' for index, source in pairs]
    assert "dest_port" in result.representative_schemas["network:events"]
    assert any("sample" in item and "exhaustive" in item for item in result.coverage_limitations)


def test_explicit_source_pairs_cannot_expand_the_discovery_scope() -> None:
    client = FakeSplunkClient()
    with pytest.raises(AdapterError):
        make_connector(client).discover(
            approved_indexes=["main"], approved_sourcetypes=["syslog"], source_pairs=[("secret", "syslog")],
            earliest_utc="2024-01-01T00:00:00Z", latest_utc="2024-01-02T00:00:00Z",
        )
    assert client.search_calls == 0


def test_explicit_pairs_sample_each_index_even_when_the_sourcetype_has_metadata() -> None:
    class SharedSourceClient(FakeSplunkClient):
        def __init__(self) -> None:
            super().__init__()
            self.indexes = [{"name": "main"}, {"name": "archive"}]

        def search(self, query: str, **kwargs: object) -> object:
            self.search_calls += 1
            return [{"field": "dest_port" if 'index="archive"' in query else "src_ip"}]

    client = SharedSourceClient()
    result = make_connector(client).discover(
        approved_indexes=["main", "archive"], approved_sourcetypes=["syslog"],
        source_pairs=[("main", "syslog"), ("archive", "syslog")],
        earliest_utc="2024-01-01T00:00:00Z", latest_utc="2024-01-02T00:00:00Z",
    )
    assert client.search_calls == 2
    assert {"host", "message", "src_ip", "dest_port"}.issubset(result.representative_schemas["syslog"])


def test_production_discovery_derives_source_pairs_from_covered_index_events() -> None:
    class CoveredIndexClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            if path == "saved/sourcetypes":
                return {"entry": [{"name": "syslog"}]}
            return super().get(path, **kwargs)

        def search(self, query: str, **kwargs: object) -> object:
            self.search_calls += 1
            assert kwargs["earliest_time"] == "2024-01-01T00:00:00Z"
            assert kwargs["latest_time"] == "2024-01-02T00:00:00Z"
            if query == 'search index="main" | head 1':
                return [{"sourcetype": "syslog", "host": "host-1", "process": "pwsh"}]
            assert query == 'search index="main" sourcetype="syslog" | head 1 | fieldsummary'
            return [{"field": "host"}, {"field": "process"}]

    client = CoveredIndexClient()
    result = make_connector(client).discover(include_representative_schemas=True)

    assert result.representative_schemas["syslog"] == ("host", "process")
    assert client.search_calls == 2


def test_representative_schema_waits_for_delayed_read_only_job() -> None:
    class DelayedJob:
        def __init__(self) -> None:
            self.polls = 0
            self.cancel_calls = 0

        def is_done(self) -> bool:
            return self.polls >= 2

        def refresh(self) -> None:
            self.polls += 1

        def results(self, **_: object) -> list[dict[str, str]]:
            assert self.polls >= 2
            return [{"field": "host"}, {"field": "process"}]

        def cancel(self) -> None:
            self.cancel_calls += 1

    class DelayedClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            if path == "saved/sourcetypes":
                return {"entry": [{"name": "syslog"}]}
            return super().get(path, **kwargs)

        def search(self, _query: str, **_kwargs: object) -> object:
            self.search_calls += 1
            return DelayedJob()

    client = DelayedClient()
    result = make_connector(client).discover(
        approved_indexes=("main",),
        approved_sourcetypes=("syslog",),
        earliest_utc="2024-01-01T00:00:00Z",
        latest_utc="2024-01-02T00:00:00Z",
    )

    assert result.representative_schemas["syslog"] == ("host", "process")
    assert client.search_calls == 1


def test_representative_schema_discovery_requires_exact_bounded_scope() -> None:
    client = FakeSplunkClient()
    with pytest.raises(AdapterError) as caught:
        make_connector(client).discover(
            approved_indexes=("main OR index=other",),
            approved_sourcetypes=("syslog",),
            earliest_utc="2024-01-01T00:00:00Z",
            latest_utc="2024-01-02T00:00:00Z",
        )

    assert caught.value.category is FailureCategory.VALIDATION_FAILURE
    assert client.search_calls == 0


def test_discovery_requests_json_metadata_responses() -> None:
    class JsonClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            if path in {"saved/sourcetypes", "data/fields", "data/models"}:
                assert kwargs["output_mode"] == "json"
            return super().get(path, **kwargs)

    result = make_connector(JsonClient()).discover()

    assert result.sourcetypes == ("syslog",)
    assert "host" in result.fields


def test_discovery_decodes_splunk_sdk_response_body() -> None:
    class Response:
        def __init__(self, payload: object) -> None:
            self.body = BytesIO(json.dumps(payload).encode())

    class SDKResponseClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            value = super().get(path, **kwargs)
            return Response(value)

    result = make_connector(SDKResponseClient()).discover()

    assert result.sourcetypes == ("syslog",)
    assert "host" in result.fields


def test_discovery_decodes_splunk_sdk_mapping_response_body() -> None:
    class SDKResponseClient(FakeSplunkClient):
        def get(self, path: str, **kwargs: object) -> object:
            payload = super().get(path, **kwargs)
            return {"status": 200, "body": BytesIO(json.dumps(payload).encode())}

    result = make_connector(SDKResponseClient()).discover()

    assert result.sourcetypes == ("syslog",)
    assert "host" in result.fields


def test_discovery_normalizes_sdk_resource_objects() -> None:
    class Resource:
        def __init__(self, name: str, content: dict[str, object]) -> None:
            self.name = name
            self.content = content

    class SDKClient(FakeSplunkClient):
        indexes = [
            Resource(
                "main",
                {"earliestTime": "2024-01-01T00:00:00Z", "latestTime": "2024-01-02T00:00:00Z"},
            )
        ]

    result = make_connector(SDKClient()).discover()

    assert result.indexes == ("main",)
    assert result.time_coverage["main"]["earliest"].endswith("Z")


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
            if path == "saved/sourcetypes":
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


def test_healthcheck_normalizes_sdk_auth_property_failures() -> None:
    class AuthenticationError(Exception):
        pass

    class AuthFailingClient:
        @property
        def info(self) -> object:
            raise AuthenticationError("session is not logged in")

    health = make_connector(AuthFailingClient()).healthcheck()

    assert health.available is False
    assert health.error_category is FailureCategory.INVALID_CREDENTIALS


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


def test_fetch_results_requests_json_records() -> None:
    class Job:
        def __init__(self) -> None:
            self.kwargs: dict[str, object] | None = None

        def results(self, **kwargs: object) -> bytes:
            self.kwargs = kwargs
            return b'{"results": [{"host": "host-1", "event_id": "evt-1"}]}'

    client = CancellableClient()
    job = Job()
    client.jobs["job-123"] = job

    rows = make_connector(client).fetch_results("job-123", page=1, limit=25)

    assert rows == [{"host": "host-1", "event_id": "evt-1"}]
    assert job.kwargs == {"offset": 25, "count": 25, "output_mode": "json"}


def test_page_deadline_bounds_body_read_and_late_body_is_not_returned():
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    class Body:
        def read(self, _size=None):
            entered.set()
            release.wait(timeout=2)
            finished.set()
            return b'{"results":[{"event_id":"late"}]}'

    class Job:
        def results(self, **kwargs):
            return Body()

    client = CancellableClient()
    client.jobs["job-123"] = Job()
    try:
        with pytest.raises(AdapterError) as error:
            make_connector(client).fetch_results("job-123", timeout_seconds=0.05)
        assert error.value.category is FailureCategory.HARD_TIMEOUT
        assert entered.is_set()
        # Caller timeout does not stop the underlying reader. Release and join
        # its completion explicitly; its late result must never be accepted.
        assert not finished.is_set()
    finally:
        release.set()
        assert finished.wait(timeout=2)


def test_result_body_failure_is_not_an_empty_success():
    class Body:
        def read(self, _size=None):
            raise TimeoutError("read failed")

    class Job:
        def results(self, **kwargs):
            return Body()

    client = CancellableClient()
    client.jobs["job-123"] = Job()
    with pytest.raises(AdapterError) as error:
        make_connector(client).fetch_results("job-123")
    assert error.value.category is FailureCategory.HARD_TIMEOUT


def test_tls_and_endpoint_validation_rejects_unsafe_configuration() -> None:
    with pytest.raises(ValueError):
        SplunkConnectionConfig(endpoint="http://splunk.example", token="x")
    with pytest.raises(ValueError):
        SplunkConnectionConfig(endpoint="https://splunk.example", verify_tls=False, token="x")


def test_submit_reuses_existing_requested_job_id() -> None:
    class Job:
        name = "query-1"

    class Jobs(dict[str, Job]):
        create_calls = 0

        def create(self, _query: str, **_: object) -> Job:
            self.create_calls += 1
            raise AssertionError("an existing deterministic job must not be resubmitted")

    class Client(FakeSplunkClient):
        def __init__(self) -> None:
            super().__init__()
            self.jobs = Jobs({"query-1": Job()})

    client = Client()

    assert make_connector(client).submit("search index=main", id="query-1") == "query-1"
    assert client.jobs.create_calls == 0
