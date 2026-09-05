"""Read-only Splunk transport and metadata discovery adapter.

Only the official ``splunk-sdk`` client is used when a real client is needed.
Unit tests inject a small fake client, which keeps the adapter deterministic and
avoids a live Splunk dependency.  Discovery deliberately uses metadata REST
resources and collection properties; it never calls ``search`` or reads event
rows.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib.parse import urlsplit

from pydantic import SecretStr

from threat_hunting.domain.errors import FailureCategory

from .errors import AdapterError


class SplunkClient(Protocol):
    """Small subset of a ``splunklib.client.Service`` used by the adapter."""

    def get(self, path: str, **params: Any) -> Any: ...


class CancellationToken:
    """Cooperative cancellation signal shared by bounded adapter operations."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        return self.is_cancelled()


def _is_cancelled(token: Any) -> bool:
    if token is None:
        return False
    value = getattr(token, "is_cancelled", None)
    if callable(value):
        return bool(value())
    value = getattr(token, "is_set", None)
    if callable(value):
        return bool(value())
    return bool(getattr(token, "cancelled", False))


@dataclass(frozen=True, slots=True)
class SplunkConnectionConfig:
    """Validated, non-secret Splunk connection settings.

    Credentials are accepted as strings for ergonomic construction but wrapped
    in ``SecretStr`` immediately so they do not appear in reprs or errors.
    """

    endpoint: str
    token: SecretStr | str | None = None
    username: str | None = None
    password: SecretStr | str | None = None
    verify_tls: bool = True
    ca_bundle_path: Path | None = None
    lab_only_allow_insecure: bool = False
    timeout_seconds: float = 30.0
    app_namespace: str = "search"
    max_discovery_items: int = 1_000
    max_discovery_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("Splunk endpoint must be an absolute http(s) URL")
        if parsed.username or parsed.password:
            raise ValueError("Splunk endpoint must not embed credentials")
        if parsed.path not in {"", "/"}:
            raise ValueError("Splunk endpoint must not include a path")
        if not self.verify_tls and not self.lab_only_allow_insecure:
            raise ValueError("TLS verification can be disabled only in an explicitly enabled lab")
        if parsed.scheme == "http" and self.verify_tls:
            raise ValueError("TLS verification requires an https Splunk endpoint")
        if self.ca_bundle_path is not None and not Path(self.ca_bundle_path).is_absolute():
            raise ValueError("ca_bundle_path must be absolute")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise ValueError("timeout_seconds must be greater than 0 and at most 300")
        if not self.app_namespace or len(self.app_namespace) > 100:
            raise ValueError("app_namespace must be a non-empty short identifier")
        if self.max_discovery_items <= 0 or self.max_discovery_items > 100_000:
            raise ValueError("max_discovery_items is outside the supported bound")
        if self.max_discovery_bytes <= 0 or self.max_discovery_bytes > 64 * 1024 * 1024:
            raise ValueError("max_discovery_bytes is outside the supported bound")
        if self.token is not None:
            object.__setattr__(
                self,
                "token",
                self.token if isinstance(self.token, SecretStr) else SecretStr(self.token),
            )
        if self.password is not None:
            object.__setattr__(
                self,
                "password",
                self.password
                if isinstance(self.password, SecretStr)
                else SecretStr(self.password),
            )
        if self.token is None and (self.username is None or self.password is None):
            raise ValueError("configure a Splunk token or username and password")
        if self.token is not None and self.username is not None:
            raise ValueError("configure either token or username/password, not both")

    @property
    def host(self) -> str:
        return urlsplit(self.endpoint).hostname or ""

    @property
    def port(self) -> int:
        parsed = urlsplit(self.endpoint)
        return parsed.port or (443 if parsed.scheme == "https" else 80)

    @property
    def scheme(self) -> str:
        return urlsplit(self.endpoint).scheme

    def sdk_kwargs(self) -> dict[str, Any]:
        """Return safe connection kwargs, including secrets only for the SDK."""

        kwargs: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "app": self.app_namespace,
            "verify": str(self.ca_bundle_path) if self.ca_bundle_path else self.verify_tls,
        }
        if self.token is not None:
            kwargs["token"] = self.token.get_secret_value()
        else:
            kwargs["username"] = self.username
            kwargs["password"] = self.password.get_secret_value()  # type: ignore[union-attr]
        return kwargs


@dataclass(frozen=True, slots=True)
class SplunkDiscoveryItem:
    """One normalized metadata item retained in a discovery snapshot."""

    name: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("discovery item name must not be empty")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


def _freeze_discovery_value(value: Any) -> Any:
    """Recursively copy discovery containers into mutation-resistant values."""

    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_discovery_value(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_discovery_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_discovery_value(item) for item in value)
    return value


def _freeze_unique_discovery_values(values: Iterable[Any]) -> tuple[Any, ...]:
    """Deduplicate values into a genuinely immutable snapshot."""

    return tuple(_freeze_discovery_value(value) for value in dict.fromkeys(values))


@dataclass(frozen=True, slots=True)
class SplunkDiscovery:
    """Bounded, serializable metadata-only discovery result."""

    discovered_at_utc: datetime
    indexes: tuple[str, ...] | list[str]
    sourcetypes: tuple[str, ...] | list[str]
    fields: tuple[str, ...] | list[str]
    representative_schemas: Mapping[str, tuple[str, ...] | list[str]]
    time_coverage: Mapping[str, Mapping[str, str]]
    accelerated_data_models: tuple[str, ...] | list[str]
    tstats_available: bool | None
    coverage_limitations: tuple[str, ...] | list[str]
    errors: tuple[str, ...] | list[str]
    complete: bool

    def __post_init__(self) -> None:
        timestamp = self.discovered_at_utc
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("discovered_at_utc must include a timezone")
        object.__setattr__(self, "discovered_at_utc", timestamp.astimezone(timezone.utc))
        object.__setattr__(self, "indexes", _freeze_unique_discovery_values(self.indexes))
        object.__setattr__(self, "sourcetypes", _freeze_unique_discovery_values(self.sourcetypes))
        object.__setattr__(self, "fields", _freeze_unique_discovery_values(self.fields))
        object.__setattr__(
            self,
            "accelerated_data_models",
            _freeze_unique_discovery_values(self.accelerated_data_models),
        )
        object.__setattr__(
            self,
            "representative_schemas",
            MappingProxyType(
                {
                    key: _freeze_unique_discovery_values(value)
                    for key, value in self.representative_schemas.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "time_coverage",
            MappingProxyType(
                {
                    key: _freeze_discovery_value(value)
                    for key, value in self.time_coverage.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "coverage_limitations",
            _freeze_unique_discovery_values(self.coverage_limitations),
        )
        object.__setattr__(self, "errors", _freeze_unique_discovery_values(self.errors))

    @property
    def discovered_at(self) -> datetime:
        """Compatibility alias used by snapshot persistence code."""

        return self.discovered_at_utc

    def to_dict(self) -> dict[str, Any]:
        return {
            "discovered_at_utc": self.discovered_at_utc.isoformat().replace("+00:00", "Z"),
            "indexes": list(self.indexes),
            "sourcetypes": list(self.sourcetypes),
            "fields": list(self.fields),
            "representative_schemas": {key: list(value) for key, value in self.representative_schemas.items()},
            "time_coverage": {key: dict(value) for key, value in self.time_coverage.items()},
            "accelerated_data_models": list(self.accelerated_data_models),
            "tstats_available": self.tstats_available,
            "coverage_limitations": list(self.coverage_limitations),
            "errors": list(self.errors),
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True)
class SplunkHealth:
    available: bool
    checked_at_utc: datetime
    error_category: FailureCategory | None = None


class SplunkConnector:
    """Application-owned wrapper around the official Splunk SDK.

    ``client`` or ``client_factory`` can be injected in tests.  Without an
    injected client, importing or connecting to ``splunklib`` is lazy, so
    environments that only run unit tests do not need the optional SDK.
    """

    def __init__(
        self,
        config: SplunkConnectionConfig,
        *,
        client: SplunkClient | Any | None = None,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config
        self._client = client
        self._client_factory = client_factory

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from splunklib import client as splunk_client  # type: ignore[import-not-found]
        except ImportError as exc:
            raise AdapterError(
                FailureCategory.INVALID_CONFIGURATION,
                "the official splunk-sdk package is not installed",
                operation="connect",
            ) from exc
        factory = self._client_factory or splunk_client.connect
        kwargs = self.config.sdk_kwargs()
        try:
            # ``timeout`` is accepted by recent SDK versions and by test
            # factories.  Older releases reject it, so retry construction
            # without it (the adapter still enforces its own call timeout).
            self._client = factory(timeout=self.config.timeout_seconds, **kwargs)
        except TypeError:
            try:
                self._client = factory(**kwargs)
            except Exception as exc:  # noqa: BLE001 - normalized below
                raise self._normalize_error(exc, operation="connect") from exc
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise self._normalize_error(exc, operation="connect") from exc
        return self._client

    def _invoke(
        self,
        operation: str,
        callback: Callable[[], Any],
        *,
        cancellation_token: Any = None,
    ) -> Any:
        if _is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation=operation)
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="splunk-adapter")
        future = executor.submit(callback)
        try:
            value = future.result(timeout=self.config.timeout_seconds)
        except FutureTimeout as exc:
            future.cancel()
            raise AdapterError(
                FailureCategory.HARD_TIMEOUT,
                "Splunk operation exceeded its transport timeout",
                operation=operation,
            ) from exc
        except AdapterError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise self._normalize_error(exc, operation=operation) from exc
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        if _is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation=operation)
        return value

    @staticmethod
    def _normalize_error(exc: Exception, *, operation: str) -> AdapterError:
        name = type(exc).__name__.lower()
        status = getattr(exc, "status", None) or getattr(exc, "status_code", None)
        if isinstance(status, str) and status.isdigit():
            status = int(status)
        if status in {401, 403} or "auth" in name:
            category = FailureCategory.INVALID_CREDENTIALS if status != 403 else FailureCategory.PERMISSION_DENIED
            message = "Splunk authentication failed" if category is FailureCategory.INVALID_CREDENTIALS else "Splunk permission denied"
        elif status == 429 or "ratelimit" in name or "thrott" in name:
            category, message = FailureCategory.RATE_LIMITED, "Splunk rate limit reached"
        elif status is not None and status >= 500:
            category, message = FailureCategory.PROVIDER_SERVER_ERROR, "Splunk service returned a server error"
        elif isinstance(exc, (TimeoutError, FutureTimeout)) or "timeout" in name:
            category, message = FailureCategory.HARD_TIMEOUT, "Splunk operation exceeded its transport timeout"
        elif "ssl" in name or "certificate" in name or "tls" in name:
            category, message = FailureCategory.TLS_CERTIFICATE_FAILURE, "Splunk TLS verification failed"
        elif isinstance(exc, (ConnectionError, OSError)) or any(
            marker in name for marker in ("connection", "socket", "transport", "network")
        ):
            category, message = FailureCategory.TEMPORARY_NETWORK, "Splunk connection failed"
        else:
            category, message = FailureCategory.UNKNOWN, "Splunk operation failed"
        return AdapterError(category, message, operation=operation)

    @staticmethod
    def _decode_response(value: Any, *, max_bytes: int | None = None) -> Any:
        if value is None:
            return None
        if isinstance(value, bytes):
            if max_bytes is not None and len(value) > max_bytes:
                raise ValueError("Splunk response exceeds the configured byte limit")
            return SplunkConnector._decode_response(
                value.decode("utf-8", errors="replace"),
                max_bytes=max_bytes,
            )
        if isinstance(value, (dict, list, tuple, str, int, float, bool)):
            if isinstance(value, str):
                if max_bytes is not None and len(value.encode("utf-8")) > max_bytes:
                    raise ValueError("Splunk response exceeds the configured byte limit")
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return value
        reader = getattr(value, "read", None)
        if callable(reader):
            try:
                raw = reader(max_bytes + 1) if max_bytes is not None else reader()
            except Exception:  # noqa: BLE001 - malformed SDK response
                return None
            return SplunkConnector._decode_response(raw, max_bytes=max_bytes)
        content = getattr(value, "content", None)
        if content is not None:
            return SplunkConnector._decode_response(content, max_bytes=max_bytes)
        return value

    @staticmethod
    def _records(
        value: Any,
        *,
        limit: int | None = None,
        max_bytes: int | None = None,
    ) -> list[Mapping[str, Any]]:
        value = SplunkConnector._decode_response(value, max_bytes=max_bytes)
        if value is None:
            return []
        if isinstance(value, Mapping):
            for key in ("entry", "entries", "results", "items", "data", "records"):
                nested = value.get(key)
                if nested is not None and not isinstance(nested, (str, bytes)):
                    return SplunkConnector._records(nested, limit=limit, max_bytes=max_bytes)
            return [value]
        try:
            items = islice(value, limit) if limit is not None else iter(value)
            return [item if isinstance(item, Mapping) else {"value": item} for item in items]
        except TypeError:
            return [{"value": value}]

    def _collection(
        self,
        name: str,
        *,
        endpoint: str,
        cancellation_token: Any = None,
    ) -> list[Mapping[str, Any]]:
        client = self._get_client()

        def read_collection() -> Any:
            value = getattr(client, name, None)
            if value is not None:
                try:
                    return list(islice(value, self.config.max_discovery_items))
                except TypeError:
                    return value
            getter = getattr(client, "get", None)
            if not callable(getter):
                raise RuntimeError("Splunk client does not expose metadata access")
            return getter(endpoint, count=self.config.max_discovery_items)

        return self._records(
            self._invoke(
                f"discover.{name}",
                read_collection,
                cancellation_token=cancellation_token,
            ),
            limit=self.config.max_discovery_items,
            max_bytes=self.config.max_discovery_bytes,
        )

    def _endpoint(
        self,
        label: str,
        endpoint: str,
        *,
        cancellation_token: Any = None,
    ) -> list[Mapping[str, Any]]:
        client = self._get_client()
        getter = getattr(client, "get", None)
        if not callable(getter):
            raise RuntimeError("Splunk client does not expose metadata access")
        value = self._invoke(
            f"discover.{label}",
            lambda: getter(endpoint, count=self.config.max_discovery_items),
            cancellation_token=cancellation_token,
        )
        return self._records(
            value,
            limit=self.config.max_discovery_items,
            max_bytes=self.config.max_discovery_bytes,
        )

    @staticmethod
    def _record_name(record: Mapping[str, Any]) -> str | None:
        for key in ("name", "title", "sourcetype", "index", "id"):
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        content = record.get("content")
        if isinstance(content, Mapping):
            return SplunkConnector._record_name(content)
        return None

    @staticmethod
    def _record_content(record: Mapping[str, Any]) -> Mapping[str, Any]:
        content = record.get("content")
        return content if isinstance(content, Mapping) else record

    @staticmethod
    def _field_names(record: Mapping[str, Any]) -> list[str]:
        content = SplunkConnector._record_content(record)
        raw = content.get("fields") or content.get("fieldMetadata") or content.get("field_names")
        if isinstance(raw, Mapping):
            return [str(key) for key in raw if str(key)]
        if isinstance(raw, (list, tuple, set)):
            names: list[str] = []
            for item in raw:
                if isinstance(item, Mapping):
                    name = item.get("name") or item.get("fieldName")
                else:
                    name = item
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
            return names
        return []

    def healthcheck(self, *, cancellation_token: Any = None) -> SplunkHealth:
        checked = datetime.now(timezone.utc)
        try:
            client = self._get_client()
            info = getattr(client, "info", None)
            if info is None:
                getter = getattr(client, "get", None)
                if not callable(getter):
                    raise RuntimeError("Splunk client does not expose health metadata")
                self._invoke("healthcheck", lambda: getter("server/info"), cancellation_token=cancellation_token)
            else:
                self._invoke("healthcheck", lambda: info, cancellation_token=cancellation_token)
        except AdapterError as exc:
            return SplunkHealth(False, checked, exc.category)
        return SplunkHealth(True, checked)

    def discover(self, *, cancellation_token: Any = None) -> SplunkDiscovery:
        """Discover Splunk catalog metadata without submitting an event search."""

        if _is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="discover")
        discovered_at = datetime.now(timezone.utc)
        indexes: list[str] = []
        sourcetypes: list[str] = []
        fields: list[str] = []
        schemas: dict[str, list[str]] = {}
        coverage: dict[str, dict[str, str]] = {}
        models: list[str] = []
        errors: list[str] = []
        limitations: list[str] = []
        endpoint_specs: list[tuple[str, Callable[[], list[Mapping[str, Any]]]]] = [
            (
                "indexes",
                lambda: self._collection(
                    "indexes",
                    endpoint="data/indexes",
                    cancellation_token=cancellation_token,
                ),
            ),
            (
                "sourcetypes",
                lambda: self._endpoint(
                    "sourcetypes",
                    "data/sourcetypes",
                    cancellation_token=cancellation_token,
                ),
            ),
            (
                "fields",
                lambda: self._endpoint("fields", "data/fields", cancellation_token=cancellation_token),
            ),
            (
                "data_models",
                lambda: self._endpoint(
                    "data_models",
                    "data/models",
                    cancellation_token=cancellation_token,
                ),
            ),
        ]
        results: dict[str, list[Mapping[str, Any]]] = {}
        for label, reader in endpoint_specs:
            if _is_cancelled(cancellation_token):
                raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="discover")
            try:
                results[label] = reader()
            except AdapterError as exc:
                if exc.category is FailureCategory.CANCELLED:
                    raise
                errors.append(f"{label}: {exc.failure.category.value}")
            except Exception as exc:  # noqa: BLE001 - normalize partial discovery
                normalized = self._normalize_error(exc, operation=f"discover.{label}")
                errors.append(f"{label}: {normalized.failure.category.value}")

        for record in results.get("indexes", []):
            name = self._record_name(record)
            if not name:
                continue
            indexes.append(name)
            content = self._record_content(record)
            earliest = content.get("earliest") or content.get("earliestTime") or content.get("minTime")
            latest = content.get("latest") or content.get("latestTime") or content.get("maxTime")
            if earliest is not None or latest is not None:
                coverage[name] = {}
                if earliest is not None:
                    coverage[name]["earliest"] = str(earliest)
                if latest is not None:
                    coverage[name]["latest"] = str(latest)
            fields.extend(self._field_names(record))

        for record in results.get("sourcetypes", []):
            name = self._record_name(record)
            if name:
                sourcetypes.append(name)
            fields.extend(self._field_names(record))
            if name:
                schema_fields = self._field_names(record)
                if schema_fields:
                    schemas[name] = schema_fields

        for record in results.get("fields", []):
            name = self._record_name(record)
            if name:
                fields.append(name)
            fields.extend(self._field_names(record))

        tstats_available: bool | None = None
        for record in results.get("data_models", []):
            name = self._record_name(record)
            content = self._record_content(record)
            accelerated = content.get("accelerated")
            if name:
                is_accelerated = accelerated is True or str(accelerated).lower() == "true"
                if is_accelerated:
                    models.append(name)
                if "tstats_available" in content:
                    tstats_available = bool(content["tstats_available"])
        if tstats_available is None and models:
            tstats_available = True
        if tstats_available is None:
            limitations.append("tstats availability was not exposed by Splunk metadata")
        if not fields:
            limitations.append("field catalog was unavailable from metadata endpoints")
        if not coverage:
            limitations.append("index time coverage was unavailable from metadata endpoints")
        if errors:
            limitations.append("one or more metadata endpoints failed; discovery is partial")
        complete = not errors and bool(indexes or sourcetypes)
        if not results:
            raise AdapterError(
                FailureCategory.TEMPORARY_NETWORK,
                "Splunk metadata discovery was unavailable",
                operation="discover",
            )
        if _is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="discover")
        return SplunkDiscovery(
            discovered_at_utc=discovered_at,
            indexes=indexes,
            sourcetypes=sourcetypes,
            fields=fields,
            representative_schemas=schemas,
            time_coverage=coverage,
            accelerated_data_models=models,
            tstats_available=tstats_available,
            coverage_limitations=limitations,
            errors=errors,
            complete=complete,
        )

    # The remaining methods preserve the application-owned connector shape for
    # execution slices.  Discovery itself never calls any of them.
    def validate_query(self, query: str) -> str:
        if not isinstance(query, str) or not query.strip():
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "query must be non-empty", operation="validate_query")
        return query.strip()

    def submit(self, query: str, *, cancellation_token: Any = None, **kwargs: Any) -> str:
        query = self.validate_query(query)
        client = self._get_client()

        def submit_job() -> Any:
            jobs = getattr(client, "jobs", None)
            if jobs is not None and hasattr(jobs, "create"):
                return jobs.create(query, **kwargs)
            search = getattr(client, "search", None)
            if callable(search):
                return search(query, **kwargs)
            raise RuntimeError("Splunk client does not expose search job submission")

        job = self._invoke("submit", submit_job, cancellation_token=cancellation_token)
        job_id = getattr(job, "name", None) or getattr(job, "sid", None)
        if not isinstance(job_id, str) or not job_id:
            if isinstance(job, Mapping):
                job_id = job.get("sid") or job.get("name")
        if not isinstance(job_id, str) or not job_id:
            raise AdapterError(FailureCategory.UNKNOWN, "Splunk did not return a job identifier", operation="submit")
        return job_id

    def _job(self, job_id: str) -> Any:
        if not isinstance(job_id, str) or not job_id.strip():
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "job_id must be non-empty", operation="job")
        client = self._get_client()
        jobs = getattr(client, "jobs", None)
        if jobs is not None:
            try:
                return jobs[job_id]
            except (KeyError, TypeError):
                pass
        getter = getattr(client, "get", None)
        if callable(getter):
            return getter(f"search/jobs/{job_id}")
        raise AdapterError(FailureCategory.UNKNOWN, "Splunk client does not expose job access", operation="job")

    def status(self, job_id: str, *, cancellation_token: Any = None) -> Mapping[str, Any]:
        job = self._invoke("status", lambda: self._job(job_id), cancellation_token=cancellation_token)
        content = getattr(job, "content", job)
        return dict(content) if isinstance(content, Mapping) else {"status": str(content)}

    def fetch_results(self, job_id: str, page: int = 0, limit: int = 100, *, cancellation_token: Any = None) -> list[Mapping[str, Any]]:
        if page < 0 or limit <= 0 or limit > 10_000:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "invalid result page or limit", operation="fetch_results")
        job = self._invoke("fetch_results", lambda: self._job(job_id), cancellation_token=cancellation_token)

        def fetch() -> Any:
            results = getattr(job, "results", None)
            if not callable(results):
                raise RuntimeError("Splunk job does not expose results")
            return results(offset=page * limit, count=limit)

        return self._records(self._invoke("fetch_results", fetch, cancellation_token=cancellation_token))[:limit]

    def cancel(self, job_id: str, *, cancellation_token: Any = None) -> bool:
        # Cancellation is best effort: once a hunt is being cancelled, the
        # cleanup request must still reach Splunk even when its token is set.
        job = self._invoke("cancel", lambda: self._job(job_id), cancellation_token=None)

        def do_cancel() -> Any:
            method = getattr(job, "cancel", None)
            if not callable(method):
                raise RuntimeError("Splunk job does not expose cancellation")
            return method()

        self._invoke("cancel", do_cancel, cancellation_token=None)
        return True

    def job_metadata(self, job_id: str, *, cancellation_token: Any = None) -> Mapping[str, Any]:
        return self.status(job_id, cancellation_token=cancellation_token)


# Compatibility aliases used by service code and tests.
SplunkConfig = SplunkConnectionConfig
DiscoveryResult = SplunkDiscovery
SplunkUnavailableError = AdapterError


__all__ = [
    "CancellationToken",
    "DiscoveryResult",
    "SplunkClient",
    "SplunkConfig",
    "SplunkConnectionConfig",
    "SplunkConnector",
    "SplunkDiscovery",
    "SplunkDiscoveryItem",
    "SplunkHealth",
    "SplunkUnavailableError",
]
