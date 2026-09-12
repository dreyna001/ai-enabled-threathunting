"""Read-only Splunk transport and metadata discovery adapter.

Only the official ``splunk-sdk`` client is used when a real client is needed.
Unit tests inject a small fake client, which keeps the adapter deterministic and
avoids a live Splunk dependency.  Discovery uses metadata REST resources and
collection properties by default. Production planning also reads a bounded
indexed-sourcetype catalog using tstats. An explicitly approved source scope may
additionally use one bounded ``fieldsummary`` search to discover search-time
fields.
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from itertools import islice
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib.parse import urlsplit

from pydantic import SecretStr

from threat_hunting.domain.common import is_absolute_config_path
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
    max_representative_searches: int = 8
    representative_event_limit: int = 1

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
        if self.ca_bundle_path is not None and not is_absolute_config_path(self.ca_bundle_path):
            raise ValueError("ca_bundle_path must be absolute")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise ValueError("timeout_seconds must be greater than 0 and at most 300")
        if not self.app_namespace or len(self.app_namespace) > 100:
            raise ValueError("app_namespace must be a non-empty short identifier")
        if self.max_discovery_items <= 0 or self.max_discovery_items > 100_000:
            raise ValueError("max_discovery_items is outside the supported bound")
        if self.max_discovery_bytes <= 0 or self.max_discovery_bytes > 64 * 1024 * 1024:
            raise ValueError("max_discovery_bytes is outside the supported bound")
        if self.max_representative_searches <= 0 or self.max_representative_searches > 100:
            raise ValueError("max_representative_searches is outside the supported bound")
        if self.representative_event_limit <= 0 or self.representative_event_limit > 100:
            raise ValueError("representative_event_limit is outside the supported bound")
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
            kwargs["token"] = self.token.get_secret_value() if isinstance(self.token, SecretStr) else self.token
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
            from splunklib import client as splunk_client
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
        timeout_seconds: float | None = None,
    ) -> Any:
        if _is_cancelled(cancellation_token):
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation=operation)
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="splunk-adapter")
        future = executor.submit(callback)
        try:
            value = future.result(timeout=timeout_seconds or self.config.timeout_seconds)
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
        if isinstance(value, Mapping) and "body" in value and "status" in value:
            return SplunkConnector._decode_response(value["body"], max_bytes=max_bytes)
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
            raw = reader(max_bytes + 1) if max_bytes is not None else reader()
            return SplunkConnector._decode_response(raw, max_bytes=max_bytes)
        body = getattr(value, "body", None)
        if body is not None:
            return SplunkConnector._decode_response(body, max_bytes=max_bytes)
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
            records = [value]
        else:
            try:
                items = islice(value, limit) if limit is not None else iter(value)
                records = []
                for item in items:
                    if isinstance(item, Mapping):
                        records.append(item)
                        continue
                    name = getattr(item, "name", None)
                    content = getattr(item, "content", None)
                    if isinstance(content, Mapping):
                        record: dict[str, Any] = {"content": content}
                        if isinstance(name, str) and name:
                            record["name"] = name
                        records.append(record)
                    elif isinstance(name, str) and name:
                        records.append({"name": name})
                    else:
                        records.append({"value": item})
            except TypeError:
                records = [{"value": value}]
        if max_bytes is not None:
            encoded = json.dumps(records, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
            if len(encoded) > max_bytes:
                raise ValueError("Splunk response exceeds the configured byte limit")
        return records

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
            lambda: getter(endpoint, count=self.config.max_discovery_items, output_mode="json"),
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

    def _searchable_indexes(self, *, cancellation_token: Any = None) -> tuple[set[str], set[str]]:
        """Resolve this account's explicit and inherited index permissions."""

        context = self._endpoint("current_context", "authentication/current-context", cancellation_token=cancellation_token)
        roles = self._record_content(context[0]).get("roles") if len(context) == 1 else None
        if (not isinstance(roles, (list, tuple)) or not roles or len(roles) > 32
                or any(not isinstance(role, str) or role in {".", ".."}
                       or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", role) for role in roles)):
            raise ValueError("current account roles are unavailable or exceed the bounded role scope")
        allowed: set[str] = set()
        denied: set[str] = set()
        for role in dict.fromkeys(roles):
            records = self._endpoint("role_scope", f"authorization/roles/{role}", cancellation_token=cancellation_token)
            if len(records) != 1 or self._record_name(records[0]) != role:
                raise ValueError("effective role permissions are unavailable")
            content = self._record_content(records[0])
            for key, target in (("srchIndexesAllowed", allowed), ("imported_srchIndexesAllowed", allowed),
                                ("srchIndexesDisallowed", denied), ("imported_srchIndexesDisallowed", denied)):
                patterns = content.get(key, [])
                if isinstance(patterns, str):
                    patterns = [patterns] if patterns else []
                if (not isinstance(patterns, (list, tuple)) or len(patterns) > self.config.max_discovery_items
                        or any(not isinstance(pattern, str) or not re.fullmatch(r"[A-Za-z0-9_.:*-]{1,256}", pattern)
                               for pattern in patterns)):
                    raise ValueError("effective index permissions are malformed or exceed the discovery limit")
                target.update(patterns)
        return allowed, denied

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

    @staticmethod
    def _approved_scope_values(values: Iterable[str] | None, *, label: str, limit: int) -> tuple[str, ...]:
        """Normalize a bounded exact-value scope supplied for schema discovery."""

        if values is None:
            return ()
        if isinstance(values, str):
            raise AdapterError(
                FailureCategory.VALIDATION_FAILURE,
                f"approved {label} must be a bounded sequence of strings",
                operation="discover",
            )
        normalized: list[str] = []
        for value in islice(values, limit + 1):
            if not isinstance(value, str) or not value.strip():
                raise AdapterError(
                    FailureCategory.VALIDATION_FAILURE,
                    f"approved {label} must contain non-empty strings",
                    operation="discover",
                )
            value = value.strip()
            # These values are inserted into a fixed search expression.  Keep
            # them exact and token-like; wildcards and SPL syntax are not an
            # approved discovery scope.
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
                raise AdapterError(
                    FailureCategory.VALIDATION_FAILURE,
                    f"approved {label} must contain exact safe identifiers",
                    operation="discover",
                )
            if value not in normalized:
                normalized.append(value)
        if len(normalized) > limit:
            raise AdapterError(
                FailureCategory.BUDGET_EXHAUSTED,
                f"approved {label} exceed the discovery limit",
                operation="discover",
            )
        return tuple(normalized)

    @staticmethod
    def _absolute_utc(value: datetime | str | None, *, label: str) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise AdapterError(
                    FailureCategory.VALIDATION_FAILURE,
                    f"{label} must be an absolute RFC3339 timestamp",
                    operation="discover",
                ) from exc
        else:
            raise AdapterError(
                FailureCategory.VALIDATION_FAILURE,
                f"{label} must be an absolute RFC3339 timestamp",
                operation="discover",
            )
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise AdapterError(
                FailureCategory.VALIDATION_FAILURE,
                f"{label} must include a timezone",
                operation="discover",
            )
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _schema_fields(records: Iterable[Mapping[str, Any]]) -> list[str]:
        """Extract fieldsummary rows or keys from bounded representative rows."""

        fields: list[str] = []
        for record in records:
            field = record.get("field") or record.get("fieldName")
            if isinstance(field, str) and field.strip():
                fields.append(field.strip())
                continue
            for key in record:
                if isinstance(key, str) and key.strip() and key not in {"_raw", "_time"}:
                    fields.append(key.strip())
        return list(dict.fromkeys(fields))

    def _representative_schema(
        self,
        index: str,
        sourcetype: str,
        *,
        earliest_utc: datetime,
        latest_utc: datetime,
        cancellation_token: Any = None,
    ) -> list[str]:
        """Read a bounded fieldsummary result for one approved source pair."""

        client = self._get_client()
        query = (
            f'search index="{index}" sourcetype="{sourcetype}" '
            f"| head {self.config.representative_event_limit} | fieldsummary"
        )
        kwargs = {
            "earliest_time": earliest_utc.isoformat().replace("+00:00", "Z"),
            "latest_time": latest_utc.isoformat().replace("+00:00", "Z"),
            "output_mode": "json",
            # ``fieldsummary`` emits one row per field, so cap its output by
            # the discovery item budget while fixed ``head`` separately caps
            # the number of events inspected.
            "max_count": self.config.max_discovery_items,
        }

        def submit_schema_search() -> Any:
            search = getattr(client, "search", None)
            if callable(search):
                return search(query, **kwargs)
            jobs = getattr(client, "jobs", None)
            create = getattr(jobs, "create", None)
            if callable(create):
                return create(query, **kwargs)
            raise RuntimeError("Splunk client does not expose read-only search")

        # Keep the returned job available so cancellation that arrives while
        # Splunk is creating it can still cancel that job before returning.
        # The caller checks the token immediately before entering this method.
        job_or_rows = self._invoke("discover.representative_schema", submit_schema_search)
        if _is_cancelled(cancellation_token):
            cancel = getattr(job_or_rows, "cancel", None)
            if callable(cancel):
                try:
                    cancel()
                except Exception:  # noqa: BLE001 - cancellation is best effort
                    pass
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="discover")
        results = getattr(job_or_rows, "results", None)
        if callable(results):
            try:
                self._wait_for_representative_job(job_or_rows, cancellation_token=cancellation_token)
                job_or_rows = self._invoke(
                    "discover.representative_schema.results",
                    lambda: results(output_mode="json", count=self.config.max_discovery_items),
                    cancellation_token=cancellation_token,
                )
            except AdapterError:
                cancel = getattr(job_or_rows, "cancel", None)
                if callable(cancel) and _is_cancelled(cancellation_token):
                    try:
                        cancel()
                    except Exception:  # noqa: BLE001 - cancellation is best effort
                        pass
                raise
        try:
            records = self._records(
                job_or_rows,
                limit=self.config.max_discovery_items,
                max_bytes=self.config.max_discovery_bytes,
            )
        except ValueError as exc:
            raise AdapterError(
                FailureCategory.BUDGET_EXHAUSTED,
                "representative schema exceeded the configured byte limit",
                operation="discover.representative_schema",
            ) from exc
        return self._schema_fields(records)

    def _wait_for_representative_job(self, job: Any, *, cancellation_token: Any = None) -> None:
        """Wait for a read-only discovery job within the transport timeout."""

        is_done = getattr(job, "is_done", None)
        content = getattr(job, "content", None)
        has_status = callable(is_done) or isinstance(content, Mapping)
        if not has_status:
            return
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            if _is_cancelled(cancellation_token):
                cancel = getattr(job, "cancel", None)
                if callable(cancel):
                    try:
                        cancel()
                    except Exception:  # noqa: BLE001 - cancellation is best effort
                        pass
                raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="discover")
            if callable(is_done):
                done = bool(
                    self._invoke(
                        "discover.representative_schema.status",
                        is_done,
                        cancellation_token=cancellation_token,
                        timeout_seconds=max(0.001, min(self.config.timeout_seconds, deadline - time.monotonic())),
                    )
                )
            else:
                current = getattr(job, "content", {})
                done = False
                if isinstance(current, Mapping):
                    done = any(
                        value is True
                        or str(value).lower()
                        in {"1", "true", "yes", "done", "complete", "finished", "success", "successful"}
                        for key, value in current.items()
                        if key in {"isDone", "done", "is_done", "dispatchState", "state", "status"}
                    )
            if done:
                return
            if time.monotonic() >= deadline:
                cancel = getattr(job, "cancel", None)
                if callable(cancel):
                    try:
                        cancel()
                    except Exception:  # noqa: BLE001 - cancellation is best effort
                        pass
                raise AdapterError(
                    FailureCategory.HARD_TIMEOUT,
                    "representative schema search exceeded its transport timeout",
                    operation="discover.representative_schema",
                )
            refresh = getattr(job, "refresh", None)
            if callable(refresh):
                self._invoke(
                    "discover.representative_schema.refresh",
                    refresh,
                    cancellation_token=cancellation_token,
                    timeout_seconds=max(0.001, min(self.config.timeout_seconds, deadline - time.monotonic())),
                )
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def _representative_event(
        self,
        index: str,
        *,
        earliest_utc: datetime,
        latest_utc: datetime,
        cancellation_token: Any = None,
    ) -> list[Mapping[str, Any]]:
        """Read one bounded event from an index to derive an actual source pair."""

        client = self._get_client()
        query = f'search index="{index}" | head {self.config.representative_event_limit}'
        kwargs = {
            "earliest_time": earliest_utc.isoformat().replace("+00:00", "Z"),
            "latest_time": latest_utc.isoformat().replace("+00:00", "Z"),
            "output_mode": "json",
            "max_count": self.config.representative_event_limit,
        }

        def submit() -> Any:
            search = getattr(client, "search", None)
            if callable(search):
                return search(query, **kwargs)
            jobs = getattr(client, "jobs", None)
            create = getattr(jobs, "create", None)
            if callable(create):
                return create(query, **kwargs)
            raise RuntimeError("Splunk client does not expose read-only search")

        job_or_rows = self._invoke(
            "discover.representative_event",
            submit,
            cancellation_token=cancellation_token,
        )
        if _is_cancelled(cancellation_token):
            cancel = getattr(job_or_rows, "cancel", None)
            if callable(cancel):
                try:
                    cancel()
                except Exception:  # noqa: BLE001 - cancellation is best effort
                    pass
            raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="discover")
        results = getattr(job_or_rows, "results", None)
        if callable(results):
            self._wait_for_representative_job(job_or_rows, cancellation_token=cancellation_token)
            job_or_rows = self._invoke(
                "discover.representative_event.results",
                lambda: results(output_mode="json", count=self.config.representative_event_limit),
                cancellation_token=cancellation_token,
            )
        try:
            return self._records(
                job_or_rows,
                limit=self.config.representative_event_limit,
                max_bytes=self.config.max_discovery_bytes,
            )
        except ValueError as exc:
            raise AdapterError(
                FailureCategory.BUDGET_EXHAUSTED,
                "representative event exceeded the configured byte limit",
                operation="discover.representative_event",
            ) from exc

    def _indexed_sourcetypes(
        self, indexes: Iterable[str], *, latest_utc: datetime, cancellation_token: Any = None,
    ) -> list[Mapping[str, Any]]:
        """Read indexed source names without scanning or returning raw events."""
        names = self._approved_scope_values(indexes, label="indexes", limit=self.config.max_discovery_items)
        if not names:
            return []
        scope = " OR ".join(f'index="{name}"' for name in names)
        query = f"| tstats count WHERE ({scope}) BY sourcetype | head {self.config.max_discovery_items}"
        client = self._get_client()
        kwargs = {"earliest_time": "0", "latest_time": latest_utc.isoformat().replace("+00:00", "Z"),
                  "output_mode": "json", "max_count": self.config.max_discovery_items}

        def submit() -> Any:
            search = getattr(client, "search", None)
            if callable(search):
                return search(query, **kwargs)
            create = getattr(getattr(client, "jobs", None), "create", None)
            if callable(create):
                return create(query, **kwargs)
            raise RuntimeError("Splunk client does not expose read-only search")

        job = self._invoke("discover.indexed_sourcetypes", submit)
        try:
            if _is_cancelled(cancellation_token):
                raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="discover")
            results = getattr(job, "results", None)
            if callable(results):
                self._wait_for_representative_job(job, cancellation_token=cancellation_token)
                rows = self._invoke(
                    "discover.indexed_sourcetypes.results",
                    lambda: results(output_mode="json", count=self.config.max_discovery_items),
                    cancellation_token=cancellation_token,
                )
            else:
                rows = job
            return self._records(rows, limit=self.config.max_discovery_items, max_bytes=self.config.max_discovery_bytes)
        finally:
            if _is_cancelled(cancellation_token):
                cancel = getattr(job, "cancel", None)
                if callable(cancel):
                    try:
                        cancel()
                    except Exception:  # noqa: BLE001 - cancellation cleanup is best effort
                        pass

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
        except Exception as exc:  # noqa: BLE001 - normalize SDK property failures
            return SplunkHealth(False, checked, self._normalize_error(exc, operation="healthcheck").failure.category)
        return SplunkHealth(True, checked)

    def discover(
        self,
        *,
        approved_indexes: Iterable[str] | None = None,
        approved_sourcetypes: Iterable[str] | None = None,
        source_pairs: Iterable[tuple[str, str]] | None = None,
        earliest_utc: datetime | str | None = None,
        latest_utc: datetime | str | None = None,
        include_representative_schemas: bool = False,
        include_indexed_sources: bool = False,
        cancellation_token: Any = None,
    ) -> SplunkDiscovery:
        """Discover catalog metadata and optionally bounded representative schemas.

        Metadata endpoints remain the default.  Representative searches are
        attempted only when the caller supplies exact approved source values
        and absolute UTC bounds; those values are intersected with the
        metadata catalog before a fixed ``head``/``fieldsummary`` search runs.
        """

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
        sampling_limited = False
        approved_index_values = self._approved_scope_values(
            approved_indexes,
            label="indexes",
            limit=self.config.max_discovery_items,
        )
        approved_sourcetype_values = self._approved_scope_values(
            approved_sourcetypes,
            label="sourcetypes",
            limit=self.config.max_discovery_items,
        )
        representative_earliest = self._absolute_utc(earliest_utc, label="earliest_utc")
        representative_latest = self._absolute_utc(latest_utc, label="latest_utc")
        selected_pairs: list[tuple[str, str]] | None = None
        if source_pairs is not None:
            selected_pairs = []
            for pair in islice(source_pairs, self.config.max_discovery_items + 1):
                if (not isinstance(pair, (tuple, list)) or len(pair) != 2
                        or pair[0] not in approved_index_values or pair[1] not in approved_sourcetype_values):
                    raise AdapterError(FailureCategory.VALIDATION_FAILURE, "source pair is outside the exact discovery scope", operation="discover")
                if tuple(pair) not in selected_pairs:
                    selected_pairs.append((pair[0], pair[1]))
            if not selected_pairs or len(selected_pairs) > self.config.max_discovery_items or representative_earliest is None or representative_latest is None:
                raise AdapterError(FailureCategory.VALIDATION_FAILURE, "source pairs require a bounded source and UTC scope", operation="discover")
        if (representative_earliest is None) != (representative_latest is None):
            raise AdapterError(
                FailureCategory.VALIDATION_FAILURE,
                "earliest_utc and latest_utc must be supplied together",
                operation="discover",
            )
        if representative_earliest is not None and representative_latest is not None:
            if representative_latest <= representative_earliest:
                raise AdapterError(
                    FailureCategory.VALIDATION_FAILURE,
                    "latest_utc must be after earliest_utc",
                    operation="discover",
                )
            if (representative_latest - representative_earliest).total_seconds() > 7 * 24 * 60 * 60:
                raise AdapterError(
                    FailureCategory.BUDGET_EXHAUSTED,
                    "representative discovery time range exceeds seven days",
                    operation="discover",
                )
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
                    "saved/sourcetypes",
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

        try:
            allowed_patterns, denied_patterns = self._searchable_indexes(cancellation_token=cancellation_token)
        except AdapterError as exc:
            if exc.category is FailureCategory.CANCELLED:
                raise
            errors.append(f"index_scope: {exc.failure.category.value}")
            allowed_patterns, denied_patterns = set(), set()
        except ValueError:
            errors.append("index_scope: effective search permissions are unavailable or malformed")
            allowed_patterns, denied_patterns = set(), set()

        def matches_index(name: str, patterns: set[str]) -> bool:
            # Splunk's * wildcard excludes internal indexes unless the pattern
            # starts with _. Explicit or inherited denies override all allows.
            return any(name.startswith("_") == pattern.startswith("_") and fnmatchcase(name, pattern)
                       for pattern in patterns)

        for record in results.get("indexes", []):
            name = self._record_name(record)
            if not name or not matches_index(name, allowed_patterns) or matches_index(name, denied_patterns):
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
                    if name in schemas and set(schemas[name]) != set(schema_fields):
                        limitations.append(f"differing field lists were returned for sourcetype {name}; their union is observational, not an exhaustive schema")
                    schemas[name] = list(dict.fromkeys([*schemas.get(name, []), *schema_fields]))

        indexed_tstats_succeeded = False
        if include_indexed_sources:
            limitations.append(
                "Source catalog combines configured sourcetypes with indexed sourcetypes observed through discovery time. "
                "Catalog membership does not establish a source pair, activity in the hunt window, or continuous coverage; "
                "absence from this bounded catalog does not prove a source is unavailable."
            )
            try:
                probe_indexes = approved_index_values or indexes
                source_rows = self._indexed_sourcetypes(
                    probe_indexes, latest_utc=discovered_at, cancellation_token=cancellation_token,
                )
                indexed_tstats_succeeded = bool(probe_indexes)
                for record in source_rows:
                    name = record.get("sourcetype")
                    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", name):
                        raise ValueError("indexed sourcetype metadata contained an invalid identifier")
                    sourcetypes.append(name)
                if len(source_rows) >= self.config.max_discovery_items:
                    sampling_limited = True
                    limitations.append("indexed sourcetype result limit reached; discovery is partial")
            except AdapterError as exc:
                if exc.category is FailureCategory.CANCELLED:
                    raise
                errors.append(f"indexed_sourcetypes: {exc.failure.category.value}")
            except Exception as exc:  # noqa: BLE001 - preserve observable partial discovery
                normalized = self._normalize_error(exc, operation="discover.indexed_sourcetypes")
                errors.append(f"indexed_sourcetypes: {normalized.failure.category.value}")

        for record in results.get("fields", []):
            name = self._record_name(record)
            if name:
                fields.append(name)
            fields.extend(self._field_names(record))

        metadata_has_complete_schemas = bool(sourcetypes) and all(schemas.get(source) for source in sourcetypes)
        if include_representative_schemas and not metadata_has_complete_schemas and not any(
            (approved_index_values, approved_sourcetype_values, representative_earliest, representative_latest)
        ):
            candidates = [
                (index, values)
                for index, values in coverage.items()
                if values.get("earliest") and values.get("latest")
            ][: self.config.max_representative_searches]
            if len(coverage) > len(candidates):
                limitations.append("representative schema search limit reached; discovery is partial")
                sampling_limited = True
            for index, bounds in candidates:
                try:
                    index_earliest = self._absolute_utc(bounds["earliest"], label="index earliest coverage")
                    index_latest = self._absolute_utc(bounds["latest"], label="index latest coverage")
                    if index_earliest is None or index_latest is None or index_latest <= index_earliest:
                        continue
                    if (index_latest - index_earliest).total_seconds() > 7 * 24 * 60 * 60:
                        index_earliest = index_latest - timedelta(days=7)
                    rows = self._representative_event(
                        index,
                        earliest_utc=index_earliest,
                        latest_utc=index_latest,
                        cancellation_token=cancellation_token,
                    )
                    for row in rows:
                        source = row.get("sourcetype")
                        if not isinstance(source, str) or not source.strip():
                            limitations.append(f"representative event had no sourcetype for index {index}")
                            continue
                        source = source.strip()
                        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", source):
                            limitations.append(f"representative event sourcetype was not a safe identifier for index {index}")
                            continue
                        if source not in sourcetypes:
                            sourcetypes.append(source)
                        schema_fields = self._representative_schema(
                            index,
                            source,
                            earliest_utc=index_earliest,
                            latest_utc=index_latest,
                            cancellation_token=cancellation_token,
                        )
                        if schema_fields:
                            schemas.setdefault(source, []).extend(schema_fields)
                            fields.extend(schema_fields)
                except AdapterError as exc:
                    if exc.category is FailureCategory.CANCELLED:
                        raise
                    errors.append(f"representative_schema[{index}]: {exc.failure.category.value}")
                except Exception as exc:  # noqa: BLE001 - normalize partial discovery
                    normalized = self._normalize_error(exc, operation="discover.representative_schema")
                    errors.append(f"representative_schema[{index}]: {normalized.failure.category.value}")
        elif approved_index_values and approved_sourcetype_values and representative_earliest and representative_latest:
            catalog_indexes = set(indexes)
            catalog_sourcetypes = set(sourcetypes)
            candidate_pairs = [
                pair for pair in selected_pairs
                if pair[0] in catalog_indexes and pair[1] in catalog_sourcetypes
            ] if selected_pairs is not None else [
                (index, sourcetype)
                for index in approved_index_values
                if index in catalog_indexes
                for sourcetype in approved_sourcetype_values
                if sourcetype in catalog_sourcetypes
            ]
            if len(candidate_pairs) > self.config.max_representative_searches:
                limitations.append("representative schema search limit reached; discovery is partial")
                sampling_limited = True
            if selected_pairs is not None and len(candidate_pairs) != len(selected_pairs):
                limitations.append("some requested source pairs were not present in the catalog; discovery is partial")
                sampling_limited = True
            pairs = candidate_pairs[: self.config.max_representative_searches]
            if not pairs:
                limitations.append("approved representative schema scope was not present in Splunk metadata")
            limitations.append(
                f"Field lists combine catalog metadata and any bounded samples of up to {self.config.representative_event_limit} events per source "
                f"within {representative_earliest.isoformat()} to {representative_latest.isoformat()}; they are not exhaustive. "
                "A field missing from a sample does not establish that the source cannot provide it."
            )
            for index, sourcetype in pairs:
                if selected_pairs is None and schemas.get(sourcetype):
                    continue
                if _is_cancelled(cancellation_token):
                    raise AdapterError(FailureCategory.CANCELLED, "operation cancelled", operation="discover")
                try:
                    schema_fields = self._representative_schema(
                        index,
                        sourcetype,
                        earliest_utc=representative_earliest,
                        latest_utc=representative_latest,
                        cancellation_token=cancellation_token,
                    )
                    if schema_fields:
                        schemas.setdefault(sourcetype, []).extend(schema_fields)
                        fields.extend(schema_fields)
                    else:
                        limitations.append(f"representative schema was empty for {index}/{sourcetype}")
                except AdapterError as exc:
                    if exc.category is FailureCategory.CANCELLED:
                        raise
                    errors.append(f"representative_schema[{index}/{sourcetype}]: {exc.failure.category.value}")
                except Exception as exc:  # noqa: BLE001 - normalize partial discovery
                    normalized = self._normalize_error(exc, operation="discover.representative_schema")
                    errors.append(
                        f"representative_schema[{index}/{sourcetype}]: {normalized.failure.category.value}"
                    )
        elif any((approved_index_values, approved_sourcetype_values, representative_earliest, representative_latest)):
            limitations.append(
                "representative schema discovery requires approved indexes, sourcetypes, and absolute UTC bounds"
            )

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
        if indexed_tstats_succeeded:
            tstats_available = True
            limitations.append(
                "Indexed-source tstats succeeded in this discovery scope; this does not establish "
                "data-model acceleration or support for every tstats query."
            )
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
        complete = not errors and not sampling_limited and bool(indexes or sourcetypes)
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
        requested_job_id = kwargs.get("id")
        if requested_job_id is not None and (not isinstance(requested_job_id, str) or not requested_job_id):
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "Splunk job id must be non-empty", operation="submit")

        def submit_job() -> Any:
            jobs = getattr(client, "jobs", None)
            if jobs is not None and hasattr(jobs, "create"):
                if requested_job_id is not None:
                    try:
                        return jobs[requested_job_id]
                    except (KeyError, TypeError):
                        pass
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
        if requested_job_id is not None and job_id != requested_job_id:
            cancel = getattr(job, "cancel", None)
            if callable(cancel):
                cancel()
            raise AdapterError(FailureCategory.UNKNOWN, "Splunk did not honor the requested job id", operation="submit")
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

    def fetch_results(
        self,
        job_id: str,
        page: int = 0,
        limit: int = 100,
        *,
        max_bytes: int | None = None,
        cancellation_token: Any = None,
        timeout_seconds: float | None = None,
    ) -> list[Mapping[str, Any]]:
        if page < 0 or limit <= 0 or limit > 10_000:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "invalid result page or limit", operation="fetch_results")
        if max_bytes is not None and max_bytes <= 0:
            raise AdapterError(FailureCategory.VALIDATION_FAILURE, "invalid result byte limit", operation="fetch_results")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise AdapterError(FailureCategory.HARD_TIMEOUT, "Result page deadline exceeded", operation="fetch_results")

        def fetch() -> list[Mapping[str, Any]]:
            job = self._job(job_id)
            results = getattr(job, "results", None)
            if not callable(results):
                raise RuntimeError("Splunk job does not expose results")
            try:
                return self._records(
                    results(offset=page * limit, count=limit, output_mode="json"),
                    limit=limit, max_bytes=max_bytes,
                )[:limit]
            except ValueError as exc:
                raise AdapterError(
                    FailureCategory.BUDGET_EXHAUSTED,
                    "Splunk result exceeded the configured byte limit", operation="fetch_results",
                ) from exc

        return self._invoke(
            "fetch_results", fetch, cancellation_token=cancellation_token,
            timeout_seconds=min(timeout_seconds, self.config.timeout_seconds) if timeout_seconds is not None else None,
        )

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
