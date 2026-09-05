"""Shared primitives used by the threat-hunting domain contracts.

The domain uses UTC-aware timestamps and application-assigned UUIDs.  This
module deliberately contains no persistence or integration concerns so that
the same validation rules can be used by API, worker, and test code.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, PlainSerializer


def _as_utc(value: datetime) -> datetime:
    """Validate and normalize a timestamp to an aware UTC datetime."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset")
    return value.astimezone(timezone.utc)


def _serialize_utc(value: datetime) -> str:
    """Serialize a UTC timestamp in canonical RFC 3339 ``Z`` form."""

    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# Pydantic parses RFC 3339 strings into ``datetime`` before the after-validator
# runs.  The serializer makes ``model_dump(mode='json')`` deterministic while
# still allowing normal ``datetime`` values in Python callers.
UTCDateTime = Annotated[
    datetime,
    AfterValidator(_as_utc),
    PlainSerializer(_serialize_utc, return_type=str, when_used="json"),
]


UnknownOrUTCDateTime = UTCDateTime | Literal["unknown"]


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Normalize an aware datetime to UTC, rejecting naive values."""

    return _as_utc(value)


def canonical_utc(value: datetime) -> str:
    """Return an aware datetime encoded as canonical RFC 3339 UTC text."""

    return _serialize_utc(_as_utc(value))


# Explicit aliases keep call sites readable and make the UTC boundary easy to
# discover when integrating the domain package.
now_utc = utc_now
to_utc = ensure_utc
serialize_utc = canonical_utc


class DomainModel(BaseModel):
    """Base model for strict domain contracts.

    Unknown fields are rejected to prevent model output from silently
    introducing unvalidated data.  Primitive strict types are declared on the
    individual fields where JSON inputs need to remain strings or integers.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def validate_sha256(value: str) -> str:
    """Validate and return a lowercase SHA-256 hexadecimal digest."""

    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("value must be a lowercase SHA-256 hex digest")
    return value


def validate_non_empty_mapping(value: dict[str, Any]) -> dict[str, Any]:
    """Require a selected result to contain at least one field."""

    if not value:
        raise ValueError("selected_result must contain at least one field")
    return value


def validate_uuid(value: UUID) -> UUID:
    """Return a UUID unchanged; useful as an explicit validator target."""

    return value
