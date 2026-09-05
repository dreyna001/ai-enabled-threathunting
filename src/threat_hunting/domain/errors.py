"""Failure categories and bounded retry classification rules."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, StrictInt, StrictStr, model_validator

from .common import DomainModel


class FailureCategory(StrEnum):
    """Normalized failure categories emitted by external-call adapters."""

    TEMPORARY_NETWORK = "temporary_network"
    RATE_LIMITED = "rate_limited"
    PROVIDER_SERVER_ERROR = "provider_server_error"
    INVALID_CREDENTIALS = "invalid_credentials"
    PERMISSION_DENIED = "permission_denied"
    INVALID_CONFIGURATION = "invalid_configuration"
    TLS_CERTIFICATE_FAILURE = "tls_certificate_failure"
    DATABASE_FAILURE = "database_failure"
    QUERY_POLICY_REJECTED = "query_policy_rejected"
    MODEL_OUTPUT_INVALID = "model_output_invalid"
    HARD_TIMEOUT = "hard_timeout"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"
    VALIDATION_FAILURE = "validation_failure"
    UNKNOWN = "unknown"


class RetryClassification(StrEnum):
    """Permitted retry behaviors for a normalized failure."""

    RETRYABLE = "retryable"
    REPAIRABLE = "repairable"
    NON_RETRYABLE = "non_retryable"


# More explicit aliases are useful when a caller needs to distinguish the one
# transport retry from a model's two structured-output repairs.
RetryClass = RetryClassification
ErrorCategory = FailureCategory


_RETRY_CLASSIFICATION: dict[FailureCategory, RetryClassification] = {
    FailureCategory.TEMPORARY_NETWORK: RetryClassification.RETRYABLE,
    FailureCategory.RATE_LIMITED: RetryClassification.RETRYABLE,
    FailureCategory.PROVIDER_SERVER_ERROR: RetryClassification.RETRYABLE,
    FailureCategory.MODEL_OUTPUT_INVALID: RetryClassification.REPAIRABLE,
    FailureCategory.INVALID_CREDENTIALS: RetryClassification.NON_RETRYABLE,
    FailureCategory.PERMISSION_DENIED: RetryClassification.NON_RETRYABLE,
    FailureCategory.INVALID_CONFIGURATION: RetryClassification.NON_RETRYABLE,
    FailureCategory.TLS_CERTIFICATE_FAILURE: RetryClassification.NON_RETRYABLE,
    FailureCategory.DATABASE_FAILURE: RetryClassification.NON_RETRYABLE,
    FailureCategory.QUERY_POLICY_REJECTED: RetryClassification.NON_RETRYABLE,
    FailureCategory.HARD_TIMEOUT: RetryClassification.NON_RETRYABLE,
    FailureCategory.BUDGET_EXHAUSTED: RetryClassification.NON_RETRYABLE,
    FailureCategory.CANCELLED: RetryClassification.NON_RETRYABLE,
    FailureCategory.VALIDATION_FAILURE: RetryClassification.NON_RETRYABLE,
    FailureCategory.UNKNOWN: RetryClassification.NON_RETRYABLE,
}


def retry_classification(category: FailureCategory | str) -> RetryClassification:
    """Return the deterministic retry class for a failure category."""

    return _RETRY_CLASSIFICATION[FailureCategory(category)]


def max_retries_for(category: FailureCategory | str) -> int:
    """Return the maximum retry/repair attempts for a category.

    Temporary transport failures have one retry; invalid model output has two
    repair attempts.  All other categories are not retried automatically.
    """

    classification = retry_classification(category)
    if classification is RetryClassification.RETRYABLE:
        return 1
    if classification is RetryClassification.REPAIRABLE:
        return 2
    return 0


def should_retry(category: FailureCategory | str, attempt: int) -> bool:
    """Return whether ``attempt`` may be followed by another request."""

    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 0:
        raise ValueError("attempt must be a non-negative integer")
    return attempt < max_retries_for(category)


class FailureRecord(DomainModel):
    """Structured failure metadata safe to persist in an audit record."""

    category: FailureCategory
    retry_classification: RetryClassification
    message: StrictStr = Field(min_length=1)
    retry_number: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_classification(self) -> "FailureRecord":
        """Prevent adapters from claiming an unsafe retry class."""

        expected = retry_classification(self.category)
        if expected is not self.retry_classification:
            raise ValueError(
                f"{self.category.value} must use retry classification {expected.value}"
            )
        if self.retry_number > max_retries_for(self.category):
            raise ValueError("retry_number exceeds the category retry limit")
        return self


# Alternate names used by API and worker layers.
DomainFailure = FailureRecord
Failure = FailureRecord

