"""Normalized failures raised by external adapters.

Error messages are deliberately safe to persist or return to callers.  They
never contain endpoint credentials or provider response bodies.
"""

from __future__ import annotations

from dataclasses import dataclass

from threat_hunting.domain.errors import (
    FailureCategory,
    RetryClassification,
    max_retries_for,
    retry_classification,
)


@dataclass(frozen=True, slots=True)
class AdapterFailure:
    """A safe, normalized description of one failed adapter operation."""

    category: FailureCategory
    message: str
    operation: str
    retry_classification: RetryClassification | None = None
    retry_number: int = 0

    def __post_init__(self) -> None:
        classification = self.retry_classification or retry_classification(self.category)
        if classification is not retry_classification(self.category):
            raise ValueError("retry classification does not match failure category")
        if self.retry_number < 0 or self.retry_number > max_retries_for(self.category):
            raise ValueError("retry_number exceeds the category retry limit")
        if not self.message.strip():
            raise ValueError("failure message must not be empty")
        object.__setattr__(self, "retry_classification", classification)


class AdapterError(RuntimeError):
    """Exception carrying an :class:`AdapterFailure` without secret material."""

    def __init__(
        self,
        category: FailureCategory,
        message: str,
        *,
        operation: str,
        retry_number: int = 0,
    ) -> None:
        self.failure = AdapterFailure(
            category=category,
            message=message,
            operation=operation,
            retry_number=retry_number,
        )
        super().__init__(message)

    @property
    def category(self) -> FailureCategory:
        """Return the normalized category for callers that do not need details."""

        return self.failure.category

    @property
    def operation(self) -> str:
        return self.failure.operation


__all__ = ["AdapterError", "AdapterFailure"]
