"""Tests for usage accounting and retry classifications."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.errors import (
    FailureCategory,
    FailureRecord,
    RetryClassification,
    max_retries_for,
    retry_classification,
    should_retry,
)


def test_failed_and_repair_model_requests_count_toward_call_budget() -> None:
    counters = BudgetCounters()
    counters.record_model_call(input_tokens=11, output_tokens=7, failed=True)
    counters.record_model_call(input_tokens=3, output_tokens=4, repair=True)

    assert counters.model_calls == 2
    assert counters.failed_model_calls == 1
    assert counters.model_repair_attempts == 1
    assert counters.model_input_tokens == 14
    assert counters.model_output_tokens == 11


def test_query_and_result_counters_include_failed_submissions() -> None:
    counters = BudgetCounters()
    counters.record_splunk_query(failed=True)
    counters.record_splunk_query()
    counters.record_result(rows=2, bytes_=128)
    assert counters.splunk_queries == 2
    assert counters.failed_splunk_queries == 1
    assert counters.cached_rows == 2
    assert counters.cached_bytes == 128


def test_budget_rejects_unsafe_limit_combinations() -> None:
    with pytest.raises(ValidationError):
        BudgetLimits(query_start_cutoff_seconds=1200)
    with pytest.raises(ValidationError):
        BudgetLimits(max_model_output_tokens_per_call=100_000)
    with pytest.raises(ValidationError):
        BudgetLimits(max_cached_rows_per_query=60_000)


def test_retry_categories_have_bounded_deterministic_classification() -> None:
    assert retry_classification(FailureCategory.RATE_LIMITED) is RetryClassification.RETRYABLE
    assert retry_classification(FailureCategory.MODEL_OUTPUT_INVALID) is RetryClassification.REPAIRABLE
    assert retry_classification(FailureCategory.TLS_CERTIFICATE_FAILURE) is RetryClassification.NON_RETRYABLE
    assert max_retries_for(FailureCategory.RATE_LIMITED) == 1
    assert max_retries_for(FailureCategory.MODEL_OUTPUT_INVALID) == 2
    assert should_retry(FailureCategory.RATE_LIMITED, 0)
    assert not should_retry(FailureCategory.RATE_LIMITED, 1)


def test_failure_record_cannot_claim_a_different_retry_class() -> None:
    with pytest.raises(ValidationError):
        FailureRecord(
            category=FailureCategory.INVALID_CREDENTIALS,
            retry_classification=RetryClassification.RETRYABLE,
            message="credentials rejected",
            retry_number=0,
        )
    record = FailureRecord(
        category=FailureCategory.RATE_LIMITED,
        retry_classification=RetryClassification.RETRYABLE,
        message="provider throttled request",
        retry_number=1,
    )
    assert record.category is FailureCategory.RATE_LIMITED
