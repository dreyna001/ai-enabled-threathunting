"""Typed hunt limits and usage counters.

Counters are recorded before and after external actions by application
services.  In particular, failed model calls and structured-output repair
requests are real model requests and therefore increment ``model_calls``.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, StrictBool, StrictInt, model_validator

from .common import DomainModel

NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]


class BudgetLimits(DomainModel):
    """Deployment-adjustable per-hunt and shared concurrency limits."""

    hard_hunt_seconds: PositiveInt = 720
    query_start_cutoff_seconds: PositiveInt = 480
    max_inflight_query_seconds_after_cutoff: PositiveInt = 120
    synthesis_allowance_seconds: PositiveInt = 120
    max_agent_cycles: PositiveInt = 8
    max_splunk_queries: PositiveInt = 12
    max_concurrent_splunk_jobs: PositiveInt = 2
    max_active_hunts: PositiveInt = 1
    max_deployment_splunk_jobs: PositiveInt = 2
    splunk_query_timeout_seconds: PositiveInt = 120
    splunk_transport_timeout_seconds: PositiveInt = 120
    max_model_calls: PositiveInt = 12
    max_model_input_tokens: PositiveInt = 500_000
    max_model_output_tokens: PositiveInt = 96_000
    max_model_output_tokens_per_call: PositiveInt = 8_000
    max_model_call_timeout_seconds: PositiveInt = 120
    max_cached_rows_per_query: PositiveInt = 10_000
    max_cached_bytes_per_query: PositiveInt = 262_144_000
    max_cached_rows_per_hunt: PositiveInt = 50_000
    max_cached_bytes_per_hunt: PositiveInt = 1_073_741_824
    max_representative_events: PositiveInt = 100
    max_targeted_events: PositiveInt = 500
    max_model_repair_attempts: NonNegativeInt = 2
    max_transport_retries: NonNegativeInt = 1
    max_report_render_retries: NonNegativeInt = 1

    @model_validator(mode="after")
    def validate_relationships(self) -> "BudgetLimits":
        """Reject combinations that would make a hunt budget unsafe."""

        if self.query_start_cutoff_seconds >= self.hard_hunt_seconds:
            raise ValueError("query_start_cutoff_seconds must be below hard_hunt_seconds")
        if self.synthesis_allowance_seconds > self.hard_hunt_seconds:
            raise ValueError("synthesis_allowance_seconds cannot exceed hard_hunt_seconds")
        if self.max_inflight_query_seconds_after_cutoff > self.splunk_query_timeout_seconds:
            raise ValueError(
                "max_inflight_query_seconds_after_cutoff cannot exceed splunk_query_timeout_seconds"
            )
        if self.max_model_output_tokens_per_call > self.max_model_output_tokens:
            raise ValueError("per-call output limit cannot exceed total output limit")
        if self.max_cached_rows_per_query > self.max_cached_rows_per_hunt:
            raise ValueError("per-query row limit cannot exceed per-hunt row limit")
        if self.max_cached_bytes_per_query > self.max_cached_bytes_per_hunt:
            raise ValueError("per-query byte limit cannot exceed per-hunt byte limit")
        if self.max_targeted_events < self.max_representative_events:
            raise ValueError("targeted event limit cannot be below representative limit")
        return self


class BudgetCounters(DomainModel):
    """Mutable usage ledger for one hunt.

    ``model_calls`` counts every request sent to a model, including requests
    that fail and repair attempts.  ``failed_model_calls`` and
    ``model_repair_attempts`` provide the required accounting detail without
    changing the total-call semantics.
    """

    model_config = {"extra": "forbid", "validate_assignment": True}

    model_calls: NonNegativeInt = 0
    failed_model_calls: NonNegativeInt = 0
    model_repair_attempts: NonNegativeInt = 0
    model_input_tokens: NonNegativeInt = 0
    model_output_tokens: NonNegativeInt = 0
    splunk_queries: NonNegativeInt = 0
    failed_splunk_queries: NonNegativeInt = 0
    agent_cycles: NonNegativeInt = 0
    cached_rows: NonNegativeInt = 0
    cached_bytes: NonNegativeInt = 0
    transport_retries: NonNegativeInt = 0
    report_render_retries: NonNegativeInt = 0

    @model_validator(mode="after")
    def validate_counter_relationships(self) -> "BudgetCounters":
        """Ensure detail counters cannot exceed their parent totals."""

        if self.failed_model_calls > self.model_calls:
            raise ValueError("failed_model_calls cannot exceed model_calls")
        if self.model_repair_attempts > self.model_calls:
            raise ValueError("model_repair_attempts cannot exceed model_calls")
        if self.failed_splunk_queries > self.splunk_queries:
            raise ValueError("failed_splunk_queries cannot exceed splunk_queries")
        return self

    @staticmethod
    def _check_usage(value: int, field_name: str) -> None:
        """Raise a useful error for negative provider usage values."""

        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{field_name} must be a non-negative integer")

    def record_model_call(
        self,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        failed: bool = False,
        repair: bool = False,
    ) -> None:
        """Record one model request, including failed or repair requests."""

        self._check_usage(input_tokens, "input_tokens")
        self._check_usage(output_tokens, "output_tokens")
        if not isinstance(failed, bool) or not isinstance(repair, bool):
            raise ValueError("failed and repair must be booleans")
        self.model_calls += 1
        self.model_input_tokens += input_tokens
        self.model_output_tokens += output_tokens
        if failed:
            self.failed_model_calls += 1
        if repair:
            self.model_repair_attempts += 1

    def record_splunk_query(self, *, failed: bool = False) -> None:
        """Record one submitted Splunk search, including failed searches."""

        if not isinstance(failed, bool):
            raise ValueError("failed must be a boolean")
        self.splunk_queries += 1
        if failed:
            self.failed_splunk_queries += 1

    def record_result(self, *, rows: int, bytes_: int) -> None:
        """Add accepted temporary-result rows and bytes to the ledger."""

        self._check_usage(rows, "rows")
        self._check_usage(bytes_, "bytes_")
        self.cached_rows += rows
        self.cached_bytes += bytes_

    def record_cycle(self) -> None:
        """Record one agent investigation cycle."""

        self.agent_cycles += 1

    def record_transport_retry(self) -> None:
        """Record a bounded transport retry."""

        self.transport_retries += 1

    def record_report_render_retry(self) -> None:
        """Record a bounded report-render retry."""

        self.report_render_retries += 1

    def can_start_model_call(self, limits: BudgetLimits) -> bool:
        """Return whether another model request fits the call budget."""

        return self.model_calls < limits.max_model_calls

    def can_start_query(self, limits: BudgetLimits) -> bool:
        """Return whether another submitted Splunk search fits the budget."""

        return self.splunk_queries < limits.max_splunk_queries

    def exhausted(self, limits: BudgetLimits) -> bool:
        """Return whether any hard per-hunt budget has been reached."""

        return (
            self.model_calls >= limits.max_model_calls
            or self.model_input_tokens >= limits.max_model_input_tokens
            or self.model_output_tokens >= limits.max_model_output_tokens
            or self.splunk_queries >= limits.max_splunk_queries
            or self.agent_cycles >= limits.max_agent_cycles
            or self.cached_rows >= limits.max_cached_rows_per_hunt
            or self.cached_bytes >= limits.max_cached_bytes_per_hunt
        )


# Compatibility vocabulary used in services and tests.
UsageCounters = BudgetCounters
HuntBudget = BudgetLimits

