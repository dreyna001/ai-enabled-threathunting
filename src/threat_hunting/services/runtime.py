"""Production composition for configured Splunk and model adapters."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy.engine import Engine

from threat_hunting.config import (
    MODEL_API_KEY_FILE_ENV,
    RuntimeSettings,
    load_optional_secret_file,
    load_splunk_token,
)
from threat_hunting.domain.budgets import BudgetLimits
from threat_hunting.integrations.models.factory import ModelConfiguration, ModelFactory
from threat_hunting.integrations.splunk import SplunkConnectionConfig, SplunkConnector
from threat_hunting.services.jobs import JobLease
from threat_hunting.services.workflow import IntegrationUnavailable, WorkflowService


def budget_limits_from_settings(settings: RuntimeSettings) -> BudgetLimits:
    """Translate immutable runtime limits to the domain budget contract."""

    limits = settings.hunt_limits
    return BudgetLimits(
        hard_hunt_seconds=limits.hard_completion_minutes * 60,
        query_start_cutoff_seconds=min(480, max(1, limits.hard_completion_minutes * 60 - 1)),
        max_inflight_query_seconds_after_cutoff=min(limits.search_job_timeout_seconds, 120),
        synthesis_allowance_seconds=min(120, limits.hard_completion_minutes * 60 - 1),
        max_agent_cycles=limits.agent_cycles,
        max_splunk_queries=limits.query_count,
        max_concurrent_splunk_jobs=limits.per_hunt_query_concurrency,
        max_active_hunts=limits.active_hunts_per_deployment,
        max_deployment_splunk_jobs=limits.deployment_query_concurrency,
        splunk_query_timeout_seconds=limits.search_job_timeout_seconds,
        splunk_transport_timeout_seconds=limits.splunk_transport_timeout_seconds,
        max_model_calls=limits.model_calls,
        max_model_input_tokens=limits.input_tokens,
        max_model_output_tokens=limits.output_tokens,
        max_model_call_timeout_seconds=limits.model_call_timeout_seconds,
        max_cached_rows_per_query=limits.per_query_row_limit,
        max_cached_bytes_per_query=limits.per_query_byte_limit,
        max_cached_rows_per_hunt=limits.per_hunt_row_limit,
        max_cached_bytes_per_hunt=limits.per_hunt_byte_limit,
        max_representative_events=limits.representative_event_limit,
        max_targeted_events=limits.targeted_event_limit,
    )


def build_production_adapters(settings: RuntimeSettings) -> tuple[SplunkConnector, Any]:
    """Construct real adapters from non-secret settings and secret files.

    This function has no fake-provider branch.  Tests inject adapters directly
    into ``WorkflowService`` rather than changing production composition.
    """

    if settings.execution.mode != "direct":
        raise IntegrationUnavailable("MCP execution composition is not enabled for the direct worker")
    splunk = SplunkConnector(
        SplunkConnectionConfig(
            endpoint=settings.splunk.url,
            token=load_splunk_token(),
            verify_tls=settings.tls.verify,
            ca_bundle_path=settings.tls.ca_bundle_path,
            lab_only_allow_insecure=settings.tls.lab_only_allow_insecure,
            timeout_seconds=settings.hunt_limits.splunk_transport_timeout_seconds,
            app_namespace=settings.splunk.app_namespace,
            max_discovery_items=1_000,
            max_discovery_bytes=8 * 1024 * 1024,
        )
    )
    api_key = load_optional_secret_file(MODEL_API_KEY_FILE_ENV, label="model API key")
    if settings.model.provider in {"openai", "litellm"} and api_key is None:
        raise IntegrationUnavailable(
            f"{MODEL_API_KEY_FILE_ENV} must name the configured model API-key secret file"
        )
    model = ModelFactory.create(
        ModelConfiguration(
            provider=settings.model.provider,
            model_name=settings.model.model_name,
            endpoint=settings.model.endpoint,
            api_key=api_key,
            verify_tls=settings.tls.verify,
            ca_bundle_path=settings.tls.ca_bundle_path,
            timeout_seconds=settings.hunt_limits.model_call_timeout_seconds,
        )
    )
    return splunk, model


def build_production_service(engine: Engine, settings: RuntimeSettings) -> WorkflowService:
    """Build an owner-scoped service with production adapters selected once."""

    splunk, model = build_production_adapters(settings)
    return WorkflowService(
        engine,
        local_demo=False,
        splunk_connector=splunk,
        model_adapter=model,
        budget_limits=budget_limits_from_settings(settings),
        execution_config={
            "provider": settings.model.provider,
            "model_name": settings.model.model_name,
            "endpoint": settings.model.endpoint or "configured_provider_default",
            "deployment_scope_id": settings.execution.deployment_scope_id,
            "splunk_app_namespace": settings.splunk.app_namespace,
            "splunk_poll_interval_seconds": settings.hunt_limits.splunk_poll_interval_seconds,
            "hunt_limits": settings.hunt_limits.model_dump(mode="json"),
            "prompt_contract_version": "1.0",
            "spl_policy_version": "2026-01",
            "image_version": settings.image_version,
        },
    )


def build_worker_handler(service: WorkflowService) -> Callable[[JobLease], None]:
    """Return the durable worker callback bound to the configured service."""

    return service.execute_job


__all__ = [
    "budget_limits_from_settings",
    "build_production_adapters",
    "build_production_service",
    "build_worker_handler",
]
