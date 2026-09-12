"""PydanticAI boundary for one structured hunt model step.

The application still owns budgets, evidence labels, and the single repair.
This adapter never starts a tool loop or a second provider request.
"""

from __future__ import annotations

from typing import Any

from pydantic_ai import Agent
from pydantic_ai.exceptions import RunCancelled, UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import ModelResponse as AgentModelResponse
from pydantic_ai.messages import TextPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.function import ModelMessage as AgentModelMessage
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import RequestUsage, UsageLimits

from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models.base import ModelAdapter, ModelRequest, ModelResponse


def complete_structured(
    adapter: ModelAdapter,
    request: ModelRequest,
    *,
    timeout_seconds: float | None = None,
    cancellation_token: Any = None,
) -> ModelResponse:
    """Run one PydanticAI Agent request through the existing provider adapter."""

    captured: ModelResponse | None = None

    async def function(_messages: list[AgentModelMessage], _info: AgentInfo) -> AgentModelResponse:
        nonlocal captured
        captured = adapter.complete(
            request,
            timeout_seconds=timeout_seconds,
            cancellation_token=cancellation_token,
        )
        return AgentModelResponse(
            parts=[TextPart(captured.text)],
            usage=RequestUsage(
                input_tokens=captured.usage.input_tokens,
                output_tokens=captured.usage.output_tokens,
            ),
            model_name=captured.model_name,
            provider_name=captured.provider_name,
            provider_response_id=captured.request_id,
        )

    settings: ModelSettings = {
        "temperature": 0 if request.temperature is None else request.temperature,
    }
    if request.max_output_tokens is not None:
        settings["max_tokens"] = request.max_output_tokens
    agent = Agent(
        FunctionModel(function, model_name=adapter.model_name),
        output_type=str,
        system_prompt=request.system or "",
        retries=0,
        name="hunt_structured_step",
        model_settings=settings,
    )
    agent.instrument = False
    try:
        agent.run_sync(
            "",
            usage_limits=UsageLimits(request_limit=1),
        )
    except AdapterError:
        raise
    except RunCancelled as exc:
        raise AdapterError(FailureCategory.CANCELLED, "model operation cancelled", operation="model.complete") from exc
    except UsageLimitExceeded as exc:
        raise AdapterError(FailureCategory.BUDGET_EXHAUSTED, "model call budget exhausted", operation="model.complete") from exc
    except UnexpectedModelBehavior:
        if captured is None:
            raise AdapterError(FailureCategory.UNKNOWN, "model provider returned a malformed response", operation="model.complete")
        return captured
    if captured is None:
        raise AdapterError(FailureCategory.UNKNOWN, "model provider returned a malformed response", operation="model.complete")
    return captured


__all__ = ["complete_structured"]
