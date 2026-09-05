"""Portable model-provider contracts and adapters."""

from .base import (
    BaseModelAdapter,
    CancellationToken,
    ModelAdapter,
    ModelCancellationToken,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    parse_structured,
)
from .bedrock import BedrockAdapter, BedrockModelAdapter
from .fake import FakeAdapter, FakeModelAdapter
from .factory import ModelConfiguration, ModelFactory, ModelProviderFactory
from .openai import (
    LiteLLMAdapter,
    LiteLLMModelAdapter,
    LocalOpenAICompatibleAdapter,
    OpenAIAdapter,
    OpenAIModelAdapter,
)

__all__ = [
    "BaseModelAdapter",
    "BedrockAdapter",
    "BedrockModelAdapter",
    "CancellationToken",
    "FakeAdapter",
    "FakeModelAdapter",
    "LiteLLMAdapter",
    "LiteLLMModelAdapter",
    "LocalOpenAICompatibleAdapter",
    "ModelAdapter",
    "ModelCancellationToken",
    "ModelConfiguration",
    "ModelFactory",
    "ModelProvider",
    "ModelProviderFactory",
    "ModelRequest",
    "ModelResponse",
    "ModelUsage",
    "OpenAIAdapter",
    "OpenAIModelAdapter",
    "parse_structured",
]
