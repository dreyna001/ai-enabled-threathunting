"""Deterministic model-provider factory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from pydantic import SecretStr

from .base import ModelAdapter, ModelProvider, _as_secret
from .bedrock import BedrockModelAdapter
from .fake import FakeModelAdapter
from .openai import LiteLLMModelAdapter, OpenAIModelAdapter, _validate_endpoint


@dataclass(frozen=True, slots=True)
class ModelConfiguration:
    provider: str
    model_name: str
    endpoint: str | None = None
    api_key: SecretStr | str | None = None
    region_name: str | None = None
    verify_tls: bool = True
    ca_bundle_path: Path | None = None
    timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        normalized = self.provider.lower().strip()
        aliases = {"local": "litellm", "local_openai": "litellm", "openai_compatible": "litellm"}
        normalized = aliases.get(normalized, normalized)
        if normalized not in {item.value for item in ModelProvider}:
            raise ValueError(f"unsupported model provider: {self.provider}")
        if not self.model_name.strip():
            raise ValueError("model_name must not be empty")
        object.__setattr__(self, "provider", normalized)
        object.__setattr__(self, "api_key", _as_secret(self.api_key))
        if self.endpoint is not None and normalized in {
            ModelProvider.OPENAI.value,
            ModelProvider.BEDROCK.value,
            ModelProvider.LITELLM.value,
        }:
            _validate_endpoint(self.endpoint, verify_tls=self.verify_tls)


class ModelFactory:
    """Select exactly one configured provider; no automatic failover."""

    @staticmethod
    def create(
        configuration: ModelConfiguration | Mapping[str, Any] | Any,
        *,
        client: Any | None = None,
        fake_responses: Any = None,
        fake_errors: Any = None,
    ) -> ModelAdapter:
        config = ModelFactory._coerce(configuration)
        provider = config.provider
        if provider == ModelProvider.OPENAI.value:
            return OpenAIModelAdapter(
                config.model_name,
                api_key=config.api_key,
                endpoint=config.endpoint,
                verify_tls=config.verify_tls,
                ca_bundle_path=config.ca_bundle_path,
                timeout_seconds=config.timeout_seconds,
                client=client,
            )
        if provider == ModelProvider.BEDROCK.value:
            return BedrockModelAdapter(
                config.model_name,
                region_name=config.region_name,
                endpoint=config.endpoint,
                verify_tls=config.verify_tls,
                ca_bundle_path=config.ca_bundle_path,
                timeout_seconds=config.timeout_seconds,
                client=client,
            )
        if provider == ModelProvider.LITELLM.value:
            if not config.endpoint:
                raise ValueError("litellm provider requires endpoint")
            return LiteLLMModelAdapter(
                config.model_name,
                endpoint=config.endpoint,
                api_key=config.api_key,
                verify_tls=config.verify_tls,
                ca_bundle_path=config.ca_bundle_path,
                timeout_seconds=config.timeout_seconds,
                client=client,
            )
        return FakeModelAdapter(
            config.model_name,
            responses=fake_responses,
            errors=fake_errors,
            timeout_seconds=config.timeout_seconds,
        )

    @staticmethod
    def _coerce(configuration: ModelConfiguration | Mapping[str, Any] | Any) -> ModelConfiguration:
        if isinstance(configuration, ModelConfiguration):
            return configuration
        if isinstance(configuration, Mapping):
            return ModelConfiguration(**dict(configuration))
        # Runtime ModelSettings is a strict Pydantic model.  Access fields by
        # name instead of importing config into the integration boundary.
        values = {
            "provider": getattr(configuration, "provider", None),
            "model_name": getattr(configuration, "model_name", None),
            "endpoint": getattr(configuration, "endpoint", None),
        }
        if not values["provider"] or not values["model_name"]:
            raise ValueError("model configuration must provide provider and model_name")
        return ModelConfiguration(**values)

    __call__ = create


ModelProviderFactory = ModelFactory


__all__ = ["ModelConfiguration", "ModelFactory", "ModelProviderFactory"]
