#!/usr/bin/env python3
"""Run the versioned known-answer qualification suite.

Synthetic mode verifies the scorer with scripted fixtures, without measuring
model quality. Observed mode scores exported workflow results and independent
analyst judgments without making external calls. Live
mode is intentionally explicit and requires secret-file configuration before
any adapter is constructed.  The live adapter is supplied by the configured
application workflow; this runner only performs bounded preflight and scores
the adapter's terminal run records against the private answer key.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from known_answer.observed import score_observed_runs  # noqa: E402

from known_answer.bindings import (  # noqa: E402
    BINDINGS_ENV,
    BindingsError,
    HuntResultExport,
    KnownAnswerBindings,
    adapter_configuration_without_bindings,
    extract_synthetic_runs,
    load_bindings_from_env,
)
from known_answer.harness import (  # noqa: E402
    KnownAnswerError,
    SyntheticRun,
    load_answers,
    load_cases,
    run_suite,
    score_runs,
)
from threat_hunting.domain.common import is_absolute_config_path  # noqa: E402
from threat_hunting.integrations.models import ModelConfiguration, ModelFactory  # noqa: E402
from threat_hunting.integrations.splunk import SplunkConnectionConfig, SplunkConnector  # noqa: E402


class LiveConfigurationError(RuntimeError):
    """Raised when live qualification lacks required deployment settings."""


_LIVE_ADAPTER_ENV = "THREAT_HUNTING_KNOWN_ANSWER_LIVE_ADAPTER"
_FIXTURE_ID_ENV = "THREAT_HUNTING_KNOWN_ANSWER_FIXTURE_ID"
_IMPLEMENTED_FAULT_INJECTORS: frozenset[str] = frozenset()


def _env_flag(name: str, *, default: bool = False) -> bool:
    """Parse a strict boolean environment flag without accepting ambiguity."""

    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().casefold()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise LiveConfigurationError(f"{name} must be one of true/false")


def _read_secret(path_value: str, *, label: str) -> str:
    """Read a non-empty secret without returning its contents in errors."""

    path = Path(path_value)
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise LiveConfigurationError(f"could not read the configured {label} secret file") from exc
    if not value:
        raise LiveConfigurationError(f"the configured {label} secret file is empty")
    return value


def _require_live_configuration() -> dict[str, str]:
    required = {
        "THREAT_HUNTING_SPLUNK_URL": "Splunk endpoint",
        "THREAT_HUNTING_SPLUNK_TOKEN_FILE": "Splunk token secret-file path",
        "THREAT_HUNTING_MODEL_PROVIDER": "model provider",
        "THREAT_HUNTING_MODEL_NAME": "model name",
        _FIXTURE_ID_ENV: "non-production fixture identifier",
    }
    missing = [label for name, label in required.items() if not os.environ.get(name)]
    if missing:
        raise LiveConfigurationError(
            "live qualification requires configured secret-file/runtime values: "
            + ", ".join(missing)
        )
    provider = os.environ["THREAT_HUNTING_MODEL_PROVIDER"].strip().casefold()
    if provider not in {"openai", "bedrock", "litellm"}:
        raise LiveConfigurationError(
            "live qualification requires a real model provider: openai, bedrock, or litellm"
        )
    _read_secret(os.environ["THREAT_HUNTING_SPLUNK_TOKEN_FILE"], label="Splunk token")
    api_key_file = os.environ.get("THREAT_HUNTING_MODEL_API_KEY_FILE")
    if provider in {"openai", "litellm"} and not api_key_file:
        raise LiveConfigurationError(
            "live qualification requires THREAT_HUNTING_MODEL_API_KEY_FILE for the configured model provider"
        )
    if api_key_file:
        _read_secret(api_key_file, label="model API key")

    endpoint = os.environ.get("THREAT_HUNTING_MODEL_ENDPOINT", "").strip()
    if provider == "litellm" and not endpoint:
        raise LiveConfigurationError(
            "live qualification requires THREAT_HUNTING_MODEL_ENDPOINT for the litellm provider"
        )
    fixture_id = os.environ[_FIXTURE_ID_ENV].strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", fixture_id):
        raise LiveConfigurationError("non-production fixture identifier contains unsupported characters")
    # Never return or print credentials.  This metadata is safe to pass to the
    # live workflow adapter and to include in a qualification result.
    return {
        "splunk_url": os.environ["THREAT_HUNTING_SPLUNK_URL"].strip(),
        "model_provider": provider,
        "model_name": os.environ["THREAT_HUNTING_MODEL_NAME"].strip(),
        "model_endpoint": endpoint,
        "fixture_id": fixture_id,
        "verify_tls": "false" if not _env_flag("THREAT_HUNTING_TLS_VERIFY", default=True) else "true",
        "live_adapter": os.environ.get(_LIVE_ADAPTER_ENV, "").strip(),
    }


def _load_live_adapter(spec: str) -> Callable[..., Mapping[str, Any]]:
    """Load the explicitly configured application-owned live workflow hook."""

    if not spec:
        raise LiveConfigurationError(
            "live qualification is blocked: the application has no configured known-answer workflow adapter; "
            f"set {_LIVE_ADAPTER_ENV}=module:function after implementing the non-production fixture workflow"
        )
    module_name, separator, function_name = spec.partition(":")
    if not separator or not module_name or not function_name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", module_name) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function_name):
        raise LiveConfigurationError(
            f"{_LIVE_ADAPTER_ENV} must use the safe module:function form"
        )
    try:
        module = importlib.import_module(module_name)
        callback = getattr(module, function_name)
    except (ImportError, AttributeError) as exc:
        raise LiveConfigurationError(
            f"configured live workflow adapter could not be loaded: {module_name}:{function_name}"
        ) from exc
    if not callable(callback):
        raise LiveConfigurationError("configured live workflow adapter is not callable")
    return callback


def _build_live_adapters(configuration: Mapping[str, str]) -> tuple[SplunkConnector, Any]:
    """Construct the real external adapters after safe configuration checks."""

    verify_tls = configuration["verify_tls"] == "true"
    allow_insecure = _env_flag("THREAT_HUNTING_LAB_ALLOW_INSECURE", default=False)
    ca_bundle = os.environ.get("THREAT_HUNTING_TLS_CA_BUNDLE_FILE")
    if ca_bundle:
        ca_path = Path(ca_bundle)
        if not is_absolute_config_path(ca_path):
            raise LiveConfigurationError("THREAT_HUNTING_TLS_CA_BUNDLE_FILE must be an absolute path")
    else:
        ca_path = None
    token = _read_secret(os.environ["THREAT_HUNTING_SPLUNK_TOKEN_FILE"], label="Splunk token")
    try:
        splunk = SplunkConnector(
            SplunkConnectionConfig(
                endpoint=configuration["splunk_url"],
                token=token,
                verify_tls=verify_tls,
                ca_bundle_path=ca_path,
                lab_only_allow_insecure=allow_insecure,
                timeout_seconds=float(os.environ.get("THREAT_HUNTING_SPLUNK_TIMEOUT_SECONDS", "30")),
            )
        )
    except (TypeError, ValueError) as exc:
        raise LiveConfigurationError("configured Splunk live qualification settings are invalid") from exc

    api_key_file = os.environ.get("THREAT_HUNTING_MODEL_API_KEY_FILE")
    api_key = _read_secret(api_key_file, label="model API key") if api_key_file else None
    try:
        model = ModelFactory.create(
            ModelConfiguration(
                provider=configuration["model_provider"],
                model_name=configuration["model_name"],
                endpoint=configuration["model_endpoint"] or None,
                api_key=api_key,
                region_name=os.environ.get("THREAT_HUNTING_MODEL_REGION"),
                verify_tls=verify_tls,
                ca_bundle_path=ca_path,
                allow_insecure=allow_insecure,
                timeout_seconds=float(os.environ.get("THREAT_HUNTING_MODEL_TIMEOUT_SECONDS", "120")),
            )
        )
    except (TypeError, ValueError) as exc:
        raise LiveConfigurationError("configured model live qualification settings are invalid") from exc
    return splunk, model


def _assert_live_matrix_ready(bindings: KnownAnswerBindings) -> None:
    """Block the paid twelve-case matrix until fault injection is supplied."""

    blocked = bindings.fault_scenarios_blocked_for_live(_IMPLEMENTED_FAULT_INJECTORS)
    if blocked:
        raise LiveConfigurationError(
            "live qualification is blocked: deterministic fault injection is required for "
            f"{', '.join(blocked)}; supply a supported fault injector in the private bindings file"
        )


def _coerce_live_exports(raw_exports: object, bindings: KnownAnswerBindings) -> list[SyntheticRun]:
    """Normalize terminal hunt exports through the validated binding extractor."""

    if not isinstance(raw_exports, Sequence) or isinstance(raw_exports, (str, bytes)):
        raise LiveConfigurationError("live workflow adapter must return an exports list")
    exports: list[HuntResultExport] = []
    for item in raw_exports:
        if not isinstance(item, Mapping):
            raise LiveConfigurationError("live workflow adapter returned a malformed scenario export")
        scenario_id = item.get("scenario_id")
        results = item.get("results")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise LiveConfigurationError("live workflow export requires scenario_id")
        if not isinstance(results, Mapping):
            raise LiveConfigurationError("live workflow export requires results")
        binding = bindings.scenarios.get(scenario_id)
        if binding is None:
            raise LiveConfigurationError(f"live workflow export references unknown scenario: {scenario_id}")
        exports.append(
            HuntResultExport(
                scenario_id=scenario_id,
                category=binding.category,
                terminal_state=str(item["terminal_state"]) if item.get("terminal_state") is not None else None,
                limitation=str(item.get("limitation", "")),
                results=dict(results),
            )
        )
    try:
        return extract_synthetic_runs(exports, bindings)
    except BindingsError as exc:
        raise LiveConfigurationError(str(exc)) from exc


def run_live_suite(configuration: Mapping[str, str]) -> dict[str, Any]:
    """Run and score the configured live workflow against non-production fixtures."""

    try:
        bindings = load_bindings_from_env(BINDINGS_ENV)
    except BindingsError as exc:
        raise LiveConfigurationError(str(exc)) from exc
    _assert_live_matrix_ready(bindings)
    if bindings.fixture_id != configuration["fixture_id"]:
        raise LiveConfigurationError("configured fixture identifier does not match private scenario bindings")
    callback = _load_live_adapter(configuration.get("live_adapter", ""))
    splunk, model = _build_live_adapters(configuration)
    health = splunk.healthcheck()
    if not health.available:
        category = health.error_category.value if health.error_category is not None else "unknown"
        raise LiveConfigurationError(
            f"live qualification blocked: Splunk fixture preflight failed ({category}); "
            "verify the dedicated non-production endpoint, token, and TLS trust"
        )
    cases = load_cases()
    adapter_configuration = adapter_configuration_without_bindings(configuration, bindings)
    try:
        adapter_result = callback(
            cases=cases,
            splunk=splunk,
            model=model,
            configuration=adapter_configuration,
        )
    except LiveConfigurationError:
        raise
    except Exception as exc:  # noqa: BLE001 - adapter errors are intentionally bounded
        raise LiveConfigurationError("live workflow adapter failed before producing terminal results") from exc
    if not isinstance(adapter_result, Mapping):
        raise LiveConfigurationError("live workflow adapter must return a result object")
    if adapter_result.get("fixture_id") != configuration["fixture_id"]:
        raise LiveConfigurationError("live workflow adapter returned an unexpected fixture identifier")
    if adapter_result.get("exports") is not None:
        runs = _coerce_live_exports(adapter_result.get("exports"), bindings)
    elif adapter_result.get("runs") is not None:
        raise LiveConfigurationError(
            "live qualification is blocked: the workflow adapter returned pre-scored runs; "
            "return terminal hunt exports and use the validated binding extractor instead"
        )
    else:
        raise LiveConfigurationError("live workflow adapter must return terminal exports")
    result = score_runs(runs, load_answers())
    return {
        **result,
        "qualification_mode": "live",
        "fixture_id": configuration["fixture_id"],
        "model_provider": configuration["model_provider"],
        "model_name": configuration["model_name"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("synthetic", "live", "observed"), default="synthetic")
    parser.add_argument("--observations", type=Path, help="JSON exports of actual workflow results and optional independent analyst judgments")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args(argv)
    try:
        if args.mode == "observed":
            if args.observations is None:
                raise KnownAnswerError("observed mode requires --observations PATH")
            try:
                with args.observations.open("rb") as handle:
                    raw = handle.read(32 * 1024 * 1024 + 1)
                if len(raw) > 32 * 1024 * 1024:
                    raise ValueError("observation file exceeds 32 MiB")
                result = score_observed_runs(json.loads(raw))
            except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
                raise KnownAnswerError("observations must be a valid bounded export with complete, consistent judgments when supplied") from exc
        elif args.mode == "live":
            configuration = _require_live_configuration()
            result = run_live_suite(configuration)
        else:
            result = run_suite()
    except (KnownAnswerError, LiveConfigurationError, BindingsError) as exc:
        print(f"known-answer qualification failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True))
    elif args.mode == "observed":
        print(f"observed workflow evaluation: {len(result['scenarios'])} scenarios; "
              f"analytical quality {'assessed' if result['analytical_quality_assessed'] else 'unassessed'}")
    else:
        print(
            f"known-answer suite: {'PASS' if result['passed'] else 'FAIL'}; "
            f"{result['scenario_count']} scenarios; "
            f"evidence recovery {result['recovery_percent']:.2f}%; "
            f"queries {result['query_count']}; model calls {result['model_calls']}"
        )
    outcome = result["answer_key_matched"] if args.mode == "observed" else result["passed"]
    return 2 if outcome is None else 0 if outcome else 1


if __name__ == "__main__":
    raise SystemExit(main())
