"""Private known-answer scenario bindings and export-to-SyntheticRun extraction.

Bindings map evaluator-only abstract evidence IDs to fixture identity values.
They are loaded only from an explicit protected file path and must never be
committed or forwarded to application, model, query, or adapter payloads.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from known_answer.harness import KnownAnswerError, SyntheticRun, load_cases

BINDING_VERSION = "1.0"
BINDINGS_ENV = "THREAT_HUNTING_KNOWN_ANSWER_BINDINGS_FILE"
SUPPORTED_FAULT_INJECTOR = "deterministic-v1"
MAX_STRING = 256
MAX_LIST = 64
MAX_MAP_ENTRIES = 32

FAULT_CATEGORIES = frozenset(
    {"timeout", "model_repair", "restart_recovery", "hard_budget", "cancellation"}
)
FAULT_MODES = FAULT_CATEGORIES | {"none"}

_ABSTRACT_EVIDENCE_RE = re.compile(r"^ka\d{2}-e\d+$")
_EVALUATOR_LEAKAGE_KEYS = frozenset(
    {
        "answer_key",
        "answer_key_version",
        "expected_evidence_ids",
        "evidence_id_map",
        "binding_version",
        "fault_injector",
    }
)
_EVALUATOR_LEAKAGE_VALUE_RE = re.compile(r"ka\d{2}-e\d+")


class BindingsError(KnownAnswerError):
    """Raised when private scenario bindings are missing or invalid."""


class ScenarioBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str = Field(min_length=1, max_length=MAX_STRING)
    execution_source: str = Field(min_length=1, max_length=MAX_STRING)
    export_source: str = Field(min_length=1, max_length=MAX_STRING)
    identity_field: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    evidence_id_map: dict[str, str] = Field(max_length=MAX_MAP_ENTRIES)
    fault_mode: Literal[
        "none",
        "timeout",
        "model_repair",
        "restart_recovery",
        "hard_budget",
        "cancellation",
    ]

    @field_validator("evidence_id_map")
    @classmethod
    def validate_map_entries(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) != len(set(value.values())):
            raise ValueError("evidence_id_map values must be unique")
        for abstract, real in value.items():
            if not _ABSTRACT_EVIDENCE_RE.fullmatch(abstract):
                raise ValueError("evidence_id_map keys must use abstract evaluator evidence IDs")
            if not real or len(real) > MAX_STRING:
                raise ValueError("evidence_id_map values must be bounded non-empty strings")
        return value


class KnownAnswerBindings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    binding_version: Literal["1.0"]
    fixture_id: str = Field(min_length=1, max_length=MAX_STRING)
    fixture_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    fixture_version: str = Field(min_length=1, max_length=MAX_STRING)
    fault_injector: str | None = Field(default=None, max_length=MAX_STRING)
    scenarios: dict[str, ScenarioBinding] = Field(min_length=12, max_length=12)

    @field_validator("fault_injector")
    @classmethod
    def validate_fault_injector(cls, value: str | None) -> str | None:
        if value is not None and value != SUPPORTED_FAULT_INJECTOR:
            raise ValueError(f"fault_injector must be {SUPPORTED_FAULT_INJECTOR!r} when declared")
        return value

    @model_validator(mode="after")
    def validate_against_public_scenarios(self) -> "KnownAnswerBindings":
        cases = {case["scenario_id"]: case for case in load_cases()}
        if set(self.scenarios) != set(cases):
            raise ValueError("bindings must contain exactly the twelve public scenario IDs")
        for scenario_id, binding in self.scenarios.items():
            case = cases[scenario_id]
            if binding.category != case["category"]:
                raise ValueError(f"binding category mismatch for {scenario_id}")
            expected_abstract = {
                str(event["evidence_id"])
                for event in case.get("events", [])
                if isinstance(event, Mapping) and event.get("evidence_id")
            }
            if set(binding.evidence_id_map) != expected_abstract:
                raise ValueError(f"binding evidence_id_map must match scenario events for {scenario_id}")
            if binding.category in FAULT_CATEGORIES:
                if binding.fault_mode != binding.category:
                    raise ValueError(
                        f"fault scenario {scenario_id} must declare fault_mode={binding.category!r}"
                    )
            elif binding.fault_mode != "none":
                raise ValueError(f"non-fault scenario {scenario_id} must declare fault_mode='none'")
        return self

    def fault_scenarios_blocked_for_live(
        self,
        implemented_fault_injectors: frozenset[str] = frozenset(),
    ) -> tuple[str, ...]:
        """Return fault scenarios blocked until their injector is actually implemented."""

        if self.fault_injector in implemented_fault_injectors:
            return ()
        return tuple(
            scenario_id
            for scenario_id, binding in sorted(self.scenarios.items())
            if binding.category in FAULT_CATEGORIES
        )


def load_bindings(path: Path | str) -> KnownAnswerBindings:
    """Load and validate private bindings from an explicit protected file path."""

    binding_path = Path(path)
    try:
        payload = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BindingsError("could not load private scenario bindings file") from exc
    try:
        return KnownAnswerBindings.model_validate(payload)
    except (ValueError, ValidationError) as exc:
        raise BindingsError(f"invalid private scenario bindings: {exc}") from exc


def load_bindings_from_env(env_name: str = BINDINGS_ENV) -> KnownAnswerBindings:
    """Load bindings from the configured environment variable."""

    path_value = os.environ.get(env_name)
    if not path_value:
        raise BindingsError(
            f"private scenario bindings are required; set {env_name} to a protected file outside version control"
        )
    return load_bindings(path_value)


@dataclass(frozen=True, slots=True)
class HuntResultExport:
    """Terminal application hunt export used by the matrix extractor."""

    scenario_id: str
    category: str
    terminal_state: str | None
    limitation: str
    results: Mapping[str, Any]


def _identity_value(record: Mapping[str, Any], identity_field: str) -> str | None:
    selected = record.get("selected_result")
    if isinstance(selected, Mapping):
        value = selected.get(identity_field)
        if isinstance(value, str) and value and value != "unknown":
            return value
    source_ref = record.get("source_event_ref")
    if isinstance(source_ref, str) and source_ref and source_ref != "unknown":
        return source_ref
    return None


def _derive_disposition(export: HuntResultExport) -> str:
    category_dispositions = {
        "incomplete": "inconclusive",
        "timeout": "failed",
        "hard_budget": "budget_exhausted",
        "cancellation": "cancelled",
    }
    if export.category in category_dispositions:
        return category_dispositions[export.category]
    if export.terminal_state == "cancelled":
        return "cancelled"
    if export.terminal_state == "failed":
        return "failed"
    findings = export.results.get("findings")
    if isinstance(findings, list):
        classifications = {
            str(item.get("classification"))
            for item in findings
            if isinstance(item, Mapping) and item.get("classification") is not None
        }
        if classifications == {"not_supported_within_scope"}:
            return "not_supported_within_scope"
        if "supported_observation" in classifications or "hunt_lead" in classifications:
            return "supported"
    if export.limitation:
        return "inconclusive"
    if export.terminal_state in {"report_draft", "finalized"}:
        return "supported"
    return "failed"


def extract_synthetic_run(export: HuntResultExport, binding: ScenarioBinding) -> SyntheticRun:
    """Convert one terminal export plus validated bindings into SyntheticRun.

    Abstract evaluator evidence IDs are derived from fixture identity mapping.
    This function never reads the private answer key.
    """

    real_to_abstract = {real: abstract for abstract, real in binding.evidence_id_map.items()}
    evidence = [
        item for item in export.results.get("evidence", []) if isinstance(item, Mapping)
    ]
    queries = [
        item for item in export.results.get("queries", []) if isinstance(item, Mapping)
    ]
    findings = [
        item for item in export.results.get("findings", []) if isinstance(item, Mapping)
    ]
    usage = export.results.get("usage")
    usage_mapping = usage if isinstance(usage, Mapping) else {}

    evidence_by_id: dict[str, str | None] = {}
    retained_abstract: list[str] = []
    for record in evidence:
        evidence_id = str(record.get("evidence_id", ""))
        if not evidence_id:
            continue
        identity = _identity_value(record, binding.identity_field)
        abstract = real_to_abstract.get(identity) if identity else None
        evidence_by_id[evidence_id] = abstract
        if abstract is not None:
            retained_abstract.append(abstract)

    cited_abstract: list[str] = []
    fabricated_abstract: list[str] = []
    citation_failures: list[str] = []
    completed_queries = {
        str(item.get("query_id"))
        for item in queries
        if str(item.get("status")) == "completed" and item.get("query_id") is not None
    }
    for finding in findings:
        finding_id = str(finding.get("finding_id", "finding"))
        cited_ids = [str(value) for value in finding.get("evidence_ids", []) if value is not None]
        query_ids = {str(value) for value in finding.get("query_ids", []) if value is not None}
        mapped_cited = [evidence_by_id.get(value) for value in cited_ids]
        if any(value is None for value in mapped_cited):
            citation_failures.append(finding_id)
        if query_ids.difference(completed_queries):
            citation_failures.append(finding_id)
        for evidence_id, abstract in zip(cited_ids, mapped_cited, strict=False):
            if abstract is None:
                fabricated_abstract.append(evidence_id)
            else:
                cited_abstract.append(abstract)
                if abstract not in retained_abstract:
                    fabricated_abstract.append(abstract)

    duplicate_query_count = len(queries) - len({str(item.get("query_id")) for item in queries if item.get("query_id")})
    hard_budget_violation = False
    completed = export.terminal_state not in {"failed", "cancelled"} and export.category not in {
        "timeout",
        "hard_budget",
        "cancellation",
    }

    return SyntheticRun(
        scenario_id=export.scenario_id,
        category=export.category,
        disposition=_derive_disposition(export),
        retained_evidence_ids=tuple(dict.fromkeys(retained_abstract)),
        cited_evidence_ids=tuple(dict.fromkeys(cited_abstract)),
        limitation=export.limitation,
        query_count=len(queries),
        duplicate_query_count=max(0, duplicate_query_count),
        model_calls=int(usage_mapping.get("model_calls", 0)),
        model_repair_attempts=int(usage_mapping.get("model_repair_attempts", 0)),
        model_input_tokens=int(usage_mapping.get("model_input_tokens", 0)),
        model_output_tokens=int(usage_mapping.get("model_output_tokens", 0)),
        fabricated_evidence_ids=tuple(dict.fromkeys(fabricated_abstract)),
        citation_failures=tuple(dict.fromkeys(citation_failures)),
        hard_budget_violation=bool(hard_budget_violation),
        completed=completed,
    )


def extract_synthetic_runs(
    exports: list[HuntResultExport],
    bindings: KnownAnswerBindings,
) -> list[SyntheticRun]:
    """Extract all terminal exports in binding order."""

    if len(exports) != 12:
        raise BindingsError("live matrix extraction requires twelve terminal exports")
    export_by_id = {item.scenario_id: item for item in exports}
    if set(export_by_id) != set(bindings.scenarios):
        raise BindingsError("terminal exports must cover exactly the twelve bound scenarios")
    return [
        extract_synthetic_run(export_by_id[scenario_id], bindings.scenarios[scenario_id])
        for scenario_id in sorted(bindings.scenarios)
    ]


def assert_no_evaluator_leakage(payload: Any, *, label: str = "payload") -> None:
    """Fail when evaluator-only binding or abstract answer identifiers appear."""

    def walk(value: Any, path: str) -> None:
        if isinstance(value, str):
            if _EVALUATOR_LEAKAGE_VALUE_RE.search(value):
                raise BindingsError(f"{label} leaks abstract evaluator evidence IDs at {path}")
            return
        if isinstance(value, Mapping):
            for key, nested in value.items():
                key_text = str(key)
                if key_text in _EVALUATOR_LEAKAGE_KEYS:
                    raise BindingsError(f"{label} leaks evaluator-only key {key_text!r} at {path}")
                walk(nested, f"{path}.{key_text}")
            return
        if isinstance(value, list):
            if len(value) > MAX_LIST:
                raise BindingsError(f"{label} list exceeds bound at {path}")
            for index, nested in enumerate(value):
                walk(nested, f"{path}[{index}]")

    walk(payload, label)


def adapter_configuration_without_bindings(
    configuration: Mapping[str, str],
    bindings: KnownAnswerBindings,
) -> dict[str, str]:
    """Return adapter-safe configuration without evaluator binding material."""

    sanitized = dict(configuration)
    assert_no_evaluator_leakage(sanitized, label="adapter configuration")
    if bindings.fixture_id != sanitized.get("fixture_id"):
        raise BindingsError("adapter fixture_id must match validated private bindings")
    return sanitized


__all__ = [
    "BINDINGS_ENV",
    "BindingsError",
    "FAULT_CATEGORIES",
    "HuntResultExport",
    "KnownAnswerBindings",
    "ScenarioBinding",
    "SUPPORTED_FAULT_INJECTOR",
    "adapter_configuration_without_bindings",
    "assert_no_evaluator_leakage",
    "extract_synthetic_run",
    "extract_synthetic_runs",
    "load_bindings",
    "load_bindings_from_env",
]
