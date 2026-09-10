"""Score exported workflow results and independent analyst judgments."""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from threat_hunting.domain.budgets import BudgetCounters
from threat_hunting.domain.contracts import FindingProposal


class Judgment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str
    supported: StrictBool
    expected_finding_ids: list[str]


class ObservedEvidence(BaseModel):
    evidence_id: UUID
    query_id: UUID
    source_event_ref: str | None = None
    selected_result: dict[str, Any] = Field(default_factory=dict)


class ObservedQuery(BaseModel):
    query_id: UUID
    status: str
    question_id: str | None = None


class ObservedFinding(FindingProposal):
    finding_id: UUID


class ObservedResults(BaseModel):
    evidence: list[ObservedEvidence]
    queries: list[ObservedQuery]
    findings: list[ObservedFinding]
    usage: BudgetCounters


class ObservedRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str = Field(min_length=1, max_length=200)
    model_provider: str = Field(min_length=1, max_length=100)
    model_name: str = Field(min_length=1, max_length=200)
    reasoning_effort: str | None = None
    variant_id: str = Field(default="default", min_length=1, max_length=200)
    trial_id: str = Field(default="1", min_length=1, max_length=200)
    hunt_id: UUID | None = None
    fixture_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    prompt_contract_version: str | None = None
    image_version: str | None = None
    terminal_state: Literal["report_draft", "finalized", "failed", "cancelled"] | None = None
    fixture_event_id_field: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    expected_event_ids: list[str] | None = None
    approved_question_ids: list[str] | None = None
    results: ObservedResults
    expected_finding_ids: list[str] | None = None
    judgments: list[Judgment] | None = None
    judgment_source: Literal["analyst", "assistant", "unspecified"] = "unspecified"
    measured_cost_usd: float | None = Field(default=None, ge=0, allow_inf_nan=False)


class Observations(BaseModel):
    model_config = ConfigDict(extra="forbid")
    runs: list[ObservedRun] = Field(min_length=1, max_length=100)


def _percent(numerator: int, denominator: int) -> float | None:
    return round(100 * numerator / denominator, 2) if denominator else None


def score_observed_runs(payload: dict[str, Any]) -> dict[str, Any]:
    """Use actual findings, usage, and checks; never infer claim truth from IDs."""
    observations = Observations.model_validate(payload)
    identities = {(run.scenario_id, run.variant_id, run.trial_id) for run in observations.runs}
    if len(identities) != len(observations.runs):
        raise ValueError("observed scenario, variant, and trial IDs must be unique")
    hunt_ids = [run.hunt_id for run in observations.runs if run.hunt_id is not None]
    if len(hunt_ids) != len(set(hunt_ids)):
        raise ValueError("each trial must reference a different hunt")
    for run in observations.runs:
        for values in (run.expected_event_ids, run.approved_question_ids):
            if values is not None and (len(set(values)) != len(values) or any(not value.strip() for value in values)):
                raise ValueError("expected event and approved question IDs must be unique and nonempty")
    scenarios = []
    for run in observations.runs:
        usage = run.results.usage
        evidence = {str(item.evidence_id): str(item.query_id) for item in run.results.evidence}
        completed = {str(item.query_id) for item in run.results.queries if item.status == "completed"}
        if len({item.query_id for item in run.results.queries}) != len(run.results.queries):
            raise ValueError("observed query IDs must be unique")
        if len(evidence) != len(run.results.evidence):
            raise ValueError("observed evidence IDs must be unique")
        findings = run.results.findings
        by_id = {str(item.finding_id): item for item in findings}
        if len(by_id) != len(findings):
            raise ValueError("observed findings must have unique IDs")
        citation_failures = 0
        for item in findings:
            cited = {str(value) for value in item.evidence_ids}
            queries = {str(value) for value in item.query_ids}
            if cited.difference(evidence) or queries.difference(completed) or any(evidence.get(value) not in queries for value in cited):
                citation_failures += 1
        cited_ids = {str(value) for finding in findings for value in finding.evidence_ids}
        event_refs: dict[str, str] = {}
        for item in run.results.evidence:
            value = item.selected_result.get(run.fixture_event_id_field) if run.fixture_event_id_field else item.source_event_ref
            if isinstance(value, list):
                if not value:
                    value = None
                elif not all(isinstance(part, str) for part in value) or len(set(value)) != 1:
                    raise ValueError("fixture event identity must identify one event per retained record")
                else:
                    value = value[0]
            if value is not None and not isinstance(value, str):
                raise ValueError("fixture event identity must be a string")
            if value and value != "unknown":
                event_refs[str(item.evidence_id)] = value
        retained_events = set(event_refs.values())
        cited_events = {value for identifier, value in event_refs.items() if identifier in cited_ids}
        recovery = None
        if run.expected_event_ids is not None:
            expected_events = set(run.expected_event_ids)
            unidentified = set(evidence) - set(event_refs)
            unidentified_cited = cited_ids & unidentified
            retrieval_measurable = not unidentified or expected_events.issubset(retained_events)
            citation_measurable = not unidentified_cited or expected_events.issubset(cited_events)
            recovery = {
                "identity_field": f"selected_result.{run.fixture_event_id_field}" if run.fixture_event_id_field else "source_event_ref",
                "unidentified_retained_record_count": len(unidentified),
                "unidentified_cited_record_count": len(unidentified_cited),
                "measurement_basis": "Counts include identified matches only; recall and missed-event lists are unknown when missing identities could change them.",
                "expected_event_count": len(expected_events),
                "retained_expected_event_count": len(expected_events & retained_events),
                "cited_expected_event_count": len(expected_events & cited_events),
                "retrieval_recall_percent": _percent(len(expected_events & retained_events), len(expected_events)) if retrieval_measurable else None,
                "citation_recall_percent": _percent(len(expected_events & cited_events), len(expected_events)) if citation_measurable else None,
                "missed_retrieval_event_ids": sorted(expected_events - retained_events) if retrieval_measurable else None,
                "retrieved_but_uncited_event_ids": sorted((expected_events & retained_events) - cited_events) if citation_measurable else None,
            }
        coverage = None
        if run.approved_question_ids is not None:
            approved = set(run.approved_question_ids)
            executed = {item.question_id for item in run.results.queries if item.status == "completed"}
            coverage = {
                "approved_question_count": len(approved),
                "executed_approved_question_count": len(approved & executed),
                "execution_coverage_percent": _percent(len(approved & executed), len(approved)),
                "unexecuted_question_ids": sorted(approved - executed),
                "measurement_basis": "completed search coverage; does not establish that questions were answered",
            }
        initial = [check for check in usage.model_output_checks if not check.repair]
        grounded = [check for check in initial if check.contract in {"QueryAssessment[]", "FindingProposal[]"}]
        complete_trace = len(usage.model_output_checks) == usage.model_calls and usage.model_calls > 0
        grounding_trace_complete = complete_trace and all(
            check.contract_valid is not True or check.grounding_valid is not None for check in grounded
        )
        quality = None
        if run.judgments is not None and run.expected_finding_ids is not None:
            judgments = {item.finding_id: item for item in run.judgments}
            expected = set(run.expected_finding_ids)
            if len(judgments) != len(run.judgments) or set(judgments) != set(by_id):
                raise ValueError("provide exactly one analyst judgment for every observed finding")
            if len(expected) != len(run.expected_finding_ids):
                raise ValueError("expected finding IDs must be unique")
            matched = set()
            relevant = unsupported = 0
            for judgment in judgments.values():
                if set(judgment.expected_finding_ids).difference(expected):
                    raise ValueError("judgment references an unknown expected finding")
                if not judgment.supported and judgment.expected_finding_ids:
                    raise ValueError("unsupported findings cannot satisfy expected findings")
                if judgment.supported:
                    matched.update(judgment.expected_finding_ids)
                    relevant += bool(judgment.expected_finding_ids)
                else:
                    unsupported += 1
            quality = {
                "finding_precision_percent": _percent(relevant, len(findings)),
                "finding_recall_percent": _percent(len(matched), len(expected)),
                "unsupported_claim_count": unsupported,
                "measurement_basis": "finding-level judgments; unsupported_claim_count counts findings with unsupported claims, not individual claims",
                "missed_expected_findings": len(expected - matched),
                "unexpected_findings": len(findings) - relevant,
                "judgment_source": run.judgment_source,
            }
        scenarios.append({
            "scenario_id": run.scenario_id,
            "variant_id": run.variant_id,
            "trial_id": run.trial_id,
            "hunt_id": str(run.hunt_id) if run.hunt_id else None,
            "terminal_state": run.terminal_state,
            "fixture_sha256": run.fixture_sha256,
            "prompt_contract_version": run.prompt_contract_version,
            "image_version": run.image_version,
            "model_provider": run.model_provider,
            "model_name": run.model_name,
            "reasoning_effort": run.reasoning_effort,
            "evidence_recovery": recovery,
            "approved_question_coverage": coverage,
            "retained_record_count": len(evidence),
            "distinct_cited_record_count": len(cited_ids),
            "classification_counts": dict(Counter(item.classification.value for item in findings)),
            "duplicate_citation_count": sum(len(item.evidence_ids) - len(set(item.evidence_ids)) for item in findings),
            "validation_trace_complete": complete_trace,
            "first_pass_contract_valid_percent": _percent(sum(check.contract_valid is True for check in initial), len(initial)) if complete_trace else None,
            "first_pass_grounded_output_percent": _percent(sum(check.contract_valid is True and check.grounding_valid is True for check in grounded), len(grounded)) if grounding_trace_complete else None,
            "repair_call_percent": _percent(usage.model_repair_attempts, usage.model_calls),
            "citation_failure_count": citation_failures,
            "model_calls": usage.model_calls,
            "model_input_tokens": usage.model_input_tokens,
            "model_output_tokens": usage.model_output_tokens,
            "measured_cost_usd": run.measured_cost_usd,
            "analytical_quality": quality,
        })
    groups: list[dict[str, Any]] = []
    for scenario_id, variant_id in dict.fromkeys((run.scenario_id, run.variant_id) for run in observations.runs):
        members = [run for run in observations.runs if (run.scenario_id, run.variant_id) == (scenario_id, variant_id)]
        metrics = [item for item in scenarios if (item["scenario_id"], item["variant_id"]) == (scenario_id, variant_id)]
        signatures = {
            (run.fixture_sha256, run.model_provider, run.model_name, run.reasoning_effort,
             run.prompt_contract_version, run.image_version, run.fixture_event_id_field,
             tuple(sorted(run.expected_event_ids)) if run.expected_event_ids is not None else None,
             tuple(sorted(run.approved_question_ids)) if run.approved_question_ids is not None else None)
            for run in members
        }
        if len(signatures) != 1:
            raise ValueError("trials in a variant must use the same fixture, model settings, versions, and expectations")
        ranges = {}
        for name, values in {
            "model_calls": [run.results.usage.model_calls for run in members],
            "input_tokens": [run.results.usage.model_input_tokens for run in members],
            "output_tokens": [run.results.usage.model_output_tokens for run in members],
            "citation_recall_percent": [(item["evidence_recovery"] or {}).get("citation_recall_percent") for item in metrics],
            "execution_coverage_percent": [(item["approved_question_coverage"] or {}).get("execution_coverage_percent") for item in metrics],
        }.items():
            ranges[name] = {"minimum": min(values), "maximum": max(values)} if all(value is not None for value in values) else None
        groups.append({
            "scenario_id": scenario_id, "variant_id": variant_id, "trial_count": len(members),
            "comparison_metadata_complete": all(run.hunt_id and run.fixture_sha256 and run.prompt_contract_version and run.image_version for run in members),
            "observed_ranges": ranges,
            "terminal_state_counts": dict(Counter(run.terminal_state or "unknown" for run in members)),
            "report_completion_percent": _percent(sum(run.terminal_state in {"report_draft", "finalized"} for run in members), len(members)) if all(run.terminal_state is not None for run in members) else None,
            "measurement_basis": "observed trials only; these ranges do not predict future reliability",
        })
    assessed = all(item["analytical_quality"] is not None for item in scenarios)
    # These are exact answer-key checks, not a statistical production-readiness claim.
    passed = all(
        item["terminal_state"] not in {"failed", "cancelled"}
        and item["citation_failure_count"] == 0
        and item["analytical_quality"]["unsupported_claim_count"] == 0
        and item["analytical_quality"]["missed_expected_findings"] == 0
        and item["analytical_quality"]["unexpected_findings"] == 0
        for item in scenarios
    ) if assessed else None
    return {
        "qualification_mode": "observed",
        "scenario_count": len({run.scenario_id for run in observations.runs}),
        "trial_count": len(scenarios),
        "trial_groups": groups,
        "analytical_quality_assessed": assessed,
        "provider_execution": "recorded metadata; this scorer does not execute or authenticate model runs",
        "answer_key_matched": passed,
        "production_qualification": "not established by offline scoring",
        "scenarios": scenarios,
    }
