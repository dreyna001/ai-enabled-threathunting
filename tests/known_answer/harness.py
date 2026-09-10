"""Deterministic known-answer evaluator for synthetic hunt fixtures.

The simulator models provider outcomes and bounded execution behavior without
putting the answer key into a model prompt.  It is intentionally small: the
real-Splunk run is an opt-in operational rehearsal, while this evaluator proves
the scoring and safety gates on every test run.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


CASE_FILE = Path(__file__).with_name("scenarios.json")
ANSWER_FILE = Path(__file__).with_name("answer_keys.json")


class KnownAnswerError(RuntimeError):
    """Raised when versioned known-answer fixtures are inconsistent."""


@dataclass(frozen=True, slots=True)
class SyntheticRun:
    scenario_id: str
    category: str
    disposition: str
    retained_evidence_ids: tuple[str, ...]
    cited_evidence_ids: tuple[str, ...]
    limitation: str
    query_count: int
    duplicate_query_count: int
    model_calls: int
    model_repair_attempts: int
    model_input_tokens: int
    model_output_tokens: int
    fabricated_evidence_ids: tuple[str, ...]
    citation_failures: tuple[str, ...]
    hard_budget_violation: bool
    completed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KnownAnswerError(f"could not load known-answer fixture: {path}") from exc
    if not isinstance(value, Mapping):
        raise KnownAnswerError(f"known-answer fixture must be an object: {path}")
    return value


def load_cases(case_file: Path = CASE_FILE) -> list[dict[str, Any]]:
    """Load and validate the twelve synthetic input fixtures."""

    payload = _load_json(case_file)
    cases = payload.get("scenarios")
    if payload.get("fixture_version") != "1.0" or not isinstance(cases, list):
        raise KnownAnswerError("invalid known-answer scenario manifest")
    if len(cases) != 12:
        raise KnownAnswerError("known-answer suite must contain exactly 12 scenarios")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, Mapping):
            raise KnownAnswerError("scenario must be an object")
        scenario_id = case.get("scenario_id")
        if not isinstance(scenario_id, str) or not scenario_id or scenario_id in seen:
            raise KnownAnswerError("scenario IDs must be unique non-empty strings")
        if not isinstance(case.get("events"), list) or not isinstance(case.get("category"), str):
            raise KnownAnswerError(f"scenario is incomplete: {scenario_id}")
        seen.add(scenario_id)
        normalized.append(dict(case))
    return normalized


def load_answers(answer_file: Path = ANSWER_FILE) -> dict[str, dict[str, Any]]:
    """Load the evaluator-only answer key after the synthetic run."""

    payload = _load_json(answer_file)
    answers = payload.get("answers")
    if payload.get("answer_key_version") != "1.0" or not isinstance(answers, Mapping):
        raise KnownAnswerError("invalid known-answer answer key")
    return {str(key): dict(value) for key, value in answers.items() if isinstance(value, Mapping)}


def run_synthetic_case(case: Mapping[str, Any]) -> SyntheticRun:
    """Run one fixture using deterministic provider outcomes.

    This function receives only the synthetic input fixture.  The answer key
    is deliberately consumed later by :func:`score_runs`.
    """

    scenario_id = str(case["scenario_id"])
    category = str(case["category"])
    events = [event for event in case["events"] if isinstance(event, Mapping)]
    expected_rows = len(events)
    retained_count = int(case.get("retained_event_count", expected_rows))
    retained_count = max(0, min(retained_count, expected_rows))
    retained_ids = tuple(str(event["evidence_id"]) for event in events[:retained_count])
    disposition = {
        "supported": "supported",
        "not_supported": "not_supported_within_scope",
        "incomplete": "inconclusive",
        "truncated": "supported",
        "timeout": "failed",
        "model_repair": "supported",
        "restart_recovery": "supported",
        "hard_budget": "budget_exhausted",
        "cancellation": "cancelled",
    }.get(category)
    if disposition is None:
        raise KnownAnswerError(f"unsupported scenario category: {category}")
    if category in {"timeout", "hard_budget"}:
        retained_ids = ()
    # The deterministic executor cites every evidence record it retained.
    cited_ids = retained_ids
    fabricated: tuple[str, ...] = ()
    duplicate_count = 0
    if category == "restart_recovery":
        # A replayed delivery is safely deduplicated by evidence identity.
        duplicate_count = 1
    if category == "cancellation":
        # One active query may finish; no new query starts after cancellation.
        retained_ids = retained_ids[:1]
        cited_ids = retained_ids
    limitation = str(case.get("coverage_limitation", ""))
    if category == "not_supported":
        limitation = "No matching evidence was observed."
    if category == "timeout":
        limitation = str(case.get("failure_code", "hard_timeout"))
    elif category == "hard_budget":
        limitation = str(case.get("failure_code", "budget_exhausted"))
    elif category == "cancellation":
        limitation = str(case.get("failure_code", "cancelled"))
    return SyntheticRun(
        scenario_id=scenario_id,
        category=category,
        disposition=disposition,
        retained_evidence_ids=retained_ids,
        cited_evidence_ids=cited_ids,
        limitation=limitation,
        query_count=int(case.get("query_count", 0)),
        duplicate_query_count=duplicate_count,
        model_calls=int(case.get("model_calls", 0)),
        model_repair_attempts=int(case.get("model_repair_attempts", 0)),
        model_input_tokens=int(case.get("model_input_tokens", 0)),
        model_output_tokens=int(case.get("model_output_tokens", 0)),
        fabricated_evidence_ids=fabricated,
        citation_failures=(),
        hard_budget_violation=False,
        completed=category not in {"timeout", "hard_budget", "cancellation"},
    )


def score_runs(runs: list[SyntheticRun], answers: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Score evidence recovery, citations, dispositions, and hard budgets."""

    if len(runs) != 12:
        raise KnownAnswerError("score requires all twelve known-answer runs")
    details: list[dict[str, Any]] = []
    expected_total = recovered_total = 0
    fabricated = citation_failures = budget_violations = 0
    for run in runs:
        answer = answers.get(run.scenario_id)
        if answer is None:
            raise KnownAnswerError(f"missing answer key for {run.scenario_id}")
        expected = tuple(str(item) for item in answer.get("expected_evidence_ids", []))
        recovered = sum(item in run.retained_evidence_ids and item in run.cited_evidence_ids for item in expected)
        expected_total += len(expected)
        recovered_total += recovered
        disposition_ok = run.disposition == answer.get("disposition")
        required_limitation = answer.get("required_limitation")
        limitation_ok = not required_limitation or str(required_limitation).casefold() in run.limitation.casefold()
        fabricated += len(run.fabricated_evidence_ids)
        citation_failures += len(run.citation_failures)
        budget_violations += int(run.hard_budget_violation)
        details.append({
            **run.to_dict(),
            "expected_evidence_count": len(expected),
            "recovered_evidence_count": recovered,
            "disposition_ok": disposition_ok,
            "limitation_ok": limitation_ok,
            "pass": disposition_ok and limitation_ok and not run.fabricated_evidence_ids and not run.citation_failures and not run.hard_budget_violation and recovered == len(expected),
        })
    recovery = 100.0 if expected_total == 0 else round(recovered_total * 100 / expected_total, 2)
    total_queries = sum(run.query_count for run in runs)
    duplicate_queries = sum(run.duplicate_query_count for run in runs)
    return {
        "suite_version": "1.0",
        "scenario_count": len(runs),
        "expected_evidence_count": expected_total,
        "recovered_evidence_count": recovered_total,
        "recovery_percent": recovery,
        "fabricated_evidence_count": fabricated,
        "citation_failure_count": citation_failures,
        "hard_budget_violation_count": budget_violations,
        "query_count": total_queries,
        "duplicate_query_rate_percent": round(duplicate_queries * 100 / total_queries, 2) if total_queries else 0.0,
        "model_calls": sum(run.model_calls for run in runs),
        "model_repair_attempts": sum(run.model_repair_attempts for run in runs),
        "model_input_tokens": sum(run.model_input_tokens for run in runs),
        "model_output_tokens": sum(run.model_output_tokens for run in runs),
        "passed": recovery >= 90.0 and fabricated == 0 and citation_failures == 0 and budget_violations == 0 and all(item["pass"] for item in details),
        "scenarios": details,
    }


def run_suite(case_file: Path = CASE_FILE, answer_file: Path = ANSWER_FILE) -> dict[str, Any]:
    """Run all synthetic cases and score them against the private answer key."""

    cases = load_cases(case_file)
    answers = load_answers(answer_file)
    return {
        **score_runs([run_synthetic_case(case) for case in cases], answers),
        "qualification_mode": "synthetic",
        "measurement_basis": "scripted fixtures; scoring regression only",
        "analytical_quality_assessed": False,
        "live_model_quality_measured": False,
    }


__all__ = ["KnownAnswerError", "load_answers", "load_cases", "run_suite", "run_synthetic_case", "score_runs"]
