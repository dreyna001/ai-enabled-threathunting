"""Bounded investigation context and deterministic interpretation grounding.

This module selects retained evidence and validates model proposals. It performs
no external calls or database writes; the workflow owns those effects.
"""

from __future__ import annotations

from collections import deque
from typing import Annotated, Any, Mapping
from uuid import uuid4

from pydantic import AfterValidator, BaseModel, TypeAdapter, create_model

from threat_hunting.domain.common import DomainModel
from threat_hunting.domain.contracts import FindingProposal, FollowUpDecision, HuntPlan, QuestionAnswer, QuestionAnswerStep, QueryAssessment, QueryProposal
from threat_hunting.domain.errors import Validation
from threat_hunting.domain.spl_policy import source_pairs
from threat_hunting.services.evidence import _flatten_scalar_values, advisory_lead_groups, evidence_time_bounds, lookup_retained_evidence, query_results_incomplete, query_source_coverage, raw_event_time, result_source
from threat_hunting.services.reports import _derive_report_limitations
from threat_hunting.services.threat_intel import compare_advisory_iocs, query_ioc_context


MAX_FOLLOW_UP_QUESTIONS = 3


_MODEL_EVIDENCE_SAMPLE_LIMIT = 500


def _spread_evidence_in_time(rows: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Put early, late and interior observations into a bounded sample."""
    timed = []
    unknown = []
    for position, row in enumerate(rows):
        stamp = raw_event_time(row)
        if stamp is None:
            unknown.append(row)
        else:
            timed.append((stamp, position, row))
    if len(timed) < 2:
        return rows
    timed.sort(key=lambda item: (item[0], item[1]))
    ordered = [timed[0][2], timed[-1][2]]
    intervals = deque([(1, len(timed) - 1)])
    while intervals:
        left, right = intervals.popleft()
        if left >= right:
            continue
        middle = (left + right) // 2
        ordered.append(timed[middle][2])
        intervals.extend(((left, middle), (middle + 1, right)))
    # Unknown-time records are still represented; they cannot establish a
    # chronology, but may carry important fields missing from timed records.
    return [group[position] for position in range(max(len(ordered), len(unknown)))
            for group in (ordered, unknown) if position < len(group)]


def _balanced_evidence_sample(
    evidence: Any,
    queries: Any,
    *,
    query_ids: set[str] | None = None,
    limit: int = _MODEL_EVIDENCE_SAMPLE_LIMIT,
    preferred_evidence_ids: set[str] | None = None,
    requested_evidence_groups: list[set[str]] | None = None,
) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]]]:
    """Return a deterministic, query-balanced evidence sample and coverage metadata.

    Evidence is retained in the execution record without this limit.  The limit
    applies only to the bounded model context, with round-robin selection so a
    large early query cannot hide later query results. Within a query, observed
    sources remain balanced and explicitly selected pivot rows can come first.
    """

    if limit <= 0:
        raise ValueError("evidence sample limit must be positive")
    if not isinstance(evidence, list):
        evidence = []
    if not isinstance(queries, list):
        queries = []
    allowed = {str(value) for value in query_ids} if query_ids is not None else None
    rows_by_query: dict[str, list[Mapping[str, Any]]] = {}
    query_order: list[str] = []
    query_records: dict[str, Mapping[str, Any]] = {}
    for item in queries:
        if not isinstance(item, Mapping) or item.get("status") != "completed":
            continue
        query_id = item.get("query_id")
        if query_id is None or (allowed is not None and str(query_id) not in allowed):
            continue
        query_key = str(query_id)
        if query_key not in query_records:
            query_order.append(query_key)
        query_records[query_key] = item
        rows_by_query.setdefault(query_key, [])
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        query_id = item.get("query_id")
        if query_id is None or (allowed is not None and str(query_id) not in allowed):
            continue
        query_key = str(query_id)
        if query_key not in rows_by_query:
            query_order.append(query_key)
            rows_by_query[query_key] = []
        rows_by_query[query_key].append(item)

    for query_id, rows in rows_by_query.items():
        rows = _spread_evidence_in_time(rows)
        if preferred_evidence_ids:
            rows.sort(key=lambda row: str(row.get("evidence_id")) not in preferred_evidence_ids)
        rows_by_query[query_id] = rows
        try:
            pairs = source_pairs(str(query_records.get(query_id, {}).get("spl", "")))
        except ValueError:
            pairs = frozenset()
        if len(pairs) > 1:
            by_source: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
            for row in rows:
                by_source.setdefault(result_source(row.get("selected_result", {}), pairs), []).append(row)
            # Retained minority sources must also survive model-context sampling.
            rows_by_query[query_id] = [
                group[position] for position in range(max((len(group) for group in by_source.values()), default=0))
                for group in by_source.values() if position < len(group)
            ]

    sampled: list[Mapping[str, Any]] = []
    # Newest requested pages precede older pages, then ordinary sampling.
    # Keep query/source balance within each round and original coverage below.
    selected_ids: set[str] = set()
    for requested in [*(requested_evidence_groups or []), None]:
        groups = {
            query_id: [row for row in rows if
                       str(row.get("evidence_id")) not in selected_ids
                       and (requested is None or str(row.get("evidence_id")) in requested)]
            for query_id, rows in rows_by_query.items()
        }
        positions = {query_id: 0 for query_id in query_order}
        while len(sampled) < limit:
            added = False
            for query_id in query_order:
                position = positions[query_id]
                rows = groups[query_id]
                if position >= len(rows):
                    continue
                sampled.append(rows[position])
                selected_ids.add(str(rows[position].get("evidence_id")))
                positions[query_id] = position + 1
                added = True
                if len(sampled) >= limit:
                    break
            if not added:
                break

    supplied_by_query: dict[str, int] = {}
    for item in sampled:
        query_id = item.get("query_id")
        if query_id is not None:
            key = str(query_id)
            supplied_by_query[key] = supplied_by_query.get(key, 0) + 1
    coverage: list[dict[str, Any]] = []
    for query_id in query_order:
        retained_count = len(rows_by_query[query_id])
        supplied_count = supplied_by_query.get(query_id, 0)
        query_record = query_records.get(query_id, {})
        result_count = query_record.get("result_count")
        result_count_value = result_count if isinstance(result_count, int) else None
        omitted_count = max(0, retained_count - supplied_count)
        retention_gap = (
            max(0, result_count_value - retained_count)
            if result_count_value is not None
            else 0
        )
        if query_record.get("truncated") and retained_count == 0:
            coverage_status = "retrieval_incomplete"
        elif result_count_value == 0 and retained_count == 0:
            coverage_status = "no_results"
        elif retention_gap:
            coverage_status = "retention_gap"
        elif omitted_count:
            coverage_status = "sampled"
        else:
            coverage_status = "complete"
        coverage.append({
            "query_id": query_id,
            "result_count": result_count_value,
            "retained_evidence_count": retained_count,
            "supplied_evidence_count": supplied_count,
            "omitted_evidence_count": omitted_count,
            "sample_omitted": bool(omitted_count),
            "query_truncated": query_record.get("truncated"),
            "available_result_count": query_record.get("available_result_count"),
            "retrieval_stop_reason": query_record.get("retrieval_stop_reason"),
            "coverage_status": coverage_status,
            "observed_time_bounds": evidence_time_bounds(rows_by_query[query_id]),
            "coverage_note": (
                "Only a bounded sample was supplied; omitted retained records may contain relevant activity."
                if omitted_count
                else "Retrieval stopped before evidence could be retained; this does not establish zero matching events."
                if coverage_status == "retrieval_incomplete"
                else "The query returned no results; no evidence was supplied."
                if coverage_status == "no_results"
                else "No retained evidence was supplied for this query."
                if retained_count == 0 and result_count_value not in (None, 0)
                else "The supplied evidence covers all retained records for this query."
            ),
        })
    return sampled, coverage


def _assessment_context(
    plan: HuntPlan,
    results: Mapping[str, Any],
    *,
    query_ids: set[str] | None = None,
    threat_intelligence: str = "",
    limit: int = _MODEL_EVIDENCE_SAMPLE_LIMIT,
) -> dict[str, Any]:
    """Build bounded direct-evidence context for one adaptive assessment round."""

    advisory_iocs = query_ioc_context(threat_intelligence)
    evidence = results.get("evidence", [])
    queries = results.get("queries", [])
    question_by_query = _completed_query_questions(results)
    query_windows = {
        str(entry.get("query_id")): {key: entry["proposal"][key] for key in ("earliest_utc", "latest_utc") if key in entry["proposal"]}
        for entry in results.get("query_ledger", []) if isinstance(entry.get("proposal"), Mapping)
    }
    retained_evidence, evidence_coverage = _balanced_evidence_sample(
        evidence,
        queries,
        query_ids=query_ids,
        limit=limit,
    )
    retained_evidence = [
        {
            key: item[key]
            for key in ("evidence_id", "query_id", "event_time_utc", "evidence_kind", "selected_result")
            if key in item
        } | {"advisory_ioc_comparison": compare_advisory_iocs(item.get("selected_result"), advisory_iocs)}
        for item in retained_evidence
    ]
    return {
        "approved_plan": {
            "hypothesis": plan.hypothesis,
            "objective": plan.objective,
            "scope": plan.scope.model_dump(mode="json"),
            "questions": [question.model_dump(mode="json") for question in plan.questions],
        },
        "completed_queries": [
            {
                key: item[key]
                for key in ("query_id", "purpose", "spl", "result_count", "truncated", "available_result_count", "retrieval_stop_reason", "earliest_utc", "latest_utc")
                if key in item
            } | query_windows.get(str(item["query_id"]), {}) | {
                "question_id": question_by_query[str(item["query_id"])],
                "allowed_evidence_ids": [
                    row["evidence_id"] for row in retained_evidence
                    if str(row.get("query_id")) == str(item["query_id"])
                ],
                "retained_evidence": [
                    row for row in retained_evidence
                    if str(row.get("query_id")) == str(item["query_id"])
                ],
            }
            for item in queries
            if isinstance(item, Mapping)
            and item.get("status") == "completed"
            and str(item.get("query_id")) in question_by_query
            and (query_ids is None or str(item.get("query_id")) in query_ids)
        ] if isinstance(queries, list) else [],
        "advisory_iocs": advisory_iocs,
        "evidence_coverage": evidence_coverage,
        "source_coverage": [item for item in query_source_coverage(results, supplied_evidence=retained_evidence)
                            if query_ids is None or item["query_id"] in query_ids],
        "assessment_rules": [
            "Return one assessment for every completed query and select its exact query_id label. The application derives question_id from that query.",
            "Use evidence_id values as evidence_candidate_row_refs. For new_entities return entity_type and value only; the application derives result_row_refs from exact value matches in this query's supplied rows.",
            "Each completed query contains its own retained_evidence. Cite only rows in that query's group; cross-query relationships may motivate pivots but do not replace that query's supporting evidence.",
            "Copy citations exactly from that completed query's allowed_evidence_ids; never use query IDs, event IDs, or another query's evidence IDs as citations.",
            "When allowed_evidence_ids is empty, return empty evidence_candidate_row_refs and new_entities. Report any missing coverage as a limitation; do not borrow evidence from another query.",
            "evidence_coverage distinguishes no results from a bounded sample; sample_omitted means records were not supplied and must not be treated as absent.",
            "source_coverage counts identified rows per source. needs_source_check is an unresolved source omitted from truncated results, not evidence of absence. A completed source check establishes a search, not an answered question or complete telemetry.",
            "Each query's earliest_utc/latest_utc are its actual search window. A narrow or empty search does not establish absence elsewhere in the approved scope. Identify useful unsearched time before or after an observed lead instead of treating its timestamps as the full activity window.",
            "Every entity value must equal a complete scalar field value or list element in its cited retained evidence, including scalar values inside JSON _raw. A substring merely appearing inside a longer string does not satisfy this contract.",
            "Do not parse file paths from command_line, remove quotes/arguments, or invent normalized entity values. Select the existing file_name or process value when suitable. Describe useful command-line interpretations in the evidence-backed summary, not as a new entity. Do not label an entire command line as a file.",
            "Extract actionable observed entities from cited rows when present, including hosts, users, source or destination IPs, processes, domains, and files; do not default to filenames when stronger pivot entities are available.",
            "Select a concise set of material entities and supporting citations for each assessment; do not enumerate every evidence row or repeat equivalent observations. Prioritize entities that support the next investigation step.",
            "Use each row's application-computed advisory_ioc_comparison. A filename match does not establish a hash or path match. hash_literals compares complete hexadecimal scalar values ignoring case; empty means no comparable hash literal was supplied. Name/domain matches use exact whole-value equality. Comparisons cover only the bounded extracted advisory_iocs, not full STIX pattern logic or all advisory content; they do not infer field meaning, file identity, or maliciousness. State which value matched and distinguish it from observed execution and a confirmed incident.",
            "Describe the observed action without assuming its intent or authorization. Familiar process names, common-looking domains, ports and successful events do not establish a normal or benign baseline. A supplied baseline or authorization can support only the comparison or permission it actually documents; otherwise state that those properties are unknown.",
            "Distinguish shared host/account context, overlapping times, a matching logon session, and a matching process identity. Use the actual stable identifiers and their host/time scope when present. Different process or session identifiers do not establish the same process/session merely because other fields match. Keep unsupported relationships tentative and identify the useful next check.",
            "State whether the result advances scope and spread, and identify useful before or after timeline context when the retained rows support it.",
            "Identify unanswered questions, missing telemetry, noisy results, and truncation that affect scope or timeline conclusions.",
            "Use application-computed observed_time_bounds in evidence_coverage. The approved hunt range does not establish observed coverage. Point timestamps never prove continuous activity or full-window telemetry; state only the observed points and their limitations.",
            "Propose a follow-up question only when the results justify a useful evidence-grounded pivot for an unanswered question; when proposing none, give a concise limitations explanation grounded in answered questions, unavailable telemetry, or exhausted relevant leads, without requiring arbitrary extra queries.",
            "Use general NIST SP 800-61 Rev. 3 DE.AE-03, DE.AE-04, and RS.AN-08 and MITRE TTP-Based Hunting section 2.4.3.6 as guidance for correlation and scope assessment; do not claim compliance or invent facts.",
            "Separate direct evidence from inference and do not invent entities, identifiers, or telemetry.",
        ],
    }


def _assessment_repair_context(
    context: Mapping[str, Any],
    assessments: list[QueryAssessment],
    results: Mapping[str, Any],
) -> dict[str, Any]:
    """Isolate failed assessments using exactly the originally supplied evidence."""

    groups = context["completed_queries"]
    expected_ids = {str(group["query_id"]) for group in groups}
    if any(str(assessment.query_id) not in expected_ids for assessment in assessments):
        raise Validation("query assessment has an unknown query_id; cannot safely target a repair")
    supplied_results = {
        **results,
        "evidence": [row for group in groups for row in group["retained_evidence"]],
    }
    errors: dict[str, str] = {}
    for group in groups:
        query_id = str(group["query_id"])
        try:
            _materialize_follow_up_questions(
                [item for item in assessments if str(item.query_id) == query_id],
                supplied_results,
                query_ids={query_id},
            )
        except Validation as exc:
            errors[query_id] = str(exc)
    return {
        **context,
        "completed_queries": [group for group in groups if str(group["query_id"]) in errors],
        "evidence_coverage": [
            item for item in context["evidence_coverage"] if str(item["query_id"]) in errors
        ],
        "validation_errors": errors,
    }


def _completed_query_questions(results: Mapping[str, Any]) -> dict[str, str]:
    """Resolve question IDs from current records or older durable ledger entries."""

    question_by_query: dict[str, str] = {}
    ledger = results.get("query_ledger", [])
    if isinstance(ledger, list):
        for item in ledger:
            proposal = item.get("proposal") if isinstance(item, Mapping) else None
            if (
                isinstance(item, Mapping)
                and isinstance(proposal, Mapping)
                and item.get("query_id")
                and proposal.get("question_id")
            ):
                question_by_query[str(item["query_id"])] = str(proposal["question_id"])
    queries = results.get("queries", [])
    if isinstance(queries, list):
        for item in queries:
            if (
                isinstance(item, Mapping)
                and item.get("status") == "completed"
                and item.get("query_id")
                and item.get("question_id")
            ):
                question_by_query[str(item["query_id"])] = str(item["question_id"])
    return question_by_query


def _materialize_follow_up_questions(
    assessments: list[QueryAssessment],
    results: Mapping[str, Any],
    *,
    query_ids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate assessment grounding and assign IDs to bounded follow-up questions."""

    queries = results.get("queries", [])
    evidence = results.get("evidence", [])
    completed_query_ids = {
        str(item.get("query_id"))
        for item in queries
        if isinstance(item, Mapping)
        and item.get("status") == "completed"
        and item.get("query_id")
    } if isinstance(queries, list) else set()
    completed = {
        query_id: question_id
        for query_id, question_id in _completed_query_questions(results).items()
        if query_id in completed_query_ids
        and (query_ids is None or query_id in query_ids)
    }
    evidence_by_query: dict[str, dict[str, Mapping[str, Any]]] = {}
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, Mapping):
                continue
            evidence_by_query.setdefault(str(item.get("query_id")), {})[
                str(item.get("evidence_id"))
            ] = item

    if len(assessments) != len(completed) or {str(item.query_id) for item in assessments} != set(completed):
        raise Validation("query assessments must cover every supplied completed query exactly once")

    stored: list[dict[str, Any]] = []
    follow_ups: list[dict[str, Any]] = []
    for assessment in assessments:
        query_id = str(assessment.query_id)
        if assessment.question_id != completed[query_id]:
            raise Validation("query assessment question does not match its completed query")
        available = evidence_by_query.get(query_id, {})
        candidate_refs = {str(value) for value in assessment.evidence_candidate_row_refs}
        if not candidate_refs.issubset(available):
            raise Validation(
                f"query assessment referenced unavailable evidence for query_id={query_id}: "
                f"invalid evidence_candidate_row_refs={sorted(candidate_refs - available.keys())}; "
                f"allowed_evidence_ids={sorted(available)}"
            )
        grounded_entities: list[dict[str, Any]] = []
        invalid_entity_positions: list[int] = []
        for position, entity in enumerate(assessment.new_entities):
            refs = {str(value) for value in entity.result_row_refs}
            if not refs or not refs.issubset(available):
                raise Validation(
                    f"query assessment entity referenced unavailable evidence for query_id={query_id}: "
                    f"entity={entity.value!r}, result_row_refs={sorted(refs)}; "
                    f"allowed_evidence_ids={sorted(available)}; nonempty citations required for entities"
                )
            observed_values = {
                str(value)
                for ref in refs
                for value in _flatten_scalar_values(available[ref].get("selected_result"))
            }
            if entity.value not in observed_values:
                invalid_entity_positions.append(position)
            grounded_entities.append(entity.model_dump(mode="json"))
        if invalid_entity_positions:
            fields = ", ".join(f"new_entities[{position}].value" for position in invalid_entity_positions)
            raise Validation(
                "query assessment entity was not present as a complete scalar field value "
                f"or list element in cited evidence: {fields}. "
                "Copy an observed value suitable for the entity type or remove that entity. "
                "Substrings and parsed command-line paths are not accepted as entity values; "
                "keep useful interpretations in the evidence-backed summary."
            )
        stored.append(assessment.model_dump(mode="json"))
        if (
            assessment.proposed_next_question is not None
            and len(follow_ups) < MAX_FOLLOW_UP_QUESTIONS
        ):
            follow_ups.append({
                "question_id": str(uuid4()),
                "source_query_id": query_id,
                "source_question_id": assessment.question_id,
                "source_evidence_ids": sorted(
                    candidate_refs
                    | {
                        str(ref)
                        for entity in assessment.new_entities
                        for ref in entity.result_row_refs
                    }
                ),
                "grounded_entities": grounded_entities,
                **assessment.proposed_next_question.model_dump(mode="json"),
            })
    return stored, follow_ups


def _pending_investigation_questions(
    plan: HuntPlan, results: Mapping[str, Any],
    new_questions: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Prioritize unsearched approved questions, retaining every deferred pivot."""
    completed = {
        str(item.get("question_id")) for item in results.get("queries", [])
        if isinstance(item, Mapping) and item.get("status") == "completed"
    }
    completed_query_ids = {
        str(item.get("query_id")) for item in results.get("queries", [])
        if isinstance(item, Mapping) and item.get("status") == "completed" and item.get("query_id")
    }
    latest_decisions = {
        str(item.get("question_id")): item for item in results.get("follow_up_decisions", [])
        if isinstance(item, Mapping)
    }
    skipped = {
        identifier for identifier, item in latest_decisions.items() if item.get("skip_reason") and (
            "considered_query_ids" not in item  # Preserve historical decisions without a recorded basis.
            or item.get("decision_source") == "application_duplicate_suppression"
            or set(item["considered_query_ids"]) == completed_query_ids
        )
    }
    questions = [
        {**question.model_dump(mode="json"), "approved_question": True}
        for question in plan.questions
    ] + list(results.get("follow_up_questions", [])) + list(new_questions or [])
    pending: dict[str, dict[str, Any]] = {}
    for question in questions:
        identifier = str(question["question_id"])
        if identifier not in completed | skipped:
            pending.setdefault(identifier, question)
    return list(pending.values())


def _follow_up_decision_contract(question_ids: list[str]) -> TypeAdapter[list[FollowUpDecision]]:
    """Require an explicit decision for every generated question, including skips."""

    def validate_coverage(decisions: list[FollowUpDecision]) -> list[FollowUpDecision]:
        if len(decisions) != len(question_ids) or {d.question_id for d in decisions} != set(question_ids):
            raise ValueError("return exactly one FollowUpDecision for each question_id: " + ", ".join(question_ids))
        return decisions

    return TypeAdapter(Annotated[list[FollowUpDecision], AfterValidator(validate_coverage)])


def _follow_up_proposal_errors(
    proposals: list[QueryProposal],
    follow_up_questions: list[dict[str, Any]],
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Attribute validation errors to the offending proposal, preserving earlier valid queries."""

    questions = {str(item["question_id"]): item for item in follow_up_questions}
    seen_questions: set[str] = set()
    errors: dict[str, str] = {}
    for proposal in proposals:
        question = questions.get(proposal.question_id)
        if question is None or proposal.question_id in seen_questions:
            errors[proposal.question_id] = "follow-up query must reference one unique generated question"
            continue
        normalized_spl = proposal.spl.strip().casefold()
        entity_values = [
            str(entity.get("value"))
            for entity in question.get("grounded_entities", [])
            if isinstance(entity, Mapping) and entity.get("value")
        ]
        source_ids = set(question.get("source_evidence_ids", []))
        entity_values.extend(
            str(value)
            for row in evidence or []
            if row.get("evidence_id") in source_ids
            and str(row.get("query_id")) == str(question.get("source_query_id"))
            for value in _flatten_scalar_values(row.get("selected_result"))
        )
        if entity_values and not any(value.casefold() in normalized_spl for value in entity_values):
            errors[proposal.question_id] = "follow-up query did not use an evidence-grounded pivot value"
            continue
        seen_questions.add(proposal.question_id)
    return errors


def _question_synthesis_contract(plan: HuntPlan, *, allow_retrieval: bool = False) -> type[BaseModel]:
    """Require one closed answer slot per approved question, with app-owned keys."""

    def validate_lookup_scope(answer: QuestionAnswerStep) -> QuestionAnswerStep:
        for request in answer.retained_evidence_requests:
            earliest = request.earliest_utc or plan.scope.earliest_utc
            latest = request.latest_utc or plan.scope.latest_utc
            if earliest < plan.scope.earliest_utc or latest > plan.scope.latest_utc or earliest >= latest:
                raise ValueError("retained evidence lookup exceeds the approved time window")
        return answer

    fields: dict[str, Any] = {
        f"question_{index}": (Annotated[QuestionAnswerStep, AfterValidator(validate_lookup_scope)] if allow_retrieval else QuestionAnswer, ...)
        for index, _ in enumerate(plan.questions, 1)
    }
    return create_model("QuestionSynthesis", __base__=DomainModel, **fields)


def _materialize_question_answers(answer: BaseModel, plan: HuntPlan, results: Mapping[str, Any], *, threat_intelligence: str = "") -> dict[str, Any]:
    """Assign question/finding relationships without asking the model to copy IDs."""

    findings: list[dict[str, Any]] = []
    answers: list[dict[str, Any]] = []
    advisory_iocs = query_ioc_context(threat_intelligence)
    completed = {str(query["query_id"]) for query in results.get("queries", []) if query.get("status") == "completed"}
    leads = advisory_lead_groups([
        {**row, "advisory_ioc_comparison": compare_advisory_iocs(row.get("selected_result"), advisory_iocs)}
        for row in results.get("evidence", []) if str(row.get("query_id")) in completed
    ])
    lead_by_evidence = {identifier: lead for lead in leads for identifier in lead["evidence_ids"]}
    for index, question in enumerate(plan.questions, 1):
        item: QuestionAnswer = getattr(answer, f"question_{index}")
        if getattr(item, "retained_evidence_requests", []):
            continue
        materialized = _materialize_findings(item.findings, results)
        findings.extend(materialized)
        stored: dict[str, Any] = {
            "question_id": question.question_id, "question": question.question,
            "summary": item.summary,
            "finding_ids": [finding["finding_id"] for finding in materialized],
            "limitations": list(item.limitations),
        }
        if leads:
            covered = set()
            coverage = []
            for disposition in item.lead_coverage:
                lead = lead_by_evidence.get(str(disposition.lead_evidence_id))
                if lead is None or lead["lead_evidence_id"] in covered:
                    raise Validation("lead coverage must reference distinct retained advisory leads")
                linked = []
                for number in disposition.finding_numbers:
                    if not 1 <= number <= len(materialized):
                        raise Validation("lead coverage references an unavailable finding")
                    finding = materialized[number - 1]
                    if finding["classification"] != "not_supported_within_scope" and not set(finding["evidence_ids"]).intersection(lead["evidence_ids"]):
                        raise Validation("lead coverage finding must cite that advisory lead")
                    linked.append(finding["finding_id"])
                covered.add(lead["lead_evidence_id"])
                coverage.append({"lead_evidence_ids": lead["evidence_ids"], "identity_fields": lead["identity_fields"],
                                 "finding_ids": linked, "limitation": disposition.limitation})
            for lead in leads:
                if lead["lead_evidence_id"] not in covered:
                    coverage.append({"lead_evidence_ids": lead["evidence_ids"], "identity_fields": lead["identity_fields"],
                                     "finding_ids": [], "limitation": "This retained advisory lead was not accounted for in the supplied model context."})
            stored["lead_coverage"] = coverage
            unanswered = sum(not lead["finding_ids"] for lead in coverage)
            if unanswered:
                stored["limitations"].append(f"{unanswered} of {len(coverage)} retained advisory lead groups remain unanswered for this question.")
        elif item.lead_coverage:
            raise Validation("lead coverage has no retained advisory support")
        answers.append(stored)
    return {"findings": findings, "question_answers": answers}


def _retained_synthesis_pages(answer: BaseModel, plan: HuntPlan, results: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Resolve requests using this owned hunt's immutable retained results."""

    pages = []
    for index, question in enumerate(plan.questions, 1):
        for request in getattr(getattr(answer, f"question_{index}"), "retained_evidence_requests", []):
            earliest = request.earliest_utc or plan.scope.earliest_utc
            latest = request.latest_utc or plan.scope.latest_utc
            if earliest < plan.scope.earliest_utc or latest > plan.scope.latest_utc or earliest >= latest:
                raise Validation("retained evidence lookup exceeds the approved time window")
            page = lookup_retained_evidence(
                results, query_ids=set(request.query_ids),
                filters={item.field: item.value for item in request.filters},
                earliest_utc=earliest if request.earliest_utc or request.latest_utc else None,
                latest_utc=latest if request.earliest_utc or request.latest_utc else None,
                offset=request.offset, limit=request.limit,
            )
            records = page.pop("records")
            identifiers = [str(record["evidence_id"]) for record in records]
            identifiers.extend(str(origin["evidence_id"]) for record in records
                               for origin in record.get("duplicate_references", []))
            pages.append({**page, "question_id": question.question_id,
                          "returned_evidence_ids": list(dict.fromkeys(identifiers))})
    return pages


def _synthesis_context(
    *,
    plan: HuntPlan,
    threat_intelligence: str,
    results: Mapping[str, Any],
    limit: int = _MODEL_EVIDENCE_SAMPLE_LIMIT,
) -> dict[str, Any]:
    """Provide the model only bounded, retained evidence and completed queries."""

    advisory_iocs = query_ioc_context(threat_intelligence)
    evidence = results.get("evidence", [])
    queries = results.get("queries", [])
    completed_ids = {
        str(query.get("query_id")) for query in queries
        if isinstance(query, Mapping) and query.get("status") == "completed"
    } if isinstance(queries, list) else set()
    # Source selection must not inherit an earlier model's conclusions or
    # oversized citation groups. Advisory comparisons are exact application
    # lookups; prioritize those rows within each query without starving others.
    pending_ids = {question.question_id for question in plan.questions}
    lookup_pages = [page for page in results.get("synthesis_retrievals", [])
                    if page.get("question_id") in pending_ids]
    requested_rounds: dict[int, set[str]] = {}
    for position, page in enumerate(lookup_pages):
        requested_rounds.setdefault(page.get("retrieval_round", position), set()).update(
            str(identifier) for identifier in page["returned_evidence_ids"])
    indicator_ids: set[str] = set().union(*requested_rounds.values())
    for item in evidence if isinstance(evidence, list) else []:
        if not isinstance(item, Mapping):
            continue
        comparison = compare_advisory_iocs(item.get("selected_result"), advisory_iocs)
        if (comparison["matched_file_name_literals"] or comparison["matched_domain_literals"]
                or any(match["matches_extracted_advisory_hash"] for match in comparison["hash_literals"])):
            indicator_ids.add(str(item.get("evidence_id")))
    sampled_evidence, evidence_coverage = _balanced_evidence_sample(
        evidence, queries, query_ids=completed_ids, preferred_evidence_ids=indicator_ids, limit=limit,
        requested_evidence_groups=[requested_rounds[key] for key in sorted(requested_rounds, reverse=True)],
    )
    query_inventories = []
    for query_id in sorted(completed_ids):
        inventory = lookup_retained_evidence(results, query_ids={query_id}, limit=1)
        query_inventories.append({key: inventory[key] for key in (
            "scope", "query_coverage", "matching_raw_record_count", "aggregate_rows_excluded",
            "observed_time_bounds", "distinct_fields", "limitation",
        )})
    evidence_rows = [
        {
            key: item[key]
            for key in (
                "evidence_id", "query_id", "index", "sourcetype", "event_time_utc", "evidence_kind", "selected_result"
            )
            if key in item
        } | {"advisory_ioc_comparison": compare_advisory_iocs(item.get("selected_result"), advisory_iocs)}
        for item in sampled_evidence
    ]
    query_windows = {
        str(entry.get("query_id")): {key: entry["proposal"][key] for key in ("earliest_utc", "latest_utc") if key in entry["proposal"]}
        for entry in results.get("query_ledger", []) if isinstance(entry.get("proposal"), Mapping)
    }
    query_rows = [
        {
            key: item[key]
            for key in ("query_id", "question_id", "purpose", "spl", "status", "outcome", "partial_fetch", "result_count", "truncated", "available_result_count", "retrieval_stop_reason", "earliest_utc", "latest_utc")
            if key in item
        } | query_windows.get(str(item["query_id"]), {})
        for item in queries
        if isinstance(item, Mapping) and item.get("status") == "completed"
    ] if isinstance(queries, list) else []
    return {
        "approved_plan": {
            "hypothesis": plan.hypothesis,
            "objective": plan.objective,
            "scope": plan.scope.model_dump(mode="json"),
            "questions": [
                question.model_dump(mode="json") | {"answer_slot": f"question_{index}"}
                for index, question in enumerate(plan.questions, 1)
            ],
        },
        "advisory_context": threat_intelligence,
        "advisory_iocs": advisory_iocs,
        "investigation_limitations": _derive_report_limitations({
            key: value for key, value in results.items()
            if key not in {"query_assessments", "follow_up_decisions"}
        }),
        "adaptive_status": results.get("adaptive_status", "unknown"),
        "completed_queries": query_rows,
        "retained_evidence": evidence_rows,
        "evidence_coverage": evidence_coverage,
        "source_coverage": query_source_coverage(results, supplied_evidence=sampled_evidence),
        "retained_query_inventories": query_inventories,
        "retained_lookup_pages": [{**page, "supplied_evidence_ids": [
            item["evidence_id"] for item in sampled_evidence if str(item["evidence_id"]) in page["returned_evidence_ids"]],
            "sample_omitted": any(identifier not in {str(item["evidence_id"]) for item in sampled_evidence}
                                  for identifier in page["returned_evidence_ids"])} for page in lookup_pages],
        "synthesis_rules": [
            "If the response schema permits retained_evidence_requests, each question may either give a final answer or request up to three local pages first. For a request, give findings=[] and explain the missing support in limitations. The application checkpoints completed answers and resolves pages from this hunt only; requests cannot submit searches or expand the approved scope.",
            "Use exact typed field filters, optional half-open UTC time bounds within the approved scope, completed query labels and the returned next_offset for paging. Original query coverage, matching subset counts, page size and supplied sample coverage are different. An empty local subset is not proof of absence from Splunk. Do not repeat an identical page request. If requests are unavailable or a needed page remains omitted, give an explicitly limited answer.",
            "Answer every approved question in its application-assigned answer_slot. Each slot requires findings responsive to that question or an explicit limitation explaining why it cannot be answered. Repeating an indicator finding does not answer a different chronology, authentication, or communications question. Use original indicator records as supporting evidence for related observations when needed.",
            "For every advisory_leads entry, include one lead_coverage disposition in every final question answer. Select its lead_evidence_id and the one-based positions of findings responsive to that question for that lead, or state the missing answer explicitly. Each linked positive finding must cite a record from that lead plus any records supporting the related activity. Shared identity_fields define literal review groups, not proof of one process lifetime or causation. Do not treat a valid disposition as proof of a complete answer. Native identifiers belong in observed facts; citation fields use supplied labels.",
            "Give each question a concise summary covering its material findings and limitations. Group related observations instead of listing every event. Apply the same grounding standard to summaries as to finding titles and statements. Keep the full findings independently of summary length; report presentation must not restrict investigation coverage.",
            "Use retained_query_inventories for application-computed distinct literal counts over each query's full retained raw rows. State their query scope and missing or ambiguous fields. These are observed field-value counts, not confirmed affected entities or unique process instances. Do not sum per-query distinct counts across overlapping searches or infer that a whole-query count describes a narrower lead, session or time window. Truncated searches prevent a complete inventory, but do not erase the recorded observations.",
            "For chronology questions, cover every material lead and the supplied related process/module records before and after it. State the actual process or session relationship and event times; an indicator start/end alone is not a complete surrounding timeline.",
            "Use only the supplied evidence_ids and query_ids.",
            "For every material claim, select the records that establish each stated entity, action, and relationship. A cross-source correlation requires citations from every source involved; otherwise separate the observations and label the correlation as unconfirmed inference.",
            "Apply the same evidence standard to titles and statements. An observed field value and a conventional interpretation are different: a port number does not establish an application protocol, and a familiar file or domain name does not establish identity or ownership. State the observed value; put a tentative interpretation in inference and identify the missing verification.",
            "Keep titles and statements limited to supported observations. Describe successful logons, process starts and connections as those actions. Normal, routine, benign, authorized, deliberate or coordinated behavior needs its own supplied support; familiar names, ports and successful events do not establish those properties. If a baseline or authorization is supplied, report the precise supported comparison or permission and its scope. Otherwise leave those properties unknown rather than asserting them and adding a caveat later.",
            "For correlations, state the actual relationship keys. Shared hosts/accounts and overlapping times establish only that context; they do not establish the same logon session, process or cause. Check stable process/session identifiers together with host and time when supplied. Keep activity from different identities separate, and do not attribute one process's connections to another. A proposed relationship without such support belongs in tentative inference, with the missing evidence identified.",
            "Review each distinct relevant indicator event in the supplied evidence. Cite the events that support the finding, including materially different hosts, tools, and times; do not add irrelevant citations or duplicate copies of the same event for a higher count.",
            "The application owns search result counts, query_truncated, and sample_omitted. result_count counts retained rows; available_result_count is the server's output count when known, not the number of underlying events scanned. query_truncated means retrieval was incomplete; retrieval_stop_reason explains why. sample_omitted means retained rows were omitted only from this model context. Zero retained rows after incomplete retrieval do not establish zero matching events. Report supplied application-computed distinct field counts when answering an inventory question, naming their exact query/filter/time scope and missing-value limitations. Do not invent counts or infer complete source coverage from them.",
            "Derive findings from source records and executed query scope. A query purpose describes the intended investigation, not an established observation; inspect its SPL and actual results before making a claim.",
            "Base statements only on retained_evidence; advisory_context is context, not evidence.",
            "Use application-computed observed_time_bounds in evidence_coverage. The approved hunt range is a search constraint, not observed coverage. Point timestamps, including heartbeats at one time, never establish continuous activity throughout that window. Do not imply duration, continuity, or full-window monitoring without direct coverage evidence.",
            "Use evidence_coverage to distinguish no matching results from evidence omitted from the bounded model sample; do not treat sample_omitted records as absent.",
            "Use source_coverage to distinguish requested sources, identified retained/supplied rows, and completed source-specific checks. A source with needs_source_check is uninvestigated in the truncated result; do not claim it is absent or that the question is answered.",
            "Confidence describes certainty in the observed telemetry, not certainty in attribution, impact, or incident scope.",
            "An advisory IOC match is a hunt lead; state malware execution or attribution only when direct evidence establishes that conclusion beyond the IOC match.",
            "A no-matching-activity or zero-result conclusion uses not_supported_within_scope, completed query citations, and no evidence citations. supported_observation describes positive event evidence. Never attach an unrelated event to a negative conclusion to satisfy the schema.",
            "A broad sample of activity that looks familiar does not test absence of command-and-control, lateral movement or other malicious behavior. A negative finding must describe what the cited query actually tested within its filters and time window. If the question was not tested adequately, report it as unanswered or limited instead of embedding a no-malicious-behavior claim in a positive observation.",
            "Use each row's application-computed advisory_ioc_comparison. A filename match does not establish a hash or path match. hash_literals compares complete hexadecimal scalar values ignoring case; empty means no comparable hash literal was supplied. Name/domain matches use exact whole-value equality. Comparisons cover only the bounded extracted advisory_iocs, not full STIX pattern logic or all advisory content; they do not infer field meaning, file identity, or maliciousness. Distinguish exact matched values, observed execution or activity, and a confirmed incident.",
            "State scope limitations, unanswered investigation questions, and missing telemetry when the supplied coverage cannot establish blast radius.",
            "Limit any absence claim to the cited query's actual earliest_utc/latest_utc and filters. Search completion does not prove the question was answered, the query was logically correct, or the approved time range had complete telemetry. Unknown search windows cannot support full-range absence claims.",
            "Do not invent facts, entities, timestamps, telemetry, or identifiers.",
            "When retained evidence supports no finding for a question, return findings=[] in that question's slot and explain the missing support in limitations.",
        ],
    }


def _materialize_findings(
    proposals: list[FindingProposal], results: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Assign finding IDs and reject citations outside the retained execution record."""

    evidence = results.get("evidence", [])
    queries = results.get("queries", [])
    evidence_ids = {
        str(item.get("evidence_id")) for item in evidence if isinstance(item, Mapping)
    } if isinstance(evidence, list) else set()
    query_ids = {
        str(item.get("query_id")) for item in queries
        if isinstance(item, Mapping) and item.get("status") == "completed"
    } if isinstance(queries, list) else set()
    incomplete_queries = {str(item.get("query_id")) for item in queries
                          if isinstance(item, Mapping) and query_results_incomplete(item)} if isinstance(queries, list) else set()
    findings: list[dict[str, Any]] = []
    for proposal in proposals:
        if not {str(value) for value in proposal.evidence_ids}.issubset(evidence_ids):
            raise Validation("synthesis referenced unavailable evidence")
        if not {str(value) for value in proposal.query_ids}.issubset(query_ids):
            raise Validation("synthesis referenced unavailable completed query")
        if proposal.classification.value == "not_supported_within_scope" and incomplete_queries.intersection(str(value) for value in proposal.query_ids):
            raise Validation("negative findings require complete query results")
        finding = {"finding_id": str(uuid4()), **proposal.model_dump(mode="json")}
        finding["evidence_ids"] = list(dict.fromkeys(finding["evidence_ids"]))
        finding["query_ids"] = list(dict.fromkeys(finding["query_ids"]))
        cited = {str(value) for value in proposal.evidence_ids}
        if cited:
            bounds = evidence_time_bounds([item for item in evidence if isinstance(item, Mapping) and str(item.get("evidence_id")) in cited])
            finding["limitations"] = [*finding["limitations"], bounds["limitation"]]
        findings.append(finding)
    return findings
