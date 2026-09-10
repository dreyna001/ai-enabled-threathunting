"""Provider response schemas and request-local evidence references."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from threat_hunting.domain.contracts import FINDING_GROUNDING_FIELDS
from threat_hunting.services.evidence import _flatten_scalar_values, compact_evidence_records, query_results_incomplete


_EVIDENCE_FIELDS = {"evidence_id", "evidence_ids", "allowed_evidence_ids", "result_row_refs", "evidence_candidate_row_refs",
                    "returned_evidence_ids", "supplied_evidence_ids"}
_QUERY_FIELDS = {"query_id", "query_ids", "source_query_id"}
_SCHEMA_KEYS = {"type", "properties", "items", "$ref", "$defs", "anyOf", "enum", "format", "description", "title"}


@dataclass(frozen=True)
class ReferenceLabels:
    """Immutable mapping containing only the records supplied for one call."""

    evidence: Mapping[str, Mapping[str, Any]]
    queries: Mapping[str, Mapping[str, Any]]

    @classmethod
    def from_context(cls, context: Mapping[str, Any]) -> "ReferenceLabels":
        queries = context.get("completed_queries", [])
        records = list(context.get("retained_evidence", []))
        for query in queries:
            records.extend(query.get("retained_evidence", []))
        records.extend({**row, **origin, "duplicate_references": []}
                       for row in list(records) for origin in row.get("duplicate_references", []))
        evidence_by_id = {str(row["evidence_id"]): row for row in records}
        query_by_id = {str(row["query_id"]): row for row in queries}
        if any(str(row["query_id"]) not in query_by_id for row in evidence_by_id.values()):
            raise ValueError("model evidence must belong to a supplied completed query")
        return cls(
            MappingProxyType({f"E{index}": MappingProxyType(dict(row)) for index, row in enumerate(evidence_by_id.values(), 1)}),
            MappingProxyType({f"Q{index}": MappingProxyType(dict(row)) for index, row in enumerate(query_by_id.values(), 1)}),
        )

    def encode(self, value: Any) -> Any:
        """Replace reference fields without modifying raw telemetry or prose."""
        evidence = {str(row["evidence_id"]): label for label, row in self.evidence.items()}
        queries = {str(row["query_id"]): label for label, row in self.queries.items()}

        def visit(item: Any, key: str = "") -> Any:
            if key == "selected_result":
                return item
            if isinstance(item, Mapping):
                if key == "validation_errors":
                    # Errors describe the original IDs; keep them aligned to this
                    # repair's mapping without changing source evidence text.
                    errors = {}
                    for query_id, reason in item.items():
                        for original, label in {**evidence, **queries}.items():
                            reason = str(reason).replace(original, label)
                        errors[queries.get(str(query_id), str(query_id))] = reason
                    return errors
                return {name: visit(child, name) for name, child in item.items()}
            if isinstance(item, (list, tuple)):
                return [visit(child, key) for child in item]
            mapping = evidence if key in _EVIDENCE_FIELDS else queries if key in _QUERY_FIELDS else {}
            return mapping.get(str(item), "UNAVAILABLE") if key in _EVIDENCE_FIELDS | _QUERY_FIELDS else item

        return visit(value)

    def decode(self, value: Any, *, findings: bool) -> Any:
        """Resolve only allowed labels and derive evidence-to-query relations."""
        def visit(item: Any, key: str = "") -> Any:
            if isinstance(item, Mapping):
                return {name: visit(child, name) for name, child in item.items()}
            if isinstance(item, list):
                values = [visit(child, key) for child in item]
                return list(dict.fromkeys(values)) if key in _EVIDENCE_FIELDS | _QUERY_FIELDS else values
            mapping = self.evidence if key in _EVIDENCE_FIELDS else self.queries if key in _QUERY_FIELDS else None
            if mapping is None:
                return item
            if not isinstance(item, str) or item not in mapping:
                raise ValueError(f"unknown {key} label; choose only supplied labels")
            return str(mapping[item]["evidence_id" if mapping is self.evidence else "query_id"])

        decoded = visit(value)
        if not findings and isinstance(decoded, list):
            query_by_id = {str(row["query_id"]): row for row in self.queries.values()}
            observed_refs: dict[tuple[str, str], list[str]] = {}
            for row in self.evidence.values():
                values = {str(value) for value in _flatten_scalar_values(row.get("selected_result"))}
                for observed in values:
                    observed_refs.setdefault((str(row["query_id"]), observed), []).append(str(row["evidence_id"]))
            for assessment in decoded:
                if not isinstance(assessment, dict):
                    continue
                query_id = str(assessment.get("query_id"))
                if "question_id" not in assessment:
                    query = query_by_id.get(query_id, {})
                    if "question_id" in query:
                        assessment["question_id"] = query["question_id"]
                # Canonical/historical assessments retain explicit references.
                # The current wire shape selects values; their row relationship
                # is an exact lookup within this query's supplied evidence.
                for position, entity in enumerate(assessment.get("new_entities", [])):
                    if not isinstance(entity, dict) or "result_row_refs" in entity:
                        continue
                    selected = entity.get("value")
                    matches = observed_refs.get((query_id, selected), []) if isinstance(selected, str) else []
                    if not matches:
                        raise ValueError(
                            f"new_entities[{position}].value must equal a complete scalar value "
                            "in the selected query's supplied evidence; substrings and "
                            "values from other queries are not accepted"
                        )
                    entity["result_row_refs"] = matches
        if findings:
            evidence_by_id = {str(row["evidence_id"]): row for row in self.evidence.values()}
            query_by_id = {str(row["query_id"]): row for row in self.queries.values()}
            groups = [decoded] if isinstance(decoded, list) else [
                answer["findings"] for answer in decoded.values()
                if isinstance(answer, Mapping) and isinstance(answer.get("findings"), list)
            ] if isinstance(decoded, Mapping) else []
            for finding in (item for group in groups for item in group):
                if not isinstance(finding, dict):
                    continue
                if finding.get("classification") == "not_supported_within_scope":
                    query_ids = finding.get("query_ids", [])
                    if not isinstance(query_ids, list):
                        raise ValueError("finding query_ids must be a list")
                    if any(query_results_incomplete(query_by_id[identifier]) for identifier in query_ids):
                        raise ValueError("negative findings require complete query results")
                if not finding.get("evidence_ids"):
                    continue
                expected = sorted({str(evidence_by_id[identifier]["query_id"]) for identifier in finding["evidence_ids"]})
                explicit = finding.get("query_ids", [])
                if not isinstance(explicit, list) or set(explicit).difference(expected):
                    raise ValueError("finding query labels do not match its selected evidence")
                finding["query_ids"] = expected
        return decoded


def structured_response_format(contract: Any, name: str, references: ReferenceLabels | None = None) -> dict[str, Any]:
    """Derive a closed response shape; domain validators retain semantic limits.

    Providers have different support for numeric/string constraints. The shared
    wire schema enforces types, required keys, formats, enums, and references; Pydantic
    still enforces lengths, ranges, timestamps, and cross-field invariants.
    """
    factory = getattr(contract, "model_json_schema", None) or getattr(contract, "json_schema", None)
    if not callable(factory):
        raise TypeError("model contract must expose a JSON schema")
    citation_definitions: dict[str, Any] = {}

    def convert(source: Mapping[str, Any]) -> dict[str, Any]:
        result = {key: value for key, value in source.items() if key in _SCHEMA_KEYS}
        if "const" in source:
            result["enum"] = [source["const"]]
        for key in ("properties", "$defs"):
            if key in result:
                result[key] = {label: convert(child) for label, child in result[key].items()}
        if "items" in result:
            result["items"] = convert(result["items"])
        if "anyOf" in result:
            result["anyOf"] = [convert(child) for child in result["anyOf"]]
        if result.get("type") == "object":
            if source.get("additionalProperties") not in (None, False):
                raise ValueError("strict model contracts require explicitly named object properties")
            result["additionalProperties"] = False
            result["required"] = list(result.get("properties", {}))
        if references is not None:
            for key, prop in result.get("properties", {}).items():
                labels = list(references.evidence) if key in _EVIDENCE_FIELDS else list(references.queries) if key in _QUERY_FIELDS else None
                if labels is None:
                    continue
                # Reuse finite choices across classification branches instead
                # of multiplying the provider's total enum-value count.
                reference_name = "SuppliedEvidenceReference" if key in _EVIDENCE_FIELDS else "SuppliedQueryReference"
                citation_definitions[reference_name] = {"type": "string", **({"enum": labels} if labels else {})}
                choice = {"$ref": f"#/$defs/{reference_name}"}
                if prop.get("type") == "array":
                    prop["items"] = choice
                else:
                    prop.clear()
                    prop.update(choice)
                if key == "query_ids" and "evidence_ids" in result["properties"]:
                    prop["description"] = "Use [] when selecting evidence_ids; the application derives their queries. Select query labels for findings with no evidence, including zero-result searches."
        return result

    schema = convert(factory())
    if citation_definitions:
        schema.setdefault("$defs", {}).update(citation_definitions)
    if name == "HuntPlan":
        schema["properties"].pop("intelligence_refs")
        schema["required"].remove("intelligence_refs")
    if name == "QueryAssessment[]" and references is not None:
        definition = schema["$defs"]["QueryAssessment"]
        definition["properties"].pop("question_id")
        definition["required"].remove("question_id")
        entity = schema["$defs"]["AssessmentEntity"]
        entity["properties"].pop("result_row_refs")
        entity["required"].remove("result_row_refs")
    if "FindingProposal" in schema.get("$defs", {}):
        definition = schema["$defs"]["FindingProposal"]
        variants = []
        for classification, required_field in FINDING_GROUNDING_FIELDS.items():
            variant = deepcopy(definition)
            variant["properties"]["classification"] = {
                "type": "string", "enum": [classification.value],
                "description": (
                    "A scoped absence or no-matching-activity conclusion; cite the completed searches, including zero-result searches."
                    if required_field == "query_ids"
                    else "A positive observation or lead supported by the selected event records; do not use for no-matching-activity conclusions."
                ),
            }
            variant["properties"][required_field]["minItems"] = 1
            if references is not None:
                if required_field == "query_ids":
                    eligible = [label for label, query in references.queries.items() if not query_results_incomplete(query)]
                    if not eligible:
                        continue
                    schema["$defs"]["CompleteScopeQueryReference"] = {"type": "string", "enum": eligible}
                    variant["properties"]["query_ids"]["items"] = {"$ref": "#/$defs/CompleteScopeQueryReference"}
                other_field = "evidence_ids" if required_field == "query_ids" else "query_ids"
                variant["properties"][other_field]["maxItems"] = 0
            variants.append(variant)
        schema["$defs"]["FindingProposal"] = {"anyOf": variants}
    for answer_name in ("QuestionAnswer", "QuestionAnswerStep"):
        if answer_name not in schema.get("$defs", {}):
            continue
        definition = schema["$defs"][answer_name]
        variants = []
        for required_field in ("findings", "limitations"):
            variant = deepcopy(definition)
            variant["properties"][required_field]["minItems"] = 1
            variants.append(variant)
        schema["$defs"][answer_name] = {"anyOf": variants}
    if name.endswith("[]"):
        definitions = schema.pop("$defs", {})
        schema = {
            "type": "object", "properties": {name[:-2]: schema},
            "required": [name[:-2]], "additionalProperties": False,
            **({"$defs": definitions} if definitions else {}),
        }
    if schema.get("type") != "object":
        raise ValueError("model response schema must have an object root")
    return {"type": "json_schema", "json_schema": {"name": re.sub(r"[^A-Za-z0-9_-]", "_", name), "strict": True, "schema": schema}}


def prepare_model_context(payload: Any, name: str) -> tuple[Any, ReferenceLabels | None]:
    if name not in {"QueryAssessment[]", "FindingProposal[]", "QuestionSynthesis"}:
        return payload, None
    payload = deepcopy(payload)
    queries = payload.get("completed_queries", [])
    if "retained_evidence" in payload:
        payload["retained_evidence"] = compact_evidence_records(payload["retained_evidence"], queries)
    for query in queries:
        if "retained_evidence" in query:
            query["retained_evidence"] = compact_evidence_records(query["retained_evidence"], queries)
    payload["evidence_representation_rule"] = (
        "Identical raw representations may share a selected_result with duplicate_references preserving "
        "all original evidence and query citations. Differing fields or conflicting values remain separate. "
        "Coverage counts still describe original representations, not unique source events."
    )
    references = ReferenceLabels.from_context(payload)
    context = references.encode(payload)
    context["reference_rules"] = [
        "Citation fields (evidence_ids, query_ids and evidence_candidate_row_refs) use only the supplied E and Q labels, never native telemetry identifiers. Native process GUIDs, session IDs and other observed field values remain evidence: include their exact values in findings when the question requests them or a relationship depends on them.",
        "For findings with evidence_ids, return query_ids=[]; the application derives their query relationships.",
        "For scoped negative findings, select only completed query labels with successful, complete result retrieval. Truncated or partial results cannot establish absence; explain missing support in the question's limitations instead.",
    ]
    if name == "QueryAssessment[]":
        context["reference_rules"].append("Select the completed query's Q label; the application derives question_id. Do not return question_id.")
        context["reference_rules"].append("For each new entity select entity_type and a complete observed scalar value only. Do not return result_row_refs; the application finds every supplied row in this query containing that exact value. Values from other queries or command-line substrings are not accepted.")
    return context, references
